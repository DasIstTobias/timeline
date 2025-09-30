use axum::{
    extract::{State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, services::ServeDir, limit::RequestBodyLimitLayer};
use uuid::Uuid;
use regex::Regex;

mod auth;
mod crypto;
mod models;
mod twofa;

use auth::{create_session, verify_session};
use crypto::{generate_random_password, hash_password, verify_password};
use twofa::TwoFABruteForceProtection;

// Helper function to validate input strings for null bytes and control characters
fn validate_input_string(input: &str, max_length: Option<usize>) -> Result<(), String> {
    // Check for null bytes and control characters
    if input.contains('\0') {
        return Err("Input contains null bytes".to_string());
    }
    
    // Check for other problematic control characters
    for ch in input.chars() {
        if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
            return Err("Input contains invalid control characters".to_string());
        }
    }
    
    // Check length if specified
    if let Some(max_len) = max_length {
        if input.len() > max_len {
            return Err(format!("Input exceeds maximum length of {} characters", max_len));
        }
    }
    
    Ok(())
}

type AppState = Arc<AppData>;

#[derive(Clone)]
struct AppData {
    db: PgPool,
    sessions: Arc<RwLock<HashMap<String, Uuid>>>, // session_id -> user_id
    pending_2fa: Arc<RwLock<HashMap<String, Pending2FAAuth>>>, // temp_session_id -> pending auth
    pending_2fa_secrets: Arc<RwLock<HashMap<Uuid, PendingSecret>>>, // user_id -> pending secret
    twofa_protection: Arc<TwoFABruteForceProtection>,
}

// Temporary authentication state while waiting for 2FA
#[derive(Clone)]
struct Pending2FAAuth {
    user_id: Uuid,
    username: String,
    is_admin: bool,
    remember_me: bool,
    password: String, // Store password temporarily to decrypt TOTP secret
    created_at: std::time::SystemTime,
}

// Pending 2FA secret during setup
#[derive(Clone)]
struct PendingSecret {
    secret: String,
    created_at: std::time::SystemTime,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://timeline_user:timeline_password@localhost:5432/timeline".to_string());
    
    let db = PgPool::connect(&database_url).await?;
    
    // Generate admin password and update database
    let admin_password = generate_random_password();
    let admin_password_hash = hash_password(&admin_password).await?;
    
    sqlx::query("UPDATE users SET password_hash = $1 WHERE username = 'admin'")
        .bind(&admin_password_hash)
        .execute(&db)
        .await?;
    
    // Write admin credentials to file
    tokio::fs::write("admin_credentials.txt", format!("Username: admin\nPassword: {}", admin_password)).await?;
    log::info!("Admin credentials written to admin_credentials.txt");
    
    let app_state = AppState::new(AppData {
        db,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        pending_2fa: Arc::new(RwLock::new(HashMap::new())),
        pending_2fa_secrets: Arc::new(RwLock::new(HashMap::new())),
        twofa_protection: Arc::new(TwoFABruteForceProtection::new()),
    });
    
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/login", post(login))
        .route("/api/verify-2fa", post(verify_2fa_login))
        .route("/api/logout", post(logout))
        .route("/api/user-info", get(get_user_info))
        .route("/api/register", post(register))
        .route("/api/change-password", post(change_password))
        .route("/api/users", get(list_users))
        .route("/api/users", post(register))
        .route("/api/users/:id", post(delete_user))
        .route("/api/user-data", post(clear_user_data))
        .route("/api/events", get(get_events))
        .route("/api/events", post(create_event))
        .route("/api/events/:id", post(delete_event))
        .route("/api/tags", get(get_tags))
        .route("/api/settings", get(get_settings))
        .route("/api/settings", post(save_settings))
        .route("/api/notes", get(get_notes))
        .route("/api/notes", post(save_notes))
        .route("/api/2fa/status", get(get_2fa_status))
        .route("/api/2fa/setup", post(setup_2fa))
        .route("/api/2fa/enable", post(enable_2fa))
        .route("/api/2fa/disable", post(disable_2fa))
        .nest_service("/static", ServeDir::new("static"))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024)) // 2MB limit
        .layer(CorsLayer::permissive())
        .with_state(app_state);
    
    log::info!("Timeline server starting on port 8080");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn get_user_info(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    Ok(Json(serde_json::json!({
        "username": auth_state.username,
        "is_admin": auth_state.is_admin
    })))
}

async fn serve_index(_headers: HeaderMap, State(_state): State<AppState>) -> Response {
    let html = tokio::fs::read_to_string("static/index.html").await
        .unwrap_or_else(|_| include_str!("../static/index.html").to_string());
    Html(html).into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    remember_me: Option<bool>,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    user_type: Option<String>, // "admin" or "user"
    message: Option<String>,
    requires_2fa: Option<bool>, // true if 2FA verification is needed
    temp_session_id: Option<String>, // temporary session ID for 2FA verification
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), StatusCode> {
    // Always perform a dummy hash operation to ensure constant time
    let dummy_hash = "$2b$12$dummy.hash.for.timing.protection.with.enough.length.here.ok";
    let mut password_to_verify = dummy_hash.to_string();
    let mut is_valid_user = false;
    let mut user_data: Option<(Uuid, String, bool)> = None;

    // Check for null bytes in input to prevent injection
    if req.username.contains('\0') || req.password.contains('\0') {
        // Still perform dummy hash for constant time
        let _ = verify_password("dummy", &password_to_verify).await.unwrap_or(false);
        return Ok((HeaderMap::new(), Json(LoginResponse {
            success: false,
            user_type: None,
            message: Some("Invalid credentials".to_string()),
            requires_2fa: None,
            temp_session_id: None,
        })));
    }
    
    let user_row = sqlx::query("SELECT id, username, password_hash, is_admin, totp_enabled FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let mut totp_enabled = false;
    if let Some(row) = user_row {
        let stored_hash: String = row.get("password_hash");
        password_to_verify = stored_hash;
        is_valid_user = true;
        let user_id: Uuid = row.get("id");
        let username: String = row.get("username");
        let is_admin: bool = row.get("is_admin");
        totp_enabled = row.get::<bool, _>("totp_enabled");
        user_data = Some((user_id, username, is_admin));
    }
    
    // Always verify password (either real or dummy) for constant time
    let password_valid = verify_password(&req.password, &password_to_verify).await.unwrap_or(false);
    
    if is_valid_user && password_valid {
        if let Some((user_id, username, is_admin)) = user_data {
            // Check if user has 2FA enabled (only for non-admin users)
            if !is_admin && totp_enabled {
                // Create a temporary pending 2FA session
                let temp_session_id = uuid::Uuid::new_v4().to_string();
                
                state.pending_2fa.write().await.insert(temp_session_id.clone(), Pending2FAAuth {
                    user_id,
                    username: username.clone(),
                    is_admin,
                    remember_me: req.remember_me.unwrap_or(false),
                    password: req.password.clone(), // Store password temporarily for TOTP decryption
                    created_at: std::time::SystemTime::now(),
                });
                
                // Return without revealing success until 2FA is completed
                return Ok((HeaderMap::new(), Json(LoginResponse {
                    success: false,
                    user_type: None,
                    message: Some("2FA verification required".to_string()),
                    requires_2fa: Some(true),
                    temp_session_id: Some(temp_session_id),
                })));
            }
            
            // No 2FA required or admin user - create full session
            let session_id = create_session(user_id, &state.sessions).await;
            
            let mut headers = HeaderMap::new();
            let cookie_value = if req.remember_me.unwrap_or(false) {
                // Persistent cookie for 24 hours when remember me is checked
                format!("session_id={}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict", session_id)
            } else {
                // Session-only cookie when remember me is not checked
                format!("session_id={}; HttpOnly; Path=/; SameSite=Strict", session_id)
            };
            headers.insert(header::SET_COOKIE, cookie_value.parse().unwrap());
            
            return Ok((headers, Json(LoginResponse {
                success: true,
                user_type: Some(if is_admin { "admin".to_string() } else { "user".to_string() }),
                message: None,
                requires_2fa: None,
                temp_session_id: None,
            })));
        }
    }
    
    Ok((HeaderMap::new(), Json(LoginResponse {
        success: false,
        user_type: None,
        message: Some("Invalid credentials".to_string()),
        requires_2fa: None,
        temp_session_id: None,
    })))
}

async fn logout(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<(HeaderMap, Json<serde_json::Value>), StatusCode> {
    // Verify session exists before logout
    let _auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if let Some(session_id) = auth::extract_session_id(&headers) {
        state.sessions.write().await.remove(&session_id);
    }
    
    // Invalidate the cookie by setting it with Max-Age=0
    let mut response_headers = HeaderMap::new();
    let cookie_value = "session_id=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict";
    response_headers.insert(header::SET_COOKIE, cookie_value.parse().unwrap());
    
    Ok((response_headers, Json(serde_json::json!({"success": true}))))
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    success: bool,
    password: Option<String>,
    message: Option<String>,
}

async fn register(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    // Verify admin session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if !auth_state.is_admin {
        return Ok(Json(RegisterResponse {
            success: false,
            password: None,
            message: Some("Admin access required".to_string()),
        }));
    }
    
    // Validate username - only allow alphanumeric characters, underscores, and hyphens
    let username_regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    if !username_regex.is_match(&req.username) || req.username.len() < 3 || req.username.len() > 50 {
        return Ok(Json(RegisterResponse {
            success: false,
            password: None,
            message: Some("Username must be 3-50 characters and contain only letters, numbers, underscores, and hyphens".to_string()),
        }));
    }
    
    // Check for null bytes and other problematic characters
    if req.username.contains('\0') || req.username.contains('\x01') || req.username.contains('\x02') {
        return Ok(Json(RegisterResponse {
            success: false,
            password: None,
            message: Some("Username contains invalid characters".to_string()),
        }));
    }
    
    // Generate random password
    let password = generate_random_password();
    let password_hash = hash_password(&password).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Create user
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
        .bind(&req.username)
        .bind(&password_hash)
        .execute(&state.db)
        .await;
    
    match result {
        Ok(_) => Ok(Json(RegisterResponse {
            success: true,
            password: Some(password),
            message: None,
        })),
        Err(_) => Ok(Json(RegisterResponse {
            success: false,
            password: None,
            message: Some("Username already exists".to_string()),
        })),
    }
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    old_password: String,
    new_password: String,
}

async fn change_password(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Get current password hash
    let current_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Verify old password
    if !verify_password(&req.old_password, &current_hash).await.unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "message": "Current password is incorrect"
        })));
    }
    
    // Hash new password
    let new_hash = hash_password(&req.new_password).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Update password
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({"success": true})))
}

async fn list_users(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if !auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let users = sqlx::query("SELECT id, username, created_at FROM users WHERE is_admin = FALSE ORDER BY username")
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let users_json: Vec<serde_json::Value> = users.iter().map(|row| {
        serde_json::json!({
            "id": row.get::<Uuid, _>("id"),
            "username": row.get::<String, _>("username"),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
        })
    }).collect();
    
    Ok(Json(users_json))
}

#[derive(Deserialize)]
struct DeleteUserRequest {
    confirmation_username: String,
}

async fn delete_user(
    headers: HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<Uuid>,
    State(state): State<AppState>,
    Json(req): Json<DeleteUserRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if !auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get username to verify
    let username: Option<String> = sqlx::query_scalar("SELECT username FROM users WHERE id = $1 AND is_admin = FALSE")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if let Some(username) = username {
        if username == req.confirmation_username {
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(&state.db)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            Ok(Json(serde_json::json!({"success": true})))
        } else {
            Ok(Json(serde_json::json!({
                "success": false,
                "message": "Username confirmation does not match"
            })))
        }
    } else {
        Ok(Json(serde_json::json!({
            "success": false,
            "message": "User not found"
        })))
    }
}

async fn clear_user_data(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Delete all user's events (this will cascade to event_tags)
    sqlx::query("DELETE FROM events WHERE user_id = $1")
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Delete all user's tags
    sqlx::query("DELETE FROM tags WHERE user_id = $1")
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Clear user's settings and display name
    sqlx::query("UPDATE users SET settings_encrypted = NULL, display_name_encrypted = NULL WHERE id = $1")
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({"success": true})))
}

async fn get_events(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let events = sqlx::query(
        "SELECT e.id, e.title_encrypted, e.description_encrypted, e.event_timestamp,
                COALESCE(array_agg(t.name_encrypted) FILTER (WHERE t.name_encrypted IS NOT NULL), '{}') as tag_names
         FROM events e
         LEFT JOIN event_tags et ON e.id = et.event_id
         LEFT JOIN tags t ON et.tag_id = t.id
         WHERE e.user_id = $1
         GROUP BY e.id, e.title_encrypted, e.description_encrypted, e.event_timestamp
         ORDER BY e.event_timestamp ASC"
    )
        .bind(auth_state.user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let events_json: Vec<serde_json::Value> = events.iter().map(|row| {
        serde_json::json!({
            "id": row.get::<Uuid, _>("id"),
            "title_encrypted": row.get::<String, _>("title_encrypted"),
            "description_encrypted": row.get::<String, _>("description_encrypted"),
            "event_timestamp": row.get::<chrono::DateTime<chrono::Utc>, _>("event_timestamp"),
            "tag_names_encrypted": row.get::<Vec<String>, _>("tag_names")
        })
    }).collect();
    
    Ok(Json(events_json))
}

#[derive(Deserialize)]
struct CreateEventRequest {
    title_encrypted: String,
    description_encrypted: String,
    event_timestamp: chrono::DateTime<chrono::Utc>,
    tag_names_encrypted: Vec<String>,
}

async fn create_event(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateEventRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Validate input strings
    if let Err(msg) = validate_input_string(&req.title_encrypted, Some(10000)) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "message": format!("Invalid title: {}", msg)
        })));
    }
    
    if let Err(msg) = validate_input_string(&req.description_encrypted, Some(50000)) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "message": format!("Invalid description: {}", msg)
        })));
    }
    
    // Validate tag names
    for tag_name in &req.tag_names_encrypted {
        if let Err(msg) = validate_input_string(tag_name, Some(1000)) {
            return Ok(Json(serde_json::json!({
                "success": false,
                "message": format!("Invalid tag name: {}", msg)
            })));
        }
    }
    
    // Create event
    let event_id: Uuid = sqlx::query_scalar(
        "INSERT INTO events (user_id, title_encrypted, description_encrypted, event_timestamp) VALUES ($1, $2, $3, $4) RETURNING id"
    )
        .bind(auth_state.user_id)
        .bind(&req.title_encrypted)
        .bind(&req.description_encrypted)
        .bind(req.event_timestamp)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Handle tags
    for tag_name in req.tag_names_encrypted {
        // Get or create tag
        let tag_id: Uuid = sqlx::query_scalar(
            "INSERT INTO tags (user_id, name_encrypted) VALUES ($1, $2) ON CONFLICT (user_id, name_encrypted) DO UPDATE SET name_encrypted = EXCLUDED.name_encrypted RETURNING id"
        )
            .bind(auth_state.user_id)
            .bind(&tag_name)
            .fetch_one(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        // Link event to tag
        sqlx::query("INSERT INTO event_tags (event_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(event_id)
            .bind(tag_id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    
    Ok(Json(serde_json::json!({"success": true, "id": event_id})))
}

#[derive(Deserialize)]
struct DeleteEventRequest {
    confirmation_title: String,
}

async fn delete_event(
    headers: HeaderMap,
    axum::extract::Path(event_id): axum::extract::Path<Uuid>,
    State(state): State<AppState>,
    Json(_req): Json<DeleteEventRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Delete event (cascades to event_tags)
    let deleted = sqlx::query("DELETE FROM events WHERE id = $1 AND user_id = $2")
        .bind(event_id)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Clean up unused tags
    sqlx::query("DELETE FROM tags WHERE user_id = $1 AND id NOT IN (SELECT DISTINCT tag_id FROM event_tags)")
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if deleted.rows_affected() > 0 {
        Ok(Json(serde_json::json!({"success": true})))
    } else {
        Ok(Json(serde_json::json!({
            "success": false,
            "message": "Event not found"
        })))
    }
}

async fn get_tags(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let tags = sqlx::query("SELECT id, name_encrypted FROM tags WHERE user_id = $1 ORDER BY name_encrypted")
        .bind(auth_state.user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let tags_json: Vec<serde_json::Value> = tags.iter().map(|row| {
        serde_json::json!({
            "id": row.get::<Uuid, _>("id"),
            "name_encrypted": row.get::<String, _>("name_encrypted")
        })
    }).collect();
    
    Ok(Json(tags_json))
}

async fn get_settings(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let settings: Option<String> = sqlx::query_scalar("SELECT settings_encrypted FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({
        "settings_encrypted": settings
    })))
}

#[derive(Deserialize)]
struct SaveSettingsRequest {
    settings_encrypted: String,
    display_name_encrypted: Option<String>,
}

async fn save_settings(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SaveSettingsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Validate settings input
    if let Err(msg) = validate_input_string(&req.settings_encrypted, Some(10000)) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "message": format!("Invalid settings: {}", msg)
        })));
    }
    
    // Validate display name if provided
    if let Some(ref display_name) = req.display_name_encrypted {
        if let Err(msg) = validate_input_string(display_name, Some(1000)) {
            return Ok(Json(serde_json::json!({
                "success": false,
                "message": format!("Invalid display name: {}", msg)
            })));
        }
    }
    
    sqlx::query("UPDATE users SET settings_encrypted = $1, display_name_encrypted = $2 WHERE id = $3")
        .bind(&req.settings_encrypted)
        .bind(&req.display_name_encrypted)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({"success": true})))
}

async fn get_notes(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get or create notes for user
    let notes: Option<String> = sqlx::query_scalar(
        "SELECT content_encrypted FROM notes WHERE user_id = $1"
    )
        .bind(auth_state.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // If no notes exist, create empty notes
    if notes.is_none() {
        sqlx::query("INSERT INTO notes (user_id, content_encrypted) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING")
            .bind(auth_state.user_id)
            .bind("")
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    
    Ok(Json(serde_json::json!({
        "content_encrypted": notes.unwrap_or_default()
    })))
}

#[derive(Deserialize)]
struct SaveNotesRequest {
    content_encrypted: String,
}

async fn save_notes(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SaveNotesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Validate input
    if let Err(msg) = validate_input_string(&req.content_encrypted, Some(100000)) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "message": format!("Invalid notes content: {}", msg)
        })));
    }
    
    sqlx::query(
        "INSERT INTO notes (user_id, content_encrypted, updated_at) VALUES ($1, $2, NOW()) 
         ON CONFLICT (user_id) DO UPDATE SET content_encrypted = $2, updated_at = NOW()"
    )
        .bind(auth_state.user_id)
        .bind(&req.content_encrypted)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({"success": true})))
}
// 2FA Endpoints

#[derive(Deserialize)]
struct Verify2FALoginRequest {
    temp_session_id: String,
    totp_code: String,
}

async fn verify_2fa_login(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Verify2FALoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), StatusCode> {
    // Get client identifier for brute-force protection (use IP address)
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    
    // Validate TOTP code format (6 digits)
    if req.totp_code.len() != 6 || !req.totp_code.chars().all(|c| c.is_ascii_digit()) {
        return Ok((HeaderMap::new(), Json(LoginResponse {
            success: false,
            user_type: None,
            message: Some("Invalid 2FA code format".to_string()),
            requires_2fa: None,
            temp_session_id: None,
        })));
    }
    
    // Get pending 2FA auth
    let pending_auth = {
        let pending_map = state.pending_2fa.read().await;
        pending_map.get(&req.temp_session_id).cloned()
    };
    
    let pending = match pending_auth {
        Some(p) => p,
        None => {
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("Invalid or expired session".to_string()),
                requires_2fa: None,
                temp_session_id: None,
            })));
        }
    };
    
    // Check if pending session is too old (5 minutes max)
    if let Ok(elapsed) = pending.created_at.elapsed() {
        if elapsed > std::time::Duration::from_secs(300) {
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("Session expired".to_string()),
                requires_2fa: None,
                temp_session_id: None,
            })));
        }
    }
    
    // Get ENCRYPTED TOTP secret from database
    let totp_secret_encrypted: Option<String> = sqlx::query_scalar(
        "SELECT totp_secret_encrypted FROM users WHERE id = $1 AND totp_enabled = true"
    )
        .bind(pending.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let encrypted_secret = match totp_secret_encrypted {
        Some(s) => s,
        None => {
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("2FA not properly configured".to_string()),
                requires_2fa: None,
                temp_session_id: None,
            })));
        }
    };
    
    // Decrypt TOTP secret using user's password
    let secret = match crypto::decrypt_totp_secret(&encrypted_secret, &pending.password) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to decrypt TOTP secret: {}", e);
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("Failed to verify 2FA".to_string()),
                requires_2fa: None,
                temp_session_id: None,
            })));
        }
    };
    
    // Verify TOTP code using temporarily decrypted secret
    let code_valid = twofa::verify_totp_code(&secret, &req.totp_code);
    
    // Check brute-force protection
    if let Err(msg) = state.twofa_protection.check_and_update(&client_ip, code_valid).await {
        return Ok((HeaderMap::new(), Json(LoginResponse {
            success: false,
            user_type: None,
            message: Some(msg),
            requires_2fa: None,
            temp_session_id: None,
        })));
    }
    
    if !code_valid {
        return Ok((HeaderMap::new(), Json(LoginResponse {
            success: false,
            user_type: None,
            message: Some("Invalid 2FA code".to_string()),
            requires_2fa: None,
            temp_session_id: None,
        })));
    }
    
    // 2FA verification successful - remove pending session and create real session
    state.pending_2fa.write().await.remove(&req.temp_session_id);
    let session_id = create_session(pending.user_id, &state.sessions).await;
    
    let mut response_headers = HeaderMap::new();
    let cookie_value = if pending.remember_me {
        format!("session_id={}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict", session_id)
    } else {
        format!("session_id={}; HttpOnly; Path=/; SameSite=Strict", session_id)
    };
    response_headers.insert(header::SET_COOKIE, cookie_value.parse().unwrap());
    
    Ok((response_headers, Json(LoginResponse {
        success: true,
        user_type: Some("user".to_string()),
        message: None,
        requires_2fa: None,
        temp_session_id: None,
    })))
}

#[derive(Serialize)]
struct TwoFAStatusResponse {
    enabled: bool,
    enabled_at: Option<String>,
}

async fn get_2fa_status(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<TwoFAStatusResponse>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let row = sqlx::query("SELECT totp_enabled, totp_enabled_at FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let enabled: bool = row.get("totp_enabled");
    let enabled_at: Option<chrono::DateTime<chrono::Utc>> = row.get("totp_enabled_at");
    
    Ok(Json(TwoFAStatusResponse {
        enabled,
        enabled_at: enabled_at.map(|dt| dt.to_rfc3339()),
    }))
}

#[derive(Deserialize)]
struct Setup2FARequest {
    password: String,
}

#[derive(Serialize)]
struct Setup2FAResponse {
    success: bool,
    secret: Option<String>,
    qr_uri: Option<String>,
    message: Option<String>,
}

async fn setup_2fa(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Setup2FARequest>,
) -> Result<Json<Setup2FAResponse>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Verify password first
    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let password_valid = verify_password(&req.password, &password_hash).await.unwrap_or(false);
    if !password_valid {
        return Ok(Json(Setup2FAResponse {
            success: false,
            secret: None,
            qr_uri: None,
            message: Some("Invalid password".to_string()),
        }));
    }
    
    // Check if 2FA is already enabled
    let already_enabled: bool = sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if already_enabled {
        return Ok(Json(Setup2FAResponse {
            success: false,
            secret: None,
            qr_uri: None,
            message: Some("2FA is already enabled".to_string()),
        }));
    }
    
    // Generate new TOTP secret
    let secret = twofa::generate_totp_secret();
    
    // Store secret temporarily (expires in 10 minutes)
    state.pending_2fa_secrets.write().await.insert(
        auth_state.user_id,
        PendingSecret {
            secret: secret.clone(),
            created_at: std::time::SystemTime::now(),
        }
    );
    
    let qr_uri = twofa::generate_totp_uri(&secret, &auth_state.username, "Timeline");
    
    Ok(Json(Setup2FAResponse {
        success: true,
        secret: Some(secret),
        qr_uri: Some(qr_uri),
        message: None,
    }))
}

#[derive(Deserialize)]
struct Enable2FARequest {
    totp_code: String,
    password: String,
}

#[derive(Serialize)]
struct Enable2FAResponse {
    success: bool,
    message: Option<String>,
}

async fn enable_2fa(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Enable2FARequest>,
) -> Result<Json<Enable2FAResponse>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    if req.totp_code.len() != 6 || !req.totp_code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid 2FA code format".to_string()),
        }));
    }
    
    // Get secret from server storage, not from client
    let pending_secret = {
        let secrets = state.pending_2fa_secrets.read().await;
        secrets.get(&auth_state.user_id).cloned()
    };
    
    let pending = match pending_secret {
        Some(p) => p,
        None => {
            return Ok(Json(Enable2FAResponse {
                success: false,
                message: Some("No 2FA setup in progress. Please call /api/2fa/setup first.".to_string()),
            }));
        }
    };
    
    // Check expiration (10 minutes)
    if pending.created_at.elapsed().unwrap_or_default() > std::time::Duration::from_secs(600) {
        state.pending_2fa_secrets.write().await.remove(&auth_state.user_id);
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Setup expired. Please start again.".to_string()),
        }));
    }
    
    // Check if 2FA is already enabled
    let already_enabled: bool = sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if already_enabled {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("2FA is already enabled".to_string()),
        }));
    }
    
    // Verify password
    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let password_valid = verify_password(&req.password, &password_hash).await.unwrap_or(false);
    if !password_valid {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid password".to_string()),
        }));
    }
    
    // Verify TOTP code against SERVER's secret, not client's
    if !twofa::verify_totp_code(&pending.secret, &req.totp_code) {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid 2FA code".to_string()),
        }));
    }
    
    // Encrypt TOTP secret with user's password before storing
    let user_id_str = auth_state.user_id.to_string();
    let encrypted_secret = crypto::encrypt_totp_secret(&pending.secret, &req.password, &user_id_str)
        .map_err(|e| {
            log::error!("Failed to encrypt TOTP secret: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Enable 2FA with ENCRYPTED secret
    sqlx::query("UPDATE users SET totp_secret_encrypted = $1, totp_enabled = true, totp_enabled_at = NOW() WHERE id = $2")
        .bind(&encrypted_secret)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Clean up temporary storage
    state.pending_2fa_secrets.write().await.remove(&auth_state.user_id);
    
    Ok(Json(Enable2FAResponse {
        success: true,
        message: None,
    }))
}

#[derive(Deserialize)]
struct Disable2FARequest {
    totp_code: String,
    password: String,
}

#[derive(Serialize)]
struct Disable2FAResponse {
    success: bool,
    message: Option<String>,
}

async fn disable_2fa(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Disable2FARequest>,
) -> Result<Json<Disable2FAResponse>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Validate TOTP code format
    if req.totp_code.len() != 6 || !req.totp_code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(Json(Disable2FAResponse {
            success: false,
            message: Some("Invalid 2FA code format".to_string()),
        }));
    }
    
    // Get current 2FA status and encrypted secret
    let row = sqlx::query("SELECT totp_enabled, totp_secret_encrypted, password_hash FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let totp_enabled: bool = row.get("totp_enabled");
    let totp_secret_encrypted: Option<String> = row.get("totp_secret_encrypted");
    let password_hash: String = row.get("password_hash");
    
    if !totp_enabled {
        return Ok(Json(Disable2FAResponse {
            success: false,
            message: Some("2FA is not enabled".to_string()),
        }));
    }
    
    let encrypted_secret = totp_secret_encrypted.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Verify password
    let password_valid = verify_password(&req.password, &password_hash).await.unwrap_or(false);
    if !password_valid {
        return Ok(Json(Disable2FAResponse {
            success: false,
            message: Some("Invalid password".to_string()),
        }));
    }
    
    // Decrypt TOTP secret to verify code
    let secret = match crypto::decrypt_totp_secret(&encrypted_secret, &req.password) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to decrypt TOTP secret: {}", e);
            return Ok(Json(Disable2FAResponse {
                success: false,
                message: Some("Failed to verify 2FA".to_string()),
            }));
        }
    };
    
    // Verify TOTP code
    if !twofa::verify_totp_code(&secret, &req.totp_code) {
        return Ok(Json(Disable2FAResponse {
            success: false,
            message: Some("Invalid 2FA code".to_string()),
        }));
    }
    
    // Disable 2FA
    sqlx::query("UPDATE users SET totp_secret_encrypted = NULL, totp_enabled = false, totp_enabled_at = NULL WHERE id = $1")
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(Disable2FAResponse {
        success: true,
        message: None,
    }))
}
