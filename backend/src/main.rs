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
use tower_http::{services::ServeDir, limit::RequestBodyLimitLayer};
use uuid::Uuid;
use regex::Regex;

mod auth;
mod crypto;
mod models;
mod srp;
mod tls;
mod twofa;

use auth::{create_session, verify_session, verify_csrf_token, SessionData};
use crypto::generate_random_password;
use tls::TlsConfig;
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

// Security audit logging for important events
fn audit_log(event_type: &str, username: Option<&str>, user_id: Option<Uuid>, details: &str, success: bool) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let user_info = if let Some(uname) = username {
        format!("user:{}", uname)
    } else {
        "anonymous".to_string()
    };
    
    let status = if success { "SUCCESS" } else { "FAILURE" };
    
    log::info!(
        "[AUDIT] {} | {} | {} | {} | {}",
        timestamp,
        event_type,
        user_info,
        status,
        details
    );
}

type AppState = Arc<AppData>;

#[derive(Clone)]
struct AppData {
    db: PgPool,
    sessions: Arc<RwLock<HashMap<String, SessionData>>>, // session_id -> SessionData
    pending_2fa: Arc<RwLock<HashMap<String, Pending2FAAuth>>>, // temp_session_id -> pending auth
    pending_2fa_secrets: Arc<RwLock<HashMap<Uuid, PendingSecret>>>, // user_id -> pending secret
    pending_srp: Arc<RwLock<HashMap<String, PendingSrpAuth>>>, // temp_session_id -> SRP ephemeral data
    pending_2fa_password_verify: Arc<RwLock<HashMap<String, PendingSrpAuth>>>, // temp_session_id -> SRP auth for 2FA password verification
    pending_password_change: Arc<RwLock<HashMap<String, PendingSrpAuth>>>, // temp_session_id -> SRP auth for password change
    pending_admin_password_change: Arc<RwLock<HashMap<String, PendingSrpAuth>>>, // temp_session_id -> SRP auth for admin password change
    twofa_protection: Arc<TwoFABruteForceProtection>,
    login_rate_limiter: Arc<RwLock<HashMap<String, LoginRateLimit>>>, // IP -> rate limit data
    username_rate_limiter: Arc<RwLock<HashMap<String, UsernameRateLimit>>>, // username -> rate limit data
    registration_rate_limiter: Arc<RwLock<HashMap<String, RegistrationRateLimit>>>, // Admin session -> rate limit data
    tls_config: Arc<RwLock<TlsConfig>>,
    is_https_port: bool, // Track which port this instance is running on
    password_change_locks: Arc<RwLock<HashMap<Uuid, std::time::SystemTime>>>, // user_id -> lock timestamp for preventing concurrent password changes
}

// Rate limiting for login attempts by IP
#[derive(Clone)]
struct LoginRateLimit {
    attempts: u32,
    last_attempt: std::time::SystemTime,
    locked_until: Option<std::time::SystemTime>,
}

// Rate limiting for login attempts by username
#[derive(Clone)]
struct UsernameRateLimit {
    attempts: u32,
    last_attempt: std::time::SystemTime,
    locked_until: Option<std::time::SystemTime>,
}

// Rate limiting for user registration by admin
#[derive(Clone)]
struct RegistrationRateLimit {
    count: u32,
    window_start: std::time::SystemTime,
}

// Temporary authentication state while waiting for 2FA
#[derive(Clone)]
struct Pending2FAAuth {
    user_id: Uuid,
    remember_me: bool,
    password_hash: String, // Store password hash temporarily to decrypt TOTP secret
    created_at: std::time::SystemTime,
}

impl Drop for Pending2FAAuth {
    fn drop(&mut self) {
        // Overwrite password hash with zeros before dropping
        unsafe {
            let bytes = self.password_hash.as_bytes_mut();
            for byte in bytes.iter_mut() {
                *byte = 0;
            }
        }
    }
}

// Pending SRP authentication data
#[derive(Clone)]
struct PendingSrpAuth {
    username: String,
    b_priv: num_bigint::BigUint,  // Server's private ephemeral
    b_pub: Vec<u8>,               // Server's public ephemeral (bytes)
    verifier: Vec<u8>,            // User's verifier
    salt: Vec<u8>,                // User's salt
    created_at: std::time::SystemTime,
}

impl Drop for PendingSrpAuth {
    fn drop(&mut self) {
        // Zero out sensitive ephemeral data before dropping
        // b_priv is BigUint, can't directly zero but it will be dropped
        // Zero out byte arrays
        for byte in self.b_pub.iter_mut() {
            *byte = 0;
        }
        for byte in self.verifier.iter_mut() {
            *byte = 0;
        }
        for byte in self.salt.iter_mut() {
            *byte = 0;
        }
    }
}

// Pending 2FA secret during setup
#[derive(Clone)]
struct PendingSecret {
    secret: String,
    created_at: std::time::SystemTime,
    password_verified: bool, // Track if password was verified via SRP
}

impl Drop for PendingSecret {
    fn drop(&mut self) {
        // Overwrite secret with zeros before dropping
        unsafe {
            let bytes = self.secret.as_bytes_mut();
            for byte in bytes.iter_mut() {
                *byte = 0;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://timeline_user:timeline_password@localhost:5432/timeline".to_string());
    
    let db = PgPool::connect(&database_url).await?;
    
    // Check if migration is needed (old password_hash column exists)
    let needs_migration: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'password_hash'
        )"
    )
    .fetch_one(&db)
    .await
    .unwrap_or(false);
    
    if needs_migration {
        log::info!("Database migration needed: Converting from bcrypt to SRP authentication...");
        
        // Run migration script
        let migration_sql = r#"
            -- Add new SRP columns if they don't exist
            DO $$ 
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'srp_salt'
                ) THEN
                    ALTER TABLE users ADD COLUMN srp_salt VARCHAR(255);
                END IF;

                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'srp_verifier'
                ) THEN
                    ALTER TABLE users ADD COLUMN srp_verifier TEXT;
                END IF;
            END $$;
            
            -- Set placeholder values for existing users
            UPDATE users 
            SET srp_salt = '$placeholder$', 
                srp_verifier = '$placeholder$'
            WHERE srp_salt IS NULL OR srp_verifier IS NULL;
            
            -- Make the new columns NOT NULL
            ALTER TABLE users ALTER COLUMN srp_salt SET NOT NULL;
            ALTER TABLE users ALTER COLUMN srp_verifier SET NOT NULL;
            
            -- Drop the old password_hash column
            ALTER TABLE users DROP COLUMN password_hash;
        "#;
        
        sqlx::raw_sql(migration_sql).execute(&db).await?;
        log::info!("Migration complete: Database schema updated to SRP authentication");
    } else {
        log::info!("Database schema check: Already using SRP authentication");
    }
    
    // Generate admin password and update database with SRP credentials
    let admin_password = generate_random_password();
    let (admin_salt, admin_verifier) = srp::generate_srp_credentials("admin", &admin_password);
    
    sqlx::query("UPDATE users SET srp_salt = $1, srp_verifier = $2 WHERE username = 'admin'")
        .bind(&admin_salt)
        .bind(&admin_verifier)
        .execute(&db)
        .await?;
    
    // Write admin credentials to file
    // Try to write to host directory if mounted, otherwise write to current directory
    let credentials_content = format!("Username: admin\nPassword: {}", admin_password);
    let host_path = "host/admin_credentials.txt";
    let local_path = "admin_credentials.txt";
    
    if tokio::fs::metadata("host").await.is_ok() {
        tokio::fs::write(host_path, &credentials_content).await?;
        log::info!("Admin credentials written to {}", host_path);
    } else {
        tokio::fs::write(local_path, &credentials_content).await?;
        log::info!("Admin credentials written to {}", local_path);
    }
    
    // Read TLS configuration from environment
    let tls_config = Arc::new(RwLock::new(TlsConfig::from_env()));
    tls_config.read().await.log_configuration();
    
    
    // Configure CORS based on domain configuration
    let cors = {
        let config = tls_config.read().await;
        tls::create_cors_layer(&config.domains, config.http_port, config.https_port)
    };
    
    // Create base router (will be used for both HTTP and HTTPS)
    let base_router = Router::new()
        .route("/", get(serve_index))
        .route("/api/login/init", post(login_init))
        .route("/api/login/verify", post(login_verify))
        .route("/api/verify-2fa", post(verify_2fa_login))
        .route("/api/logout", post(logout))
        .route("/api/user-info", get(get_user_info))
        .route("/api/csrf-token", get(get_csrf_token_endpoint))
        .route("/api/register", post(register))
        .route("/api/change-password/init", post(change_password_init))
        .route("/api/change-password/verify", post(change_password_verify))
        .route("/api/admin/change-password/init", post(change_admin_password_init))
        .route("/api/admin/change-password/verify", post(change_admin_password_verify))
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
        .route("/api/profile-picture", post(save_profile_picture).delete(delete_profile_picture))
        .route("/api/notes", get(get_notes))
        .route("/api/notes", post(save_notes))
        .route("/api/2fa/status", get(get_2fa_status))
        .route("/api/2fa/verify-password/init", post(verify_password_for_2fa_init))
        .route("/api/2fa/verify-password/verify", post(verify_password_for_2fa_verify))
        .route("/api/2fa/setup", post(setup_2fa))
        .route("/api/2fa/enable", post(enable_2fa))
        .route("/api/2fa/disable", post(disable_2fa))
        .nest_service("/static", ServeDir::new("static"))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024)); // 2MB limit
    
    // Check if we should start HTTPS server
    let use_self_signed_ssl = tls_config.read().await.use_self_signed_ssl;
    
    if use_self_signed_ssl {
        // Start both HTTP and HTTPS servers
        log::info!("Starting HTTP and HTTPS servers");
        
        // Create HTTP app state
        let http_app_state = AppState::new(AppData {
            db: db.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_2fa: Arc::new(RwLock::new(HashMap::new())),
            pending_2fa_secrets: Arc::new(RwLock::new(HashMap::new())),
            pending_srp: Arc::new(RwLock::new(HashMap::new())),
            pending_2fa_password_verify: Arc::new(RwLock::new(HashMap::new())),
            pending_password_change: Arc::new(RwLock::new(HashMap::new())),
            pending_admin_password_change: Arc::new(RwLock::new(HashMap::new())),
            twofa_protection: Arc::new(TwoFABruteForceProtection::new()),
            login_rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            username_rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            registration_rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            password_change_locks: Arc::new(RwLock::new(HashMap::new())),
            tls_config: tls_config.clone(),
            is_https_port: false,
        });
        
        // Create HTTPS app state (SEPARATE session store for security, shares other data)
        let https_app_state = AppState::new(AppData {
            db: db.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())), // SEPARATE session store for HTTPS
            pending_2fa: http_app_state.pending_2fa.clone(),
            pending_2fa_secrets: http_app_state.pending_2fa_secrets.clone(),
            pending_srp: http_app_state.pending_srp.clone(),
            pending_2fa_password_verify: http_app_state.pending_2fa_password_verify.clone(),
            pending_password_change: http_app_state.pending_password_change.clone(),
            pending_admin_password_change: http_app_state.pending_admin_password_change.clone(),
            twofa_protection: http_app_state.twofa_protection.clone(),
            login_rate_limiter: http_app_state.login_rate_limiter.clone(),
            username_rate_limiter: http_app_state.username_rate_limiter.clone(),
            registration_rate_limiter: http_app_state.registration_rate_limiter.clone(),
            password_change_locks: http_app_state.password_change_locks.clone(),
            tls_config: tls_config.clone(),
            is_https_port: true,
        });
        
        // Start cleanup tasks with both HTTP and HTTPS app states
        let http_sessions_for_cleanup = http_app_state.sessions.clone();
        let https_sessions_for_cleanup = https_app_state.sessions.clone();
        let pending_2fa_cleanup = http_app_state.pending_2fa.clone();
        let pending_secrets_cleanup = http_app_state.pending_2fa_secrets.clone();
        let pending_srp_cleanup = http_app_state.pending_srp.clone();
        let pending_2fa_password_verify_cleanup = http_app_state.pending_2fa_password_verify.clone();
        let pending_password_change_cleanup = http_app_state.pending_password_change.clone();
        let pending_admin_password_change_cleanup = http_app_state.pending_admin_password_change.clone();
        
        // Cleanup HTTP sessions
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                auth::cleanup_expired_sessions(&http_sessions_for_cleanup).await;
                log::info!("Cleaned up expired HTTP sessions");
            }
        });
        
        // Cleanup HTTPS sessions separately
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                auth::cleanup_expired_sessions(&https_sessions_for_cleanup).await;
                log::info!("Cleaned up expired HTTPS sessions");
            }
        });
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                let now = std::time::SystemTime::now();
                let mut pending = pending_2fa_cleanup.write().await;
                pending.retain(|_, auth| {
                    if let Ok(elapsed) = now.duration_since(auth.created_at) {
                        elapsed.as_secs() <= 300
                    } else {
                        false
                    }
                });
                drop(pending);
                
                let mut secrets = pending_secrets_cleanup.write().await;
                secrets.retain(|_, secret| {
                    if let Ok(elapsed) = now.duration_since(secret.created_at) {
                        elapsed.as_secs() <= 600
                    } else {
                        false
                    }
                });
                log::info!("Cleaned up expired pending 2FA sessions and secrets");
            }
        });
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                let now = std::time::SystemTime::now();
                let mut srp_sessions = pending_srp_cleanup.write().await;
                srp_sessions.retain(|_, srp_auth| {
                    if let Ok(elapsed) = now.duration_since(srp_auth.created_at) {
                        elapsed.as_secs() <= 300 // 5 minutes
                    } else {
                        false
                    }
                });
                log::info!("Cleaned up expired pending SRP sessions");
            }
        });
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                let now = std::time::SystemTime::now();
                let mut verify_sessions = pending_2fa_password_verify_cleanup.write().await;
                verify_sessions.retain(|_, srp_auth| {
                    if let Ok(elapsed) = now.duration_since(srp_auth.created_at) {
                        elapsed.as_secs() <= 300 // 5 minutes
                    } else {
                        false
                    }
                });
                log::info!("Cleaned up expired 2FA password verification sessions");
            }
        });
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                let now = std::time::SystemTime::now();
                let mut password_change_sessions = pending_password_change_cleanup.write().await;
                password_change_sessions.retain(|_, srp_auth| {
                    if let Ok(elapsed) = now.duration_since(srp_auth.created_at) {
                        elapsed.as_secs() <= 300 // 5 minutes
                    } else {
                        false
                    }
                });
                log::info!("Cleaned up expired password change sessions");
            }
        });
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                let now = std::time::SystemTime::now();
                let mut admin_password_change_sessions = pending_admin_password_change_cleanup.write().await;
                admin_password_change_sessions.retain(|_, srp_auth| {
                    if let Ok(elapsed) = now.duration_since(srp_auth.created_at) {
                        elapsed.as_secs() <= 300 // 5 minutes
                    } else {
                        false
                    }
                });
                log::info!("Cleaned up expired admin password change sessions");
            }
        });
        
        let http_app = base_router.clone().layer(cors.clone()).with_state(http_app_state);
        let https_app = base_router.layer(cors).with_state(https_app_state);
        
        let tls_config_for_http = tls_config.clone();
        
        // Start HTTP server in separate task
        tokio::spawn(async move {
            if let Err(e) = tls::start_http_server(http_app, tls_config_for_http).await {
                log::error!("HTTP server error: {}", e);
            }
        });
        
        // Start HTTPS server (this blocks)
        let https_port = tls_config.read().await.https_port;
        tls::start_https_server(https_app, https_port).await?;
    } else {
        // Only start HTTP server (traditional mode)
        let app_state = AppState::new(AppData {
            db,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_2fa: Arc::new(RwLock::new(HashMap::new())),
            pending_2fa_secrets: Arc::new(RwLock::new(HashMap::new())),
            pending_srp: Arc::new(RwLock::new(HashMap::new())),
            pending_2fa_password_verify: Arc::new(RwLock::new(HashMap::new())),
            pending_password_change: Arc::new(RwLock::new(HashMap::new())),
            pending_admin_password_change: Arc::new(RwLock::new(HashMap::new())),
            twofa_protection: Arc::new(TwoFABruteForceProtection::new()),
            login_rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            username_rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            registration_rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            password_change_locks: Arc::new(RwLock::new(HashMap::new())),
            tls_config: tls_config.clone(),
            is_https_port: false,
        });
        
        let app = base_router.layer(cors).with_state(app_state);
        
        let http_port = tls_config.read().await.http_port;
        log::info!("Timeline server starting on port {} (HTTP only)", http_port);
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", http_port)).await?;
        axum::serve(listener, app).await?;
    }
    
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

async fn get_csrf_token_endpoint(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify user has a valid session
    let _ = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Get CSRF token from session
    let session_id = auth::extract_session_id(&headers)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let csrf_token = auth::get_csrf_token(&session_id, &state.sessions).await
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({
        "csrf_token": csrf_token
    })))
}

// Helper function to get client IP address
fn get_client_ip(headers: &HeaderMap) -> String {
    // Check X-Forwarded-For header first (set by reverse proxy)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(ip_str) = forwarded.to_str() {
            // Take first IP in the list
            if let Some(ip) = ip_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }
    
    // Check X-Real-IP header
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }
    
    // Fallback to "unknown"
    "unknown".to_string()
}

// Check and update login rate limiting
async fn check_login_rate_limit(
    ip: &str,
    rate_limiter: &Arc<RwLock<HashMap<String, LoginRateLimit>>>,
) -> Result<(), String> {
    let now = std::time::SystemTime::now();
    let mut limiter = rate_limiter.write().await;
    
    let rate_limit = limiter.entry(ip.to_string()).or_insert(LoginRateLimit {
        attempts: 0,
        last_attempt: now,
        locked_until: None,
    });
    
    // Check if currently locked
    if let Some(locked_until) = rate_limit.locked_until {
        if now < locked_until {
            let remaining = locked_until.duration_since(now).unwrap_or_default().as_secs();
            return Err(format!("Too many login attempts. Try again in {} seconds", remaining));
        } else {
            // Lock expired, reset
            rate_limit.attempts = 0;
            rate_limit.locked_until = None;
        }
    }
    
    // Check if we should reset the counter (more than 15 minutes since last attempt)
    if let Ok(duration) = now.duration_since(rate_limit.last_attempt) {
        if duration.as_secs() > 900 {
            rate_limit.attempts = 0;
        }
    }
    
    // Increment attempts
    rate_limit.attempts += 1;
    rate_limit.last_attempt = now;
    
    // Apply progressive lockout
    if rate_limit.attempts >= 10 {
        // 10+ attempts = 1 hour lockout
        rate_limit.locked_until = Some(now + std::time::Duration::from_secs(3600));
        return Err("Too many login attempts. Locked for 1 hour".to_string());
    } else if rate_limit.attempts >= 7 {
        // 7-9 attempts = 15 minutes lockout
        rate_limit.locked_until = Some(now + std::time::Duration::from_secs(900));
        return Err("Too many login attempts. Locked for 15 minutes".to_string());
    } else if rate_limit.attempts >= 5 {
        // 5-6 attempts = 5 minutes lockout
        rate_limit.locked_until = Some(now + std::time::Duration::from_secs(300));
        return Err("Too many login attempts. Locked for 5 minutes".to_string());
    }
    
    Ok(())
}

// Reset login rate limit on successful login
async fn reset_login_rate_limit(
    ip: &str,
    rate_limiter: &Arc<RwLock<HashMap<String, LoginRateLimit>>>,
) {
    let mut limiter = rate_limiter.write().await;
    limiter.remove(ip);
}

// Check username-based rate limiting (more aggressive than IP-based)
async fn check_username_rate_limit(
    username: &str,
    rate_limiter: &Arc<RwLock<HashMap<String, UsernameRateLimit>>>,
) -> Result<(), String> {
    let now = std::time::SystemTime::now();
    let mut limiter = rate_limiter.write().await;
    
    let rate_limit = limiter.entry(username.to_string()).or_insert(UsernameRateLimit {
        attempts: 0,
        last_attempt: now,
        locked_until: None,
    });
    
    // Check if currently locked
    if let Some(locked_until) = rate_limit.locked_until {
        if now < locked_until {
            let remaining = locked_until.duration_since(now).unwrap_or_default().as_secs();
            return Err(format!("Account temporarily locked due to too many failed attempts. Try again in {} seconds", remaining));
        } else {
            // Lock expired, reset
            rate_limit.attempts = 0;
            rate_limit.locked_until = None;
        }
    }
    
    // Check if we should reset the counter (more than 30 minutes since last attempt)
    if let Ok(duration) = now.duration_since(rate_limit.last_attempt) {
        if duration.as_secs() > 1800 {
            rate_limit.attempts = 0;
        }
    }
    
    // Increment attempts
    rate_limit.attempts += 1;
    rate_limit.last_attempt = now;
    
    // Apply more aggressive lockout for targeted attacks on specific accounts
    if rate_limit.attempts >= 5 {
        // 5+ attempts = 30 minutes lockout
        rate_limit.locked_until = Some(now + std::time::Duration::from_secs(1800));
        return Err("Too many failed login attempts for this account. Locked for 30 minutes".to_string());
    } else if rate_limit.attempts >= 3 {
        // 3-4 attempts = 5 minutes lockout
        rate_limit.locked_until = Some(now + std::time::Duration::from_secs(300));
        return Err("Too many failed login attempts for this account. Locked for 5 minutes".to_string());
    }
    
    Ok(())
}

// Reset username rate limit on successful login
async fn reset_username_rate_limit(
    username: &str,
    rate_limiter: &Arc<RwLock<HashMap<String, UsernameRateLimit>>>,
) {
    let mut limiter = rate_limiter.write().await;
    limiter.remove(username);
}

async fn serve_index(headers: HeaderMap, State(state): State<AppState>) -> Response {
    // Check domain and TLS requirements
    let config = state.tls_config.read().await;
    if let Err(status) = tls::check_domain_allowed(&headers, &config.domains) {
        return (status, "Domain not allowed").into_response();
    }
    if let Err(status) = tls::check_tls_requirement(&headers, config.require_tls, state.is_https_port) {
        return (status, "TLS required").into_response();
    }
    drop(config);
    
    let html = tokio::fs::read_to_string("static/index.html").await
        .unwrap_or_else(|_| include_str!("../static/index.html").to_string());
    
    // Add security headers
    let mut response_headers = HeaderMap::new();
    
    // Content Security Policy - only allow local resources
    response_headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    
    // Additional security headers
    response_headers.insert(
        "X-Frame-Options",
        "DENY".parse().unwrap(),
    );
    response_headers.insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap(),
    );
    response_headers.insert(
        "Referrer-Policy",
        "no-referrer".parse().unwrap(),
    );
    response_headers.insert(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );
    
    // Add HSTS header if running on HTTPS
    if state.is_https_port {
        response_headers.insert(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }
    
    (response_headers, Html(html)).into_response()
}

// SRP Login Step 1: Initialize authentication
#[derive(Deserialize)]
struct LoginInitRequest {
    username: String,
}

#[derive(Serialize)]
struct LoginInitResponse {
    salt: String,
    b_pub: String,
    session_id: String,
}

async fn login_init(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<LoginInitRequest>,
) -> Result<Json<LoginInitResponse>, StatusCode> {
    // Check domain and TLS requirements
    let config = state.tls_config.read().await;
    tls::check_domain_allowed(&headers, &config.domains)?;
    tls::check_tls_requirement(&headers, config.require_tls, state.is_https_port)?;
    drop(config);
    
    // Check for null bytes in input
    if req.username.contains('\0') {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Get salt and verifier from database
    let row = sqlx::query("SELECT srp_salt, srp_verifier FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let (salt_hex, verifier_hex) = match row {
        Some(r) => (
            r.get::<String, _>("srp_salt"),
            r.get::<String, _>("srp_verifier")
        ),
        None => {
            // Fake response for timing attack protection
            let fake_salt = "0".repeat(64);
            let fake_verifier = "0".repeat(512);
            (fake_salt, fake_verifier)
        }
    };
    
    let salt = hex::decode(&salt_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let verifier = hex::decode(&verifier_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Generate server's ephemeral values
    let server_eph = srp::srp_begin_authentication(&req.username, &salt, &verifier)
        .map_err(|e| {
            log::error!("SRP begin failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Store ephemeral data temporarily
    let temp_session_id = uuid::Uuid::new_v4().to_string();
    state.pending_srp.write().await.insert(temp_session_id.clone(), PendingSrpAuth {
        username: req.username,
        b_priv: server_eph.b_priv,
        b_pub: server_eph.b_pub.clone(),
        verifier,
        salt: salt.clone(),
        created_at: std::time::SystemTime::now(),
    });
    
    Ok(Json(LoginInitResponse {
        salt: salt_hex,
        b_pub: hex::encode(server_eph.b_pub),
        session_id: temp_session_id,
    }))
}

// SRP Login Step 2: Verify authentication
#[derive(Deserialize)]
struct LoginVerifyRequest {
    session_id: String,
    a_pub: String,
    m1: String,
    remember_me: Option<bool>,
}

#[derive(Serialize)]
struct LoginVerifyResponse {
    success: bool,
    m2: Option<String>,
    user_type: Option<String>,
    requires_2fa: Option<bool>,
    temp_2fa_session_id: Option<String>,
    message: Option<String>,
}

async fn login_verify(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<LoginVerifyRequest>,
) -> Result<(HeaderMap, Json<LoginVerifyResponse>), StatusCode> {
    // Check domain and TLS requirements
    let config = state.tls_config.read().await;
    tls::check_domain_allowed(&headers, &config.domains)?;
    tls::check_tls_requirement(&headers, config.require_tls, state.is_https_port)?;
    drop(config);
    
    // Get client IP for rate limiting
    let client_ip = get_client_ip(&headers);
    
    // Get pending SRP auth first to get username
    let pending = {
        let map = state.pending_srp.read().await;
        map.get(&req.session_id).cloned()
    };
    
    let pending = match pending {
        Some(p) => p,
        None => {
            return Ok((HeaderMap::new(), Json(LoginVerifyResponse {
                success: false,
                m2: None,
                user_type: None,
                requires_2fa: None,
                temp_2fa_session_id: None,
                message: Some("Invalid or expired session".to_string()),
            })));
        }
    };
    
    // Check IP-based rate limiting
    if let Err(msg) = check_login_rate_limit(&client_ip, &state.login_rate_limiter).await {
        return Ok((HeaderMap::new(), Json(LoginVerifyResponse {
            success: false,
            m2: None,
            user_type: None,
            requires_2fa: None,
            temp_2fa_session_id: None,
            message: Some(msg),
        })));
    }
    
    // Check username-based rate limiting (more aggressive)
    if let Err(msg) = check_username_rate_limit(&pending.username, &state.username_rate_limiter).await {
        return Ok((HeaderMap::new(), Json(LoginVerifyResponse {
            success: false,
            m2: None,
            user_type: None,
            requires_2fa: None,
            temp_2fa_session_id: None,
            message: Some(msg),
        })));
    }
    
    // Check expiration (5 minutes)
    if pending.created_at.elapsed().unwrap_or_default() > std::time::Duration::from_secs(300) {
        state.pending_srp.write().await.remove(&req.session_id);
        return Ok((HeaderMap::new(), Json(LoginVerifyResponse {
            success: false,
            m2: None,
            user_type: None,
            requires_2fa: None,
            temp_2fa_session_id: None,
            message: Some("Session expired".to_string()),
        })));
    }
    
    // Decode A and M1 with input validation
    let a_pub = hex::decode(&req.a_pub).map_err(|_| StatusCode::BAD_REQUEST)?;
    let m1 = hex::decode(&req.m1).map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Validate lengths (A should be ~256 bytes for 2048-bit group, M1 should be 32 bytes for SHA-256)
    if a_pub.is_empty() || a_pub.len() > 512 || m1.len() != 32 {
        state.pending_srp.write().await.remove(&req.session_id);
        return Ok((HeaderMap::new(), Json(LoginVerifyResponse {
            success: false,
            m2: None,
            user_type: None,
            requires_2fa: None,
            temp_2fa_session_id: None,
            message: Some("Invalid credentials".to_string()),
        })));
    }
    
    // Verify SRP
    let m2 = match srp::srp_verify_session(
        &pending.username,
        &pending.salt,
        &pending.verifier,
        &a_pub,
        &pending.b_priv,
        &m1,
    ) {
        Ok(m) => m,
        Err(e) => {
            log::debug!("SRP verification failed: {}", e);
            state.pending_srp.write().await.remove(&req.session_id);
            return Ok((HeaderMap::new(), Json(LoginVerifyResponse {
                success: false,
                m2: None,
                user_type: None,
                requires_2fa: None,
                temp_2fa_session_id: None,
                message: Some("Invalid credentials".to_string()),
            })));
        }
    };
    
    // Authentication successful! Clean up pending SRP
    state.pending_srp.write().await.remove(&req.session_id);
    
    // Get user data
    let row = sqlx::query("SELECT id, is_admin, totp_enabled FROM users WHERE username = $1")
        .bind(&pending.username)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let user_id: Uuid = row.get("id");
    let is_admin: bool = row.get("is_admin");
    let totp_enabled: bool = row.get("totp_enabled");
    
    // Check if 2FA is required
    if !is_admin && totp_enabled {
        // Create temporary 2FA session
        // Note: We don't have the password anymore, so we need to pass empty string
        // The client will need to provide password_hash in 2FA verification
        let temp_2fa_id = uuid::Uuid::new_v4().to_string();
        
        state.pending_2fa.write().await.insert(temp_2fa_id.clone(), Pending2FAAuth {
            user_id,
            remember_me: req.remember_me.unwrap_or(false),
            password_hash: String::new(), // Will be provided by client during 2FA
            created_at: std::time::SystemTime::now(),
        });
        
        return Ok((HeaderMap::new(), Json(LoginVerifyResponse {
            success: false,
            m2: Some(hex::encode(m2)),
            user_type: None,
            requires_2fa: Some(true),
            temp_2fa_session_id: Some(temp_2fa_id),
            message: Some("2FA verification required".to_string()),
        })));
    }
    
    // No 2FA required - create full session
    let session_id = create_session(user_id, &state.sessions).await;
    
    // Reset rate limits on successful login
    reset_login_rate_limit(&client_ip, &state.login_rate_limiter).await;
    reset_username_rate_limit(&pending.username, &state.username_rate_limiter).await;
    
    // Audit log successful login
    audit_log("LOGIN", Some(&pending.username), Some(user_id), &format!("IP: {}", client_ip), true);
    
    let mut response_headers = HeaderMap::new();
    let cookie_value = if req.remember_me.unwrap_or(false) {
        format!("session_id={}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict", session_id)
    } else {
        format!("session_id={}; HttpOnly; Path=/; SameSite=Strict", session_id)
    };
    response_headers.insert(header::SET_COOKIE, cookie_value.parse().unwrap());
    
    Ok((response_headers, Json(LoginVerifyResponse {
        success: true,
        m2: Some(hex::encode(m2)),
        user_type: Some(if is_admin { "admin".to_string() } else { "user".to_string() }),
        requires_2fa: None,
        temp_2fa_session_id: None,
        message: None,
    })))
}

async fn logout(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<(HeaderMap, Json<serde_json::Value>), StatusCode> {
    // Verify session exists before logout
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Audit log logout
    audit_log("LOGOUT", Some(&auth_state.username), Some(auth_state.user_id), "", true);
    
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
    // Verify CSRF token
    if let Err(e) = verify_csrf_token(&headers, &state.sessions).await {
        log::warn!("CSRF token verification failed: {}", e);
        return Err(StatusCode::FORBIDDEN);
    }
    
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
    
    // Rate limiting: Max 10 registrations per hour per admin
    {
        let mut rate_limiter = state.registration_rate_limiter.write().await;
        let now = std::time::SystemTime::now();
        let session_id = auth::extract_session_id(&headers).unwrap_or_default();
        
        let rate_limit = rate_limiter.entry(session_id.clone()).or_insert(RegistrationRateLimit {
            count: 0,
            window_start: now,
        });
        
        // Check if window has expired (1 hour)
        if let Ok(elapsed) = now.duration_since(rate_limit.window_start) {
            if elapsed.as_secs() > 3600 {
                // Reset window
                rate_limit.count = 0;
                rate_limit.window_start = now;
            }
        }
        
        // Check rate limit
        if rate_limit.count >= 10 {
            return Ok(Json(RegisterResponse {
                success: false,
                password: None,
                message: Some("Rate limit exceeded. Maximum 10 registrations per hour.".to_string()),
            }));
        }
        
        rate_limit.count += 1;
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
    
    // Generate SRP credentials
    let (salt, verifier) = srp::generate_srp_credentials(&req.username, &password);
    
    // Create user
    let result = sqlx::query("INSERT INTO users (username, srp_salt, srp_verifier) VALUES ($1, $2, $3)")
        .bind(&req.username)
        .bind(&salt)
        .bind(&verifier)
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

// Password change init - Step 1: Start SRP verification of old password
#[derive(Deserialize)]
struct ChangePasswordInitRequest {
    // Empty - we use the session to identify the user
}

#[derive(Serialize)]
struct ChangePasswordInitResponse {
    salt: String,
    b_pub: String,
    session_id: String,
}

async fn change_password_init(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(_req): Json<ChangePasswordInitRequest>,
) -> Result<Json<ChangePasswordInitResponse>, StatusCode> {
    // Verify the user has a valid session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get user's SRP salt and verifier from database
    let row = sqlx::query("SELECT srp_salt, srp_verifier FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let salt_hex: String = row.get("srp_salt");
    let verifier_hex: String = row.get("srp_verifier");
    
    let salt = hex::decode(&salt_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let verifier = hex::decode(&verifier_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Generate server's ephemeral values
    let server_eph = srp::srp_begin_authentication(&auth_state.username, &salt, &verifier)
        .map_err(|e| {
            log::error!("SRP begin failed for password change: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Store ephemeral data temporarily
    let temp_session_id = uuid::Uuid::new_v4().to_string();
    state.pending_password_change.write().await.insert(temp_session_id.clone(), PendingSrpAuth {
        username: auth_state.username.clone(),
        b_priv: server_eph.b_priv,
        b_pub: server_eph.b_pub.clone(),
        verifier,
        salt: salt.clone(),
        created_at: std::time::SystemTime::now(),
    });
    
    Ok(Json(ChangePasswordInitResponse {
        salt: salt_hex,
        b_pub: hex::encode(server_eph.b_pub),
        session_id: temp_session_id,
    }))
}

// Password change verify - Step 2: Verify old password and change to new
#[derive(Deserialize)]
struct ChangePasswordVerifyRequest {
    session_id: String,
    a_pub: String,
    m1: String,
    new_salt: String,
    new_verifier: String,
    old_password_hash: String, // For 2FA re-encryption
    new_password_hash: String, // For 2FA re-encryption
}

#[derive(Serialize)]
struct ChangePasswordVerifyResponse {
    success: bool,
    m2: Option<String>,
    message: Option<String>,
}

async fn change_password_verify(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordVerifyRequest>,
) -> Result<Json<ChangePasswordVerifyResponse>, StatusCode> {
    // Verify the user still has a valid session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Acquire password change lock to prevent concurrent password changes (RACE CONDITION FIX)
    {
        let mut locks = state.password_change_locks.write().await;
        let now = std::time::SystemTime::now();
        
        // Check if there's an active lock for this user
        if let Some(&lock_time) = locks.get(&auth_state.user_id) {
            // If lock is less than 30 seconds old, reject the request
            if let Ok(elapsed) = now.duration_since(lock_time) {
                if elapsed.as_secs() < 30 {
                    return Ok(Json(ChangePasswordVerifyResponse {
                        success: false,
                        m2: None,
                        message: Some("Password change already in progress. Please wait.".to_string()),
                    }));
                }
            }
        }
        
        // Acquire lock for this user
        locks.insert(auth_state.user_id, now);
    }
    
    // Get pending SRP auth for password change
    let pending = {
        let map = state.pending_password_change.read().await;
        map.get(&req.session_id).cloned()
    };
    
    let pending = match pending {
        Some(p) => p,
        None => {
            // Release lock on error
            state.password_change_locks.write().await.remove(&auth_state.user_id);
            return Ok(Json(ChangePasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid or expired session".to_string()),
            }));
        }
    };
    
    // Check expiration (5 minutes)
    if pending.created_at.elapsed().unwrap_or_default() > std::time::Duration::from_secs(300) {
        state.password_change_locks.write().await.remove(&auth_state.user_id);
        state.pending_password_change.write().await.remove(&req.session_id);
        return Ok(Json(ChangePasswordVerifyResponse {
            success: false,
            m2: None,
            message: Some("Session expired".to_string()),
        }));
    }
    
    // Verify username matches (security check)
    if pending.username != auth_state.username {
        state.password_change_locks.write().await.remove(&auth_state.user_id);
        state.pending_password_change.write().await.remove(&req.session_id);
        return Ok(Json(ChangePasswordVerifyResponse {
            success: false,
            m2: None,
            message: Some("Invalid session".to_string()),
        }));
    }
    
    // Decode client's public ephemeral and M1
    let a_pub = match hex::decode(&req.a_pub) {
        Ok(a) => a,
        Err(_) => {
            state.password_change_locks.write().await.remove(&auth_state.user_id);
            state.pending_password_change.write().await.remove(&req.session_id);
            return Ok(Json(ChangePasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid credentials".to_string()),
            }));
        }
    };
    
    let m1 = match hex::decode(&req.m1) {
        Ok(m) => m,
        Err(_) => {
            state.password_change_locks.write().await.remove(&auth_state.user_id);
            state.pending_password_change.write().await.remove(&req.session_id);
            return Ok(Json(ChangePasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid credentials".to_string()),
            }));
        }
    };
    
    // Verify SRP - this proves the user knows the old password
    let m2 = match srp::srp_verify_session(
        &pending.username,
        &pending.salt,
        &pending.verifier,
        &a_pub,
        &pending.b_priv,
        &m1,
    ) {
        Ok(m) => m,
        Err(e) => {
            log::debug!("SRP verification failed during password change: {}", e);
            state.password_change_locks.write().await.remove(&auth_state.user_id);
            state.pending_password_change.write().await.remove(&req.session_id);
            return Ok(Json(ChangePasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid old password".to_string()),
            }));
        }
    };
    
    // Old password verified! Clean up pending SRP
    state.pending_password_change.write().await.remove(&req.session_id);
    
    // Get 2FA status
    let row = sqlx::query("SELECT totp_enabled, totp_encryption_key_encrypted FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let totp_enabled: bool = row.get("totp_enabled");
    let totp_encryption_key_encrypted: Option<String> = row.get("totp_encryption_key_encrypted");
    
    // If 2FA is enabled, re-wrap the encryption key with new password hash
    let new_wrapped_key = if totp_enabled && totp_encryption_key_encrypted.is_some() {
        let old_wrapped_key = totp_encryption_key_encrypted.unwrap();
        
        // Unwrap with old password hash
        let encryption_key = match crypto::decrypt_encryption_key_with_password(&old_wrapped_key, &req.old_password_hash) {
            Ok(key) => key,
            Err(e) => {
                log::error!("Failed to unwrap encryption key during password change: {}", e);
                return Ok(Json(ChangePasswordVerifyResponse {
                    success: false,
                    m2: Some(hex::encode(&m2)),
                    message: Some("Failed to re-wrap 2FA encryption key. Invalid old password hash.".to_string()),
                }));
            }
        };
        
        // Re-wrap with new password hash
        let new_wrapped = match crypto::encrypt_encryption_key_with_password(&encryption_key, &req.new_password_hash, &auth_state.user_id.to_string()) {
            Ok(wrapped) => wrapped,
            Err(e) => {
                log::error!("Failed to re-wrap encryption key during password change: {}", e);
                return Ok(Json(ChangePasswordVerifyResponse {
                    success: false,
                    m2: Some(hex::encode(&m2)),
                    message: Some("Failed to re-wrap 2FA encryption key with new password.".to_string()),
                }));
            }
        };
        
        Some(new_wrapped)
    } else {
        None
    };
    
    // Update SRP credentials and optionally re-wrapped encryption key
    let db_result = if let Some(new_wrapped) = new_wrapped_key {
        sqlx::query("UPDATE users SET srp_salt = $1, srp_verifier = $2, totp_encryption_key_encrypted = $3 WHERE id = $4")
            .bind(&req.new_salt)
            .bind(&req.new_verifier)
            .bind(&new_wrapped)
            .bind(auth_state.user_id)
            .execute(&state.db)
            .await
    } else {
        sqlx::query("UPDATE users SET srp_salt = $1, srp_verifier = $2 WHERE id = $3")
            .bind(&req.new_salt)
            .bind(&req.new_verifier)
            .bind(auth_state.user_id)
            .execute(&state.db)
            .await
    };
    
    // Release password change lock
    state.password_change_locks.write().await.remove(&auth_state.user_id);
    
    // Check database result
    db_result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Audit log successful password change
    audit_log("PASSWORD_CHANGE", Some(&auth_state.username), Some(auth_state.user_id), "", true);
    
    Ok(Json(ChangePasswordVerifyResponse {
        success: true,
        m2: Some(hex::encode(m2)),
        message: None,
    }))
}

// Admin password change init - Step 1: Start SRP verification of old password
#[derive(Deserialize)]
struct ChangeAdminPasswordInitRequest {
    // Empty - we use the session to identify the user
}

#[derive(Serialize)]
struct ChangeAdminPasswordInitResponse {
    salt: String,
    b_pub: String,
    session_id: String,
}

async fn change_admin_password_init(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(_req): Json<ChangeAdminPasswordInitRequest>,
) -> Result<Json<ChangeAdminPasswordInitResponse>, StatusCode> {
    // Verify the user has a valid session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if !auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get user's SRP salt and verifier from database
    let row = sqlx::query("SELECT srp_salt, srp_verifier FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let salt_hex: String = row.get("srp_salt");
    let verifier_hex: String = row.get("srp_verifier");
    
    let salt = hex::decode(&salt_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let verifier = hex::decode(&verifier_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Generate server's ephemeral values
    let server_eph = srp::srp_begin_authentication(&auth_state.username, &salt, &verifier)
        .map_err(|e| {
            log::error!("SRP begin failed for admin password change: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Store ephemeral data temporarily
    let temp_session_id = uuid::Uuid::new_v4().to_string();
    state.pending_admin_password_change.write().await.insert(temp_session_id.clone(), PendingSrpAuth {
        username: auth_state.username.clone(),
        b_priv: server_eph.b_priv,
        b_pub: server_eph.b_pub.clone(),
        verifier,
        salt: salt.clone(),
        created_at: std::time::SystemTime::now(),
    });
    
    Ok(Json(ChangeAdminPasswordInitResponse {
        salt: salt_hex,
        b_pub: hex::encode(server_eph.b_pub),
        session_id: temp_session_id,
    }))
}

// Admin password change verify - Step 2: Verify old password and change to new
#[derive(Deserialize)]
struct ChangeAdminPasswordVerifyRequest {
    session_id: String,
    a_pub: String,
    m1: String,
    new_salt: String,
    new_verifier: String,
}

#[derive(Serialize)]
struct ChangeAdminPasswordVerifyResponse {
    success: bool,
    m2: Option<String>,
    message: Option<String>,
}

async fn change_admin_password_verify(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ChangeAdminPasswordVerifyRequest>,
) -> Result<Json<ChangeAdminPasswordVerifyResponse>, StatusCode> {
    // Verify the user still has a valid session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if !auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get pending SRP auth for admin password change
    let pending = {
        let map = state.pending_admin_password_change.read().await;
        map.get(&req.session_id).cloned()
    };
    
    let pending = match pending {
        Some(p) => p,
        None => {
            return Ok(Json(ChangeAdminPasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid or expired session".to_string()),
            }));
        }
    };
    
    // Check expiration (5 minutes)
    if pending.created_at.elapsed().unwrap_or_default() > std::time::Duration::from_secs(300) {
        state.pending_admin_password_change.write().await.remove(&req.session_id);
        return Ok(Json(ChangeAdminPasswordVerifyResponse {
            success: false,
            m2: None,
            message: Some("Session expired".to_string()),
        }));
    }
    
    // Verify username matches (security check)
    if pending.username != auth_state.username {
        state.pending_admin_password_change.write().await.remove(&req.session_id);
        return Ok(Json(ChangeAdminPasswordVerifyResponse {
            success: false,
            m2: None,
            message: Some("Invalid session".to_string()),
        }));
    }
    
    // Decode client's public ephemeral and M1
    let a_pub = match hex::decode(&req.a_pub) {
        Ok(a) => a,
        Err(_) => {
            state.pending_admin_password_change.write().await.remove(&req.session_id);
            return Ok(Json(ChangeAdminPasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid credentials".to_string()),
            }));
        }
    };
    
    let m1 = match hex::decode(&req.m1) {
        Ok(m) => m,
        Err(_) => {
            state.pending_admin_password_change.write().await.remove(&req.session_id);
            return Ok(Json(ChangeAdminPasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid credentials".to_string()),
            }));
        }
    };
    
    // Verify SRP - this proves the user knows the old password
    let m2 = match srp::srp_verify_session(
        &pending.username,
        &pending.salt,
        &pending.verifier,
        &a_pub,
        &pending.b_priv,
        &m1,
    ) {
        Ok(m) => m,
        Err(e) => {
            log::debug!("SRP verification failed during admin password change: {}", e);
            state.pending_admin_password_change.write().await.remove(&req.session_id);
            return Ok(Json(ChangeAdminPasswordVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid old password".to_string()),
            }));
        }
    };
    
    // Old password verified! Clean up pending SRP
    state.pending_admin_password_change.write().await.remove(&req.session_id);
    
    // Admin users don't have 2FA, so just update SRP credentials
    sqlx::query("UPDATE users SET srp_salt = $1, srp_verifier = $2 WHERE id = $3")
        .bind(&req.new_salt)
        .bind(&req.new_verifier)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Invalidate all sessions for this user (force re-login)
    state.sessions.write().await.retain(|_, session_data| {
        session_data.user_id != auth_state.user_id
    });
    
    Ok(Json(ChangeAdminPasswordVerifyResponse {
        success: true,
        m2: Some(hex::encode(m2)),
        message: None,
    }))
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
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
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
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
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
    
    // Clear user's settings, display name, and profile picture
    sqlx::query("UPDATE users SET settings_encrypted = NULL, display_name_encrypted = NULL, profile_picture_encrypted = NULL WHERE id = $1")
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
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
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
    #[allow(dead_code)]
    confirmation_title: String,
}

async fn delete_event(
    headers: HeaderMap,
    axum::extract::Path(event_id): axum::extract::Path<Uuid>,
    State(state): State<AppState>,
    Json(_req): Json<DeleteEventRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
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
    
    let row = sqlx::query("SELECT settings_encrypted, profile_picture_encrypted FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let settings: Option<String> = row.get("settings_encrypted");
    let profile_picture: Option<String> = row.get("profile_picture_encrypted");
    
    Ok(Json(serde_json::json!({
        "settings_encrypted": settings,
        "profile_picture_encrypted": profile_picture
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
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
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

#[derive(Deserialize)]
struct SaveProfilePictureRequest {
    profile_picture_encrypted: String,
}

async fn save_profile_picture(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SaveProfilePictureRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Validate profile picture input (base64 encoded image data can be large)
    if let Err(msg) = validate_input_string(&req.profile_picture_encrypted, Some(500000)) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "message": format!("Invalid profile picture: {}", msg)
        })));
    }
    
    sqlx::query("UPDATE users SET profile_picture_encrypted = $1 WHERE id = $2")
        .bind(&req.profile_picture_encrypted)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({"success": true})))
}

async fn delete_profile_picture(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    sqlx::query("UPDATE users SET profile_picture_encrypted = NULL WHERE id = $1")
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
    // Verify CSRF token
    if let Err(_) = verify_csrf_token(&headers, &state.sessions).await {
        return Err(StatusCode::FORBIDDEN);
    }
    
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
    password_hash: String, // Client-derived password hash for TOTP decryption
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    user_type: Option<String>,
    message: Option<String>,
}

async fn verify_2fa_login(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Verify2FALoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), StatusCode> {
    // Check domain and TLS requirements
    let config = state.tls_config.read().await;
    tls::check_domain_allowed(&headers, &config.domains)?;
    tls::check_tls_requirement(&headers, config.require_tls, state.is_https_port)?;
    drop(config);
    
    // Get client identifier for brute-force protection (use IP address)
    let client_ip = get_client_ip(&headers);
    
    // Validate TOTP code format (6 digits)
    if req.totp_code.len() != 6 || !req.totp_code.chars().all(|c| c.is_ascii_digit()) {
        return Ok((HeaderMap::new(), Json(LoginResponse {
            success: false,
            user_type: None,
            message: Some("Invalid 2FA code format".to_string()),
        })));
    }
    
    // Get pending 2FA auth
    let pending_auth = {
        let pending_map = state.pending_2fa.read().await;
        pending_map.get(&req.temp_session_id).cloned()
    };
    
    let mut pending = match pending_auth {
        Some(p) => p,
        None => {
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("Invalid or expired session".to_string()),
            })));
        }
    };
    
    // Update pending with password_hash from client
    pending.password_hash = req.password_hash;
    
    // Check if pending session is too old (5 minutes max)
    if let Ok(elapsed) = pending.created_at.elapsed() {
        if elapsed > std::time::Duration::from_secs(300) {
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("Session expired".to_string()),
            })));
        }
    }
    
    // Get ENCRYPTED TOTP secret and wrapped key from database
    let row = sqlx::query("SELECT totp_secret_encrypted, totp_encryption_key_encrypted FROM users WHERE id = $1 AND totp_enabled = true")
        .bind(pending.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let (encrypted_secret, wrapped_key) = match row {
        Some(r) => {
            let secret: Option<String> = r.get("totp_secret_encrypted");
            let key: Option<String> = r.get("totp_encryption_key_encrypted");
            (secret, key)
        },
        None => {
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("2FA not properly configured".to_string()),
            })));
        }
    };
    
    let encrypted_secret = match encrypted_secret {
        Some(s) => s,
        None => {
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("2FA not properly configured".to_string()),
            })));
        }
    };
    
    let wrapped_key = match wrapped_key {
        Some(k) => k,
        None => {
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("2FA not properly configured".to_string()),
            })));
        }
    };
    
    // Unwrap the encryption key with password hash
    let encryption_key = match crypto::decrypt_encryption_key_with_password(&wrapped_key, &pending.password_hash) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to unwrap encryption key: {}", e);
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("Failed to verify 2FA. Incorrect password.".to_string()),
            })));
        }
    };
    
    // Decrypt TOTP secret using unwrapped encryption key
    let secret = match crypto::decrypt_totp_secret_secure(&encrypted_secret, &encryption_key) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to decrypt TOTP secret: {}", e);
            state.pending_2fa.write().await.remove(&req.temp_session_id);
            return Ok((HeaderMap::new(), Json(LoginResponse {
                success: false,
                user_type: None,
                message: Some("Failed to verify 2FA".to_string()),
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
        })));
    }
    
    if !code_valid {
        return Ok((HeaderMap::new(), Json(LoginResponse {
            success: false,
            user_type: None,
            message: Some("Invalid 2FA code".to_string()),
        })));
    }
    
    // 2FA verification successful - remove pending session and create real session
    state.pending_2fa.write().await.remove(&req.temp_session_id);
    let session_id = create_session(pending.user_id, &state.sessions).await;
    
    // Get username to reset username rate limit
    let username: Option<String> = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(pending.user_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    
    // Reset login rate limits on successful 2FA verification
    reset_login_rate_limit(&client_ip, &state.login_rate_limiter).await;
    if let Some(uname) = username {
        reset_username_rate_limit(&uname, &state.username_rate_limiter).await;
    }
    
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

// SECURITY FIX: New SRP-based password verification for 2FA setup
#[derive(Deserialize)]
struct VerifyPasswordFor2FAInitRequest {
    // No parameters needed - we get user from session
}

#[derive(Serialize)]
struct VerifyPasswordFor2FAInitResponse {
    salt: String,
    b_pub: String,
    session_id: String,
}

async fn verify_password_for_2fa_init(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(_req): Json<VerifyPasswordFor2FAInitRequest>,
) -> Result<Json<VerifyPasswordFor2FAInitResponse>, StatusCode> {
    // Verify the user has a valid session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get user's SRP salt and verifier from database
    let row = sqlx::query("SELECT srp_salt, srp_verifier FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let salt_hex: String = row.get("srp_salt");
    let verifier_hex: String = row.get("srp_verifier");
    
    let salt = hex::decode(&salt_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let verifier = hex::decode(&verifier_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Generate server's ephemeral values
    let server_eph = srp::srp_begin_authentication(&auth_state.username, &salt, &verifier)
        .map_err(|e| {
            log::error!("SRP begin failed for 2FA password verification: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Store ephemeral data temporarily
    let temp_session_id = uuid::Uuid::new_v4().to_string();
    state.pending_2fa_password_verify.write().await.insert(temp_session_id.clone(), PendingSrpAuth {
        username: auth_state.username.clone(),
        b_priv: server_eph.b_priv,
        b_pub: server_eph.b_pub.clone(),
        verifier,
        salt: salt.clone(),
        created_at: std::time::SystemTime::now(),
    });
    
    Ok(Json(VerifyPasswordFor2FAInitResponse {
        salt: salt_hex,
        b_pub: hex::encode(server_eph.b_pub),
        session_id: temp_session_id,
    }))
}

#[derive(Deserialize)]
struct VerifyPasswordFor2FAVerifyRequest {
    session_id: String,
    a_pub: String,
    m1: String,
}

#[derive(Serialize)]
struct VerifyPasswordFor2FAVerifyResponse {
    success: bool,
    m2: Option<String>,
    message: Option<String>,
}

async fn verify_password_for_2fa_verify(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<VerifyPasswordFor2FAVerifyRequest>,
) -> Result<Json<VerifyPasswordFor2FAVerifyResponse>, StatusCode> {
    // Verify the user still has a valid session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Get pending SRP auth for 2FA password verification
    let pending = {
        let map = state.pending_2fa_password_verify.read().await;
        map.get(&req.session_id).cloned()
    };
    
    let pending = match pending {
        Some(p) => p,
        None => {
            return Ok(Json(VerifyPasswordFor2FAVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid or expired session".to_string()),
            }));
        }
    };
    
    // Check expiration (5 minutes)
    if pending.created_at.elapsed().unwrap_or_default() > std::time::Duration::from_secs(300) {
        state.pending_2fa_password_verify.write().await.remove(&req.session_id);
        return Ok(Json(VerifyPasswordFor2FAVerifyResponse {
            success: false,
            m2: None,
            message: Some("Session expired".to_string()),
        }));
    }
    
    // Verify username matches (security check)
    if pending.username != auth_state.username {
        state.pending_2fa_password_verify.write().await.remove(&req.session_id);
        return Ok(Json(VerifyPasswordFor2FAVerifyResponse {
            success: false,
            m2: None,
            message: Some("Invalid session".to_string()),
        }));
    }
    
    // Decode client's public ephemeral and M1
    let a_pub = match hex::decode(&req.a_pub) {
        Ok(a) => a,
        Err(_) => {
            return Ok(Json(VerifyPasswordFor2FAVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid credentials".to_string()),
            }));
        }
    };
    
    let m1 = match hex::decode(&req.m1) {
        Ok(m) => m,
        Err(_) => {
            return Ok(Json(VerifyPasswordFor2FAVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid credentials".to_string()),
            }));
        }
    };
    
    // Verify SRP
    let m2 = match srp::srp_verify_session(
        &pending.username,
        &pending.salt,
        &pending.verifier,
        &a_pub,
        &pending.b_priv,
        &m1,
    ) {
        Ok(m) => m,
        Err(e) => {
            log::debug!("SRP verification failed for 2FA password verification: {}", e);
            state.pending_2fa_password_verify.write().await.remove(&req.session_id);
            return Ok(Json(VerifyPasswordFor2FAVerifyResponse {
                success: false,
                m2: None,
                message: Some("Invalid password".to_string()),
            }));
        }
    };
    
    // Password verified successfully!
    // Mark this in the user's pending 2FA secret (if one exists) or create a new one
    state.pending_2fa_secrets.write().await.entry(auth_state.user_id).or_insert_with(|| {
        PendingSecret {
            secret: String::new(), // Will be filled in by setup_2fa
            created_at: std::time::SystemTime::now(),
            password_verified: false,
        }
    }).password_verified = true;
    
    // Clean up the SRP session
    state.pending_2fa_password_verify.write().await.remove(&req.session_id);
    
    log::info!("Password verified for 2FA setup");
    
    Ok(Json(VerifyPasswordFor2FAVerifyResponse {
        success: true,
        m2: Some(hex::encode(m2)),
        message: None,
    }))
}

#[derive(Deserialize)]
struct Setup2FARequest {
    // Removed: password_hash and password_verification (flawed mechanism)
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
    Json(_req): Json<Setup2FARequest>,
) -> Result<Json<Setup2FAResponse>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Check if 2FA is already enabled
    let row = sqlx::query("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let already_enabled: bool = row.get("totp_enabled");
    
    if already_enabled {
        return Ok(Json(Setup2FAResponse {
            success: false,
            secret: None,
            qr_uri: None,
            message: Some("2FA is already enabled".to_string()),
        }));
    }
    
    // SECURITY FIX: Check if password was verified via SRP
    let password_verified = {
        let secrets = state.pending_2fa_secrets.read().await;
        secrets.get(&auth_state.user_id)
            .map(|s| s.password_verified)
            .unwrap_or(false)
    };
    
    if !password_verified {
        log::warn!("Attempt to setup 2FA without password verification");
        return Ok(Json(Setup2FAResponse {
            success: false,
            secret: None,
            qr_uri: None,
            message: Some("Password verification required. Please verify your password first.".to_string()),
        }));
    }
    
    // Generate new TOTP secret
    let secret = twofa::generate_totp_secret();
    
    // Store secret temporarily (expires in 10 minutes) and maintain password_verified flag
    state.pending_2fa_secrets.write().await.insert(
        auth_state.user_id,
        PendingSecret {
            secret: secret.clone(),
            created_at: std::time::SystemTime::now(),
            password_verified: true,
        }
    );
    
    let qr_uri = twofa::generate_totp_uri(&secret, &auth_state.username, "Timeline");
    
    log::info!("2FA setup initiated after password verification");
    
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
    password_hash: String, // Client-derived password hash for encryption
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
    
    // Verify TOTP code against SERVER's secret, not client's
    if !twofa::verify_totp_code(&pending.secret, &req.totp_code) {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid 2FA code".to_string()),
        }));
    }
    
    // SECURITY FIX: Generate random encryption key for TOTP secret (zero-knowledge)
    let totp_encryption_key = crypto::generate_totp_encryption_key();
    
    // Encrypt TOTP secret with random key (NOT password-derived)
    let encrypted_secret = crypto::encrypt_totp_secret_secure(&pending.secret, &totp_encryption_key)
        .map_err(|e| {
            log::error!("Failed to encrypt TOTP secret: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Wrap the encryption key with password hash so we can store it
    let user_id_str = auth_state.user_id.to_string();
    let wrapped_key = crypto::encrypt_encryption_key_with_password(
        &totp_encryption_key,
        &req.password_hash,
        &user_id_str
    ).map_err(|e| {
        log::error!("Failed to wrap encryption key: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // CRITICAL SECURITY FIX: Test that we can unwrap and decrypt
    // This ensures the password hash is valid and the user won't be locked out
    match crypto::decrypt_encryption_key_with_password(&wrapped_key, &req.password_hash) {
        Ok(unwrapped_key) => {
            if unwrapped_key != totp_encryption_key {
                log::error!("Key wrapping test failed: keys don't match");
                return Ok(Json(Enable2FAResponse {
                    success: false,
                    message: Some("Encryption verification failed. Please try again.".to_string()),
                }));
            }
            // Also verify we can decrypt the TOTP secret
            match crypto::decrypt_totp_secret_secure(&encrypted_secret, &unwrapped_key) {
                Ok(decrypted) => {
                    if decrypted != pending.secret {
                        log::error!("TOTP decryption test failed: secrets don't match");
                        return Ok(Json(Enable2FAResponse {
                            success: false,
                            message: Some("Encryption verification failed. Please try again.".to_string()),
                        }));
                    }
                },
                Err(e) => {
                    log::error!("TOTP decryption test failed: {}", e);
                    return Ok(Json(Enable2FAResponse {
                        success: false,
                        message: Some("Encryption verification failed. Please try again.".to_string()),
                    }));
                }
            }
        },
        Err(e) => {
            log::error!("Key unwrapping test failed: {}", e);
            return Ok(Json(Enable2FAResponse {
                success: false,
                message: Some("Encryption verification failed. Please try again.".to_string()),
            }));
        }
    }
    
    // Enable 2FA with ENCRYPTED secret and wrapped key
    sqlx::query("UPDATE users SET totp_secret_encrypted = $1, totp_encryption_key_encrypted = $2, totp_enabled = true, totp_enabled_at = NOW() WHERE id = $3")
        .bind(&encrypted_secret)
        .bind(&wrapped_key)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Clean up temporary storage
    state.pending_2fa_secrets.write().await.remove(&auth_state.user_id);
    
    // Audit log 2FA enable
    audit_log("2FA_ENABLE", Some(&auth_state.username), Some(auth_state.user_id), "", true);
    
    Ok(Json(Enable2FAResponse {
        success: true,
        message: None,
    }))
}

#[derive(Deserialize)]
struct Disable2FARequest {
    totp_code: String,
    password_hash: String, // Client-derived password hash for decryption
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
    let row = sqlx::query("SELECT totp_enabled, totp_secret_encrypted, totp_encryption_key_encrypted FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let totp_enabled: bool = row.get("totp_enabled");
    let totp_secret_encrypted: Option<String> = row.get("totp_secret_encrypted");
    let totp_encryption_key_encrypted: Option<String> = row.get("totp_encryption_key_encrypted");
    
    if !totp_enabled {
        return Ok(Json(Disable2FAResponse {
            success: false,
            message: Some("2FA is not enabled".to_string()),
        }));
    }
    
    let encrypted_secret = totp_secret_encrypted.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let wrapped_key = totp_encryption_key_encrypted.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Unwrap the encryption key with password hash
    let encryption_key = match crypto::decrypt_encryption_key_with_password(&wrapped_key, &req.password_hash) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to unwrap encryption key: {}", e);
            return Ok(Json(Disable2FAResponse {
                success: false,
                message: Some("Failed to verify 2FA. Incorrect password.".to_string()),
            }));
        }
    };
    
    // Decrypt TOTP secret with the unwrapped encryption key
    let secret = match crypto::decrypt_totp_secret_secure(&encrypted_secret, &encryption_key) {
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
    
    // Disable 2FA and clear encryption key
    sqlx::query("UPDATE users SET totp_secret_encrypted = NULL, totp_encryption_key_encrypted = NULL, totp_enabled = false, totp_enabled_at = NULL WHERE id = $1")
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Audit log 2FA disable
    audit_log("2FA_DISABLE", Some(&auth_state.username), Some(auth_state.user_id), "", true);
    
    Ok(Json(Disable2FAResponse {
        success: true,
        message: None,
    }))
}
