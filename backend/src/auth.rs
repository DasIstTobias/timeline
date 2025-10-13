use axum::http::HeaderMap;
use sqlx::{PgPool, Row};
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use tokio::sync::RwLock;
use uuid::Uuid;
use rand::Rng;

pub struct AuthState {
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
}

// Session data with expiration tracking and CSRF token
#[derive(Clone)]
pub struct SessionData {
    pub user_id: Uuid,
    pub created_at: SystemTime,
    pub last_accessed: SystemTime,
    pub csrf_token: String, // CSRF protection token
}

impl SessionData {
    pub fn new(user_id: Uuid) -> Self {
        let now = SystemTime::now();
        Self {
            user_id,
            created_at: now,
            last_accessed: now,
            csrf_token: generate_csrf_token(),
        }
    }
    
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        if let Ok(elapsed) = self.last_accessed.elapsed() {
            elapsed.as_secs() > max_age_secs
        } else {
            true // If we can't determine elapsed time, consider it expired
        }
    }
    
    pub fn update_last_accessed(&mut self) {
        self.last_accessed = SystemTime::now();
    }
    
    pub fn regenerate_csrf_token(&mut self) {
        self.csrf_token = generate_csrf_token();
    }
}

/// Generate a cryptographically secure CSRF token
fn generate_csrf_token() -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub async fn create_session(
    user_id: Uuid,
    sessions: &Arc<RwLock<HashMap<String, SessionData>>>,
) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    sessions.write().await.insert(session_id.clone(), SessionData::new(user_id));
    session_id
}

/// Regenerate session ID to prevent session fixation attacks
/// Returns the new session ID and CSRF token
pub async fn regenerate_session_id(
    old_session_id: &str,
    sessions: &Arc<RwLock<HashMap<String, SessionData>>>,
) -> Option<(String, String)> {
    let mut sessions_write = sessions.write().await;
    
    if let Some(mut session_data) = sessions_write.remove(old_session_id) {
        // Generate new session ID and CSRF token
        let new_session_id = uuid::Uuid::new_v4().to_string();
        session_data.regenerate_csrf_token();
        let csrf_token = session_data.csrf_token.clone();
        
        // Move session data to new ID
        sessions_write.insert(new_session_id.clone(), session_data);
        
        Some((new_session_id, csrf_token))
    } else {
        None
    }
}

/// Get CSRF token for a session
pub async fn get_csrf_token(
    session_id: &str,
    sessions: &Arc<RwLock<HashMap<String, SessionData>>>,
) -> Option<String> {
    let sessions_read = sessions.read().await;
    sessions_read.get(session_id).map(|s| s.csrf_token.clone())
}

/// Verify CSRF token
pub async fn verify_csrf_token(
    headers: &HeaderMap,
    sessions: &Arc<RwLock<HashMap<String, SessionData>>>,
) -> Result<(), String> {
    // Extract session ID
    let session_id = extract_session_id(headers)
        .ok_or("No session found")?;
    
    // Get CSRF token from header
    let csrf_token = headers.get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or("No CSRF token provided")?;
    
    // Verify token
    let sessions_read = sessions.read().await;
    let session_data = sessions_read.get(&session_id)
        .ok_or("Invalid session")?;
    
    // Constant-time comparison to prevent timing attacks
    if constant_time_compare(csrf_token, &session_data.csrf_token) {
        Ok(())
    } else {
        Err("Invalid CSRF token".to_string())
    }
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

pub async fn verify_session(
    headers: &HeaderMap,
    sessions: &Arc<RwLock<HashMap<String, SessionData>>>,
    db: &PgPool,
) -> Result<AuthState, Box<dyn std::error::Error>> {
    let session_id = extract_session_id(headers)
        .ok_or("No session found")?;
    
    // Check session and expiration
    let mut sessions_write = sessions.write().await;
    let session_data = sessions_write.get_mut(&session_id)
        .ok_or("Invalid session")?;
    
    // Check if session expired (24 hours)
    const SESSION_MAX_AGE: u64 = 24 * 60 * 60; // 24 hours
    if session_data.is_expired(SESSION_MAX_AGE) {
        sessions_write.remove(&session_id);
        return Err("Session expired".into());
    }
    
    // Update last accessed time
    session_data.update_last_accessed();
    let user_id = session_data.user_id;
    
    // Release write lock before database query
    drop(sessions_write);
    
    let user_row = sqlx::query("SELECT username, is_admin FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_one(db)
        .await?;
    
    Ok(AuthState {
        user_id,
        username: user_row.get("username"),
        is_admin: user_row.get("is_admin"),
    })
}

pub fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    use axum::http::header;
    
    headers.get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';')
                .find(|cookie| cookie.trim().starts_with("session_id="))
                .map(|cookie| cookie.trim().strip_prefix("session_id=").unwrap_or("").to_string())
        })
}

// Cleanup expired sessions periodically
pub async fn cleanup_expired_sessions(sessions: &Arc<RwLock<HashMap<String, SessionData>>>) {
    const SESSION_MAX_AGE: u64 = 24 * 60 * 60; // 24 hours
    let mut sessions_write = sessions.write().await;
    sessions_write.retain(|_, session_data| !session_data.is_expired(SESSION_MAX_AGE));
}