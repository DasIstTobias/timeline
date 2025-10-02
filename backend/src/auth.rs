use axum::http::HeaderMap;
use sqlx::{PgPool, Row};
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AuthState {
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
}

// Session data with expiration tracking
#[derive(Clone)]
pub struct SessionData {
    pub user_id: Uuid,
    pub created_at: SystemTime,
    pub last_accessed: SystemTime,
}

impl SessionData {
    pub fn new(user_id: Uuid) -> Self {
        let now = SystemTime::now();
        Self {
            user_id,
            created_at: now,
            last_accessed: now,
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
}

pub async fn create_session(
    user_id: Uuid,
    sessions: &Arc<RwLock<HashMap<String, SessionData>>>,
) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    sessions.write().await.insert(session_id.clone(), SessionData::new(user_id));
    session_id
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