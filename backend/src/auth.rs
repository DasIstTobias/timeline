use axum::http::HeaderMap;
use sqlx::{PgPool, Row};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AuthState {
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
}

pub async fn create_session(
    user_id: Uuid,
    sessions: &Arc<RwLock<HashMap<String, Uuid>>>,
) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    sessions.write().await.insert(session_id.clone(), user_id);
    session_id
}

pub async fn verify_session(
    headers: &HeaderMap,
    sessions: &Arc<RwLock<HashMap<String, Uuid>>>,
    db: &PgPool,
) -> Result<AuthState, Box<dyn std::error::Error>> {
    let session_id = extract_session_id(headers)
        .ok_or("No session found")?;
    
    let sessions_read = sessions.read().await;
    let user_id = sessions_read.get(&session_id)
        .ok_or("Invalid session")?;
    
    let user_row = sqlx::query("SELECT username, is_admin FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
    
    Ok(AuthState {
        user_id: *user_id,
        username: user_row.get("username"),
        is_admin: user_row.get("is_admin"),
    })
}

fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    use axum::http::header;
    
    headers.get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';')
                .find(|cookie| cookie.trim().starts_with("session_id="))
                .map(|cookie| cookie.trim().strip_prefix("session_id=").unwrap_or("").to_string())
        })
}