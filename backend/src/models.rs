use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub is_admin: bool,
    pub display_name_encrypted: Option<String>,
    pub settings_encrypted: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title_encrypted: String,
    pub description_encrypted: String,
    pub event_timestamp: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct Tag {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name_encrypted: String,
}

#[derive(Serialize, Deserialize)]
pub struct Note {
    pub id: Uuid,
    pub user_id: Uuid,
    pub content_encrypted: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}