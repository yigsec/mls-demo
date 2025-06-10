use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateGroupRequest {
    pub name: String,
    pub creator: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JoinGroupRequest {
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaveGroupRequest {
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendMessageRequest {
    pub sender: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MlsMessage {
    pub id: Uuid,
    pub group_id: Uuid,
    pub sender: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UploadKeyPackageRequest {
    pub client_id: String,
    pub key_package: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyPackageResponse {
    pub key_package: Vec<u8>,
} 