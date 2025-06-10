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
    pub encrypted_content: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MlsMessage {
    pub id: Uuid,
    pub group_id: Uuid,
    pub sender: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encrypted_content: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl MlsMessage {
    /// Get the message content, handling both old and new formats
    pub fn get_content(&self) -> Vec<u8> {
        if !self.encrypted_content.is_empty() {
            // New format: return encrypted content as-is
            self.encrypted_content.clone()
        } else if let Some(ref legacy_content) = self.content {
            // Legacy format: convert plaintext to bytes for backward compatibility
            format!("LEGACY_PLAINTEXT: {}", legacy_content).into_bytes()
        } else {
            // Fallback: empty content
            Vec::new()
        }
    }
    
    /// Create a new message with encrypted content
    pub fn new_encrypted(
        group_id: Uuid,
        sender: String,
        encrypted_content: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            group_id,
            sender,
            encrypted_content,
            content: None, // No legacy content for new messages
            timestamp: chrono::Utc::now(),
        }
    }
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendWelcomeRequest {
    pub client_id: String,
    pub welcome_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetWelcomeResponse {
    pub welcome_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendRatchetTreeRequest {
    pub client_id: String,
    pub group_id: Uuid,
    pub ratchet_tree: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetRatchetTreeResponse {
    pub ratchet_tree: Vec<u8>,
} 