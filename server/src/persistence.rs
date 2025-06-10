use anyhow::Result;
// use serde::{Deserialize, Serialize}; // Unused imports removed
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use tokio::fs as async_fs;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{types::*, GroupInfo};

#[derive(Debug, Clone)]
pub struct PersistenceManager {
    data_dir: PathBuf,
    groups_file: PathBuf,
    messages_dir: PathBuf,
}

impl PersistenceManager {
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let groups_file = data_dir.join("groups.json");
        let messages_dir = data_dir.join("messages");

        // Create directories if they don't exist
        fs::create_dir_all(&data_dir)?;
        fs::create_dir_all(&messages_dir)?;

        info!("Persistence manager initialized at: {}", data_dir.display());

        Ok(Self {
            data_dir,
            groups_file,
            messages_dir,
        })
    }

    // Groups persistence
    pub async fn save_groups(&self, groups: &HashMap<Uuid, GroupInfo>) -> Result<()> {
        let json = serde_json::to_string(groups)?;
        async_fs::write(&self.groups_file, json).await?;
        info!("Saved {} groups to disk", groups.len());
        Ok(())
    }

    pub async fn load_groups(&self) -> Result<HashMap<Uuid, GroupInfo>> {
        if !self.groups_file.exists() {
            info!("No existing groups file found, starting fresh");
            return Ok(HashMap::new());
        }

        match async_fs::read_to_string(&self.groups_file).await {
            Ok(json) => {
                let groups: HashMap<Uuid, GroupInfo> = serde_json::from_str(&json)?;
                info!("Loaded {} groups from disk", groups.len());
                Ok(groups)
            }
            Err(e) => {
                warn!("Failed to load groups: {}, starting fresh", e);
                Ok(HashMap::new())
            }
        }
    }

    // Messages persistence
    pub async fn save_messages(&self, group_id: Uuid, messages: &[MlsMessage]) -> Result<()> {
        let file_path = self.messages_dir.join(format!("{}.json", group_id));
        let json = serde_json::to_string(messages)?;
        async_fs::write(&file_path, json).await?;
        Ok(())
    }

    pub async fn load_messages(&self, group_id: Uuid) -> Result<Vec<MlsMessage>> {
        let file_path = self.messages_dir.join(format!("{}.json", group_id));
        
        if !file_path.exists() {
            return Ok(Vec::new());
        }

        match async_fs::read_to_string(&file_path).await {
            Ok(json) => {
                let messages: Vec<MlsMessage> = serde_json::from_str(&json)?;
                Ok(messages)
            }
            Err(e) => {
                warn!("Failed to load messages for group {}: {}", group_id, e);
                Ok(Vec::new())
            }
        }
    }

    pub async fn load_all_messages(&self) -> Result<HashMap<Uuid, Vec<MlsMessage>>> {
        let mut all_messages = HashMap::new();
        
        let mut entries = async_fs::read_dir(&self.messages_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(extension) = entry.path().extension() {
                if extension == "json" {
                    if let Some(stem) = entry.path().file_stem() {
                        if let Some(filename) = stem.to_str() {
                            if let Ok(group_id) = Uuid::parse_str(filename) {
                                let messages = self.load_messages(group_id).await?;
                                all_messages.insert(group_id, messages);
                            }
                        }
                    }
                }
            }
        }

        info!("Loaded messages for {} groups", all_messages.len());
        Ok(all_messages)
    }

    // Auto-save functionality
    pub async fn auto_save_messages(&self, messages: &HashMap<Uuid, Vec<MlsMessage>>) -> Result<()> {
        for (group_id, group_messages) in messages {
            if let Err(e) = self.save_messages(*group_id, group_messages).await {
                warn!("Failed to auto-save messages for group {}: {}", group_id, e);
            }
        }
        Ok(())
    }
} 