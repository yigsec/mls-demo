use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use tokio::fs as async_fs;
use tracing::{info, warn};
use uuid::Uuid;

use crate::types::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EpochKey {
    pub epoch: u64,
    pub application_secret: Vec<u8>,
    pub saved_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MlsGroupState {
    pub group_id: Uuid,
    pub current_epoch: u64,
    pub members: Vec<String>,
    pub is_creator: bool,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub group_info_bytes: Option<Vec<u8>>, // Serialized group info if available
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientState {
    pub client_id: String,
    pub joined_groups: Vec<GroupInfo>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ClientPersistenceManager {
    data_dir: PathBuf,
    client_id: String,
    state_file: PathBuf,
}

impl ClientPersistenceManager {
    pub fn new(client_id: String, base_data_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_data_dir.as_ref();
        let data_dir = base_dir.join("clients").join(&client_id);
        let state_file = data_dir.join("state.json");

        // Create directories if they don't exist
        fs::create_dir_all(&data_dir)?;

        info!(
            "Client persistence manager initialized for '{}' at: {}",
            client_id,
            data_dir.display()
        );

        Ok(Self {
            data_dir,
            client_id,
            state_file,
        })
    }

    pub async fn save_state(&self, groups: &[GroupInfo]) -> Result<()> {
        let state = ClientState {
            client_id: self.client_id.clone(),
            joined_groups: groups.to_vec(),
            last_updated: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&state)?;
        async_fs::write(&self.state_file, json).await?;
        info!(
            "Saved client state for '{}' with {} groups",
            self.client_id,
            groups.len()
        );
        Ok(())
    }

    pub async fn load_state(&self) -> Result<Option<ClientState>> {
        if !self.state_file.exists() {
            info!(
                "No existing state file found for client '{}'",
                self.client_id
            );
            return Ok(None);
        }

        match async_fs::read_to_string(&self.state_file).await {
            Ok(json) => {
                let state: ClientState = serde_json::from_str(&json)?;
                info!(
                    "Loaded client state for '{}' with {} groups",
                    self.client_id,
                    state.joined_groups.len()
                );
                Ok(Some(state))
            }
            Err(e) => {
                warn!(
                    "Failed to load client state for '{}': {}",
                    self.client_id, e
                );
                Ok(None)
            }
        }
    }

    pub async fn save_cache(&self, cache_type: &str, data: &impl Serialize) -> Result<()> {
        let cache_file = self.data_dir.join(format!("{}.json", cache_type));
        let json = serde_json::to_string(data)?;
        async_fs::write(&cache_file, json).await?;
        Ok(())
    }

    pub async fn load_cache<T>(&self, cache_type: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let cache_file = self.data_dir.join(format!("{}.json", cache_type));

        if !cache_file.exists() {
            return Ok(None);
        }

        match async_fs::read_to_string(&cache_file).await {
            Ok(json) => {
                let data: T = serde_json::from_str(&json)?;
                Ok(Some(data))
            }
            Err(e) => {
                warn!(
                    "Failed to load cache '{}' for client '{}': {}",
                    cache_type, self.client_id, e
                );
                Ok(None)
            }
        }
    }

    /// Save last seen messages timestamp for a group
    pub async fn save_last_seen(
        &self,
        group_id: Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let mut last_seen: HashMap<String, chrono::DateTime<chrono::Utc>> =
            self.load_cache("last_seen").await?.unwrap_or_default();

        last_seen.insert(group_id.to_string(), timestamp);
        self.save_cache("last_seen", &last_seen).await
    }

    /// Get last seen timestamp for a group
    pub async fn get_last_seen(
        &self,
        group_id: Uuid,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let last_seen: HashMap<String, chrono::DateTime<chrono::Utc>> =
            self.load_cache("last_seen").await?.unwrap_or_default();

        Ok(last_seen.get(&group_id.to_string()).copied())
    }

    /// Clear all client data
    pub async fn clear_all_data(&self) -> Result<()> {
        if self.data_dir.exists() {
            fs::remove_dir_all(&self.data_dir)?;
            fs::create_dir_all(&self.data_dir)?;
            info!("Cleared all data for client '{}'", self.client_id);
        }
        Ok(())
    }

    /// Save client's own key package
    pub async fn save_key_package(&self, key_package_data: &[u8]) -> Result<()> {
        #[derive(Serialize)]
        struct KeyPackageInfo {
            client_id: String,
            key_package: Vec<u8>,
            created_at: chrono::DateTime<chrono::Utc>,
        }

        let info = KeyPackageInfo {
            client_id: self.client_id.clone(),
            key_package: key_package_data.to_vec(),
            created_at: chrono::Utc::now(),
        };

        self.save_cache("key_package", &info).await?;
        info!("Saved key package for client '{}'", self.client_id);
        Ok(())
    }

    /// Load client's own key package
    pub async fn load_key_package(&self) -> Result<Option<Vec<u8>>> {
        #[derive(Deserialize)]
        struct KeyPackageInfo {
            key_package: Vec<u8>,
        }

        match self.load_cache::<KeyPackageInfo>("key_package").await? {
            Some(info) => {
                info!(
                    "Loaded existing key package for client '{}'",
                    self.client_id
                );
                Ok(Some(info.key_package))
            }
            None => {
                info!(
                    "No existing key package found for client '{}'",
                    self.client_id
                );
                Ok(None)
            }
        }
    }

    /// Save epoch key for a group (with permanent retention for historical decryption)
    pub async fn save_epoch_key(&self, group_id: Uuid, epoch_key: &EpochKey) -> Result<()> {
        // Use permanent storage to ensure users can always decrypt historical messages
        self.save_epoch_key_permanent(group_id, epoch_key).await
    }

    /// Load epoch keys for a group
    pub async fn load_epoch_keys(&self, group_id: Uuid) -> Result<Vec<EpochKey>> {
        let cache_key = format!("epoch_keys_{}", group_id);
        let epoch_keys: Vec<EpochKey> = self.load_cache(&cache_key).await?.unwrap_or_default();

        if !epoch_keys.is_empty() {
            info!(
                "Loaded {} epoch keys for group {}",
                epoch_keys.len(),
                group_id
            );
        }

        Ok(epoch_keys)
    }

    /// Get epoch key for a specific epoch
    pub async fn get_epoch_key(&self, group_id: Uuid, epoch: u64) -> Result<Option<EpochKey>> {
        let epoch_keys = self.load_epoch_keys(group_id).await?;
        Ok(epoch_keys.iter().find(|k| k.epoch == epoch).cloned())
    }

    /// Get all epoch keys across all groups (for comprehensive historical decryption)
    pub async fn get_all_epoch_keys(&self) -> Result<HashMap<Uuid, Vec<EpochKey>>> {
        let mut all_epoch_keys = HashMap::new();

        // Read all cache files that match the epoch_keys pattern
        if let Ok(mut dir) = async_fs::read_dir(&self.data_dir).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Some(file_name) = entry.file_name().to_str() {
                    if file_name.starts_with("epoch_keys_") && file_name.ends_with(".json") {
                        // Extract group ID from filename
                        let group_id_str = file_name
                            .strip_prefix("epoch_keys_")
                            .and_then(|s| s.strip_suffix(".json"));

                        if let Some(group_id_str) = group_id_str {
                            if let Ok(group_id) = Uuid::parse_str(group_id_str) {
                                if let Ok(epoch_keys) = self.load_epoch_keys(group_id).await {
                                    if !epoch_keys.is_empty() {
                                        all_epoch_keys.insert(group_id, epoch_keys);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(all_epoch_keys)
    }

    /// Save epoch keys with unlimited retention (never auto-delete)
    pub async fn save_epoch_key_permanent(
        &self,
        group_id: Uuid,
        epoch_key: &EpochKey,
    ) -> Result<()> {
        let cache_key = format!("epoch_keys_{}", group_id);

        // Load existing epoch keys for this group
        let mut epoch_keys: Vec<EpochKey> = self.load_cache(&cache_key).await?.unwrap_or_default();

        // Add the new epoch key if it doesn't already exist
        if !epoch_keys.iter().any(|k| k.epoch == epoch_key.epoch) {
            epoch_keys.push(epoch_key.clone());
            epoch_keys.sort_by_key(|k| k.epoch);

            self.save_cache(&cache_key, &epoch_keys).await?;
            info!(
                "Permanently saved epoch key for group {} epoch {} (no auto-deletion)",
                group_id, epoch_key.epoch
            );
        }

        Ok(())
    }

    /// Save detailed MLS group state for proper restoration
    pub async fn save_mls_group_state(&self, group_state: &MlsGroupState) -> Result<()> {
        let cache_key = format!("mls_group_state_{}", group_state.group_id);
        self.save_cache(&cache_key, group_state).await?;
        info!(
            "Saved detailed MLS group state for {} at epoch {}",
            group_state.group_id, group_state.current_epoch
        );
        Ok(())
    }

    /// Load detailed MLS group state for restoration
    pub async fn load_mls_group_state(&self, group_id: Uuid) -> Result<Option<MlsGroupState>> {
        let cache_key = format!("mls_group_state_{}", group_id);
        match self.load_cache::<MlsGroupState>(&cache_key).await? {
            Some(state) => {
                info!(
                    "Loaded MLS group state for {} at epoch {}",
                    group_id, state.current_epoch
                );
                Ok(Some(state))
            }
            None => {
                info!("No detailed MLS group state found for {}", group_id);
                Ok(None)
            }
        }
    }

    /// Clear detailed MLS group state
    pub async fn clear_mls_group_state(&self, group_id: Uuid) -> Result<()> {
        let cache_key = format!("mls_group_state_{}", group_id);
        let cache_file = self.data_dir.join(format!("{}.json", cache_key));

        if cache_file.exists() {
            if let Err(e) = async_fs::remove_file(&cache_file).await {
                warn!(
                    "Failed to remove MLS group state file for {}: {}",
                    group_id, e
                );
            } else {
                info!("Cleared detailed MLS group state for {}", group_id);
            }
        }

        Ok(())
    }
}
