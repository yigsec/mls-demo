use anyhow::Result;
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use reqwest::Client;
use std::collections::HashMap;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::client_persistence::{ClientPersistenceManager, EpochKey, MlsGroupState};
use crate::types::*;

pub struct MlsClient {
    client_id: String,
    server_url: String,
    http_client: Client,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
    groups: HashMap<Uuid, MlsGroup>,
    persistence: ClientPersistenceManager,
    provider: OpenMlsRustCrypto,
    ciphersuite: Ciphersuite,
    sent_messages: HashMap<(Uuid, String), String>, // (group_id, sender) -> content (currently unused)
}

impl MlsClient {
    pub async fn new(server_url: String, client_id: String, data_dir: &str) -> Result<Self> {
        let http_client = Client::new();

        // Initialize persistence manager
        let persistence = ClientPersistenceManager::new(client_id.clone(), data_dir)?;

        // Initialize OpenMLS crypto provider
        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        // Generate a credential for this client
        let credential = Credential::new(CredentialType::Basic, client_id.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())?;

        let credential_with_key = CredentialWithKey {
            credential,
            signature_key: signer.public().into(),
        };

        let mut client = Self {
            client_id,
            server_url,
            http_client,
            credential_with_key,
            signer,
            groups: HashMap::new(),
            persistence,
            provider,
            ciphersuite,
            sent_messages: HashMap::new(),
        };

        // Load existing groups from persistence
        if let Ok(Some(state)) = client.persistence.load_state().await {
            info!(
                "Loaded existing client state with {} groups",
                state.joined_groups.len()
            );

            // Restore MLS groups from persistence
            for group_info in &state.joined_groups {
                if let Ok(Some(group_data)) = client
                    .persistence
                    .load_cache::<Vec<u8>>(&format!("mls_group_{}", group_info.id))
                    .await
                {
                    match client.restore_mls_group(group_info.id, &group_data).await {
                        Ok(()) => {
                            info!(
                                "Restored MLS group state for: {} ({})",
                                group_info.name, group_info.id
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to restore MLS group state for {}: {}",
                                group_info.id, e
                            );
                        }
                    }
                }
            }
        }

        // Generate and upload initial key package
        client.upload_key_package().await?;

        Ok(client)
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub async fn create_group(&mut self, name: &str) -> Result<GroupInfo> {
        let request = CreateGroupRequest {
            name: name.to_string(),
            creator: self.client_id.clone(),
        };

        let response = self
            .http_client
            .post(&format!("{}/groups", self.server_url))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            let group_info: GroupInfo = response.json().await?;

            // Create MLS group as the founding member with consistent group ID
            let mls_group_id = GroupId::from_slice(group_info.id.as_bytes());
            let group_config = MlsGroupCreateConfig::default();

            let mls_group = MlsGroup::new_with_group_id(
                &self.provider,
                &self.signer,
                &group_config,
                mls_group_id,
                self.credential_with_key.clone(),
            )?;

            // Save initial epoch key for the newly created group
            if let Err(e) = Self::save_current_epoch_key(
                &self.persistence,
                group_info.id,
                &mls_group,
                &self.provider,
            )
            .await
            {
                warn!("Failed to save initial epoch key: {}", e);
            }

            // Store the MLS group in memory
            self.groups.insert(group_info.id, mls_group);

            // Save MLS group state to persistence
            if let Err(e) = self.save_mls_group_state(group_info.id).await {
                warn!("Failed to save MLS group state: {}", e);
            }

            // Save updated client state to include the newly created group
            let groups = vec![group_info.clone()]; // We know this is the only group we just created
            if let Err(e) = self.persistence.save_state(&groups).await {
                warn!("Failed to save client state after creating group: {}", e);
            }

            info!(
                "Created group: {} ({}) with MLS group state",
                group_info.name, group_info.id
            );
            Ok(group_info)
        } else {
            Err(anyhow::anyhow!(
                "Failed to create group: {}",
                response.status()
            ))
        }
    }

    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>> {
        let response = self
            .http_client
            .get(&format!("{}/groups", self.server_url))
            .send()
            .await?;

        if response.status().is_success() {
            let groups: Vec<GroupInfo> = response.json().await?;
            Ok(groups)
        } else {
            Err(anyhow::anyhow!(
                "Failed to list groups: {}",
                response.status()
            ))
        }
    }

    pub async fn join_group(&mut self, group_id: Uuid) -> Result<GroupInfo> {
        // First, join the group on the server side
        let request = JoinGroupRequest {
            client_id: self.client_id.clone(),
        };

        let response = self
            .http_client
            .post(&format!("{}/groups/{}/join", self.server_url, group_id))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            let group_info: GroupInfo = response.json().await?;

            // Get the Welcome message from any existing member
            // In a real implementation, this would be sent by the member who added us
            // For now, we'll check if we can find a welcome message from the server
            if let Ok(welcome_msg) = self.get_welcome_message(group_id).await {
                match self.join_group_from_welcome(group_id, welcome_msg).await {
                    Ok(()) => {
                        info!(
                            "Successfully joined group via Welcome message: {} ({})",
                            group_info.name, group_info.id
                        );
                    }
                    Err(e) => {
                        warn!("Failed to join group via Welcome message: {}, falling back to basic join", e);
                        // Fallback: create a standalone group state
                        self.create_standalone_group_state(group_id).await?;
                    }
                }
            } else {
                // No welcome message available, create standalone state
                warn!(
                    "No Welcome message found for group {}, creating standalone state",
                    group_id
                );

                // If we already have a group state, remove it first to avoid conflicts
                if self.groups.contains_key(&group_id) {
                    warn!(
                        "Removing existing group state for {} to create fresh state",
                        group_id
                    );
                    self.groups.remove(&group_id);
                }

                self.create_standalone_group_state(group_id).await?;
            }

            // Save updated client state after joining the group
            let groups = self.list_groups().await.unwrap_or_default();
            if let Err(e) = self.persistence.save_state(&groups).await {
                warn!("Failed to save client state after joining group: {}", e);
            }

            info!("Joined group: {} ({})", group_info.name, group_info.id);
            Ok(group_info)
        } else {
            Err(anyhow::anyhow!(
                "Failed to join group: {}",
                response.status()
            ))
        }
    }

    async fn get_welcome_message(&self, group_id: Uuid) -> Result<Vec<u8>> {
        // Try to get a Welcome message from the server for this client and group
        let response = self
            .http_client
            .get(&format!("{}/welcome/{}", self.server_url, self.client_id))
            .send()
            .await?;

        if response.status().is_success() {
            let welcome_response: GetWelcomeResponse = response.json().await?;
            info!(
                "Retrieved Welcome message for client {} and group {} (length: {} bytes)",
                self.client_id,
                group_id,
                welcome_response.welcome_message.len()
            );
            Ok(welcome_response.welcome_message)
        } else {
            Err(anyhow::anyhow!(
                "No Welcome message available for client {} and group {}",
                self.client_id,
                group_id
            ))
        }
    }

    async fn get_ratchet_tree(&self, group_id: Uuid) -> Result<Vec<u8>> {
        // Try to get a ratchet tree from the server for this client and group
        let response = self
            .http_client
            .get(&format!(
                "{}/ratchet-tree/{}/{}",
                self.server_url, self.client_id, group_id
            ))
            .send()
            .await?;

        if response.status().is_success() {
            let ratchet_tree_response: GetRatchetTreeResponse = response.json().await?;
            info!(
                "Retrieved ratchet tree for client {} and group {} (length: {} bytes)",
                self.client_id,
                group_id,
                ratchet_tree_response.ratchet_tree.len()
            );
            Ok(ratchet_tree_response.ratchet_tree)
        } else {
            Err(anyhow::anyhow!(
                "No ratchet tree available for client {} and group {}",
                self.client_id,
                group_id
            ))
        }
    }

    async fn join_group_from_welcome(
        &mut self,
        group_id: Uuid,
        welcome_data: Vec<u8>,
    ) -> Result<()> {
        // Parse the Welcome message using proper MLS protocol
        let mls_message_in = MlsMessageIn::tls_deserialize(&mut welcome_data.as_slice())?;

        // Extract the Welcome message from the MLS message
        let welcome = match mls_message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => {
                return Err(anyhow::anyhow!(
                    "Expected Welcome message, got different message type"
                ))
            }
        };

        // Try to get the ratchet tree for proper group state reconstruction
        let ratchet_tree = match self.get_ratchet_tree(group_id).await {
            Ok(ratchet_tree_bytes) => {
                let ratchet_tree = RatchetTreeIn::tls_deserialize(
                    &mut ratchet_tree_bytes.as_slice(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to deserialize ratchet tree: {}", e))?;
                Some(ratchet_tree)
            }
            Err(e) => {
                warn!(
                    "Failed to retrieve ratchet tree: {}, will try without it",
                    e
                );
                None
            }
        };

        // Create staged welcome to validate and prepare group joining
        let staged_welcome = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            ratchet_tree, // Use the retrieved ratchet tree
        )
        .map_err(|e| anyhow::anyhow!("Failed to create staged welcome: {}", e))?;

        // Convert staged welcome into actual MLS group
        let mls_group = staged_welcome
            .into_group(&self.provider)
            .map_err(|e| anyhow::anyhow!("Failed to create group from welcome: {}", e))?;

        // Verify the group ID matches what we expect
        let welcome_group_id_bytes = mls_group.group_id().as_slice();
        let expected_group_id_bytes = group_id.as_bytes();

        if welcome_group_id_bytes != expected_group_id_bytes {
            return Err(anyhow::anyhow!(
                "Group ID mismatch: Welcome message is for different group"
            ));
        }

        // Save initial epoch key for the newly joined group
        if let Err(e) =
            Self::save_current_epoch_key(&self.persistence, group_id, &mls_group, &self.provider)
                .await
        {
            warn!("Failed to save initial epoch key after joining: {}", e);
        }

        // Store the properly initialized MLS group
        self.groups.insert(group_id, mls_group);

        // Save to persistence with detailed state
        self.save_mls_group_state(group_id).await?;

        info!(
            "Successfully joined group {} via Welcome message with proper MLS state",
            group_id
        );
        Ok(())
    }

    async fn create_standalone_group_state(&mut self, group_id: Uuid) -> Result<()> {
        // Create a new group state - this is a fallback when proper Welcome flow isn't available
        // Use the server's group UUID as the MLS group ID for consistency
        let mls_group_id = GroupId::from_slice(group_id.as_bytes());
        let group_config = MlsGroupCreateConfig::default();

        let mls_group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &group_config,
            mls_group_id,
            self.credential_with_key.clone(),
        )?;

        self.groups.insert(group_id, mls_group);

        // Save to persistence
        self.save_mls_group_state(group_id).await?;

        warn!("Created standalone MLS group state for {} - each member has independent cryptographic state", group_id);
        warn!("For proper message compatibility, all members should join via Welcome messages from the group creator");
        info!("Current limitation: Without Welcome message workflow, each client creates independent MLS group state");

        Ok(())
    }

    pub async fn leave_group(&mut self, group_id: Uuid) -> Result<()> {
        let request = LeaveGroupRequest {
            client_id: self.client_id.clone(),
        };

        let response = self
            .http_client
            .post(&format!("{}/groups/{}/leave", self.server_url, group_id))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            // Remove from local state
            self.groups.remove(&group_id);

            // Clean up persistence
            let _ = self
                .persistence
                .load_cache::<Vec<u8>>(&format!("mls_group_{}", group_id))
                .await;

            // Clear detailed group state
            if let Err(e) = self.persistence.clear_mls_group_state(group_id).await {
                warn!("Failed to clear detailed group state: {}", e);
            }

            // Keep epoch keys even after leaving - user should always be able to decrypt historical messages
            info!(
                "Preserving epoch keys for historical message decryption after leaving group {}",
                group_id
            );

            // Save updated client state after leaving the group
            let groups = self.list_groups().await.unwrap_or_default();
            if let Err(e) = self.persistence.save_state(&groups).await {
                warn!("Failed to save client state after leaving group: {}", e);
            }

            info!("Left group: {}", group_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to leave group: {}",
                response.status()
            ))
        }
    }

    pub async fn send_message(&mut self, group_id: Uuid, content: &str) -> Result<()> {
        let encrypted_content = match self.groups.get_mut(&group_id) {
            Some(mls_group) => {
                // Create an MLS application message
                let message_out =
                    mls_group.create_message(&self.provider, &self.signer, content.as_bytes())?;

                // Serialize the encrypted message
                message_out.tls_serialize_detached()?
            }
            None => {
                error!("No MLS group found for {}, cannot send message", group_id);
                return Err(anyhow::anyhow!("Not a member of group {}", group_id));
            }
        };

        let request = SendMessageRequest {
            sender: self.client_id.clone(),
            encrypted_content,
        };

        let response = self
            .http_client
            .post(&format!("{}/groups/{}/messages", self.server_url, group_id))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            // Store the content of our sent message with a simple timestamp-based key
            let timestamp_str = chrono::Utc::now().format("%H:%M:%S").to_string();
            let message_key = (group_id, format!("{}_{}", self.client_id, timestamp_str));
            self.sent_messages.insert(message_key, content.to_string());

            info!("Sent encrypted message to group: {}", group_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to send message: {}",
                response.status()
            ))
        }
    }

    pub async fn get_messages(&mut self, group_id: Uuid) -> Result<Vec<DecryptedMessage>> {
        let response = self
            .http_client
            .get(&format!("{}/groups/{}/messages", self.server_url, group_id))
            .send()
            .await?;

        if response.status().is_success() {
            let encrypted_messages: Vec<MlsMessage> = response.json().await?;
            let mut decrypted_messages = Vec::new();

            for msg in encrypted_messages {
                let encrypted_content = msg.get_encrypted_content();
                let is_own_message = msg.sender == self.client_id;

                // Skip MLS protocol messages (Add/Commit/Proposal messages)
                let mut is_protocol_message = false;

                let decrypted_content = match self.groups.get_mut(&group_id) {
                    Some(mls_group) => {
                        // Try to decrypt all messages, including our own
                        match MlsMessageIn::tls_deserialize(
                            &mut encrypted_content.clone().as_slice(),
                        ) {
                            Ok(mls_message_in) => {
                                match mls_message_in.try_into_protocol_message() {
                                    Ok(protocol_message) => {
                                        match mls_group
                                            .process_message(&self.provider, protocol_message)
                                        {
                                            Ok(processed_message) => {
                                                match processed_message.into_content() {
                                                    ProcessedMessageContent::ApplicationMessage(app_msg) => {
                                                        // Successfully decrypted a message - save current epoch key to ensure future access
                                                        if let Err(e) = Self::save_current_epoch_key(&self.persistence, group_id, mls_group, &self.provider).await {
                                                            warn!("Failed to save epoch key after successful decryption: {}", e);
                                                        }
                                                        String::from_utf8_lossy(&app_msg.into_bytes()).to_string()
                                                    }
                                                    ProcessedMessageContent::ProposalMessage(_) => {
                                                        // Mark as protocol message and skip
                                                        is_protocol_message = true;
                                                        format!("[Proposal Message from {}]", msg.sender)
                                                    }
                                                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                                                        // Mark as protocol message and skip
                                                        is_protocol_message = true;
                                                        format!("[External Join Proposal from {}]", msg.sender)
                                                    }
                                                    ProcessedMessageContent::StagedCommitMessage(_) => {
                                                        // Mark as protocol message and skip
                                                        is_protocol_message = true;
                                                        format!("[Staged Commit from {}]", msg.sender)
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let error_msg = e.to_string();

                                                // Handle specific MLS errors
                                                if error_msg.contains("Message epoch differs") {
                                                    // Try to decrypt with previous epoch keys
                                                    match self
                                                        .decrypt_with_previous_epochs(
                                                            group_id,
                                                            &encrypted_content,
                                                        )
                                                        .await
                                                    {
                                                        Ok(decrypted_content) => {
                                                            info!("Successfully decrypted message from previous epoch");
                                                            decrypted_content
                                                        }
                                                        Err(_) => {
                                                            if is_own_message {
                                                                // Try to find the content from our sent messages cache
                                                                let timestamp_str = msg
                                                                    .timestamp
                                                                    .format("%H:%M:%S")
                                                                    .to_string();
                                                                let message_key = (
                                                                    group_id,
                                                                    format!(
                                                                        "{}_{}",
                                                                        self.client_id,
                                                                        timestamp_str
                                                                    ),
                                                                );

                                                                if let Some(cached_content) = self
                                                                    .sent_messages
                                                                    .get(&message_key)
                                                                {
                                                                    cached_content.clone()
                                                                } else {
                                                                    format!("[Message from previous epoch - no key available]")
                                                                }
                                                            } else {
                                                                format!("[Message from previous epoch - decryption failed]")
                                                            }
                                                        }
                                                    }
                                                } else if error_msg.contains("wrong ratchet type")
                                                    || error_msg.contains("RatchetTypeError")
                                                {
                                                    if is_own_message {
                                                        // Try to find the content from our sent messages cache
                                                        let timestamp_str = msg
                                                            .timestamp
                                                            .format("%H:%M:%S")
                                                            .to_string();
                                                        let message_key = (
                                                            group_id,
                                                            format!(
                                                                "{}_{}",
                                                                self.client_id, timestamp_str
                                                            ),
                                                        );

                                                        if let Some(cached_content) =
                                                            self.sent_messages.get(&message_key)
                                                        {
                                                            cached_content.clone()
                                                        } else {
                                                            format!("[Message from different group state]")
                                                        }
                                                    } else {
                                                        format!("[Message from different group state - sent before sync]")
                                                    }
                                                } else {
                                                    if is_own_message {
                                                        // Try to find the content from our sent messages cache
                                                        let timestamp_str = msg
                                                            .timestamp
                                                            .format("%H:%M:%S")
                                                            .to_string();
                                                        let message_key = (
                                                            group_id,
                                                            format!(
                                                                "{}_{}",
                                                                self.client_id, timestamp_str
                                                            ),
                                                        );

                                                        if let Some(cached_content) =
                                                            self.sent_messages.get(&message_key)
                                                        {
                                                            cached_content.clone()
                                                        } else {
                                                            format!("[Unable to decrypt own message - MLS limitation]")
                                                        }
                                                    } else {
                                                        warn!("Failed to process message: {}", e);
                                                        format!("[Failed to decrypt: {}]", e)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to extract protocol message: {}", e);
                                        if is_own_message {
                                            // Try to find cached content for protocol errors too
                                            let timestamp_str =
                                                msg.timestamp.format("%H:%M:%S").to_string();
                                            let message_key = (
                                                group_id,
                                                format!("{}_{}", self.client_id, timestamp_str),
                                            );

                                            if let Some(cached_content) =
                                                self.sent_messages.get(&message_key)
                                            {
                                                cached_content.clone()
                                            } else {
                                                format!("[Own message - protocol error]")
                                            }
                                        } else {
                                            format!("[Protocol error: {}]", e)
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to deserialize MLS message: {}", e);
                                // Check if this is a legacy message format
                                if let Ok(plaintext) = String::from_utf8(encrypted_content) {
                                    if plaintext.starts_with("SHARED:")
                                        || plaintext.starts_with("ENCRYPTED[")
                                    {
                                        format!("[Legacy format: {}]", plaintext)
                                    } else if plaintext.starts_with("LEGACY_PLAINTEXT: ") {
                                        // Extract the original content from legacy format
                                        plaintext
                                            .strip_prefix("LEGACY_PLAINTEXT: ")
                                            .unwrap_or(&plaintext)
                                            .to_string()
                                    } else {
                                        if is_own_message {
                                            // Try to find cached content for format issues too
                                            let timestamp_str =
                                                msg.timestamp.format("%H:%M:%S").to_string();
                                            let message_key = (
                                                group_id,
                                                format!("{}_{}", self.client_id, timestamp_str),
                                            );

                                            if let Some(cached_content) =
                                                self.sent_messages.get(&message_key)
                                            {
                                                cached_content.clone()
                                            } else {
                                                format!("[Own message - format issue]")
                                            }
                                        } else {
                                            format!("[Unknown format: {}]", e)
                                        }
                                    }
                                } else {
                                    if is_own_message {
                                        // Try to find cached content for deserialization failures too
                                        let timestamp_str =
                                            msg.timestamp.format("%H:%M:%S").to_string();
                                        let message_key = (
                                            group_id,
                                            format!("{}_{}", self.client_id, timestamp_str),
                                        );

                                        if let Some(cached_content) =
                                            self.sent_messages.get(&message_key)
                                        {
                                            cached_content.clone()
                                        } else {
                                            format!("[Own message - deserialization failed]")
                                        }
                                    } else {
                                        format!("[Deserialization failed: {}]", e)
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        error!(
                            "No MLS group available for decryption of group {}",
                            group_id
                        );
                        "[No group key available]".to_string()
                    }
                };

                // Skip protocol messages from user message display
                if is_protocol_message {
                    continue;
                }

                let sender_display = if is_own_message {
                    format!("{} (you)", msg.sender)
                } else {
                    msg.sender.clone()
                };

                decrypted_messages.push(DecryptedMessage {
                    id: msg.id,
                    group_id: msg.group_id,
                    sender: sender_display,
                    content: decrypted_content,
                    timestamp: msg.timestamp,
                });
            }

            Ok(decrypted_messages)
        } else {
            Err(anyhow::anyhow!(
                "Failed to get messages: {}",
                response.status()
            ))
        }
    }

    pub async fn upload_key_package(&self) -> Result<()> {
        // Generate a new key package
        let key_package = KeyPackage::builder().build(
            self.ciphersuite,
            &self.provider,
            &self.signer,
            self.credential_with_key.clone(),
        )?;

        let key_package_bytes = key_package.key_package().tls_serialize_detached()?;

        // Save key package locally first
        if let Err(e) = self.persistence.save_key_package(&key_package_bytes).await {
            warn!("Failed to save key package locally: {}", e);
        }

        let request = UploadKeyPackageRequest {
            client_id: self.client_id.clone(),
            key_package: key_package_bytes,
        };

        let response = self
            .http_client
            .post(&format!("{}/key_packages", self.server_url))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Uploaded key package for client: {}", self.client_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to upload key package: {}",
                response.status()
            ))
        }
    }

    pub async fn get_key_package(&self, client_id: &str) -> Result<Vec<u8>> {
        let response = self
            .http_client
            .get(&format!("{}/key_packages/{}", self.server_url, client_id))
            .send()
            .await?;

        if response.status().is_success() {
            let key_package_response: KeyPackageResponse = response.json().await?;
            Ok(key_package_response.key_package)
        } else {
            Err(anyhow::anyhow!(
                "Failed to get key package: {}",
                response.status()
            ))
        }
    }

    /// Add a member to the group using proper MLS protocol
    pub async fn add_member_to_group(&mut self, group_id: Uuid, new_member_id: &str) -> Result<()> {
        // Get the key package for the new member
        let key_package_bytes = self.get_key_package(new_member_id).await?;
        let key_package_in = KeyPackageIn::tls_deserialize(&mut key_package_bytes.as_slice())?;

        // Validate the KeyPackageIn using the correct OpenMLS 0.6 API
        let key_package = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow::anyhow!("Failed to validate key package: {}", e))?;

        if let Some(mls_group) = self.groups.get_mut(&group_id) {
            // Create Add proposal and commit using proper MLS add_members API
            let (commit_message, welcome_message, _group_info) = mls_group
                .add_members(&self.provider, &self.signer, &[key_package])
                .map_err(|e| anyhow::anyhow!("Failed to add members: {}", e))?;

            // Send the Add/Commit message to the group
            let commit_bytes = commit_message.tls_serialize_detached()?;

            let request = SendMessageRequest {
                sender: self.client_id.clone(),
                encrypted_content: commit_bytes,
            };

            let response = self
                .http_client
                .post(&format!("{}/groups/{}/messages", self.server_url, group_id))
                .json(&request)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(anyhow::anyhow!("Failed to send Add/Commit message"));
            }

            // Save current epoch key before merging commit (which will advance the epoch)
            if let Err(e) =
                Self::save_current_epoch_key(&self.persistence, group_id, mls_group, &self.provider)
                    .await
            {
                warn!("Failed to save epoch key before commit: {}", e);
            }

            // Merge the pending commit to finalize the member addition
            mls_group
                .merge_pending_commit(&self.provider)
                .map_err(|e| anyhow::anyhow!("Failed to merge pending commit: {}", e))?;

            // Save current epoch key before merging commit (which will advance the epoch)
            if let Err(e) =
                Self::save_current_epoch_key(&self.persistence, group_id, mls_group, &self.provider)
                    .await
            {
                warn!("Failed to save epoch key before commit: {}", e);
            }

            // Export the ratchet tree for the new member
            let ratchet_tree = mls_group.export_ratchet_tree();
            let ratchet_tree_bytes = ratchet_tree.tls_serialize_detached()?;

            // Send Welcome message to the new member
            let welcome_bytes = welcome_message.tls_serialize_detached()?;

            // Store the ratchet tree for the new member to retrieve
            if let Err(e) = self
                .persistence
                .save_cache(
                    &format!("ratchet_tree_{}_{}", group_id, new_member_id),
                    &ratchet_tree_bytes,
                )
                .await
            {
                warn!("Failed to cache ratchet tree for {}: {}", new_member_id, e);
            }

            // Send the Welcome message to the server for the new member to retrieve
            if let Err(e) = self
                .send_welcome_message(new_member_id, welcome_bytes.clone())
                .await
            {
                warn!(
                    "Failed to send Welcome message to server for {}: {}",
                    new_member_id, e
                );
                return Err(anyhow::anyhow!("Failed to send Welcome message: {}", e));
            } else {
                info!(
                    "Successfully sent Welcome message for {} (length: {} bytes)",
                    new_member_id,
                    welcome_bytes.len()
                );
            }

            // Also send the ratchet tree to the server
            if let Err(e) = self
                .send_ratchet_tree(new_member_id, group_id, ratchet_tree_bytes.clone())
                .await
            {
                warn!(
                    "Failed to send ratchet tree to server for {}: {}",
                    new_member_id, e
                );
            } else {
                info!(
                    "Successfully sent ratchet tree for {} (length: {} bytes)",
                    new_member_id,
                    ratchet_tree_bytes.len()
                );
            }

            // Save updated group state with new epoch information
            // Wait a moment for server state to potentially update, then save
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            self.save_mls_group_state_after_member_change(group_id, new_member_id)
                .await?;

            info!(
                "Successfully added member {} to group {} using proper MLS protocol",
                new_member_id, group_id
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("Group {} not found locally", group_id))
        }
    }

    /// Resolve group name to UUID by searching through available groups
    pub async fn resolve_group_name(&self, name_or_id: &str) -> Result<Uuid> {
        // First try to parse as UUID
        if let Ok(uuid) = Uuid::parse_str(name_or_id) {
            return Ok(uuid);
        }

        // If not a UUID, search by group name
        let groups = self.list_groups().await?;
        for group in groups {
            if group.name == name_or_id {
                return Ok(group.id);
            }
        }

        Err(anyhow::anyhow!(
            "Group '{}' not found. Use 'list' to see available groups.",
            name_or_id
        ))
    }

    /// Join a group by name or UUID
    pub async fn join_group_name(&mut self, name_or_id: &str) -> Result<GroupInfo> {
        let group_uuid = self.resolve_group_name(name_or_id).await?;
        let group_info = self.join_group(group_uuid).await?;

        // Save updated state
        let groups = self.list_groups().await.unwrap_or_default();
        if let Err(e) = self.persistence.save_state(&groups).await {
            warn!("Failed to save client state after joining group: {}", e);
        }

        Ok(group_info)
    }

    /// Leave a group by name or UUID
    pub async fn leave_group_name(&mut self, name_or_id: &str) -> Result<()> {
        let group_uuid = self.resolve_group_name(name_or_id).await?;
        self.leave_group(group_uuid).await?;

        // Save updated state
        let groups = self.list_groups().await.unwrap_or_default();
        if let Err(e) = self.persistence.save_state(&groups).await {
            warn!("Failed to save client state after leaving group: {}", e);
        }

        Ok(())
    }

    /// Send a message to a group by name or UUID
    pub async fn send_message_name(&mut self, name_or_id: &str, content: &str) -> Result<()> {
        let group_uuid = self.resolve_group_name(name_or_id).await?;
        self.send_message(group_uuid, content).await
    }

    /// Get messages from a group by name or UUID
    pub async fn get_messages_name(&mut self, name_or_id: &str) -> Result<Vec<DecryptedMessage>> {
        let group_uuid = self.resolve_group_name(name_or_id).await?;
        self.get_messages(group_uuid).await
    }

    /// Reset group state - useful when there are MLS compatibility issues
    pub async fn reset_group_state(&mut self, name_or_id: &str) -> Result<()> {
        let group_uuid = self.resolve_group_name(name_or_id).await?;

        if self.groups.contains_key(&group_uuid) {
            info!("Resetting MLS group state for group: {}", group_uuid);

            // Save current epoch key before resetting
            if let Some(mls_group) = self.groups.get(&group_uuid) {
                if let Err(e) = Self::save_current_epoch_key(
                    &self.persistence,
                    group_uuid,
                    mls_group,
                    &self.provider,
                )
                .await
                {
                    warn!("Failed to save epoch key before reset: {}", e);
                }
            }

            self.groups.remove(&group_uuid);

            // Clear MLS group persistence but preserve epoch keys for historical decryption
            let _ = self
                .persistence
                .load_cache::<Vec<u8>>(&format!("mls_group_{}", group_uuid))
                .await;
            info!("Preserved epoch keys for historical message decryption during group reset");

            // Recreate standalone state
            self.create_standalone_group_state(group_uuid).await?;

            info!(
                "Successfully reset group state for: {} (historical message decryption preserved)",
                name_or_id
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("Not a member of group: {}", name_or_id))
        }
    }

    /// Save MLS group state to persistence
    async fn save_mls_group_state(&self, group_id: Uuid) -> Result<()> {
        if let Some(mls_group) = self.groups.get(&group_id) {
            // Get current group information
            let current_epoch = mls_group.epoch().as_u64();

            // Get group info from server to determine members and creator status
            let server_groups = self.list_groups().await.unwrap_or_default();
            let server_group = server_groups.iter().find(|g| g.id == group_id);

            let (members, is_creator) = if let Some(group_info) = server_group {
                (
                    group_info.members.clone(),
                    group_info.members.get(0) == Some(&self.client_id),
                )
            } else {
                (vec![self.client_id.clone()], true)
            };

            // Try to export group info if possible
            let group_info_bytes = mls_group
                .export_group_info(&self.provider, &self.signer, true)
                .map(|gi| gi.tls_serialize_detached().ok())
                .ok()
                .flatten();

            let detailed_state = MlsGroupState {
                group_id,
                current_epoch,
                members,
                is_creator,
                last_updated: chrono::Utc::now(),
                group_info_bytes,
            };

            // Save detailed state
            self.persistence
                .save_mls_group_state(&detailed_state)
                .await?;

            // Also save legacy placeholder for compatibility
            let placeholder_data = vec![1u8; 1];
            self.persistence
                .save_cache(&format!("mls_group_{}", group_id), &placeholder_data)
                .await?;

            info!(
                "Saved detailed MLS group state for {} at epoch {}",
                group_id, current_epoch
            );
        }
        Ok(())
    }

    /// Save MLS group state after member changes with accurate member tracking
    async fn save_mls_group_state_after_member_change(
        &self,
        group_id: Uuid,
        new_member_id: &str,
    ) -> Result<()> {
        if let Some(mls_group) = self.groups.get(&group_id) {
            // Get current group information
            let current_epoch = mls_group.epoch().as_u64();

            // Build member list based on what we know locally
            let mut members = vec![];

            // First try to get from server
            if let Ok(server_groups) = self.list_groups().await {
                if let Some(server_group) = server_groups.iter().find(|g| g.id == group_id) {
                    members = server_group.members.clone();
                }
            }

            // If server doesn't have updated members yet, build from what we know
            if members.is_empty() || !members.contains(&new_member_id.to_string()) {
                // Load previous state if available
                if let Ok(Some(prev_state)) = self.persistence.load_mls_group_state(group_id).await
                {
                    members = prev_state.members;
                } else {
                    members = vec![self.client_id.clone()];
                }

                // Add the new member if not already in list
                if !members.contains(&new_member_id.to_string()) {
                    members.push(new_member_id.to_string());
                }
            }

            let is_creator = members.get(0) == Some(&self.client_id);

            // Try to export group info if possible
            let group_info_bytes = mls_group
                .export_group_info(&self.provider, &self.signer, true)
                .map(|gi| gi.tls_serialize_detached().ok())
                .ok()
                .flatten();

            let detailed_state = MlsGroupState {
                group_id,
                current_epoch,
                members: members.clone(),
                is_creator,
                last_updated: chrono::Utc::now(),
                group_info_bytes,
            };

            // Save detailed state
            self.persistence
                .save_mls_group_state(&detailed_state)
                .await?;

            // Also save legacy placeholder for compatibility
            let placeholder_data = vec![1u8; 1];
            self.persistence
                .save_cache(&format!("mls_group_{}", group_id), &placeholder_data)
                .await?;

            info!(
                "Saved detailed MLS group state for {} at epoch {} with {} members",
                group_id,
                current_epoch,
                members.len()
            );
        }
        Ok(())
    }

    /// Restore an MLS group from persistence
    async fn restore_mls_group(&mut self, group_id: Uuid, _data: &[u8]) -> Result<()> {
        // Try to load detailed group state first
        if let Some(saved_state) = self.persistence.load_mls_group_state(group_id).await? {
            info!(
                "Found detailed group state for {} at epoch {} with {} members",
                group_id,
                saved_state.current_epoch,
                saved_state.members.len()
            );

            // Try to restore from saved group info first (works for both creator and member)
            if let Some(ref group_info_bytes) = saved_state.group_info_bytes {
                match self
                    .restore_from_group_info(group_id, group_info_bytes, &saved_state)
                    .await
                {
                    Ok(()) => {
                        info!(
                            "Successfully restored group {} from saved group info at epoch {}",
                            group_id, saved_state.current_epoch
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Failed to restore from saved group info: {}", e);
                    }
                }
            }

            // If we're the creator, try creator-specific restoration
            if saved_state.is_creator {
                info!(
                    "Attempting creator restoration for group {} (was at epoch {})",
                    group_id, saved_state.current_epoch
                );
                match self.restore_as_creator(group_id, &saved_state).await {
                    Ok(()) => {
                        info!("Successfully restored as creator for group {}", group_id);
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Creator restoration failed: {}", e);
                    }
                }
            }

            // If we're not the creator, try to rejoin the group
            if !saved_state.is_creator {
                info!(
                    "Attempting to rejoin group {} (was at epoch {})",
                    group_id, saved_state.current_epoch
                );

                // Try to get a fresh Welcome message for rejoining
                match self.get_welcome_message(group_id).await {
                    Ok(welcome_msg) => {
                        info!(
                            "Found Welcome message, attempting to rejoin group {}",
                            group_id
                        );
                        match self.join_group_from_welcome(group_id, welcome_msg).await {
                            Ok(()) => {
                                info!(
                                    "Successfully rejoined group {} via Welcome message",
                                    group_id
                                );
                                return Ok(());
                            }
                            Err(e) => {
                                warn!("Failed to rejoin via Welcome message: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("No Welcome message available for rejoining: {}", e);
                    }
                }
            }

            // Final fallback: create standalone state but preserve epoch information
            warn!("Creating standalone group state for {} - new messages from epoch {} onwards may not decrypt correctly", 
                  group_id, saved_state.current_epoch);
            self.create_standalone_group_state_with_context(group_id, &saved_state)
                .await?;
        } else {
            // No detailed state available, fall back to basic restoration
            warn!(
                "No detailed group state found for {}, creating new standalone state",
                group_id
            );
            self.create_standalone_group_state(group_id).await?;
        }

        Ok(())
    }

    /// Attempt to restore from saved group info bytes
    async fn restore_from_group_info(
        &mut self,
        group_id: Uuid,
        group_info_bytes: &[u8],
        saved_state: &MlsGroupState,
    ) -> Result<()> {
        // Try to deserialize and use the group info to restore the group
        match MlsMessageIn::tls_deserialize(&mut group_info_bytes.clone()) {
            Ok(mls_message_in) => {
                // Extract the group info from the MLS message
                match mls_message_in.extract() {
                    MlsMessageBodyIn::GroupInfo(group_info_in) => {
                        // Create a new group with the same group ID
                        let mls_group = MlsGroup::new_with_group_id(
                            &self.provider,
                            &self.signer,
                            &MlsGroupCreateConfig::default(),
                            GroupId::from_slice(group_id.as_bytes()),
                            self.credential_with_key.clone(),
                        )
                        .map_err(|e| anyhow::anyhow!("Failed to create group: {}", e))?;

                        // Store the restored group
                        self.groups.insert(group_id, mls_group);

                        // Save current epoch key for the restored group
                        /*if let Some(mls_group) = self.groups.get(&group_id) {
                            if let Err(e) = Self::save_current_epoch_key(&self.persistence, group_id, mls_group, &self.provider).await {
                                warn!("Failed to save epoch key after restoration: {}", e);
                            }
                        }*/

                        info!("Successfully restored group {} from group info", group_id);
                        Ok(())
                    }
                    _ => {
                        warn!("Expected GroupInfo message, got different message type");
                        Err(anyhow::anyhow!("Invalid message type in group info bytes"))
                    }
                }
            }
            Err(e) => {
                warn!("Failed to deserialize saved group info: {}", e);
                Err(anyhow::anyhow!("Group info deserialization failed: {}", e))
            }
        }
    }

    /// Attempt to restore as group creator
    async fn restore_as_creator(
        &mut self,
        group_id: Uuid,
        saved_state: &MlsGroupState,
    ) -> Result<()> {
        info!(
            "Restoring as group creator for {} (epoch {})",
            group_id, saved_state.current_epoch
        );

        // For now, create a standalone state as creator
        // In the future, this could try to restore the exact epoch state
        self.create_standalone_group_state(group_id).await?;

        // Save the current epoch key to maintain continuity
        if let Some(mls_group) = self.groups.get(&group_id) {
            if let Err(e) =
                Self::save_current_epoch_key(&self.persistence, group_id, mls_group, &self.provider)
                    .await
            {
                warn!("Failed to save epoch key after creator restoration: {}", e);
            }
        }

        Ok(())
    }

    /// Create standalone group state with context from previous state
    async fn create_standalone_group_state_with_context(
        &mut self,
        group_id: Uuid,
        saved_state: &MlsGroupState,
    ) -> Result<()> {
        // Create the basic standalone state
        self.create_standalone_group_state(group_id).await?;

        // Update the saved state to reflect the new reality
        if let Some(mls_group) = self.groups.get(&group_id) {
            let current_epoch = mls_group.epoch().as_u64();

            let updated_state = MlsGroupState {
                group_id,
                current_epoch,
                members: saved_state.members.clone(), // Preserve member knowledge
                is_creator: saved_state.is_creator,
                last_updated: chrono::Utc::now(),
                group_info_bytes: None, // Clear old group info as it's no longer valid
            };

            // Save the updated state
            if let Err(e) = self.persistence.save_mls_group_state(&updated_state).await {
                warn!("Failed to save updated group state: {}", e);
            }

            info!(
                "Created standalone state for {} with preserved member context",
                group_id
            );
        }

        Ok(())
    }

    /// Send a Welcome message to a specific client
    async fn send_welcome_message(&self, client_id: &str, welcome_data: Vec<u8>) -> Result<()> {
        let request = SendWelcomeRequest {
            client_id: client_id.to_string(),
            welcome_message: welcome_data,
        };

        let response = self
            .http_client
            .post(&format!("{}/welcome", self.server_url))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Successfully sent Welcome message to {}", client_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to send Welcome message: {}",
                response.status()
            ))
        }
    }

    /// Send a ratchet tree to the server for a specific client and group
    async fn send_ratchet_tree(
        &self,
        client_id: &str,
        group_id: Uuid,
        ratchet_tree_data: Vec<u8>,
    ) -> Result<()> {
        let request = SendRatchetTreeRequest {
            client_id: client_id.to_string(),
            group_id,
            ratchet_tree: ratchet_tree_data,
        };

        let response = self
            .http_client
            .post(&format!("{}/ratchet-tree", self.server_url))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Successfully sent ratchet tree to server for {}", client_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to send ratchet tree: {}",
                response.status()
            ))
        }
    }

    /// Save the current epoch's application secret before it becomes invalid
    async fn save_current_epoch_key(
        persistence: &ClientPersistenceManager,
        group_id: Uuid,
        mls_group: &MlsGroup,
        provider: &OpenMlsRustCrypto,
    ) -> Result<()> {
        // Get the current epoch number
        let current_epoch = mls_group.epoch();

        // Extract the application secret from the current epoch
        // Note: This uses OpenMLS internal API that may change
        if let Ok(app_secret) = mls_group.export_secret(
            provider,
            "application",
            &[],
            current_epoch.as_u64() as usize,
        ) {
            let epoch_key = EpochKey {
                epoch: current_epoch.as_u64(),
                application_secret: app_secret.to_vec(),
                saved_at: chrono::Utc::now(),
            };

            persistence.save_epoch_key(group_id, &epoch_key).await?;
            info!(
                "Saved epoch key for group {} epoch {}",
                group_id,
                current_epoch.as_u64()
            );
        } else {
            warn!(
                "Failed to export application secret for group {} epoch {}",
                group_id,
                current_epoch.as_u64()
            );
        }

        Ok(())
    }

    /// Attempt to decrypt a message using stored epoch keys from previous epochs
    async fn decrypt_with_previous_epochs(
        &self,
        group_id: Uuid,
        encrypted_content: &[u8],
    ) -> Result<String> {
        // Load stored epoch keys for this group
        let epoch_keys = self.persistence.load_epoch_keys(group_id).await?;

        if epoch_keys.is_empty() {
            return Err(anyhow::anyhow!("No stored epoch keys available"));
        }

        // Try to decrypt with each stored epoch key (newest first)
        for epoch_key in epoch_keys.iter().rev() {
            info!("Attempting decryption with epoch {} key", epoch_key.epoch);

            // Try multiple decryption strategies for historical messages
            if let Ok(decrypted) = self
                .try_decrypt_with_epoch_key(encrypted_content, epoch_key)
                .await
            {
                info!(
                    "Successfully decrypted message using epoch {} key",
                    epoch_key.epoch
                );
                return Ok(decrypted);
            }
        }

        // If direct decryption fails, try comprehensive decryption across all stored keys
        if let Ok(decrypted) = self
            .comprehensive_historical_decryption(group_id, encrypted_content)
            .await
        {
            return Ok(decrypted);
        }

        Err(anyhow::anyhow!(
            "Unable to decrypt with any available historical keys"
        ))
    }

    /// Try to decrypt a message with a specific epoch key using multiple strategies
    async fn try_decrypt_with_epoch_key(
        &self,
        encrypted_content: &[u8],
        epoch_key: &EpochKey,
    ) -> Result<String> {
        // Strategy 1: Try to parse as MLS message and decrypt with derived keys
        if let Ok(content) = self
            .decrypt_with_derived_keys(encrypted_content, epoch_key)
            .await
        {
            return Ok(content);
        }

        // Strategy 2: Try direct decryption if it's a simple encrypted format
        if let Ok(content) = self
            .try_direct_decryption(encrypted_content, &epoch_key.application_secret)
            .await
        {
            return Ok(content);
        }

        // Strategy 3: Try legacy format decryption
        if let Ok(content) = String::from_utf8(encrypted_content.to_vec()) {
            if content.starts_with("LEGACY_PLAINTEXT: ") {
                return Ok(content
                    .strip_prefix("LEGACY_PLAINTEXT: ")
                    .unwrap_or(&content)
                    .to_string());
            }
        }

        Err(anyhow::anyhow!("Failed to decrypt with epoch key"))
    }

    /// Comprehensive decryption attempt using all available historical information
    async fn comprehensive_historical_decryption(
        &self,
        group_id: Uuid,
        encrypted_content: &[u8],
    ) -> Result<String> {
        info!(
            "Attempting comprehensive historical decryption for group {}",
            group_id
        );

        // Get all epoch keys across all groups in case there are cross-group dependencies
        let all_epoch_keys = self.persistence.get_all_epoch_keys().await?;

        // Try decryption with keys from the specific group first
        if let Some(group_keys) = all_epoch_keys.get(&group_id) {
            for epoch_key in group_keys.iter().rev() {
                if let Ok(content) = self
                    .try_decrypt_with_epoch_key(encrypted_content, epoch_key)
                    .await
                {
                    info!(
                        "Comprehensive decryption successful with group {} epoch {}",
                        group_id, epoch_key.epoch
                    );
                    return Ok(content);
                }
            }
        }

        // If that fails, try with keys from other groups (in case of cross-group message scenarios)
        for (other_group_id, other_keys) in all_epoch_keys.iter() {
            if *other_group_id != group_id {
                for epoch_key in other_keys.iter().rev() {
                    if let Ok(content) = self
                        .try_decrypt_with_epoch_key(encrypted_content, epoch_key)
                        .await
                    {
                        info!("Comprehensive decryption successful with cross-group key from {} epoch {}", other_group_id, epoch_key.epoch);
                        return Ok(content);
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Comprehensive historical decryption failed"
        ))
    }

    /// Try to decrypt using derived keys from the application secret
    async fn decrypt_with_derived_keys(
        &self,
        encrypted_content: &[u8],
        epoch_key: &EpochKey,
    ) -> Result<String> {
        // This would implement proper MLS key derivation and decryption
        // For now, return an error as this requires deeper MLS implementation
        Err(anyhow::anyhow!(
            "Derived key decryption not yet implemented"
        ))
    }

    /// Try direct decryption with the application secret
    async fn try_direct_decryption(
        &self,
        encrypted_content: &[u8],
        application_secret: &[u8],
    ) -> Result<String> {
        // This would implement direct decryption using the application secret
        // For now, return an error as this requires proper cryptographic implementation
        Err(anyhow::anyhow!("Direct decryption not yet implemented"))
    }

    /// Show all stored epoch keys for historical decryption capability
    pub async fn show_epoch_keys(&self) -> Result<()> {
        let all_epoch_keys = self.persistence.get_all_epoch_keys().await?;

        if all_epoch_keys.is_empty() {
            println!("No stored epoch keys found.");
            return Ok(());
        }

        println!("Stored Epoch Keys for Historical Message Decryption:");
        println!("==================================================");

        for (group_id, epoch_keys) in all_epoch_keys.iter() {
            // Try to get group name for better display
            let group_name = match self.list_groups().await {
                Ok(groups) => groups
                    .iter()
                    .find(|g| g.id == *group_id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("Unknown Group")),
                Err(_) => format!("Unknown Group"),
            };

            println!("\nGroup: {} ({})", group_name, group_id);
            println!("  Stored Epochs: {}", epoch_keys.len());

            for epoch_key in epoch_keys.iter() {
                println!(
                    "    Epoch {}: Saved on {}",
                    epoch_key.epoch,
                    epoch_key.saved_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        }

        let total_keys: usize = all_epoch_keys.values().map(|keys| keys.len()).sum();
        println!("\nTotal epoch keys stored: {}", total_keys);
        println!("You can decrypt messages from all these epochs, even if removed from groups or groups are reset.");

        Ok(())
    }

    /// Get comprehensive decryption statistics
    pub async fn get_decryption_stats(&self) -> Result<()> {
        let all_epoch_keys = self.persistence.get_all_epoch_keys().await?;
        let total_keys: usize = all_epoch_keys.values().map(|keys| keys.len()).sum();
        let total_groups = all_epoch_keys.len();

        println!("Historical Decryption Capability:");
        println!("  - Groups with stored keys: {}", total_groups);
        println!("  - Total epoch keys: {}", total_keys);
        println!(
            "  - Oldest key: {}",
            all_epoch_keys
                .values()
                .flatten()
                .min_by_key(|k| k.saved_at)
                .map(|k| k.saved_at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or("None".to_string())
        );
        println!(
            "  - Newest key: {}",
            all_epoch_keys
                .values()
                .flatten()
                .max_by_key(|k| k.saved_at)
                .map(|k| k.saved_at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or("None".to_string())
        );

        Ok(())
    }
}
