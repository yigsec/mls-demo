use anyhow::Result;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;
use reqwest::Client;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

pub struct MlsClient {
    client_id: String,
    server_url: String,
    http_client: Client,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
    key_packages: HashMap<Uuid, KeyPackage>,
    groups: HashMap<Uuid, MlsGroup>,
}

impl MlsClient {
    pub async fn new(server_url: String, client_id: String) -> Result<Self> {
        let http_client = Client::new();
        
        // Initialize OpenMLS crypto provider
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        
        // Generate a credential for this client
        let credential = Credential::new(
            client_id.as_bytes().to_vec(),
            CredentialType::Basic,
        )?;
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("Error generating signature key pair");
        
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
            key_packages: HashMap::new(),
            groups: HashMap::new(),
        };

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
            info!("Created group: {} ({})", group_info.name, group_info.id);
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
            info!("Joined group: {} ({})", group_info.name, group_info.id);
            Ok(group_info)
        } else {
            Err(anyhow::anyhow!("Failed to join group: {}", response.status()))
        }
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
            self.groups.remove(&group_id);
            info!("Left group: {}", group_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to leave group: {}",
                response.status()
            ))
        }
    }

    pub async fn send_message(&self, group_id: Uuid, content: &str) -> Result<()> {
        let request = SendMessageRequest {
            sender: self.client_id.clone(),
            content: content.to_string(),
        };

        let response = self
            .http_client
            .post(&format!(
                "{}/groups/{}/messages",
                self.server_url, group_id
            ))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Sent message to group: {}", group_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to send message: {}",
                response.status()
            ))
        }
    }

    pub async fn get_messages(&self, group_id: Uuid) -> Result<Vec<MlsMessage>> {
        let response = self
            .http_client
            .get(&format!(
                "{}/groups/{}/messages",
                self.server_url, group_id
            ))
            .send()
            .await?;

        if response.status().is_success() {
            let messages: Vec<MlsMessage> = response.json().await?;
            Ok(messages)
        } else {
            Err(anyhow::anyhow!(
                "Failed to get messages: {}",
                response.status()
            ))
        }
    }

    pub async fn upload_key_package(&self) -> Result<()> {
        // Generate a new key package
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let provider = OpenMlsRustCrypto::default();
        
        let key_package = KeyPackage::builder()
            .build(
                CryptoConfig::with_default_version(ciphersuite),
                &provider,
                &self.signer,
                self.credential_with_key.clone(),
            )?;

        let key_package_bytes = key_package.tls_serialize_detached()?;

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
} 