use std::collections::HashMap;

pub struct MlsManager {
    key_packages: HashMap<String, Vec<u8>>,
}

impl MlsManager {
    pub fn new() -> Self {
        Self {
            key_packages: HashMap::new(),
        }
    }

    pub fn store_key_package(&mut self, client_id: String, key_package: Vec<u8>) {
        self.key_packages.insert(client_id, key_package);
    }

    pub fn get_key_package(&self, client_id: &str) -> Option<Vec<u8>> {
        self.key_packages.get(client_id).cloned()
    }

    pub fn remove_key_package(&mut self, client_id: &str) -> Option<Vec<u8>> {
        self.key_packages.remove(client_id)
    }
} 