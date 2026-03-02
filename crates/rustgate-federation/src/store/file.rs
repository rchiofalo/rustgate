use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::config::RoutingMode;
use crate::store::{FederateInfo, FederateStore, FederateUpdate};

/// File-backed federate store using JSON serialization.
#[derive(Debug)]
pub struct FileStore {
    path: Option<PathBuf>,
    federates: HashMap<String, FederateInfo>,
}

impl FileStore {
    /// Create a new file store at the given path.
    ///
    /// If `path` is `None`, the store operates in-memory only (no persistence).
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            federates: HashMap::new(),
        }
    }
}

impl FederateStore for FileStore {
    fn load(&mut self) -> anyhow::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        if !path.exists() {
            return Ok(());
        }

        let data = std::fs::read_to_string(path)?;
        let entries: Vec<FederateInfo> = serde_json::from_str(&data)?;

        self.federates.clear();
        for mut entry in entries {
            // Default routing mode for entries that don't have one set
            if entry.routing_mode == RoutingMode::default() {
                // Already defaulted by serde, but ensure consistency
            }
            // Ensure created_at is set
            if entry.created_at == SystemTime::UNIX_EPOCH {
                entry.created_at = SystemTime::now();
            }
            let _ = self.federates.insert(entry.id.clone(), entry);
        }

        Ok(())
    }

    fn save(&self) -> anyhow::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let entries: Vec<&FederateInfo> = self.federates.values().collect();
        let data = serde_json::to_string_pretty(&entries)?;
        std::fs::write(path, data)?;

        Ok(())
    }

    fn add(&mut self, info: FederateInfo) {
        let _ = self.federates.insert(info.id.clone(), info);
    }

    fn get(&self, id: &str) -> Option<&FederateInfo> {
        self.federates.get(id)
    }

    fn list(&self) -> Vec<&FederateInfo> {
        self.federates.values().collect()
    }

    fn list_enabled(&self) -> Vec<&FederateInfo> {
        self.federates.values().filter(|f| f.enabled).collect()
    }

    fn list_outbound(&self) -> Vec<&FederateInfo> {
        self.federates
            .values()
            .filter(|f| f.enabled && f.is_outbound)
            .collect()
    }

    fn remove(&mut self, id: &str) -> bool {
        self.federates.remove(id).is_some()
    }

    fn update(&mut self, id: &str, update: FederateUpdate) -> anyhow::Result<Option<String>> {
        let info = self
            .federates
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("federate not found: {id}"))?;

        let old_address = if let Some(addr) = update.address {
            let old = info.address.clone();
            info.address = addr;
            Some(old)
        } else {
            None
        };

        if let Some(groups) = update.groups {
            info.groups = groups;
        }
        if let Some(is_outbound) = update.is_outbound {
            info.is_outbound = is_outbound;
        }
        if let Some(trust_cert_cn) = update.trust_cert_cn {
            info.trust_cert_cn = trust_cert_cn;
        }

        Ok(old_address)
    }

    fn set_enabled(&mut self, id: &str, enabled: bool) -> anyhow::Result<()> {
        let info = self
            .federates
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("federate not found: {id}"))?;
        info.enabled = enabled;
        Ok(())
    }

    fn set_routing_mode(&mut self, id: &str, mode: RoutingMode) -> anyhow::Result<()> {
        let info = self
            .federates
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("federate not found: {id}"))?;
        info.routing_mode = mode;
        Ok(())
    }

    fn update_last_seen(&mut self, id: &str) {
        if let Some(info) = self.federates.get_mut(id) {
            info.last_seen = Some(SystemTime::now());
        }
    }

    fn update_stats(&mut self, id: &str, sent: u64, recv: u64) {
        if let Some(info) = self.federates.get_mut(id) {
            info.messages_sent += sent;
            info.messages_recv += recv;
        }
    }

    fn count(&self) -> usize {
        self.federates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_info(id: &str) -> FederateInfo {
        FederateInfo {
            id: id.to_string(),
            address: format!("10.0.0.1:{}", 9001),
            groups: vec!["Alpha".into()],
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            created_at: SystemTime::now(),
            last_seen: None,
            messages_sent: 0,
            messages_recv: 0,
        }
    }

    #[test]
    fn add_and_get() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));

        assert!(store.get("peer-1").is_some());
        assert!(store.get("peer-2").is_none());
    }

    #[test]
    fn list_all() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));
        store.add(test_info("peer-2"));

        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn list_enabled() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));
        let mut disabled = test_info("peer-2");
        disabled.enabled = false;
        store.add(disabled);

        assert_eq!(store.list_enabled().len(), 1);
    }

    #[test]
    fn list_outbound() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));
        let mut inbound = test_info("peer-2");
        inbound.is_outbound = false;
        store.add(inbound);

        let outbound = store.list_outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].id, "peer-1");
    }

    #[test]
    fn remove() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));

        assert!(store.remove("peer-1"));
        assert!(!store.remove("peer-1")); // Already removed
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn update_address() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));

        let old = store
            .update(
                "peer-1",
                FederateUpdate {
                    address: Some("10.0.0.2:9001".into()),
                    ..Default::default()
                },
            )
            .expect("update");

        assert_eq!(old, Some("10.0.0.1:9001".into()));
        assert_eq!(
            store.get("peer-1").expect("exists").address,
            "10.0.0.2:9001"
        );
    }

    #[test]
    fn update_nonexistent_returns_error() {
        let mut store = FileStore::new(None);
        let result = store.update("nope", FederateUpdate::default());
        assert!(result.is_err());
    }

    #[test]
    fn set_enabled_toggle() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));

        store.set_enabled("peer-1", false).expect("toggle");
        assert!(!store.get("peer-1").expect("exists").enabled);

        store.set_enabled("peer-1", true).expect("toggle");
        assert!(store.get("peer-1").expect("exists").enabled);
    }

    #[test]
    fn set_routing_mode() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));

        store
            .set_routing_mode("peer-1", RoutingMode::Broadcast)
            .expect("set");
        assert_eq!(
            store.get("peer-1").expect("exists").routing_mode,
            RoutingMode::Broadcast
        );
    }

    #[test]
    fn update_last_seen() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));
        assert!(store.get("peer-1").expect("exists").last_seen.is_none());

        store.update_last_seen("peer-1");
        assert!(store.get("peer-1").expect("exists").last_seen.is_some());
    }

    #[test]
    fn update_stats() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));

        store.update_stats("peer-1", 10, 5);
        let info = store.get("peer-1").expect("exists");
        assert_eq!(info.messages_sent, 10);
        assert_eq!(info.messages_recv, 5);

        store.update_stats("peer-1", 3, 2);
        let info = store.get("peer-1").expect("exists");
        assert_eq!(info.messages_sent, 13);
        assert_eq!(info.messages_recv, 7);
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("federates.json");

        // Save
        {
            let mut store = FileStore::new(Some(path.clone()));
            store.add(test_info("peer-1"));
            store.add(test_info("peer-2"));
            store.save().expect("save");
        }

        // Load
        {
            let mut store = FileStore::new(Some(path));
            store.load().expect("load");
            assert_eq!(store.count(), 2);
            assert!(store.get("peer-1").is_some());
            assert!(store.get("peer-2").is_some());
        }
    }

    #[test]
    fn load_nonexistent_file_is_ok() {
        let mut store = FileStore::new(Some(PathBuf::from("/tmp/does-not-exist-12345.json")));
        assert!(store.load().is_ok());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn load_no_path_is_ok() {
        let mut store = FileStore::new(None);
        assert!(store.load().is_ok());
    }

    #[test]
    fn save_no_path_is_ok() {
        let store = FileStore::new(None);
        assert!(store.save().is_ok());
    }

    #[test]
    fn save_creates_parent_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nested").join("dir").join("federates.json");

        let mut store = FileStore::new(Some(path.clone()));
        store.add(test_info("peer-1"));
        store.save().expect("save");

        assert!(path.exists());
    }

    #[test]
    fn count() {
        let mut store = FileStore::new(None);
        assert_eq!(store.count(), 0);
        store.add(test_info("peer-1"));
        assert_eq!(store.count(), 1);
        store.add(test_info("peer-2"));
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn add_overwrites() {
        let mut store = FileStore::new(None);
        store.add(test_info("peer-1"));
        assert_eq!(
            store.get("peer-1").expect("exists").address,
            "10.0.0.1:9001"
        );

        let mut updated = test_info("peer-1");
        updated.address = "10.0.0.99:9001".into();
        store.add(updated);

        assert_eq!(store.count(), 1);
        assert_eq!(
            store.get("peer-1").expect("exists").address,
            "10.0.0.99:9001"
        );
    }
}
