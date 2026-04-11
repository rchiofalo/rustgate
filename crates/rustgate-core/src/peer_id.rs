// Copyright © 2026 Roberto Chiofalo.

//! Strongly-typed identifiers for federation peers and servers.
//!
//! Provides [`PeerId`] and [`ServerName`] newtypes that wrap `String` to prevent
//! accidental mix-ups between different string identifiers at the type level.

use std::borrow::Borrow;
use std::fmt;

/// Unique identifier for a federation peer.
///
/// Wraps a `String` to prevent accidental mix-ups with other string identifiers
/// like server names, group names, or certificate CNs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct PeerId(String);

impl PeerId {
    /// Create a new `PeerId` from a string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the inner string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl AsRef<str> for PeerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for PeerId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for PeerId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for PeerId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Human-readable or DNS-based name for a federation server.
///
/// Wraps a `String` to prevent accidental mix-ups with peer identifiers
/// and other string types at the type level.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ServerName(String);

impl ServerName {
    /// Create a new `ServerName` from a string.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Get the inner string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ServerName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ServerName {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl AsRef<str> for ServerName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for ServerName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for ServerName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for ServerName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn peer_id_display() {
        let id = PeerId::new("peer-1");
        assert_eq!(id.to_string(), "peer-1");
    }

    #[test]
    fn peer_id_as_str() {
        let id = PeerId::new("peer-1");
        assert_eq!(id.as_str(), "peer-1");
    }

    #[test]
    fn peer_id_into_inner() {
        let id = PeerId::new("peer-1");
        assert_eq!(id.into_inner(), "peer-1");
    }

    #[test]
    fn peer_id_from_string() {
        let id: PeerId = String::from("peer-1").into();
        assert_eq!(id.as_str(), "peer-1");
    }

    #[test]
    fn peer_id_from_str() {
        let id: PeerId = "peer-1".into();
        assert_eq!(id.as_str(), "peer-1");
    }

    #[test]
    fn peer_id_equality() {
        let a = PeerId::new("peer-1");
        let b = PeerId::new("peer-1");
        assert_eq!(a, b);
    }

    #[test]
    fn peer_id_inequality() {
        let a = PeerId::new("peer-1");
        let b = PeerId::new("peer-2");
        assert_ne!(a, b);
    }

    #[test]
    fn peer_id_hash_map_lookup() {
        use std::collections::HashMap;
        let mut map: HashMap<PeerId, i32> = HashMap::new();
        let _ = map.insert(PeerId::new("peer-1"), 42);
        assert_eq!(map.get("peer-1"), Some(&42));
    }

    #[test]
    fn peer_id_serde_round_trip() {
        let id = PeerId::new("peer-1");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"peer-1\"");
        let parsed: PeerId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn peer_id_clone() {
        let a = PeerId::new("peer-1");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn server_name_display() {
        let name = ServerName::new("server-1");
        assert_eq!(name.to_string(), "server-1");
    }

    #[test]
    fn server_name_as_str() {
        let name = ServerName::new("server-1");
        assert_eq!(name.as_str(), "server-1");
    }

    #[test]
    fn server_name_into_inner() {
        let name = ServerName::new("server-1");
        assert_eq!(name.into_inner(), "server-1");
    }

    #[test]
    fn server_name_from_string() {
        let name: ServerName = String::from("server-1").into();
        assert_eq!(name.as_str(), "server-1");
    }

    #[test]
    fn server_name_from_str() {
        let name: ServerName = "server-1".into();
        assert_eq!(name.as_str(), "server-1");
    }

    #[test]
    fn server_name_serde_round_trip() {
        let name = ServerName::new("server-1");
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"server-1\"");
        let parsed: ServerName = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, name);
    }

    #[test]
    fn server_name_hash_map_lookup() {
        use std::collections::HashMap;
        let mut map: HashMap<ServerName, i32> = HashMap::new();
        let _ = map.insert(ServerName::new("server-1"), 42);
        assert_eq!(map.get("server-1"), Some(&42));
    }

    #[test]
    fn types_are_not_interchangeable() {
        // This test documents the intent: PeerId and ServerName are distinct types.
        // The following would NOT compile if uncommented:
        // let peer: PeerId = ServerName::new("name").into();
        let _peer = PeerId::new("id");
        let _server = ServerName::new("name");
    }
}
