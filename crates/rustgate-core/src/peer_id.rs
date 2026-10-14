// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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

    #[test]
    fn peer_id_and_server_name_are_send_sync_clone_debug_static() {
        // Compile-time bound pin: both newtypes flow across task
        // boundaries (federation manager, etcd/consul reconcile tasks,
        // HA registry, per-connection receive loops). A refactor that
        // embedded a non-`Send` field (raw pointer, `Rc`, `RefCell`) or
        // a borrowed reference would break every downstream caller; pin
        // the full bound locally so the regression surfaces here rather
        // than at a far-away spawn site.
        fn assert_bounds<T: Send + Sync + Clone + std::fmt::Debug + 'static>() {}
        assert_bounds::<PeerId>();
        assert_bounds::<ServerName>();
    }

    #[test]
    fn peer_id_partial_eq_with_str_and_str_ref_impls_both_hold() {
        // Pins BOTH `impl PartialEq<str> for PeerId` and
        // `impl PartialEq<&str> for PeerId`. The two impls are listed
        // as distinct items in the source; a refactor that collapsed
        // them to a single blanket would still compile at most call
        // sites but would silently change the inference behaviour for
        // generic code that bounds on `PartialEq<str>` (no `&`).
        //
        // Use explicit trait-qualified syntax so the intent of
        // exercising each impl is unambiguous — `peer == "x"` in
        // source would resolve to the `&str` impl by type inference,
        // leaving the `str` impl uncovered at runtime.
        let peer = PeerId::new("peer-1");
        assert!(<PeerId as PartialEq<str>>::eq(&peer, "peer-1"));
        assert!(<PeerId as PartialEq<&str>>::eq(&peer, &"peer-1"));
        assert!(!<PeerId as PartialEq<str>>::eq(&peer, "other"));
        assert!(!<PeerId as PartialEq<&str>>::eq(&peer, &"other"));
    }

    #[test]
    fn server_name_partial_eq_with_str_and_str_ref_impls_both_hold() {
        // Same shape as the PeerId test above — the ServerName type
        // carries two separate `PartialEq<str>` / `PartialEq<&str>`
        // impls in source and both need exercising.
        let name = ServerName::new("server-1");
        assert!(<ServerName as PartialEq<str>>::eq(&name, "server-1"));
        assert!(<ServerName as PartialEq<&str>>::eq(&name, &"server-1"));
        assert!(!<ServerName as PartialEq<str>>::eq(&name, "other"));
        assert!(!<ServerName as PartialEq<&str>>::eq(&name, &"other"));
    }

    #[test]
    fn peer_id_accessor_methods_all_agree_on_byte_content() {
        // `as_str` / `AsRef::as_ref` / `Borrow::borrow` / `Display` all
        // expose the inner `String` as a `&str`. A refactor that
        // diverged any one of them (e.g. `as_ref` returning a trimmed
        // slice, `Display` prefixing with a type name) would break
        // either the Prometheus label path, the HashMap-lookup-by-&str
        // path, or the audit-log rendering path — all three are
        // load-bearing and exercised here against one construction.
        let peer = PeerId::new("peer-1");
        let via_as_str: &str = peer.as_str();
        let via_as_ref: &str = <PeerId as AsRef<str>>::as_ref(&peer);
        let via_borrow: &str = <PeerId as Borrow<str>>::borrow(&peer);
        let via_display: String = peer.to_string();
        assert_eq!(via_as_str, "peer-1");
        assert_eq!(via_as_ref, "peer-1");
        assert_eq!(via_borrow, "peer-1");
        assert_eq!(via_display, "peer-1");
        // Pointer identity: the three `&str` accessors all return a
        // reference into the same underlying `String`, not defensive
        // copies. Pins the zero-copy contract at the accessor layer.
        assert!(std::ptr::eq(via_as_str.as_ptr(), via_as_ref.as_ptr()));
        assert!(std::ptr::eq(via_as_str.as_ptr(), via_borrow.as_ptr()));
    }

    #[test]
    fn server_name_accessor_methods_all_agree_on_byte_content() {
        // Same shape as the PeerId accessor-agreement test.
        let name = ServerName::new("server-1");
        let via_as_str: &str = name.as_str();
        let via_as_ref: &str = <ServerName as AsRef<str>>::as_ref(&name);
        let via_borrow: &str = <ServerName as Borrow<str>>::borrow(&name);
        let via_display: String = name.to_string();
        assert_eq!(via_as_str, "server-1");
        assert_eq!(via_as_ref, "server-1");
        assert_eq!(via_borrow, "server-1");
        assert_eq!(via_display, "server-1");
        assert!(std::ptr::eq(via_as_str.as_ptr(), via_as_ref.as_ptr()));
        assert!(std::ptr::eq(via_as_str.as_ptr(), via_borrow.as_ptr()));
    }

    #[test]
    fn peer_id_serde_is_transparent_when_nested_in_a_struct_field() {
        // `#[serde(transparent)]` on the newtype means a `PeerId` value
        // serializes as a bare JSON string (no `{"0": …}` wrapper).
        // A refactor that dropped the attribute would silently change
        // the wire format of every federation peer config file AND
        // every Consul / etcd service entry — operators with hand-rolled
        // peer files would see parse failures at startup. Pin the
        // contract by nesting a `PeerId` inside another struct and
        // asserting the enclosing JSON shape carries the raw string
        // not an inner-tuple wrapper.
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Outer {
            peer: PeerId,
            count: u32,
        }
        let outer = Outer {
            peer: PeerId::new("peer-x"),
            count: 7,
        };
        let json = serde_json::to_string(&outer).unwrap();
        assert_eq!(json, r#"{"peer":"peer-x","count":7}"#);
        let parsed: Outer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outer);
    }

    #[test]
    fn server_name_serde_is_transparent_when_nested_in_a_struct_field() {
        // Same shape as the PeerId serde-transparent test — the
        // `#[serde(transparent)]` attribute is applied independently
        // to ServerName and needs independent pinning.
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Outer {
            name: ServerName,
            count: u32,
        }
        let outer = Outer {
            name: ServerName::new("server-x"),
            count: 9,
        };
        let json = serde_json::to_string(&outer).unwrap();
        assert_eq!(json, r#"{"name":"server-x","count":9}"#);
        let parsed: Outer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outer);
    }

    #[test]
    fn peer_id_and_server_name_keep_distinct_hashmap_keyspaces() {
        // The whole point of these newtypes is type-level mix-up
        // prevention: `HashMap<PeerId, _>` must not accept a
        // `ServerName` key even when the two wrap the same underlying
        // string. This is enforced at compile-time; the runtime check
        // below asserts that inserting one into its own typed map does
        // NOT reach into the other map's keyspace. Together they pin
        // the "newtype equals nominal distinctness" contract.
        use std::collections::HashMap;
        let mut peer_map: HashMap<PeerId, &'static str> = HashMap::new();
        let mut server_map: HashMap<ServerName, &'static str> = HashMap::new();
        let _ = peer_map.insert(PeerId::new("shared-name"), "peer-value");
        let _ = server_map.insert(ServerName::new("shared-name"), "server-value");
        assert_eq!(peer_map.get("shared-name"), Some(&"peer-value"));
        assert_eq!(server_map.get("shared-name"), Some(&"server-value"));
        assert_eq!(peer_map.len(), 1);
        assert_eq!(server_map.len(), 1);
        // A compile-time pin that the two types are not
        // interchangeable: `peer_map.get(&ServerName::new("..."))`
        // would require `ServerName: Borrow<PeerId>` which is not
        // implemented — the intent of the newtype.
    }

    #[test]
    fn peer_id_allows_empty_string_construction_without_validation() {
        // The constructor does not validate — it is a type-level tag,
        // not a semantic gate. Empty strings, whitespace-only strings,
        // and other "suspicious" values are accepted. Pin this so a
        // well-meaning refactor that added `if id.is_empty() { panic! }`
        // (or similar `Result`-returning validation) trips the test
        // before it reaches the federation startup path where peers
        // are constructed from arbitrary config strings.
        let empty = PeerId::new("");
        assert_eq!(empty.as_str(), "");
        assert_eq!(empty.to_string(), "");
        let whitespace = PeerId::new("   ");
        assert_eq!(whitespace.as_str(), "   ");
        let empty_server = ServerName::new("");
        assert_eq!(empty_server.as_str(), "");
    }

    #[test]
    fn peer_id_round_trips_unicode_and_special_characters_verbatim() {
        // Config may carry non-ASCII peer identifiers (SPIFFE URIs with
        // percent-encoded UTF-8, internationalised tenant names). Pin
        // that neither the constructor, the accessor, Display, nor the
        // serde round-trip normalizes / re-encodes / escapes the inner
        // string. A regression that added `.nfc()` on the constructor
        // (well-meaning for ACL-match parity but wrong here, where the
        // type is an opaque tag) would silently corrupt peer IDs on
        // the wire.
        let tricky = "peer/🔒\tα-β\nγ\"'\\";
        let peer = PeerId::new(tricky);
        assert_eq!(peer.as_str(), tricky);
        assert_eq!(peer.to_string(), tricky);
        // serde_json correctly escapes the control chars and quote in
        // the JSON output, but decoding back yields the exact original
        // bytes — pin that round-trip invariant.
        let json = serde_json::to_string(&peer).unwrap();
        let parsed: PeerId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_str(), tricky);
        assert_eq!(parsed, peer);
    }

    #[test]
    fn peer_id_hash_is_consistent_with_equality() {
        // `#[derive(Hash, PartialEq, Eq)]` implies the Rust contract
        // that `a == b` => `hash(a) == hash(b)`. The derive is
        // load-bearing for the `HashMap<PeerId, _>` lookup via
        // `Borrow<str>` — a regression that hand-rolled Hash while
        // keeping the derived PartialEq would silently break cache
        // lookups (keys present in the map never found again) while
        // leaving every other test green. Pin the invariant by
        // comparing two equal PeerIds' hashes through `DefaultHasher`.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let a = PeerId::new("peer-1");
        let b = PeerId::new("peer-1");
        assert_eq!(a, b);
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }
}
