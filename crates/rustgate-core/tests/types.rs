// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for rustgate-core foundational types.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::{AttrValue, GroupId, Identity, IdentityError};
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::peer_id::{PeerId, ServerName};
use rustgate_core::protocol::{FramingStrategy, HeaderSize};

// ---------------------------------------------------------------------------
// Identity tests
// ---------------------------------------------------------------------------

fn make_groups(names: &[&str]) -> BTreeSet<GroupId> {
    names.iter().map(|s| s.to_string()).collect()
}

fn make_identity(cn: &str, fp: &str, groups: &[&str]) -> Identity {
    Identity::new(cn.to_string(), fp.to_string(), make_groups(groups)).unwrap()
}

#[test]
fn identity_creation_with_cn_fingerprint_groups() {
    let id = make_identity("alice", "aa:bb:cc", &["Alpha", "Bravo"]);
    assert_eq!(id.cn, "alice");
    assert_eq!(id.fingerprint, "aa:bb:cc");
    assert_eq!(id.groups.len(), 2);
}

#[test]
fn identity_is_member_of_existing_group() {
    let id = make_identity("alice", "fp", &["Alpha", "Bravo"]);
    assert!(id.is_member_of("Alpha"));
    assert!(id.is_member_of("Bravo"));
}

#[test]
fn identity_is_member_of_nonexistent_group() {
    let id = make_identity("alice", "fp", &["Alpha"]);
    assert!(!id.is_member_of("Charlie"));
}

#[test]
fn identity_empty_groups() {
    let id = make_identity("alice", "fp", &[]);
    assert!(id.groups.is_empty());
    assert!(!id.is_member_of("anything"));
}

#[test]
fn identity_display_shows_cn() {
    let id = make_identity("alice", "fp", &[]);
    assert_eq!(format!("{id}"), "alice");
}

#[test]
fn identity_equality_and_hash() {
    let a = make_identity("alice", "fp", &["Alpha"]);
    let b = make_identity("alice", "fp", &["Alpha"]);
    assert_eq!(a, b);

    // Hash consistency: equal values produce equal hashes.
    use std::hash::{Hash, Hasher};
    let mut ha = std::collections::hash_map::DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = std::collections::hash_map::DefaultHasher::new();
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn identity_inequality_different_cn() {
    let a = make_identity("alice", "fp", &[]);
    let b = make_identity("bob", "fp", &[]);
    assert_ne!(a, b);
}

#[test]
fn identity_btreeset_ordering_of_groups() {
    let id = make_identity("alice", "fp", &["Charlie", "Alpha", "Bravo"]);
    let ordered: Vec<&String> = id.groups.iter().collect();
    assert_eq!(ordered, vec!["Alpha", "Bravo", "Charlie"]);
}

#[test]
fn identity_plaintext_has_empty_fingerprint() {
    let id = Identity::plaintext("udp-anon".to_string(), BTreeSet::new()).unwrap();
    assert_eq!(id.fingerprint, "");
}

#[test]
fn identity_rejects_empty_cn() {
    let result = Identity::new(String::new(), "fp".to_string(), BTreeSet::new());
    assert!(matches!(result.unwrap_err(), IdentityError::EmptyCn));
}

#[test]
fn identity_rejects_empty_fingerprint() {
    let result = Identity::new("alice".to_string(), String::new(), BTreeSet::new());
    assert!(matches!(
        result.unwrap_err(),
        IdentityError::EmptyFingerprint
    ));
}

#[test]
fn identity_rejects_control_chars_in_cn() {
    let result = Identity::new("alice\x00".to_string(), "fp".to_string(), BTreeSet::new());
    assert!(matches!(
        result.unwrap_err(),
        IdentityError::CnContainsControlChars
    ));
}

// ---------------------------------------------------------------------------
// Identity attribute / SPIFFE tests
// ---------------------------------------------------------------------------

#[test]
fn identity_defaults_empty_attributes_and_no_spiffe() {
    let id = make_identity("alice", "fp", &[]);
    assert!(id.attributes.is_empty());
    assert!(id.spiffe_id.is_none());
}

#[test]
fn identity_builder_with_attributes_and_spiffe() {
    let mut attrs = std::collections::BTreeMap::new();
    let _ = attrs.insert("org".to_string(), AttrValue::Str("Acme".to_string()));
    let _ = attrs.insert(
        "san_dns".to_string(),
        AttrValue::Set(vec!["a.example.com".to_string()]),
    );
    let id = make_identity("alice", "fp", &[])
        .with_attributes(attrs.clone())
        .with_spiffe_id("spiffe://example.org/svc/alice");

    assert_eq!(
        id.spiffe_id.as_deref(),
        Some("spiffe://example.org/svc/alice")
    );
    assert_eq!(
        id.attributes.get("org"),
        Some(&AttrValue::Str("Acme".to_string()))
    );
}

#[test]
fn identity_equality_considers_attributes_and_spiffe() {
    let a = make_identity("alice", "fp", &[]).with_spiffe_id("spiffe://ex/a");
    let b = make_identity("alice", "fp", &[]).with_spiffe_id("spiffe://ex/b");
    assert_ne!(a, b);
    let c = make_identity("alice", "fp", &[]);
    let d = make_identity("alice", "fp", &[]);
    assert_eq!(c, d);
}

#[test]
fn attr_value_serde_round_trip() {
    let values = vec![
        AttrValue::Str("hello".to_string()),
        AttrValue::Int(42),
        AttrValue::Bool(true),
        AttrValue::Set(vec!["a".to_string(), "b".to_string()]),
    ];
    for v in values {
        let json = serde_json::to_string(&v).unwrap();
        let decoded: AttrValue = serde_json::from_str(&json).unwrap();
        assert_eq!(v, decoded);
    }
}

// ---------------------------------------------------------------------------
// RoutableMessage tests
// ---------------------------------------------------------------------------

fn make_source() -> Identity {
    make_identity("sender", "aa:bb", &[])
}

fn make_metadata() -> Metadata {
    Metadata {
        received_at: SystemTime::now(),
        source_protocol: "tcp".to_string(),
        message_type: MessageType::Position,
        ttl: None,
    }
}

#[test]
fn routable_message_with_broadcast_destination() {
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Broadcast,
        payload: Bytes::from_static(b"hello"),
        metadata: make_metadata(),
    };
    assert!(matches!(msg.destination, Destination::Broadcast));
    assert_eq!(&msg.payload[..], b"hello");
}

#[test]
fn routable_message_with_group_destination() {
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Group("team-alpha".to_string()),
        payload: Bytes::from_static(b"data"),
        metadata: make_metadata(),
    };
    assert!(matches!(msg.destination, Destination::Group(ref g) if g == "team-alpha"));
}

#[test]
fn routable_message_with_direct_destination() {
    let target = make_identity("bob", "bb:cc", &[]);
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Direct(target),
        payload: Bytes::from_static(b"secret"),
        metadata: make_metadata(),
    };
    assert!(matches!(msg.destination, Destination::Direct(ref id) if id.cn == "bob"));
}

#[test]
fn routable_message_payload_preservation() {
    let payload = Bytes::from(vec![0u8, 1, 2, 255, 254, 253]);
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Broadcast,
        payload: payload.clone(),
        metadata: make_metadata(),
    };
    assert_eq!(msg.payload, payload);
}

#[test]
fn routable_message_metadata_fields() {
    let now = SystemTime::now();
    let meta = Metadata {
        received_at: now,
        source_protocol: "websocket".to_string(),
        message_type: MessageType::Chat,
        ttl: Some(Duration::from_secs(60)),
    };
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Broadcast,
        payload: Bytes::new(),
        metadata: meta,
    };
    assert_eq!(msg.metadata.source_protocol, "websocket");
    assert_eq!(msg.metadata.ttl, Some(Duration::from_secs(60)));
    assert!(matches!(msg.metadata.message_type, MessageType::Chat));
}

#[test]
fn routable_message_no_ttl() {
    let meta = Metadata {
        received_at: SystemTime::now(),
        source_protocol: "tcp".to_string(),
        message_type: MessageType::Status,
        ttl: None,
    };
    assert!(meta.ttl.is_none());
}

#[test]
fn routable_message_large_payload() {
    let large = vec![42u8; 10 * 1024 * 1024]; // 10 MB
    let payload = Bytes::from(large);
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Broadcast,
        payload,
        metadata: make_metadata(),
    };
    assert_eq!(msg.payload.len(), 10 * 1024 * 1024);
}

#[test]
fn routable_message_empty_payload() {
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Broadcast,
        payload: Bytes::new(),
        metadata: make_metadata(),
    };
    assert!(msg.payload.is_empty());
}

#[test]
fn routable_message_clone() {
    let msg = RoutableMessage {
        source: make_source(),
        destination: Destination::Broadcast,
        payload: Bytes::from_static(b"test"),
        metadata: make_metadata(),
    };
    let cloned = msg.clone();
    assert_eq!(cloned.source.cn, msg.source.cn);
    assert_eq!(cloned.payload, msg.payload);
}

// ---------------------------------------------------------------------------
// Destination tests
// ---------------------------------------------------------------------------

#[test]
fn destination_group_name_preservation() {
    let dest = Destination::Group("team-bravo".to_string());
    match &dest {
        Destination::Group(name) => assert_eq!(name, "team-bravo"),
        other => panic!("expected Group variant, got {other:?}"),
    }
}

#[test]
fn destination_direct_identity_equality() {
    let id = make_identity("alice", "fp", &["Alpha"]);
    let dest = Destination::Direct(id.clone());
    match &dest {
        Destination::Direct(inner) => assert_eq!(inner, &id),
        other => panic!("expected Direct variant, got {other:?}"),
    }
}

#[test]
fn destination_pattern_matching_all_variants() {
    let variants: [Destination; 4] = [
        Destination::Broadcast,
        Destination::Group("g".to_string()),
        Destination::Direct(make_identity("x", "fp", &[])),
        Destination::Multicast(vec!["a".to_string(), "b".to_string()]),
    ];
    for dest in &variants {
        match dest {
            Destination::Broadcast => {}
            Destination::Group(_) => {}
            Destination::Direct(_) => {}
            Destination::Multicast(_) => {}
        }
    }
    assert_eq!(variants.len(), 4);
}

#[test]
fn destination_clone_semantics() {
    let dest = Destination::Group("ops".to_string());
    let cloned = dest.clone();
    assert!(matches!(cloned, Destination::Group(ref g) if g == "ops"));
}

#[test]
fn destination_display() {
    assert_eq!(Destination::Broadcast.to_string(), "broadcast");
    assert_eq!(
        Destination::Group("alpha".to_string()).to_string(),
        "group:alpha"
    );
    let id = make_identity("bob", "fp", &[]);
    assert_eq!(Destination::Direct(id).to_string(), "direct:bob");
}

// ---------------------------------------------------------------------------
// MessageType tests
// ---------------------------------------------------------------------------

#[test]
fn message_type_all_variants() {
    let variants = [
        MessageType::Position,
        MessageType::Chat,
        MessageType::Alert,
        MessageType::Status,
        MessageType::File,
        MessageType::Other("custom".to_string()),
    ];
    assert_eq!(variants.len(), 6);
}

#[test]
fn message_type_other_preserves_string() {
    let mt = MessageType::Other("my-protocol".to_string());
    match &mt {
        MessageType::Other(s) => assert_eq!(s, "my-protocol"),
        other => panic!("expected Other variant, got {other:?}"),
    }
}

#[test]
fn message_type_equality() {
    assert_eq!(MessageType::Position, MessageType::Position);
    assert_eq!(
        MessageType::Other("x".to_string()),
        MessageType::Other("x".to_string())
    );
}

#[test]
fn message_type_inequality() {
    assert_ne!(MessageType::Position, MessageType::Chat);
    assert_ne!(
        MessageType::Other("a".to_string()),
        MessageType::Other("b".to_string())
    );
    assert_ne!(MessageType::File, MessageType::Other("file".to_string()));
}

#[test]
fn message_type_display() {
    assert_eq!(MessageType::Position.to_string(), "position");
    assert_eq!(MessageType::Chat.to_string(), "chat");
    assert_eq!(MessageType::Alert.to_string(), "alert");
    assert_eq!(MessageType::Status.to_string(), "status");
    assert_eq!(MessageType::File.to_string(), "file");
    assert_eq!(
        MessageType::Other("custom".to_string()).to_string(),
        "other:custom"
    );
}

#[test]
fn message_type_clone() {
    let mt = MessageType::Other("test".to_string());
    let cloned = mt.clone();
    assert_eq!(mt, cloned);
}

// ---------------------------------------------------------------------------
// FramingStrategy & HeaderSize tests
// ---------------------------------------------------------------------------

#[test]
fn header_size_byte_count_one() {
    assert_eq!(HeaderSize::One.byte_count(), 1);
}

#[test]
fn header_size_byte_count_two() {
    assert_eq!(HeaderSize::Two.byte_count(), 2);
}

#[test]
fn header_size_byte_count_four() {
    assert_eq!(HeaderSize::Four.byte_count(), 4);
}

#[test]
fn header_size_equality() {
    assert_eq!(HeaderSize::One, HeaderSize::One);
    assert_ne!(HeaderSize::One, HeaderSize::Two);
    assert_ne!(HeaderSize::Two, HeaderSize::Four);
}

#[test]
fn header_size_copy() {
    let a = HeaderSize::Four;
    let b = a; // Copy
    assert_eq!(a, b); // `a` is still usable because HeaderSize is Copy
}

#[test]
fn framing_strategy_length_prefixed() {
    let fs = FramingStrategy::LengthPrefixed {
        header_size: HeaderSize::Two,
    };
    assert!(matches!(
        fs,
        FramingStrategy::LengthPrefixed {
            header_size: HeaderSize::Two
        }
    ));
}

#[test]
fn framing_strategy_xml_stream() {
    let fs = FramingStrategy::XmlStream;
    assert!(matches!(fs, FramingStrategy::XmlStream));
}

#[test]
fn framing_strategy_line_delimited() {
    let fs = FramingStrategy::LineDelimited;
    assert!(matches!(fs, FramingStrategy::LineDelimited));
}

#[test]
fn framing_strategy_tak_protobuf() {
    let fs = FramingStrategy::TakProtobuf;
    assert!(matches!(fs, FramingStrategy::TakProtobuf));
}

#[test]
fn framing_strategy_clone_and_debug() {
    let fs = FramingStrategy::XmlStream;
    let cloned = fs.clone();
    // Debug impl exists if this compiles and produces non-empty output.
    let debug = format!("{cloned:?}");
    assert!(!debug.is_empty());
}

// ---------------------------------------------------------------------------
// PeerId tests
// ---------------------------------------------------------------------------

#[test]
fn peer_id_creation_and_display() {
    let id = PeerId::new("peer-1");
    assert_eq!(id.to_string(), "peer-1");
}

#[test]
fn peer_id_as_ref_str() {
    let id = PeerId::new("peer-1");
    let s: &str = id.as_ref();
    assert_eq!(s, "peer-1");
}

#[test]
fn peer_id_borrow_str() {
    use std::borrow::Borrow;
    let id = PeerId::new("peer-1");
    let s: &str = id.borrow();
    assert_eq!(s, "peer-1");
}

#[test]
fn peer_id_partial_eq_str() {
    let id = PeerId::new("peer-1");
    assert!(id == *"peer-1");
    assert!(id == "peer-1");
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
fn peer_id_hashmap_lookup_via_str() {
    let mut map: HashMap<PeerId, i32> = HashMap::new();
    let _ = map.insert(PeerId::new("peer-1"), 42);
    assert_eq!(map.get("peer-1"), Some(&42));
}

#[test]
fn peer_id_into_inner() {
    let id = PeerId::new("peer-1");
    let inner: String = id.into_inner();
    assert_eq!(inner, "peer-1");
}

// ---------------------------------------------------------------------------
// ServerName tests
// ---------------------------------------------------------------------------

#[test]
fn server_name_creation_and_display() {
    let name = ServerName::new("server-east");
    assert_eq!(name.to_string(), "server-east");
}

#[test]
fn server_name_as_ref_str() {
    let name = ServerName::new("server-east");
    let s: &str = name.as_ref();
    assert_eq!(s, "server-east");
}

#[test]
fn server_name_borrow_str() {
    use std::borrow::Borrow;
    let name = ServerName::new("server-east");
    let s: &str = name.borrow();
    assert_eq!(s, "server-east");
}

#[test]
fn server_name_partial_eq_str() {
    let name = ServerName::new("server-east");
    assert!(name == *"server-east");
    assert!(name == "server-east");
}

#[test]
fn server_name_serde_round_trip() {
    let name = ServerName::new("server-east");
    let json = serde_json::to_string(&name).unwrap();
    assert_eq!(json, "\"server-east\"");
    let parsed: ServerName = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, name);
}

#[test]
fn server_name_hashmap_lookup_via_str() {
    let mut map: HashMap<ServerName, i32> = HashMap::new();
    let _ = map.insert(ServerName::new("server-east"), 99);
    assert_eq!(map.get("server-east"), Some(&99));
}

#[test]
fn peer_id_and_server_name_are_distinct_types() {
    // This test documents that PeerId and ServerName are not interchangeable.
    // A function accepting PeerId won't accept ServerName and vice versa.
    fn takes_peer_id(id: &PeerId) -> &str {
        id.as_str()
    }
    fn takes_server_name(name: &ServerName) -> &str {
        name.as_str()
    }
    let peer = PeerId::new("p1");
    let server = ServerName::new("s1");
    assert_eq!(takes_peer_id(&peer), "p1");
    assert_eq!(takes_server_name(&server), "s1");
}

#[test]
fn metadata_is_expired_no_ttl() {
    let m = Metadata {
        received_at: SystemTime::now(),
        source_protocol: "tcp".into(),
        message_type: MessageType::Position,
        ttl: None,
    };
    assert!(!m.is_expired());
}

#[test]
fn metadata_is_expired_future_ttl() {
    let m = Metadata {
        received_at: SystemTime::now(),
        source_protocol: "tcp".into(),
        message_type: MessageType::Position,
        ttl: Some(Duration::from_secs(3600)),
    };
    assert!(!m.is_expired());
}

#[test]
fn metadata_is_expired_past_ttl() {
    let m = Metadata {
        received_at: SystemTime::now() - Duration::from_secs(10),
        source_protocol: "tcp".into(),
        message_type: MessageType::Position,
        ttl: Some(Duration::from_secs(1)),
    };
    assert!(m.is_expired());
}
