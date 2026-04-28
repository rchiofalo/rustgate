// Copyright © 2026 Roberto Chiofalo.

//! `RoutableMessage` ↔ `FederatedEvent` conversions.
//!
//! Bridges the internal routing layer (`RoutableMessage`) with the V2
//! federation wire format (`FederatedEvent`). Also provides metadata
//! extraction for provenance tracking.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::message::{
    Destination, MessageType, Metadata, RoutableMessage, SOURCE_FEDERATION,
};

use super::ConvertError;
use super::cot_to_event::{federated_event_to_xml, xml_to_federated_event};
use super::proto::figpb;
use crate::provenance::FederationMetadata;

// ---------------------------------------------------------------------------
// RoutableMessage → FederatedEvent
// ---------------------------------------------------------------------------

/// Convert a `RoutableMessage` (with XML payload) into a `FederatedEvent`.
///
/// The source identity's groups are merged with any groups found in the
/// CoT XML detail section to form the `federate_groups` list.
pub fn routable_to_federated_event(
    msg: &RoutableMessage,
    metadata: &FederationMetadata,
) -> Result<figpb::FederatedEvent, ConvertError> {
    let mut event = xml_to_federated_event(&msg.payload, metadata)?;

    // Merge source identity groups into federate_groups
    for group in &msg.source.groups {
        if !event.federate_groups.contains(group) {
            event.federate_groups.push(group.clone());
        }
    }

    // If destination is a specific group, ensure it's in federate_groups.
    // `Destination::Group` / `Multicast` are now `Arc<str>` for fan-out
    // (closes #784); the wire format remains `Vec<String>`, so deref the
    // `Arc<str>` to `&str` for the membership probe and clone bytes
    // into a fresh `String` only when actually appending.
    match &msg.destination {
        Destination::Group(group_id) if !event.federate_groups.iter().any(|g| g == &**group_id) => {
            event.federate_groups.push(group_id.to_string());
        }
        Destination::Multicast(groups) => {
            for group_id in groups {
                if !event.federate_groups.iter().any(|g| g == &**group_id) {
                    event.federate_groups.push(group_id.to_string());
                }
            }
        }
        _ => {}
    }

    Ok(event)
}

// ---------------------------------------------------------------------------
// FederatedEvent → RoutableMessage
// ---------------------------------------------------------------------------

/// Convert a `FederatedEvent` into a `RoutableMessage` with an XML payload.
///
/// Creates an identity from the peer's certificate information and determines
/// the destination from the event's `federate_groups`.
///
/// # Trust boundary
///
/// `trust_peer_groups` controls whether the wire-claimed `federate_groups`
/// field is accepted as the authoritative group set for the origin CN.
/// A Byzantine peer with a valid mTLS client certificate can forge
/// arbitrary group memberships for any origin CN in that field, so the
/// default is `false` (deny-by-default). When `false`, the source
/// identity is constructed with the empty group set and any wire-claimed
/// groups are reported via [`rustgate_core::audit::federation_group_claim_rejected`].
/// The destination is derived from the wire-claimed groups regardless —
/// those merely express the sender's routing intent, not a trust claim.
///
/// Set `trust_peer_groups = true` only when every federation peer is
/// fully trusted to speak for every origin CN on its side of the
/// federation (e.g. single-operator multi-region deployments with a
/// single shared identity authority).
pub fn federated_event_to_routable(
    event: &figpb::FederatedEvent,
    peer_cn: &str,
    peer_fingerprint: &str,
    trust_peer_groups: bool,
) -> Result<RoutableMessage, ConvertError> {
    let xml = federated_event_to_xml(event)?;

    // Trust-boundary decision: wire-claimed `federate_groups` are
    // advisory metadata. Without `trust_peer_groups=true`, drop them
    // and build the source identity with the empty group set (the
    // receiver should substitute its own locally-known membership for
    // the origin CN if it has any; absent that, deny-by-default).
    let groups: BTreeSet<GroupId> = if trust_peer_groups {
        event.federate_groups.iter().cloned().collect()
    } else {
        if !event.federate_groups.is_empty() {
            rustgate_core::audit::federation_group_claim_rejected(
                peer_cn,
                peer_cn,
                &event.federate_groups,
            );
        }
        BTreeSet::new()
    };

    let source = if peer_fingerprint.is_empty() {
        Identity::plaintext(peer_cn.to_string(), groups)
    } else {
        Identity::new(peer_cn.to_string(), peer_fingerprint.to_string(), groups)
    }
    .map_err(|e| ConvertError::InvalidField(format!("invalid peer identity: {e}")))?;

    // Determine destination: if exactly one group, route to that group;
    // otherwise broadcast to all. `federate_groups` expresses routing
    // intent (where the sender wants the event delivered), not an
    // authorization claim — the local ACL/authz layer re-evaluates
    // delivery on the receive side.
    let destination = if event.federate_groups.len() == 1 {
        Destination::Group(event.federate_groups[0].as_str().into())
    } else {
        Destination::Broadcast
    };

    // Infer message type from CoT type attribute
    let message_type = event
        .event
        .as_ref()
        .map(|geo| infer_message_type(&geo.r#type))
        .unwrap_or(MessageType::Other("unknown".to_string()));

    // Compute TTL from start/stale times if available
    let ttl = event.event.as_ref().and_then(|geo| {
        if geo.stale_time > 0 && geo.start_time > 0 && geo.stale_time > geo.start_time {
            let diff_ms = (geo.stale_time - geo.start_time) as u64;
            Some(Duration::from_millis(diff_ms))
        } else {
            None
        }
    });

    Ok(RoutableMessage {
        source,
        destination,
        payload: Bytes::from(xml),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: SOURCE_FEDERATION.to_string(),
            message_type,
            ttl,
        },
    })
}

// ---------------------------------------------------------------------------
// FederationMetadata ↔ FederatedEvent provenance
// ---------------------------------------------------------------------------

/// Extract `FederationMetadata` from a `FederatedEvent`'s provenance fields.
pub fn extract_metadata(event: &figpb::FederatedEvent) -> FederationMetadata {
    let provenance = event
        .federate_provenance
        .iter()
        .map(|p| crate::provenance::FederateProvenance {
            server_id: rustgate_core::PeerId::new(&p.federation_server_id),
            server_name: rustgate_core::ServerName::new(&p.federation_server_name),
        })
        .collect();

    let (max_hops, current_hops) = event
        .federate_hops
        .as_ref()
        .map(|h| (h.max_hops as u32, h.current_hops as u32))
        .unwrap_or((10, 0));

    FederationMetadata {
        provenance,
        max_hops,
        current_hops,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Infer the message type from a CoT type string.
fn infer_message_type(cot_type: &str) -> MessageType {
    if cot_type.starts_with("a-") {
        MessageType::Position
    } else if cot_type.starts_with("b-t-f") {
        MessageType::Chat
    } else if cot_type.starts_with("b-a") {
        MessageType::Alert
    } else {
        MessageType::Other(cot_type.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;
    use crate::provenance::FederationMetadata;

    fn sample_xml() -> &'static [u8] {
        b"<event version=\"2.0\" uid=\"ALPHA-1\" type=\"a-f-G-U-C\" how=\"m-g\" \
          time=\"2021-02-27T20:32:24.000Z\" start=\"2021-02-27T20:32:24.000Z\" \
          stale=\"2021-02-27T20:37:24.000Z\">\
          <point lat=\"38.8977\" lon=\"-77.0365\" hae=\"10.5\" ce=\"50.0\" le=\"30.0\"/>\
          <detail>\
            <contact callsign=\"ALPHA\" endpoint=\"*:-1:stcp\"/>\
            <__group name=\"Cyan\" role=\"Team Lead\"/>\
            <track speed=\"10.5\" course=\"90.0\"/>\
            <precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/>\
            <status battery=\"85\"/>\
          </detail>\
          </event>"
    }

    fn empty_metadata() -> FederationMetadata {
        FederationMetadata {
            provenance: Vec::new(),
            max_hops: 10,
            current_hops: 0,
        }
    }

    fn sample_metadata() -> FederationMetadata {
        FederationMetadata {
            provenance: vec![crate::provenance::FederateProvenance {
                server_id: rustgate_core::PeerId::new("server-1"),
                server_name: rustgate_core::ServerName::new("Server One"),
            }],
            max_hops: 10,
            current_hops: 1,
        }
    }

    // --- routable_to_federated_event tests ---

    #[test]
    fn routable_to_event_merges_source_groups() {
        let mut groups = BTreeSet::new();
        let _ = groups.insert("Alpha".to_string());
        let _ = groups.insert("Bravo".to_string());

        let msg = RoutableMessage {
            source: Identity::new("test-peer".into(), "abc123".into(), groups)
                .expect("valid identity"),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(sample_xml()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: SOURCE_FEDERATION.to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };

        let event = routable_to_federated_event(&msg, &empty_metadata()).expect("conversion");

        // Should contain "Cyan" from XML + "Alpha" and "Bravo" from source
        assert!(event.federate_groups.contains(&"Cyan".to_string()));
        assert!(event.federate_groups.contains(&"Alpha".to_string()));
        assert!(event.federate_groups.contains(&"Bravo".to_string()));
    }

    #[test]
    fn routable_to_event_includes_destination_group() {
        let msg = RoutableMessage {
            source: Identity {
                cn: "test-peer".into(),
                fingerprint: "abc123".into(),
                groups: BTreeSet::new(),
                tenant: None,
                spiffe_id: None,
                attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
            },
            destination: Destination::Group("Delta".into()),
            payload: Bytes::from_static(sample_xml()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: SOURCE_FEDERATION.to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };

        let event = routable_to_federated_event(&msg, &empty_metadata()).expect("conversion");
        assert!(event.federate_groups.contains(&"Delta".to_string()));
    }

    // --- federated_event_to_routable tests ---

    #[test]
    fn event_to_routable_source_identity() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let msg = federated_event_to_routable(&event, "peer-1", "fingerprint-abc", false)
            .expect("conversion");
        assert_eq!(&*msg.source.cn, "peer-1");
        assert_eq!(msg.source.fingerprint, "fingerprint-abc");
    }

    #[test]
    fn event_to_routable_source_protocol() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let msg = federated_event_to_routable(&event, "peer-1", "fp", false).expect("conversion");
        assert_eq!(msg.metadata.source_protocol, SOURCE_FEDERATION);
    }

    #[test]
    fn event_to_routable_message_type_position() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let msg = federated_event_to_routable(&event, "peer-1", "fp", false).expect("conversion");
        assert_eq!(msg.metadata.message_type, MessageType::Position);
    }

    #[test]
    fn event_to_routable_single_group_routes_to_group() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            federate_groups: vec!["OnlyGroup".into()],
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp", false).expect("conversion");
        assert!(
            matches!(&msg.destination, Destination::Group(g) if &**g == "OnlyGroup"),
            "expected Group(OnlyGroup) destination"
        );
    }

    #[test]
    fn event_to_routable_multiple_groups_broadcasts() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            federate_groups: vec!["A".into(), "B".into()],
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp", false).expect("conversion");
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    #[test]
    fn event_to_routable_ttl_computed_from_timestamps() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                start_time: 1000000,
                stale_time: 1300000, // 300 seconds later
                ..Default::default()
            }),
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp", false).expect("conversion");
        let ttl = msg.metadata.ttl.expect("should have ttl");
        assert_eq!(ttl, Duration::from_millis(300000));
    }

    #[test]
    fn event_to_routable_no_ttl_when_no_timestamps() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp", false).expect("conversion");
        assert!(msg.metadata.ttl.is_none());
    }

    #[test]
    fn event_to_routable_trusted_groups_populate_identity() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            federate_groups: vec!["X".into(), "Y".into()],
            ..Default::default()
        };
        // trust_peer_groups = true: wire groups become source identity groups
        let msg = federated_event_to_routable(&event, "peer", "fp", true).expect("conversion");
        assert!(msg.source.groups.contains("X"));
        assert!(msg.source.groups.contains("Y"));
    }

    #[test]
    fn event_to_routable_untrusted_groups_are_dropped() {
        // Issue #720: default path must NOT trust wire-claimed groups.
        // A Byzantine peer with a valid mTLS cert could otherwise forge
        // arbitrary group memberships for any origin CN.
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            federate_groups: vec!["Admin".into(), "Command".into()],
            ..Default::default()
        };
        // trust_peer_groups = false: source identity has empty groups
        // regardless of what the wire claimed.
        let msg = federated_event_to_routable(&event, "peer", "fp", false).expect("conversion");
        assert!(
            msg.source.groups.is_empty(),
            "source groups must be empty when trust_peer_groups=false, got {:?}",
            msg.source.groups
        );
        // Destination still honors wire routing intent (ACL re-checks on
        // the receive side).
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    // --- extract_metadata tests ---

    #[test]
    fn extract_metadata_empty_event() {
        let event = figpb::FederatedEvent::default();
        let meta = extract_metadata(&event);
        assert!(meta.provenance.is_empty());
        assert_eq!(meta.max_hops, 10);
        assert_eq!(meta.current_hops, 0);
    }

    #[test]
    fn extract_metadata_with_provenance() {
        let event = figpb::FederatedEvent {
            federate_provenance: vec![
                figpb::FederateProvenance {
                    federation_server_id: "s1".into(),
                    federation_server_name: "S One".into(),
                },
                figpb::FederateProvenance {
                    federation_server_id: "s2".into(),
                    federation_server_name: "S Two".into(),
                },
            ],
            federate_hops: Some(figpb::FederateHops {
                max_hops: 5,
                current_hops: 2,
            }),
            ..Default::default()
        };
        let meta = extract_metadata(&event);
        assert_eq!(meta.provenance.len(), 2);
        assert_eq!(meta.provenance[0].server_id.as_str(), "s1");
        assert_eq!(meta.provenance[1].server_id.as_str(), "s2");
        assert_eq!(meta.max_hops, 5);
        assert_eq!(meta.current_hops, 2);
    }

    // --- infer_message_type tests ---

    #[test]
    fn infer_message_type_position() {
        assert_eq!(infer_message_type("a-f-G-U-C"), MessageType::Position);
        assert_eq!(infer_message_type("a-h-G"), MessageType::Position);
    }

    #[test]
    fn infer_message_type_chat() {
        assert_eq!(infer_message_type("b-t-f"), MessageType::Chat);
    }

    #[test]
    fn infer_message_type_alert() {
        assert_eq!(infer_message_type("b-a-g"), MessageType::Alert);
    }

    #[test]
    fn infer_message_type_other() {
        assert_eq!(
            infer_message_type("t-x-c-t"),
            MessageType::Other("t-x-c-t".to_string())
        );
    }

    // --- Full round-trip through routable ---

    #[test]
    fn full_round_trip_routable_to_event_to_routable() {
        let source_groups: BTreeSet<GroupId> = ["Alpha".to_string()].into_iter().collect();

        let msg = RoutableMessage {
            source: Identity::new("test-server".into(), "fp-abc".into(), source_groups)
                .expect("valid identity"),
            destination: Destination::Group("Alpha".into()),
            payload: Bytes::from_static(sample_xml()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: SOURCE_FEDERATION.to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };

        let event = routable_to_federated_event(&msg, &sample_metadata()).expect("to event");

        // Verify groups merged
        assert!(event.federate_groups.contains(&"Cyan".to_string()));
        assert!(event.federate_groups.contains(&"Alpha".to_string()));

        // Convert back. trust_peer_groups = true preserves the wire
        // group claims so this end-to-end test can validate the
        // destination and identity plumbing; the security default
        // (`false`) is exercised by `event_to_routable_untrusted_groups_are_dropped`.
        let msg_back =
            federated_event_to_routable(&event, "peer-x", "fp-xyz", true).expect("to routable");

        assert_eq!(&*msg_back.source.cn, "peer-x");
        assert_eq!(msg_back.metadata.source_protocol, SOURCE_FEDERATION);
        assert_eq!(msg_back.metadata.message_type, MessageType::Position);
    }
}
