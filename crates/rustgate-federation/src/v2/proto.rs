//! Generated protobuf types for V2 federation (gRPC FederatedChannel).
//!
//! These types are compiled from `proto/figpb/fig.proto` by tonic-build
//! at build time and provide the wire types for the V2 federation protocol.

/// FederatedChannel service and message types.
///
/// Contains the gRPC service definition and all associated message types
/// for V2 TAK Server federation, including:
/// - `FederatedEvent`, `GeoEvent`, `ContactListEntry`
/// - `FederateProvenance`, `FederateHops`, `FederateGroupHopLimits`
/// - `Identity`, `Subscription`, `ServerHealth`, `ClientHealth`
/// - `FederateGroups`, `Rol`, `BinaryBlob`
/// - `federated_channel_client` / `federated_channel_server` — gRPC stubs
#[allow(warnings)]
pub mod figpb {
    tonic::include_proto!("com.atakmap");
}

/// Binary payload types from the TAK COP protobuf package.
///
/// Used by `GeoEvent.bloads` for carrying binary attachments alongside
/// federation events.
#[allow(warnings)]
pub mod binarypayload {
    include!(concat!(env!("OUT_DIR"), "/gov.tak.cop.proto.v1.rs"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federated_event_default() {
        let event = figpb::FederatedEvent::default();
        assert!(event.event.is_none());
        assert!(event.contact.is_none());
        assert!(event.federate_groups.is_empty());
        assert!(event.federate_provenance.is_empty());
    }

    #[test]
    fn geo_event_default() {
        let geo = figpb::GeoEvent::default();
        assert_eq!(geo.uid, "");
        assert_eq!(geo.r#type, "");
        assert_eq!(geo.lat, 0.0);
        assert_eq!(geo.lon, 0.0);
    }

    #[test]
    fn identity_connection_types() {
        use figpb::identity::ConnectionType;
        assert_eq!(ConnectionType::FederationHubServer as i32, 0);
        assert_eq!(ConnectionType::FederationHubClient as i32, 1);
        assert_eq!(ConnectionType::FederationTakServer as i32, 2);
        assert_eq!(ConnectionType::FederationTakClient as i32, 3);
    }

    #[test]
    fn federate_provenance_fields() {
        let prov = figpb::FederateProvenance {
            federation_server_id: "server-1".into(),
            federation_server_name: "Server One".into(),
        };
        assert_eq!(prov.federation_server_id, "server-1");
        assert_eq!(prov.federation_server_name, "Server One");
    }

    #[test]
    fn federate_hops_default() {
        let hops = figpb::FederateHops::default();
        assert_eq!(hops.max_hops, 0);
        assert_eq!(hops.current_hops, 0);
    }

    #[test]
    fn server_health_serving_status() {
        use figpb::server_health::ServingStatus;
        assert_eq!(ServingStatus::Unknown as i32, 0);
        assert_eq!(ServingStatus::Serving as i32, 1);
        assert_eq!(ServingStatus::NotServing as i32, 2);
        assert_eq!(ServingStatus::NotConnected as i32, 3);
    }

    #[test]
    fn client_health_serving_status() {
        use figpb::client_health::ServingStatus;
        assert_eq!(ServingStatus::Unknown as i32, 0);
        assert_eq!(ServingStatus::Serving as i32, 1);
        assert_eq!(ServingStatus::NotServing as i32, 2);
    }

    #[test]
    fn crud_enum_values() {
        use figpb::Crud;
        assert_eq!(Crud::Invalid as i32, 0);
        assert_eq!(Crud::Create as i32, 1);
        assert_eq!(Crud::Read as i32, 2);
        assert_eq!(Crud::Update as i32, 3);
        assert_eq!(Crud::Delete as i32, 4);
    }

    #[test]
    fn binary_types_enum_values() {
        use figpb::BinaryTypes;
        assert_eq!(BinaryTypes::Empty as i32, 0);
        assert_eq!(BinaryTypes::Other as i32, 1);
        assert_eq!(BinaryTypes::Image as i32, 2);
    }

    #[test]
    fn subscription_default() {
        let sub = figpb::Subscription::default();
        assert!(sub.identity.is_none());
        assert_eq!(sub.filter, "");
        assert!(sub.version.is_none());
    }

    #[test]
    fn tak_server_version_fields() {
        let ver = figpb::TakServerVersion {
            major: 5,
            minor: 2,
            patch: 1,
            branch: "release".into(),
            variant: "RELEASE".into(),
        };
        assert_eq!(ver.major, 5);
        assert_eq!(ver.minor, 2);
        assert_eq!(ver.patch, 1);
    }

    #[test]
    fn contact_list_entry_fields() {
        let entry = figpb::ContactListEntry {
            operation: figpb::Crud::Create as i32,
            uid: "uid-123".into(),
            callsign: "ALPHA-1".into(),
            phone: "+1234567890".into(),
            sip: "".into(),
            direct_connect: "".into(),
        };
        assert_eq!(entry.uid, "uid-123");
        assert_eq!(entry.callsign, "ALPHA-1");
    }

    #[test]
    fn federate_group_hop_limit_fields() {
        let limit = figpb::FederateGroupHopLimit {
            group_name: "Alpha".into(),
            max_hops: 5,
            current_hops: 2,
        };
        assert_eq!(limit.group_name, "Alpha");
        assert_eq!(limit.max_hops, 5);
        assert_eq!(limit.current_hops, 2);
    }

    #[test]
    fn federate_groups_default() {
        let groups = figpb::FederateGroups::default();
        assert!(groups.stream_update.is_none());
        assert!(groups.federate_groups.is_empty());
        assert!(groups.federate_provenance.is_empty());
    }

    #[test]
    fn geo_event_with_coordinates() {
        let geo = figpb::GeoEvent {
            lat: 38.8977,
            lon: -77.0365,
            hae: 9999999.0,
            ce: 9999999.0,
            le: 9999999.0,
            uid: "test-uid".into(),
            r#type: "a-f-G-U-C".into(),
            ..Default::default()
        };
        assert!((geo.lat - 38.8977).abs() < f64::EPSILON);
        assert!((geo.lon - (-77.0365)).abs() < f64::EPSILON);
    }

    #[test]
    fn binary_blob_fields() {
        let blob = figpb::BinaryBlob {
            r#type: figpb::BinaryTypes::Image as i32,
            data: vec![0xFF, 0xD8, 0xFF],
            filename: "photo.jpg".into(),
            timestamp: 1700000000,
            description: "test image".into(),
            ..Default::default()
        };
        assert_eq!(blob.data.len(), 3);
        assert_eq!(blob.filename, "photo.jpg");
    }

    #[test]
    fn binary_payload_default() {
        let payload = binarypayload::BinaryPayload::default();
        assert_eq!(payload.r#type, "");
        assert_eq!(payload.version, "");
        assert!(payload.data.is_empty());
    }

    #[test]
    fn prost_encode_decode_federated_event() {
        use prost::Message;

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test-uid".into(),
                r#type: "a-f-G-U-C".into(),
                lat: 38.8977,
                lon: -77.0365,
                ..Default::default()
            }),
            federate_groups: vec!["Alpha".into(), "Bravo".into()],
            federate_provenance: vec![figpb::FederateProvenance {
                federation_server_id: "server-1".into(),
                federation_server_name: "Server One".into(),
            }],
            federate_hops: Some(figpb::FederateHops {
                max_hops: 10,
                current_hops: 1,
            }),
            ..Default::default()
        };

        let mut buf = Vec::new();
        event.encode(&mut buf).expect("encode");
        assert!(!buf.is_empty());

        let decoded = figpb::FederatedEvent::decode(&buf[..]).expect("decode");
        assert_eq!(decoded.federate_groups, vec!["Alpha", "Bravo"]);
        assert_eq!(decoded.federate_provenance.len(), 1);
        assert_eq!(decoded.event.as_ref().expect("event").uid, "test-uid");
    }

    #[test]
    fn prost_encode_decode_identity() {
        use prost::Message;

        let identity = figpb::Identity {
            name: "federation-server-1".into(),
            uid: "uid-12345".into(),
            description: "Test server".into(),
            r#type: figpb::identity::ConnectionType::FederationHubServer as i32,
            server_id: "server-id-1".into(),
        };

        let mut buf = Vec::new();
        identity.encode(&mut buf).expect("encode");

        let decoded = figpb::Identity::decode(&buf[..]).expect("decode");
        assert_eq!(decoded.name, "federation-server-1");
        assert_eq!(decoded.uid, "uid-12345");
        assert_eq!(
            decoded.r#type,
            figpb::identity::ConnectionType::FederationHubServer as i32
        );
    }

    #[test]
    fn rol_default() {
        let rol = figpb::Rol::default();
        assert_eq!(rol.program, "");
        assert!(rol.payload.is_empty());
        assert!(rol.federate_groups.is_empty());
    }

    #[test]
    fn federate_group_hop_limits_default() {
        let limits = figpb::FederateGroupHopLimits::default();
        assert!(limits.limits.is_empty());
        assert!(!limits.use_federate_group_hop_limits);
    }

    #[test]
    fn federate_token_response_default() {
        let resp = figpb::FederateTokenResponse::default();
        assert_eq!(resp.token, "");
    }
}
