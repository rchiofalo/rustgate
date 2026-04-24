// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Compilation smoke tests for server-level feature gates.
//!
//! Each test is gated behind the corresponding feature flag and verifies
//! that the feature-gated dependency crate compiles and its basic public
//! types are accessible. These are not full integration tests -- the goal
//! is ensuring feature combinations compile correctly.

// ── NATS feature ────────────────────────────────────────────────────

#[cfg(feature = "nats")]
mod nats_gate {
    use rustgate_nats::{NatsConfig, NatsPublisher, WireEvent};

    #[test]
    fn nats_config_default() {
        let config = NatsConfig::default();
        assert_eq!(config.url, "nats://localhost:4222");
    }

    #[test]
    fn wire_event_type_exists() {
        // WireEvent is the serialization envelope for NATS messages.
        // Verify the type is accessible and can be referenced.
        fn _assert_send<T: Send>() {}
        _assert_send::<WireEvent>();
    }

    #[test]
    fn nats_publisher_type_exists() {
        // NatsPublisher requires a live NATS connection to construct,
        // so we just verify the type is accessible.
        fn _assert_send<T: Send>() {}
        _assert_send::<NatsPublisher>();
    }
}

// ── Enrollment feature ──────────────────────────────────────────────

#[cfg(feature = "enrollment")]
mod enrollment_gate {
    use rustgate_enrollment::{Credentials, EnrollmentError, EnrollmentServer};

    #[test]
    fn credentials_type_exists() {
        fn _assert_send<T: Send>() {}
        _assert_send::<Credentials>();
    }

    #[test]
    fn enrollment_error_type_exists() {
        fn _assert_send<T: Send>() {}
        _assert_send::<EnrollmentError>();
    }

    #[test]
    fn enrollment_server_type_exists() {
        fn _assert_send<T: Send>() {}
        _assert_send::<EnrollmentServer>();
    }
}

// ── Proto feature ───────────────────────────────────────────────────

#[cfg(feature = "proto")]
mod proto_gate {
    use rustgate_proto::{ProtoError, TakFrameCodec, TakProtobufCodec};

    #[test]
    fn proto_types_accessible() {
        fn _assert_send<T: Send>() {}
        _assert_send::<TakFrameCodec>();
        _assert_send::<TakProtobufCodec>();
        _assert_send::<ProtoError>();
    }

    #[test]
    fn tak_frame_codec_default() {
        let codec = TakFrameCodec::default();
        // Codec exists and can be instantiated
        let _ = codec;
    }
}

// ── Metrics feature ─────────────────────────────────────────────────

#[cfg(feature = "metrics")]
mod metrics_gate {
    #[test]
    fn prometheus_crate_accessible() {
        // When the metrics feature is enabled, the prometheus crate
        // should be available as a dependency.
        let counter = prometheus::IntCounter::new("test_counter", "test").unwrap();
        counter.inc();
        assert_eq!(counter.get(), 1);
    }

    #[test]
    fn prometheus_gauge_accessible() {
        let gauge = prometheus::IntGauge::new("test_gauge", "test").unwrap();
        gauge.set(42);
        assert_eq!(gauge.get(), 42);
    }
}

// ── Federation feature ──────────────────────────────────────────────

#[cfg(feature = "federation")]
mod federation_gate {
    use rustgate_federation::config::{FederationConfig, PeerConfig};
    use rustgate_federation::manager::FederationStatus;
    use rustgate_federation::store::FederateStore;
    use rustgate_federation::store::file::FileStore;
    use rustgate_federation::trust_store::TrustStore;

    #[test]
    fn federation_config_default() {
        let config = FederationConfig::default();
        assert!(config.peers.is_empty());
    }

    #[test]
    fn peer_config_construction() {
        let peer = PeerConfig {
            id: "peer-1".into(),
            address: "10.0.0.1:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: Default::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
            compression: None,
        };
        assert_eq!(peer.id.as_str(), "peer-1");
        assert!(peer.enabled);
    }

    #[test]
    fn federation_status_type_exists() {
        let status = FederationStatus {
            running: false,
            v1_server_active: false,
            v2_server_active: false,
            total_peers: 0,
            connected_peers: 0,
            peers: vec![],
            ha_enabled: false,
            pod_id: None,
        };
        assert!(!status.running);
    }

    #[test]
    fn file_store_empty() {
        let store = FileStore::new(None);
        assert!(store.list().is_empty());
    }

    #[test]
    fn trust_store_empty() {
        let store = TrustStore::new(None);
        assert!(store.list_certificates().expect("list certs").is_empty());
    }

    // The `api` sub-feature is automatically enabled when the server's
    // `federation` feature is active (it implies `rustgate-federation/api`).
    #[test]
    fn api_module_accessible() {
        use rustgate_federation::api::{ApiState, handle_request};

        let store = FileStore::new(None);
        let trust_store = TrustStore::new(None);

        let state = ApiState {
            store: std::sync::Arc::new(std::sync::RwLock::new(store)),
            trust_store: std::sync::Arc::new(trust_store),
            status_fn: std::sync::Arc::new(|| FederationStatus {
                running: false,
                v1_server_active: false,
                v2_server_active: false,
                total_peers: 0,
                connected_peers: 0,
                peers: vec![],
                ha_enabled: false,
                pod_id: None,
            }),
            peer_status_fn: std::sync::Arc::new(|_| None),
        };

        // Non-federation path returns None
        let result = handle_request(&hyper::Method::GET, "/healthz", &[], &state);
        assert!(result.is_none());
    }

    // The `metrics` sub-module is gated behind `api` in the federation crate.
    #[test]
    fn federation_metrics_accessible() {
        use rustgate_federation::metrics;

        // Verify metric accessor functions exist and return valid metrics.
        let _ = metrics::connections();
        let _ = metrics::messages_in();
        let _ = metrics::messages_out();
        let _ = metrics::errors();
        let _ = metrics::circuit_breaker_trips();
        let _ = metrics::circuit_breaker_recoveries();
    }
}

// ── WebSocket feature ───────────────────────────────────────────────

#[cfg(feature = "websocket")]
mod websocket_gate {
    use rustgate_websocket::{WsServerConfig, WsSession};

    #[test]
    fn ws_types_accessible() {
        fn _assert_send<T: Send>() {}
        _assert_send::<WsSession>();
    }

    #[test]
    fn ws_server_config_type_exists() {
        fn _assert_send<T: Send>() {}
        _assert_send::<WsServerConfig>();
    }
}

// ── MQTT feature ────────────────────────────────────────────────────

#[cfg(feature = "mqtt")]
mod mqtt_gate {
    use rustgate_mqtt::{MqttListener, MqttServer, MqttServerConfig};

    #[test]
    fn mqtt_types_accessible() {
        fn _assert_send<T: Send>() {}
        _assert_send::<MqttServer>();
    }

    #[test]
    fn mqtt_server_config_type_exists() {
        fn _assert_send<T: Send>() {}
        _assert_send::<MqttServerConfig>();
    }

    #[test]
    fn mqtt_listener_type_exists() {
        fn _assert_send<T: Send>() {}
        _assert_send::<MqttListener>();
    }
}
