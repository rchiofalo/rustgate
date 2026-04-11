// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for per-tenant resource quota enforcement.
#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use rustgate_core::identity::Identity;
use rustgate_transport::quota::{QuotaConfig, TenantQuota, TenantQuotaTracker};
use rustgate_transport::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, Router, SessionHandle,
};
use tokio::sync::mpsc;

/// Build an identity with the given CN and tenant.
fn make_identity(cn: &str, tenant: Option<&str>) -> Arc<Identity> {
    let mut id = Identity::new(cn.to_string(), format!("{cn}-fp"), BTreeSet::new()).unwrap();
    if let Some(t) = tenant {
        id = id.with_tenant(t);
    }
    Arc::new(id)
}

/// Build a session handle from an identity.
fn make_handle(identity: Arc<Identity>) -> SessionHandle {
    let (ptx, _prx) = mpsc::channel(PRIORITY_CHANNEL_CAPACITY);
    let (ntx, _nrx) = mpsc::channel(NORMAL_CHANNEL_CAPACITY);
    SessionHandle::new(identity, ptx, ntx)
}

/// Helper: create a QuotaConfig with a single tenant entry.
fn config_single(tenant: &str, max_conn: u32) -> QuotaConfig {
    let mut tenants = HashMap::new();
    let _ = tenants.insert(
        tenant.to_string(),
        TenantQuota {
            max_connections: max_conn,
            max_message_rate: 0,
        },
    );
    QuotaConfig {
        tenants,
        default_quota: None,
    }
}

/// Set max_connections=2 for tenant "acme". Register 2 sessions from
/// "acme". Third registration should be rejected.
#[tokio::test]
async fn tenant_connection_limit_enforced() {
    let tracker = Arc::new(TenantQuotaTracker::new(config_single("acme", 2)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    let h1 = make_handle(make_identity("alice", Some("acme")));
    let h2 = make_handle(make_identity("bob", Some("acme")));
    let h3 = make_handle(make_identity("carol", Some("acme")));

    assert!(
        router.register(h1).await,
        "first session should be accepted"
    );
    assert!(
        router.register(h2).await,
        "second session should be accepted"
    );
    assert!(
        !router.register(h3).await,
        "third session should be rejected"
    );

    assert_eq!(tracker.active_connections("acme"), 2);
}

/// Set default_quota with max_connections=1. Register from unknown
/// tenant. Second registration should be rejected.
#[tokio::test]
async fn default_quota_applies_to_unknown_tenant() {
    let config = QuotaConfig {
        tenants: HashMap::new(),
        default_quota: Some(TenantQuota {
            max_connections: 1,
            max_message_rate: 0,
        }),
    };
    let tracker = Arc::new(TenantQuotaTracker::new(config));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    let h1 = make_handle(make_identity("alice", Some("unknown-org")));
    let h2 = make_handle(make_identity("bob", Some("unknown-org")));

    assert!(
        router.register(h1).await,
        "first session should be accepted"
    );
    assert!(
        !router.register(h2).await,
        "second session should be rejected by default quota"
    );
}

/// No tracker installed: all registrations succeed regardless of tenant.
#[tokio::test]
async fn no_quota_file_means_unlimited() {
    let router = Router::new();

    for i in 0..10 {
        let h = make_handle(make_identity(&format!("user-{i}"), Some("acme")));
        assert!(
            router.register(h).await,
            "registration must succeed without quota tracker"
        );
    }
}

/// At limit, disconnect one session, new registration succeeds.
#[tokio::test]
async fn disconnect_frees_slot() {
    let tracker = Arc::new(TenantQuotaTracker::new(config_single("acme", 1)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    let h1 = make_handle(make_identity("alice", Some("acme")));
    let session_id = h1.id;
    assert!(router.register(h1).await);

    // At limit — next registration should fail.
    let h2 = make_handle(make_identity("bob", Some("acme")));
    assert!(!router.register(h2).await);

    // Disconnect alice.
    router.unregister("alice", session_id).await;
    assert_eq!(tracker.active_connections("acme"), 0);

    // Now bob can connect.
    let h3 = make_handle(make_identity("bob", Some("acme")));
    assert!(router.register(h3).await);
    assert_eq!(tracker.active_connections("acme"), 1);
}

/// Sessions without a tenant field are mapped to the default quota key
/// so they are subject to default_quota limits when configured.
#[tokio::test]
async fn no_tenant_uses_default_quota() {
    let config = QuotaConfig {
        tenants: HashMap::new(),
        default_quota: Some(TenantQuota {
            max_connections: 2,
            max_message_rate: 0,
        }),
    };
    let tracker = Arc::new(TenantQuotaTracker::new(config));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    // No tenant field: mapped to __default__ key, subject to default_quota.
    let h1 = make_handle(make_identity("user-0", None));
    let h2 = make_handle(make_identity("user-1", None));
    let h3 = make_handle(make_identity("user-2", None));

    assert!(router.register(h1).await, "first should be accepted");
    assert!(router.register(h2).await, "second should be accepted");
    assert!(
        !router.register(h3).await,
        "third should be rejected by default quota"
    );
}

/// Different tenants have independent quotas.
#[tokio::test]
async fn independent_tenant_quotas() {
    let mut tenants = HashMap::new();
    let _ = tenants.insert(
        "acme".to_string(),
        TenantQuota {
            max_connections: 1,
            max_message_rate: 0,
        },
    );
    let _ = tenants.insert(
        "globex".to_string(),
        TenantQuota {
            max_connections: 1,
            max_message_rate: 0,
        },
    );
    let config = QuotaConfig {
        tenants,
        default_quota: None,
    };
    let tracker = Arc::new(TenantQuotaTracker::new(config));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    let h1 = make_handle(make_identity("alice", Some("acme")));
    let h2 = make_handle(make_identity("bob", Some("globex")));

    assert!(router.register(h1).await);
    assert!(router.register(h2).await);

    // Both at limit.
    let h3 = make_handle(make_identity("carol", Some("acme")));
    let h4 = make_handle(make_identity("dave", Some("globex")));
    assert!(!router.register(h3).await);
    assert!(!router.register(h4).await);
}
