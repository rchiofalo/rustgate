// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for per-tenant resource quota enforcement.
#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::quota::{QuotaConfig, TenantQuota, TenantQuotaTracker};
use rustgate_router::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, RoutedMessage, Router, SessionHandle,
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

/// Register a session that RETAINS its normal-channel receiver, so
/// routed messages (and the per-tenant byte permits they carry) stay
/// alive in the channel until the caller drains or drops the receiver.
/// This is what lets a queued-byte reservation stay pegged against a
/// slow reader.
async fn make_session(
    router: &Router,
    cn: &str,
    tenant: Option<&str>,
) -> (Arc<Identity>, mpsc::Receiver<RoutedMessage>) {
    let identity = make_identity(cn, tenant);
    let (ptx, _prx) = mpsc::channel(PRIORITY_CHANNEL_CAPACITY);
    let (ntx, nrx) = mpsc::channel(NORMAL_CHANNEL_CAPACITY);
    let handle = SessionHandle::new(Arc::clone(&identity), ptx, ntx);
    let _ = router.register(handle).await;
    (identity, nrx)
}

/// Build a broadcast message of at least `len` bytes from `source`.
fn make_msg(source: &Arc<Identity>, len: usize, uid: &str) -> RoutableMessage {
    let payload = format!(
        "<event uid=\"{uid}\" time=\"2026-05-04T00:00:00Z\" type=\"a-f-G\">{:0>1$}</event>",
        "",
        len.saturating_sub(80)
    );
    RoutableMessage {
        entity: None,
        source: (**source).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Chat),
    }
}

/// Build a `QuotaConfig` with a single queued-byte-capped tenant.
fn quota_queued_bytes(tenant: &str, max_queued_bytes: u64) -> QuotaConfig {
    let mut tenants = HashMap::new();
    let _ = tenants.insert(
        tenant.to_string(),
        TenantQuota {
            max_connections: 0,
            max_message_rate: 0,
            max_queued_bytes,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
        },
    );
    QuotaConfig {
        tenants,
        default_quota: None,
    }
}

/// Helper: create a QuotaConfig with a single tenant entry.
fn config_single(tenant: &str, max_conn: u32) -> QuotaConfig {
    let mut tenants = HashMap::new();
    let _ = tenants.insert(
        tenant.to_string(),
        TenantQuota {
            max_connections: max_conn,
            max_message_rate: 0,
            max_queued_bytes: 0,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
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
            max_queued_bytes: 0,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
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
            max_queued_bytes: 0,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
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
            max_queued_bytes: 0,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
        },
    );
    let _ = tenants.insert(
        "globex".to_string(),
        TenantQuota {
            max_connections: 1,
            max_message_rate: 0,
            max_queued_bytes: 0,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
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

// ---------------------------------------------------------------------------
// #1514: per-tenant *queued-byte* admission at the router egress path.
//
// Distinct from the throughput (bytes/sec) cap in tenant_token_bucket.rs:
// these tests pin the *instantaneous in-flight* byte cap, which only
// releases when the last recipient channel drains its RoutedMessage.
// ---------------------------------------------------------------------------

/// A noisy tenant whose recipient channels are NOT drained cannot reserve
/// beyond its `max_queued_bytes`; the over-cap message is dropped
/// (returns `None`) while a separate tenant keeps routing successfully.
/// Proves per-tenant isolation at the admission layer.
#[tokio::test(flavor = "current_thread")]
async fn queued_bytes_over_cap_dropped_and_tenant_isolated() {
    let mut tenants = HashMap::new();
    let _ = tenants.insert(
        "noisy".to_string(),
        TenantQuota {
            max_connections: 0,
            max_message_rate: 0,
            max_queued_bytes: 1_024,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
        },
    );
    let _ = tenants.insert(
        "quiet".to_string(),
        TenantQuota {
            max_connections: 0,
            max_message_rate: 0,
            max_queued_bytes: 1_024,
            max_throughput_bps: 0,
            refill_throughput_bps: 0,
        },
    );
    let tracker = Arc::new(TenantQuotaTracker::new(QuotaConfig {
        tenants,
        default_quota: None,
    }));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    // Receivers are held (never drained), so routed messages — and their
    // byte permits — stay pegged in the channel.
    let (_n_id, _n_rx) = make_session(&router, "noisy-recv", Some("noisy")).await;
    let (_q_id, _q_rx) = make_session(&router, "quiet-recv", Some("quiet")).await;
    let noisy_sender = make_identity("noisy-sender", Some("noisy"));
    let quiet_sender = make_identity("quiet-sender", Some("quiet"));

    // First 700-byte message from "noisy" reserves under the 1 024 cap.
    assert!(
        router
            .route_for_egress(make_msg(&noisy_sender, 700, "N-1"))
            .await
            .is_some(),
        "first sub-cap message must be admitted"
    );
    // Second 700-byte message would push the reservation to 1 400 > 1 024:
    // rejected because the first is still held in the un-drained channel.
    assert!(
        router
            .route_for_egress(make_msg(&noisy_sender, 700, "N-2"))
            .await
            .is_none(),
        "second message exceeds the tenant queued-byte cap and must drop"
    );

    // "quiet" is untouched by "noisy"'s saturation — full cap available.
    assert!(
        router
            .route_for_egress(make_msg(&quiet_sender, 700, "Q-1"))
            .await
            .is_some(),
        "an isolated tenant must retain its full queued-byte cap"
    );
}

/// The dropped-message path fires the `quota.tenant_queued_bytes_exceeded`
/// audit event and increments the dropped-reason callback exactly once.
#[tokio::test(flavor = "current_thread")]
async fn queued_bytes_drop_emits_audit_and_dropped_reason() {
    use std::sync::Mutex;

    use tracing::Subscriber;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    #[derive(Default, Clone)]
    struct AuditCapture {
        events: Arc<Mutex<Vec<String>>>,
    }
    impl<S: Subscriber> Layer<S> for AuditCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            if event.metadata().target() != "audit" {
                return;
            }
            struct V(String);
            impl tracing::field::Visit for V {
                fn record_debug(
                    &mut self,
                    _f: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write;
                    let _ = write!(&mut self.0, " {value:?}");
                }
                fn record_str(&mut self, _f: &tracing::field::Field, value: &str) {
                    use std::fmt::Write;
                    let _ = write!(&mut self.0, " {value}");
                }
            }
            let mut visitor = V(String::new());
            event.record(&mut visitor);
            if let Ok(mut events) = self.events.lock() {
                events.push(visitor.0);
            }
        }
    }

    let capture = AuditCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let tracker = Arc::new(TenantQuotaTracker::new(quota_queued_bytes("noisy", 256)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    // Count dropped-reason emissions via the router's dropped callback.
    let dropped = Arc::new(AtomicU64::new(0));
    {
        let d = Arc::clone(&dropped);
        router.set_on_dropped(Some(Arc::new(move |reason: &'static str| {
            if reason == "tenant_queued_bytes_exceeded" {
                let _ = d.fetch_add(1, Ordering::Relaxed);
            }
        })));
    }

    let (_id, _rx) = make_session(&router, "noisy-recv", Some("noisy")).await;
    let sender = make_identity("noisy-sender", Some("noisy"));

    // 512-byte message into a 256-byte cap → immediate reject.
    let routed = router
        .route_for_egress(make_msg(&sender, 512, "REJ-1"))
        .await;
    assert!(routed.is_none(), "over-cap message must be dropped");

    tokio::task::yield_now().await;

    assert_eq!(
        dropped.load(Ordering::Relaxed),
        1,
        "dropped-reason callback must fire once with tenant_queued_bytes_exceeded"
    );

    let events = capture.events.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| e.contains("tenant_queued_bytes_exceeded")),
        "expected tenant_queued_bytes_exceeded audit event; got {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("noisy")),
        "audit event must carry the tenant key; got {events:?}"
    );
}

/// Draining (and dropping) the recipient channels releases every byte
/// permit through the RoutedMessage clone chain, returning the tenant's
/// queued-byte counter to zero — proving release-on-last-drain.
#[tokio::test(flavor = "current_thread")]
async fn queued_bytes_permit_releases_on_channel_drain() {
    let tracker = Arc::new(TenantQuotaTracker::new(quota_queued_bytes("noisy", 4_096)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    let (_id, mut rx) = make_session(&router, "noisy-recv", Some("noisy")).await;
    let sender = make_identity("noisy-sender", Some("noisy"));

    // Two admitted messages accumulate a nonzero reservation.
    assert!(
        router
            .route_for_egress(make_msg(&sender, 500, "R-1"))
            .await
            .is_some()
    );
    assert!(
        router
            .route_for_egress(make_msg(&sender, 500, "R-2"))
            .await
            .is_some()
    );
    assert!(
        tracker.queued_bytes("noisy") > 0,
        "in-flight messages must peg the tenant queued-byte counter"
    );

    // Drain every held envelope, then drop the receiver so the last
    // RoutedMessage clone — and thus the last TenantBytePermit — is
    // released.
    while rx.try_recv().is_ok() {}
    drop(rx);
    // Give any Drop-triggered saturating decrement a chance to settle.
    tokio::task::yield_now().await;

    assert_eq!(
        tracker.queued_bytes("noisy"),
        0,
        "draining all recipients must release the reservation to zero"
    );
}

/// Compat guard: a tenant with `max_queued_bytes == 0` (unlimited) or no
/// quota entry is NEVER dropped by this layer, regardless of volume —
/// guarding against the overloaded-`None` footgun where "no cap
/// configured" would otherwise read as a rejection.
#[tokio::test(flavor = "current_thread")]
async fn queued_bytes_uncapped_tenant_never_dropped() {
    // Tenant present but max_queued_bytes = 0 (unlimited).
    let tracker = Arc::new(TenantQuotaTracker::new(quota_queued_bytes("acme", 0)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));
    let (_id, _rx) = make_session(&router, "acme-recv", Some("acme")).await;
    let sender = make_identity("acme-sender", Some("acme"));

    // Never drained; without a cap none of these should ever be shed by
    // the queued-byte layer.
    for i in 0..20 {
        assert!(
            router
                .route_for_egress(make_msg(&sender, 4_096, &format!("U-{i}")))
                .await
                .is_some(),
            "uncapped tenant must never be dropped by the queued-byte layer"
        );
    }

    // A tenant with no config entry at all also sails through.
    let stranger = make_identity("stranger-sender", Some("nobody"));
    let (_sid, _srx) = make_session(&router, "stranger-recv", Some("nobody")).await;
    for i in 0..20 {
        assert!(
            router
                .route_for_egress(make_msg(&stranger, 4_096, &format!("S-{i}")))
                .await
                .is_some(),
            "tenant with no quota entry must never be dropped by this layer"
        );
    }
}
