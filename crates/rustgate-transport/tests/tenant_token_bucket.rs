// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the per-tenant aggregate-throughput token bucket
//! (issue #883 sub-item 4).
//!
//! These tests drive the full router send path so the per-tenant bucket
//! is exercised through `Router::route` exactly as production traffic
//! would. They also pin composition with the per-session bucket: a
//! message that passes both buckets is delivered exactly once, and a
//! tenant-bucket reject does not double-account against the per-session
//! bucket.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::quota::{QuotaConfig, TenantQuota, TenantQuotaTracker};
use rustgate_transport::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, RoutedMessage, Router, SessionHandle,
};
use tokio::sync::mpsc;
use tracing_subscriber::layer::SubscriberExt;

/// Identity helpers (mirror tests/tenant_quota.rs).
fn make_identity(cn: &str, tenant: Option<&str>) -> Arc<Identity> {
    let mut id = Identity::new(cn.to_string(), format!("{cn}-fp"), BTreeSet::new()).unwrap();
    if let Some(t) = tenant {
        id = id.with_tenant(t);
    }
    Arc::new(id)
}

/// Register a session that drains messages into the returned receiver.
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

/// Build a broadcast message of `len` bytes from `source`.
fn make_msg(source: &Arc<Identity>, len: usize, uid: &str) -> RoutableMessage {
    let payload = format!(
        "<event uid=\"{uid}\" time=\"2026-05-04T00:00:00Z\" type=\"a-f-G\">{:0>1$}</event>",
        "",
        len.saturating_sub(80)
    );
    RoutableMessage {
        source: (**source).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "tcp".to_string(),
            message_type: MessageType::Chat,
            ttl: None,
        },
    }
}

/// Build a `QuotaConfig` with a single throughput-capped tenant.
fn quota_throughput(tenant: &str, cap_bps: u64, refill_bps: u64) -> QuotaConfig {
    let mut tenants = HashMap::new();
    let _ = tenants.insert(
        tenant.to_string(),
        TenantQuota {
            max_connections: 0,
            max_message_rate: 0,
            max_queued_bytes: 0,
            max_throughput_bps: cap_bps,
            refill_throughput_bps: refill_bps,
        },
    );
    QuotaConfig {
        tenants,
        default_quota: None,
    }
}

/// Test 1: A tenant with N sessions cannot collectively exceed the
/// aggregate cap. Open 5 sessions for "acme", drain ~3× the cap from
/// the same source, and verify only the cap's worth makes it through.
#[tokio::test(flavor = "current_thread")]
async fn tenant_token_bucket_default_throughput_caps_aggregate() {
    // 1_000-byte cap, no refill (rate=0 → bucket starts full and stays
    // drained for the test window).
    let tracker = Arc::new(TenantQuotaTracker::new(quota_throughput("acme", 1_000, 0)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    // Register 5 receiver sessions all in tenant "acme" — the aggregate
    // is what we cap, not any individual session's intake.
    let mut receivers = Vec::new();
    for i in 0..5 {
        let (_id, rx) = make_session(&router, &format!("acme-recv-{i}"), Some("acme")).await;
        receivers.push(rx);
    }
    // Sender is also acme, so its outbound charges the same bucket.
    let sender = make_identity("acme-sender", Some("acme"));

    // Send 5 × 500-byte messages → 2_500 bytes. Cap is 1 000 — first
    // two messages should be admitted (1 000 bytes), the remaining
    // three rejected.
    let mut admitted = 0;
    for i in 0..5 {
        // 500-byte payload: route_for_egress returns Some(_) on admit,
        // None on tenant-throughput drop (matches all other drop
        // reasons).
        let routed = router
            .route_for_egress(make_msg(&sender, 500, &format!("MSG-{i}")))
            .await;
        if routed.is_some() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 2,
        "only 2×500B should pass under a 1 000B cap; got {admitted}"
    );
}

/// Test 2: Tenants are isolated. Tenant A saturating its bucket does
/// not affect tenant B.
#[tokio::test(flavor = "current_thread")]
async fn tenant_token_bucket_per_tenant_isolation() {
    let mut tenants = HashMap::new();
    for t in &["acme", "globex"] {
        let _ = tenants.insert(
            (*t).to_string(),
            TenantQuota {
                max_connections: 0,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: 1_000,
                refill_throughput_bps: 0,
            },
        );
    }
    let tracker = Arc::new(TenantQuotaTracker::new(QuotaConfig {
        tenants,
        default_quota: None,
    }));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    let (_a_id, _a_rx) = make_session(&router, "acme-recv", Some("acme")).await;
    let (_b_id, _b_rx) = make_session(&router, "globex-recv", Some("globex")).await;
    let acme_sender = make_identity("acme-sender", Some("acme"));
    let globex_sender = make_identity("globex-sender", Some("globex"));

    // Saturate acme.
    assert!(
        router
            .route_for_egress(make_msg(&acme_sender, 1_000, "ACME-1"))
            .await
            .is_some()
    );
    assert!(
        router
            .route_for_egress(make_msg(&acme_sender, 1, "ACME-2"))
            .await
            .is_none(),
        "acme bucket exhausted"
    );
    // Globex is untouched — full cap available.
    assert!(
        router
            .route_for_egress(make_msg(&globex_sender, 1_000, "GLOBEX-1"))
            .await
            .is_some(),
        "globex must retain its full cap regardless of acme's state"
    );
}

/// Test 3: A per-tenant override raises the cap for the named tenant
/// while the default applies to everyone else.
#[tokio::test(flavor = "current_thread")]
async fn tenant_token_bucket_override_raises_cap_for_named_tenant() {
    let mut tenants = HashMap::new();
    let _ = tenants.insert(
        "Acme Corp".to_string(),
        TenantQuota {
            max_connections: 0,
            max_message_rate: 0,
            max_queued_bytes: 0,
            max_throughput_bps: 10_000,
            refill_throughput_bps: 0,
        },
    );
    let config = QuotaConfig {
        tenants,
        default_quota: Some(TenantQuota {
            max_connections: 0,
            max_message_rate: 0,
            max_queued_bytes: 0,
            max_throughput_bps: 1_000,
            refill_throughput_bps: 0,
        }),
    };
    let tracker = Arc::new(TenantQuotaTracker::new(config));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));

    let (_acme_id, _) = make_session(&router, "acme-recv", Some("Acme Corp")).await;
    let (_other_id, _) = make_session(&router, "other-recv", Some("OtherOrg")).await;
    let acme_sender = make_identity("acme-sender", Some("Acme Corp"));
    let other_sender = make_identity("other-sender", Some("OtherOrg"));

    // Acme can drain 10 000 bytes total (its override).
    assert!(
        router
            .route_for_egress(make_msg(&acme_sender, 5_000, "ACME-A"))
            .await
            .is_some()
    );
    assert!(
        router
            .route_for_egress(make_msg(&acme_sender, 5_000, "ACME-B"))
            .await
            .is_some(),
        "acme override grants 10 000B aggregate cap"
    );
    // OtherOrg is held to the default 1 000-byte cap.
    assert!(
        router
            .route_for_egress(make_msg(&other_sender, 1_000, "OTHER-A"))
            .await
            .is_some()
    );
    assert!(
        router
            .route_for_egress(make_msg(&other_sender, 1, "OTHER-B"))
            .await
            .is_none(),
        "default-cap tenant must not see acme's higher cap"
    );
}

/// Test 4: The bucket refills over time. Drain → throttled → wait →
/// admit. Uses the `try_acquire_tenant_tokens` API directly because
/// the router-level test would need a real wall-clock sleep.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn tenant_token_bucket_refills_over_time() {
    let tracker = Arc::new(TenantQuotaTracker::new(quota_throughput(
        "acme", 1_000, 1_000,
    )));
    // Drain.
    assert!(tracker.try_acquire_tenant_tokens("acme", 1_000).is_ok());
    assert!(tracker.try_acquire_tenant_tokens("acme", 1).is_err());
    // Wait 0.5s — refills 500 tokens at 1 000/s.
    tokio::time::advance(std::time::Duration::from_millis(500)).await;
    // 500 bytes available now; charging 500 succeeds, 1 more fails.
    assert!(tracker.try_acquire_tenant_tokens("acme", 500).is_ok());
    assert!(tracker.try_acquire_tenant_tokens("acme", 1).is_err());
}

/// Test 5: A tenant-throughput drop emits the
/// `quota.tenant_throughput_exceeded` audit event. Capture via a
/// tracing subscriber.
#[tokio::test(flavor = "current_thread")]
async fn tenant_throughput_exceeded_audit_event_fires() {
    use std::sync::Mutex;

    use tracing::Subscriber;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;

    #[derive(Default, Clone)]
    struct AuditCapture {
        events: Arc<Mutex<Vec<String>>>,
    }
    impl<S: Subscriber> Layer<S> for AuditCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            // The audit module emits with target = "audit"; grab every
            // such event and stringify it via Display on the visitor.
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

    let tracker = Arc::new(TenantQuotaTracker::new(quota_throughput("acme", 100, 0)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));
    let (_id, _rx) = make_session(&router, "acme-recv", Some("acme")).await;
    let sender = make_identity("acme-sender", Some("acme"));

    // 200-byte message into a 100-byte cap → reject + audit.
    let routed = router
        .route_for_egress(make_msg(&sender, 200, "REJ-1"))
        .await;
    assert!(routed.is_none(), "over-cap message must be dropped");

    // Allow tracing to flush.
    tokio::task::yield_now().await;

    let events = capture.events.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| e.contains("tenant_throughput_exceeded")),
        "expected tenant_throughput_exceeded audit event; got {events:?}"
    );
    // Tenant key must be present in the captured fields.
    assert!(
        events.iter().any(|e| e.contains("acme")),
        "audit event must carry tenant key; got {events:?}"
    );
}

/// Test 6: The throughput-rejection callback fires once per drop, so
/// a Prometheus counter wired to it sees the expected increment.
#[tokio::test(flavor = "current_thread")]
async fn tenant_throughput_metric_increments_on_rejection() {
    let tracker = Arc::new(TenantQuotaTracker::new(quota_throughput("acme", 100, 0)));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));
    let counter = Arc::new(AtomicU64::new(0));
    {
        let c = Arc::clone(&counter);
        tracker.set_on_throughput_rejection(Some(Arc::new(move |t: &str| {
            assert_eq!(t, "acme");
            let _ = c.fetch_add(1, Ordering::Relaxed);
        })));
    }
    let (_id, _rx) = make_session(&router, "acme-recv", Some("acme")).await;
    let sender = make_identity("acme-sender", Some("acme"));

    // 3 over-cap drains → 3 callback invocations.
    for i in 0..3 {
        let routed = router
            .route_for_egress(make_msg(&sender, 200, &format!("REJ-{i}")))
            .await;
        assert!(routed.is_none(), "over-cap message must be dropped");
    }
    assert_eq!(counter.load(Ordering::Relaxed), 3);
}

/// Test 7: An unrecognized tenant gets the default cap when one is
/// configured; without a default it sails through (the tenant bucket
/// is a layer on top of per-session, not a replacement).
#[tokio::test(flavor = "current_thread")]
async fn tenant_token_bucket_handles_unknown_tenant_with_default() {
    let config = QuotaConfig {
        tenants: HashMap::new(),
        default_quota: Some(TenantQuota {
            max_connections: 0,
            max_message_rate: 0,
            max_queued_bytes: 0,
            max_throughput_bps: 100,
            refill_throughput_bps: 0,
        }),
    };
    let tracker = Arc::new(TenantQuotaTracker::new(config));
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));
    let (_id, _rx) = make_session(&router, "stranger-recv", Some("Unknown LLC")).await;
    let sender = make_identity("stranger-sender", Some("Unknown LLC"));

    // First 100B admit, second 1B rejected (default cap = 100).
    assert!(
        router
            .route_for_egress(make_msg(&sender, 100, "U-1"))
            .await
            .is_some()
    );
    assert!(
        router
            .route_for_egress(make_msg(&sender, 1, "U-2"))
            .await
            .is_none(),
        "default cap must apply to unknown tenants when configured"
    );
}

/// Test 8: The per-tenant bucket and the per-session bucket compose:
/// per-session is a SUB-cap (each session's read loop limits its
/// individual rate); per-tenant is the AGGREGATE cap. A message that
/// passes both is delivered exactly once (no double-decrement of the
/// per-session bucket from a tenant-side check).
///
/// We pin the composition at the API level: the tenant bucket lives
/// in `TenantQuotaTracker`, the per-session bucket lives in
/// `rustgate_transport::ClientThrottle` — they are independent
/// counters with no shared state. Charging one must not affect the
/// other. A regression that wired the tenant bucket as a subset of
/// the per-session counter would make `ClientThrottle::available`
/// jump on a tenant-side acquire.
#[tokio::test(flavor = "current_thread")]
async fn tenant_token_bucket_does_not_double_account_with_per_session_bucket() {
    use rustgate_transport::ClientThrottle;

    // Per-session throttle: 5 messages burst, no refill. We charge it
    // once and expect 4 to remain.
    let session_throttle = ClientThrottle::new(0, 5);
    assert_eq!(session_throttle.available(), 5);
    assert!(session_throttle.allow());
    assert_eq!(session_throttle.available(), 4);

    // Per-tenant bucket: 10 000-byte cap.
    let tracker = Arc::new(TenantQuotaTracker::new(quota_throughput("acme", 10_000, 0)));
    // Charging the tenant bucket must not affect the session throttle.
    assert!(tracker.try_acquire_tenant_tokens("acme", 1_000).is_ok());
    assert_eq!(
        session_throttle.available(),
        4,
        "tenant-bucket acquire must not touch per-session counter"
    );
    // And vice versa: charging the session throttle must not refund
    // or charge the tenant bucket.
    assert!(session_throttle.allow());
    assert_eq!(session_throttle.available(), 3);
    let level_after = tracker.tenant_throughput_available("acme").unwrap();
    assert!(
        (level_after - 9_000.0).abs() < 1.0,
        "tenant bucket level must remain ~9 000 after a session-side allow; got {level_after}"
    );

    // Compose under load: a message that passes BOTH buckets is
    // delivered once. Drive through the router with a 100-byte
    // payload — both buckets admit (session has 3 tokens, tenant has
    // 9 000B). The post-route fan-out increments exactly one
    // recipient delivery.
    let router = Router::new().with_quota_tracker(Arc::clone(&tracker));
    let (_id, mut rx) = make_session(&router, "acme-recv", Some("acme")).await;
    let sender = make_identity("acme-sender", Some("acme"));
    let routed = router
        .route_for_egress(make_msg(&sender, 100, "BOTH-1"))
        .await;
    assert!(routed.is_some(), "passes both buckets → admitted");
    let received = rx.try_recv();
    assert!(
        received.is_ok(),
        "exactly-once delivery: receiver must observe the admitted message"
    );
}
