// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration test for store-forward drain re-applying obligations
//! introduced while the recipient was offline (refs #787, F-24).
//!
//! The pre-existing `store_forward_authz.rs` integration suite covers
//! two drain-time policy-change paths:
//!
//! - **Permission unchanged** — message passes straight through.
//! - **ACL/authz tightened to deny** — drained message is filtered out.
//!
//! What is missing — and what this test pins — is the third path:
//! **the policy was *augmented* with a new obligation while the client
//! was offline**. Specifically: a recipient who could previously
//! receive a CoT position with raw coordinates is now required to
//! receive it with `<point>` masked, because the operator added a
//! `MaskPoint` obligation to the Receive PEP after the client
//! disconnected. The drain must re-apply the **current** Receive
//! obligations, not the (stale) decision that was in force at storage
//! time, so on reconnect Bob receives the message with coordinates
//! zeroed exactly as if it had been routed live under the new policy.
//!
//! Without this test, a regression that bypassed
//! `apply_obligations_with_limiter` on the drain path would let stored
//! coordinates leak to a recipient whose live-stream form is now
//! masked — the leak vector is invisible to the existing "permission
//! tightened to deny" coverage because the message still passes the
//! authz allow check on drain.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::{
    Action, Decision, DecisionOutcome, Effect, NativeEngine, Obligation, PolicyEngine, Resource,
    RuleSet, Subject,
};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{ClientQueue, Router};
use tempfile::TempDir;

const SAMPLE_COT: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;

fn identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
    Arc::new(
        Identity::new(
            cn.to_string(),
            format!("{cn}-fp"),
            groups
                .iter()
                .map(|g| g.to_string())
                .collect::<BTreeSet<_>>(),
        )
        .expect("valid identity"),
    )
}

fn cot_position(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(SAMPLE_COT),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Position),
    }
}

/// Engine that allows everything with no obligations. Mirrors the
/// pre-policy-change steady state where the message was originally
/// routed and stored.
fn allow_all_engine() -> Arc<dyn PolicyEngine> {
    let rules = RuleSet {
        version: 1,
        default_effect: Effect::Allow,
        rules: Vec::new(),
    };
    Arc::new(NativeEngine::new(rules).expect("compile"))
}

/// Engine that allows everything but attaches a `MaskPoint` obligation
/// on `Receive`. Mirrors the post-policy-change state where the
/// operator tightened recipient-side leak prevention while the
/// recipient was offline.
struct AllowWithReceiveMaskPointEngine;

impl PolicyEngine for AllowWithReceiveMaskPointEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, action: Action) -> DecisionOutcome {
        let obligations = if action == Action::Receive {
            vec![Obligation::MaskPoint]
        } else {
            Vec::new()
        };
        DecisionOutcome {
            decision: Decision::Allow,
            rule_id: Some(smol_str::SmolStr::new("test-mask-point-on-receive")),
            obligations,
        }
    }
    fn policy_id(&self) -> &str {
        "test-mask-point-on-receive"
    }
}

// ── F-24: obligation added while offline ────────────────────────────────

/// Store a CoT position destined for an offline recipient under an
/// allow-all policy with no obligations, then swap to a policy that
/// attaches `MaskPoint` on `Receive` before the recipient reconnects.
/// On drain, `filter_offline_messages` must re-apply the **current**
/// Receive obligation set so the recipient receives the message with
/// `<point>` coordinates zeroed — even though no obligation existed
/// at storage time.
///
/// Without this re-evaluation, a recipient who reconnected after a
/// post-storage policy tightening would observe raw coordinates in the
/// drained copy while the live-stream form (under the same
/// post-tightening policy) would be masked. The store-forward queue
/// must not become a leak vector for stored payloads.
#[tokio::test]
async fn stored_message_acquires_receive_obligation_added_while_offline() {
    let tmp = TempDir::new().expect("tempdir");
    let queue = Arc::new(ClientQueue::open(tmp.path(), 1_000_000).expect("open queue"));

    // Step 1: original policy is allow-all with NO obligations. The
    // message is routed under this policy and lands in the queue with
    // raw coordinates intact (the store-forward queue persists the
    // pre-PEP form; the PEP runs again at drain time).
    let router = Router::new()
        .with_client_queue(Arc::clone(&queue))
        .with_authz(allow_all_engine());

    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    router
        .route(cot_position(&alice, Destination::Direct((*bob).clone())))
        .await;

    // Wait for the async writer task to persist the message.
    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(queue.stats("bob").depth, 1, "message must be queued");

    // Step 2: while bob is still offline, swap to a policy that attaches
    // `MaskPoint` to every `Receive` decision. Live deliveries from this
    // moment forward would be masked at the per-recipient PEP.
    router.swap_authz(Arc::new(AllowWithReceiveMaskPointEngine));

    // Step 3: bob reconnects → drain offline messages. The drained
    // payload before filtering still contains the raw coordinates
    // (storage preserves the original bytes); the filter step must
    // re-evaluate the Receive PEP and apply the new MaskPoint
    // obligation before handing the envelope to the recipient.
    let drained = router.drain_offline_messages("bob").await;
    assert_eq!(drained.len(), 1, "raw drain should return the message");

    // Sanity: storage preserved the pre-PEP payload — the masked form
    // is produced by the drain-time obligation re-application, not by
    // any compute that happened at storage time.
    let raw_payload = drained
        .first()
        .map(|m| m.payload.clone())
        .expect("one drained message");
    let raw = std::str::from_utf8(&raw_payload).expect("CoT is valid UTF-8");
    assert!(
        raw.contains("38.8977"),
        "store-forward must preserve the pre-PEP payload; got {raw}"
    );

    let filtered = router.filter_offline_messages(&bob, drained);
    assert_eq!(
        filtered.len(),
        1,
        "the post-tightening policy still allows the receive — only the obligation is new"
    );

    let pending = filtered
        .into_iter()
        .next()
        .expect("filter produced one envelope");
    let (delivered, _audit) = pending.into_parts();

    let masked = std::str::from_utf8(&delivered.payload).expect("masked payload is valid UTF-8");
    assert!(
        masked.contains(r#"lat="0.0""#),
        "drained message must have lat zeroed by the new MaskPoint obligation: {masked}"
    );
    assert!(
        masked.contains(r#"lon="0.0""#),
        "drained message must have lon zeroed by the new MaskPoint obligation: {masked}"
    );
    assert!(
        masked.contains(r#"hae="0.0""#),
        "drained message must have hae zeroed by the new MaskPoint obligation: {masked}"
    );
    assert!(
        !masked.contains("38.8977"),
        "raw lat must not leak through the drain re-evaluation: {masked}"
    );
    assert!(
        !masked.contains("-77.0365"),
        "raw lon must not leak through the drain re-evaluation: {masked}"
    );
}

/// Companion case: `MaskPayload` added while offline must also be
/// re-applied at drain time. The redactor pair (`MaskPoint`,
/// `MaskPayload`) is the load-bearing leak-prevention surface; pinning
/// both variants here keeps a regression that bypassed the
/// recv-obligation application from being caught by only the
/// coordinate-mask path.
#[tokio::test]
async fn stored_message_acquires_mask_payload_obligation_added_while_offline() {
    let tmp = TempDir::new().expect("tempdir");
    let queue = Arc::new(ClientQueue::open(tmp.path(), 1_000_000).expect("open queue"));

    let router = Router::new()
        .with_client_queue(Arc::clone(&queue))
        .with_authz(allow_all_engine());

    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    router
        .route(cot_position(&alice, Destination::Direct((*bob).clone())))
        .await;

    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(queue.stats("bob").depth, 1, "message must be queued");

    /// Allow-all + MaskPayload on Receive. Defined inline so the helper
    /// in this module remains a single-purpose test fixture.
    struct AllowWithReceiveMaskPayload;
    impl PolicyEngine for AllowWithReceiveMaskPayload {
        fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, action: Action) -> DecisionOutcome {
            let obligations = if action == Action::Receive {
                vec![Obligation::MaskPayload]
            } else {
                Vec::new()
            };
            DecisionOutcome {
                decision: Decision::Allow,
                rule_id: Some(smol_str::SmolStr::new("test-mask-payload-on-receive")),
                obligations,
            }
        }
        fn policy_id(&self) -> &str {
            "test-mask-payload-on-receive"
        }
    }

    router.swap_authz(Arc::new(AllowWithReceiveMaskPayload));

    let drained = router.drain_offline_messages("bob").await;
    assert_eq!(drained.len(), 1, "raw drain should return the message");

    let filtered = router.filter_offline_messages(&bob, drained);
    assert_eq!(filtered.len(), 1, "filter must allow the receive");

    let pending = filtered
        .into_iter()
        .next()
        .expect("filter produced one envelope");
    let (delivered, _audit) = pending.into_parts();

    assert!(
        delivered.payload.is_empty(),
        "drained payload body must be wiped by the new MaskPayload obligation"
    );
    assert_eq!(
        delivered.metadata.message_type,
        MessageType::Other("masked".into()),
        "MaskPayload must coerce message_type to other:masked even on the drain path"
    );
}
