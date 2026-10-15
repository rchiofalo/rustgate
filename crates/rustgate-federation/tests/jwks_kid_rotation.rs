// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the JWKS `kid` rotation-window state machine
//! (closes #952). This is the third sub-item of #952 — Ed25519 (RFC
//! 8037 EdDSA) signing landed via PR #1230 and JWKS URL fetching landed
//! via PR #1252; this PR rounds out the umbrella.
//!
//! The whole file is gated behind the `jwks` feature because the
//! module under test (`rustgate_federation::jwks_rotation`) only
//! compiles when that feature is enabled.
//!
//! # Test inventory
//!
//! 1. `kid_lifecycle_pending_then_active_after_two_consecutive_refreshes`
//!    — first refresh sees a kid → Pending; second refresh after
//!    `pending_window` still sees the kid → Active.
//! 2. `kid_lifecycle_pending_disappears_before_promotion` — first
//!    refresh sees a kid → Pending; before second refresh it drops
//!    from upstream → Pending entry pruned, never registered as
//!    Active.
//! 3. `kid_lifecycle_active_to_retiring_when_dropped_from_upstream` —
//!    Active kid drops from JWKS → state transitions to Retiring.
//! 4. `kid_lifecycle_retiring_still_verifies_jwts_during_grace` — JWT
//!    signed with retiring kid verifies; audit event fires.
//! 5. `kid_lifecycle_retiring_to_retired_after_grace_window` — advance
//!    test clock past grace window → kid removed from registry.
//! 6. `kid_lifecycle_retiring_returns_to_active_if_kid_reappears_in_jwks`
//!    — Retiring kid reappears in upstream → flips back to Active
//!    without going through Pending.
//! 7. `audit_jwt_using_retiring_kid_fires_with_retiring_seconds_field`
//!    — wire shape of `jwt.using_retiring_kid` audit record pinned.
//!
//! Tests use `tokio::time::pause` + `tokio::time::advance` for
//! deterministic clock control (the workspace tokio dev-dep enables
//! the `test-util` feature per the JWKS-client tests).

#![cfg(feature = "jwks")]
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ring::rand::SystemRandom;
use ring::signature::{self as ring_sig};
use rustgate_federation::jwks_rotation::{
    RetainedVerifiers, RotationState, RotationStateMachine, install_on_authority,
};
use rustgate_federation::jwt::{ExternalVerifier, JwtAuthority};
use tokio::time::Instant;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

// ── Test fixtures ──────────────────────────────────────────────────────

/// Build a `HashSet<String>` from `&[&str]` (the in-JWKS observation
/// shape the state machine consumes).
fn observed(kids: &[&str]) -> HashSet<String> {
    kids.iter().map(|s| s.to_string()).collect()
}

/// Generate a fresh Ed25519 PKCS#8 keypair plus the raw 32-byte public
/// key the JWT verifier expects. Ed25519 is the default modern
/// federation signing algorithm and the constant-size public key keeps
/// the test fixture wiring tidy.
fn ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let pkcs8 = ring_sig::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keygen");
    let kp = ring_sig::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
    use ring::signature::KeyPair;
    let pub_key = kp.public_key().as_ref().to_vec();
    (pkcs8.as_ref().to_vec(), pub_key)
}

/// Mint a JWT signed by an Ed25519 key with the supplied `kid` and
/// issuer. Used to drive the `JwtAuthority::validate` path under test.
fn mint_ed25519_jwt(pkcs8: &[u8], kid: &str, issuer: &str) -> String {
    let auth = JwtAuthority::new_ed25519(pkcs8, kid, issuer).expect("auth");
    auth.issue("peer-test", vec![]).expect("issue")
}

/// Capture the audit-target tracing output produced by `f` into a
/// shared in-memory buffer. Returns the JSON-encoded snapshot for
/// assertion. Mirrors the helper used by other audit-shape tests.
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);
impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut g) = self.0.lock() {
            g.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn install_audit_capture() -> (SharedBuf, tracing::subscriber::DefaultGuard) {
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let guard = tracing::subscriber::set_default(subscriber);
    (buf, guard)
}

fn audit_log(buf: &SharedBuf) -> String {
    let snap = match buf.0.lock() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    };
    String::from_utf8_lossy(&snap).into_owned()
}

// ── Tests ──────────────────────────────────────────────────────────────

// 1. Pending → Active after two consecutive refreshes that satisfy the
//    pending-window floor.
#[tokio::test(start_paused = true)]
async fn kid_lifecycle_pending_then_active_after_two_consecutive_refreshes() {
    let m = RotationStateMachine::new(
        Duration::from_secs(60),
        Duration::from_secs(300),
        "https://idp.test/jwks.json",
    );
    // Refresh 1 sees the kid for the first time → Pending.
    let now1 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-new"]), now1);
    assert_eq!(
        m.state_of("k-new"),
        Some(RotationState::Pending),
        "first observation must yield Pending"
    );

    // Advance just past the pending_window. Refresh 2 must promote.
    tokio::time::advance(Duration::from_secs(61)).await;
    let now2 = Instant::now();
    let t = m.observe_refresh(&observed(&["k-new"]), now2);
    assert_eq!(
        m.state_of("k-new"),
        Some(RotationState::Active),
        "second observation past pending_window must yield Active"
    );
    assert_eq!(t.promoted, vec!["k-new".to_string()]);
}

// 2. Pending kid that disappears from the next refresh must be pruned
//    entirely — defends against typo'd JWKS pushes.
#[tokio::test(start_paused = true)]
async fn kid_lifecycle_pending_disappears_before_promotion() {
    let m = RotationStateMachine::new(
        Duration::from_secs(60),
        Duration::from_secs(300),
        "https://idp.test/jwks.json",
    );
    let now1 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-typo"]), now1);
    assert_eq!(m.state_of("k-typo"), Some(RotationState::Pending));

    tokio::time::advance(Duration::from_secs(61)).await;
    let now2 = Instant::now();
    let t = m.observe_refresh(&observed(&[]), now2);
    assert_eq!(
        m.state_of("k-typo"),
        None,
        "Pending entry must be pruned, never promoted to Active"
    );
    assert_eq!(t.pending_pruned, vec!["k-typo".to_string()]);
    assert!(
        t.promoted.is_empty(),
        "no promotion must fire for a rolled-back JWKS push"
    );
}

// 3. Active kid that drops from upstream JWKS must transition to Retiring.
#[tokio::test(start_paused = true)]
async fn kid_lifecycle_active_to_retiring_when_dropped_from_upstream() {
    let m = RotationStateMachine::new(
        Duration::from_secs(60),
        Duration::from_secs(300),
        "https://idp.test/jwks.json",
    );
    // Promote.
    let now1 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-rotating"]), now1);
    tokio::time::advance(Duration::from_secs(61)).await;
    let now2 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-rotating"]), now2);
    assert_eq!(m.state_of("k-rotating"), Some(RotationState::Active));

    // Drop.
    tokio::time::advance(Duration::from_secs(60)).await;
    let now3 = Instant::now();
    let t = m.observe_refresh(&observed(&[]), now3);
    assert_eq!(m.state_of("k-rotating"), Some(RotationState::Retiring));
    assert_eq!(t.demoted, vec!["k-rotating".to_string()]);
}

// 4. JWT signed with a Retiring kid still verifies; audit event fires.
//    This is the integration test that drives an actual JwtAuthority
//    validate call rather than just the state machine in isolation.
#[tokio::test(start_paused = true)]
async fn kid_lifecycle_retiring_still_verifies_jwts_during_grace() {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    // Set up an authority + verifier under kid "k-grace".
    let (pkcs8_local, _pub_local) = ed25519_keypair();
    let (pkcs8_peer, pub_peer) = ed25519_keypair();
    let auth =
        Arc::new(JwtAuthority::new_ed25519(&pkcs8_local, "k-self", "rustgate-test").expect("auth"));

    // Drive the state machine into Retiring for k-grace.
    let m = Arc::new(RotationStateMachine::new(
        Duration::from_secs(60),
        Duration::from_secs(300),
        "https://idp.test/jwks.json",
    ));
    let retained = RetainedVerifiers::new();
    let mut fresh = HashMap::new();
    let _ = fresh.insert(
        "k-grace".to_string(),
        ExternalVerifier::EdDsa(pub_peer.clone()),
    );
    retained.upsert(&fresh);

    let now1 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-grace"]), now1);
    tokio::time::advance(Duration::from_secs(61)).await;
    let now2 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-grace"]), now2);
    // Now Active. Install the verifier set into the authority and wire
    // the rotation hook.
    let install = m.filter_for_install(fresh.clone(), &retained.snapshot());
    auth.install_external_verifiers(install);
    install_on_authority(Arc::clone(&m), &auth);

    // Drop k-grace — moves to Retiring.
    tokio::time::advance(Duration::from_secs(60)).await;
    let now3 = Instant::now();
    let _ = m.observe_refresh(&observed(&[]), now3);
    assert_eq!(m.state_of("k-grace"), Some(RotationState::Retiring));
    // Re-install: include retained verifier for the grace window.
    let install = m.filter_for_install(HashMap::new(), &retained.snapshot());
    auth.install_external_verifiers(install);

    // Mint a JWT with the Retiring kid AND wire audit capture.
    let (buf, _guard) = install_audit_capture();
    let jwt = mint_ed25519_jwt(&pkcs8_peer, "k-grace", "rustgate-test");

    // Validation must succeed.
    let claims = auth.validate(&jwt).expect("retiring kid must still verify");
    assert_eq!(claims.sub, "peer-test");

    let log = audit_log(&buf);
    assert!(
        log.contains(r#""event_type":"jwt.using_retiring_kid""#),
        "audit event must fire for Retiring kid use: {log}"
    );
    assert!(
        log.contains(r#""kid":"k-grace""#),
        "audit event must carry kid field: {log}"
    );
}

// 5. Retiring → Retired after the grace window elapses.
#[tokio::test(start_paused = true)]
async fn kid_lifecycle_retiring_to_retired_after_grace_window() {
    let m = RotationStateMachine::new(
        Duration::from_secs(60),
        Duration::from_secs(300),
        "https://idp.test/jwks.json",
    );
    let now1 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-fade"]), now1);
    tokio::time::advance(Duration::from_secs(61)).await;
    let now2 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-fade"]), now2);
    // Active.
    tokio::time::advance(Duration::from_secs(60)).await;
    let now3 = Instant::now();
    let _ = m.observe_refresh(&observed(&[]), now3);
    assert_eq!(m.state_of("k-fade"), Some(RotationState::Retiring));

    // Past the grace window.
    tokio::time::advance(Duration::from_secs(301)).await;
    let now4 = Instant::now();
    let t = m.observe_refresh(&observed(&[]), now4);
    assert_eq!(m.state_of("k-fade"), Some(RotationState::Retired));
    assert_eq!(t.retired, vec!["k-fade".to_string()]);
}

// 6. Retiring kid that reappears in the upstream JWKS flips back to
//    Active without going through Pending.
#[tokio::test(start_paused = true)]
async fn kid_lifecycle_retiring_returns_to_active_if_kid_reappears_in_jwks() {
    let m = RotationStateMachine::new(
        Duration::from_secs(60),
        Duration::from_secs(300),
        "https://idp.test/jwks.json",
    );
    let now1 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-flap"]), now1);
    tokio::time::advance(Duration::from_secs(61)).await;
    let now2 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-flap"]), now2);
    // Active.
    tokio::time::advance(Duration::from_secs(60)).await;
    let now3 = Instant::now();
    let _ = m.observe_refresh(&observed(&[]), now3);
    assert_eq!(m.state_of("k-flap"), Some(RotationState::Retiring));

    // Reappear during grace window.
    tokio::time::advance(Duration::from_secs(30)).await;
    let now4 = Instant::now();
    let t = m.observe_refresh(&observed(&["k-flap"]), now4);
    assert_eq!(
        m.state_of("k-flap"),
        Some(RotationState::Active),
        "Retiring kid that reappears must go straight back to Active"
    );
    assert!(
        t.promoted.contains(&"k-flap".to_string()),
        "the flip must surface in the diff as a promotion"
    );
}

// 7. Audit-event field shape: `retiring_for_seconds` is the elapsed
//    grace seconds since demotion.
#[tokio::test(start_paused = true)]
async fn audit_jwt_using_retiring_kid_fires_with_retiring_seconds_field() {
    let m = RotationStateMachine::new(
        Duration::from_secs(60),
        Duration::from_secs(300),
        "https://idp.test/jwks.json",
    );

    // Promote to Active.
    let now1 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-aud"]), now1);
    tokio::time::advance(Duration::from_secs(61)).await;
    let now2 = Instant::now();
    let _ = m.observe_refresh(&observed(&["k-aud"]), now2);
    assert_eq!(m.state_of("k-aud"), Some(RotationState::Active));

    // Demote.
    tokio::time::advance(Duration::from_secs(60)).await;
    let demote_at = Instant::now();
    let _ = m.observe_refresh(&observed(&[]), demote_at);
    assert_eq!(m.state_of("k-aud"), Some(RotationState::Retiring));

    // Capture audit output and notify with a known offset.
    let (buf, _guard) = install_audit_capture();
    tokio::time::advance(Duration::from_secs(123)).await;
    let used_at = Instant::now();
    m.notify_kid_used("k-aud", used_at);

    let log = audit_log(&buf);
    assert!(
        log.contains(r#""event_type":"jwt.using_retiring_kid""#),
        "missing event_type: {log}"
    );
    assert!(log.contains(r#""kid":"k-aud""#), "missing kid: {log}");
    assert!(
        log.contains(r#""retiring_for_seconds":123"#),
        "expected retiring_for_seconds=123 in: {log}"
    );
    assert!(
        log.contains(r#""action":"verify""#),
        "missing action: {log}"
    );
    assert!(
        log.contains(r#""result":"warning""#),
        "missing result: {log}"
    );
}
