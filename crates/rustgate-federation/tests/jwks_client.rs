// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the federation JWKS URL fetcher
//! (`rustgate_federation::jwks_client`). Refs #952.
//!
//! The whole file is gated behind the `jwks` feature because the
//! module under test only compiles when that feature is enabled.

#![cfg(feature = "jwks")]
//!
//! Test inventory (one per `#[tokio::test]` below):
//!
//! 1. `initial_fetch_populates_es256_and_eddsa_verifiers` — ES256 +
//!    EdDSA JWKs roundtrip into working JWT verification.
//! 2. `cache_control_max_age_clamped_into_window` — refresh interval
//!    honours `Cache-Control: max-age=<N>`, clamped into
//!    `[refresh_min, refresh_max]`.
//! 3. `removed_kid_no_longer_verifies_after_refresh` — a kid dropped
//!    by the upstream JWKS response stops verifying.
//! 4. `server_5xx_keeps_cached_keyset_valid` — 503 responses do NOT
//!    rotate keys out (fail-closed posture).
//! 5. `hs256_rejected_by_default_loaded_when_allowed` — symmetric
//!    secrets are gated behind `allow_hs256: true`.
//! 6. `audit_events_fire_on_lifecycle_transitions` — success / failure
//!    / key-added / key-removed audit events are emitted.
//! 7. `mtls_to_jwks_server_uses_federation_trust_bundle` — the JWKS
//!    client presents the federation client cert and validates the
//!    server cert against the same CA as federation peers.
//!
//! Tests 1-6 use `wiremock` over plain HTTP because they exercise
//! protocol-level invariants (refresh interval, fail-closed
//! semantics, audit emission) that do not depend on TLS. Test 7
//! spins up a hand-rolled `tokio-rustls` server because wiremock has
//! no TLS support — it serves a fixed JWKS body and validates the
//! client cert against the same `TestCa` the federation connector
//! uses.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ring::rand::SystemRandom;
use ring::signature::{self as ring_sig, KeyPair};
use rustgate_core::b64;
use rustgate_federation::jwks_client::{JwksClient, JwksConfig};
use rustgate_federation::jwt::{Algorithm, JwtAuthority};
use rustgate_test_utils::certs::TestCa;
use rustls::pki_types::PrivateKeyDer;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

// ── Test helpers ────────────────────────────────────────────────────

/// Generate a fresh ES256 keypair → (PKCS#8 DER bytes, JWK x/y pair).
fn fresh_es256_jwk(kid: &str) -> (Vec<u8>, serde_json::Value) {
    let pkcs8 = ring_sig::EcdsaKeyPair::generate_pkcs8(
        &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
        &SystemRandom::new(),
    )
    .expect("keygen");
    let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
        &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &SystemRandom::new(),
    )
    .expect("parse");
    let pub_sec1 = key_pair.public_key().as_ref();
    assert_eq!(pub_sec1.len(), 65);
    let x = b64::encode_url_safe(&pub_sec1[1..33]);
    let y = b64::encode_url_safe(&pub_sec1[33..65]);
    (
        pkcs8.as_ref().to_vec(),
        json!({
            "kty": "EC",
            "kid": kid,
            "alg": "ES256",
            "crv": "P-256",
            "x": x,
            "y": y,
            "use": "sig"
        }),
    )
}

/// Generate a fresh Ed25519 keypair → (PKCS#8 DER, JWK).
fn fresh_ed25519_jwk(kid: &str) -> (Vec<u8>, serde_json::Value) {
    let pkcs8 = ring_sig::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keygen");
    let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
    let raw = key_pair.public_key().as_ref();
    assert_eq!(raw.len(), 32);
    (
        pkcs8.as_ref().to_vec(),
        json!({
            "kty": "OKP",
            "kid": kid,
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": b64::encode_url_safe(raw),
            "use": "sig"
        }),
    )
}

/// Build an `Arc<JwtAuthority>` seeded with an HS256 issuer (we only
/// use this authority's verifier registry — we never sign anything
/// from the test side so the issuer secret is just placeholder).
fn fresh_authority() -> Arc<JwtAuthority> {
    Arc::new(
        JwtAuthority::new(
            b"this-is-32-bytes-test-key-aaaaaa".to_vec(),
            "rustgate-test",
        )
        .expect("hs256 issuer"),
    )
}

/// Wait up to `timeout` for `predicate` to return true. Polls every
/// 25 ms. The JWKS refresh task wakes asynchronously, so tests use
/// this rather than blanket `tokio::time::sleep`.
async fn wait_for(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    predicate()
}

/// Mint a JWT signed with the supplied PKCS#8 ES256 key, stamped with
/// the given `kid`. Used to verify a refreshed verifier set actually
/// works end-to-end.
fn mint_es256_jwt(pkcs8: &[u8], kid: &str) -> String {
    let auth = JwtAuthority::new_es256(pkcs8, kid, "rustgate-test").expect("authority");
    auth.issue("peer-test", vec![]).expect("issue")
}

fn mint_ed25519_jwt(pkcs8: &[u8], kid: &str) -> String {
    let auth = JwtAuthority::new_ed25519(pkcs8, kid, "rustgate-test").expect("authority");
    auth.issue("peer-test", vec![]).expect("issue")
}

// ── Tracing capture helper for audit assertions ────────────────────

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

// ── 1. Initial fetch: ES256 + EdDSA verifier registration ───────────

#[tokio::test]
async fn initial_fetch_populates_es256_and_eddsa_verifiers() {
    let (es_pkcs8, es_jwk) = fresh_es256_jwk("k-es");
    let (ed_pkcs8, ed_jwk) = fresh_ed25519_jwk("k-ed");

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [es_jwk, ed_jwk]
        })))
        .mount(&mock)
        .await;

    let authority = fresh_authority();
    let url = format!("{}/jwks.json", mock.uri());

    // Wiremock is HTTP-only so we cannot use JwksClient::start (which
    // enforces HTTPS). Drive the same refresh body directly. We test
    // the HTTPS guard separately in `JwksConfig` unit tests.
    refresh_via_test_client(&url, &authority, false).await;

    let kids = authority.external_verifier_kids();
    assert_eq!(kids.len(), 2, "both kids registered");
    assert!(kids.contains(&"k-es".to_string()));
    assert!(kids.contains(&"k-ed".to_string()));

    // Mint and validate a JWT with each kid.
    let jwt_es = mint_es256_jwt(&es_pkcs8, "k-es");
    let claims = authority.validate(&jwt_es).expect("ES256 validates");
    assert_eq!(claims.sub, "peer-test");

    let jwt_ed = mint_ed25519_jwt(&ed_pkcs8, "k-ed");
    let claims = authority.validate(&jwt_ed).expect("EdDSA validates");
    assert_eq!(claims.sub, "peer-test");

    assert_eq!(authority.verifier_algorithm("k-es"), Some(Algorithm::Es256));
    assert_eq!(authority.verifier_algorithm("k-ed"), Some(Algorithm::EdDsa));
}

// ── 2. Cache-Control: max-age clamped into [refresh_min, refresh_max]

#[tokio::test]
async fn cache_control_max_age_clamped_into_window() {
    let (_, es_jwk) = fresh_es256_jwk("k-es");
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"keys": [es_jwk]}))
                .insert_header("cache-control", "max-age=86400, public"),
        )
        .mount(&mock)
        .await;

    // The HTTP-only test path returns the parsed `max-age` clamped.
    let cfg = JwksConfig {
        url: format!("{}/jwks.json", mock.uri()),
        refresh_min: Duration::from_secs(120),
        refresh_max: Duration::from_secs(3600),
        allow_hs256: false,
        pending_window: Duration::from_secs(60),
        retiring_window: Duration::from_secs(300),
    };
    let next_delay = test_refresh_returning_delay(&cfg).await;
    assert_eq!(
        next_delay,
        Duration::from_secs(3600),
        "86400s upstream hint must clamp DOWN to refresh_max"
    );

    // Now configure a hint below the floor.
    let mock_low = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"keys": [fresh_es256_jwk("k-es-2").1]}))
                .insert_header("cache-control", "max-age=10"),
        )
        .mount(&mock_low)
        .await;
    let cfg_low = JwksConfig {
        url: format!("{}/jwks.json", mock_low.uri()),
        refresh_min: Duration::from_secs(120),
        refresh_max: Duration::from_secs(3600),
        allow_hs256: false,
        pending_window: Duration::from_secs(60),
        retiring_window: Duration::from_secs(300),
    };
    let delay_low = test_refresh_returning_delay(&cfg_low).await;
    assert_eq!(
        delay_low,
        Duration::from_secs(120),
        "10s upstream hint must clamp UP to refresh_min"
    );
}

// ── 3. Removed kid no longer verifies after refresh ────────────────

#[tokio::test]
async fn removed_kid_no_longer_verifies_after_refresh() {
    let (es_pkcs8, es_jwk) = fresh_es256_jwk("k-old");
    let (es2_pkcs8, es2_jwk) = fresh_es256_jwk("k-new");

    // First response: only k-old.
    // Second response: only k-new.
    let mock = MockServer::start().await;
    let body_calls = Arc::new(Mutex::new(0u32));
    let bc = Arc::clone(&body_calls);
    let es_jwk_clone = es_jwk.clone();
    let es2_jwk_clone = es2_jwk.clone();
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(move |_: &Request| {
            let mut g = bc.lock().expect("calls");
            *g += 1;
            let n = *g;
            if n == 1 {
                ResponseTemplate::new(200).set_body_json(json!({"keys": [es_jwk_clone.clone()]}))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"keys": [es2_jwk_clone.clone()]}))
            }
        })
        .mount(&mock)
        .await;

    let authority = fresh_authority();
    let url = format!("{}/jwks.json", mock.uri());

    refresh_via_test_client(&url, &authority, false).await;
    // First refresh: k-old works.
    let jwt_old = mint_es256_jwt(&es_pkcs8, "k-old");
    let _claims = authority.validate(&jwt_old).expect("k-old verifies");

    refresh_via_test_client(&url, &authority, false).await;
    // Second refresh: k-old removed, k-new works.
    let kids = authority.external_verifier_kids();
    assert_eq!(kids, vec!["k-new".to_string()]);
    let err = authority
        .validate(&jwt_old)
        .expect_err("k-old must reject after removal");
    use rustgate_federation::jwt::JwtError;
    assert!(matches!(err, JwtError::UnknownKid(_)), "got {err:?}");

    let jwt_new = mint_es256_jwt(&es2_pkcs8, "k-new");
    let _ = authority.validate(&jwt_new).expect("k-new verifies");
}

// ── 4. Server 5xx keeps cached keyset valid ────────────────────────

#[tokio::test]
async fn server_5xx_keeps_cached_keyset_valid() {
    let (es_pkcs8, es_jwk) = fresh_es256_jwk("k-cached");

    let mock = MockServer::start().await;
    let calls = Arc::new(Mutex::new(0u32));
    let calls_clone = Arc::clone(&calls);
    let jwk_clone = es_jwk.clone();
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(move |_: &Request| {
            let mut g = calls_clone.lock().expect("calls");
            *g += 1;
            let n = *g;
            if n == 1 {
                ResponseTemplate::new(200).set_body_json(json!({"keys": [jwk_clone.clone()]}))
            } else {
                ResponseTemplate::new(503).set_body_string("upstream unavailable")
            }
        })
        .mount(&mock)
        .await;

    let authority = fresh_authority();
    let url = format!("{}/jwks.json", mock.uri());

    // First refresh succeeds, key registered.
    refresh_via_test_client(&url, &authority, false).await;
    let jwt = mint_es256_jwt(&es_pkcs8, "k-cached");
    let _ = authority.validate(&jwt).expect("first verify ok");

    // Second refresh fails (503) — key MUST remain valid.
    let _ = try_refresh_via_test_client(&url, &authority, false).await;

    // Cached verifier still resolves.
    let _ = authority
        .validate(&jwt)
        .expect("cached key must still verify after 503 — fail-closed posture");
    assert_eq!(
        authority.external_verifier_kids().len(),
        1,
        "503 must NOT rotate keys out"
    );
}

// ── 5. HS256 fail-closed by default; loaded on opt-in ──────────────

#[tokio::test]
async fn hs256_rejected_by_default_loaded_when_allowed() {
    let secret = b"this-is-32-bytes-test-key-aaaaaa";
    let k_b64 = b64::encode_url_safe(secret);
    let hs_jwk = json!({
        "kty": "oct",
        "kid": "k-sym",
        "alg": "HS256",
        "k": k_b64,
        "use": "sig"
    });

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": [hs_jwk.clone()]})))
        .mount(&mock)
        .await;

    let url = format!("{}/jwks.json", mock.uri());

    // allow_hs256 = false (default) → key NOT registered.
    let auth_strict = fresh_authority();
    refresh_via_test_client(&url, &auth_strict, false).await;
    assert!(
        auth_strict.external_verifier_kids().is_empty(),
        "HS256 must be filtered when allow_hs256=false"
    );

    // allow_hs256 = true → key registered.
    let auth_permissive = fresh_authority();
    refresh_via_test_client(&url, &auth_permissive, true).await;
    assert_eq!(
        auth_permissive.external_verifier_kids(),
        vec!["k-sym".to_string()],
    );
    assert_eq!(
        auth_permissive.verifier_algorithm("k-sym"),
        Some(Algorithm::Hs256)
    );
}

// ── 6. Audit events on success / failure / add / remove ────────────

#[tokio::test]
async fn audit_events_fire_on_lifecycle_transitions() {
    let (_es_pkcs8, es_jwk) = fresh_es256_jwk("k-added");
    let (_es2_pkcs8, es2_jwk) = fresh_es256_jwk("k-replaced");

    let mock = MockServer::start().await;
    let calls = Arc::new(Mutex::new(0u32));
    let calls_clone = Arc::clone(&calls);
    let jwk1 = es_jwk.clone();
    let jwk2 = es2_jwk.clone();
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(move |_: &Request| {
            let mut g = calls_clone.lock().expect("calls");
            *g += 1;
            match *g {
                1 => ResponseTemplate::new(200).set_body_json(json!({"keys": [jwk1.clone()]})),
                2 => ResponseTemplate::new(200).set_body_json(json!({"keys": [jwk2.clone()]})),
                _ => ResponseTemplate::new(503),
            }
        })
        .mount(&mock)
        .await;

    let (buf, _guard) = install_audit_capture();

    let authority = fresh_authority();
    let url = format!("{}/jwks.json", mock.uri());

    // 1st: success + key_added.
    refresh_via_test_client(&url, &authority, false).await;
    // 2nd: success + key_added(k-replaced) + key_removed(k-added).
    refresh_via_test_client(&url, &authority, false).await;
    // 3rd: failure (503) — `refresh_via_test_client` mirrors the
    // production loop by emitting `jwks_refresh_failed` on Err.
    refresh_via_test_client(&url, &authority, false).await;

    let log = audit_log(&buf);
    assert!(
        log.contains(r#""event_type":"jwks.refresh_success""#),
        "missing refresh_success: {log}"
    );
    assert!(
        log.contains(r#""event_type":"jwks.refresh_failed""#),
        "missing refresh_failed: {log}"
    );
    assert!(
        log.contains(r#""event_type":"jwks.key_added""#),
        "missing key_added: {log}"
    );
    assert!(
        log.contains(r#""kid":"k-added""#),
        "expected kid k-added in log: {log}"
    );
    assert!(
        log.contains(r#""event_type":"jwks.key_removed""#),
        "missing key_removed: {log}"
    );
}

// ── 7. mTLS to JWKS server using federation trust bundle ───────────

#[tokio::test]
async fn mtls_to_jwks_server_uses_federation_trust_bundle() {
    // The federation peer trust bundle is just (CA, client_cert,
    // client_key). We re-use it for the JWKS HTTP client and stand up
    // a tiny TLS server that requires client certs signed by the same
    // CA — the same posture as a federation peer's mTLS endpoint.

    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let ca = TestCa::new("jwks-test-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("federation-jwks-client", &[]);

    let (_es_pkcs8, es_jwk) = fresh_es256_jwk("k-mtls");
    let body = serde_json::to_string(&json!({"keys": [es_jwk]})).unwrap();
    let body_clone = body.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");

    // Build server-side TLS config: server cert + client cert
    // verifier rooted at the same CA.
    let server_certs =
        rustgate_core::pem::parse_certs(server_cert.cert_pem.as_bytes()).expect("server certs");
    let server_key: PrivateKeyDer<'static> =
        rustgate_core::pem::parse_key(server_cert.key_pem.as_bytes()).expect("server key");
    let mut client_roots = rustls::RootCertStore::empty();
    for c in rustgate_core::pem::parse_certs(ca.cert_pem.as_bytes()).expect("ca certs") {
        client_roots.add(c).expect("add ca");
    }
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("verifier");
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key)
            .expect("server config"),
    );

    // Tiny TLS HTTP/1.1 server: accept ONE connection, require client
    // cert validation, return the fixed JWKS body.
    let _server = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let (tcp, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let mut tls = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tls accept failed: {e}");
                return;
            }
        };
        let mut buf = [0u8; 4096];
        // Drain the request line + headers — content is irrelevant
        // because we always reply with the fixed JWKS document.
        let _ = tls.read(&mut buf).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Cache-Control: max-age=60\r\n\
             Connection: close\r\n\
             \r\n{}",
            body_clone.len(),
            body_clone
        );
        let _ = tls.write_all(response.as_bytes()).await;
        let _ = tls.shutdown().await;
    });

    // Build client-side rustls::ClientConfig from the federation
    // trust bundle (CA + client cert/key).
    let client_certs =
        rustgate_core::pem::parse_certs(client_cert.cert_pem.as_bytes()).expect("client certs");
    let client_key: PrivateKeyDer<'static> =
        rustgate_core::pem::parse_key(client_cert.key_pem.as_bytes()).expect("client key");
    let mut roots = rustls::RootCertStore::empty();
    for c in rustgate_core::pem::parse_certs(ca.cert_pem.as_bytes()).expect("ca certs") {
        roots.add(c).expect("add ca");
    }
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, client_key)
            .expect("client auth"),
    );

    // Drive the JWKS client through `start` + the HTTPS path. Use
    // localhost as the SNI name; addr is 127.0.0.1.
    //
    // `pending_window: 0` opts the test out of the rotation-window
    // smoothing (closes #952) so the FIRST refresh promotes the kid
    // straight to Active. The smoothing semantics are exercised by the
    // dedicated `tests/jwks_kid_rotation.rs` suite; this test is the
    // mTLS-trust-bundle integration check and only needs the verifier
    // to be installed within the 10s wait window.
    let url = format!("https://localhost:{}/jwks.json", addr.port());
    let cfg = JwksConfig {
        url: url.clone(),
        refresh_min: Duration::from_secs(60),
        refresh_max: Duration::from_secs(3600),
        allow_hs256: false,
        pending_window: Duration::from_secs(0),
        retiring_window: Duration::from_secs(300),
    };

    let authority = fresh_authority();
    let handle = JwksClient::start(cfg, tls_config, Arc::clone(&authority)).expect("jwks start");

    // Wait for the verifier to be installed.
    let installed = wait_for(Duration::from_secs(10), || {
        !authority.external_verifier_kids().is_empty()
    })
    .await;
    assert!(
        installed,
        "JWKS client did not install a verifier within 10s — mTLS likely failed"
    );
    assert!(
        authority
            .external_verifier_kids()
            .contains(&"k-mtls".to_string())
    );

    // Tear down.
    rustgate_core::tasks::stop_subsystem("jwks-mtls-test", handle).await;
}

// ── Test-only fetch helpers ────────────────────────────────────────
//
// `JwksClient::start` enforces HTTPS, but wiremock is HTTP-only. The
// helpers below call directly into the public
// `rustgate_federation::jwks_client::refresh_once` body so each test
// exercises the SAME parse / diff / install / audit pipeline that
// the production loop runs — only the surrounding tokio task and
// `validate_config` HTTPS gate are bypassed. Test 7 exercises the
// real `JwksClient::start` end-to-end with TLS.

async fn refresh_via_test_client(url: &str, authority: &Arc<JwtAuthority>, allow_hs256: bool) {
    if let Err(e) = try_refresh_via_test_client(url, authority, allow_hs256).await {
        // Mirror the failure-audit emission that lives in the
        // production refresh loop — `refresh_once` only audits on the
        // success path; the surrounding task is responsible for
        // failure audit.
        rustgate_core::audit::jwks_refresh_failed(url, &e);
    }
}

async fn try_refresh_via_test_client(
    url: &str,
    authority: &Arc<JwtAuthority>,
    allow_hs256: bool,
) -> Result<Duration, String> {
    let cfg = JwksConfig {
        url: url.to_string(),
        refresh_min: Duration::from_secs(60),
        refresh_max: Duration::from_secs(3600),
        allow_hs256,
        pending_window: Duration::from_secs(60),
        retiring_window: Duration::from_secs(300),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    // Reconstruct the prior kid → alg map from the live registry so
    // diff/audit fires correctly across calls — JwksClient does this
    // inside its task; the test driver re-derives from the authority
    // before each invocation.
    let mut current: HashMap<String, Algorithm> = authority
        .external_verifier_kids()
        .into_iter()
        .filter_map(|kid| authority.verifier_algorithm(&kid).map(|a| (kid, a)))
        .collect();
    rustgate_federation::jwks_client::refresh_once(&client, &cfg, authority, &mut current)
        .await
        .map_err(|e| e.to_string())
}

async fn test_refresh_returning_delay(cfg: &JwksConfig) -> Duration {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let authority = fresh_authority();
    let mut current: HashMap<String, Algorithm> = HashMap::new();
    rustgate_federation::jwks_client::refresh_once(&client, cfg, &authority, &mut current)
        .await
        .expect("refresh")
}
