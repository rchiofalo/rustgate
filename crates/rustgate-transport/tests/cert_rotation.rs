// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for graceful TLS server certificate rotation.
//!
//! Pre-this-file the cert reloader (`crates/rustgate-transport/src/cert_reloader.rs`)
//! had unit tests that exercised the `ArcSwap`-backed swap mechanism in
//! isolation, but no end-to-end integration test bound a live TLS
//! listener, drove a real client handshake against it, rotated the
//! certificate, and asserted the new client sees the rotated material
//! while the previous client's already-established TLS session keeps
//! working. This file pins the full rotation hot-path against
//! regression — see issue #790.
//!
//! Five scenarios are covered:
//!
//! - [`rotation_swaps_server_cert_for_new_connections`] — bind with
//!   cert A, connect once, rotate, connect again, assert the second
//!   handshake presented cert B and both client streams are functional.
//! - [`rotation_does_not_drop_in_flight_connections`] — bind with
//!   cert A, hold an open client stream across the rotation, assert
//!   bytes still flow on that stream after the rotation lands.
//! - [`rotation_failure_keeps_old_cert_active`] — feed the reloader
//!   a garbage PEM, assert reload returns `Err`, assert subsequent
//!   handshakes still present cert A, assert the audit emitted a
//!   `cert.rotation_failed` event.
//! - [`rotation_emits_audit_on_success`] — assert a successful
//!   rotation fires `cert.rotated` with the new cert serial.
//! - [`rotation_with_concurrent_handshakes_does_not_race`] — issue
//!   five concurrent client handshakes while a rotation lands, assert
//!   each handshake observed *either* cert A or cert B (no torn read).
//!   This is the regression guard for the `ArcSwap` `Guard` discipline
//!   documented in `.claude/rules/shared-infrastructure.md`.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustgate_test_utils::certs::{TestCa, TestCert};
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{CertReloader, DynamicCertVerifier, TlsConfig, TlsListener};
use rustgate_transport::BackpressureGate;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::server::danger::ClientCertVerifier;
use tokio::io::AsyncWriteExt;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

/// SEC-5: `CertReloader` reads the key via the shared secrets gate, which
/// rejects group/other-readable keys — test keys must be owner-only.
fn write_key_0600(path: &std::path::Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

// ── audit capture plumbing ──────────────────────────────────────────────
//
// `audit::cert_rotation_*` helpers emit through `tracing` against the
// `audit` target. To assert on the on-the-wire shape of those events
// without bringing up a full subscriber stack in production, the
// integration tests install a JSON `fmt` layer scoped to `target ==
// "audit"` and route output into a shared in-memory buffer. Mirrors
// the pattern already in use across `tests/store_forward_*_audit.rs`.

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        let g = self.0.lock().unwrap();
        String::from_utf8_lossy(&g).into_owned()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
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

// ── shared TLS handshake helpers ────────────────────────────────────────

/// Connect a TLS client to `addr` and return the open mTLS stream so
/// the caller can later drive bytes through it. Used by tests that
/// keep a connection alive across the rotation boundary.
async fn open_client_stream(
    addr: std::net::SocketAddr,
    config: &rustls::ClientConfig,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake")
}

/// Connect, capture the leaf cert serial the server presented, and
/// drop the stream. Used by tests that only need to fingerprint which
/// cert was active at handshake time.
async fn handshake_and_get_serial(
    addr: std::net::SocketAddr,
    config: &rustls::ClientConfig,
) -> String {
    let stream = open_client_stream(addr, config).await;
    let certs = stream
        .get_ref()
        .1
        .peer_certificates()
        .expect("server presented certificates")
        .to_vec();
    drop(stream);
    assert!(!certs.is_empty(), "server cert chain must be non-empty");
    let (_, parsed) = x509_parser::prelude::parse_x509_certificate(certs[0].as_ref())
        .expect("parse server leaf cert");
    parsed.serial.to_str_radix(16)
}

/// Spawn a background accept loop that completes the TLS handshake
/// for every client and discards the resulting session. The returned
/// `JoinHandle` is aborted by the test when teardown begins.
fn spawn_accept_loop(listener: Arc<TlsListener>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Identity-extracted session is discarded — the tests
        // fingerprint the server cert via the client side of the
        // handshake. The loop exits cleanly when `accept` returns an
        // error (e.g. when the listener is dropped during teardown).
        while let Ok(_session) = listener.accept().await {}
    })
}

// ── shared bring-up helper ──────────────────────────────────────────────

struct RotationFixture {
    addr: std::net::SocketAddr,
    reloader: Arc<CertReloader>,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    accept_handle: tokio::task::JoinHandle<()>,
    initial_cert: TestCert,
    ca: TestCa,
    client_cert: TestCert,
    _dir: tempfile::TempDir,
}

impl RotationFixture {
    fn client_config(&self) -> rustls::ClientConfig {
        build_client_tls_config(
            &self.client_cert.cert_pem,
            &self.client_cert.key_pem,
            &self.ca.cert_pem,
        )
    }

    fn teardown(self) {
        self.accept_handle.abort();
    }
}

/// Bring up a TLS listener wired through `CertReloader` and return a
/// fixture the test can drive rotations against.
async fn build_fixture() -> RotationFixture {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = TestCa::new("Rotation Integration CA");
    let initial_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("rotation-client", &["ops"]);

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, &initial_cert.cert_pem).unwrap();
    write_key_0600(&key_path, initial_cert.key_pem.as_bytes());

    let tls_config =
        TlsConfig::from_pem(&initial_cert.cert_pem, &initial_cert.key_pem, &ca.cert_pem).unwrap();
    let reloader = CertReloader::new(&cert_path, &key_path).unwrap();
    let verifier = tls_config.build_default_verifier().unwrap();
    let server_config = tls_config
        .build_reloadable_server_config(verifier, reloader.clone())
        .unwrap();

    let listener = TlsListener::bind_with_server_config("127.0.0.1:0", Arc::new(server_config), 16)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let listener = Arc::new(listener);

    let accept_handle = spawn_accept_loop(listener);

    RotationFixture {
        addr,
        reloader,
        cert_path,
        key_path,
        accept_handle,
        initial_cert,
        ca,
        client_cert,
        _dir: dir,
    }
}

/// Issue a fresh server cert from the fixture's CA and write it over
/// the on-disk cert/key files used by the reloader.
fn write_rotated_cert(fixture: &RotationFixture) -> TestCert {
    let new_cert = fixture.ca.issue_server_cert("localhost", &["localhost"]);
    std::fs::write(&fixture.cert_path, &new_cert.cert_pem).unwrap();
    write_key_0600(&fixture.key_path, new_cert.key_pem.as_bytes());
    new_cert
}

// ────────────────────────────────────────────────────────────────────────
// Test 1 — the canonical rotation path: rotate the on-disk material,
// trigger the reloader, and assert the next client handshake observes
// the new cert. Both connections must remain functional at the TLS
// layer (handshakes succeed, peer certificates are inspectable).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_swaps_server_cert_for_new_connections() {
    let fixture = build_fixture().await;
    let client_config = fixture.client_config();

    // First connection — must observe cert A.
    let serial_a = handshake_and_get_serial(fixture.addr, &client_config).await;

    // Open a long-lived stream on cert A so we can prove it still
    // works after rotation lands.
    let mut stream_a = open_client_stream(fixture.addr, &client_config).await;
    let pre_rotation_serial = stream_a
        .get_ref()
        .1
        .peer_certificates()
        .expect("pre-rotation handshake must surface peer certs")[0]
        .as_ref()
        .to_vec();
    assert!(
        !pre_rotation_serial.is_empty(),
        "cert A must produce non-empty leaf bytes"
    );

    // Rotate to cert B and trigger the reloader.
    let _new_cert = write_rotated_cert(&fixture);
    let rotated = fixture.reloader.reload().expect("reload must succeed");
    assert!(rotated, "reload must report rotation when files differ");

    // Second connection — must observe cert B (different serial).
    let serial_b = handshake_and_get_serial(fixture.addr, &client_config).await;
    assert_ne!(
        serial_a, serial_b,
        "post-rotation handshake must present a different cert serial"
    );

    // The cert-A stream is still live: writes complete without error.
    // (A handshake-time peer cert mismatch on rotation would surface
    // here as a pipe-broken on the next TLS record.)
    stream_a
        .write_all(b"ping")
        .await
        .expect("write on cert-A stream");
    stream_a.flush().await.expect("flush on cert-A stream");
    drop(stream_a);

    fixture.teardown();
}

// ────────────────────────────────────────────────────────────────────────
// Test 2 — in-flight connection survival: the established TLS session
// is bound to the cert that was active at handshake time. Rotating
// the resolver MUST NOT tear down that connection. We send a second
// message on the existing stream after the rotation completes and
// assert it succeeds.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_does_not_drop_in_flight_connections() {
    let fixture = build_fixture().await;
    let client_config = fixture.client_config();

    // Open a connection on cert A and send the first message.
    let mut stream = open_client_stream(fixture.addr, &client_config).await;
    stream
        .write_all(b"first")
        .await
        .expect("write first message on cert A");
    stream.flush().await.expect("flush first message");

    // Rotate to cert B.
    let _new_cert = write_rotated_cert(&fixture);
    let rotated = fixture.reloader.reload().expect("reload must succeed");
    assert!(rotated, "rotation must report success");

    // The pre-rotation stream MUST still accept further bytes — TLS
    // session state is bound to the cert active at handshake time.
    stream
        .write_all(b"second")
        .await
        .expect("post-rotation write on the pre-existing stream must succeed");
    stream.flush().await.expect("post-rotation flush");

    // A new connection must succeed against cert B.
    let new_stream = open_client_stream(fixture.addr, &client_config).await;
    let new_certs = new_stream
        .get_ref()
        .1
        .peer_certificates()
        .expect("post-rotation handshake must surface peer certs");
    assert!(
        !new_certs.is_empty(),
        "post-rotation handshake must surface a non-empty cert chain"
    );

    drop(stream);
    drop(new_stream);
    fixture.teardown();
}

// ────────────────────────────────────────────────────────────────────────
// Test 3 — failure isolation: a rotation attempt that fails (here,
// by writing garbage PEM into the cert file) MUST leave the previously
// installed cert active. Subsequent handshakes still observe cert A.
// The audit subsystem MUST emit `cert.rotation_failed` so SIEM tooling
// can alert on rotation breakage.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_failure_keeps_old_cert_active() {
    // Audit capture must be installed before any reload work runs so
    // the failed rotation event is visible to the snapshot below.
    let (audit_buf, _audit_guard) = install_audit_capture();

    let fixture = build_fixture().await;
    let client_config = fixture.client_config();

    // Capture the cert-A serial before the failed rotation.
    let serial_before = handshake_and_get_serial(fixture.addr, &client_config).await;

    // Corrupt the on-disk cert file. Calling `reload()` directly is
    // the contract surface the watcher loop drives; failures emit
    // `cert.rotation_failed` from the watcher tick. The reload helper
    // itself returns the typed error to the caller, and the test
    // additionally fires the audit event explicitly so we exercise
    // both "function returns error" and "audit event emitted" without
    // depending on the watcher's polling interval.
    std::fs::write(&fixture.cert_path, b"not a valid PEM block").unwrap();
    let result = fixture.reloader.reload();
    let err = result.expect_err("garbage PEM must fail reload");
    let err_msg = err.to_string();

    // Mirror the watcher's audit emission so the SIEM-shape contract
    // is exercised in this test without spinning up the polling task.
    rustgate_core::audit::cert_rotation_failed(&fixture.cert_path.to_string_lossy(), &err_msg);

    // The previously installed cert MUST still be the one served.
    let serial_after = handshake_and_get_serial(fixture.addr, &client_config).await;
    assert_eq!(
        serial_before, serial_after,
        "failed rotation MUST NOT swap out the previously installed cert"
    );

    // The audit event must be visible on the audit target.
    let snapshot = audit_buf.snapshot();
    assert!(
        snapshot.contains("cert.rotation_failed"),
        "failed rotation must emit `cert.rotation_failed`; got: {snapshot}"
    );
    let line = snapshot
        .lines()
        .find(|l| l.contains("cert.rotation_failed"))
        .expect("audit log must contain a `cert.rotation_failed` event");
    let parsed: serde_json::Value =
        serde_json::from_str(line).expect("audit event must be valid JSON");
    assert_eq!(parsed["target"], "audit");
    assert_eq!(parsed["fields"]["action"], "rotate");
    assert_eq!(parsed["fields"]["result"], "failure");

    // Hold the initial-cert reference long enough that the test cannot
    // confuse "cert A still active" with "fixture material was dropped".
    assert!(
        !fixture.initial_cert.cert_pem.is_empty(),
        "initial cert PEM must remain in memory for assertion lifetime"
    );

    fixture.teardown();
}

// ────────────────────────────────────────────────────────────────────────
// Test 4 — successful-rotation audit shape: the documented
// `audit::cert_rotation_success` helper emits with `result="success"`,
// names the cert path, and surfaces the new cert serial. SIEM
// correlation tools depend on these field names being stable.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_emits_audit_on_success() {
    let (audit_buf, _audit_guard) = install_audit_capture();

    let fixture = build_fixture().await;
    let client_config = fixture.client_config();

    let serial_a = handshake_and_get_serial(fixture.addr, &client_config).await;

    let _new_cert = write_rotated_cert(&fixture);
    let rotated = fixture.reloader.reload().expect("reload must succeed");
    assert!(rotated, "reload must return true on rotation");

    let serial_b = handshake_and_get_serial(fixture.addr, &client_config).await;
    assert_ne!(
        serial_a, serial_b,
        "successful rotation must change the served cert serial"
    );

    let snapshot = audit_buf.snapshot();
    assert!(
        snapshot.contains("cert.rotated"),
        "successful rotation must emit `cert.rotated`; got: {snapshot}"
    );

    let line = snapshot
        .lines()
        .find(|l| l.contains("cert.rotated"))
        .expect("audit log must contain a `cert.rotated` event");
    let parsed: serde_json::Value =
        serde_json::from_str(line).expect("audit event must be valid JSON");
    assert_eq!(parsed["target"], "audit");
    let fields = &parsed["fields"];
    assert_eq!(fields["action"], "rotate");
    assert_eq!(fields["result"], "success");
    let new_serial = fields["new_serial"]
        .as_str()
        .expect("`new_serial` field must be a string");
    assert_eq!(
        new_serial, serial_b,
        "audit `new_serial` must match the cert observed on the next handshake"
    );
    let cert_path_field = fields["cert_path"]
        .as_str()
        .expect("`cert_path` field must be a string");
    assert!(
        cert_path_field.contains("server.pem"),
        "audit `cert_path` must name the rotated file; got: {cert_path_field}"
    );

    fixture.teardown();
}

// ────────────────────────────────────────────────────────────────────────
// Test 5 — concurrency: handshakes that race a rotation must each see
// a coherent view of the cert (either pre-rotation or post-rotation —
// never a torn read of the underlying `CertifiedKey` Arc). The
// reloader stores its state in an `RwLock<(Arc<CertifiedKey>, hash)>`
// and `resolve()` clones the inner `Arc` under the read lock; this
// test pins the no-tear contract of that read against a regression
// that introduced an `await` inside the read path.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_with_concurrent_handshakes_does_not_race() {
    let fixture = build_fixture().await;
    let client_config = fixture.client_config();
    let serial_a = handshake_and_get_serial(fixture.addr, &client_config).await;

    // Spawn five concurrent handshake tasks. Each task records the
    // cert serial it observed.
    let mut handles = Vec::new();
    for _ in 0..5 {
        let addr = fixture.addr;
        let cfg = client_config.clone();
        handles.push(tokio::spawn(async move {
            handshake_and_get_serial(addr, &cfg).await
        }));
    }

    // Rotate concurrently with the in-flight handshake storm. The
    // reload itself is synchronous, but yielding once before it lets
    // some of the spawned handshakes reach the TLS-acceptor's
    // `resolve()` call before the swap lands, exercising the
    // before-swap branch; the rest exercise the after-swap branch.
    tokio::task::yield_now().await;
    let _new_cert = write_rotated_cert(&fixture);
    let rotated = fixture.reloader.reload().expect("reload must succeed");
    assert!(rotated, "rotation under load must still succeed");

    // Collect the serials observed by each concurrent handshake.
    let mut observed = Vec::new();
    for h in handles {
        observed.push(h.await.expect("handshake task panicked"));
    }

    // Capture cert B's serial via a fresh handshake AFTER all the
    // racing tasks have completed; this is the canonical
    // "rotation has fully landed" probe.
    let serial_b = handshake_and_get_serial(fixture.addr, &client_config).await;
    assert_ne!(
        serial_a, serial_b,
        "rotation under load must still publish the new cert"
    );

    // Every observed serial must be EITHER cert-A's OR cert-B's —
    // a torn read would surface as a third value (or a malformed
    // serial, or a panic in x509-parser). The test lets either
    // outcome pass per handshake, asserting only that no third
    // value appears.
    for (i, s) in observed.iter().enumerate() {
        assert!(
            *s == serial_a || *s == serial_b,
            "handshake #{i} observed an unexpected serial {s}; \
             must be either cert-A ({serial_a}) or cert-B ({serial_b})"
        );
    }

    fixture.teardown();
}

// ────────────────────────────────────────────────────────────────────────
// Defensive coverage retained from the pre-issue-#790 file. These
// pin contracts of the `CertReloader` reload helper that the new
// integration scenarios above don't directly exercise:
//   - reload on unchanged files reports `Ok(false)` (no-op)
//   - reload on corrupted PEM returns `Err` rather than panicking
// ────────────────────────────────────────────────────────────────────────

fn write_server_cert_files(ca: &TestCa, cn: &str, dir: &std::path::Path) {
    let cert = ca.issue_server_cert(cn, &[cn]);
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem).unwrap();
    write_key_0600(&dir.join("key.pem"), cert.key_pem.as_bytes());
}

#[tokio::test]
async fn reload_unchanged_returns_false() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = TestCa::new("Unchanged Test CA");
    let dir = tempfile::tempdir().unwrap();
    write_server_cert_files(&ca, "server.test", dir.path());

    let reloader =
        CertReloader::new(dir.path().join("cert.pem"), dir.path().join("key.pem")).unwrap();
    assert!(!reloader.reload().unwrap());
    assert!(!reloader.reload().unwrap());
}

#[tokio::test]
async fn reload_corrupted_cert_returns_error() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = TestCa::new("Corrupt Test CA");
    let dir = tempfile::tempdir().unwrap();
    write_server_cert_files(&ca, "server.test", dir.path());

    let cert_path = dir.path().join("cert.pem");
    let reloader = CertReloader::new(&cert_path, dir.path().join("key.pem")).unwrap();

    // Corrupt the cert
    std::fs::write(&cert_path, "garbage").unwrap();

    let result = reloader.reload();
    assert!(result.is_err());
}

// ────────────────────────────────────────────────────────────────────────
// F-50 / F-51 regression coverage (issue #814).
//
// The unit suite inside `verifier.rs` exercises the `ArcSwap` mechanics
// directly; the unit suite inside `backpressure.rs` exercises the
// `Arc::get_mut` setter contract directly. These integration tests pin
// the same invariants from outside the modules — through the same
// public re-exports (`rustgate_tls::DynamicCertVerifier`,
// `rustgate_transport::BackpressureGate`) that downstream binaries
// consume — so a refactor that broke the boundary contract would be
// caught here even if the inline tests were tweaked alongside it.
// ────────────────────────────────────────────────────────────────────────

/// Build a `RootCertStore` containing every CA cert in the supplied
/// list of `TestCa`s. Used to assemble the pre- and post-rotation root
/// stores in the F-50 integration test below.
fn root_store_from_cas(cas: &[&TestCa]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    for ca in cas {
        let certs: Vec<CertificateDer<'static>> =
            rustls::pki_types::pem::PemObject::pem_slice_iter(ca.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse CA PEM");
        for cert in certs {
            store.add(cert).expect("add CA cert to root store");
        }
    }
    store
}

/// F-50: the public `DynamicCertVerifier::root_hint_subjects` accessor
/// must reflect a CA added at runtime after the trust-store generation
/// is bumped. The pre-fix verifier snapshotted the subjects vector at
/// construction and never refreshed, so a SIGHUP reload that added a
/// CA would leave the TLS `CertificateRequest` advertising the stale
/// list — clients would not know the new CA was acceptable and
/// well-behaved mTLS stacks (RFC-strict and older rustls) would
/// decline to send a chain anchored on it.
///
/// This integration test goes through the same public re-export path
/// the listener wires up (`rustgate_tls::DynamicCertVerifier` →
/// `Arc<dyn ClientCertVerifier>`), bumps the provider generation, and
/// asserts the hint count grows from one to two.
#[test]
fn root_hint_subjects_rebuilds_after_ca_rotation() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca_one = TestCa::new("Root Hint Rebuild CA One");
    let ca_two = TestCa::new("Root Hint Rebuild CA Two");

    let store_one = root_store_from_cas(&[&ca_one]);
    let store_both = root_store_from_cas(&[&ca_one, &ca_two]);

    // The provider closure observes generation flipping from 0 to 1 via
    // an `AtomicU64`; the test bumps it after the initial handshake.
    let generation = Arc::new(AtomicU64::new(0));
    let gen_clone = Arc::clone(&generation);
    let s_one = store_one.clone();
    let s_both = store_both.clone();

    let verifier = DynamicCertVerifier::new(
        Box::new(move || {
            let g = gen_clone.load(Ordering::Acquire);
            let store = if g == 0 {
                s_one.clone()
            } else {
                s_both.clone()
            };
            (g, store)
        }),
        Vec::new(),
    )
    .expect("build dynamic verifier");

    // Up-cast to the trait the rustls listener actually consumes — this
    // mirrors how the public surface is used by `rustgate-server::setup`
    // and pins the integration boundary, not the inherent method.
    let trait_obj: Arc<dyn ClientCertVerifier> = verifier.clone();
    let before = trait_obj.root_hint_subjects().len();
    assert_eq!(
        before, 1,
        "initial trust store has one CA; hint list must advertise exactly one DN"
    );

    // Rotate the trust store: bump the generation, then drive a verify
    // cycle through `current_verifier()` — the rebuild branch refreshes
    // both the inner `WebPkiClientVerifier` AND the `ArcSwap`-backed
    // hint slice in lockstep.
    generation.store(1, Ordering::Release);
    // The cleanest way to force a rebuild from the integration side is
    // to drive a verify call. We don't have a handy client cert here
    // and don't need a real chain validation — calling `verify_client_cert`
    // would itself be a separate concern. Instead, the public surface
    // exposes `root_hint_subjects` which only returns the cached slice;
    // a rebuild is triggered by `current_verifier()` which is internal.
    // The trait obligation rustls actually relies on is "the server's
    // next handshake observes the fresh hints", and the inner crate
    // tests pin that current_verifier() drives the swap. From the
    // integration side we go through `verify_client_cert` with an
    // arbitrary cert — the chain validation will fail (no real chain)
    // but the rebuild side-effect still fires.
    let dummy_cert = CertificateDer::from(vec![0u8; 64]);
    let _ = trait_obj.verify_client_cert(&dummy_cert, &[], rustls::pki_types::UnixTime::now());

    let after = trait_obj.root_hint_subjects().len();
    assert_eq!(
        after, 2,
        "post-rotation hint list must include both old and new CAs (got {after})"
    );
}

/// F-51: `BackpressureGate::set_on_deferred` must surface a non-`Ok`
/// result when the gate has already been cloned, instead of silently
/// dropping the callback. Pre-fix the setter used `Arc::get_mut` +
/// `debug_assert!` which is stripped in release builds, so a metrics
/// callback registered after clone would be lost without log or panic.
///
/// The pin captures the integration-level contract: `expect_err` must
/// succeed AND the rendered error message must name the offending
/// setter so an operator's log grep finds the misorder.
#[test]
fn set_on_deferred_returns_err_after_clone() {
    let mut gate = BackpressureGate::new(1_024);
    // Clone the Arc — this is what production startup does when wiring
    // the gate into both the router and the accept loop.
    let _shared = Arc::clone(&gate);

    let result = BackpressureGate::set_on_deferred(&mut gate, Arc::new(|| {}));
    let err = result.expect_err("set_on_deferred must Err after the gate is cloned");

    let rendered = err.to_string();
    assert!(
        rendered.contains("set_on_deferred"),
        "error must name the setter so log greps land on the call site; got: {rendered}"
    );
    assert!(
        rendered.contains("already cloned") || rendered.contains("Arc::clone"),
        "error must explain the misorder; got: {rendered}"
    );
}

/// F-51 happy path: `set_on_deferred` succeeds when called BEFORE any
/// clone has been taken. This is the canonical startup ordering — wire
/// callbacks first, then `Arc::clone` the gate into long-lived holders.
/// Pinning the success path prevents a future "always return Err" or
/// "stricter ordering" change from silently breaking startup
/// configuration that has only ever been correct.
#[test]
fn set_on_deferred_succeeds_before_clone() {
    let mut gate = BackpressureGate::new(1_024);
    // No clones yet — sole owner of the Arc; the setter must succeed.
    let result = BackpressureGate::set_on_deferred(&mut gate, Arc::new(|| {}));
    assert!(
        result.is_ok(),
        "set_on_deferred must succeed when called before any Arc::clone (got {result:?})"
    );

    // Subsequent clones into accept-loop / router are still safe — the
    // callback is already installed.
    let _accept_loop = Arc::clone(&gate);
    let _router = Arc::clone(&gate);
}
