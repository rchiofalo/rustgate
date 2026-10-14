// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! SPIFFE Workload API identity source.
//!
//! This module wires the [`spiffe`] crate's `WorkloadApiClient` into
//! rustgate's existing [`CertReloader`] so that the server can obtain its
//! X.509-SVID and trust bundle from a SPIRE agent rather than from static
//! files on disk. Refreshes flow through the same atomic `CertifiedKey`
//! swap that file-based rotation uses, so in-flight TLS handshakes continue
//! to resolve the previous certificate until the swap completes.
//!
//! This is the first half of the SPIFFE integration (issue #570): loading
//! the server identity from a workload API. Accepting SPIFFE IDs from
//! *connecting* clients (extracting the URI SAN post-handshake and using it
//! as the client identity in place of the X.509 CN) is tracked as a
//! follow-up and continues to use the existing CN-based identity path.

use std::sync::{Arc, Weak};
use std::time::Duration;

use rustgate_core::error::{ConfigError, Result, RustgateError};
use rustgate_core::tasks::spawn_background;
use spiffe::cert::Certificate;
use spiffe::svid::x509::X509Svid;
use spiffe::workload_api::client::WorkloadApiClient;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::cert_reloader::CertReloader;

/// Initial material fetched from the Workload API at startup.
///
/// The caller uses [`cert_reloader`](Self::cert_reloader) as the rustls
/// cert resolver and [`trust_bundle_pem`](Self::trust_bundle_pem) as the
/// CA bundle for verifying connecting clients.
#[derive(Debug)]
pub struct SpiffeIdentity {
    /// Cert reloader seeded with the initial X.509-SVID. Subsequent
    /// refreshes by the background task call
    /// [`CertReloader::update_from_der`] to atomically swap the active key.
    pub cert_reloader: Arc<CertReloader>,
    /// Concatenated trust bundle(s) in PEM form. Used once at startup to
    /// build the client-cert verifier; dynamic trust bundle rotation is
    /// deferred (clients reconnect within SVID TTL to pick up new roots).
    pub trust_bundle_pem: String,
    /// Leaf + intermediate certificates in PEM form. Used by the rest of
    /// the server (federation, enrollment, metrics) which still expect
    /// PEM-encoded material.
    pub cert_pem: String,
    /// PKCS#8 private key in PEM form. Wrapped in [`Zeroizing`] so the
    /// private key is wiped from memory on drop.
    pub key_pem: Zeroizing<String>,
    /// SPIFFE ID of the fetched SVID, e.g. `spiffe://example.org/rustgate`.
    pub spiffe_id: String,
    /// Trust domain of the fetched SVID, e.g. `example.org`.
    pub trust_domain: String,
}

/// Configuration for the SPIFFE identity source.
#[derive(Debug, Clone)]
pub struct SpiffeConfig {
    /// Path to the SPIRE agent Workload API Unix socket.
    /// Example: `unix:///tmp/spire-agent/public/api.sock`.
    pub workload_api_socket: String,
    /// Optional trust domain to enforce. When set, the fetched SVID must
    /// belong to this trust domain or startup fails.
    pub expected_trust_domain: Option<String>,
    /// Polling interval for SVID refresh when the streaming API is not
    /// available. Set to zero to disable polling (used only for tests).
    pub refresh_interval: Duration,
}

impl Default for SpiffeConfig {
    fn default() -> Self {
        Self {
            workload_api_socket: "unix:///tmp/spire-agent/public/api.sock".to_string(),
            expected_trust_domain: None,
            refresh_interval: Duration::from_secs(300),
        }
    }
}

/// Fetch the initial X.509-SVID from the Workload API, seed a
/// [`CertReloader`] with it, and return both the reloader and the trust
/// bundle PEM so the caller can construct the TLS server config.
///
/// This function is async because the underlying SPIFFE client uses a
/// gRPC transport over the Workload API Unix socket.
pub async fn fetch_initial_identity(cfg: &SpiffeConfig) -> Result<SpiffeIdentity> {
    let client = WorkloadApiClient::connect_to(&cfg.workload_api_socket)
        .await
        .map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to connect to SPIFFE Workload API at {}: {e}",
                cfg.workload_api_socket
            )))
        })?;

    let ctx = client.fetch_x509_context().await.map_err(|e| {
        RustgateError::from(ConfigError::Other(format!(
            "failed to fetch X.509 context from SPIFFE Workload API: {e}"
        )))
    })?;

    let svid = ctx.default_svid().ok_or_else(|| {
        RustgateError::from(ConfigError::Other(
            "SPIFFE Workload API returned no default X.509-SVID".to_string(),
        ))
    })?;

    let spiffe_id = svid.spiffe_id().to_string();
    let trust_domain = svid.spiffe_id().trust_domain().to_string();

    if let Some(expected) = &cfg.expected_trust_domain
        && expected != &trust_domain
    {
        return Err(ConfigError::Other(format!(
            "SPIFFE trust domain mismatch: expected {expected}, got {trust_domain}"
        ))
        .into());
    }

    let (cert_chain_der, private_key_der) = svid_to_der(svid.as_ref());

    let reloader = CertReloader::from_der(&cert_chain_der, &private_key_der)?;

    // Build a PEM bundle from all authorities in all trust bundles. PEM
    // form is used so the bundle plugs into the existing `TlsConfig` path
    // unchanged.
    let mut trust_bundle_pem = String::new();
    for (_td, bundle) in ctx.bundle_set().iter() {
        for authority in bundle.authorities() {
            append_cert_pem(&mut trust_bundle_pem, authority);
        }
    }

    // Build PEM encodings of the cert chain and private key for consumers
    // (federation, enrollment, TlsConfig::from_pem) that still expect PEM.
    let mut cert_pem = String::new();
    for der in &cert_chain_der {
        append_der_as_pem(&mut cert_pem, "CERTIFICATE", der);
    }
    let mut key_pem_raw = String::new();
    append_der_as_pem(&mut key_pem_raw, "PRIVATE KEY", &private_key_der);
    let key_pem = Zeroizing::new(key_pem_raw);

    if trust_bundle_pem.is_empty() {
        return Err(ConfigError::Other(
            "SPIFFE Workload API returned an empty trust bundle".to_string(),
        )
        .into());
    }

    info!(
        spiffe_id = %spiffe_id,
        trust_domain = %trust_domain,
        "loaded initial SPIFFE X.509-SVID from Workload API"
    );

    let expiry = svid_expiry_unix(&cert_chain_der);
    rustgate_core::audit::spiffe_svid_refresh_success(&spiffe_id, &trust_domain, expiry);

    Ok(SpiffeIdentity {
        cert_reloader: reloader,
        trust_bundle_pem,
        cert_pem,
        key_pem,
        spiffe_id,
        trust_domain,
    })
}

/// Spawn a background task that periodically re-fetches the X.509-SVID
/// from the Workload API and hands it to [`CertReloader::update_from_der`]
/// for atomic rotation. On success, the task emits an audit event and
/// (when the `metrics` feature is enabled) updates the SPIFFE refresh
/// metrics. On failure the task logs and retries on the next tick.
///
/// The task is best-effort: a single failed poll does not take down the
/// server. The currently loaded SVID continues to serve traffic until it
/// expires, at which point clients will see handshake failures — that's
/// the same behavior as file-based rotation when the file is deleted.
pub fn spawn_refresh_task(
    reloader: Weak<CertReloader>,
    cfg: SpiffeConfig,
    hooks: Option<SpiffeHooks>,
) {
    if cfg.refresh_interval.is_zero() {
        return;
    }
    spawn_background("spiffe-svid-refresh", async move {
        let mut tick = tokio::time::interval(cfg.refresh_interval);
        let _ = tick.tick().await; // skip the immediate tick
        loop {
            let _ = tick.tick().await;
            // Exit cleanly when the owning `TlsListenerHandle` drops its
            // `Arc<CertReloader>` during shutdown — no further Workload API
            // calls are made after the reloader is gone.
            let Some(reloader) = reloader.upgrade() else {
                tracing::debug!("SPIFFE refresh task exiting: reloader dropped");
                return;
            };
            match refresh_once(&reloader, &cfg).await {
                Ok(Some((spiffe_id, trust_domain, expiry))) => {
                    info!(
                        spiffe_id = %spiffe_id,
                        trust_domain = %trust_domain,
                        "SPIFFE X.509-SVID rotated"
                    );
                    rustgate_core::audit::spiffe_svid_refresh_success(
                        &spiffe_id,
                        &trust_domain,
                        expiry,
                    );
                    if let Some(h) = hooks.as_ref() {
                        (h.on_success)(expiry);
                    }
                }
                Ok(None) => {
                    // unchanged
                }
                Err(e) => {
                    warn!(error = %e, "SPIFFE SVID refresh failed");
                    rustgate_core::audit::spiffe_svid_refresh_failure(&e.to_string());
                    if let Some(h) = hooks.as_ref() {
                        (h.on_failure)();
                    }
                }
            }
        }
    });
}

/// Fetch once and update the reloader. Returns the new SPIFFE ID, trust
/// domain, and expiry on rotation; `None` if the material is unchanged.
async fn refresh_once(
    reloader: &CertReloader,
    cfg: &SpiffeConfig,
) -> Result<Option<(String, String, i64)>> {
    let client = WorkloadApiClient::connect_to(&cfg.workload_api_socket)
        .await
        .map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "workload api connect failed: {e}"
            )))
        })?;
    let svid = client.fetch_x509_svid().await.map_err(|e| {
        RustgateError::from(ConfigError::Other(format!(
            "workload api fetch failed: {e}"
        )))
    })?;

    let (cert_chain_der, private_key_der) = svid_to_der(&svid);

    let changed = reloader.update_from_der(&cert_chain_der, &private_key_der)?;
    if !changed {
        return Ok(None);
    }
    let spiffe_id = svid.spiffe_id().to_string();
    let trust_domain = svid.spiffe_id().trust_domain().to_string();
    let expiry = svid_expiry_unix(&cert_chain_der);
    Ok(Some((spiffe_id, trust_domain, expiry)))
}

/// Convert an [`X509Svid`] into the DER-encoded cert chain + PKCS#8 private
/// key bytes expected by [`CertReloader::update_from_der`].
///
/// The private key is wrapped in [`Zeroizing`] so it is wiped from memory
/// once the caller is done with it.
fn svid_to_der(svid: &X509Svid) -> (Vec<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let chain: Vec<Vec<u8>> = svid
        .cert_chain()
        .iter()
        .map(|c: &Certificate| c.as_bytes().to_vec())
        .collect();
    let key = Zeroizing::new(svid.private_key().as_bytes().to_vec());
    (chain, key)
}

/// Append a single DER-encoded certificate to a PEM string buffer.
fn append_cert_pem(out: &mut String, cert: &Certificate) {
    append_der_as_pem(out, "CERTIFICATE", cert.as_bytes());
}

/// Append an arbitrary DER blob as PEM with the given label.
///
/// Base64 output is pure ASCII, so we wrap at 64 columns using direct
/// string slicing (char boundaries == byte boundaries for ASCII) instead
/// of a `from_utf8` round-trip with a silent fallback.
fn append_der_as_pem(out: &mut String, label: &str, der: &[u8]) {
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let encoded = rustgate_core::b64::encode(der);
    let mut idx = 0;
    while idx < encoded.len() {
        let end = (idx + 64).min(encoded.len());
        out.push_str(&encoded[idx..end]);
        out.push('\n');
        idx = end;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
}

/// Extract the notAfter field of the leaf cert as a unix timestamp.
/// Returns 0 if parsing fails — the caller only uses this for audit/metrics.
fn svid_expiry_unix(cert_chain_der: &[Vec<u8>]) -> i64 {
    let leaf = match cert_chain_der.first() {
        Some(c) => c,
        None => return 0,
    };
    match x509_parser::prelude::parse_x509_certificate(leaf) {
        Ok((_, parsed)) => parsed.validity().not_after.timestamp(),
        Err(_) => 0,
    }
}

/// Hooks for observing SPIFFE refresh outcomes from the background task.
/// The server crate wires these up to Prometheus counters/gauges when the
/// `metrics` feature is on; with metrics off, the hooks are simply `None`
/// and the refresh task still updates the reloader and emits audit events.
#[derive(Clone)]
pub struct SpiffeHooks {
    /// Called on a successful refresh with the new leaf expiry (unix seconds).
    pub on_success: Arc<dyn Fn(i64) + Send + Sync>,
    /// Called on a failed refresh.
    pub on_failure: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for SpiffeHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeHooks").finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn default_config_has_standard_socket() {
        let cfg = SpiffeConfig::default();
        assert!(cfg.workload_api_socket.starts_with("unix://"));
        assert!(cfg.expected_trust_domain.is_none());
    }

    #[test]
    fn svid_expiry_returns_zero_for_empty_chain() {
        assert_eq!(svid_expiry_unix(&[]), 0);
    }

    #[test]
    fn svid_expiry_returns_zero_for_garbage() {
        assert_eq!(svid_expiry_unix(&[vec![0, 1, 2, 3]]), 0);
    }

    #[test]
    fn cert_reloader_update_from_der_roundtrip() {
        // This exercises the CertReloader in-memory path that the SPIFFE
        // refresh task drives. We build certs via TestCa (DER form) and
        // confirm that update_from_der swaps the active CertifiedKey.
        use rustgate_test_utils::certs::TestCa;
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca = TestCa::new("SPIFFE Test CA");
        let cert_a = ca.issue_server_cert("svid-a.spiffe.test", &["svid-a.spiffe.test"]);
        let cert_b = ca.issue_server_cert("svid-b.spiffe.test", &["svid-b.spiffe.test"]);

        let chain_a = pem_to_der_chain(&cert_a.cert_pem);
        let key_a = pem_private_key_to_der(&cert_a.key_pem);
        let reloader = CertReloader::from_der(&chain_a, &key_a).expect("from_der");

        // Same material → no change.
        assert!(!reloader.update_from_der(&chain_a, &key_a).unwrap());

        // Different cert → rotated.
        let chain_b = pem_to_der_chain(&cert_b.cert_pem);
        let key_b = pem_private_key_to_der(&cert_b.key_pem);
        assert!(reloader.update_from_der(&chain_b, &key_b).unwrap());
    }

    fn pem_to_der_chain(pem: &str) -> Vec<Vec<u8>> {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .filter_map(|r| r.ok())
            .map(|c| c.as_ref().to_vec())
            .collect()
    }

    fn pem_private_key_to_der(pem: &str) -> Vec<u8> {
        use rustls_pki_types::PrivateKeyDer;
        use rustls_pki_types::pem::PemObject;
        let key = PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("parse key");
        key.secret_der().to_vec()
    }

    #[test]
    fn default_config_refresh_interval_is_exactly_five_minutes() {
        // The module doc-comment commits to a 300-second polling interval
        // as the default fallback when the streaming Workload API is not
        // available. Pin this explicitly so a future `Duration::from_secs(N)`
        // edit in `impl Default` cannot silently reshape every SPIFFE
        // deployment's SVID-refresh cadence — a too-short interval floods
        // the SPIRE agent; a too-long interval lets SVIDs expire before the
        // next refresh lands.
        let cfg = SpiffeConfig::default();
        assert_eq!(cfg.refresh_interval, Duration::from_secs(300));
    }

    #[test]
    fn spiffe_config_supports_clone_and_debug_derives() {
        // `SpiffeConfig` is passed through startup code and captured into
        // the refresh task's async closure, so `Clone` is load-bearing —
        // narrowing to `&'static SpiffeConfig` would force a ripple through
        // `spawn_refresh_task` and the server bin. `Debug` is the operator
        // UX contract for `tracing::debug!(config = ?cfg, …)` one-liners
        // on startup; both derives are pinned here so a silent removal of
        // either one breaks this test instead of callers.
        let cfg = SpiffeConfig {
            workload_api_socket: "unix:///run/spire/api.sock".into(),
            expected_trust_domain: Some("example.org".into()),
            refresh_interval: Duration::from_secs(60),
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.workload_api_socket, cfg.workload_api_socket);
        assert_eq!(cloned.expected_trust_domain, cfg.expected_trust_domain);
        assert_eq!(cloned.refresh_interval, cfg.refresh_interval);
        let rendered = format!("{cfg:?}");
        assert!(
            rendered.contains("SpiffeConfig"),
            "Debug output missing struct name: {rendered}",
        );
        assert!(
            rendered.contains("example.org"),
            "Debug output missing trust_domain field: {rendered}",
        );
    }

    #[test]
    fn spiffe_hooks_debug_elides_both_callback_fields() {
        // `SpiffeHooks` has a MANUAL `Debug` impl that uses
        // `debug_struct("SpiffeHooks").finish()` — no fields are emitted,
        // on purpose, because the `Arc<dyn Fn(...)>` callbacks render as
        // raw pointers that leak binary layout to any logger. A future
        // `#[derive(Debug)]` would silently put the callback pointers into
        // every `tracing::debug!(hooks = ?h, …)` line; this test pins the
        // contract by asserting the rendered shape and the absence of
        // field labels `on_success` / `on_failure`.
        let hooks = SpiffeHooks {
            on_success: Arc::new(|_| {}),
            on_failure: Arc::new(|| {}),
        };
        let rendered = format!("{hooks:?}");
        assert!(
            rendered.contains("SpiffeHooks"),
            "Debug output missing struct name: {rendered}",
        );
        assert!(
            !rendered.contains("on_success"),
            "Debug output leaked on_success field: {rendered}",
        );
        assert!(
            !rendered.contains("on_failure"),
            "Debug output leaked on_failure field: {rendered}",
        );
    }

    #[test]
    fn spiffe_hooks_is_clone_preserving_arc_callback_references() {
        // `SpiffeHooks` derives `Clone` so the server binary can pass one
        // hook set into `spawn_refresh_task` while also keeping a handle
        // locally for further refresh-task wiring. Each `Arc<dyn Fn(...)>`
        // clone bumps the strong count, not the body — we verify the
        // cloned handle invokes the SAME closure by counting calls through
        // a shared `AtomicUsize`. Without this test, a refactor that
        // accidentally cloned deeply (e.g. `Arc::new(**orig)`) or shallowly
        // swapped one callback for a no-op could ship silently.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let success_count = Arc::new(AtomicUsize::new(0));
        let failure_count = Arc::new(AtomicUsize::new(0));
        let sc = Arc::clone(&success_count);
        let fc = Arc::clone(&failure_count);
        let hooks = SpiffeHooks {
            on_success: Arc::new(move |_expiry| {
                let _ = sc.fetch_add(1, Ordering::Relaxed);
            }),
            on_failure: Arc::new(move || {
                let _ = fc.fetch_add(1, Ordering::Relaxed);
            }),
        };
        let cloned = hooks.clone();

        (hooks.on_success)(42);
        (cloned.on_success)(43);
        (cloned.on_failure)();

        assert_eq!(success_count.load(Ordering::Relaxed), 2);
        assert_eq!(failure_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn append_der_as_pem_emits_canonical_begin_end_markers_with_label() {
        // RFC 7468 requires `-----BEGIN <label>-----` and
        // `-----END <label>-----` as the envelope markers. A future refactor
        // that dropped the dashes, the label, or the trailing newline
        // would break every strict downstream parser (OpenSSL, rustls
        // pki-types). The label parameter is load-bearing — the same helper
        // is used for both CERTIFICATE and PRIVATE KEY labels.
        let mut out = String::new();
        append_der_as_pem(&mut out, "CERTIFICATE", &[0x30, 0x82, 0x01, 0x23]);
        assert!(
            out.starts_with("-----BEGIN CERTIFICATE-----\n"),
            "missing BEGIN marker: {out:?}",
        );
        assert!(
            out.ends_with("-----END CERTIFICATE-----\n"),
            "missing END marker: {out:?}",
        );

        let mut out2 = String::new();
        append_der_as_pem(&mut out2, "PRIVATE KEY", &[0x30, 0x82, 0x01, 0x23]);
        assert!(out2.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(out2.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn append_der_as_pem_wraps_base64_body_at_64_columns_per_line() {
        // RFC 7468 mandates that PEM base64 bodies wrap at 64 characters
        // per line — strict parsers reject payloads that exceed that width.
        // The encoder uses direct string slicing (`idx..idx+64`) on the
        // base64 output, which is ASCII so char and byte boundaries align.
        // A regression that dropped the 64-col wrap (writing the entire
        // base64 on one long line) would still round-trip through rustls
        // pki-types (lenient) but fail every OpenSSL-backed deployment.
        // We feed 200 random-ish bytes so the base64 output is > 256 chars
        // and must span multiple lines — then we assert every interior
        // base64 line is exactly 64 columns wide (the last line may be
        // shorter because the total base64 length need not be a multiple
        // of 64).
        let input: Vec<u8> = (0u8..200).collect();
        let mut out = String::new();
        append_der_as_pem(&mut out, "CERTIFICATE", &input);

        let lines: Vec<&str> = out.lines().collect();
        // Strip BEGIN + END markers; body lines are everything in between.
        let body: Vec<&str> = lines
            .iter()
            .filter(|l| !l.starts_with("-----"))
            .copied()
            .collect();
        assert!(
            body.len() >= 4,
            "expected multiple body lines for 200-byte input, got {body:?}",
        );
        // Every body line EXCEPT the final one must be exactly 64 cols.
        for line in &body[..body.len() - 1] {
            assert_eq!(
                line.len(),
                64,
                "interior body line is not 64 cols: {line:?}",
            );
        }
        // The final line is <= 64 cols (may be shorter on the last chunk).
        assert!(
            body[body.len() - 1].len() <= 64,
            "trailing body line > 64 cols: {:?}",
            body[body.len() - 1],
        );
    }

    #[test]
    fn svid_expiry_unix_extracts_real_notafter_from_testca_cert_as_positive_seconds() {
        // The two existing tests only exercise the error/zero branches
        // (empty chain, garbage DER). The happy path — parse a well-formed
        // X.509 cert and extract the `notAfter` unix timestamp — was
        // otherwise unexercised inside the module's own suite. This test
        // issues a real cert via `TestCa`, parses it through
        // `svid_expiry_unix`, and asserts the returned timestamp is
        // strictly greater than the current unix time — a regression that
        // silently returned 0 on the happy path (e.g. because
        // `x509_parser::prelude` moved and the import no longer resolves)
        // would fail here rather than only manifesting as an `expiry=0`
        // audit-log field in production. We do NOT upper-bound the
        // returned timestamp because `TestCa` uses `rcgen`'s default
        // `CertificateParams` which places `notAfter` far in the future
        // (intentionally, so test certs do not expire during CI) — any
        // value strictly greater than `now` is sufficient to validate the
        // positive path.
        use rustgate_test_utils::certs::TestCa;
        let ca = TestCa::new("SPIFFE Expiry Test CA");
        let cert = ca.issue_server_cert("svid.spiffe.test", &["svid.spiffe.test"]);
        let chain_der = pem_to_der_chain(&cert.cert_pem);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expiry = svid_expiry_unix(&chain_der);

        assert!(
            expiry > now,
            "expected future notAfter, got expiry={expiry} (now={now})",
        );
    }
}
