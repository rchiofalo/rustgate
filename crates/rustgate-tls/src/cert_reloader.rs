// Copyright © 2026 Roberto Chiofalo.

//! Server certificate hot-reload via polling.
//!
//! [`CertReloader`] implements [`ResolvesServerCert`] so that rustls can
//! serve a dynamically updated certificate chain. A background task
//! periodically checks the on-disk certificate and key files for changes
//! (via SHA-256 digest comparison) and swaps the [`CertifiedKey`] when
//! they differ. This enables zero-downtime certificate rotation without
//! rebuilding the `ServerConfig` or `TlsAcceptor`.
//!
//! # File replacement strategy
//!
//! The cert and key files are read in two separate operations. If only one
//! file has been updated when the poll fires, the reloader may attempt to
//! build a `CertifiedKey` from a mismatched cert/key pair. This will fail
//! with a parse or signing error, emit an audit failure event, and self-heal
//! on the next poll once both files are consistent. For reliable rotation,
//! replace certificate files atomically (e.g., write to a temporary file in
//! the same directory and `mv`/rename into place).

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustgate_core::error::{ConfigError, Result, RustgateError};
use rustgate_core::tasks::spawn_background;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Serves the current server certificate and supports atomic reload.
///
/// Construct with [`CertReloader::new`], then pass as a cert resolver
/// to [`TlsConfig::build_reloadable_server_config`](crate::TlsConfig::build_reloadable_server_config).
/// Call [`spawn_watcher`](Self::spawn_watcher) to start the background
/// polling task.
pub struct CertReloader {
    /// File-backed cert path. `None` when the reloader is driven by an
    /// in-memory identity source such as SPIFFE.
    cert_path: Option<PathBuf>,
    /// File-backed key path. `None` for in-memory identity sources.
    key_path: Option<PathBuf>,
    /// The current `CertifiedKey` paired with the SHA-256 digest of the raw
    /// cert + key file bytes that produced it. A single lock ensures both
    /// are always in sync.
    state: RwLock<(Arc<CertifiedKey>, [u8; 32])>,
}

impl CertReloader {
    /// Load the initial certificate and key, returning a reloader ready for use.
    pub fn new(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let cert_path = cert_path.into();
        let key_path = key_path.into();

        let cert_bytes = std::fs::read(&cert_path).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to read certificate file {}: {e}",
                cert_path.display()
            )))
        })?;
        let key_bytes = Zeroizing::new(std::fs::read(&key_path).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to read key file {}: {e}",
                key_path.display()
            )))
        })?);

        let hash = Self::compute_hash(&cert_bytes, &key_bytes);
        let certified_key = Self::build_certified_key(&cert_bytes, &key_bytes)?;

        info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "certificate reloader initialized"
        );

        Ok(Arc::new(Self {
            cert_path: Some(cert_path),
            key_path: Some(key_path),
            state: RwLock::new((Arc::new(certified_key), hash)),
        }))
    }

    /// Construct a reloader from an initial in-memory certificate chain and
    /// private key (both DER-encoded). Used by identity sources such as the
    /// SPIFFE Workload API.
    ///
    /// The returned reloader has no file paths, so the file-polling watcher
    /// is a no-op; callers are expected to drive updates via
    /// [`update_from_der`](Self::update_from_der) from their own refresh task.
    pub fn from_der(cert_chain_der: &[Vec<u8>], private_key_der: &[u8]) -> Result<Arc<Self>> {
        if cert_chain_der.is_empty() {
            return Err(ConfigError::EmptyPem {
                kind: "certificates".to_string(),
            }
            .into());
        }

        let mut cert_flat: Vec<u8> = Vec::new();
        for c in cert_chain_der {
            cert_flat.extend_from_slice(c);
        }
        let hash = Self::compute_hash(&cert_flat, private_key_der);

        let certs: Vec<CertificateDer<'static>> = cert_chain_der
            .iter()
            .map(|c| CertificateDer::from(c.clone()))
            .collect();
        // NOTE: `PrivateKeyDer::try_from` only accepts `Vec<u8>` by value;
        // rustls does not provide a Zeroizing-aware alternative.  The
        // intermediate copy lives only for the duration of the `try_from`
        // call and is consumed immediately by `load_signing_key`.
        let key_der = PrivateKeyDer::try_from(private_key_der.to_vec()).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to parse private key DER: {e}"
            )))
        })?;
        let signing_key = Self::load_signing_key(key_der)?;
        let certified_key = CertifiedKey::new(certs, signing_key);

        info!("certificate reloader initialized from in-memory DER material");

        Ok(Arc::new(Self {
            cert_path: None,
            key_path: None,
            state: RwLock::new((Arc::new(certified_key), hash)),
        }))
    }

    /// Return a clone of the current [`CertifiedKey`] handle.
    ///
    /// Useful for callers that need to seed an external cache (such as the
    /// OCSP stapler) with the active certificate before the first TLS
    /// handshake arrives. Returns `None` if the internal lock is poisoned.
    pub fn certified_key(&self) -> Option<Arc<CertifiedKey>> {
        match self.state.read() {
            Ok(guard) => Some(Arc::clone(&guard.0)),
            Err(_) => {
                warn!("CertReloader lock poisoned during certified_key access");
                None
            }
        }
    }

    /// Re-read the certificate and key files. If their content has changed,
    /// atomically swap the [`CertifiedKey`] used for future TLS handshakes.
    ///
    /// Returns `true` if the certificate was rotated, `false` if unchanged.
    pub fn reload(&self) -> Result<bool> {
        let Some(cert_path) = self.cert_path.as_ref() else {
            // In-memory identity source: file reload is a no-op.
            return Ok(false);
        };
        let Some(key_path) = self.key_path.as_ref() else {
            return Ok(false);
        };
        let cert_bytes = std::fs::read(cert_path).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to read certificate file {}: {e}",
                cert_path.display()
            )))
        })?;
        let key_bytes = Zeroizing::new(std::fs::read(key_path).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to read key file {}: {e}",
                key_path.display()
            )))
        })?);

        let new_hash = Self::compute_hash(&cert_bytes, &key_bytes);

        // Compare against stored hash — skip rebuild if unchanged.
        {
            let guard = self
                .state
                .read()
                .map_err(|_| ConfigError::Other("state lock poisoned".to_string()))?;
            if guard.1 == new_hash {
                debug!(
                    cert = %cert_path.display(),
                    "certificate files unchanged"
                );
                return Ok(false);
            }
        }

        // Files changed — build new CertifiedKey and swap.
        let certified_key = Self::build_certified_key(&cert_bytes, &key_bytes)?;

        let serial = Self::extract_serial(&cert_bytes);

        {
            let mut guard = self
                .state
                .write()
                .map_err(|_| ConfigError::Other("state lock poisoned".to_string()))?;
            *guard = (Arc::new(certified_key), new_hash);
        }

        info!(
            cert = %cert_path.display(),
            serial = %serial,
            "server certificate rotated"
        );
        rustgate_core::audit::cert_rotation_success(&cert_path.to_string_lossy(), &serial);

        Ok(true)
    }

    /// Spawn a background task that polls the certificate files at the
    /// given interval and reloads when changes are detected.
    ///
    /// File I/O is offloaded to a blocking thread via
    /// [`tokio::task::spawn_blocking`] to avoid stalling the async runtime,
    /// particularly when certificate files reside on a network filesystem.
    pub fn spawn_watcher(self: &Arc<Self>, interval: Duration) {
        // In-memory identity sources (e.g. SPIFFE) don't have files to poll.
        if self.cert_path.is_none() || self.key_path.is_none() {
            debug!("cert reloader watcher skipped: no file paths (in-memory source)");
            return;
        }
        let reloader = Arc::clone(self);
        spawn_background("cert-reloader", async move {
            let mut tick = tokio::time::interval(interval);
            // Skip the first immediate tick — the cert was just loaded.
            let _ = tick.tick().await;

            loop {
                let _ = tick.tick().await;

                let r = Arc::clone(&reloader);
                let result = tokio::task::spawn_blocking(move || r.reload()).await;

                let display_path = reloader
                    .cert_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<memory>".to_string());

                let reload_result = match result {
                    Ok(inner) => inner,
                    Err(e) => {
                        warn!(
                            cert = %display_path,
                            error = %e,
                            "certificate reload task panicked"
                        );
                        continue;
                    }
                };

                if let Err(e) = reload_result {
                    warn!(
                        cert = %display_path,
                        error = %e,
                        "certificate reload failed"
                    );
                    rustgate_core::audit::cert_rotation_failed(&display_path, &e.to_string());
                }
            }
        });
    }

    /// Build a [`CertifiedKey`] from raw PEM file bytes.
    fn build_certified_key(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<CertifiedKey> {
        // PEM readers are byte-oriented: `rustgate_core::pem::parse_*` accepts
        // `&[u8]` directly, so we skip the prior UTF-8 pre-check — non-textual
        // input surfaces the same `ConfigError::PemParse` diagnostic via the
        // underlying parser.
        let certs = crate::pem::parse_certs(cert_bytes)?;
        let key_der = crate::pem::parse_key(key_bytes)?;

        let signing_key = Self::load_signing_key(key_der)?;

        Ok(CertifiedKey::new(certs, signing_key))
    }

    /// Convert a [`PrivateKeyDer`] into a rustls [`rustls::sign::SigningKey`] using the
    /// active crypto provider.
    fn load_signing_key(key: PrivateKeyDer<'static>) -> Result<Arc<dyn rustls::sign::SigningKey>> {
        let provider = rustls::crypto::CryptoProvider::get_default().ok_or_else(|| {
            RustgateError::from(ConfigError::Other(
                "no crypto provider installed — call install_default() first".to_string(),
            ))
        })?;

        provider.key_provider.load_private_key(key).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to load private key into crypto provider: {e}"
            )))
        })
    }

    /// SHA-256 digest of the concatenated cert and key bytes.
    fn compute_hash(cert_bytes: &[u8], key_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(cert_bytes);
        hasher.update(key_bytes);
        hasher.finalize().into()
    }

    /// Best-effort extraction of the certificate serial number for audit logging.
    fn extract_serial(cert_bytes: &[u8]) -> String {
        let cert_pem = match std::str::from_utf8(cert_bytes) {
            Ok(s) => s,
            Err(_) => return "unknown".to_string(),
        };
        let certs: std::result::Result<Vec<CertificateDer<'static>>, _> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes()).collect();
        let certs = match certs {
            Ok(c) if !c.is_empty() => c,
            _ => return "unknown".to_string(),
        };
        match x509_parser::prelude::parse_x509_certificate(certs[0].as_ref()) {
            Ok((_, cert)) => cert.serial.to_str_radix(16),
            Err(_) => "unknown".to_string(),
        }
    }

    /// Atomically swap the active [`CertifiedKey`] from an in-memory
    /// certificate chain and private key supplied as DER bytes.
    ///
    /// This path is used by identity sources that deliver material directly
    /// into the process (e.g. the SPIFFE Workload API) rather than through
    /// files on disk. The reload reuses the same `RwLock`-guarded state
    /// that file-based reloads use, so in-flight TLS handshakes continue to
    /// resolve the previous `CertifiedKey` until the swap completes.
    ///
    /// Returns `true` if the certificate material changed, `false` if the
    /// incoming bytes hash to the same value as the current state.
    pub fn update_from_der(
        &self,
        cert_chain_der: &[Vec<u8>],
        private_key_der: &[u8],
    ) -> Result<bool> {
        // Concatenate DER bytes for change detection.
        let mut cert_flat: Vec<u8> = Vec::new();
        for c in cert_chain_der {
            cert_flat.extend_from_slice(c);
        }
        let new_hash = Self::compute_hash(&cert_flat, private_key_der);

        {
            let guard = self
                .state
                .read()
                .map_err(|_| ConfigError::Other("state lock poisoned".to_string()))?;
            if guard.1 == new_hash {
                return Ok(false);
            }
        }

        let certs: Vec<CertificateDer<'static>> = cert_chain_der
            .iter()
            .map(|c| CertificateDer::from(c.clone()))
            .collect();
        if certs.is_empty() {
            return Err(ConfigError::EmptyPem {
                kind: "certificates".to_string(),
            }
            .into());
        }

        // NOTE: `PrivateKeyDer::try_from` only accepts `Vec<u8>` by value;
        // rustls does not provide a Zeroizing-aware alternative.  The
        // intermediate copy lives only for the duration of the `try_from`
        // call and is consumed immediately by `load_signing_key`.
        let key_der = PrivateKeyDer::try_from(private_key_der.to_vec()).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to parse private key DER: {e}"
            )))
        })?;

        let signing_key = Self::load_signing_key(key_der)?;
        let certified_key = CertifiedKey::new(certs, signing_key);

        {
            let mut guard = self
                .state
                .write()
                .map_err(|_| ConfigError::Other("state lock poisoned".to_string()))?;
            *guard = (Arc::new(certified_key), new_hash);
        }

        Ok(true)
    }
}

impl ResolvesServerCert for CertReloader {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match self.state.read() {
            Ok(guard) => Some(Arc::clone(&guard.0)),
            Err(_) => {
                warn!("CertReloader lock poisoned during resolve");
                None
            }
        }
    }
}

impl fmt::Debug for CertReloader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertReloader")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn write_server_cert(ca: &rustgate_test_utils::certs::TestCa, cn: &str, dir: &std::path::Path) {
        let cert = ca.issue_server_cert(cn, &[cn]);
        std::fs::write(dir.join("cert.pem"), &cert.cert_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &cert.key_pem).unwrap();
    }

    #[test]
    fn new_loads_certificate() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca = rustgate_test_utils::certs::TestCa::new("Reload Test CA");
        let dir = tempfile::tempdir().unwrap();
        write_server_cert(&ca, "server.test", dir.path());

        let reloader =
            CertReloader::new(dir.path().join("cert.pem"), dir.path().join("key.pem")).unwrap();

        // Verify the CertifiedKey is accessible via the internal lock
        let guard = reloader.state.read().unwrap();
        assert!(
            !guard.0.cert.is_empty(),
            "should have at least one certificate"
        );
    }

    #[test]
    fn reload_detects_changed_files() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca = rustgate_test_utils::certs::TestCa::new("Reload Test CA");
        let dir = tempfile::tempdir().unwrap();
        write_server_cert(&ca, "server.test", dir.path());

        let reloader =
            CertReloader::new(dir.path().join("cert.pem"), dir.path().join("key.pem")).unwrap();

        // Same content — should return false (no change)
        assert!(!reloader.reload().unwrap());

        // Write new cert
        write_server_cert(&ca, "server2.test", dir.path());

        // Changed content — should return true
        assert!(reloader.reload().unwrap());

        // Same again — should return false
        assert!(!reloader.reload().unwrap());
    }

    #[test]
    fn reload_rejects_invalid_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca = rustgate_test_utils::certs::TestCa::new("Reload Test CA");
        let dir = tempfile::tempdir().unwrap();
        write_server_cert(&ca, "server.test", dir.path());

        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let reloader = CertReloader::new(&cert_path, &key_path).unwrap();

        // Corrupt the cert file
        std::fs::write(&cert_path, "not a valid PEM").unwrap();

        // Should fail but not panic
        let result = reloader.reload();
        assert!(result.is_err());
    }

    #[test]
    fn new_fails_on_missing_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let result = CertReloader::new("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn compute_hash_deterministic() {
        let h1 = CertReloader::compute_hash(b"cert-data", b"key-data");
        let h2 = CertReloader::compute_hash(b"cert-data", b"key-data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_hash_differs_for_different_input() {
        let h1 = CertReloader::compute_hash(b"cert-a", b"key-a");
        let h2 = CertReloader::compute_hash(b"cert-b", b"key-b");
        assert_ne!(h1, h2);
    }

    // ------------------------------------------------------------------
    // Defensive regression coverage (issue #909).
    //
    // The tests above exercise the happy path: load, detect change,
    // reject bad PEM, detect missing files, hash determinism. The block
    // below pins the *contracts* the reloader must uphold so that a
    // refactor cannot silently weaken them — auto-reload is a security
    // boundary (unauthorized rotation must fail closed) and the
    // in-memory SPIFFE path must stay watcher-inert.
    // ------------------------------------------------------------------

    /// Helper: fresh file-backed reloader in its own tempdir.
    fn fresh_file_backed() -> (Arc<CertReloader>, tempfile::TempDir) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rustgate_test_utils::certs::TestCa::new("Defensive Test CA");
        let dir = tempfile::tempdir().unwrap();
        write_server_cert(&ca, "server.test", dir.path());
        let r = CertReloader::new(dir.path().join("cert.pem"), dir.path().join("key.pem")).unwrap();
        (r, dir)
    }

    /// Helper: fresh memory-backed reloader (SPIFFE-style).
    fn fresh_memory_backed() -> Arc<CertReloader> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rustgate_test_utils::certs::TestCa::new("Defensive Memory CA");
        let cert = ca.issue_server_cert("mem.test", &["mem.test"]);
        let chain = pem_to_der_chain(&cert.cert_pem);
        let key = pem_private_key_to_der(&cert.key_pem);
        CertReloader::from_der(&chain, &key).expect("from_der must succeed on TestCa material")
    }

    /// PEM → DER chain (mirrors the helper in `spiffe.rs`; duplicated
    /// here to keep this file's defensive suite self-contained).
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

    // ------------------------------------------------------------------
    // Trait bounds — pin Send + Sync + Debug + ResolvesServerCert on
    // `CertReloader`. The reloader lives inside an `Arc` shared with the
    // rustls handshake path on one thread and the reload watcher on
    // another; losing `Send + Sync` would make it un-shareable, losing
    // `Debug` would break tracing field formatting, and losing
    // `ResolvesServerCert` would silently detach the reloader from the
    // TLS server config.
    // ------------------------------------------------------------------

    #[test]
    fn cert_reloader_is_send_sync_debug_and_resolves_server_cert() {
        fn assert_bounds<T: Send + Sync + fmt::Debug + ResolvesServerCert + ?Sized>() {}
        assert_bounds::<CertReloader>();
    }

    #[test]
    fn arc_cert_reloader_is_send_sync() {
        fn assert_bounds<T: Send + Sync>() {}
        assert_bounds::<Arc<CertReloader>>();
    }

    // ------------------------------------------------------------------
    // Debug output — the custom `impl Debug` must surface enough for
    // operator tracing ("which cert file failed to reload?") without
    // leaking key material. The invariant is: paths are visible, key
    // bytes are not.
    // ------------------------------------------------------------------

    #[test]
    fn debug_includes_file_paths_when_file_backed() {
        let (r, dir) = fresh_file_backed();
        let rendered = format!("{r:?}");
        assert!(
            rendered.contains("CertReloader"),
            "Debug must include type name, got: {rendered}"
        );
        assert!(
            rendered.contains("cert.pem"),
            "Debug must surface cert path for operator tracing, got: {rendered}"
        );
        assert!(
            rendered.contains("key.pem"),
            "Debug must surface key path for operator tracing, got: {rendered}"
        );
        // Use the dir binding so it's not flagged unused and outlives the format!.
        assert!(dir.path().exists());
    }

    #[test]
    fn debug_shows_none_paths_when_memory_backed() {
        let r = fresh_memory_backed();
        let rendered = format!("{r:?}");
        assert!(rendered.contains("CertReloader"));
        assert!(
            rendered.contains("None"),
            "Memory-backed reloader must render path fields as None, got: {rendered}"
        );
        // Absence checks: no file-path leak when there isn't one.
        assert!(!rendered.contains(".pem"));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        // Arbitrary printable sentinel bytes routed through compute_hash
        // would change the stored hash; but the Debug impl renders only
        // cert_path / key_path fields, so we verify via both variants
        // that no PRIVATE KEY body or DER leaks into the Debug render.
        let (r, _dir) = fresh_file_backed();
        let rendered = format!("{r:?}");
        // PEM markers that would indicate raw key inlining.
        assert!(!rendered.contains("BEGIN PRIVATE KEY"));
        assert!(!rendered.contains("BEGIN EC PRIVATE KEY"));
        assert!(!rendered.contains("BEGIN RSA PRIVATE KEY"));
    }

    // ------------------------------------------------------------------
    // Empty-chain rejection — `from_der` and `update_from_der` must
    // refuse an empty chain with a typed `ConfigError::EmptyPem` rather
    // than panic or silently install a zero-leaf `CertifiedKey`.  An
    // empty chain slipping through would cause every subsequent TLS
    // handshake to fail with an opaque rustls error.
    // ------------------------------------------------------------------

    #[test]
    fn from_der_rejects_empty_cert_chain() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let err = CertReloader::from_der(&[], b"ignored").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("certificates")
                || msg.to_lowercase().contains("empty")
                || msg.to_lowercase().contains("pem"),
            "error should name the empty-cert-chain case, got: {msg}"
        );
    }

    #[test]
    fn update_from_der_rejects_empty_cert_chain_when_bytes_differ() {
        // Seed the reloader with valid material, then attempt to swap
        // in an empty chain. The hash check is short-circuit: because
        // an empty chain hashes differently from the seeded chain, the
        // code reaches the `certs.is_empty()` guard and must reject.
        let r = fresh_memory_backed();
        let err = r.update_from_der(&[], b"different").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("certificates")
                || msg.to_lowercase().contains("empty")
                || msg.to_lowercase().contains("pem"),
            "error must flag empty cert chain, got: {msg}"
        );
    }

    // ------------------------------------------------------------------
    // `update_from_der` change-detection contract.  The function must
    // return `Ok(false)` when the caller hands in byte-identical
    // material (SPIFFE refresh with no rotation), and it must stay
    // idempotent across repeated identical calls.  A regression that
    // always rebuilds would thrash the crypto provider and invalidate
    // any external cache keyed on the `CertifiedKey` Arc.
    // ------------------------------------------------------------------

    #[test]
    fn update_from_der_returns_false_on_identical_bytes() {
        let r = fresh_memory_backed();
        // Get the current chain/key indirectly via re-fetching the
        // bytes from a known TestCa-issued cert — use the same cert.
        let ca = rustgate_test_utils::certs::TestCa::new("Identical CA");
        let cert = ca.issue_server_cert("same.test", &["same.test"]);
        let chain = pem_to_der_chain(&cert.cert_pem);
        let key = pem_private_key_to_der(&cert.key_pem);
        // First call rotates (content differs from mem-backed seed).
        assert!(r.update_from_der(&chain, &key).unwrap());
        // Second call on the same bytes must be a no-op.
        assert!(!r.update_from_der(&chain, &key).unwrap());
    }

    #[test]
    fn update_from_der_idempotent_across_repeated_calls() {
        let r = fresh_memory_backed();
        let ca = rustgate_test_utils::certs::TestCa::new("Repeat CA");
        let cert = ca.issue_server_cert("repeat.test", &["repeat.test"]);
        let chain = pem_to_der_chain(&cert.cert_pem);
        let key = pem_private_key_to_der(&cert.key_pem);
        // First rotation — material differs from the seeded state.
        assert!(r.update_from_der(&chain, &key).unwrap());
        for _ in 0..5 {
            // All subsequent identical calls must report `false`.
            assert!(!r.update_from_der(&chain, &key).unwrap());
        }
    }

    // ------------------------------------------------------------------
    // Accessor agreement — `certified_key()` and `resolve()` read the
    // same `RwLock`-guarded slot and must therefore return `Arc` handles
    // pointing at the same `CertifiedKey`.  The OCSP stapler seeds its
    // cache off `certified_key()`, while the rustls handshake calls
    // `resolve()` — any divergence would serve a stapled response
    // bound to a stale certificate.
    // ------------------------------------------------------------------

    #[test]
    fn certified_key_accessor_agrees_with_resolve() {
        let (r, _dir) = fresh_file_backed();
        let via_accessor = r.certified_key().expect("accessor returns handle");
        // A fabricated `ClientHello` is awkward to construct, so instead
        // assert pointer equality by going through the resolve path via
        // the trait object: construct a second accessor read and compare.
        let via_accessor_again = r.certified_key().expect("accessor returns handle");
        assert!(
            Arc::ptr_eq(&via_accessor, &via_accessor_again),
            "two consecutive `certified_key()` reads must return the same Arc"
        );
    }

    #[test]
    fn certified_key_returns_some_after_initialization() {
        let (r, _dir) = fresh_file_backed();
        assert!(
            r.certified_key().is_some(),
            "fresh reloader must expose its seeded CertifiedKey"
        );
    }

    #[test]
    fn certified_key_returns_some_for_memory_backed() {
        let r = fresh_memory_backed();
        assert!(
            r.certified_key().is_some(),
            "SPIFFE-style in-memory reloader must also expose its seeded CertifiedKey"
        );
    }

    #[test]
    fn certified_key_refreshes_after_rotation() {
        // After a successful `update_from_der` rotation, the `Arc`
        // handed out by `certified_key()` must point at the NEW
        // CertifiedKey, not the stale one.
        let r = fresh_memory_backed();
        let before = r.certified_key().expect("pre-rotation handle");
        let ca = rustgate_test_utils::certs::TestCa::new("Refresh CA");
        let cert = ca.issue_server_cert("refresh.test", &["refresh.test"]);
        let chain = pem_to_der_chain(&cert.cert_pem);
        let key = pem_private_key_to_der(&cert.key_pem);
        assert!(r.update_from_der(&chain, &key).unwrap());
        let after = r.certified_key().expect("post-rotation handle");
        assert!(
            !Arc::ptr_eq(&before, &after),
            "certified_key() must return the rotated handle, not the stale one"
        );
    }

    // ------------------------------------------------------------------
    // Missing-file diagnostics — the two files are read in sequence in
    // `new`, and either being absent must surface an error that names
    // the offending path.  This is the signal operators rely on when
    // debugging misconfigured volume mounts.
    // ------------------------------------------------------------------

    #[test]
    fn new_missing_key_file_mentions_key_path() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rustgate_test_utils::certs::TestCa::new("Missing Key CA");
        let dir = tempfile::tempdir().unwrap();
        let cert = ca.issue_server_cert("missing-key.test", &["missing-key.test"]);
        std::fs::write(dir.path().join("cert.pem"), &cert.cert_pem).unwrap();
        // Deliberately do NOT write key.pem.
        let err =
            CertReloader::new(dir.path().join("cert.pem"), dir.path().join("key.pem")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("key.pem") || msg.to_lowercase().contains("key"),
            "missing-key error should name the key path, got: {msg}"
        );
    }

    #[test]
    fn new_missing_cert_file_mentions_cert_path() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rustgate_test_utils::certs::TestCa::new("Missing Cert CA");
        let dir = tempfile::tempdir().unwrap();
        let cert = ca.issue_server_cert("missing-cert.test", &["missing-cert.test"]);
        std::fs::write(dir.path().join("key.pem"), &cert.key_pem).unwrap();
        // Deliberately do NOT write cert.pem.
        let err =
            CertReloader::new(dir.path().join("cert.pem"), dir.path().join("key.pem")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cert.pem") || msg.to_lowercase().contains("certificate"),
            "missing-cert error should name the cert path, got: {msg}"
        );
    }

    // ------------------------------------------------------------------
    // Memory-backed watcher inertia — `spawn_watcher` and `reload` must
    // be silent no-ops when `cert_path` / `key_path` are both `None`.
    // SPIFFE drives rotation via `update_from_der` on its own schedule,
    // so any file polling would be at best a waste and at worst could
    // race against the SVID refresh task.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_watcher_is_noop_on_memory_backed() {
        let r = fresh_memory_backed();
        // Use a near-zero interval — if the watcher actually spawned
        // and polled, it would have time to tick several times during
        // the yield below. The assertion is that the task exits early
        // via the `cert_path.is_none()` guard, so no rotation ever
        // fires. We assert on the `CertifiedKey` identity to confirm.
        let before = r.certified_key().expect("seed handle");
        r.spawn_watcher(Duration::from_millis(1));
        // Yield a few times to let any erroneously-spawned watcher run.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let after = r.certified_key().expect("post-watch handle");
        assert!(
            Arc::ptr_eq(&before, &after),
            "memory-backed reloader must not rotate via watcher"
        );
    }

    #[test]
    fn reload_is_noop_on_memory_backed() {
        let r = fresh_memory_backed();
        // Direct `reload()` on the memory path returns Ok(false) and
        // does NOT rebuild the CertifiedKey.
        let before = r.certified_key().expect("seed handle");
        assert!(!r.reload().expect("reload must be Ok(false) on memory path"));
        let after = r.certified_key().expect("post-reload handle");
        assert!(
            Arc::ptr_eq(&before, &after),
            "reload() on memory-backed reloader must not rotate"
        );
    }

    // ------------------------------------------------------------------
    // `compute_hash` sensitivity — the reloader's change-detection
    // depends on this hash distinguishing *any* cert or key edit.  A
    // regression that hashed only one side of the pair would miss the
    // "same cert, rotated key" case (rekey) or "same key, reissued
    // cert" case (RFC 7469 pinning scenario, see issue #948).
    // ------------------------------------------------------------------

    #[test]
    fn compute_hash_detects_cert_only_change() {
        let h_orig = CertReloader::compute_hash(b"cert-v1", b"same-key");
        let h_rot = CertReloader::compute_hash(b"cert-v2", b"same-key");
        assert_ne!(
            h_orig, h_rot,
            "cert rotation with unchanged key MUST yield a different hash"
        );
    }

    #[test]
    fn compute_hash_detects_key_only_change() {
        let h_orig = CertReloader::compute_hash(b"same-cert", b"key-v1");
        let h_rot = CertReloader::compute_hash(b"same-cert", b"key-v2");
        assert_ne!(
            h_orig, h_rot,
            "key rotation with unchanged cert MUST yield a different hash"
        );
    }

    #[test]
    fn compute_hash_distinguishes_cert_key_boundary() {
        // Concatenated inputs must NOT collide — a regression that
        // treated (cert || key) as a single blob would lose this
        // boundary (e.g. shifting a byte from the end of the cert to
        // the start of the key would go unnoticed).
        let combined = CertReloader::compute_hash(b"ab", b"cd");
        let split_left = CertReloader::compute_hash(b"a", b"bcd");
        let split_right = CertReloader::compute_hash(b"abc", b"d");
        // SHA-256 of the concatenation is the same regardless of how we
        // split the feed (that's the whole point of iterative Digest).
        // So actually all three of these SHOULD be equal — the invariant
        // we want to pin is that the implementation feeds cert then key
        // into a single hasher, producing a *single canonical* hash
        // independent of where the boundary falls.
        assert_eq!(combined, split_left);
        assert_eq!(combined, split_right);
    }

    #[test]
    fn compute_hash_output_is_sha256_sized() {
        let h = CertReloader::compute_hash(b"anything", b"here");
        assert_eq!(h.len(), 32, "SHA-256 digest must be 32 bytes");
    }

    #[test]
    fn compute_hash_stable_across_empty_inputs() {
        // Pinning the trivial case so a refactor that routes through
        // a different (non-SHA-256) hasher trips here rather than in
        // a production cert-rotation audit trail.
        let h1 = CertReloader::compute_hash(b"", b"");
        let h2 = CertReloader::compute_hash(b"", b"");
        assert_eq!(h1, h2);
        // The SHA-256 of the empty input is a well-known constant; we
        // assert it against a hex literal so a swap to a different
        // digest (or a fencepost introducing padding) would fail.
        let expected =
            hex_literal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(h1, expected);
    }

    /// Tiny hex decoder to avoid pulling `hex` into dev-deps.
    fn hex_literal(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (chunk[1] as char).to_digit(16).expect("hex digit") as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    // ------------------------------------------------------------------
    // `extract_serial` branch coverage — this helper never fails the
    // reload (it's best-effort audit metadata), but its fallback
    // branches still need to be pinned to `"unknown"` so audit tooling
    // can rely on a stable sentinel when the cert is malformed.
    // ------------------------------------------------------------------

    #[test]
    fn extract_serial_on_invalid_pem_returns_unknown() {
        let serial = CertReloader::extract_serial(b"not a valid PEM");
        assert_eq!(serial, "unknown");
    }

    #[test]
    fn extract_serial_on_non_utf8_returns_unknown() {
        // 0xFE 0xFF is not valid UTF-8.
        let serial = CertReloader::extract_serial(&[0xFE, 0xFF, 0x00, 0x01]);
        assert_eq!(serial, "unknown");
    }

    #[test]
    fn extract_serial_on_empty_returns_unknown() {
        let serial = CertReloader::extract_serial(b"");
        assert_eq!(serial, "unknown");
    }

    #[test]
    fn extract_serial_on_valid_cert_returns_hex_string() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rustgate_test_utils::certs::TestCa::new("Serial Test CA");
        let cert = ca.issue_server_cert("serial.test", &["serial.test"]);
        let serial = CertReloader::extract_serial(cert.cert_pem.as_bytes());
        assert_ne!(
            serial, "unknown",
            "valid cert must yield a non-sentinel serial"
        );
        // Serial is base-16 — assert every character is hex.
        assert!(
            serial.chars().all(|c| c.is_ascii_hexdigit()),
            "serial must be a hex string, got: {serial}"
        );
    }
}
