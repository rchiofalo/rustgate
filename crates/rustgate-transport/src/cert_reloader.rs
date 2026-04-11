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
        drop(tokio::spawn(async move {
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
        }));
    }

    /// Build a [`CertifiedKey`] from raw PEM file bytes.
    fn build_certified_key(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<CertifiedKey> {
        let cert_pem = std::str::from_utf8(cert_bytes).map_err(|e| {
            RustgateError::from(ConfigError::PemParse {
                kind: "certificate".to_string(),
                reason: format!("invalid UTF-8: {e}"),
            })
        })?;
        let key_pem = std::str::from_utf8(key_bytes).map_err(|e| {
            RustgateError::from(ConfigError::PemParse {
                kind: "private key".to_string(),
                reason: format!("invalid UTF-8: {e}"),
            })
        })?;

        let certs = crate::pem::parse_certs(cert_pem)?;
        let key_der = crate::pem::parse_key(key_pem)?;

        let signing_key = Self::load_signing_key(key_der)?;

        Ok(CertifiedKey::new(certs, signing_key))
    }

    /// Convert a [`PrivateKeyDer`] into a rustls [`SigningKey`] using the
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
}
