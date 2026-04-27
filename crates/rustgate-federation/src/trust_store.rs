// Copyright © 2026 Roberto Chiofalo.

//! Dynamic CA certificate management for federation trust.
//!
//! Manages trusted CA certificates that can be added and removed at runtime
//! without restarting the server. Certificates persist to disk as PEM files
//! in a configured data directory.
//!
//! Changes take effect on the next TLS handshake when the trust store is
//! queried to build a fresh [`RootCertStore`].

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use rustgate_core::masking::hash_cn;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::error::{FederationError, Result};

/// Metadata about a stored certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// Subject common name (used as the store key).
    pub common_name: String,
    /// Issuer common name.
    pub issuer: String,
    /// Validity start (human-readable).
    pub not_before: String,
    /// Validity end (human-readable).
    pub not_after: String,
    /// SHA-256 fingerprint of the DER encoding.
    pub fingerprint: String,
}

/// A stored certificate with its DER data, PEM representation, and metadata.
struct StoredCert {
    der: CertificateDer<'static>,
    pem: Vec<u8>,
    info: CertInfo,
}

/// Dynamic CA certificate store for federation TLS.
///
/// Certificates can be added and removed at runtime. The store
/// persists certificates to disk as PEM files if a data directory
/// is configured.
pub struct TrustStore {
    certs: RwLock<HashMap<String, StoredCert>>,
    data_dir: Option<PathBuf>,
    /// Monotonically increasing counter that increments on every add or remove.
    /// Consumers can poll this to detect when the trust store contents have changed
    /// and cached TLS configurations need rebuilding.
    generation: AtomicU64,
}

impl std::fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = match self.certs.read() {
            Ok(c) => Some(c.len()),
            Err(_) => None,
        };
        f.debug_struct("TrustStore")
            .field("count", &count)
            .field("data_dir", &self.data_dir)
            .finish()
    }
}

impl TrustStore {
    /// Create a new empty trust store with optional disk persistence.
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
            data_dir,
            generation: AtomicU64::new(0),
        }
    }

    /// Load certificates from a directory.
    ///
    /// Reads all `.pem` and `.crt` files from the specified directory.
    /// Creates the directory if it does not exist.
    pub fn load_from_directory(dir: &Path) -> Result<Self> {
        let store = Self::new(Some(dir.to_path_buf()));

        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| {
                FederationError::io(
                    format!("failed to create trust store directory: {}", dir.display()),
                    e,
                )
            })?;
            return Ok(store);
        }

        let entries = fs::read_dir(dir).map_err(|e| {
            FederationError::io(
                format!("failed to read trust store directory: {}", dir.display()),
                e,
            )
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| FederationError::io("reading trust store entry", e))?;
            let path = entry.path();

            if path.is_dir() {
                continue;
            }

            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if !name.ends_with(".pem") && !name.ends_with(".crt") {
                continue;
            }

            match fs::read(&path) {
                Ok(pem_data) => match store.add_certificate_from_pem(&pem_data) {
                    Ok(cert_info) => {
                        debug!(
                            cn = %hash_cn(&cert_info.common_name),
                            path = %path.display(),
                            "loaded certificate"
                        );
                    }
                    Err(e) => {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "failed to load certificate"
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to read certificate file"
                    );
                }
            }
        }

        let count = store.count()?;
        info!(count, dir = %dir.display(), "loaded trust store certificates");

        Ok(store)
    }

    /// Add a certificate from PEM-encoded data.
    ///
    /// The certificate is stored in memory and optionally persisted to disk.
    /// Returns metadata about the added certificate.
    pub fn add_certificate_from_pem(&self, pem_data: &[u8]) -> Result<CertInfo> {
        // Shared helper — `parse_certs` already rejects empty inputs via
        // `ConfigError::EmptyPem`, so we lose the separate empty-check.
        let mut certs = rustgate_core::pem::parse_certs(pem_data)
            .map_err(|e| FederationError::pem("failed to parse PEM data", e))?;

        // Take the first certificate (safe: parse_certs guarantees non-empty).
        let der = certs.remove(0);

        let cert_info = extract_cert_info(&der)?;
        let cn = cert_info.common_name.clone();

        let stored = StoredCert {
            der,
            pem: pem_data.to_vec(),
            info: cert_info.clone(),
        };

        // Store in memory
        {
            let mut certs = self
                .certs
                .write()
                .map_err(|e| FederationError::lock("lock poisoned", e))?;
            let _ = certs.insert(cn.clone(), stored);
        }
        let _ = self.generation.fetch_add(1, Ordering::Release);

        // Persist to disk
        if let Some(ref dir) = self.data_dir
            && let Err(e) = persist_cert_to_disk(dir, &cn, pem_data)
        {
            warn!(cn = %cn, error = %e, "failed to persist certificate to disk");
        }

        info!(cn = %hash_cn(&cn), "added certificate to trust store");
        Ok(cert_info)
    }

    /// Remove a certificate by common name.
    ///
    /// Returns `true` if the certificate was found and removed.
    pub fn remove_certificate(&self, cn: &str) -> Result<bool> {
        let removed = {
            let mut certs = self.certs.write().map_err(|e| {
                error!("trust store lock poisoned — cannot remove certificate");
                FederationError::lock("trust store lock poisoned", e)
            })?;
            certs.remove(cn).is_some()
        };

        if removed {
            let _ = self.generation.fetch_add(1, Ordering::Release);
            // Remove from disk
            if let Some(ref dir) = self.data_dir {
                let filename = sanitize_filename(cn);
                let path = dir.join(format!("{filename}.pem"));
                if path.exists()
                    && let Err(e) = fs::remove_file(&path)
                {
                    warn!(
                        cn = %cn,
                        path = %path.display(),
                        error = %e,
                        "failed to remove certificate file"
                    );
                }
            }

            info!(cn = %hash_cn(cn), "removed certificate from trust store");
        }

        Ok(removed)
    }

    /// Get a certificate's PEM data by common name.
    pub fn get_certificate_pem(&self, cn: &str) -> Result<Option<Vec<u8>>> {
        let certs = self.certs.read().map_err(|e| {
            error!("trust store lock poisoned — cannot retrieve certificate PEM");
            FederationError::lock("trust store lock poisoned", e)
        })?;
        Ok(certs.get(cn).map(|c| c.pem.clone()))
    }

    /// Get certificate metadata by common name.
    pub fn get_certificate_info(&self, cn: &str) -> Result<Option<CertInfo>> {
        let certs = self.certs.read().map_err(|e| {
            error!("trust store lock poisoned — cannot retrieve certificate info");
            FederationError::lock("trust store lock poisoned", e)
        })?;
        Ok(certs.get(cn).map(|c| c.info.clone()))
    }

    /// List metadata for all stored certificates.
    pub fn list_certificates(&self) -> Result<Vec<CertInfo>> {
        let certs = self.certs.read().map_err(|e| {
            error!("trust store lock poisoned — cannot list certificates");
            FederationError::lock("trust store lock poisoned", e)
        })?;
        Ok(certs.values().map(|c| c.info.clone()).collect())
    }

    /// Return the number of stored certificates.
    pub fn count(&self) -> Result<usize> {
        let certs = self.certs.read().map_err(|e| {
            error!("trust store lock poisoned — cannot read certificate count");
            FederationError::lock("trust store lock poisoned", e)
        })?;
        Ok(certs.len())
    }

    /// Return the current generation counter.
    ///
    /// This value increments on every `add_certificate_from_pem` or
    /// `remove_certificate` call. Consumers can compare it against a
    /// previously observed value to detect trust store changes and
    /// invalidate cached TLS configurations.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Check if a certificate with the given common name is trusted.
    pub fn is_trusted(&self, cn: &str) -> Result<bool> {
        let certs = self.certs.read().map_err(|e| {
            error!("trust store lock poisoned — cannot check certificate trust");
            FederationError::lock("trust store lock poisoned", e)
        })?;
        Ok(certs.contains_key(cn))
    }

    /// Build a [`RootCertStore`] containing all certificates in the trust store.
    ///
    /// Used to construct TLS configurations that verify peer certificates
    /// against dynamically managed CAs.
    ///
    /// Returns an error if the internal lock is poisoned, which would
    /// otherwise silently produce an empty store and disable CA verification.
    pub fn build_root_cert_store(&self) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();

        let certs = self.certs.read().map_err(|e| {
            error!(
                "trust store lock poisoned — cannot build root cert store, CA verification disabled"
            );
            FederationError::lock("trust store lock poisoned", e)
        })?;

        for (cn, cert) in certs.iter() {
            if let Err(e) = store.add(cert.der.clone()) {
                warn!(cn = %cn, error = %e, "failed to add certificate to root store");
            }
        }

        Ok(store)
    }

    /// Build a [`RootCertStore`] starting from a base CA PEM, then adding
    /// all certificates from the trust store.
    pub fn build_root_cert_store_with_base(&self, base_pem: &[u8]) -> Result<RootCertStore> {
        // Build the store from the base CA PEM via the shared helper; then
        // layer in per-peer certs tracked by this trust store.
        let mut store = rustgate_core::pem::parse_ca_store(base_pem)
            .map_err(|e| FederationError::pem("failed to parse base CA PEM", e))?;

        let certs = self
            .certs
            .read()
            .map_err(|e| FederationError::lock("lock poisoned", e))?;

        for (cn, cert) in certs.iter() {
            if let Err(e) = store.add(cert.der.clone()) {
                warn!(cn = %cn, error = %e, "failed to add trust store cert to root store");
            }
        }

        Ok(store)
    }
}

/// Extract certificate metadata from DER-encoded certificate data.
fn extract_cert_info(der: &CertificateDer<'_>) -> Result<CertInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|e| FederationError::X509(e.to_string()))?;

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let issuer = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let not_before = format!("{}", cert.validity().not_before);
    let not_after = format!("{}", cert.validity().not_after);

    // SHA-256 fingerprint of the DER encoding
    let mut hasher = Sha256::new();
    hasher.update(der.as_ref());
    let hash = hasher.finalize();
    let fingerprint = hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    Ok(CertInfo {
        common_name,
        issuer,
        not_before,
        not_after,
        fingerprint,
    })
}

/// Persist a certificate PEM to disk.
fn persist_cert_to_disk(dir: &Path, cn: &str, pem_data: &[u8]) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| {
            FederationError::io(
                format!("failed to create trust store directory {}", dir.display()),
                e,
            )
        })?;
    }
    let filename = sanitize_filename(cn);
    let path = dir.join(format!("{filename}.pem"));
    fs::write(&path, pem_data).map_err(|e| {
        FederationError::io(
            format!("failed to write certificate to {}", path.display()),
            e,
        )
    })?;
    Ok(())
}

/// Sanitize a certificate common name for use as a filename.
///
/// Replaces every character that is not alphanumeric, `-`, `_`, or `.`
/// with a single underscore. This produces a filename that is safe on
/// every common filesystem (POSIX, NTFS, FAT, APFS) without depending
/// on path-quoting at the syscall site.
///
/// This is one of four sanitization helpers in the workspace; see the
/// matrix in [`rustgate_core::sanitize`] for the full set of helpers
/// and the rationale for why their rules differ. Output bytes for any
/// given input are pinned by `sanitize_filename_byte_stable_for_known_inputs`.
///
/// Note that `c.is_alphanumeric()` accepts non-ASCII alphanumerics
/// (e.g. the Cyrillic 'а', U+0430). This is intentional: a CN that
/// legitimately contains non-Latin script should round-trip through
/// the trust-store layout without losing identifying information. The
/// CN itself has already been authenticated by the certificate-issuance
/// path before reaching this helper, so there is no Unicode-equivalence
/// spoofing surface to defend against here.
fn sanitize_filename(cn: &str) -> String {
    cn.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(unused_results, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Generate a self-signed CA certificate for testing.
    fn test_ca_pem() -> Vec<u8> {
        let ca = rustgate_test_utils::certs::TestCa::new("Test CA 1");
        ca.cert_pem.into_bytes()
    }

    /// Generate a second self-signed CA certificate for testing.
    fn test_ca_pem_2() -> Vec<u8> {
        let ca = rustgate_test_utils::certs::TestCa::new("Test CA 2");
        ca.cert_pem.into_bytes()
    }

    #[test]
    fn new_creates_empty_store() {
        let store = TrustStore::new(None);
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.list_certificates().unwrap().is_empty());
    }

    #[test]
    fn debug_output() {
        let store = TrustStore::new(None);
        let debug = format!("{store:?}");
        assert!(debug.contains("TrustStore"));
        assert!(debug.contains("count"));
    }

    #[test]
    fn add_certificate_from_pem() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();

        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        assert!(!info.common_name.is_empty());
        assert!(!info.fingerprint.is_empty());
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn add_certificate_invalid_pem_fails() {
        let store = TrustStore::new(None);
        let result = store.add_certificate_from_pem(b"not valid PEM data");
        assert!(result.is_err());
    }

    #[test]
    fn add_certificate_empty_pem_fails() {
        let store = TrustStore::new(None);
        let result = store.add_certificate_from_pem(b"");
        assert!(result.is_err());
    }

    #[test]
    fn get_certificate_pem_returns_data() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        let retrieved = store
            .get_certificate_pem(&info.common_name)
            .expect("get pem")
            .expect("should be Some");
        assert_eq!(retrieved, pem);
    }

    #[test]
    fn get_certificate_pem_nonexistent_returns_none() {
        let store = TrustStore::new(None);
        assert!(store.get_certificate_pem("nonexistent").unwrap().is_none());
    }

    #[test]
    fn get_certificate_info_returns_metadata() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        let retrieved = store
            .get_certificate_info(&info.common_name)
            .expect("get info")
            .expect("should be Some");
        assert_eq!(retrieved.common_name, info.common_name);
        assert_eq!(retrieved.fingerprint, info.fingerprint);
    }

    #[test]
    fn get_certificate_info_nonexistent_returns_none() {
        let store = TrustStore::new(None);
        assert!(store.get_certificate_info("nonexistent").unwrap().is_none());
    }

    #[test]
    fn remove_certificate() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        assert!(store.remove_certificate(&info.common_name).unwrap());
        assert_eq!(store.count().unwrap(), 0);
        assert!(
            store
                .get_certificate_pem(&info.common_name)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let store = TrustStore::new(None);
        assert!(!store.remove_certificate("nonexistent").unwrap());
    }

    #[test]
    fn list_certificates() {
        let store = TrustStore::new(None);
        let pem1 = test_ca_pem();
        let pem2 = test_ca_pem_2();

        store.add_certificate_from_pem(&pem1).expect("add cert 1");
        store.add_certificate_from_pem(&pem2).expect("add cert 2");

        let list = store.list_certificates().unwrap();
        // Could be 1 or 2 depending on CN uniqueness
        assert!(!list.is_empty());
    }

    #[test]
    fn is_trusted() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        assert!(store.is_trusted(&info.common_name).unwrap());
        assert!(!store.is_trusted("untrusted").unwrap());
    }

    #[test]
    fn is_trusted_after_remove() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        assert!(store.is_trusted(&info.common_name).unwrap());
        store.remove_certificate(&info.common_name).unwrap();
        assert!(!store.is_trusted(&info.common_name).unwrap());
    }

    #[test]
    fn build_root_cert_store() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();
        store.add_certificate_from_pem(&pem).expect("add cert");

        let root_store = store.build_root_cert_store().unwrap();
        assert!(!root_store.is_empty());
    }

    #[test]
    fn build_root_cert_store_empty() {
        let store = TrustStore::new(None);
        let root_store = store.build_root_cert_store().unwrap();
        assert!(root_store.is_empty());
    }

    #[test]
    fn build_root_cert_store_with_base() {
        let store = TrustStore::new(None);
        let base_pem = test_ca_pem();
        let extra_pem = test_ca_pem_2();
        store.add_certificate_from_pem(&extra_pem).expect("add");

        let root_store = store
            .build_root_cert_store_with_base(&base_pem)
            .expect("build");
        assert!(!root_store.is_empty());
    }

    #[test]
    fn build_root_cert_store_with_base_invalid_pem_fails() {
        let store = TrustStore::new(None);
        let result = store.build_root_cert_store_with_base(b"not valid PEM");
        assert!(result.is_err());
    }

    #[test]
    fn load_from_directory_creates_dir_if_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");

        let store = TrustStore::load_from_directory(&trust_dir).expect("load");
        assert_eq!(store.count().unwrap(), 0);
        assert!(trust_dir.exists());
    }

    #[test]
    fn load_from_directory_reads_pem_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");
        fs::create_dir_all(&trust_dir).expect("create dir");

        // Write a test cert
        let pem = test_ca_pem();
        fs::write(trust_dir.join("test-ca.pem"), &pem).expect("write cert");

        let store = TrustStore::load_from_directory(&trust_dir).expect("load");
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn load_from_directory_ignores_non_cert_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");
        fs::create_dir_all(&trust_dir).expect("create dir");

        // Write non-cert files
        fs::write(trust_dir.join("notes.txt"), "not a cert").expect("write");
        fs::write(trust_dir.join("config.json"), "{}").expect("write");

        let store = TrustStore::load_from_directory(&trust_dir).expect("load");
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn load_from_directory_skips_invalid_certs() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");
        fs::create_dir_all(&trust_dir).expect("create dir");

        // Write an invalid PEM file
        fs::write(trust_dir.join("bad.pem"), "invalid pem data").expect("write");

        // Write a valid cert
        let pem = test_ca_pem();
        fs::write(trust_dir.join("good.pem"), &pem).expect("write cert");

        let store = TrustStore::load_from_directory(&trust_dir).expect("load");
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn add_persists_to_disk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");
        fs::create_dir_all(&trust_dir).expect("create dir");

        let store = TrustStore::new(Some(trust_dir.clone()));
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        // Verify file was written
        let filename = sanitize_filename(&info.common_name);
        let path = trust_dir.join(format!("{filename}.pem"));
        assert!(path.exists());
    }

    #[test]
    fn remove_deletes_from_disk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");
        fs::create_dir_all(&trust_dir).expect("create dir");

        let store = TrustStore::new(Some(trust_dir.clone()));
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        let filename = sanitize_filename(&info.common_name);
        let path = trust_dir.join(format!("{filename}.pem"));
        assert!(path.exists());

        store.remove_certificate(&info.common_name).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn disk_persistence_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");

        // Add via store (persists to disk)
        let pem = test_ca_pem();
        {
            let store = TrustStore::load_from_directory(&trust_dir).expect("load");
            store.add_certificate_from_pem(&pem).expect("add");
            assert_eq!(store.count().unwrap(), 1);
        }

        // Load from directory again
        {
            let store = TrustStore::load_from_directory(&trust_dir).expect("load");
            assert_eq!(store.count().unwrap(), 1);
        }
    }

    #[test]
    fn add_replaces_existing_cert_with_same_cn() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();

        let info1 = store.add_certificate_from_pem(&pem).expect("add first");

        // Adding the same PEM again should replace, not duplicate
        let info2 = store.add_certificate_from_pem(&pem).expect("add second");

        assert_eq!(info1.common_name, info2.common_name);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn cert_info_serialization() {
        let info = CertInfo {
            common_name: "Test CA".into(),
            issuer: "Test CA".into(),
            not_before: "2024-01-01".into(),
            not_after: "2025-01-01".into(),
            fingerprint: "aa:bb:cc".into(),
        };

        let json = serde_json::to_string(&info).expect("serialize");
        let parsed: CertInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.common_name, "Test CA");
        assert_eq!(parsed.fingerprint, "aa:bb:cc");
    }

    #[test]
    fn sanitize_filename_replaces_special_chars() {
        assert_eq!(sanitize_filename("my-cert.pem"), "my-cert.pem");
        assert_eq!(sanitize_filename("My CA/Root"), "My_CA_Root");
        assert_eq!(sanitize_filename("cert with spaces"), "cert_with_spaces");
        assert_eq!(sanitize_filename("a@b#c$d"), "a_b_c_d");
    }

    #[test]
    fn sanitize_filename_byte_stable_for_known_inputs() {
        // Pins the exact output bytes for a corpus of inputs spanning
        // every documented behavior class of `sanitize_filename`. The
        // matrix in `rustgate_core::sanitize` claims byte-stable output;
        // a wire-visible change here would rename existing trust-store
        // files on disk and break operator-facing trust layouts.
        let cases: &[(&str, &str)] = &[
            ("plain", "plain"),
            ("my-cert.pem", "my-cert.pem"),
            ("My CA/Root", "My_CA_Root"),
            ("cert with spaces", "cert_with_spaces"),
            ("a@b#c$d", "a_b_c_d"),
            // Path-traversal attempt collapses to underscores.
            ("../etc/passwd", ".._etc_passwd"),
            // Control char becomes underscore (NOT U+FFFD — distinguishes
            // from `sanitize_for_log`).
            ("a\nb", "a_b"),
            ("a\tb", "a_b"),
            // Non-ASCII alphanumeric is preserved (CN with non-Latin
            // script must round-trip).
            ("caf\u{00e9}", "caf\u{00e9}"),
            // Underscore and dot pass through.
            ("_..__", "_..__"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_filename(input),
                *expected,
                "byte-stable output regression for input {input:?}"
            );
        }
    }

    #[test]
    fn matrix_invariant_sanitize_filename_uses_underscore_not_u_fffd() {
        // Pinned axis from the module-doc matrix in `rustgate_core::sanitize`:
        // `sanitize_filename` REPLACES with `_`, NOT with `U+FFFD`. The
        // matrix claim "filename helper uses '_' as the replacement
        // character" is wire-visible — a regression that switched to
        // `U+FFFD` would create non-ASCII filenames (legal on most
        // filesystems, but a behavior change downstream tooling would
        // not expect).
        let out = sanitize_filename("a/b");
        assert!(
            !out.contains('\u{FFFD}'),
            "filename must not contain U+FFFD, got {out:?}"
        );
        assert_eq!(out, "a_b");
    }

    #[test]
    fn fingerprint_format_is_colon_separated_hex() {
        let store = TrustStore::new(None);
        let pem = test_ca_pem();
        let info = store
            .add_certificate_from_pem(&pem)
            .expect("add certificate");

        // Should be colon-separated hex pairs
        assert!(info.fingerprint.contains(':'));
        let parts: Vec<&str> = info.fingerprint.split(':').collect();
        assert_eq!(parts.len(), 32); // SHA-256 = 32 bytes
        for part in parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn load_reads_crt_files_too() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");
        fs::create_dir_all(&trust_dir).expect("create dir");

        let pem = test_ca_pem();
        fs::write(trust_dir.join("test-ca.crt"), &pem).expect("write cert");

        let store = TrustStore::load_from_directory(&trust_dir).expect("load");
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn load_skips_directories() {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = dir.path().join("trust");
        fs::create_dir_all(&trust_dir).expect("create dir");
        fs::create_dir_all(trust_dir.join("subdir.pem")).expect("create subdir");

        let pem = test_ca_pem();
        fs::write(trust_dir.join("valid.pem"), &pem).expect("write cert");

        let store = TrustStore::load_from_directory(&trust_dir).expect("load");
        assert_eq!(store.count().unwrap(), 1);
    }
}
