// Copyright © 2026 Roberto Chiofalo.

//! Certificate revocation and CRL generation.
//!
//! Maintains a persistent list of revoked certificate serial numbers and
//! generates X.509 CRLs signed by the enrollment CA. The revocation store
//! is backed by a JSON file on disk for durability across restarts.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    CertificateRevocationListParams, Issuer, KeyPair, RevocationReason, RevokedCertParams,
    SerialNumber,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::error::EnrollmentError;

/// Global CRL serial number counter to ensure unique CRL identifiers.
static CRL_SERIAL: AtomicU64 = AtomicU64::new(1);

/// Default CRL validity period in days.
const DEFAULT_CRL_VALIDITY_DAYS: u32 = 7;

/// A revoked certificate entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedEntry {
    /// Hex-encoded certificate serial number.
    pub serial: String,
    /// Revocation reason.
    pub reason: String,
    /// Who initiated the revocation.
    pub revoked_by: String,
    /// Unix timestamp when the certificate was revoked.
    pub revoked_at: u64,
}

/// Persistent certificate revocation store with CRL generation.
///
/// Tracks revoked certificate serials in a JSON file and generates
/// X.509 CRLs signed by the enrollment CA on demand.
pub struct RevocationStore {
    /// Path to the JSON revocation database.
    db_path: PathBuf,
    /// In-memory copy of revoked entries, keyed by hex serial.
    entries: RwLock<HashMap<String, RevokedEntry>>,
    /// CA issuer for CRL signing.
    issuer: Issuer<'static, KeyPair>,
    /// CRL validity period in days.
    crl_validity_days: u32,
    /// Cached CRL PEM (regenerated on revocation).
    cached_crl: RwLock<Option<String>>,
}

impl std::fmt::Debug for RevocationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationStore")
            .field("db_path", &self.db_path)
            .field("crl_validity_days", &self.crl_validity_days)
            .finish_non_exhaustive()
    }
}

impl RevocationStore {
    /// Create a new revocation store, loading existing entries from disk.
    ///
    /// The CA certificate and key are used to sign generated CRLs.
    pub async fn new(
        db_path: PathBuf,
        ca_cert_pem: &str,
        ca_key_pem: &str,
    ) -> Result<Self, EnrollmentError> {
        let issuer = build_crl_issuer(ca_cert_pem, ca_key_pem)?;

        let entries = if db_path.exists() {
            let data = tokio::fs::read_to_string(&db_path).await.map_err(|e| {
                EnrollmentError::Config(format!("failed to read revocation db: {e}"))
            })?;
            serde_json::from_str(&data).map_err(|e| {
                EnrollmentError::Config(format!("failed to parse revocation db: {e}"))
            })?
        } else {
            HashMap::new()
        };

        let store = Self {
            db_path,
            entries: RwLock::new(entries),
            issuer,
            crl_validity_days: DEFAULT_CRL_VALIDITY_DAYS,
            cached_crl: RwLock::new(None),
        };

        // Generate initial CRL
        let crl = store.generate_crl_inner().await?;
        *store.cached_crl.write().await = Some(crl);

        Ok(store)
    }

    /// Set the CRL validity period in days.
    pub fn with_crl_validity_days(mut self, days: u32) -> Self {
        self.crl_validity_days = days;
        self
    }

    /// Revoke a certificate by serial number.
    ///
    /// Returns `true` if the certificate was newly revoked, `false` if it was
    /// already in the revocation list.
    pub async fn revoke(
        &self,
        serial: &str,
        reason: &str,
        revoked_by: &str,
    ) -> Result<bool, EnrollmentError> {
        let mut entries = self.entries.write().await;
        if entries.contains_key(serial) {
            return Ok(false);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = RevokedEntry {
            serial: serial.to_string(),
            reason: reason.to_string(),
            revoked_by: revoked_by.to_string(),
            revoked_at: now,
        };

        let _ = entries.insert(serial.to_string(), entry);
        drop(entries);

        self.persist().await?;
        self.regenerate_crl().await?;

        rustgate_core::audit::enrollment_certificate_revoked(serial, reason, revoked_by);
        tracing::info!(serial = %serial, reason = %reason, revoked_by = %revoked_by, "certificate revoked");

        Ok(true)
    }

    /// Check if a certificate serial is revoked.
    pub async fn is_revoked(&self, serial: &str) -> bool {
        let entries = self.entries.read().await;
        entries.contains_key(serial)
    }

    /// List all revoked certificate entries.
    pub async fn list_revoked(&self) -> Vec<RevokedEntry> {
        let entries = self.entries.read().await;
        entries.values().cloned().collect()
    }

    /// Return the number of revoked certificates.
    pub async fn count(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Get the current CRL as PEM-encoded data.
    ///
    /// Returns the cached CRL, regenerating it if the cache is empty.
    pub async fn crl_pem(&self) -> Result<String, EnrollmentError> {
        let cached = self.cached_crl.read().await;
        if let Some(crl) = cached.as_ref() {
            return Ok(crl.clone());
        }
        drop(cached);

        self.regenerate_crl().await?;
        let cached = self.cached_crl.read().await;
        cached
            .clone()
            .ok_or_else(|| EnrollmentError::Config("CRL generation produced no output".to_string()))
    }

    /// Persist the revocation database to disk.
    async fn persist(&self) -> Result<(), EnrollmentError> {
        let entries = self.entries.read().await;
        let data = serde_json::to_string_pretty(&*entries)?;
        drop(entries);

        // Write atomically via temp file + rename
        let tmp_path = self.db_path.with_extension("tmp");
        tokio::fs::write(&tmp_path, data.as_bytes()).await?;
        tokio::fs::rename(&tmp_path, &self.db_path).await?;

        Ok(())
    }

    /// Regenerate the CRL from the current revocation list and update the cache.
    async fn regenerate_crl(&self) -> Result<(), EnrollmentError> {
        let crl = self.generate_crl_inner().await?;
        *self.cached_crl.write().await = Some(crl);
        Ok(())
    }

    /// Generate a CRL PEM from the current revocation entries.
    async fn generate_crl_inner(&self) -> Result<String, EnrollmentError> {
        let entries = self.entries.read().await;

        let mut revoked_certs = Vec::new();
        for entry in entries.values() {
            let serial_bytes = hex_to_bytes(&entry.serial).map_err(|e| {
                EnrollmentError::Config(format!("invalid serial number '{}': {e}", entry.serial))
            })?;

            let reason = parse_revocation_reason(&entry.reason);

            revoked_certs.push(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&serial_bytes),
                revocation_time: OffsetDateTime::from_unix_timestamp(entry.revoked_at as i64)
                    .unwrap_or(OffsetDateTime::now_utc()),
                reason_code: Some(reason),
                invalidity_date: None,
            });
        }
        drop(entries);

        let revoked_certs_count = revoked_certs.len();
        let now = OffsetDateTime::now_utc();
        let next_update = now + time::Duration::days(i64::from(self.crl_validity_days));
        let serial = CRL_SERIAL.fetch_add(1, Ordering::Relaxed);

        let crl_params = CertificateRevocationListParams {
            this_update: now,
            next_update,
            crl_number: SerialNumber::from(serial),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };

        let crl = crl_params
            .signed_by(&self.issuer)
            .map_err(|e| EnrollmentError::Signing(format!("failed to sign CRL: {e}")))?;

        let pem = crl
            .pem()
            .map_err(|e| EnrollmentError::Signing(format!("failed to encode CRL as PEM: {e}")))?;

        tracing::info!(
            revoked_count = revoked_certs_count,
            validity_days = self.crl_validity_days,
            "CRL generated"
        );

        Ok(pem)
    }
}

/// Build a `Issuer` from CA PEM for CRL signing.
fn build_crl_issuer(
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<Issuer<'static, KeyPair>, EnrollmentError> {
    // Shared PEM helpers from `rustgate_core::pem` for consistent
    // error mapping (`ConfigError::PemParse`).
    let mut ca_certs = rustgate_core::pem::parse_certs(ca_cert_pem.as_bytes())
        .map_err(|e| EnrollmentError::Config(format!("failed to parse CA cert PEM: {e}")))?;
    // `parse_certs` guarantees non-empty.
    let ca_cert_der = ca_certs.remove(0);

    let key_der = rustgate_core::pem::parse_key(ca_key_pem.as_bytes())
        .map_err(|e| EnrollmentError::Config(format!("failed to parse CA key PEM: {e}")))?;

    let key_pair = KeyPair::try_from(&key_der)
        .map_err(|e| EnrollmentError::Config(format!("failed to load CA key: {e}")))?;

    Issuer::from_ca_cert_der(&ca_cert_der, key_pair)
        .map_err(|e| EnrollmentError::Config(format!("failed to build CRL issuer: {e}")))
}

/// Parse a revocation reason string into an `rcgen::RevocationReason`.
fn parse_revocation_reason(reason: &str) -> RevocationReason {
    match reason.to_lowercase().as_str() {
        "key_compromise" | "keycompromise" => RevocationReason::KeyCompromise,
        "ca_compromise" | "cacompromise" => RevocationReason::CaCompromise,
        "affiliation_changed" | "affiliationchanged" => RevocationReason::AffiliationChanged,
        "superseded" => RevocationReason::Superseded,
        "cessation_of_operation" | "cessationofoperation" => RevocationReason::CessationOfOperation,
        "privilege_withdrawn" | "privilegewithdrawn" => RevocationReason::PrivilegeWithdrawn,
        _ => RevocationReason::Unspecified,
    }
}

/// Convert a hex string to bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
    // Left-pad odd-length hex with a leading zero. X.509 serial numbers
    // can naturally produce odd-length hex when the leading byte is < 0x10.
    let padded;
    let hex = if !hex.len().is_multiple_of(2) {
        padded = format!("0{hex}");
        &padded
    } else {
        hex
    };
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at offset {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_ca() -> (String, String) {
        let ca = rustgate_test_utils::certs::TestCa::new("Revocation Test CA");
        (ca.cert_pem, ca.key_pem)
    }

    fn issue_test_cert(ca_cert_pem: &str, ca_key_pem: &str) -> String {
        let signer =
            crate::signing::CsrSigner::from_pem(ca_cert_pem, ca_key_pem, "TestOrg").unwrap();

        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "test-client");
        params.distinguished_name = dn;
        let csr = params.serialize_request(&key).unwrap();
        let csr_pem = csr.pem().unwrap();

        let cert_der = signer.sign_csr(&csr_pem, "test-client").unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        format!("{:x}", cert.serial)
    }

    #[tokio::test]
    async fn revoke_and_list() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let store = RevocationStore::new(db_path.clone(), &cert_pem, &key_pem)
            .await
            .unwrap();

        assert_eq!(store.count().await, 0);
        assert!(!store.is_revoked("aabbccdd").await);

        // Revoke a certificate
        let newly_revoked = store
            .revoke("aabbccdd", "key_compromise", "admin")
            .await
            .unwrap();
        assert!(newly_revoked);
        assert_eq!(store.count().await, 1);
        assert!(store.is_revoked("aabbccdd").await);

        // Duplicate revocation returns false
        let duplicate = store
            .revoke("aabbccdd", "key_compromise", "admin")
            .await
            .unwrap();
        assert!(!duplicate);
        assert_eq!(store.count().await, 1);

        // List entries
        let entries = store.list_revoked().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].serial, "aabbccdd");
        assert_eq!(entries[0].reason, "key_compromise");
        assert_eq!(entries[0].revoked_by, "admin");
    }

    #[tokio::test]
    async fn persistence_across_reload() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        // Create store and revoke
        let store = RevocationStore::new(db_path.clone(), &cert_pem, &key_pem)
            .await
            .unwrap();
        let _ = store
            .revoke("112233", "superseded", "operator")
            .await
            .unwrap();
        assert_eq!(store.count().await, 1);
        drop(store);

        // Reload from disk
        let store2 = RevocationStore::new(db_path, &cert_pem, &key_pem)
            .await
            .unwrap();
        assert_eq!(store2.count().await, 1);
        assert!(store2.is_revoked("112233").await);
    }

    #[tokio::test]
    async fn generate_crl_pem() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let store = RevocationStore::new(db_path, &cert_pem, &key_pem)
            .await
            .unwrap();

        // Empty CRL should still be valid PEM
        let crl = store.crl_pem().await.unwrap();
        assert!(crl.contains("-----BEGIN X509 CRL-----"));
        assert!(crl.contains("-----END X509 CRL-----"));

        // Revoke and check CRL is updated
        let _ = store
            .revoke("aabbccdd", "key_compromise", "admin")
            .await
            .unwrap();
        let crl2 = store.crl_pem().await.unwrap();
        assert!(crl2.contains("-----BEGIN X509 CRL-----"));
        // CRL content should differ after revocation
        assert_ne!(crl, crl2);
    }

    #[tokio::test]
    async fn crl_validity_days_configurable() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let store = RevocationStore::new(db_path, &cert_pem, &key_pem)
            .await
            .unwrap()
            .with_crl_validity_days(30);

        assert_eq!(store.crl_validity_days, 30);
        let crl = store.crl_pem().await.unwrap();
        assert!(crl.contains("-----BEGIN X509 CRL-----"));
    }

    #[test]
    fn hex_to_bytes_valid() {
        assert_eq!(hex_to_bytes("aabb").unwrap(), vec![0xaa, 0xbb]);
        assert_eq!(hex_to_bytes("0xaabb").unwrap(), vec![0xaa, 0xbb]);
        assert_eq!(hex_to_bytes("0102ff").unwrap(), vec![0x01, 0x02, 0xff]);
    }

    #[test]
    fn hex_to_bytes_errors() {
        assert!(hex_to_bytes("gggg").is_err()); // invalid hex
    }

    #[test]
    fn hex_to_bytes_odd_length_padded() {
        // Odd-length hex is left-padded with a leading zero (common for X.509 serials)
        assert_eq!(hex_to_bytes("aab").unwrap(), vec![0x0a, 0xab]);
        assert_eq!(hex_to_bytes("1").unwrap(), vec![0x01]);
    }

    #[test]
    fn parse_reason_variants() {
        assert!(matches!(
            parse_revocation_reason("key_compromise"),
            RevocationReason::KeyCompromise
        ));
        assert!(matches!(
            parse_revocation_reason("superseded"),
            RevocationReason::Superseded
        ));
        assert!(matches!(
            parse_revocation_reason("unknown_thing"),
            RevocationReason::Unspecified
        ));
    }

    #[tokio::test]
    async fn revoke_real_cert_and_generate_crl() {
        let (cert_pem, key_pem) = test_ca();
        let serial = issue_test_cert(&cert_pem, &key_pem);

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let store = RevocationStore::new(db_path, &cert_pem, &key_pem)
            .await
            .unwrap();

        let _ = store
            .revoke(&serial, "key_compromise", "admin")
            .await
            .unwrap();

        assert!(store.is_revoked(&serial).await);
        let crl = store.crl_pem().await.unwrap();
        assert!(crl.contains("-----BEGIN X509 CRL-----"));
    }
}
