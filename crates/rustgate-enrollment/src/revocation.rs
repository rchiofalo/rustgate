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

/// Default CRL validity period in days.
const DEFAULT_CRL_VALIDITY_DAYS: u32 = 7;

/// On-disk format version for the revocation database. Bumped when the
/// serialized layout changes in a way that older readers would
/// misinterpret. Current readers accept format `1` and the legacy
/// (pre-#765) flat `HashMap<String, RevokedEntry>` via [`LoadedDb`].
const DB_FORMAT_VERSION: u32 = 1;

/// Serialized shape of the revocation database on disk.
///
/// Wrapping the revoked-entry map in a struct lets us persist the last-
/// issued CRL `crlNumber` alongside the revocation list. Without this,
/// every process restart would hand out CRLs starting at `crlNumber = 1`,
/// and X.509 verifiers enforcing the RFC 5280 §5.2.3 monotonic-`crlNumber`
/// rule would reject the restarted CRL as a replay of a prior one (#765 /
/// F-38). `format_version` is explicit so a future schema change can be
/// rejected cleanly rather than silently misparsed.
///
/// `format_version` deliberately has **no** default on deserialize — its
/// presence is the discriminator that the [`LoadedDb`] untagged enum uses
/// to tell a versioned document from the pre-#765 flat-map layout. Giving
/// it a serde default would let every legacy document (a bare
/// `HashMap<String, RevokedEntry>`) match this variant too, silently
/// dropping the entries into the `#[serde(default)] entries` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDb {
    /// Schema version. Readers that don't know this version refuse to
    /// load. This field being **required** is load-bearing — see the
    /// type-level doc comment above.
    format_version: u32,
    /// The highest `crlNumber` this store has ever issued. The next CRL
    /// uses `last_crl_number + 1`.
    #[serde(default)]
    last_crl_number: u64,
    /// Revoked certificate entries keyed by hex serial.
    #[serde(default)]
    entries: HashMap<String, RevokedEntry>,
}

/// Loader enum that accepts either the current versioned [`StoredDb`] or
/// the pre-#765 legacy flat `HashMap` format so existing deployments
/// upgrade transparently. Serde's `#[serde(untagged)]` attribute tries
/// variants in declaration order; `Versioned` wins only when
/// `format_version` is present in the JSON, otherwise the legacy flat-map
/// variant takes over.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LoadedDb {
    Versioned(StoredDb),
    Legacy(HashMap<String, RevokedEntry>),
}

impl LoadedDb {
    /// Split into `(entries, stored_serial)`. Legacy documents have no
    /// stored serial — callers must apply the wall-clock fallback.
    fn into_parts(self) -> (HashMap<String, RevokedEntry>, Option<u64>) {
        match self {
            Self::Versioned(db) => (db.entries, Some(db.last_crl_number)),
            Self::Legacy(entries) => (entries, None),
        }
    }
}

/// Seed value for the in-memory CRL serial counter when no prior value is
/// persisted (fresh installation, lost state file, or a legacy document
/// from before #765). Using UNIX milliseconds means the next CRL's
/// `crlNumber` exceeds any plausible small-integer serial that an older
/// build would have issued, preserving monotonicity even when persistence
/// has been lost. Falls back to `1` if the clock is broken enough to
/// return an error from `duration_since(UNIX_EPOCH)`.
fn wall_clock_fallback_serial() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(1)
}

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
    /// Last-issued CRL `crlNumber`. Persisted alongside the revoked-entry
    /// map so a process restart does not reset the counter (RFC 5280
    /// §5.2.3 — CRL verifiers enforce monotonic `crlNumber`). Each
    /// [`Self::generate_crl_inner`] call does a `fetch_add(1)` and the
    /// new value is written to disk by the subsequent [`Self::persist`]
    /// call on the hot paths that regenerate the CRL ([`Self::new`] and
    /// [`Self::revoke`]).
    crl_serial: AtomicU64,
}

impl std::fmt::Debug for RevocationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationStore")
            .field("db_path", &self.db_path)
            .field("crl_validity_days", &self.crl_validity_days)
            .field("crl_serial", &self.crl_serial.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RevocationStore {
    /// Create a new revocation store, loading existing entries from disk.
    ///
    /// The CA certificate and key are used to sign generated CRLs.
    ///
    /// Accepts both the current versioned database format and the pre-#765
    /// legacy flat-map format — legacy documents have no stored
    /// `last_crl_number`, so the in-memory counter seeds from the
    /// wall-clock fallback. Missing files get the same fallback,
    /// ensuring a lost state file does not regress the `crlNumber`
    /// back to `1`.
    pub async fn new(
        db_path: PathBuf,
        ca_cert_pem: &str,
        ca_key_pem: &str,
    ) -> Result<Self, EnrollmentError> {
        let issuer = build_crl_issuer(ca_cert_pem, ca_key_pem)?;

        let (entries, stored_serial) = if db_path.exists() {
            let data = tokio::fs::read_to_string(&db_path).await.map_err(|e| {
                EnrollmentError::Config(format!("failed to read revocation db: {e}"))
            })?;
            let loaded: LoadedDb = serde_json::from_str(&data).map_err(|e| {
                EnrollmentError::Config(format!("failed to parse revocation db: {e}"))
            })?;
            loaded.into_parts()
        } else {
            (HashMap::new(), None)
        };

        // Treat a stored `0` the same as "no stored value". A legitimate
        // RevocationStore always issues an initial CRL in [`Self::new`] and
        // persists a non-zero serial, so `last_crl_number = 0` on disk is
        // either a hand-crafted file or a corrupted upgrade from a
        // pre-versioned layout — either way, fall back to the wall-clock
        // seed rather than handing out `crlNumber = 1`.
        let initial_serial = stored_serial
            .filter(|&n| n > 0)
            .unwrap_or_else(wall_clock_fallback_serial);

        let store = Self {
            db_path,
            entries: RwLock::new(entries),
            issuer,
            crl_validity_days: DEFAULT_CRL_VALIDITY_DAYS,
            cached_crl: RwLock::new(None),
            crl_serial: AtomicU64::new(initial_serial),
        };

        // Issue the initial CRL (bumps `crl_serial` by 1) then persist so a
        // crash between this point and the first revocation does not re-use
        // the same `crlNumber` on the next boot (#765).
        let crl = store.generate_crl_inner().await?;
        *store.cached_crl.write().await = Some(crl);
        store.persist().await?;

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

        // Regenerate the CRL (bumps `crl_serial`) before persisting so the
        // updated `last_crl_number` is captured atomically with the new
        // revoked entry. A crash between the two previously could drop the
        // serial bump while keeping the revocation, handing out a CRL with
        // the same `crlNumber` but different contents on next boot (#765).
        self.regenerate_crl().await?;
        self.persist().await?;

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

    /// The last-issued CRL `crlNumber`. Test-only accessor used to pin the
    /// persistence invariant without round-tripping through x509 CRL
    /// parsing.
    #[cfg(test)]
    fn current_crl_serial(&self) -> u64 {
        self.crl_serial.load(Ordering::Relaxed)
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
    ///
    /// Writes the full versioned snapshot — format version, last-issued
    /// `crlNumber`, and the revoked-entry map — so that a restart can
    /// resume the CRL serial counter without replaying small integers that
    /// were already handed out in prior CRLs (#765). The write is atomic
    /// via temp-file + rename so a partial write does not leave a
    /// corrupted database; however, there is no fsync: a hard power cut
    /// between `write` and `rename` may still lose the update. The
    /// [`wall_clock_fallback_serial`] on load is the backstop against
    /// that class of loss.
    async fn persist(&self) -> Result<(), EnrollmentError> {
        let entries = self.entries.read().await;
        let snapshot = StoredDb {
            format_version: DB_FORMAT_VERSION,
            last_crl_number: self.crl_serial.load(Ordering::Relaxed),
            entries: (*entries).clone(),
        };
        drop(entries);
        let data = serde_json::to_string_pretty(&snapshot)?;

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
        // `fetch_add(1)` allocates the next `crlNumber`; the bumped value
        // is the one we return and sign. The subsequent `persist()` call
        // on the hot paths captures it so restarts keep the counter
        // monotonic (#765).
        let serial = self
            .crl_serial
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);

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

    // ---- #765: CRL `crlNumber` persistence across restart -----------------

    /// A brand-new store with no prior database must seed its `crlNumber`
    /// counter from the wall-clock fallback rather than `1`. The exact
    /// value is time-dependent, so the assertion checks that the counter
    /// exceeds a conservative lower bound (a small integer like `1000`)
    /// that no wall-clock-ms reading during a realistic test run would
    /// ever produce.
    #[tokio::test]
    async fn crl_serial_seeds_from_wall_clock_when_db_missing() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");
        assert!(!db_path.exists(), "test precondition: DB starts missing");

        let store = RevocationStore::new(db_path, &cert_pem, &key_pem)
            .await
            .unwrap();

        let serial = store.current_crl_serial();
        assert!(
            serial > 1_000,
            "fresh DB must seed serial from wall-clock millis, got {serial}"
        );
    }

    /// Round-trip invariant: a store that issues a CRL, persists, and is
    /// reconstructed must produce a strictly greater `crlNumber` on the
    /// next CRL. This is the exact failure mode #765 describes — pinning
    /// it prevents a future refactor from silently reintroducing the
    /// reset-to-1 bug.
    #[tokio::test]
    async fn crl_serial_persists_and_grows_across_reload() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let store1 = RevocationStore::new(db_path.clone(), &cert_pem, &key_pem)
            .await
            .unwrap();
        let first_boot_serial = store1.current_crl_serial();
        drop(store1);

        let store2 = RevocationStore::new(db_path.clone(), &cert_pem, &key_pem)
            .await
            .unwrap();
        let second_boot_serial = store2.current_crl_serial();

        assert!(
            second_boot_serial > first_boot_serial,
            "restart must produce a strictly greater crlNumber: \
             first={first_boot_serial} second={second_boot_serial}"
        );
    }

    /// Each revocation regenerates the CRL, which must bump the
    /// `crlNumber`. Two revocations on the same store must yield two
    /// distinct counter values.
    #[tokio::test]
    async fn crl_serial_increments_per_revocation() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let store = RevocationStore::new(db_path, &cert_pem, &key_pem)
            .await
            .unwrap();
        let after_boot = store.current_crl_serial();

        let _ = store
            .revoke("aabbccdd", "superseded", "admin")
            .await
            .unwrap();
        let after_first_revoke = store.current_crl_serial();

        let _ = store
            .revoke("eeff0011", "superseded", "admin")
            .await
            .unwrap();
        let after_second_revoke = store.current_crl_serial();

        assert!(after_first_revoke > after_boot);
        assert!(after_second_revoke > after_first_revoke);
    }

    /// Upgrade path: a pre-#765 database file is just a flat
    /// `HashMap<String, RevokedEntry>`. Loading one must preserve the
    /// entries (so previously revoked certs stay revoked) and must seed
    /// the new `crlNumber` counter from the wall-clock fallback — a
    /// legacy file has no stored counter, so starting from `1` would
    /// re-introduce the replay window this fix closes.
    #[tokio::test]
    async fn crl_serial_accepts_legacy_flat_db_and_applies_fallback() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let mut legacy: HashMap<String, RevokedEntry> = HashMap::new();
        let _ = legacy.insert(
            "deadbeef".to_string(),
            RevokedEntry {
                serial: "deadbeef".to_string(),
                reason: "key_compromise".to_string(),
                revoked_by: "legacy-operator".to_string(),
                revoked_at: 1_700_000_000,
            },
        );
        let legacy_json = serde_json::to_string_pretty(&legacy).unwrap();
        std::fs::write(&db_path, legacy_json).unwrap();

        let store = RevocationStore::new(db_path.clone(), &cert_pem, &key_pem)
            .await
            .unwrap();

        assert!(
            store.is_revoked("deadbeef").await,
            "legacy entries must survive the migration"
        );
        let serial = store.current_crl_serial();
        assert!(
            serial > 1_000,
            "legacy DB (no stored counter) must trigger wall-clock fallback, \
             got {serial}"
        );

        // After the first read-and-persist, the on-disk file must now be
        // in the versioned format so the next boot can resume without
        // another fallback.
        let on_disk = std::fs::read_to_string(&db_path).unwrap();
        assert!(
            on_disk.contains("\"format_version\""),
            "persist must write the versioned layout; saw: {on_disk}"
        );
        assert!(
            on_disk.contains("\"last_crl_number\""),
            "persist must include last_crl_number; saw: {on_disk}"
        );
    }

    /// A hand-crafted file with `last_crl_number = 0` (or a corrupted
    /// upgrade that lost the counter) must trigger the wall-clock
    /// fallback rather than handing out `crlNumber = 1`.
    #[tokio::test]
    async fn crl_serial_zero_is_treated_as_missing() {
        let (cert_pem, key_pem) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");

        let corrupted = StoredDb {
            format_version: DB_FORMAT_VERSION,
            last_crl_number: 0,
            entries: HashMap::new(),
        };
        std::fs::write(&db_path, serde_json::to_string(&corrupted).unwrap()).unwrap();

        let store = RevocationStore::new(db_path, &cert_pem, &key_pem)
            .await
            .unwrap();
        let serial = store.current_crl_serial();
        assert!(
            serial > 1_000,
            "zero-valued stored serial must trigger the wall-clock fallback, \
             got {serial}"
        );
    }
}
