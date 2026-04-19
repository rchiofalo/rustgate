// Copyright © 2026 Roberto Chiofalo.

//! Data package storage and retrieval.
//!
//! Implements the Marti-compatible data package API for TAK client
//! file distribution. Packages are stored on disk as `{sha256}.zip`
//! with a JSON sidecar (`{sha256}.meta.json`) containing metadata.
//!
//! Optional signature verification rejects tampered or unsigned packages
//! when strict mode is enabled. Supported algorithms: ECDSA P-256 SHA-256
//! and RSA-PSS SHA-256.

use std::path::PathBuf;

use rustgate_core::b64;
use sha2::{Digest, Sha256};
use tokio::fs;

use crate::error::EnrollmentError;

/// Metadata for a stored data package.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageMeta {
    pub hash: String,
    pub name: String,
    pub creator_uid: String,
    pub mime_type: String,
    pub size: u64,
    pub upload_time: u64,
    /// Base64-encoded detached signature over the package bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// On-disk data package store.
///
/// Packages are content-addressed by their SHA-256 hash:
/// - `{base_dir}/{sha256}.zip` — the raw file
/// - `{base_dir}/{sha256}.meta.json` — JSON metadata sidecar
///
/// When `signing_ca` is configured, uploaded packages may carry a detached
/// signature that is verified against the CA's public key. When
/// `strict_signatures` is also enabled, unsigned packages are rejected.
#[derive(Debug, Clone)]
pub struct DataPackageStore {
    base_dir: PathBuf,
    /// When true, uploads without a valid signature are rejected.
    strict_signatures: bool,
    /// DER-encoded CA public key bytes for signature verification.
    signing_ca: Option<SigningCa>,
}

/// Cached CA public key material for package signature verification.
#[derive(Clone)]
pub(crate) struct SigningCa {
    /// Raw Subject Public Key Info (SPKI) bytes from the CA certificate.
    spki_bytes: Vec<u8>,
}

impl std::fmt::Debug for SigningCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningCa")
            .field("spki_len", &self.spki_bytes.len())
            .finish()
    }
}

/// Maximum upload size (50 MiB). Prevents disk exhaustion from oversized uploads.
const MAX_UPLOAD_SIZE: usize = 50 * 1024 * 1024;

impl DataPackageStore {
    /// Create a new store rooted at `base_dir`. Creates the directory if it doesn't exist.
    pub async fn new(base_dir: PathBuf) -> Result<Self, EnrollmentError> {
        fs::create_dir_all(&base_dir).await?;
        Ok(Self {
            base_dir,
            strict_signatures: false,
            signing_ca: None,
        })
    }

    /// Enable strict signature enforcement: unsigned uploads are rejected.
    #[must_use]
    pub fn with_strict_signatures(mut self, strict: bool) -> Self {
        self.strict_signatures = strict;
        self
    }

    /// Set the CA certificate (DER-encoded) used to verify package signatures.
    ///
    /// Extracts the Subject Public Key Info from the certificate for later
    /// verification against ECDSA P-256 or RSA-PSS signatures.
    pub fn with_signing_ca(mut self, ca_der: &[u8]) -> Result<Self, EnrollmentError> {
        let spki_bytes = extract_spki_from_der(ca_der)?;
        self.signing_ca = Some(SigningCa { spki_bytes });
        tracing::info!("package signature verification CA configured");
        Ok(self)
    }

    /// Returns whether strict signature mode is active.
    pub fn strict_signatures(&self) -> bool {
        self.strict_signatures
    }

    /// Store a data package, optionally with a detached signature.
    ///
    /// When `signature_b64` is provided, the signature is verified against the
    /// CA public key before the package is stored. In strict mode, uploads
    /// without a signature are rejected.
    pub async fn upload(
        &self,
        data: &[u8],
        name: &str,
        creator_uid: &str,
    ) -> Result<PackageMeta, EnrollmentError> {
        self.upload_with_signature(data, name, creator_uid, None)
            .await
    }

    /// Store a data package with an optional base64-encoded detached signature.
    pub async fn upload_with_signature(
        &self,
        data: &[u8],
        name: &str,
        creator_uid: &str,
        signature_b64: Option<&str>,
    ) -> Result<PackageMeta, EnrollmentError> {
        if data.is_empty() {
            return Err(EnrollmentError::Config("empty upload".to_string()));
        }
        if data.len() > MAX_UPLOAD_SIZE {
            return Err(EnrollmentError::Config(format!(
                "upload exceeds {MAX_UPLOAD_SIZE} byte limit"
            )));
        }

        // Verify signature if provided, enforce strict mode
        let verified_sig = match (signature_b64, &self.signing_ca, self.strict_signatures) {
            // Signature provided and CA configured — verify it
            (Some(sig_b64), Some(ca), _) => {
                let sig_bytes = b64::decode(sig_b64).map_err(|e| {
                    EnrollmentError::Config(format!("invalid base64 signature: {e}"))
                })?;

                verify_signature(&ca.spki_bytes, data, &sig_bytes)?;
                tracing::debug!(name = %name, "package signature verified");
                Some(sig_b64.to_string())
            }
            // Signature provided but no CA configured — store but skip verification
            (Some(sig_b64), None, _) => {
                tracing::debug!(name = %name, "signature provided but no CA configured, storing unverified");
                Some(sig_b64.to_string())
            }
            // No signature, strict mode — reject
            (None, _, true) => {
                return Err(EnrollmentError::Config(
                    "signature required (strict mode enabled)".to_string(),
                ));
            }
            // No signature, non-strict — allow
            (None, _, false) => None,
        };

        let hash = hex_sha256(data);
        let pkg_path = self.package_path(&hash);
        let meta_path = self.meta_path(&hash);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let meta = PackageMeta {
            hash: hash.clone(),
            name: name.to_string(),
            creator_uid: creator_uid.to_string(),
            mime_type: "application/x-zip-compressed".to_string(),
            size: data.len() as u64,
            upload_time: now,
            signature: verified_sig,
        };

        fs::write(&pkg_path, data).await?;

        let meta_json = serde_json::to_vec(&meta)?;
        fs::write(&meta_path, &meta_json).await?;

        tracing::info!(
            hash = %hash,
            name = %name,
            size = data.len(),
            signed = meta.signature.is_some(),
            "data package stored"
        );

        Ok(meta)
    }

    /// Read a data package by its SHA-256 hash. Returns `(metadata, bytes)`.
    ///
    /// When a signing CA is configured and the package has a stored signature,
    /// the signature is re-verified against the on-disk data to detect
    /// post-upload tampering. Verification failure returns an error and the
    /// package is not served.
    pub async fn download(&self, hash: &str) -> Result<(PackageMeta, Vec<u8>), EnrollmentError> {
        if !is_valid_hex_hash(hash) {
            return Err(EnrollmentError::Config("invalid hash format".to_string()));
        }

        let meta = self.read_meta(hash).await?;
        let data = fs::read(self.package_path(hash)).await?;

        // Re-verify signature at download time to detect on-disk tampering
        if let (Some(sig_b64), Some(ca)) = (&meta.signature, &self.signing_ca) {
            let sig_bytes = b64::decode(sig_b64).map_err(|e| {
                EnrollmentError::Config(format!("stored signature is invalid base64: {e}"))
            })?;
            verify_signature(&ca.spki_bytes, &data, &sig_bytes).map_err(|_| {
                tracing::error!(hash = %hash, "download-time signature verification failed — possible tampering");
                EnrollmentError::Config(
                    "package signature verification failed at download time".to_string(),
                )
            })?;
        }

        Ok((meta, data))
    }

    /// Search packages by keyword (matches against name and creator_uid).
    pub async fn search(&self, keyword: &str) -> Result<Vec<PackageMeta>, EnrollmentError> {
        let keyword_lower = keyword.to_lowercase();
        let mut results = Vec::new();

        let mut entries = fs::read_dir(&self.base_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // Sidecar files are named {hash}.meta.json
            let Some(hash) = stem.strip_suffix(".meta") else {
                continue;
            };

            if let Ok(meta) = self.read_meta(hash).await
                && (meta.name.to_lowercase().contains(&keyword_lower)
                    || meta
                        .creator_uid
                        .to_ascii_lowercase()
                        .contains(&keyword_lower))
            {
                results.push(meta);
            }
        }

        Ok(results)
    }

    async fn read_meta(&self, hash: &str) -> Result<PackageMeta, EnrollmentError> {
        let data = fs::read(self.meta_path(hash)).await?;
        Ok(serde_json::from_slice(&data)?)
    }

    fn package_path(&self, hash: &str) -> PathBuf {
        self.base_dir.join(format!("{hash}.zip"))
    }

    fn meta_path(&self, hash: &str) -> PathBuf {
        self.base_dir.join(format!("{hash}.meta.json"))
    }
}

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Validate that a hash string is a 64-character hex string (SHA-256).
fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Extract the Subject Public Key Info (SPKI) DER bytes from a DER-encoded
/// X.509 certificate.
///
/// Uses a minimal ASN.1 parser: walks the outermost SEQUENCE, skips the
/// TBSCertificate header fields (version, serial, algorithm, issuer,
/// validity), and returns the subjectPublicKeyInfo SEQUENCE.
fn extract_spki_from_der(cert_der: &[u8]) -> Result<Vec<u8>, EnrollmentError> {
    // Parse the certificate using x509-parser (already a dev-dep, but
    // we only need it at setup time, and it's lightweight).
    // Fallback: do a minimal ASN.1 walk.
    //
    // We use ring's built-in X.509 helpers indirectly: ring expects raw
    // SPKI bytes. For simplicity, parse with the `x509-parser` crate
    // which is already available.
    //
    // However x509-parser is only a dev-dependency. Instead we'll use
    // a minimal ASN.1 extraction that is sufficient for our needs.
    parse_spki_from_x509_der(cert_der)
}

/// Minimal ASN.1 DER parser to extract SPKI from an X.509 certificate.
///
/// X.509 structure (simplified):
/// ```text
/// SEQUENCE {                       -- Certificate
///   SEQUENCE {                     -- TBSCertificate
///     [0] EXPLICIT version         -- optional
///     INTEGER serial
///     SEQUENCE algorithm
///     SEQUENCE issuer
///     SEQUENCE validity
///     SEQUENCE subject
///     SEQUENCE subjectPublicKeyInfo  <-- we want this
///     ...
///   }
///   ...
/// }
/// ```
fn parse_spki_from_x509_der(cert_der: &[u8]) -> Result<Vec<u8>, EnrollmentError> {
    let err = || EnrollmentError::Config("failed to parse SPKI from certificate DER".to_string());

    let mut pos = 0;

    // Outer SEQUENCE (Certificate)
    let (_, cert_end) = read_sequence_header(cert_der, &mut pos).map_err(|_| err())?;

    // TBSCertificate SEQUENCE
    let (tbs_start, tbs_end) = read_sequence_header(cert_der, &mut pos).map_err(|_| err())?;
    let _ = (tbs_start, tbs_end, cert_end); // use tbs context

    // version [0] EXPLICIT — optional, context-tagged
    if pos < cert_der.len() && (cert_der[pos] & 0xe0) == 0xa0 {
        // Skip the explicit tag + length + value
        skip_tlv(cert_der, &mut pos).map_err(|_| err())?;
    }

    // serialNumber INTEGER
    skip_tlv(cert_der, &mut pos).map_err(|_| err())?;

    // signature AlgorithmIdentifier SEQUENCE
    skip_tlv(cert_der, &mut pos).map_err(|_| err())?;

    // issuer Name SEQUENCE
    skip_tlv(cert_der, &mut pos).map_err(|_| err())?;

    // validity SEQUENCE
    skip_tlv(cert_der, &mut pos).map_err(|_| err())?;

    // subject Name SEQUENCE
    skip_tlv(cert_der, &mut pos).map_err(|_| err())?;

    // subjectPublicKeyInfo SEQUENCE — capture this entire TLV
    let spki_start = pos;
    skip_tlv(cert_der, &mut pos).map_err(|_| err())?;

    cert_der
        .get(spki_start..pos)
        .map(|s| s.to_vec())
        .ok_or_else(err)
}

/// Read a SEQUENCE tag and return (content_start, content_end).
fn read_sequence_header(data: &[u8], pos: &mut usize) -> Result<(usize, usize), ()> {
    if *pos >= data.len() || data[*pos] != 0x30 {
        return Err(());
    }
    *pos += 1;
    let (len, content_start) = read_der_length(data, *pos)?;
    *pos = content_start;
    Ok((content_start, content_start + len))
}

/// Skip one complete TLV (tag + length + value).
fn skip_tlv(data: &[u8], pos: &mut usize) -> Result<(), ()> {
    if *pos >= data.len() {
        return Err(());
    }
    *pos += 1; // tag
    let (len, content_start) = read_der_length(data, *pos)?;
    *pos = content_start + len;
    if *pos > data.len() {
        return Err(());
    }
    Ok(())
}

/// Read a DER length field. Returns (length_value, offset_after_length).
///
/// Uses checked arithmetic to prevent integer overflow on malformed input.
fn read_der_length(data: &[u8], pos: usize) -> Result<(usize, usize), ()> {
    if pos >= data.len() {
        return Err(());
    }
    let first = data[pos];
    if first < 0x80 {
        return Ok((first as usize, pos + 1));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        return Err(());
    }
    let after_length = pos.checked_add(1 + num_bytes).ok_or(())?;
    if after_length > data.len() {
        return Err(());
    }
    let mut len: usize = 0;
    for i in 0..num_bytes {
        len = len.checked_shl(8).ok_or(())? | (data[pos + 1 + i] as usize);
    }
    Ok((len, after_length))
}

/// Verify a detached signature over `data` using the SPKI from the signing CA.
///
/// Tries ECDSA P-256 SHA-256 first, then falls back to RSA-PSS SHA-256.
fn verify_signature(
    spki_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), EnrollmentError> {
    use ring::signature;

    // Try ECDSA P-256 SHA-256 first
    let ecdsa_result =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, spki_bytes)
            .verify(data, signature);

    if ecdsa_result.is_ok() {
        return Ok(());
    }

    // Try RSA-PSS SHA-256
    let rsa_result =
        signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, spki_bytes)
            .verify(data, signature);

    if rsa_result.is_ok() {
        return Ok(());
    }

    Err(EnrollmentError::Config(
        "signature verification failed: no supported algorithm matched".to_string(),
    ))
}

/// Extract a multipart boundary from the Content-Type header.
pub fn extract_boundary(content_type: &str) -> Option<&str> {
    content_type.split(';').find_map(|part| {
        let trimmed = part.trim();
        trimmed
            .strip_prefix("boundary=")
            .map(|b| b.trim_matches('"'))
    })
}

/// Extract a named field value from a simple multipart body.
///
/// This is a minimal parser that handles the TAK client's multipart upload
/// format. It finds the part with the given field name and returns its value.
pub fn extract_multipart_field<'a>(
    body: &'a [u8],
    boundary: &str,
    field: &str,
) -> Option<&'a [u8]> {
    let boundary_marker = format!("--{boundary}");
    let body_str = std::str::from_utf8(body).ok()?;

    let disposition_needle = format!("name=\"{field}\"");

    // Track the byte offset of each part within body_str as we iterate.
    let mut search_start = 0;
    for part in body_str.split(&boundary_marker) {
        // Find where this part actually starts within body_str.
        let part_offset = body_str[search_start..]
            .find(part)
            .map(|i| i + search_start)?;
        search_start = part_offset + part.len();

        if !part.contains(&disposition_needle) {
            continue;
        }
        // Content starts after the first blank line (\r\n\r\n)
        let content_start = part.find("\r\n\r\n").map(|i| i + 4)?;
        let content = part.get(content_start..)?;
        // Trim trailing \r\n before the next boundary
        let content = content.trim_end_matches("\r\n--").trim_end_matches("\r\n");
        let offset = part_offset + content_start;
        return body.get(offset..offset + content.len());
    }
    None
}

/// Extract the filename from a multipart part's Content-Disposition header.
pub fn extract_multipart_filename(body: &[u8], boundary: &str) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    let boundary_marker = format!("--{boundary}");

    for part in body_str.split(&boundary_marker) {
        if let Some(pos) = part.find("filename=\"") {
            let start = pos + "filename=\"".len();
            let rest = part.get(start..)?;
            let end = rest.find('"')?;
            return Some(rest.get(..end)?.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    /// Generate an ECDSA P-256 key pair, return (SPKI DER bytes, key pair) for testing.
    fn test_ecdsa_keypair() -> (Vec<u8>, ring::signature::EcdsaKeyPair) {
        use ring::signature::{self, EcdsaKeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("keygen");
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("parse pkcs8");
        let spki = key_pair.public_key().as_ref().to_vec();
        (spki, key_pair)
    }

    /// Sign data with the test key pair and return base64.
    fn sign_data(key_pair: &ring::signature::EcdsaKeyPair, data: &[u8]) -> String {
        let rng = ring::rand::SystemRandom::new();
        let sig = key_pair.sign(&rng, data).expect("sign");
        b64::encode(sig.as_ref())
    }

    #[test]
    fn test_hex_sha256() {
        let hash = hex_sha256(b"hello");
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        // Known SHA-256 of "hello"
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_valid_hex_hash() {
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(is_valid_hex_hash(good));
        assert!(!is_valid_hex_hash("tooshort"));
        assert!(!is_valid_hex_hash(
            "zzzz4dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        ));
        assert!(!is_valid_hex_hash(""));
    }

    #[test]
    fn test_extract_boundary() {
        assert_eq!(
            extract_boundary("multipart/form-data; boundary=----WebKitFormBoundary123"),
            Some("----WebKitFormBoundary123")
        );
        assert_eq!(
            extract_boundary("multipart/form-data; boundary=\"abc\""),
            Some("abc")
        );
        assert_eq!(extract_boundary("application/json"), None);
    }

    #[tokio::test]
    async fn test_upload_and_download() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let data = b"PK\x03\x04fake zip content";
        let meta = store
            .upload(data, "test.zip", "user-1")
            .await
            .expect("test");

        assert_eq!(meta.name, "test.zip");
        assert_eq!(meta.creator_uid, "user-1");
        assert_eq!(meta.size, data.len() as u64);
        assert_eq!(meta.hash.len(), 64);

        let (dl_meta, dl_data) = store.download(&meta.hash).await.expect("test");
        assert_eq!(dl_data, data);
        assert_eq!(dl_meta.name, "test.zip");
    }

    #[tokio::test]
    async fn test_upload_empty_rejected() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let result = store.upload(b"", "empty.zip", "user-1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_download_invalid_hash() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let result = store.download("not-a-hash").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_download_missing() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let result = store.download(hash).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_search() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let _ = store
            .upload(b"pkg1-data", "mission-alpha.zip", "team-lead")
            .await
            .expect("test");
        let _ = store
            .upload(b"pkg2-data", "mission-bravo.zip", "operator")
            .await
            .expect("test");
        let _ = store
            .upload(b"pkg3-data", "overlay.kml", "team-lead")
            .await
            .expect("test");

        let results = store.search("mission").await.expect("test");
        assert_eq!(results.len(), 2);

        let results = store.search("team-lead").await.expect("test");
        assert_eq!(results.len(), 2);

        let results = store.search("overlay").await.expect("test");
        assert_eq!(results.len(), 1);

        let results = store.search("nonexistent").await.expect("test");
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_multipart_filename() {
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"assetfile\"; filename=\"test.zip\"\r\nContent-Type: application/zip\r\n\r\ndata\r\n--boundary--";
        assert_eq!(
            extract_multipart_filename(body, "boundary"),
            Some("test.zip".to_string())
        );
    }

    #[test]
    fn test_extract_multipart_field_basic() {
        let body =
            b"--boundary\r\nContent-Disposition: form-data; name=\"callsign\"\r\n\r\nALPHA-1\r\n--boundary--";
        let result = extract_multipart_field(body, "boundary", "callsign");
        assert_eq!(result, Some(b"ALPHA-1".as_slice()));
    }

    #[test]
    fn test_extract_multipart_field_empty_body() {
        let result = extract_multipart_field(b"", "boundary", "callsign");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_multipart_field_missing_field() {
        let body =
            b"--boundary\r\nContent-Disposition: form-data; name=\"callsign\"\r\n\r\nALPHA-1\r\n--boundary--";
        let result = extract_multipart_field(body, "boundary", "uid");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_multipart_field_no_content_delimiter() {
        // Part header with no \r\n\r\n separator before content
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"callsign\"\r\nALPHA-1\r\n--boundary--";
        let result = extract_multipart_field(body, "boundary", "callsign");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_multipart_field_multiple_fields() {
        let body = b"--boundary\r\n\
            Content-Disposition: form-data; name=\"callsign\"\r\n\r\n\
            ALPHA-1\r\n\
            --boundary\r\n\
            Content-Disposition: form-data; name=\"uid\"\r\n\r\n\
            device-abc-123\r\n\
            --boundary\r\n\
            Content-Disposition: form-data; name=\"group\"\r\n\r\n\
            Team Red\r\n\
            --boundary--";

        let callsign = extract_multipart_field(body, "boundary", "callsign");
        assert_eq!(callsign, Some(b"ALPHA-1".as_slice()));

        let uid = extract_multipart_field(body, "boundary", "uid");
        assert_eq!(uid, Some(b"device-abc-123".as_slice()));

        let group = extract_multipart_field(body, "boundary", "group");
        assert_eq!(group, Some(b"Team Red".as_slice()));
    }

    #[test]
    fn test_extract_multipart_filename_missing_quote() {
        // filename value has opening quote but no closing quote
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"assetfile\"; filename=\"test.zip\r\nContent-Type: application/zip\r\n\r\ndata\r\n--boundary--";
        assert_eq!(extract_multipart_filename(body, "boundary"), None);
    }

    #[test]
    fn test_extract_multipart_filename_no_filename() {
        // Content-Disposition has name but no filename= attribute
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"callsign\"\r\n\r\nALPHA-1\r\n--boundary--";
        assert_eq!(extract_multipart_filename(body, "boundary"), None);
    }

    // ── Signature verification tests ──────────────────────────────────

    #[tokio::test]
    async fn test_upload_with_valid_signature() {
        let (spki, key_pair) = test_ecdsa_keypair();
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");
        // Manually set the signing CA with raw SPKI bytes (no X.509 wrapper in tests)
        let store = DataPackageStore {
            signing_ca: Some(SigningCa { spki_bytes: spki }),
            ..store
        };

        let data = b"PK\x03\x04signed package content";
        let sig_b64 = sign_data(&key_pair, data);

        let meta = store
            .upload_with_signature(data, "signed.zip", "user-1", Some(&sig_b64))
            .await
            .expect("upload should succeed with valid signature");

        assert_eq!(meta.signature.as_deref(), Some(sig_b64.as_str()));
    }

    #[tokio::test]
    async fn test_upload_without_signature_nonstrict() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let data = b"PK\x03\x04unsigned package";
        let meta = store
            .upload_with_signature(data, "unsigned.zip", "user-1", None)
            .await
            .expect("upload should succeed without signature in non-strict mode");

        assert!(meta.signature.is_none());
    }

    #[tokio::test]
    async fn test_upload_without_signature_strict_rejected() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test")
            .with_strict_signatures(true);

        let data = b"PK\x03\x04unsigned strict package";
        let result = store
            .upload_with_signature(data, "unsigned.zip", "user-1", None)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("signature required"),
            "expected signature required error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_upload_invalid_signature_rejected() {
        let (spki, _key_pair) = test_ecdsa_keypair();
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");
        let store = DataPackageStore {
            signing_ca: Some(SigningCa { spki_bytes: spki }),
            ..store
        };

        let data = b"PK\x03\x04some content";
        // Use a bogus signature
        let bad_sig = b64::encode(b"not-a-real-signature");

        let result = store
            .upload_with_signature(data, "bad.zip", "user-1", Some(&bad_sig))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("verification failed"),
            "expected verification failed error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_backward_compat_old_metadata_loads() {
        // Simulate an old metadata file without the signature field
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let data = b"PK\x03\x04legacy content";
        // Upload normally (no signature)
        let meta = store
            .upload(data, "legacy.zip", "user-old")
            .await
            .expect("test");

        // Manually rewrite the meta file without the signature field
        let old_json = serde_json::json!({
            "hash": meta.hash,
            "name": "legacy.zip",
            "creator_uid": "user-old",
            "mime_type": "application/x-zip-compressed",
            "size": data.len(),
            "upload_time": meta.upload_time
        });
        let meta_path = dir.path().join(format!("{}.meta.json", meta.hash));
        tokio::fs::write(&meta_path, old_json.to_string().as_bytes())
            .await
            .expect("test");

        // Download should succeed and signature should be None
        let (dl_meta, _dl_data) = store.download(&meta.hash).await.expect("test");
        assert!(dl_meta.signature.is_none());
        assert_eq!(dl_meta.name, "legacy.zip");
    }

    #[tokio::test]
    async fn test_download_returns_signature_in_meta() {
        let (spki, key_pair) = test_ecdsa_keypair();
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");
        let store = DataPackageStore {
            signing_ca: Some(SigningCa { spki_bytes: spki }),
            ..store
        };

        let data = b"PK\x03\x04signed download test";
        let sig_b64 = sign_data(&key_pair, data);

        let meta = store
            .upload_with_signature(data, "dl-signed.zip", "user-1", Some(&sig_b64))
            .await
            .expect("test");

        let (dl_meta, _dl_data) = store.download(&meta.hash).await.expect("test");
        assert_eq!(dl_meta.signature.as_deref(), Some(sig_b64.as_str()));
    }

    #[test]
    fn test_verify_signature_ecdsa() {
        let (spki, key_pair) = test_ecdsa_keypair();
        let data = b"test message for verification";
        let rng = ring::rand::SystemRandom::new();
        let sig = key_pair.sign(&rng, data).expect("sign");

        // Should succeed
        verify_signature(&spki, data, sig.as_ref()).expect("verification should succeed");

        // Tampered data should fail
        let result = verify_signature(&spki, b"tampered data", sig.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_upload_nonstrict_default() {
        let store_future =
            DataPackageStore::new(tempfile::tempdir().expect("test").path().to_path_buf());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test");
        let store = rt.block_on(store_future).expect("test");
        assert!(!store.strict_signatures());
    }

    #[test]
    fn test_extract_spki_from_real_x509() {
        // Generate a real X.509 certificate using TestCa
        use rustls_pki_types::pem::PemObject;
        let ca = rustgate_test_utils::certs::TestCa::new("test-spki-ca");
        let ca_cert_der = rustls_pki_types::CertificateDer::from_pem_slice(ca.cert_pem.as_bytes())
            .expect("parse CA PEM");

        // extract_spki_from_der should succeed on a real certificate
        let spki = extract_spki_from_der(&ca_cert_der)
            .expect("SPKI extraction should succeed on a real X.509 certificate");

        // SPKI should be non-empty and start with a SEQUENCE tag (0x30)
        assert!(!spki.is_empty(), "SPKI bytes should not be empty");
        assert_eq!(spki[0], 0x30, "SPKI should start with SEQUENCE tag (0x30)");
    }

    #[test]
    fn test_read_der_length_overflow() {
        // Craft a length field that would overflow: 0x84 means 4 bytes follow,
        // with values that overflow usize on 32-bit or trigger checked_shl
        let data = [0x30, 0x84, 0xff, 0xff, 0xff, 0xff];
        let result = read_der_length(&data, 1);
        // On 64-bit this parses to a huge length that will fail bounds checks
        // downstream, but the arithmetic itself should not panic
        if let Ok((len, _)) = result {
            // The length 0xffffffff = 4294967295 should be valid arithmetic
            // but would fail bounds checks when used
            assert!(len > 0);
        }
        // On 32-bit this would be Err due to checked_shl overflow — both are fine
    }

    #[tokio::test]
    async fn test_download_reverifies_signature() {
        let (spki, key_pair) = test_ecdsa_keypair();
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");
        let store = DataPackageStore {
            signing_ca: Some(SigningCa {
                spki_bytes: spki.clone(),
            }),
            ..store
        };

        let data = b"PK\x03\x04signed content for reverify";
        let sig_b64 = sign_data(&key_pair, data);

        let meta = store
            .upload_with_signature(data, "reverify.zip", "user-1", Some(&sig_b64))
            .await
            .expect("upload should succeed");

        // Normal download should succeed
        let (_, dl_data) = store
            .download(&meta.hash)
            .await
            .expect("download should succeed");
        assert_eq!(dl_data, data);

        // Tamper with the on-disk file
        let pkg_path = dir.path().join(format!("{}.zip", meta.hash));
        tokio::fs::write(&pkg_path, b"TAMPERED CONTENT")
            .await
            .expect("write tampered file");

        // Download should now fail due to signature mismatch
        let result = store.download(&meta.hash).await;
        assert!(result.is_err(), "download of tampered package should fail");
    }
}
