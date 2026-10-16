// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Filesystem-backed data-package store.
//!
//! Each package lives on disk as two files:
//!
//! ```text
//! {base_dir}/{hash}.zip          — raw ZIP body
//! {base_dir}/{hash}.meta.json    — sidecar metadata + HMAC-SHA256 tag
//! ```
//!
//! `{hash}` is the hex-encoded SHA-256 of the ZIP body, so identical
//! uploads collapse to a single on-disk entry. The sidecar is a
//! signed JSON envelope: `{ meta, tag }` where `tag` is an
//! HMAC-SHA256 over the canonical metadata blob (`hash || size ||
//! name || creator_uid || upload_time`) under the store's integrity
//! key. Tags are verified on every download using
//! [`rustgate_core::crypto::hmac_sha256_verify`], so an attacker who
//! tampers with the sidecar JSON cannot redirect a download by
//! rewriting the package name without also producing a valid HMAC.
//!
//! # Concurrency model
//!
//! The store is `Send + Sync` and may be cloned cheaply. All
//! mutating operations (`upload`, `delete`) take an internal write
//! lock that serialises capacity arithmetic; reads (`download`,
//! `list`, `metadata`) run lock-free against the disk.
//!
//! The capacity counter is rebuilt on construction by walking the
//! base directory; uploads that race against a delete may briefly
//! observe a stale total, but the subsequent capacity check uses
//! the post-add total against the configured cap, so a soak test
//! cannot drive the store past `max_total_bytes`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::sync::Mutex;

use crate::error::{MissionsError, Result};
use crate::{DEFAULT_MAX_PACKAGE_BYTES, DEFAULT_MAX_TOTAL_BYTES, ZIP_MIME_TYPE};

/// Tunable size caps for a [`PackageStore`].
#[derive(Debug, Clone)]
pub struct StoreLimits {
    /// Maximum sum of every package body in bytes. Uploads that
    /// would push the running total past this number are rejected
    /// with [`MissionsError::CapacityExceeded`]. Default:
    /// [`crate::DEFAULT_MAX_TOTAL_BYTES`] (1 GiB).
    pub max_total_bytes: u64,
    /// Maximum size of a single uploaded package body. Default:
    /// [`crate::DEFAULT_MAX_PACKAGE_BYTES`] (50 MiB).
    pub max_package_bytes: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_package_bytes: DEFAULT_MAX_PACKAGE_BYTES,
        }
    }
}

impl StoreLimits {
    /// Override [`StoreLimits::max_total_bytes`] with a builder-style
    /// setter so test code and CLI parsers can tune one cap without
    /// re-stating both.
    #[must_use]
    pub fn with_max_total_bytes(mut self, bytes: u64) -> Self {
        self.max_total_bytes = bytes;
        self
    }

    /// Override [`StoreLimits::max_package_bytes`].
    #[must_use]
    pub fn with_max_package_bytes(mut self, bytes: u64) -> Self {
        self.max_package_bytes = bytes;
        self
    }
}

/// Metadata sidecar for a stored package.
///
/// The fields are persisted to `{hash}.meta.json` and returned by
/// the listing/download APIs. The HMAC tag is held alongside in the
/// sidecar wrapper but is not exposed in the public API — it is an
/// integrity-check artefact, not user-visible content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PackageMeta {
    /// Lowercase hex SHA-256 of the package body.
    pub hash: String,
    /// Operator-supplied display name (filename of the multipart
    /// upload, or the manifest `<Configuration name=…>` value).
    pub name: String,
    /// Identity that uploaded the package. Populated from the
    /// authenticated subject of the upload request — the HTTP layer
    /// in `rustgate-admin` derives this from the bearer-token
    /// principal.
    pub creator_uid: String,
    /// IANA media type for the body. Always
    /// [`crate::ZIP_MIME_TYPE`] in this MVP; the field is preserved
    /// for forward-compat with mission packages that wrap KMZ
    /// directly.
    pub mime_type: String,
    /// Body size in bytes.
    pub size: u64,
    /// Upload timestamp as POSIX seconds since the Unix epoch.
    pub upload_time: u64,
}

/// On-disk envelope wrapping [`PackageMeta`] with an HMAC tag.
///
/// Persisted to `{hash}.meta.json`. The tag covers the canonical
/// byte sequence `hash || size || name || creator_uid || upload_time`
/// (see [`canonical_tag_input`]). On download we recompute the tag
/// over the freshly-read [`PackageMeta`] and compare in constant
/// time before serving the body.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SidecarEnvelope {
    /// Inner metadata.
    meta: PackageMeta,
    /// Lowercase hex HMAC-SHA256 over the canonical metadata blob.
    tag: String,
}

/// Filesystem-backed package store.
///
/// Cheap to clone — the inner state is `Arc<…>` so cloning duplicates
/// only the handle, not the underlying state.
#[derive(Debug, Clone)]
pub struct PackageStore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    base_dir: PathBuf,
    limits: StoreLimits,
    /// Integrity key for HMAC-SHA256 sidecar tagging. Held as raw
    /// bytes so [`rustgate_core::crypto::hmac_sha256_tag`] can
    /// consume `&[u8]` directly. Wrapped in `Arc<Vec<u8>>` so a
    /// follow-up that needs to rotate the key without rebuilding
    /// the whole store can swap the inner `Vec`.
    integrity_key: Arc<Vec<u8>>,
    /// Serialises capacity arithmetic for `upload`/`delete`. Reads
    /// (`download`, `list`, `metadata`) bypass this lock entirely.
    write_lock: Mutex<u64>,
}

impl PackageStore {
    /// Create a store rooted at `base_dir`, with `integrity_key`
    /// used for HMAC-SHA256 tagging of sidecar metadata.
    ///
    /// The directory is created if missing. The current sum of
    /// stored package bodies is computed by walking the directory
    /// and reading every `*.meta.json` sidecar; corrupt or
    /// HMAC-mismatched sidecars are skipped (logged at warn) so a
    /// single bad file cannot block startup.
    ///
    /// # Errors
    ///
    /// - [`MissionsError::Config`] if `integrity_key` is empty.
    /// - [`MissionsError::Io`] if the base directory cannot be
    ///   created or read.
    pub async fn new(
        base_dir: PathBuf,
        integrity_key: Vec<u8>,
        limits: StoreLimits,
    ) -> Result<Self> {
        if integrity_key.is_empty() {
            return Err(MissionsError::Config(
                "integrity_key must be non-empty".to_string(),
            ));
        }
        fs::create_dir_all(&base_dir)
            .await
            .map_err(|e| MissionsError::io(&base_dir, e))?;

        let initial_total = compute_initial_total(&base_dir, &integrity_key).await?;

        Ok(Self {
            inner: Arc::new(Inner {
                base_dir,
                limits,
                integrity_key: Arc::new(integrity_key),
                write_lock: Mutex::new(initial_total),
            }),
        })
    }

    /// Path to the on-disk ZIP body for `hash`.
    fn package_path(&self, hash: &str) -> PathBuf {
        self.inner.base_dir.join(format!("{hash}.zip"))
    }

    /// Path to the sidecar JSON for `hash`.
    fn meta_path(&self, hash: &str) -> PathBuf {
        self.inner.base_dir.join(format!("{hash}.meta.json"))
    }

    /// Upload a package body.
    ///
    /// The hash is computed by SHA-256 of `data`. If the same hash
    /// is already stored, the existing entry is left in place and
    /// its [`PackageMeta`] is returned unchanged — this preserves
    /// the original `creator_uid` and `upload_time` and is the
    /// behaviour TAK clients expect.
    ///
    /// # Errors
    ///
    /// - [`MissionsError::EmptyUpload`] for a zero-byte body.
    /// - [`MissionsError::PackageTooLarge`] if `data.len()` exceeds
    ///   [`StoreLimits::max_package_bytes`].
    /// - [`MissionsError::CapacityExceeded`] if accepting the
    ///   upload would push the running total past
    ///   [`StoreLimits::max_total_bytes`].
    /// - [`MissionsError::Io`] for filesystem write failures.
    /// - [`MissionsError::Hmac`] if the integrity tag cannot be
    ///   produced (only the empty-key path; rejected at construction
    ///   time, so unreachable in practice).
    pub async fn upload(&self, data: &[u8], name: &str, creator_uid: &str) -> Result<PackageMeta> {
        if data.is_empty() {
            return Err(MissionsError::EmptyUpload);
        }
        let actual = data.len() as u64;
        if actual > self.inner.limits.max_package_bytes {
            return Err(MissionsError::PackageTooLarge {
                actual,
                limit: self.inner.limits.max_package_bytes,
            });
        }

        let hash = hex_sha256(data);
        let pkg_path = self.package_path(&hash);
        let meta_path = self.meta_path(&hash);

        let mut total_guard = self.inner.write_lock.lock().await;

        // Idempotent: if the same content is already stored, return
        // the existing metadata without rewriting either file. We
        // verify the on-disk state by reading the sidecar — if it is
        // missing or corrupt we treat the entry as absent and rebuild.
        if pkg_path.exists()
            && let Ok(existing) = read_envelope(&meta_path).await
            && verify_envelope(&existing, &self.inner.integrity_key).is_ok()
        {
            return Ok(existing.meta);
        }

        let new_total = total_guard
            .checked_add(actual)
            .ok_or_else(|| MissionsError::Config("capacity counter overflow".to_string()))?;
        if new_total > self.inner.limits.max_total_bytes {
            return Err(MissionsError::CapacityExceeded {
                actual,
                current: *total_guard,
                limit: self.inner.limits.max_total_bytes,
            });
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        let meta = PackageMeta {
            hash: hash.clone(),
            name: name.to_string(),
            creator_uid: creator_uid.to_string(),
            mime_type: ZIP_MIME_TYPE.to_string(),
            size: actual,
            upload_time: now,
        };
        let envelope = build_envelope(meta, &self.inner.integrity_key)?;

        // Body first, sidecar second — if the process crashes
        // between the two writes, the orphan ZIP is rebuilt on
        // next upload (idempotent fast path) or pruned by the
        // caller's GC sweep. Writing the sidecar last guarantees
        // an entry only becomes "downloadable" once both files are
        // durably present.
        fs::write(&pkg_path, data)
            .await
            .map_err(|e| MissionsError::io(&pkg_path, e))?;

        let envelope_bytes = serde_json::to_vec(&envelope)?;
        fs::write(&meta_path, &envelope_bytes)
            .await
            .map_err(|e| MissionsError::io(&meta_path, e))?;

        *total_guard = new_total;
        tracing::info!(
            hash = %envelope.meta.hash,
            name = %envelope.meta.name,
            size = envelope.meta.size,
            creator_uid = %envelope.meta.creator_uid,
            "data package stored"
        );
        Ok(envelope.meta)
    }

    /// Read a package body by hash, after verifying its sidecar
    /// integrity tag.
    ///
    /// Returns `(metadata, body_bytes)`. The body is read into
    /// memory in full — TAK clients expect a single
    /// `Content-Length`-bounded HTTP response, and the configured
    /// per-package cap means the buffer is bounded.
    ///
    /// # Errors
    ///
    /// - [`MissionsError::InvalidHash`] if `hash` is not 64 hex chars.
    /// - [`MissionsError::NotFound`] if either the body or the
    ///   sidecar is missing.
    /// - [`MissionsError::Hmac`] if the sidecar tag fails to verify
    ///   against the stored metadata (post-upload tampering).
    /// - [`MissionsError::Io`] for read failures.
    pub async fn download(&self, hash: &str) -> Result<(PackageMeta, Vec<u8>)> {
        if !is_valid_hex_hash(hash) {
            return Err(MissionsError::InvalidHash);
        }
        let meta_path = self.meta_path(hash);
        let pkg_path = self.package_path(hash);
        if !meta_path.exists() || !pkg_path.exists() {
            return Err(MissionsError::NotFound {
                hash: hash.to_string(),
            });
        }

        let envelope = read_envelope(&meta_path).await?;
        verify_envelope(&envelope, &self.inner.integrity_key)?;
        let data = fs::read(&pkg_path)
            .await
            .map_err(|e| MissionsError::io(&pkg_path, e))?;
        Ok((envelope.meta, data))
    }

    /// Look up the metadata for a package without reading its body.
    ///
    /// Useful for the `GET /api/packages/{hash}` HEAD-equivalent or
    /// internal probes that just need to test existence.
    ///
    /// # Errors
    ///
    /// Same as [`PackageStore::download`] minus the body-read
    /// failures.
    pub async fn metadata(&self, hash: &str) -> Result<PackageMeta> {
        if !is_valid_hex_hash(hash) {
            return Err(MissionsError::InvalidHash);
        }
        let meta_path = self.meta_path(hash);
        if !meta_path.exists() {
            return Err(MissionsError::NotFound {
                hash: hash.to_string(),
            });
        }
        let envelope = read_envelope(&meta_path).await?;
        verify_envelope(&envelope, &self.inner.integrity_key)?;
        Ok(envelope.meta)
    }

    /// Delete a package and its sidecar.
    ///
    /// Returns the deleted [`PackageMeta`] so callers can emit an
    /// audit event with the package's display name. Deleting an
    /// unknown hash returns [`MissionsError::NotFound`].
    pub async fn delete(&self, hash: &str) -> Result<PackageMeta> {
        if !is_valid_hex_hash(hash) {
            return Err(MissionsError::InvalidHash);
        }
        let meta_path = self.meta_path(hash);
        let pkg_path = self.package_path(hash);
        if !meta_path.exists() || !pkg_path.exists() {
            return Err(MissionsError::NotFound {
                hash: hash.to_string(),
            });
        }

        let envelope = read_envelope(&meta_path).await?;
        verify_envelope(&envelope, &self.inner.integrity_key)?;
        let size = envelope.meta.size;

        let mut total_guard = self.inner.write_lock.lock().await;

        // Sidecar first so a crash mid-delete cannot leave a body
        // visible without the sidecar that anchors its trust.
        fs::remove_file(&meta_path)
            .await
            .map_err(|e| MissionsError::io(&meta_path, e))?;
        fs::remove_file(&pkg_path)
            .await
            .map_err(|e| MissionsError::io(&pkg_path, e))?;

        *total_guard = total_guard.saturating_sub(size);
        tracing::info!(
            hash = %envelope.meta.hash,
            name = %envelope.meta.name,
            size = envelope.meta.size,
            "data package deleted"
        );
        Ok(envelope.meta)
    }

    /// List every stored package's metadata, sorted by `upload_time`
    /// descending (newest first).
    ///
    /// Sidecars that fail HMAC verification are skipped and logged
    /// at warn — they are surfaced as a separate "needs admin
    /// attention" condition rather than failing the whole listing.
    pub async fn list(&self) -> Result<Vec<PackageMeta>> {
        let mut entries = fs::read_dir(&self.inner.base_dir)
            .await
            .map_err(|e| MissionsError::io(&self.inner.base_dir, e))?;

        let mut by_time: BTreeMap<(u64, String), PackageMeta> = BTreeMap::new();

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| MissionsError::io(&self.inner.base_dir, e))?
        {
            let path = entry.path();
            let Some(stem) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(hash) = stem.strip_suffix(".meta.json") else {
                continue;
            };
            if !is_valid_hex_hash(hash) {
                continue;
            }
            match read_envelope(&path).await {
                Ok(env) => match verify_envelope(&env, &self.inner.integrity_key) {
                    Ok(()) => {
                        let _ =
                            by_time.insert((env.meta.upload_time, env.meta.hash.clone()), env.meta);
                    }
                    Err(e) => {
                        tracing::warn!(
                            hash = %hash,
                            error = %e,
                            "sidecar HMAC mismatch — skipping in listing"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to read sidecar — skipping in listing"
                    );
                }
            }
        }

        // BTreeMap iterates ascending; collect into a Vec and reverse
        // for newest-first.
        let mut out: Vec<PackageMeta> = by_time.into_values().collect();
        out.reverse();
        Ok(out)
    }

    /// Sum of every currently-stored package body in bytes. Useful
    /// for a `/api/packages/usage` future endpoint or a Prometheus
    /// gauge wired from the admin layer.
    pub async fn current_total_bytes(&self) -> u64 {
        *self.inner.write_lock.lock().await
    }

    /// Clone of the configured [`StoreLimits`].
    pub fn limits(&self) -> &StoreLimits {
        &self.inner.limits
    }
}

/// Lowercase hex SHA-256 of `data`.
fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Validate that `s` is exactly 64 lowercase-hex characters.
fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build the canonical byte sequence that the HMAC tag covers.
///
/// Field order is fixed and MUST NOT change without a sidecar
/// version bump — a tag computed under one ordering will not verify
/// under another. The fields are joined with a `0x00` separator so
/// adjacent fields cannot be silently re-bracketed (e.g. moving a
/// byte from `name` into `creator_uid` would change the join points
/// and produce a different tag).
fn canonical_tag_input(meta: &PackageMeta) -> Vec<u8> {
    let sep = 0u8;
    let mut buf =
        Vec::with_capacity(meta.hash.len() + meta.name.len() + meta.creator_uid.len() + 32);
    buf.extend_from_slice(meta.hash.as_bytes());
    buf.push(sep);
    buf.extend_from_slice(meta.size.to_be_bytes().as_slice());
    buf.push(sep);
    buf.extend_from_slice(meta.name.as_bytes());
    buf.push(sep);
    buf.extend_from_slice(meta.creator_uid.as_bytes());
    buf.push(sep);
    buf.extend_from_slice(meta.upload_time.to_be_bytes().as_slice());
    buf
}

/// Hex-encode a byte slice (lowercase). Local helper so we do not
/// pull in the `hex` crate for this single use.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a lowercase-hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(MissionsError::Config("odd-length hex string".to_string()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = decode_nibble(bytes[i])?;
        let lo = decode_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn decode_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(MissionsError::Config(format!(
            "invalid hex nibble: 0x{b:02x}"
        ))),
    }
}

/// Build a [`SidecarEnvelope`] by computing the HMAC tag over the
/// canonical metadata blob.
fn build_envelope(meta: PackageMeta, key: &[u8]) -> Result<SidecarEnvelope> {
    let canonical = canonical_tag_input(&meta);
    let tag_bytes = rustgate_core::crypto::hmac_sha256_tag(key, &canonical)?;
    let tag = hex_encode(&tag_bytes);
    Ok(SidecarEnvelope { meta, tag })
}

/// Verify the HMAC tag inside a [`SidecarEnvelope`] against its
/// metadata using constant-time comparison. Returns `Ok(())` on
/// match.
fn verify_envelope(envelope: &SidecarEnvelope, key: &[u8]) -> Result<()> {
    let tag_bytes = hex_decode(&envelope.tag)?;
    let canonical = canonical_tag_input(&envelope.meta);
    rustgate_core::crypto::hmac_sha256_verify(key, &canonical, &tag_bytes)?;
    Ok(())
}

/// Read and JSON-parse a sidecar file.
async fn read_envelope(path: &Path) -> Result<SidecarEnvelope> {
    let bytes = fs::read(path)
        .await
        .map_err(|e| MissionsError::io(path, e))?;
    let env: SidecarEnvelope = serde_json::from_slice(&bytes)?;
    Ok(env)
}

/// Walk the base directory at construction time and sum every
/// verified sidecar's `size`. Sidecars with HMAC mismatches or
/// JSON-parse failures are skipped (the running total is
/// conservative, never inflated). Triggered once per store
/// instance.
async fn compute_initial_total(base_dir: &Path, key: &[u8]) -> Result<u64> {
    let mut total: u64 = 0;
    let mut entries = match fs::read_dir(base_dir).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(MissionsError::io(base_dir, e)),
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| MissionsError::io(base_dir, e))?
    {
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(hash) = stem.strip_suffix(".meta.json") else {
            continue;
        };
        if !is_valid_hex_hash(hash) {
            continue;
        }
        if let Ok(env) = read_envelope(&path).await
            && verify_envelope(&env, key).is_ok()
        {
            total = total.saturating_add(env.meta.size);
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn sample_key() -> Vec<u8> {
        b"a-shared-secret-of-non-zero-length-32b!".to_vec()
    }

    #[tokio::test]
    async fn upload_then_download_round_trip() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();

        let body = b"PK\x03\x04hello-zip-body";
        let meta = store
            .upload(body, "sample.zip", "operator-1")
            .await
            .unwrap();
        assert_eq!(meta.size, body.len() as u64);
        assert_eq!(meta.creator_uid, "operator-1");
        assert_eq!(meta.mime_type, ZIP_MIME_TYPE);

        let (got_meta, got_body) = store.download(&meta.hash).await.unwrap();
        assert_eq!(got_meta, meta);
        assert_eq!(got_body, body);
    }

    #[tokio::test]
    async fn duplicate_upload_is_idempotent() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();
        let body = b"deadbeef-zip";
        let first = store.upload(body, "a.zip", "op-1").await.unwrap();
        let second = store.upload(body, "renamed.zip", "op-2").await.unwrap();
        assert_eq!(first, second, "second upload must return existing meta");
        assert_eq!(second.name, "a.zip");
    }

    #[tokio::test]
    async fn rejects_empty_upload() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();
        let err = store.upload(b"", "a.zip", "op").await.unwrap_err();
        assert!(matches!(err, MissionsError::EmptyUpload));
    }

    #[tokio::test]
    async fn rejects_oversize_package() {
        let dir = temp_dir();
        let limits = StoreLimits::default().with_max_package_bytes(8);
        let store = PackageStore::new(dir.path().into(), sample_key(), limits)
            .await
            .unwrap();
        let err = store
            .upload(b"this-is-too-long", "a.zip", "op")
            .await
            .unwrap_err();
        match err {
            MissionsError::PackageTooLarge { actual, limit } => {
                assert_eq!(actual, 16);
                assert_eq!(limit, 8);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_total_capacity_exceeded() {
        let dir = temp_dir();
        let limits = StoreLimits::default()
            .with_max_total_bytes(20)
            .with_max_package_bytes(20);
        let store = PackageStore::new(dir.path().into(), sample_key(), limits)
            .await
            .unwrap();
        let _ = store
            .upload(b"first-1234567890", "a.zip", "op")
            .await
            .unwrap();
        // First upload was 16 bytes, leaving 4 free. Second is 8.
        let err = store.upload(b"second--", "b.zip", "op").await.unwrap_err();
        match err {
            MissionsError::CapacityExceeded {
                actual,
                current,
                limit,
            } => {
                assert_eq!(actual, 8);
                assert_eq!(current, 16);
                assert_eq!(limit, 20);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_invalid_hash() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();
        let err = store.download("not-a-hash").await.unwrap_err();
        assert!(matches!(err, MissionsError::InvalidHash));
        let err = store.metadata("not-a-hash").await.unwrap_err();
        assert!(matches!(err, MissionsError::InvalidHash));
        let err = store.delete("not-a-hash").await.unwrap_err();
        assert!(matches!(err, MissionsError::InvalidHash));
    }

    #[tokio::test]
    async fn missing_hash_returns_not_found() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();
        let phantom = "0000000000000000000000000000000000000000000000000000000000000000";
        let err = store.download(phantom).await.unwrap_err();
        assert!(matches!(err, MissionsError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_removes_files_and_decrements_total() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();
        let body = b"deletable-body";
        let meta = store.upload(body, "a.zip", "op").await.unwrap();
        assert_eq!(store.current_total_bytes().await, body.len() as u64);

        let removed = store.delete(&meta.hash).await.unwrap();
        assert_eq!(removed, meta);
        assert_eq!(store.current_total_bytes().await, 0);

        let err = store.download(&meta.hash).await.unwrap_err();
        assert!(matches!(err, MissionsError::NotFound { .. }));
    }

    #[tokio::test]
    async fn list_returns_newest_first() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();
        let _a = store.upload(b"alpha", "a.zip", "op").await.unwrap();
        // Sleep one second so upload_time differs.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let b = store.upload(b"bravo", "b.zip", "op").await.unwrap();

        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].hash, b.hash, "newest first");
    }

    #[tokio::test]
    async fn tampered_sidecar_fails_download() {
        let dir = temp_dir();
        let store = PackageStore::new(dir.path().into(), sample_key(), StoreLimits::default())
            .await
            .unwrap();
        let body = b"trust-anchored-body";
        let meta = store.upload(body, "a.zip", "operator-A").await.unwrap();

        // Tamper: rewrite the sidecar's `name` field without updating
        // the HMAC tag. The download path must reject.
        let path = dir.path().join(format!("{}.meta.json", meta.hash));
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        parsed["meta"]["name"] = serde_json::Value::String("evil.zip".to_string());
        std::fs::write(&path, serde_json::to_vec(&parsed).unwrap()).unwrap();

        let err = store.download(&meta.hash).await.unwrap_err();
        assert!(matches!(err, MissionsError::Hmac(_)));
    }

    #[tokio::test]
    async fn rejects_empty_integrity_key() {
        let dir = temp_dir();
        let err = PackageStore::new(dir.path().into(), Vec::new(), StoreLimits::default())
            .await
            .unwrap_err();
        match err {
            MissionsError::Config(msg) => assert!(msg.contains("integrity_key")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn hex_round_trip() {
        let bytes = vec![0x00, 0x01, 0x10, 0xab, 0xff];
        let s = hex_encode(&bytes);
        assert_eq!(s, "000110abff");
        assert_eq!(hex_decode(&s).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(matches!(
            hex_decode("abc").unwrap_err(),
            MissionsError::Config(_)
        ));
    }

    #[test]
    fn hex_decode_rejects_invalid_nibble() {
        assert!(matches!(
            hex_decode("zz").unwrap_err(),
            MissionsError::Config(_)
        ));
    }

    #[test]
    fn is_valid_hex_hash_checks_length_and_alphabet() {
        let good = "0".repeat(64);
        assert!(is_valid_hex_hash(&good));
        assert!(!is_valid_hex_hash(&"0".repeat(63)));
        assert!(!is_valid_hex_hash(&"0".repeat(65)));
        assert!(!is_valid_hex_hash(
            "ZZZ0000000000000000000000000000000000000000000000000000000000000"
        ));
    }
}
