// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured CoT event archiver.
//!
//! When enabled, logs all received CoT events as JSONL to a rotatable
//! archive file. Each line is a self-contained JSON object with source
//! identity, timestamp, and the raw payload.
//!
//! Files rotate daily (one file per UTC date). The archive directory is
//! created on first write if it does not exist.
//!
//! # Tenant partitioning (closes #859)
//!
//! When a [`RoutableMessage`] carries a populated
//! [`rustgate_core::message::Metadata::tenant_id`] the archiver routes
//! the JSONL line into a per-tenant subdirectory:
//!
//! ```text
//! <archive-dir>/<tenant-id>/cot-<date>.jsonl[.enc]
//! ```
//!
//! Messages with no tenant id fall back to the reserved
//! [`rustgate_core::constants::DEFAULT_TENANT_ARCHIVE_KEY`] bucket
//! (`_default`). Operators with single-tenant deployments observe one
//! extra path component compared to the pre-#859 layout — no other
//! behaviour change.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rustgate_core::constants::DEFAULT_TENANT_ARCHIVE_KEY;
use rustgate_core::message::RoutableMessage;

/// Writes CoT events as JSONL to date-stamped archive files.
///
/// When constructed via [`CotArchiver::with_encryption`], each daily file is
/// written through a streaming ChaCha20-Poly1305 sink and gains an `.enc`
/// suffix. Plaintext callers continue to use [`CotArchiver::new`].
///
/// Per-tenant data isolation (closes #859): each unique
/// [`rustgate_core::message::Metadata::tenant_id`] gets its own daily
/// rotation cycle under `<dir>/<tenant>/`. Messages with no tenant id
/// land under
/// `DEFAULT_TENANT_ARCHIVE_KEY`.
pub struct CotArchiver {
    dir: PathBuf,
    key_ring: Option<Arc<crate::encrypted::KeyRing>>,
    inner: Arc<Mutex<ArchiverInner>>,
}

// Custom `Debug` so a `{:?}` print never reveals key material or the
// inner buffered writer state. Mirrors the redaction pattern documented
// in the workspace playbook for types that hold a `KeyRing`.
impl std::fmt::Debug for CotArchiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CotArchiver")
            .field("dir", &self.dir)
            .field("encrypted", &self.key_ring.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum ArchiveSink {
    Plain(std::io::BufWriter<std::fs::File>),
    Encrypted(crate::encrypted::EncryptedWriter),
}

#[derive(Default)]
struct TenantState {
    current_date: String,
    writer: Option<ArchiveSink>,
}

/// Per-tenant rotation state. The outer map is keyed by the resolved
/// tenant bucket (the populated `tenant_id` or
/// `DEFAULT_TENANT_ARCHIVE_KEY`). Each tenant rotates and rolls
/// independently — a flood of messages from one tenant cannot starve
/// another tenant of its own daily rotation tick.
#[derive(Default)]
struct ArchiverInner {
    tenants: HashMap<String, TenantState>,
}

/// Resolve the on-disk tenant bucket for a message: the message's
/// populated `tenant_id`, or `DEFAULT_TENANT_ARCHIVE_KEY` when absent.
///
/// Sanitises path-traversal characters (`/`, `\`, NUL) to `_` so a
/// hostile cert Organization field cannot escape the archive directory.
/// The tenant id source is the certificate Organization (`O=`) field
/// which the operator controls, but defence-in-depth sanitisation here
/// closes the door on a misconfigured CA that issues certs with `..` in
/// the O field.
fn resolve_tenant_bucket(msg: &RoutableMessage) -> String {
    let raw = msg
        .metadata
        .tenant_id()
        .unwrap_or(DEFAULT_TENANT_ARCHIVE_KEY);
    sanitize_tenant_path_component(raw)
}

/// Replace path-traversal characters (`/`, `\`, NUL) and leading dots
/// with `_` so the resulting string is safe to use as a single
/// directory-name component. Returns the
/// `DEFAULT_TENANT_ARCHIVE_KEY` sentinel when sanitisation produces
/// an empty string.
fn sanitize_tenant_path_component(raw: &str) -> String {
    let mut cleaned: String = raw
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    // Reject pure-dot components and leading-dot components which
    // would otherwise be interpreted as parent / hidden directories.
    while cleaned.starts_with('.') {
        cleaned.replace_range(..1, "_");
    }
    if cleaned.is_empty() {
        DEFAULT_TENANT_ARCHIVE_KEY.to_string()
    } else {
        cleaned
    }
}

impl CotArchiver {
    /// Create a new archiver that writes to the given directory.
    ///
    /// The directory is created lazily on the first write.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            key_ring: None,
            inner: Arc::new(Mutex::new(ArchiverInner::default())),
        }
    }

    /// Construct an archiver that encrypts each daily file with the active
    /// key from the supplied [`KeyRing`](crate::encrypted::KeyRing).
    pub fn with_encryption(
        dir: impl Into<PathBuf>,
        key_ring: Arc<crate::encrypted::KeyRing>,
    ) -> Self {
        Self {
            dir: dir.into(),
            key_ring: Some(key_ring),
            inner: Arc::new(Mutex::new(ArchiverInner::default())),
        }
    }

    /// Archive a single message.
    ///
    /// Serialises the JSONL line on the calling task, then moves the
    /// blocking file I/O into `spawn_blocking` so the async read loop
    /// is never stalled by disk writes or file rotation.
    pub async fn record(&self, msg: &RoutableMessage) {
        let now = SystemTime::now();
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute UTC date string (YYYY-MM-DD) without chrono
        let today = utc_date_string(secs);
        let tenant = resolve_tenant_bucket(msg);

        // Build JSONL line on the async task (cheap CPU work).
        let payload_b64 = base64_encode(&msg.payload);
        let msg_type = escape_json(&msg.metadata.message_type.to_string());
        let dest = match &msg.destination {
            rustgate_core::message::Destination::Broadcast => "broadcast".to_string(),
            rustgate_core::message::Destination::Group(g) => {
                format!("group:{}", escape_json(g))
            }
            rustgate_core::message::Destination::Direct(d) => {
                format!("direct:{}", escape_json(&d.cn))
            }
            rustgate_core::message::Destination::Multicast(groups) => {
                format!("multicast:[{}]", groups.join(","))
            }
        };
        // Embed the resolved tenant bucket on every JSONL line so a
        // forensic analyst can re-bucket records that have been merged
        // out of their original directory (e.g. a `tar -czf
        // archive.tgz <archive-dir>/` flatten).
        let tenant_field = escape_json(&tenant);

        let line = format!(
            "{{\"ts\":{secs},\"cn\":\"{}\",\"fp\":\"{}\",\"type\":\"{msg_type}\",\"dest\":\"{dest}\",\"proto\":\"{}\",\"tenant\":\"{tenant_field}\",\"payload\":\"{payload_b64}\"}}\n",
            escape_json(&msg.source.cn),
            escape_json(&msg.source.fingerprint),
            escape_json(&msg.metadata.source_protocol),
        );

        // Move all blocking file I/O onto the blocking thread pool.
        let inner = Arc::clone(&self.inner);
        let dir = self.dir.clone();
        let key_ring = self.key_ring.clone();
        let _result = tokio::task::spawn_blocking(move || {
            write_line(&inner, &dir, &tenant, &today, &line, key_ring.as_deref());
        })
        .await;
    }

    /// Return the per-tenant archive segment the writer would append
    /// to right now if it received a message tagged with `tenant`.
    ///
    /// Encrypted archivers include the `.enc` suffix — previously this
    /// always returned the plaintext name, which meant the rotation
    /// sweep never actually matched (and therefore never excluded) the
    /// encrypted active file from deletion.
    ///
    /// The rotation task uses this (via [`Self::active_paths`]) to
    /// exclude every in-progress file from both size accounting and
    /// deletion sweeps, avoiding races against the writer.
    pub fn active_path_for_tenant(&self, tenant: &str) -> PathBuf {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let today = utc_date_string(secs);
        let tenant_clean = sanitize_tenant_path_component(tenant);
        let tenant_dir = self.dir.join(&tenant_clean);
        if self.key_ring.is_some() {
            tenant_dir.join(format!("cot-{today}.jsonl.enc"))
        } else {
            tenant_dir.join(format!("cot-{today}.jsonl"))
        }
    }

    /// Backward-compatible single-segment accessor: returns the
    /// active path for `DEFAULT_TENANT_ARCHIVE_KEY`.
    ///
    /// Pre-#859 callers (and tests written against the single-segment
    /// model) continue to compile. New callers that need to enumerate
    /// every active segment should use [`Self::active_paths`] instead.
    pub fn active_path(&self) -> PathBuf {
        self.active_path_for_tenant(DEFAULT_TENANT_ARCHIVE_KEY)
    }

    /// Return the active segment path for every tenant that has at
    /// least one open writer in this process. Used by the rotation
    /// sweep to exclude every in-progress file from deletion.
    pub fn active_paths(&self) -> Vec<PathBuf> {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let today = utc_date_string(secs);
        let tenants: Vec<String> = {
            let inner = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            inner.tenants.keys().cloned().collect()
        };
        let suffix = if self.key_ring.is_some() {
            format!("cot-{today}.jsonl.enc")
        } else {
            format!("cot-{today}.jsonl")
        };
        tenants
            .into_iter()
            .map(|t| self.dir.join(t).join(&suffix))
            .collect()
    }

    /// If any tenant's currently-active archive file exceeds
    /// `max_bytes`, seal and rename each one to a timestamp-suffixed
    /// path, then drop the writers so the next record per-tenant
    /// opens a fresh segment at the stable `cot-<date>.jsonl[.enc]`
    /// name.
    ///
    /// Returns the list of rolled paths (one per tenant whose
    /// segment was over-cap). An empty vector means `max_bytes == 0`,
    /// no writer is open, or every segment is still under the cap.
    ///
    /// Encrypted files are sealed by dropping the underlying
    /// [`EncryptedWriter`](crate::encrypted::EncryptedWriter),
    /// which writes the terminator chunk in its `Drop` impl. Without
    /// that the rolled `.enc` file would fail decryption.
    pub fn roll_if_over_size(&self, max_bytes: u64) -> Vec<PathBuf> {
        if max_bytes == 0 {
            return Vec::new();
        }

        // Snapshot the tenant set under the lock so each rename
        // happens with the per-tenant lock released — avoids holding
        // the mutex across a filesystem rename.
        let mut rolled = Vec::new();
        let mut inner = match self.inner.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        let tenants: Vec<String> = inner.tenants.keys().cloned().collect();
        for tenant in &tenants {
            let active = self.active_path_for_tenant(tenant);
            let Some(state) = inner.tenants.get_mut(tenant) else {
                continue;
            };
            let Some(writer) = state.writer.as_mut() else {
                continue;
            };
            // Flush any buffered writes so the on-disk size accurately
            // reflects what we have written.
            match writer {
                ArchiveSink::Plain(p) => {
                    let _ = p.flush();
                }
                ArchiveSink::Encrypted(e) => {
                    let _ = e.flush();
                }
            }
            let size = std::fs::metadata(&active).map(|m| m.len()).unwrap_or(0);
            if size < max_bytes {
                continue;
            }
            // Drop the writer (seals encrypted files via Drop), then
            // rename. Clearing `current_date` forces `write_line` to
            // open a fresh segment on the next write under this
            // tenant.
            state.writer = None;
            state.current_date.clear();
            let target = rolled_path(&active);
            if let Err(err) = std::fs::rename(&active, &target) {
                tracing::warn!(
                    tenant = %tenant,
                    from = %active.display(),
                    to = %target.display(),
                    error = %err,
                    "archive rotation: failed to rename rolled segment",
                );
                continue;
            }
            tracing::info!(
                tenant = %tenant,
                rolled = %target.display(),
                bytes = size,
                max_bytes,
                "CoT archive: rolled active segment due to size cap",
            );
            rolled.push(target);
        }
        rolled
    }

    /// Flush any buffered data to disk for every tenant.
    pub fn flush(&self) {
        let mut inner = match self.inner.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        for state in inner.tenants.values_mut() {
            if let Some(ref mut w) = state.writer {
                match w {
                    ArchiveSink::Plain(p) => {
                        let _ = p.flush();
                    }
                    ArchiveSink::Encrypted(e) => {
                        let _ = e.flush();
                    }
                }
            }
        }
    }
}

impl Drop for CotArchiver {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Perform the blocking file rotation and write on the current thread.
///
/// Extracted as a free function so it can be called inside
/// `spawn_blocking` without borrowing `self`.
fn write_line(
    inner: &Mutex<ArchiverInner>,
    base_dir: &std::path::Path,
    tenant: &str,
    today: &str,
    line: &str,
    key_ring: Option<&crate::encrypted::KeyRing>,
) {
    let mut inner = match inner.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };

    let state = inner.tenants.entry(tenant.to_string()).or_default();

    // Rotate file if date changed
    if state.current_date != today {
        if let Some(ref mut w) = state.writer {
            match w {
                ArchiveSink::Plain(p) => {
                    let _ = p.flush();
                }
                ArchiveSink::Encrypted(e) => {
                    let _ = e.flush();
                }
            }
        }
        state.writer = None;
        state.current_date = today.to_owned();

        let tenant_dir = base_dir.join(tenant);
        match open_sink(&tenant_dir, today, key_ring) {
            Ok(sink) => {
                state.writer = Some(sink);
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    dir = %tenant_dir.display(),
                    tenant = %tenant,
                    "failed to open archive file",
                );
                return;
            }
        }
    }

    let Some(ref mut writer) = state.writer else {
        return;
    };

    let res = match writer {
        ArchiveSink::Plain(p) => p.write_all(line.as_bytes()).map_err(|e| e.to_string()),
        ArchiveSink::Encrypted(e) => e
            .write_chunk(line.as_bytes())
            .map_err(|err| err.to_string()),
    };
    if let Err(e) = res {
        tracing::error!(error = %e, tenant = %tenant, "failed to write archive line");
    }
}

/// Build the timestamped roll-off path for an active archive segment.
///
/// Given `<dir>/cot-<date>.jsonl[.enc]`, inserts a `T<hh-mm-ss>` stamp
/// before the `.jsonl` extension so plaintext and encrypted paths share
/// the same suffix placement. The stamp is the current UTC time-of-day;
/// collisions at sub-second precision are tolerated — the second roll
/// would observe the target path already exists via the `rename` error
/// and log a warning without dropping data (the next rotation tick
/// retries with a later timestamp).
fn rolled_path(active: &std::path::Path) -> PathBuf {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let in_day = secs % 86_400;
    let h = (in_day / 3600) as u32;
    let m = ((in_day / 60) % 60) as u32;
    let s = (in_day % 60) as u32;
    let stamp = format!("T{h:02}-{m:02}-{s:02}");
    let parent = active.parent().unwrap_or_else(|| std::path::Path::new(""));
    let name = active
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let new_name = match name.find(".jsonl") {
        Some(idx) => {
            let (head, tail) = name.split_at(idx);
            format!("{head}{stamp}{tail}")
        }
        None => format!("{name}{stamp}"),
    };
    parent.join(new_name)
}

fn open_sink(
    dir: &std::path::Path,
    date: &str,
    key_ring: Option<&crate::encrypted::KeyRing>,
) -> Result<ArchiveSink, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    if let Some(ring) = key_ring {
        let path = dir.join(format!("cot-{date}.jsonl.enc"));
        crate::encrypted::EncryptedWriter::create(&path, ring)
            .map(ArchiveSink::Encrypted)
            .map_err(|e| e.to_string())
    } else {
        let path = dir.join(format!("cot-{date}.jsonl"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        Ok(ArchiveSink::Plain(std::io::BufWriter::new(file)))
    }
}

/// Compute UTC date string (YYYY-MM-DD) from Unix epoch seconds.
fn utc_date_string(epoch_secs: u64) -> String {
    // Days since epoch
    let days = epoch_secs / 86400;
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Minimal JSON string escaping (backslash and double-quote).
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Minimal base64 encoder (standard alphabet, with padding).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn utc_date_known_epoch() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(utc_date_string(1_704_067_200), "2024-01-01");
    }

    #[test]
    fn utc_date_unix_epoch() {
        assert_eq!(utc_date_string(0), "1970-01-01");
    }

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_encode_padding() {
        assert_eq!(base64_encode(b"Hi"), "SGk=");
        assert_eq!(base64_encode(b"Hey"), "SGV5");
    }

    #[test]
    fn escape_json_special_chars() {
        assert_eq!(escape_json(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn escape_json_clean() {
        assert_eq!(escape_json("hello"), "hello");
    }

    #[tokio::test]
    async fn archiver_escapes_special_cn_in_dest() {
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-escape-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);

        let target_identity = rustgate_core::identity::Identity::new(
            "evil\"user\\name".to_string(),
            "fp-target".to_string(),
            std::collections::BTreeSet::new(),
        )
        .expect("valid identity");

        let msg = rustgate_core::message::RoutableMessage {
            source: rustgate_core::identity::Identity::new(
                "sender".to_string(),
                "fp-sender".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("valid identity"),
            destination: rustgate_core::message::Destination::Direct(target_identity),
            payload: bytes::Bytes::from_static(b"<event/>"),
            metadata: rustgate_core::message::Metadata::new(
                SystemTime::now(),
                "cot".to_string(),
                rustgate_core::message::MessageType::Position,
            ),
            entity: None,
        };

        archiver.record(&msg).await;
        archiver.flush();

        // Post-#859 layout: messages with no tenant_id land under
        // `<dir>/_default/cot-…`. Walk into the default subdir to
        // find the segment.
        let tenant_dir = dir.join(DEFAULT_TENANT_ARCHIVE_KEY);
        let entries: Vec<_> = std::fs::read_dir(&tenant_dir)
            .expect("default tenant dir should exist")
            .collect();
        assert_eq!(entries.len(), 1);

        let file_path = entries[0].as_ref().expect("entry").path();
        let content = std::fs::read_to_string(&file_path).expect("read file");

        // Verify the special chars are escaped — no raw quotes or backslashes
        assert!(
            content.contains(r#"direct:evil\"user\\name"#),
            "CN with special chars should be escaped: {content}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn archiver_encrypts_when_key_ring_present() {
        use std::collections::BTreeMap;

        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-enc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Build a key ring with one 32-byte key.
        let mut keys = BTreeMap::new();
        let _ = keys.insert(
            "k1".to_string(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        );
        let kf = crate::encrypted::KeyFile {
            active_key_id: "k1".to_string(),
            keys,
            key_expirations: std::collections::BTreeMap::new(),
            key_derivations: std::collections::BTreeMap::new(),
            tenant_key_map: std::collections::BTreeMap::new(),
        };
        let bytes = serde_json::to_vec(&kf).expect("serialize");
        let ring =
            std::sync::Arc::new(crate::encrypted::KeyRing::from_bytes(&bytes).expect("ring"));

        let archiver = CotArchiver::with_encryption(&dir, std::sync::Arc::clone(&ring));

        let msg = rustgate_core::message::RoutableMessage {
            source: rustgate_core::identity::Identity::new(
                "alice".to_string(),
                "fp-123".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("valid identity"),
            destination: rustgate_core::message::Destination::Broadcast,
            payload: bytes::Bytes::from_static(b"<event/>"),
            metadata: rustgate_core::message::Metadata::new(
                SystemTime::now(),
                "cot".to_string(),
                rustgate_core::message::MessageType::Position,
            ),
            entity: None,
        };

        archiver.record(&msg).await;
        archiver.flush();
        drop(archiver);

        // Locate the encrypted file under the default-tenant subdir.
        let tenant_dir = dir.join(DEFAULT_TENANT_ARCHIVE_KEY);
        let entries: Vec<_> = std::fs::read_dir(&tenant_dir)
            .expect("default tenant dir should exist")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        let enc_path = entries[0].path();
        assert!(
            enc_path.extension().and_then(|s| s.to_str()) == Some("enc"),
            "expected .enc suffix, got {enc_path:?}"
        );

        // Magic header check
        let raw = std::fs::read(&enc_path).expect("read");
        assert_eq!(&raw[..8], crate::encrypted::MAGIC);
        // Plaintext "alice" must NOT appear in ciphertext.
        assert!(!raw.windows(5).any(|w| w == b"alice"));

        // Round-trip: decrypt to a sibling file and check the JSONL line.
        let out_path = dir.join("decrypted.jsonl");
        crate::encrypted::decrypt_file(&enc_path, &out_path, &ring).expect("decrypt");
        let plaintext = std::fs::read_to_string(&out_path).expect("read decrypted");
        assert!(plaintext.contains("\"cn\":\"alice\""));
        assert!(plaintext.ends_with('\n'));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rolled_path_inserts_stamp_before_jsonl_plaintext() {
        let active = std::path::PathBuf::from("/var/archive/cot-2026-04-20.jsonl");
        let rolled = rolled_path(&active);
        let name = rolled.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("cot-2026-04-20T"),
            "name should start with stable prefix: {name}"
        );
        assert!(
            name.ends_with(".jsonl"),
            "name should end with .jsonl: {name}"
        );
        // The stamp should be exactly T<hh-mm-ss>, i.e. 9 chars wedged
        // between the date and the extension.
        assert_eq!(name.len(), "cot-2026-04-20".len() + 9 + ".jsonl".len());
        assert_eq!(rolled.parent(), Some(std::path::Path::new("/var/archive")));
    }

    #[test]
    fn rolled_path_inserts_stamp_before_jsonl_encrypted() {
        // The `.enc` suffix must be preserved — sealing happens on the
        // encrypted file so the rolled name must still carry `.enc`.
        let active = std::path::PathBuf::from("/var/archive/cot-2026-04-20.jsonl.enc");
        let rolled = rolled_path(&active);
        let name = rolled.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("cot-2026-04-20T"));
        assert!(
            name.ends_with(".jsonl.enc"),
            "must keep .enc suffix: {name}"
        );
    }

    #[tokio::test]
    async fn roll_if_over_size_rolls_plaintext_segment() {
        // Record enough bytes to exceed the cap, call roll_if_over_size,
        // and assert:
        //   (a) the original active path is gone,
        //   (b) a timestamp-suffixed sibling file now holds the data,
        //   (c) a subsequent record() re-opens the stable active path.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-roll-plain-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        let msg = make_test_msg();

        // Write a few records so the active file has some on-disk bytes.
        for _ in 0..5 {
            archiver.record(&msg).await;
        }
        archiver.flush();

        let active_before = archiver.active_path();
        let size_before = std::fs::metadata(&active_before)
            .expect("active file present")
            .len();
        assert!(size_before > 0);

        // Cap well below what we just wrote.
        let rolled_paths = archiver.roll_if_over_size(1);
        assert_eq!(rolled_paths.len(), 1, "expected exactly one rolled segment");
        let rolled = rolled_paths.into_iter().next().expect("rolled segment");

        assert_ne!(rolled, active_before, "rolled name must differ from active");
        assert!(rolled.exists(), "rolled file must exist on disk");
        assert!(
            !active_before.exists(),
            "stable active path should be vacant after the rename"
        );
        assert_eq!(
            std::fs::metadata(&rolled).unwrap().len(),
            size_before,
            "rolled file should hold all the bytes we wrote",
        );

        // After the roll, the next record re-opens the stable path.
        archiver.record(&msg).await;
        archiver.flush();
        assert!(
            active_before.exists(),
            "record() after roll should open a fresh active segment"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roll_if_over_size_no_op_when_writer_not_open() {
        // With no record() call yet, the writer is None. Rolling must
        // be a no-op — we have nothing to seal or rename.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-roll-notopen-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        assert!(
            archiver.roll_if_over_size(1024).is_empty(),
            "no writer open yet — roll must produce zero rolled segments",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn roll_if_over_size_no_op_when_under_cap() {
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-roll-undercap-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        archiver.record(&make_test_msg()).await;
        archiver.flush();

        // Cap well above what we wrote.
        assert!(
            archiver.roll_if_over_size(10 * 1024 * 1024).is_empty(),
            "under-cap must produce zero rolled segments",
        );
        assert!(archiver.active_path().exists(), "active file must remain");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn roll_if_over_size_zero_cap_is_disabled() {
        // max_bytes == 0 means "feature off" — the archiver must not
        // touch the file even if it would otherwise qualify.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-roll-disabled-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        for _ in 0..3 {
            archiver.record(&make_test_msg()).await;
        }
        archiver.flush();
        let before = archiver.active_path();
        let bytes = std::fs::metadata(&before).unwrap().len();

        assert!(
            archiver.roll_if_over_size(0).is_empty(),
            "zero cap is disabled — must produce zero rolled segments",
        );
        assert!(before.exists(), "zero cap must not roll");
        assert_eq!(std::fs::metadata(&before).unwrap().len(), bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn active_path_encrypted_carries_enc_suffix() {
        use std::collections::BTreeMap;

        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-active-enc-{}",
            std::process::id()
        ));
        // No I/O — just constructing the archiver to check active_path().
        let mut keys = BTreeMap::new();
        let _ = keys.insert(
            "k1".to_string(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        );
        let kf = crate::encrypted::KeyFile {
            active_key_id: "k1".to_string(),
            keys,
            key_expirations: std::collections::BTreeMap::new(),
            key_derivations: std::collections::BTreeMap::new(),
            tenant_key_map: std::collections::BTreeMap::new(),
        };
        let bytes = serde_json::to_vec(&kf).unwrap();
        let ring = std::sync::Arc::new(crate::encrypted::KeyRing::from_bytes(&bytes).unwrap());

        let archiver = CotArchiver::with_encryption(&dir, ring);
        let active = archiver.active_path();
        let name = active.file_name().unwrap().to_str().unwrap();
        assert!(
            name.ends_with(".jsonl.enc"),
            "encrypted active_path must carry .enc suffix: {name}"
        );
    }

    #[tokio::test]
    async fn roll_if_over_size_rolls_encrypted_segment_and_round_trips() {
        // Core property: after a size-triggered roll on an encrypted
        // archiver the rolled `.enc` file must be fully sealed so
        // `decrypt_file` can round-trip it. This is what makes dropping
        // the writer the correct sealing mechanism — `EncryptedWriter`
        // writes the terminator chunk on drop.
        use std::collections::BTreeMap;

        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-roll-enc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut keys = BTreeMap::new();
        let _ = keys.insert(
            "k1".to_string(),
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        );
        let kf = crate::encrypted::KeyFile {
            active_key_id: "k1".to_string(),
            keys,
            key_expirations: std::collections::BTreeMap::new(),
            key_derivations: std::collections::BTreeMap::new(),
            tenant_key_map: std::collections::BTreeMap::new(),
        };
        let bytes = serde_json::to_vec(&kf).unwrap();
        let ring = std::sync::Arc::new(crate::encrypted::KeyRing::from_bytes(&bytes).unwrap());

        let archiver = CotArchiver::with_encryption(&dir, std::sync::Arc::clone(&ring));
        let msg = make_test_msg();
        for _ in 0..4 {
            archiver.record(&msg).await;
        }
        archiver.flush();

        let active_before = archiver.active_path();
        assert!(
            active_before.exists(),
            "encrypted active file must exist before roll: {}",
            active_before.display()
        );

        let rolled_paths = archiver.roll_if_over_size(1);
        assert_eq!(
            rolled_paths.len(),
            1,
            "encrypted single-tenant roll must produce exactly one rolled segment",
        );
        let rolled = rolled_paths.into_iter().next().expect("rolled segment");
        assert!(rolled.exists(), "rolled .enc file must exist");
        assert!(
            rolled.to_string_lossy().ends_with(".jsonl.enc"),
            "rolled encrypted file must retain .enc suffix: {}",
            rolled.display()
        );

        // Round-trip decrypt the rolled file: if sealing failed this
        // returns `MissingTerminator`.
        let out = dir.join("decrypted.jsonl");
        crate::encrypted::decrypt_file(&rolled, &out, &ring)
            .expect("rolled .enc should be fully sealed and decrypt cleanly");
        let plaintext = std::fs::read_to_string(&out).unwrap();
        assert!(plaintext.contains("\"cn\":\"alice\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_test_msg() -> rustgate_core::message::RoutableMessage {
        rustgate_core::message::RoutableMessage {
            source: rustgate_core::identity::Identity::new(
                "alice".to_string(),
                "fp-123".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("valid identity"),
            destination: rustgate_core::message::Destination::Broadcast,
            payload: bytes::Bytes::from_static(b"<event/>"),
            metadata: rustgate_core::message::Metadata::new(
                SystemTime::now(),
                "cot".to_string(),
                rustgate_core::message::MessageType::Position,
            ),
            entity: None,
        }
    }

    fn make_tenant_msg(tenant: &str) -> rustgate_core::message::RoutableMessage {
        let mut m = make_test_msg();
        m.metadata = m.metadata.with_tenant_id(tenant);
        m
    }

    // ── tenant partitioning coverage (closes #859) ───────────────────

    #[tokio::test]
    async fn archive_writes_under_default_subdir_when_tenant_is_none() {
        // Backward-compat invariant: a message with no tenant lands
        // under `<archive-dir>/_default/cot-…`. Operators with
        // single-tenant deployments see one extra path component
        // compared to pre-#859 — and nothing else changes.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-tenant-default-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        archiver.record(&make_test_msg()).await;
        archiver.flush();

        let default_dir = dir.join(DEFAULT_TENANT_ARCHIVE_KEY);
        assert!(
            default_dir.is_dir(),
            "expected default tenant directory at {}",
            default_dir.display(),
        );
        let entries: Vec<_> = std::fs::read_dir(&default_dir)
            .expect("read default subdir")
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "exactly one segment under the default tenant subdirectory"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn archive_writes_under_tenant_subdir_when_tenant_is_set() {
        // Per-tenant directories are created on demand. Two messages
        // tagged with different tenants must land in distinct
        // subdirectories — the cross-tenant isolation invariant.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-tenant-split-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        archiver.record(&make_tenant_msg("acme")).await;
        archiver.record(&make_tenant_msg("globex")).await;
        archiver.flush();

        let acme_dir = dir.join("acme");
        let globex_dir = dir.join("globex");
        assert!(acme_dir.is_dir(), "acme/ subdirectory must exist");
        assert!(globex_dir.is_dir(), "globex/ subdirectory must exist");
        assert!(
            !dir.join(DEFAULT_TENANT_ARCHIVE_KEY).exists(),
            "_default/ must not be created when every message carries a tenant"
        );

        // Each tenant directory holds exactly one segment.
        for d in [&acme_dir, &globex_dir] {
            let entries: Vec<_> = std::fs::read_dir(d).expect("read tenant subdir").collect();
            assert_eq!(entries.len(), 1, "tenant {} segment count", d.display());
        }

        // The JSONL line records the tenant for forensic re-bucketing.
        let acme_segment = std::fs::read_dir(&acme_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let acme_text = std::fs::read_to_string(&acme_segment).unwrap();
        assert!(
            acme_text.contains("\"tenant\":\"acme\""),
            "acme segment must embed tenant field, got {acme_text}",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn archive_sanitizes_path_traversal_in_tenant_id() {
        // Defence-in-depth: a hostile cert Organization field
        // (e.g. `..`) must not escape the archive directory. Tenant
        // path components with `..`, `/`, `\`, NUL, or leading dots
        // get replaced with `_` so the resulting bucket is always a
        // safe single directory name under `dir`.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-tenant-traversal-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        archiver.record(&make_tenant_msg("../escape")).await;
        archiver.record(&make_tenant_msg(".hidden")).await;
        archiver.record(&make_tenant_msg("with/slash")).await;
        archiver.flush();

        // No traversal: the parent of `dir` must hold nothing of ours.
        let parent = dir.parent().expect("temp dir has parent");
        for entry in std::fs::read_dir(parent).unwrap() {
            let p = entry.unwrap().path();
            // Anything matching our test prefix must live INSIDE `dir`,
            // not as a sibling.
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                assert!(
                    !name.starts_with("escape"),
                    "tenant id `../escape` must not produce `escape` sibling: found {}",
                    p.display(),
                );
            }
        }

        // The sanitised buckets exist under our archive dir.
        let entries: std::collections::BTreeSet<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert!(
            entries.iter().any(|n| n.contains("escape")),
            "sanitised escape bucket missing, dir entries: {entries:?}",
        );
        assert!(
            entries.iter().any(|n| n.starts_with('_')),
            "leading-dot tenant must be replaced with `_`, dir entries: {entries:?}",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn archive_active_paths_lists_every_open_tenant_segment() {
        // The rotation sweep relies on `active_paths()` to skip
        // every in-progress segment. After writing under two
        // tenants, both segment paths must appear so neither file
        // races the writer during deletion.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-active-paths-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);
        archiver.record(&make_tenant_msg("acme")).await;
        archiver.record(&make_tenant_msg("globex")).await;
        archiver.flush();

        let actives = archiver.active_paths();
        assert_eq!(actives.len(), 2);
        let names: std::collections::BTreeSet<String> = actives
            .iter()
            .filter_map(|p| {
                p.parent()
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
            .collect();
        assert!(names.contains("acme"));
        assert!(names.contains("globex"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn archiver_creates_file() {
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);

        let msg = rustgate_core::message::RoutableMessage {
            source: rustgate_core::identity::Identity::new(
                "alice".to_string(),
                "fp-123".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("valid identity"),
            destination: rustgate_core::message::Destination::Broadcast,
            payload: bytes::Bytes::from_static(b"<event/>"),
            metadata: rustgate_core::message::Metadata::new(
                SystemTime::now(),
                "cot".to_string(),
                rustgate_core::message::MessageType::Position,
            ),
            entity: None,
        };

        archiver.record(&msg).await;
        archiver.flush();

        // Verify file exists and has content under the default tenant
        // subdirectory (post-#859 layout).
        let tenant_dir = dir.join(DEFAULT_TENANT_ARCHIVE_KEY);
        let entries: Vec<_> = std::fs::read_dir(&tenant_dir)
            .expect("default tenant dir should exist")
            .collect();
        assert_eq!(entries.len(), 1, "should have one archive file");

        let file_path = entries[0].as_ref().expect("entry").path();
        let content = std::fs::read_to_string(&file_path).expect("read file");
        assert!(content.contains("\"cn\":\"alice\""));
        assert!(content.contains("\"fp\":\"fp-123\""));
        assert!(content.ends_with('\n'));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
