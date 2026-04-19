// Copyright © 2026 Roberto Chiofalo.

//! Streaming, append-friendly AEAD encryption for the CoT archive and audit
//! log sinks.
//!
//! Files written by [`EncryptedWriter`] are framed as a small fixed header
//! followed by a sequence of length-prefixed ChaCha20-Poly1305 chunks. Each
//! chunk uses a unique 96-bit nonce derived from a per-file random base nonce
//! and a monotonic chunk counter, so the same key may safely be reused across
//! many files and many chunks within a file.
//!
//! Per-chunk AAD binds the key id and chunk counter into the AEAD tag so that
//! reordering chunks within a file is detected at decrypt time, and a sealed
//! terminator chunk is written when the writer is finished so silent
//! tail-truncation is detectable on read.
//!
//! Key material is loaded from a JSON key file containing one or more named
//! keys plus an `active_key_id`. The active key is used for new writes; any
//! key still present in the file may be used to decrypt historical data,
//! enabling key rotation without rewriting the archive.
//!
//! ## File format (version 2)
//!
//! ```text
//! magic     : 8 bytes  = b"RGENC1\0\0"
//! version   : 1 byte   = 2
//! key_id_len: 1 byte
//! key_id    : key_id_len bytes (UTF-8)
//! base_nonce: 8 bytes (random)
//! repeated chunks:
//!   len     : 4 bytes (big-endian) length of `ciphertext`
//!   ciphertext: AEAD output (plaintext_len + 16-byte tag)
//! terminator chunk:
//!   len     : 4 bytes (big-endian)
//!   ciphertext: AEAD output of an empty plaintext sealed with the terminator
//!               AAD marker (see below)
//! ```
//!
//! Per-chunk nonce = `base_nonce (8 bytes) || counter_be (4 bytes)`. The
//! counter starts at 0 and increments by 1 per chunk. With a 32-bit counter
//! a single file can hold up to ~4.29 billion chunks before rollover, which
//! is enforced by returning an error.
//!
//! Per-chunk AAD layout (binds key id and chunk index, plus a 1-byte tag
//! distinguishing data from terminator chunks):
//!
//! ```text
//! aad = key_id_bytes || 0x00 (data) | 0x01 (terminator) || counter_be (4 bytes)
//! ```
//!
//! Tampering with any byte of the ciphertext, swapping two chunks, or
//! truncating the file before the terminator causes decryption to fail.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Magic bytes identifying a rustgate encrypted archive file.
pub const MAGIC: &[u8; 8] = b"RGENC1\0\0";
/// Current on-disk format version.
///
/// Version 2 adds per-chunk AAD binding (key id + chunk counter + chunk kind)
/// and a sealed terminator chunk to detect tail truncation. Files written by
/// version 1 are no longer readable; the format is intentionally not
/// backward-compatible because the v1 design was vulnerable to silent chunk
/// reordering and truncation.
pub const FORMAT_VERSION: u8 = 2;

/// AAD discriminator for normal data chunks.
const AAD_KIND_DATA: u8 = 0x00;
/// AAD discriminator for the terminator chunk.
const AAD_KIND_TERMINATOR: u8 = 0x01;

/// Errors produced by the encrypted archive subsystem.
#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    /// I/O failure reading or writing the underlying file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// AEAD encryption or authentication failure.
    #[error("aead error: {0}")]
    Aead(String),
    /// JSON parse error in the key file.
    #[error("invalid key file: {0}")]
    KeyFile(String),
    /// Hex/length validation error for a key value.
    #[error("invalid key material: {0}")]
    KeyMaterial(String),
    /// File header is missing, malformed, or unsupported.
    #[error("invalid header: {0}")]
    Header(String),
    /// Per-file chunk counter would overflow.
    #[error("chunk counter overflow")]
    CounterOverflow,
    /// The key id referenced in a file's header is not present in the key file.
    #[error("unknown key id: {0}")]
    UnknownKeyId(String),
    /// `KeyRing::active_key` was called but the configured `active_key_id` is
    /// not present in the in-memory key map (e.g. a `KeyRing` was constructed
    /// directly bypassing `from_bytes` validation).
    #[error("active key id {id:?} not present in key ring")]
    UnknownActiveKey {
        /// The missing active key id.
        id: String,
    },
    /// The shared writer's mutex was poisoned by a previous panic.
    #[error("encrypted writer mutex poisoned")]
    WriterPoisoned,
    /// The encrypted file ended before the sealed terminator chunk was reached.
    /// This indicates the file was truncated after writing.
    #[error("encrypted file truncated: terminator chunk missing")]
    Truncated,
    /// The target path resolves to a symbolic link. `EncryptedWriter` refuses
    /// to follow symlinks so a malicious local user cannot redirect a write
    /// to a sensitive file on a shared host. Unix only — on other platforms
    /// this variant is unreachable.
    #[error("target path is a symlink; refusing to follow")]
    SymlinkTarget {
        /// The offending path.
        path: PathBuf,
    },
}

/// On-disk JSON layout for the key file.
///
/// Keys are stored as 64-character lowercase hex strings (32 raw bytes,
/// the ChaCha20-Poly1305 key length).
///
/// Uses `deny_unknown_fields` to reject key files containing unexpected
/// properties — a typo like `"actve_key_id"` produces a clear
/// deserialization error instead of being silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    /// Identifier of the key used for new writes. Must be present in `keys`.
    pub active_key_id: String,
    /// All known keys, indexed by id.
    pub keys: BTreeMap<String, String>,
}

/// Loaded key material — keys decoded into raw bytes wrapped in
/// [`Zeroizing`] so they are wiped on drop.
#[derive(Clone)]
pub struct KeyRing {
    active_key_id: String,
    keys: BTreeMap<String, Arc<Zeroizing<[u8; 32]>>>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("active_key_id", &self.active_key_id)
            .field("key_count", &self.keys.len())
            .finish()
    }
}

impl KeyRing {
    /// Load a key ring from a JSON key file at `path`.
    pub fn load(path: &Path) -> Result<Self, EncryptError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Parse a key ring from raw JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptError> {
        let parsed: KeyFile =
            serde_json::from_slice(bytes).map_err(|e| EncryptError::KeyFile(e.to_string()))?;
        if parsed.active_key_id.is_empty() {
            return Err(EncryptError::KeyFile("active_key_id is empty".into()));
        }
        if !parsed.keys.contains_key(&parsed.active_key_id) {
            return Err(EncryptError::KeyFile(format!(
                "active_key_id {:?} not found in keys",
                parsed.active_key_id
            )));
        }
        let mut keys = BTreeMap::new();
        for (id, hex_value) in parsed.keys.iter() {
            let raw = hex::decode(hex_value)
                .map_err(|e| EncryptError::KeyMaterial(format!("key {id}: {e}")))?;
            if raw.len() != 32 {
                return Err(EncryptError::KeyMaterial(format!(
                    "key {id}: expected 32 bytes, got {}",
                    raw.len()
                )));
            }
            let mut buf = Zeroizing::new([0u8; 32]);
            buf.copy_from_slice(&raw);
            let _ = keys.insert(id.clone(), Arc::new(buf));
        }
        Ok(Self {
            active_key_id: parsed.active_key_id,
            keys,
        })
    }

    /// Identifier of the currently active key.
    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    /// Look up a key by id, returning its raw 32 bytes.
    pub fn key(&self, id: &str) -> Option<Arc<Zeroizing<[u8; 32]>>> {
        self.keys.get(id).cloned()
    }

    /// Convenience: the active key.
    ///
    /// Returns [`EncryptError::UnknownActiveKey`] if the configured
    /// `active_key_id` is not present in the in-memory key map. This can only
    /// happen when a `KeyRing` is constructed directly (bypassing
    /// [`KeyRing::from_bytes`], which enforces the invariant). Returning an
    /// error rather than falling back to a sentinel key prevents accidentally
    /// encrypting data with an all-zero key.
    pub fn active_key(&self) -> Result<Arc<Zeroizing<[u8; 32]>>, EncryptError> {
        self.keys
            .get(&self.active_key_id)
            .cloned()
            .ok_or_else(|| EncryptError::UnknownActiveKey {
                id: self.active_key_id.clone(),
            })
    }
}

/// A streaming AEAD writer that appends length-prefixed ChaCha20-Poly1305
/// chunks to a single file. Each call to [`EncryptedWriter::write_chunk`]
/// produces exactly one sealed chunk.
///
/// Writes are buffered via [`BufWriter`]; call [`EncryptedWriter::flush`]
/// to force them to disk.
///
/// **Call [`EncryptedWriter::finish`] (or drop the writer) before considering
/// the file complete.** `finish` writes a sealed terminator chunk; without it
/// readers will reject the file as [`EncryptError::Truncated`]. The `Drop`
/// impl makes a best-effort call to `finish`, but explicit `finish` is
/// preferred so errors are surfaced.
pub struct EncryptedWriter {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    base_nonce: [u8; 8],
    counter: u32,
    writer: Option<BufWriter<File>>,
    key_id_bytes: Vec<u8>,
    finished: bool,
}

impl std::fmt::Debug for EncryptedWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedWriter")
            .field("path", &self.path)
            .field("counter", &self.counter)
            .field("finished", &self.finished)
            .finish()
    }
}

impl EncryptedWriter {
    /// Create or open `path` for writing.
    ///
    /// **WARNING: This is destructive and not resumable.** If `path` already
    /// exists it will be **truncated** — the encrypted stream cannot be
    /// resumed across process restarts because the per-file random base nonce
    /// and chunk counter live only in memory and would otherwise produce
    /// catastrophic nonce reuse on append. Callers that need rotation should
    /// use a fresh path per rotation window (e.g. a new file per UTC date).
    pub fn create(path: &Path, key_ring: &KeyRing) -> Result<Self, EncryptError> {
        let key_id = key_ring.active_key_id().to_string();
        let key_bytes = key_ring.active_key()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let mut base_nonce = [0u8; 8];
        getrandom(&mut base_nonce)?;

        // Refuse to follow a symlink at the final path component.
        //
        // On a multi-tenant host, an attacker who can plant a symlink at
        // `path` could otherwise trick us into truncating and overwriting
        // whatever file the symlink points to — a sensitive file owned by
        // a different principal, for example. `O_NOFOLLOW` is the atomic
        // TOCTOU-free defense: the open() call itself fails with `ELOOP`
        // (or `EMLINK` on some platforms) when the terminal component is
        // a symlink, which we translate into `EncryptError::SymlinkTarget`
        // so callers can surface a clear error. Intermediate symlinks in
        // the path are still followed; the policy here is "don't follow
        // the tip", matching how `open(O_NOFOLLOW)` is defined on Linux.
        let file = open_no_follow(path)?;
        let mut writer = BufWriter::new(file);

        // Write header
        writer.write_all(MAGIC)?;
        writer.write_all(&[FORMAT_VERSION])?;
        let id_bytes = key_id.as_bytes();
        if id_bytes.len() > u8::MAX as usize {
            return Err(EncryptError::Header("key id longer than 255 bytes".into()));
        }
        writer.write_all(&[id_bytes.len() as u8])?;
        writer.write_all(id_bytes)?;
        writer.write_all(&base_nonce)?;

        Ok(Self {
            path: path.to_path_buf(),
            cipher,
            base_nonce,
            counter: 0,
            writer: Some(writer),
            key_id_bytes: id_bytes.to_vec(),
            finished: false,
        })
    }

    /// Build the per-chunk AAD: `key_id || kind || counter_be`.
    fn build_aad(&self, kind: u8) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.key_id_bytes.len() + 1 + 4);
        aad.extend_from_slice(&self.key_id_bytes);
        aad.push(kind);
        aad.extend_from_slice(&self.counter.to_be_bytes());
        aad
    }

    /// Encrypt and append a single chunk of plaintext.
    pub fn write_chunk(&mut self, plaintext: &[u8]) -> Result<(), EncryptError> {
        if self.finished {
            return Err(EncryptError::Aead("writer already finished".into()));
        }
        // Reserve the post-increment BEFORE we seal and write the chunk.
        //
        // ChaCha20-Poly1305 is catastrophically insecure under nonce reuse.
        // The old code called `checked_add(1)` *after* writing, so if the
        // counter was at `u32::MAX` we would seal + persist a chunk with
        // nonce `(base, u32::MAX)`, fail the increment, and leave the
        // counter pinned at `u32::MAX`. A subsequent `finish()` — or any
        // caller ignoring the `CounterOverflow` error — would then seal
        // the terminator using the same nonce as the last data chunk.
        // Checking overflow up-front makes refusal atomic: if we cannot
        // advance, we do not write.
        let next_counter = self
            .counter
            .checked_add(1)
            .ok_or(EncryptError::CounterOverflow)?;
        let nonce = chunk_nonce(&self.base_nonce, self.counter);
        let aad = self.build_aad(AAD_KIND_DATA);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| EncryptError::Aead(e.to_string()))?;
        let len = u32::try_from(ciphertext.len())
            .map_err(|_| EncryptError::Aead("ciphertext too large".into()))?;
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| EncryptError::Aead("writer already closed".into()))?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(&ciphertext)?;
        self.counter = next_counter;
        Ok(())
    }

    /// Flush buffered writes to the underlying file.
    pub fn flush(&mut self) -> Result<(), EncryptError> {
        if let Some(w) = self.writer.as_mut() {
            w.flush()?;
        }
        Ok(())
    }

    /// Seal the stream by writing a terminator chunk and flushing. After
    /// `finish` returns successfully, no further chunks may be written.
    /// Decryption requires the terminator to be present.
    pub fn finish(&mut self) -> Result<(), EncryptError> {
        if self.finished {
            return Ok(());
        }
        // Reserve the post-increment before sealing the terminator — see
        // the equivalent guard in `write_chunk` for the nonce-reuse threat
        // model. Refusal must be atomic or we risk writing the terminator
        // with the same nonce as the last data chunk.
        let next_counter = self
            .counter
            .checked_add(1)
            .ok_or(EncryptError::CounterOverflow)?;
        let nonce = chunk_nonce(&self.base_nonce, self.counter);
        let aad = self.build_aad(AAD_KIND_TERMINATOR);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &[][..],
                    aad: &aad,
                },
            )
            .map_err(|e| EncryptError::Aead(e.to_string()))?;
        let len = u32::try_from(ciphertext.len())
            .map_err(|_| EncryptError::Aead("ciphertext too large".into()))?;
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| EncryptError::Aead("writer already closed".into()))?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(&ciphertext)?;
        writer.flush()?;
        self.counter = next_counter;
        self.finished = true;
        Ok(())
    }
}

impl Drop for EncryptedWriter {
    fn drop(&mut self) {
        if !self.finished && self.writer.is_some() {
            let _ = self.finish();
        }
    }
}

/// Decrypt the entire encrypted file at `input` and write the recovered
/// plaintext to `output`. The key file must contain the key id referenced
/// in the input header — even if it is no longer the active key.
///
/// Returns [`EncryptError::Truncated`] if the file ends before a sealed
/// terminator chunk is reached.
pub fn decrypt_file(input: &Path, output: &Path, key_ring: &KeyRing) -> Result<(), EncryptError> {
    let in_file = File::open(input)?;
    let mut reader = BufReader::new(in_file);

    // Header
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(EncryptError::Header("magic mismatch".into()));
    }
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != FORMAT_VERSION {
        return Err(EncryptError::Header(format!(
            "unsupported version {}",
            version[0]
        )));
    }
    let mut id_len = [0u8; 1];
    reader.read_exact(&mut id_len)?;
    let mut id_buf = vec![0u8; id_len[0] as usize];
    reader.read_exact(&mut id_buf)?;
    let key_id = String::from_utf8(id_buf)
        .map_err(|e| EncryptError::Header(format!("key id not UTF-8: {e}")))?;
    let key_id_bytes = key_id.as_bytes().to_vec();
    let mut base_nonce = [0u8; 8];
    reader.read_exact(&mut base_nonce)?;

    let key_bytes = key_ring
        .key(&key_id)
        .ok_or_else(|| EncryptError::UnknownKeyId(key_id.clone()))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output)?;
    let mut writer = BufWriter::new(out_file);

    let mut counter: u32 = 0;
    let mut saw_terminator = false;
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(EncryptError::Io(e)),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut chunk = vec![0u8; len];
        reader.read_exact(&mut chunk)?;
        let nonce = chunk_nonce(&base_nonce, counter);

        // Try data AAD first; if that fails, try terminator AAD.
        let mut aad_data = Vec::with_capacity(key_id_bytes.len() + 5);
        aad_data.extend_from_slice(&key_id_bytes);
        aad_data.push(AAD_KIND_DATA);
        aad_data.extend_from_slice(&counter.to_be_bytes());

        match cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: chunk.as_ref(),
                aad: &aad_data,
            },
        ) {
            Ok(plaintext) => {
                writer.write_all(&plaintext)?;
            }
            Err(_) => {
                // Maybe terminator
                let mut aad_term = Vec::with_capacity(key_id_bytes.len() + 5);
                aad_term.extend_from_slice(&key_id_bytes);
                aad_term.push(AAD_KIND_TERMINATOR);
                aad_term.extend_from_slice(&counter.to_be_bytes());
                let plaintext = cipher
                    .decrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: chunk.as_ref(),
                            aad: &aad_term,
                        },
                    )
                    .map_err(|e| EncryptError::Aead(e.to_string()))?;
                if !plaintext.is_empty() {
                    return Err(EncryptError::Aead(
                        "terminator chunk had non-empty plaintext".into(),
                    ));
                }
                saw_terminator = true;
                // Terminator must be the final chunk; any trailing bytes
                // indicate corruption.
                let mut trailing = [0u8; 1];
                match reader.read_exact(&mut trailing) {
                    Ok(()) => {
                        return Err(EncryptError::Aead(
                            "data found after terminator chunk".into(),
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(EncryptError::Io(e)),
                }
            }
        }
        counter = counter
            .checked_add(1)
            .ok_or(EncryptError::CounterOverflow)?;
    }

    if !saw_terminator {
        return Err(EncryptError::Truncated);
    }

    writer.flush()?;
    Ok(())
}

/// Build the 12-byte ChaCha20-Poly1305 nonce from the file's base nonce and
/// the chunk counter.
fn chunk_nonce(base: &[u8; 8], counter: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(base);
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Platform-specific `O_NOFOLLOW` value.
///
/// The constant is defined in each platform's `<fcntl.h>` and the numeric
/// value differs across Unix flavours. We pin the values explicitly rather
/// than pulling in the `libc` crate for one flag, since adding a new
/// workspace dep for a single constant would be out of proportion.
#[cfg(unix)]
const fn o_nofollow() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        0x20000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    {
        0x0100
    }
    // Any other Unix variant falls back to the Linux value; unknown targets
    // would need explicit vetting but the workspace only ships Linux and
    // macOS builds today.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    {
        0x20000
    }
}

/// Open `path` for write+truncate+create, refusing to follow a terminal
/// symlink. See the comment in [`EncryptedWriter::create`] for the threat
/// model.
fn open_no_follow(path: &Path) -> Result<File, EncryptError> {
    let mut opts = OpenOptions::new();
    let _ = opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        let _ = opts.custom_flags(o_nofollow());
    }
    match opts.open(path) {
        Ok(f) => Ok(f),
        Err(e) => Err(translate_open_err(path, e)),
    }
}

/// Translate an `open()` error, promoting the `O_NOFOLLOW` rejection into
/// [`EncryptError::SymlinkTarget`] so callers can distinguish a planted
/// symlink from a generic I/O failure.
fn translate_open_err(path: &Path, e: std::io::Error) -> EncryptError {
    #[cfg(unix)]
    {
        // Linux: ELOOP = 40. macOS / BSD: ELOOP = 62. On macOS some kernels
        // return EMLINK for `O_NOFOLLOW` denial instead of ELOOP; accept both.
        // We match on raw_os_error so we don't depend on std's ErrorKind
        // taxonomy, which is not stable across Rust versions for this case.
        const ELOOP_LINUX: i32 = 40;
        const ELOOP_BSD: i32 = 62;
        const EMLINK_BSD: i32 = 31;
        if let Some(code) = e.raw_os_error()
            && matches!(code, ELOOP_LINUX | ELOOP_BSD | EMLINK_BSD)
        {
            return EncryptError::SymlinkTarget {
                path: path.to_path_buf(),
            };
        }
    }
    EncryptError::Io(e)
}

/// A thread-safe wrapper around [`EncryptedWriter`] suitable for sharing
/// between async tasks via `Arc`.
#[derive(Debug)]
pub struct SharedEncryptedWriter {
    inner: Mutex<EncryptedWriter>,
}

impl SharedEncryptedWriter {
    /// Create a new shared writer at `path`.
    pub fn create(path: &Path, key_ring: &KeyRing) -> Result<Self, EncryptError> {
        Ok(Self {
            inner: Mutex::new(EncryptedWriter::create(path, key_ring)?),
        })
    }

    /// Encrypt and append a chunk, then flush so each line is durable.
    pub fn write_line(&self, plaintext: &[u8]) -> Result<(), EncryptError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| EncryptError::WriterPoisoned)?;
        guard.write_chunk(plaintext)?;
        guard.flush()?;
        Ok(())
    }

    /// Seal the underlying writer by writing the terminator chunk.
    pub fn finish(&self) -> Result<(), EncryptError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| EncryptError::WriterPoisoned)?;
        guard.finish()
    }
}

/// Fill `dest` with cryptographically random bytes via the OS.
fn getrandom(dest: &mut [u8]) -> Result<(), EncryptError> {
    use chacha20poly1305::aead::OsRng;
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut rng = OsRng;
    rng.try_fill_bytes(dest)
        .map_err(|e| EncryptError::Aead(format!("rng: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_key_ring(active: &str, keys: &[(&str, [u8; 32])]) -> KeyRing {
        let mut map = BTreeMap::new();
        for (id, raw) in keys {
            let _ = map.insert((*id).to_string(), hex::encode(raw));
        }
        let kf = KeyFile {
            active_key_id: active.to_string(),
            keys: map,
        };
        let json = serde_json::to_vec(&kf).unwrap();
        KeyRing::from_bytes(&json).unwrap()
    }

    #[test]
    fn round_trip_single_chunk() {
        let dir = tempdir();
        let enc_path = dir.join("a.enc");
        let dec_path = dir.join("a.txt");
        let ring = make_key_ring("k1", &[("k1", [0x11; 32])]);

        {
            let mut w = EncryptedWriter::create(&enc_path, &ring).unwrap();
            w.write_chunk(b"hello world\n").unwrap();
            w.finish().unwrap();
        }
        decrypt_file(&enc_path, &dec_path, &ring).unwrap();
        assert_eq!(std::fs::read(&dec_path).unwrap(), b"hello world\n");
    }

    #[test]
    fn round_trip_many_chunks() {
        let dir = tempdir();
        let enc_path = dir.join("b.enc");
        let dec_path = dir.join("b.txt");
        let ring = make_key_ring("k1", &[("k1", [0x22; 32])]);

        let mut expected = Vec::new();
        {
            let mut w = EncryptedWriter::create(&enc_path, &ring).unwrap();
            for i in 0..50u32 {
                let line = format!("line-{i}\n");
                w.write_chunk(line.as_bytes()).unwrap();
                expected.extend_from_slice(line.as_bytes());
            }
            w.finish().unwrap();
        }
        decrypt_file(&enc_path, &dec_path, &ring).unwrap();
        assert_eq!(std::fs::read(&dec_path).unwrap(), expected);
    }

    #[test]
    fn tamper_detection() {
        let dir = tempdir();
        let enc_path = dir.join("c.enc");
        let dec_path = dir.join("c.txt");
        let ring = make_key_ring("k1", &[("k1", [0x33; 32])]);

        {
            let mut w = EncryptedWriter::create(&enc_path, &ring).unwrap();
            w.write_chunk(b"sensitive payload").unwrap();
            w.finish().unwrap();
        }

        // Flip a byte well past the header.
        let mut data = std::fs::read(&enc_path).unwrap();
        let target = data.len() - 1;
        data[target] ^= 0x01;
        let mut f = std::fs::File::create(&enc_path).unwrap();
        f.write_all(&data).unwrap();
        drop(f);

        let err = decrypt_file(&enc_path, &dec_path, &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Aead(_)), "got {err:?}");
    }

    #[test]
    fn key_rotation_old_key_still_decrypts() {
        let dir = tempdir();
        let enc_path = dir.join("d.enc");
        let dec_path = dir.join("d.txt");

        let ring_old = make_key_ring("k1", &[("k1", [0x44; 32])]);
        {
            let mut w = EncryptedWriter::create(&enc_path, &ring_old).unwrap();
            w.write_chunk(b"historical data\n").unwrap();
            w.finish().unwrap();
        }

        let ring_new = make_key_ring("k2", &[("k1", [0x44; 32]), ("k2", [0x55; 32])]);
        decrypt_file(&enc_path, &dec_path, &ring_new).unwrap();
        assert_eq!(std::fs::read(&dec_path).unwrap(), b"historical data\n");
    }

    #[test]
    fn rejects_unknown_key_id() {
        let dir = tempdir();
        let enc_path = dir.join("e.enc");
        let dec_path = dir.join("e.txt");

        let ring_a = make_key_ring("k1", &[("k1", [0x66; 32])]);
        {
            let mut w = EncryptedWriter::create(&enc_path, &ring_a).unwrap();
            w.write_chunk(b"x").unwrap();
            w.finish().unwrap();
        }
        let ring_b = make_key_ring("k2", &[("k2", [0x77; 32])]);
        let err = decrypt_file(&enc_path, &dec_path, &ring_b).unwrap_err();
        assert!(matches!(err, EncryptError::UnknownKeyId(_)));
    }

    #[test]
    fn rejects_bad_magic() {
        let dir = tempdir();
        let p = dir.join("bad.enc");
        std::fs::write(&p, b"NOTRGENC........").unwrap();
        let ring = make_key_ring("k1", &[("k1", [0x88; 32])]);
        let err = decrypt_file(&p, &dir.join("out"), &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Header(_)));
    }

    #[test]
    fn key_file_validation() {
        let bad = br#"{"active_key_id":"missing","keys":{"k1":"00"}}"#;
        let err = KeyRing::from_bytes(bad).unwrap_err();
        assert!(matches!(err, EncryptError::KeyFile(_)));

        let bad2 = br#"{"active_key_id":"k1","keys":{"k1":"00"}}"#;
        let err2 = KeyRing::from_bytes(bad2).unwrap_err();
        assert!(matches!(err2, EncryptError::KeyMaterial(_)));
    }

    #[test]
    fn active_key_missing_from_map_returns_error() {
        // Construct a KeyRing directly with an active id that has no entry,
        // bypassing from_bytes validation.
        let ring = KeyRing {
            active_key_id: "ghost".to_string(),
            keys: BTreeMap::new(),
        };
        let err = ring.active_key().unwrap_err();
        match err {
            EncryptError::UnknownActiveKey { id } => assert_eq!(id, "ghost"),
            other => panic!("expected UnknownActiveKey, got {other:?}"),
        }
    }

    #[test]
    fn chunk_swap_detected() {
        let dir = tempdir();
        let enc_path = dir.join("swap.enc");
        let dec_path = dir.join("swap.txt");
        let ring = make_key_ring("k1", &[("k1", [0x99; 32])]);

        {
            let mut w = EncryptedWriter::create(&enc_path, &ring).unwrap();
            w.write_chunk(b"chunk-AAA").unwrap();
            w.write_chunk(b"chunk-BBB").unwrap();
            w.finish().unwrap();
        }

        // Parse out the file: header, then two data chunks (each len-prefix +
        // ciphertext), then a terminator. Swap the two data chunks.
        let data = std::fs::read(&enc_path).unwrap();
        // header = 8 magic + 1 version + 1 id_len + id_len + 8 base_nonce
        let id_len = data[9] as usize;
        let header_end = 8 + 1 + 1 + id_len + 8;

        let mut cursor = header_end;
        let read_chunk = |data: &[u8], cursor: &mut usize| -> Vec<u8> {
            let len_bytes: [u8; 4] = data[*cursor..*cursor + 4].try_into().unwrap();
            let len = u32::from_be_bytes(len_bytes) as usize;
            let total = 4 + len;
            let chunk = data[*cursor..*cursor + total].to_vec();
            *cursor += total;
            chunk
        };
        let c0 = read_chunk(&data, &mut cursor);
        let c1 = read_chunk(&data, &mut cursor);
        let term = read_chunk(&data, &mut cursor);

        let mut rebuilt = Vec::new();
        rebuilt.extend_from_slice(&data[..header_end]);
        rebuilt.extend_from_slice(&c1);
        rebuilt.extend_from_slice(&c0);
        rebuilt.extend_from_slice(&term);

        std::fs::write(&enc_path, &rebuilt).unwrap();

        let err = decrypt_file(&enc_path, &dec_path, &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Aead(_)), "got {err:?}");
    }

    #[test]
    fn truncated_tail_detected() {
        let dir = tempdir();
        let enc_path = dir.join("trunc.enc");
        let dec_path = dir.join("trunc.txt");
        let ring = make_key_ring("k1", &[("k1", [0xaa; 32])]);

        {
            let mut w = EncryptedWriter::create(&enc_path, &ring).unwrap();
            w.write_chunk(b"first").unwrap();
            w.write_chunk(b"second").unwrap();
            w.finish().unwrap();
        }

        // Strip the trailing terminator chunk.
        let data = std::fs::read(&enc_path).unwrap();
        let id_len = data[9] as usize;
        let header_end = 8 + 1 + 1 + id_len + 8;

        let mut cursor = header_end;
        let read_chunk_end = |data: &[u8], cursor: &mut usize| {
            let len_bytes: [u8; 4] = data[*cursor..*cursor + 4].try_into().unwrap();
            let len = u32::from_be_bytes(len_bytes) as usize;
            *cursor += 4 + len;
        };
        read_chunk_end(&data, &mut cursor); // first
        read_chunk_end(&data, &mut cursor); // second
        let truncate_at = cursor; // drop terminator and anything after

        std::fs::write(&enc_path, &data[..truncate_at]).unwrap();

        let err = decrypt_file(&enc_path, &dec_path, &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Truncated), "got {err:?}");
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rustgate-enc-test-{}-{}",
            std::process::id(),
            fastrand_u64()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn fastrand_u64() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    #[test]
    fn key_file_rejects_unknown_field() {
        let json = r#"{"active_key_id":"k1","keys":{},"extra":true}"#;
        let result = serde_json::from_str::<KeyFile>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}"
        );
    }

    // --- F-31: symlink TOCTOU ---

    #[cfg(unix)]
    #[test]
    fn create_refuses_to_follow_symlink_at_target() {
        use std::os::unix::fs::symlink;

        let dir = tempdir();
        // Plant a sensitive file the attacker would like us to clobber.
        let sensitive = dir.join("sensitive.dat");
        std::fs::write(&sensitive, b"I should not be overwritten").unwrap();
        // Attacker places a symlink at the path we are asked to write to,
        // pointing at the sensitive file.
        let enc_path = dir.join("archive.enc");
        symlink(&sensitive, &enc_path).unwrap();

        let ring = make_key_ring("k1", &[("k1", [0xcc; 32])]);
        let err = EncryptedWriter::create(&enc_path, &ring).unwrap_err();
        match err {
            EncryptError::SymlinkTarget { path } => assert_eq!(path, enc_path),
            other => panic!("expected SymlinkTarget, got {other:?}"),
        }

        // The sensitive file is untouched.
        assert_eq!(
            std::fs::read(&sensitive).unwrap(),
            b"I should not be overwritten"
        );
    }

    // --- F-33: counter overflow never writes + never reuses a nonce ---

    #[test]
    fn write_chunk_at_counter_max_refuses_before_writing() {
        let dir = tempdir();
        let enc_path = dir.join("counter_max.enc");
        let ring = make_key_ring("k1", &[("k1", [0xdd; 32])]);

        // Write a normal chunk first so the header + one data chunk are on disk.
        let pre_len = {
            let mut w = EncryptedWriter::create(&enc_path, &ring).unwrap();
            w.write_chunk(b"ok").unwrap();
            // Force the next call to exhaust the counter.
            w.counter = u32::MAX;
            w.flush().unwrap();
            let len_after_flush = std::fs::metadata(&enc_path).unwrap().len();

            let err = w.write_chunk(b"would-overflow").unwrap_err();
            assert!(matches!(err, EncryptError::CounterOverflow));
            // Counter must not have advanced past u32::MAX (no silent wrap).
            assert_eq!(w.counter, u32::MAX);
            // The failed write must not have appended anything to disk.
            w.flush().unwrap();
            let len_after_fail = std::fs::metadata(&enc_path).unwrap().len();
            assert_eq!(
                len_after_flush, len_after_fail,
                "failed write_chunk must not append bytes to the file"
            );

            // A follow-up finish() must also refuse — without this guard the
            // terminator would reuse the nonce of the previous call.
            let err2 = w.finish().unwrap_err();
            assert!(matches!(err2, EncryptError::CounterOverflow));
            // No partial terminator was written either.
            let len_after_finish = std::fs::metadata(&enc_path).unwrap().len();
            assert_eq!(len_after_flush, len_after_finish);
            len_after_flush
        };

        // Drop the writer without a successful finish. The file on disk has
        // no terminator (we refused to write one), so decrypt_file should
        // report Truncated — which is exactly the outcome we want: a user
        // who hit the counter cap is forced to rotate the key or the file,
        // not to trust a partially-sealed archive.
        let dec_path = dir.join("counter_max.txt");
        let err = decrypt_file(&enc_path, &dec_path, &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Truncated), "got {err:?}");
        let _ = pre_len; // silence unused-binding when the assert above passes
    }
}
