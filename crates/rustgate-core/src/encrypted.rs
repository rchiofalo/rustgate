//! Streaming, append-friendly AEAD encryption for the CoT archive and audit
//! log sinks.
//!
//! Files written by [`EncryptedWriter`] are framed as a small fixed header
//! followed by a sequence of length-prefixed ChaCha20-Poly1305 chunks. Each
//! chunk uses a unique 96-bit nonce derived from a per-file random base nonce
//! and a monotonic chunk counter, so the same key may safely be reused across
//! many files and many chunks within a file.
//!
//! Key material is loaded from a JSON key file containing one or more named
//! keys plus an `active_key_id`. The active key is used for new writes; any
//! key still present in the file may be used to decrypt historical data,
//! enabling key rotation without rewriting the archive.
//!
//! ## File format
//!
//! ```text
//! magic     : 8 bytes  = b"RGENC1\0\0"
//! version   : 1 byte   = 1
//! key_id_len: 1 byte
//! key_id    : key_id_len bytes (UTF-8)
//! base_nonce: 8 bytes (random)
//! repeated chunks:
//!   len     : 4 bytes (big-endian) length of `ciphertext`
//!   ciphertext: AEAD output (plaintext_len + 16-byte tag)
//! ```
//!
//! Per-chunk nonce = `base_nonce (8 bytes) || counter_be (4 bytes)`. The
//! counter starts at 0 and increments by 1 per chunk. With a 32-bit counter
//! a single file can hold up to ~4.29 billion chunks before rollover, which
//! is enforced by returning an error.
//!
//! Tampering with any byte of the ciphertext (or truncating a chunk) causes
//! the AEAD `decrypt` step to fail, surfacing as [`EncryptError::Aead`] from
//! [`decrypt_file`].

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Magic bytes identifying a rustgate encrypted archive file.
pub const MAGIC: &[u8; 8] = b"RGENC1\0\0";
/// Current on-disk format version.
pub const FORMAT_VERSION: u8 = 1;

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
}

/// On-disk JSON layout for the key file.
///
/// Keys are stored as 64-character lowercase hex strings (32 raw bytes,
/// the ChaCha20-Poly1305 key length).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn active_key(&self) -> Arc<Zeroizing<[u8; 32]>> {
        // Construction enforces presence of active_key_id; fall back is unreachable
        // but we handle it without panicking.
        self.keys
            .get(&self.active_key_id)
            .cloned()
            .unwrap_or_else(|| Arc::new(Zeroizing::new([0u8; 32])))
    }
}

/// A streaming AEAD writer that appends length-prefixed ChaCha20-Poly1305
/// chunks to a single file. Each call to [`EncryptedWriter::write_chunk`]
/// produces exactly one sealed chunk.
///
/// Writes are buffered via [`BufWriter`]; call [`EncryptedWriter::flush`]
/// to force them to disk.
pub struct EncryptedWriter {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    base_nonce: [u8; 8],
    counter: u32,
    writer: BufWriter<File>,
}

impl std::fmt::Debug for EncryptedWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedWriter")
            .field("path", &self.path)
            .field("counter", &self.counter)
            .finish()
    }
}

impl EncryptedWriter {
    /// Create or open `path` for writing. If the file already exists this
    /// truncates it — encrypted streams are not designed to be resumed mid-file
    /// because the per-file random base nonce would be lost. Callers that need
    /// per-day rotation should use distinct paths.
    pub fn create(path: &Path, key_ring: &KeyRing) -> Result<Self, EncryptError> {
        let key_id = key_ring.active_key_id().to_string();
        let key_bytes = key_ring.active_key();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let mut base_nonce = [0u8; 8];
        getrandom(&mut base_nonce)?;

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
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
            writer,
        })
    }

    /// Encrypt and append a single chunk of plaintext.
    pub fn write_chunk(&mut self, plaintext: &[u8]) -> Result<(), EncryptError> {
        let nonce = chunk_nonce(&self.base_nonce, self.counter);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| EncryptError::Aead(e.to_string()))?;
        let len = u32::try_from(ciphertext.len())
            .map_err(|_| EncryptError::Aead("ciphertext too large".into()))?;
        self.writer.write_all(&len.to_be_bytes())?;
        self.writer.write_all(&ciphertext)?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(EncryptError::CounterOverflow)?;
        Ok(())
    }

    /// Flush buffered writes to the underlying file.
    pub fn flush(&mut self) -> Result<(), EncryptError> {
        self.writer.flush()?;
        Ok(())
    }
}

/// Decrypt the entire encrypted file at `input` and write the recovered
/// plaintext to `output`. The key file must contain the key id referenced
/// in the input header — even if it is no longer the active key.
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
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), chunk.as_ref())
            .map_err(|e| EncryptError::Aead(e.to_string()))?;
        writer.write_all(&plaintext)?;
        counter = counter
            .checked_add(1)
            .ok_or(EncryptError::CounterOverflow)?;
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
            .map_err(|_| EncryptError::Aead("writer mutex poisoned".into()))?;
        guard.write_chunk(plaintext)?;
        guard.flush()?;
        Ok(())
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
            w.flush().unwrap();
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
            w.flush().unwrap();
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
            let mut w = EncryptedWriter::create(ring_path_helper(&enc_path), &ring).unwrap();
            w.write_chunk(b"sensitive payload").unwrap();
            w.flush().unwrap();
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

    // Helper that just returns the input — kept for symmetry/clarity.
    fn ring_path_helper(p: &Path) -> &Path {
        p
    }

    #[test]
    fn key_rotation_old_key_still_decrypts() {
        let dir = tempdir();
        let enc_path = dir.join("d.enc");
        let dec_path = dir.join("d.txt");

        // Write with old key as active.
        let ring_old = make_key_ring("k1", &[("k1", [0x44; 32])]);
        {
            let mut w = EncryptedWriter::create(&enc_path, &ring_old).unwrap();
            w.write_chunk(b"historical data\n").unwrap();
            w.flush().unwrap();
        }

        // Rotate: k2 is now active but k1 is still on the ring.
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
            w.flush().unwrap();
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
        // Missing active key id in keys
        let bad = br#"{"active_key_id":"missing","keys":{"k1":"00"}}"#;
        let err = KeyRing::from_bytes(bad).unwrap_err();
        assert!(matches!(err, EncryptError::KeyFile(_)));

        // Wrong key length
        let bad2 = br#"{"active_key_id":"k1","keys":{"k1":"00"}}"#;
        let err2 = KeyRing::from_bytes(bad2).unwrap_err();
        assert!(matches!(err2, EncryptError::KeyMaterial(_)));
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
}
