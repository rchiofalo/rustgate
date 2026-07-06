// Copyright © 2026 Roberto Chiofalo.

//! Streaming, append-friendly AEAD encryption for the CoT archive and audit
//! log sinks.
//!
//! Files written by [`EncryptedWriter`] are framed as a small fixed header
//! followed by a sequence of length-prefixed XChaCha20-Poly1305 chunks (format
//! version 3). Each chunk uses a unique 192-bit nonce derived from a per-file
//! random base nonce and a monotonic chunk counter. The base nonce carries 160
//! bits of randomness, so two files drawing the same base under one key has a
//! birthday bound of ~2^80 files — the same key may safely be reused across a
//! practically unbounded number of files (#1506). Version 2 archives
//! (ChaCha20-Poly1305, 64-bit base nonce) remain fully decryptable via
//! [`decrypt_file`]; only the writer was bumped to v3.
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
//! ## Per-tenant key resolution (seam)
//!
//! The key file may carry an optional `tenant_key_map` mapping a tenant id
//! (the certificate `O` field, matching the bucket already used to
//! path-namespace archives) to the key id that tenant's archives should be
//! encrypted under. [`KeyRing::key_id_for_tenant`] resolves a tenant to its
//! key id (falling back to the active key for unmapped / tenant-less
//! traffic), [`KeyRing::key_for_tenant`] returns the resolved key material,
//! and [`EncryptedWriter::create_for_tenant`] opens a file under the
//! tenant's key. An empty map — the default — makes every accessor resolve
//! to the active key, so existing single-key deployments are unchanged.
//!
//! This is the resolution seam only: the archive write path does not yet
//! pass a real tenant into the writer. The wiring is a follow-up slice — see
//! [ADR 0034](../../../docs/adr/0034-multi-tenant-at-rest-isolation.md),
//! which also records the nonce-domain and misconfiguration risks that the
//! wiring slice must address.
//!
//! ## Key derivation
//!
//! Operators have three options for how a 32-byte key reaches the [`KeyRing`]:
//!
//! 1. **Raw hex**: a 64-character lowercase hex string under
//!    `keys.<id>.value` (the legacy shape — pre-existing key files keep
//!    working without modification).
//! 2. **HKDF-SHA256** (`Derivation::HkdfSha256`): an extract-and-expand KDF
//!    over a high-entropy root secret (KMS blob, HSM output, another rustgate
//!    deployment's master key). HKDF does not add a work factor, so it is
//!    only safe with at least 128 bits of entropy in the IKM.
//! 3. **Argon2id** (`Derivation::Argon2id`): a memory-hard password hashing
//!    function suitable for low-entropy passphrases. Uses the OWASP-default
//!    parameters (m_cost=19 MiB, t_cost=2, p_cost=1) unless overridden.
//!
//! For both KDF variants the input keying material may be supplied in one of
//! three ways via the IKM-source fields on [`Derivation`]:
//!
//! - inline lowercase-hex string `ikm` (development / tests; not recommended
//!   for production secrets that should not live in a config-management blob),
//! - reading the named environment variable (`ikm_from_env`), or
//! - reading from a file (`ikm_from_file`) — the file is loaded via
//!   [`rustgate_core::secrets::read_secret_file`], so it inherits the workspace's
//!   strict permission gate (`mode 0o077` rejected on Unix), size cap
//!   (16 KiB), and ownership-UID check.
//!
//! In every case the IKM lives in [`zeroize::Zeroizing`] for the duration
//! of derivation and is wiped immediately afterward — only the derived
//! 32-byte key persists in memory in the [`KeyRing`].
//!
//! ## Key expiration
//!
//! Each key id may carry an optional `not_after` (unix-seconds since epoch)
//! via the `key_expirations` map. When [`KeyRing::active_key_expired_at`]
//! returns true for the active key, [`EncryptedWriter::create`] refuses to
//! open a new file with [`EncryptError::ActiveKeyExpired`] — historical
//! data encrypted under the expired key is still readable, only new-write
//! admission is gated. Loading a key file whose active key expires within
//! 14 days emits an [`rustgate_core::audit::archive_key_rotation_due`] audit event;
//! loading a key file with no expirations declared at all emits a
//! `tracing::warn!` so operators are nudged toward setting rotation policy.
//!
//! ## File format (version 3)
//!
//! ```text
//! magic     : 8 bytes  = b"RGENC1\0\0"
//! version   : 1 byte   = 3
//! key_id_len: 1 byte
//! key_id    : key_id_len bytes (UTF-8)
//! base_nonce: 24 bytes (20 random || 4 zero — the trailing 4 hold the counter)
//! repeated chunks:
//!   len     : 4 bytes (big-endian) length of `ciphertext`
//!   ciphertext: AEAD output (plaintext_len + 16-byte tag)
//! terminator chunk:
//!   len     : 4 bytes (big-endian)
//!   ciphertext: AEAD output of an empty plaintext sealed with the terminator
//!               AAD marker (see below)
//! ```
//!
//! Per-chunk nonce = `base_nonce[..20] (random) || counter_be (4 bytes)`, a
//! 192-bit XChaCha20 nonce. The counter starts at 0 and increments by 1 per
//! chunk; with a 32-bit counter a single file can hold up to ~4.29 billion
//! chunks before rollover, which is enforced by returning an error.
//!
//! **Version 2** (pre-#1506) is identical except `version = 2`, an 8-byte
//! random base nonce, and a 96-bit ChaCha20-Poly1305 nonce
//! (`base_nonce (8 bytes) || counter_be (4 bytes)`). [`decrypt_file`] dispatches
//! on the version byte, so v2 archives stay readable; the writer only ever
//! produces v3.
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
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Magic bytes identifying a rustgate encrypted archive file.
///
/// `MAGIC` identifies "a rustgate archive"; the format version byte that
/// follows selects the cipher and nonce width, so the magic is stable across
/// format versions.
pub const MAGIC: &[u8; 8] = b"RGENC1\0\0";

/// Current on-disk format version written by [`EncryptedWriter`].
///
/// Version 3 switches the AEAD to **XChaCha20-Poly1305** (192-bit nonce) with a
/// 24-byte per-file base nonce (20 random bytes + a 4-byte chunk counter). The
/// previous version 2 used ChaCha20-Poly1305 with a 64-bit random base nonce;
/// at archive scale (~2^32 files under one key) two files could draw the same
/// 64-bit base, reusing an identical nonce sequence — catastrophic for the
/// cipher. The 160 random bits in v3 push the base-collision birthday bound to
/// ~2^80 files (#1506). Both versions bind per-chunk AAD (key id + counter +
/// kind) and seal the stream with a terminator chunk; only the cipher and
/// nonce width differ. Files written by version 1 are not readable; version 2
/// files remain fully decryptable (see [`decrypt_file`]).
pub const FORMAT_VERSION: u8 = 3;

/// The previous format version (ChaCha20-Poly1305, 8-byte base nonce). New
/// files are never written at this version, but [`decrypt_file`] reads it so
/// archives produced before #1506 stay decryptable.
const FORMAT_VERSION_V2: u8 = 2;

/// Per-file base-nonce length for [`FORMAT_VERSION_V2`] (ChaCha20-Poly1305).
const BASE_NONCE_LEN_V2: usize = 8;
/// Per-file base-nonce length for [`FORMAT_VERSION`] v3 (XChaCha20-Poly1305).
/// 20 random bytes followed by 4 bytes that hold the per-chunk counter.
const BASE_NONCE_LEN_V3: usize = 24;

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
    /// The active key's `not_after` is in the past, so it must not be used
    /// for new writes. Historical data encrypted under this key is still
    /// readable — only new-write admission is blocked. Operators must
    /// rotate the `active_key_id` to a key whose `not_after` is in the
    /// future (or unset).
    #[error("active key id {id:?} expired at unix_seconds={not_after}")]
    ActiveKeyExpired {
        /// The expired active key id.
        id: String,
        /// The unix timestamp (seconds since epoch) at which the key expired.
        not_after: i64,
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
    /// An entry in `key_derivations` failed to produce a valid 32-byte key.
    ///
    /// Carries the offending key id and a short reason. The reason string
    /// deliberately does not include IKM or salt bytes — leaking key
    /// material into a log line would defeat the purpose of the KDF.
    #[error("key derivation failed for id {id:?}: {reason}")]
    KeyDerivation {
        /// The key id whose derivation failed.
        id: String,
        /// Human-readable reason (no secret material).
        reason: String,
    },
}

/// On-disk JSON layout for the key file.
///
/// Keys are stored as 64-character lowercase hex strings (32 raw bytes,
/// the ChaCha20-Poly1305 key length), OR — when an operator has a single
/// root secret they want to derive multiple subkeys from — via
/// [`Derivation`] entries in `key_derivations`.
///
/// Uses `deny_unknown_fields` to reject key files containing unexpected
/// properties — a typo like `"actve_key_id"` produces a clear
/// deserialization error instead of being silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    /// Identifier of the key used for new writes. Must be present in
    /// either `keys` or `key_derivations`.
    pub active_key_id: String,
    /// All known raw keys, indexed by id. Each value is a 64-character
    /// lowercase hex string.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, String>,
    /// Optional per-key expiration expressed as unix seconds since epoch.
    ///
    /// Any id listed here must also appear in either `keys` or
    /// `key_derivations`. When the `active_key_id` has an entry whose
    /// value is `<=` the current system time, new-write admission is
    /// rejected with [`EncryptError::ActiveKeyExpired`]. Keys that do
    /// not appear in this map have no expiration and may be used
    /// indefinitely (historical behaviour — unchanged for existing key
    /// files that pre-date this field).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub key_expirations: BTreeMap<String, i64>,
    /// Optional KDF-derived keys, indexed by id.
    ///
    /// Each [`Derivation`] evaluates at [`KeyRing::from_bytes`] time to
    /// produce exactly 32 bytes of key material. Derived entries are
    /// indistinguishable from raw entries at use time — they can be the
    /// active key, a historical key for decrypt, and can carry an
    /// expiration in `key_expirations`. An id must appear in at most one
    /// of `keys` or `key_derivations`; listing the same id in both is a
    /// config-file error rejected at load.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub key_derivations: BTreeMap<String, Derivation>,
    /// Optional per-tenant key-id overrides, indexed by tenant id.
    ///
    /// Maps a tenant identifier (the certificate `O` field, matching the
    /// bucket already used to path-namespace archives — see
    /// `resolve_tenant_bucket`) to the id of the key that tenant's archives
    /// must be encrypted under. Any id listed here must appear in either
    /// `keys` or `key_derivations`. A tenant absent from this map — and
    /// unauthenticated / tenant-less traffic — falls back to
    /// [`KeyFile::active_key_id`], so an empty map (the default for every
    /// pre-existing key file) reproduces today's single-key behaviour
    /// exactly.
    ///
    /// This map is the resolution seam only: the archive write path does not
    /// yet consult it (see [ADR 0034](../../../docs/adr/0034-multi-tenant-at-rest-isolation.md)).
    /// Wiring the per-tenant key into the writer is a follow-up slice; until
    /// then the field is inert and changes no on-disk bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tenant_key_map: BTreeMap<String, String>,
}

/// Key-derivation recipe for a single entry in [`KeyFile::key_derivations`].
///
/// Two KDFs are supported, picking based on the entropy of the input:
///
/// - [`Derivation::HkdfSha256`] — RFC 5869 Extract-and-Expand. The right
///   primitive when an operator has a high-entropy root secret (KMS blob,
///   HSM output, another rustgate deployment's master key) and wants to
///   derive multiple subkeys deterministically without re-provisioning.
///   HKDF does **not** add a work factor, so it is not suitable for
///   low-entropy passphrases.
/// - [`Derivation::Argon2id`] — memory-hard password hashing. The right
///   primitive when an operator wants to seed the archive key from a
///   passphrase, because the work factor turns a brute-force attack on
///   the derived key into a memory-and-CPU-bound search of the underlying
///   passphrase space.
///
/// The `kdf` tag in the serialized form discriminates the variant. Adding
/// a new variant in the future is non-breaking for existing key files
/// because `serde(tag = "kdf")` rejects unknown tags at parse time with
/// a clear error rather than silently falling back to a default.
///
/// The IKM (input keying material — passphrase or shared secret) for both
/// variants is supplied via the `ikm` / `ikm_from_env` / `ikm_from_file`
/// fields on each variant: inline-hex strings, environment variables, and
/// on-disk secret files respectively. Inline hex is convenient for
/// development but should not be used for production secrets that ought
/// not live in config-management blobs; `ikm_from_env` and `ikm_from_file`
/// keep the secret out of the JSON entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kdf", rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum Derivation {
    /// HKDF-SHA256 — RFC 5869 Extract-and-Expand.
    ///
    /// The extract stage hashes IKM and salt to produce a pseudorandom
    /// key; expand then stretches that to 32 bytes of output keyed by
    /// `info`. Two derivations that share the same `ikm` but differ in
    /// either `salt` or `info` produce cryptographically independent
    /// outputs.
    HkdfSha256 {
        /// Inline IKM, lowercase-hex encoded. Mutually exclusive with
        /// `ikm_from_env` and `ikm_from_file`; exactly one of the three
        /// must be set. Inline IKM is convenient for development but
        /// keeps the secret in the JSON config — production deployments
        /// should prefer `ikm_from_env` or `ikm_from_file`. Inline IKM
        /// MUST be at least 16 bytes (128 bits) of decoded entropy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ikm: Option<String>,
        /// Resolve IKM by reading the named environment variable at load
        /// time. The variable value is wrapped in [`Zeroizing<String>`]
        /// for the lifetime of derivation and dropped (wiped) immediately
        /// afterward.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ikm_from_env: Option<String>,
        /// Resolve IKM by reading the named file via
        /// [`rustgate_core::secrets::read_secret_file`]. The file inherits the
        /// workspace's strict permission gate (`mode 0o077` rejected on
        /// Unix), size cap (16 KiB), and ownership-UID check.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ikm_from_file: Option<PathBuf>,
        /// Salt, lowercase hex-encoded. Empty string is permitted
        /// (RFC 5869 § 3.1 — the implementation substitutes a zero
        /// block), but a deployment-unique random salt is strongly
        /// recommended.
        #[serde(default)]
        salt: String,
        /// Context string (free-form bytes, UTF-8 is conventional).
        /// Bound into the expand stage so two derivations from the same
        /// `(ikm, salt)` with different `info` values are unrelated. A
        /// convention like `"rustgate-archive/v1/" + key_id` ties each
        /// derivation to the deployment and id.
        #[serde(default)]
        info: String,
    },
    /// Argon2id — memory-hard password hashing function (RFC 9106).
    ///
    /// The hybrid Argon2id variant is the OWASP-recommended default for
    /// password-based key derivation and is the right choice when the
    /// IKM is a low-entropy passphrase rather than a high-entropy root
    /// secret. Output is exactly 32 bytes — the ChaCha20-Poly1305 key
    /// length.
    ///
    /// Default parameters follow the OWASP cheat sheet
    /// (m_cost=19 MiB, t_cost=2, p_cost=1); operators may override
    /// individual fields. The salt is mandatory and must be at least 8
    /// bytes — Argon2's security depends on a unique-per-derivation
    /// salt, and re-using a salt across deployments enables rainbow-table
    /// attacks against the passphrase space.
    Argon2id {
        /// Inline IKM, lowercase-hex encoded. See [`Derivation::HkdfSha256::ikm`]
        /// for the full discussion.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ikm: Option<String>,
        /// Resolve IKM from an environment variable. For passphrase-seeded
        /// archives this is the typical operator path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ikm_from_env: Option<String>,
        /// Resolve IKM from a secret file. Inherits the workspace-wide
        /// permission / ownership / size policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ikm_from_file: Option<PathBuf>,
        /// Salt, lowercase hex-encoded. MUST be at least 8 bytes — the
        /// load path refuses shorter salts with
        /// [`EncryptError::KeyDerivation`] because Argon2's security
        /// floor is not met without one.
        salt: String,
        /// Argon2 work parameter overrides. When unset, the OWASP
        /// defaults are applied (`m_cost=19 MiB`, `t_cost=2`,
        /// `p_cost=1`). Operators on memory-constrained hardware may
        /// reduce `m_cost`, but doing so weakens the work factor and
        /// shifts more risk back onto the underlying passphrase
        /// entropy — document the deployment posture if you do.
        #[serde(default, skip_serializing_if = "Argon2Params::is_default")]
        params: Argon2Params,
    },
}

/// Borrowed view over the three IKM-source fields. Internal helper used
/// by [`resolve_ikm`] so the source enumeration logic can be shared
/// between [`Derivation::HkdfSha256`] and [`Derivation::Argon2id`]
/// without macro repetition.
struct IkmRef<'a> {
    inline: Option<&'a str>,
    from_env: Option<&'a str>,
    from_file: Option<&'a Path>,
}

/// Resolved `(ikm_bytes, source_label)` from an [`IkmRef`], scoped to the
/// lifetime of one derivation. The bytes are zeroized on drop.
struct ResolvedIkm {
    bytes: Zeroizing<Vec<u8>>,
    /// Short label for error messages — names the source kind without
    /// leaking secret content. One of `"inline"`, `"env"`, `"file"`.
    source: &'static str,
}

/// Argon2id work parameters. Defaults follow the OWASP cheat sheet for
/// password-based KDF: `m_cost=19 MiB`, `t_cost=2`, `p_cost=1`.
///
/// `m_cost` is in **kibibytes** (1 KiB blocks), matching the underlying
/// `argon2` crate's API. The default `19_456` therefore represents
/// `19 * 1024 = 19 MiB` of working memory per derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Argon2Params {
    /// Memory cost in kibibytes. Default: `19 * 1024 = 19_456` (19 MiB).
    #[serde(default = "Argon2Params::default_m_cost")]
    pub m_cost_kib: u32,
    /// Time cost (iteration count). Default: `2`.
    #[serde(default = "Argon2Params::default_t_cost")]
    pub t_cost: u32,
    /// Parallelism (degree of parallelism). Default: `1`.
    #[serde(default = "Argon2Params::default_p_cost")]
    pub p_cost: u32,
}

impl Argon2Params {
    const DEFAULT_M_COST_KIB: u32 = 19 * 1024;
    const DEFAULT_T_COST: u32 = 2;
    const DEFAULT_P_COST: u32 = 1;

    fn default_m_cost() -> u32 {
        Self::DEFAULT_M_COST_KIB
    }
    fn default_t_cost() -> u32 {
        Self::DEFAULT_T_COST
    }
    fn default_p_cost() -> u32 {
        Self::DEFAULT_P_COST
    }

    /// True when every field equals its OWASP-default value. Used by
    /// `skip_serializing_if` so a default `Argon2Params` round-trips
    /// through serde without injecting noise into the on-disk JSON.
    fn is_default(&self) -> bool {
        self.m_cost_kib == Self::DEFAULT_M_COST_KIB
            && self.t_cost == Self::DEFAULT_T_COST
            && self.p_cost == Self::DEFAULT_P_COST
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost_kib: Self::DEFAULT_M_COST_KIB,
            t_cost: Self::DEFAULT_T_COST,
            p_cost: Self::DEFAULT_P_COST,
        }
    }
}

/// Loaded key material — keys decoded into raw bytes wrapped in
/// [`Zeroizing`] so they are wiped on drop.
#[derive(Clone)]
pub struct KeyRing {
    active_key_id: String,
    keys: BTreeMap<String, Arc<Zeroizing<[u8; 32]>>>,
    not_after: BTreeMap<String, i64>,
    tenant_key_map: BTreeMap<String, String>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("active_key_id", &self.active_key_id)
            .field("key_count", &self.keys.len())
            .field("expiring_key_count", &self.not_after.len())
            .field("tenant_key_count", &self.tenant_key_map.len())
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

        // Reject id overlap between raw and derived entries before doing
        // any hex decoding or KDF work — two entries sharing an id is a
        // config-file error (almost certainly a typo), and silently
        // preferring one over the other would hide the mistake.
        for id in parsed.key_derivations.keys() {
            if parsed.keys.contains_key(id) {
                return Err(EncryptError::KeyFile(format!(
                    "key id {id:?} appears in both `keys` and `key_derivations`"
                )));
            }
        }

        let id_is_known = |id: &str| -> bool {
            parsed.keys.contains_key(id) || parsed.key_derivations.contains_key(id)
        };
        if !id_is_known(&parsed.active_key_id) {
            return Err(EncryptError::KeyFile(format!(
                "active_key_id {:?} not found in keys or key_derivations",
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

        // Evaluate KDF entries AFTER raw entries so overlap (caught
        // above) would have already tripped. The derivation routine
        // returns a `Zeroizing<[u8; 32]>` so the IKM-derived bytes are
        // wiped when the closure returns, even though the `KeyFile`
        // itself still holds the IKM hex string until the caller drops
        // it.
        for (id, derivation) in parsed.key_derivations.iter() {
            let derived = derive_key(id, derivation)?;
            let _ = keys.insert(id.clone(), Arc::new(derived));
        }

        for id in parsed.key_expirations.keys() {
            if !id_is_known(id) {
                return Err(EncryptError::KeyFile(format!(
                    "key_expirations references unknown key id {id:?}"
                )));
            }
        }

        // A tenant map that points at a key id absent from the ring would
        // fail closed at write time with `UnknownKeyId` — surface it at
        // load instead so operators catch the misconfiguration on startup
        // rather than the first time that tenant's archive is written.
        for (tenant, id) in parsed.tenant_key_map.iter() {
            if !id_is_known(id) {
                return Err(EncryptError::KeyFile(format!(
                    "tenant_key_map entry for tenant {tenant:?} references unknown key id {id:?}"
                )));
            }
        }

        let ring = Self {
            active_key_id: parsed.active_key_id,
            keys,
            not_after: parsed.key_expirations,
            tenant_key_map: parsed.tenant_key_map,
        };

        // Operator-facing rotation hygiene signals — emitted at load
        // time so they fire on every server start (and SIGHUP-driven
        // hot reload), giving operators a steady reminder rather than a
        // one-shot at the moment a write actually fails closed.
        ring.emit_rotation_signals_at_now();

        Ok(ring)
    }

    /// Emit operator-facing rotation hygiene signals using the current
    /// system clock. Helper extracted so [`Self::emit_rotation_signals_at`]
    /// can be tested deterministically with a synthetic clock.
    fn emit_rotation_signals_at_now(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.emit_rotation_signals_at(now);
    }

    /// Emit operator-facing rotation hygiene signals based on `now_unix_seconds`.
    ///
    /// Two outputs:
    ///
    /// 1. If the key file declares **no** expirations at all, emit a
    ///    `tracing::warn!` asking the operator to set rotation. This is
    ///    a hygiene nudge — pre-this-PR key files lacking expirations
    ///    are still valid (backward-compat is preserved), but the warn
    ///    surfaces the gap so operators graduate toward managed
    ///    rotation.
    /// 2. If the active key has a configured `not_after` within the
    ///    next 14 days (inclusive of "in the past"), emit
    ///    [`rustgate_core::audit::archive_key_rotation_due`] with `kid` and
    ///    `days_remaining`. SIEMs key on this event to drive rotation
    ///    runbooks.
    ///
    /// Public-but-doc-hidden so tests in this module can drive a synthetic
    /// clock without touching the real system time.
    #[doc(hidden)]
    pub fn emit_rotation_signals_at(&self, now_unix_seconds: i64) {
        const ROTATION_WINDOW_DAYS: i64 = 14;
        const SECONDS_PER_DAY: i64 = 86_400;

        if self.not_after.is_empty() {
            tracing::warn!(
                target: "rustgate_archive::encrypted",
                active_key_id = %self.active_key_id,
                "encrypted-archive key file has no `key_expirations` set; \
                 set `not_after` per key to enable rotation hygiene checks"
            );
            return;
        }

        if let Some(&not_after) = self.not_after.get(&self.active_key_id) {
            let remaining = not_after.saturating_sub(now_unix_seconds);
            if remaining <= ROTATION_WINDOW_DAYS * SECONDS_PER_DAY {
                // floor(remaining / 86_400), clamped at 0 so a key whose
                // `not_after` has already passed reports as 0 rather than
                // a negative count. The actual admission gate
                // ([`active_key_expired_at`]) handles the past-expiry
                // case at write time — this audit event is purely
                // observational.
                let days_remaining = (remaining / SECONDS_PER_DAY).max(0);
                rustgate_core::audit::archive_key_rotation_due(&self.active_key_id, days_remaining);
            }
        }
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
    ///
    /// This accessor does **not** check expiration — callers that must
    /// refuse expired keys for new writes should first consult
    /// [`KeyRing::active_key_expired_at`] (the `EncryptedWriter::create`
    /// entrypoint does this automatically).
    pub fn active_key(&self) -> Result<Arc<Zeroizing<[u8; 32]>>, EncryptError> {
        self.keys
            .get(&self.active_key_id)
            .cloned()
            .ok_or_else(|| EncryptError::UnknownActiveKey {
                id: self.active_key_id.clone(),
            })
    }

    /// Unix-seconds `not_after` for key `id`, if one was configured.
    ///
    /// Returns `None` both for keys that have no expiration configured and
    /// for unknown ids — callers that need to distinguish the two cases
    /// should combine this with [`KeyRing::key`].
    pub fn not_after(&self, id: &str) -> Option<i64> {
        self.not_after.get(id).copied()
    }

    /// Returns `true` if the active key has an expiration configured and
    /// `not_after <= now_unix_seconds`. Keys without an expiration never
    /// report expired. This method does not read the system clock itself
    /// so callers can deterministically test both sides of the boundary.
    pub fn active_key_expired_at(&self, now_unix_seconds: i64) -> bool {
        match self.not_after.get(&self.active_key_id) {
            Some(&not_after) => not_after <= now_unix_seconds,
            None => false,
        }
    }

    /// Resolve the key id that should encrypt `tenant`'s archives.
    ///
    /// Returns the id mapped for `tenant` in the key file's
    /// `tenant_key_map`, or falls back to [`Self::active_key_id`] when the
    /// tenant is unmapped or `None` (unauthenticated / tenant-less traffic).
    /// With an empty `tenant_key_map` — the default — this always returns
    /// the active key id, reproducing today's single-key behaviour.
    ///
    /// The returned reference is tied to `&self`, so it borrows either the
    /// map entry or the active-key-id field without allocating.
    pub fn key_id_for_tenant(&self, tenant: Option<&str>) -> &str {
        tenant
            .and_then(|t| self.tenant_key_map.get(t))
            .map(String::as_str)
            .unwrap_or(&self.active_key_id)
    }

    /// Look up the raw 32-byte key that should encrypt `tenant`'s archives.
    ///
    /// Resolves the tenant to a key id via [`Self::key_id_for_tenant`] and
    /// returns that key's material. Returns [`EncryptError::UnknownKeyId`]
    /// if the resolved id is not present in the ring — this cannot happen
    /// for a ring built via [`Self::from_bytes`] (both the active key and
    /// every `tenant_key_map` target are validated at load), but is
    /// surfaced explicitly rather than falling back to a sentinel key so a
    /// directly-constructed ring cannot silently encrypt with an absent id.
    ///
    /// Like [`Self::active_key`], this does **not** check expiration —
    /// callers gating new writes must consult [`Self::active_key_expired_at`]
    /// (or, once wired, a tenant-aware equivalent) first.
    pub fn key_for_tenant(
        &self,
        tenant: Option<&str>,
    ) -> Result<Arc<Zeroizing<[u8; 32]>>, EncryptError> {
        let id = self.key_id_for_tenant(tenant);
        self.keys
            .get(id)
            .cloned()
            .ok_or_else(|| EncryptError::UnknownKeyId(id.to_string()))
    }
}

/// Evaluate a [`Derivation`] into 32 bytes of key material.
///
/// Resolves the IKM source (inline hex / env var / file) into raw bytes,
/// applies the configured minimum-length floor, and runs the named KDF.
/// The returned bytes are wrapped in [`Zeroizing`] so the caller's
/// subsequent `Arc::new` keeps the secret wiped on drop.
///
/// Intermediate decoded IKM lives in [`Zeroizing`] so it is wiped as soon
/// as the KDF is done with it. Note that the `KeyFile` itself may still
/// hold an inline IKM hex string until the caller drops it — operators
/// who care about minimising in-memory secret lifetime should prefer
/// `ikm_from_env` or `ikm_from_file` IKM sources.
fn derive_key(id: &str, derivation: &Derivation) -> Result<Zeroizing<[u8; 32]>, EncryptError> {
    match derivation {
        Derivation::HkdfSha256 {
            ikm,
            ikm_from_env,
            ikm_from_file,
            salt,
            info,
        } => {
            let ikm_ref = IkmRef {
                inline: ikm.as_deref(),
                from_env: ikm_from_env.as_deref(),
                from_file: ikm_from_file.as_deref(),
            };
            let resolved = resolve_ikm(id, &ikm_ref, /* min_bytes */ 16)?;

            let salt_bytes = hex::decode(salt).map_err(|e| EncryptError::KeyDerivation {
                id: id.to_string(),
                reason: format!("salt hex decode: {e}"),
            })?;

            // RFC 5869 § 3.1: a zero-length salt is permitted and HKDF
            // substitutes a hashlen-sized zero block. `Hkdf::new` with
            // `None` expresses that path; an explicitly-empty salt in
            // the key file maps to `None` so the implementation and the
            // specification agree.
            let salt_opt = if salt_bytes.is_empty() {
                None
            } else {
                Some(salt_bytes.as_slice())
            };
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(salt_opt, &resolved.bytes);

            let mut out = Zeroizing::new([0u8; 32]);
            hk.expand(info.as_bytes(), &mut *out)
                .map_err(|e| EncryptError::KeyDerivation {
                    id: id.to_string(),
                    reason: format!("hkdf expand: {e}"),
                })?;
            Ok(out)
        }
        Derivation::Argon2id {
            ikm,
            ikm_from_env,
            ikm_from_file,
            salt,
            params,
        } => {
            // Argon2id accepts low-entropy passphrases by design — its
            // memory-hard work factor is the security feature. Skip the
            // 16-byte minimum we apply to HKDF: a 12-character ASCII
            // passphrase is a perfectly reasonable Argon2 input. We do
            // require at least 1 byte (an empty passphrase is almost
            // certainly an env-var-not-set bug) and rely on the salt
            // floor below to enforce the rest of the security posture.
            let ikm_ref = IkmRef {
                inline: ikm.as_deref(),
                from_env: ikm_from_env.as_deref(),
                from_file: ikm_from_file.as_deref(),
            };
            let resolved = resolve_ikm(id, &ikm_ref, /* min_bytes */ 1)?;

            let salt_bytes = hex::decode(salt).map_err(|e| EncryptError::KeyDerivation {
                id: id.to_string(),
                reason: format!("salt hex decode: {e}"),
            })?;
            // Argon2 RFC 9106 § 3.1 mandates a salt of at least 8 bytes
            // (64 bits). Re-using a salt across deployments enables
            // rainbow-table attacks against the passphrase space, so the
            // operator-facing floor is non-negotiable.
            if salt_bytes.len() < 8 {
                return Err(EncryptError::KeyDerivation {
                    id: id.to_string(),
                    reason: format!(
                        "argon2id salt must be at least 8 bytes, got {}",
                        salt_bytes.len()
                    ),
                });
            }

            let work =
                argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
                    .map_err(|e| EncryptError::KeyDerivation {
                        id: id.to_string(),
                        reason: format!("argon2 params: {e}"),
                    })?;
            let argon2 =
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, work);

            let mut out = Zeroizing::new([0u8; 32]);
            argon2
                .hash_password_into(&resolved.bytes, &salt_bytes, &mut *out)
                .map_err(|e| EncryptError::KeyDerivation {
                    id: id.to_string(),
                    reason: format!("argon2id hash: {e}"),
                })?;
            Ok(out)
        }
    }
}

/// Resolve an [`IkmRef`] into raw bytes wrapped in [`Zeroizing`].
///
/// Exactly one of the three source fields must be set; zero or more than
/// one is a config-file error. The minimum-byte floor differs per KDF
/// (HKDF requires at least 16 bytes — see RFC 5869's entropy assumption;
/// Argon2id accepts shorter inputs since its work factor is the security
/// boundary), so the caller passes its own floor.
fn resolve_ikm(
    id: &str,
    field: &IkmRef<'_>,
    min_bytes: usize,
) -> Result<ResolvedIkm, EncryptError> {
    let count = field.inline.is_some() as u8
        + field.from_env.is_some() as u8
        + field.from_file.is_some() as u8;
    if count == 0 {
        return Err(EncryptError::KeyDerivation {
            id: id.to_string(),
            reason: "no IKM source set: provide one of `ikm`, `ikm_from_env`, `ikm_from_file`"
                .into(),
        });
    }
    if count > 1 {
        return Err(EncryptError::KeyDerivation {
            id: id.to_string(),
            reason:
                "multiple IKM sources set: choose exactly one of `ikm` / `ikm_from_env` / `ikm_from_file`"
                    .into(),
        });
    }

    let resolved = if let Some(hex_value) = field.inline {
        let bytes =
            Zeroizing::new(
                hex::decode(hex_value).map_err(|e| EncryptError::KeyDerivation {
                    id: id.to_string(),
                    reason: format!("ikm hex decode: {e}"),
                })?,
            );
        ResolvedIkm {
            bytes,
            source: "inline",
        }
    } else if let Some(env_var) = field.from_env {
        // Wrap the env-var value in `Zeroizing<String>` immediately and
        // copy its bytes into a `Zeroizing<Vec<u8>>` that lives only as
        // long as derivation needs it. The `String` is dropped before
        // this function returns, so it does not outlive the derivation.
        let raw = std::env::var(env_var).map_err(|e| EncryptError::KeyDerivation {
            id: id.to_string(),
            reason: format!("env var {env_var:?}: {e}"),
        })?;
        let value: Zeroizing<String> = Zeroizing::new(raw);
        let bytes = Zeroizing::new(value.as_bytes().to_vec());
        ResolvedIkm {
            bytes,
            source: "env",
        }
    } else if let Some(path) = field.from_file {
        // Reuse the workspace-wide secret-file reader so this path
        // inherits the same permission / ownership / size policy
        // already applied to enrollment passwords and federation HMAC
        // secrets.
        let opts = rustgate_core::secrets::SecretFileOpts::default();
        let value = rustgate_core::secrets::read_secret_file(path, &opts).map_err(|e| {
            EncryptError::KeyDerivation {
                id: id.to_string(),
                reason: format!("ikm file: {e}"),
            }
        })?;
        let bytes = Zeroizing::new(value.as_bytes().to_vec());
        ResolvedIkm {
            bytes,
            source: "file",
        }
    } else {
        // Unreachable given the count check above, but keeps the match
        // exhaustive without an `unwrap`.
        return Err(EncryptError::KeyDerivation {
            id: id.to_string(),
            reason: "internal: IkmRef unreachable arm".into(),
        });
    };

    if resolved.bytes.len() < min_bytes {
        let got = resolved.bytes.len();
        let source = resolved.source;
        // `resolved` drops here, zeroizing the bytes before we surface
        // the error.
        return Err(EncryptError::KeyDerivation {
            id: id.to_string(),
            reason: format!("ikm from {source} must be at least {min_bytes} bytes, got {got}"),
        });
    }
    Ok(resolved)
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
    cipher: XChaCha20Poly1305,
    base_nonce: [u8; BASE_NONCE_LEN_V3],
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
        Self::create_for_tenant(path, key_ring, None)
    }

    /// Create or open `path` for writing, resolving the encryption key by
    /// `tenant`.
    ///
    /// Identical to [`Self::create`] except the key id (and its expiry
    /// gate) are resolved via [`KeyRing::key_id_for_tenant`] rather than
    /// always using the active key. Passing `None` — or a tenant absent
    /// from the ring's `tenant_key_map` — resolves to the active key, so
    /// `create_for_tenant(path, ring, None)` is byte-for-byte equivalent
    /// to `create(path, ring)`.
    ///
    /// The same destructive, non-resumable truncation semantics as
    /// [`Self::create`] apply.
    ///
    /// Note: as of [ADR 0034](../../../docs/adr/0034-multi-tenant-at-rest-isolation.md)
    /// no caller passes a real tenant yet — the archive write path wiring is
    /// a follow-up slice.
    pub fn create_for_tenant(
        path: &Path,
        key_ring: &KeyRing,
        tenant: Option<&str>,
    ) -> Result<Self, EncryptError> {
        let key_id = key_ring.key_id_for_tenant(tenant).to_string();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        // Gate new-write admission on the resolved key's expiry, mirroring
        // the active-key check `create` performed. `active_key_expired_at`
        // only inspects the active key, so consult the resolved id's
        // `not_after` directly: a tenant pinned to a rotated-out key must
        // not open a new file with it either.
        if let Some(not_after) = key_ring.not_after(&key_id)
            && not_after <= now_unix
        {
            return Err(EncryptError::ActiveKeyExpired {
                id: key_id,
                not_after,
            });
        }
        let key_bytes = key_ring.key_for_tenant(tenant)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        // 24-byte XChaCha20 base nonce: 20 random bytes + 4 trailing zero bytes.
        // The trailing four bytes hold the per-chunk big-endian counter (set by
        // `chunk_xnonce`); only the first 20 are randomized, giving 160 random
        // bits per file (#1506). Randomizing all 24 would be harmless (the
        // counter region is overwritten per chunk) but the explicit split keeps
        // the invariant `base_nonce[20..24] == 0` checkable in tests.
        let mut base_nonce = [0u8; BASE_NONCE_LEN_V3];
        getrandom(&mut base_nonce[..20])?;

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
        let nonce = chunk_xnonce(&self.base_nonce, self.counter);
        let aad = self.build_aad(AAD_KIND_DATA);
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
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
        let nonce = chunk_xnonce(&self.base_nonce, self.counter);
        let aad = self.build_aad(AAD_KIND_TERMINATOR);
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
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
    let mut id_len = [0u8; 1];
    reader.read_exact(&mut id_len)?;
    let mut id_buf = vec![0u8; id_len[0] as usize];
    reader.read_exact(&mut id_buf)?;
    let key_id = String::from_utf8(id_buf)
        .map_err(|e| EncryptError::Header(format!("key id not UTF-8: {e}")))?;
    let key_id_bytes = key_id.as_bytes().to_vec();

    let key_bytes = key_ring
        .key(&key_id)
        .ok_or_else(|| EncryptError::UnknownKeyId(key_id.clone()))?;

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

    // Dispatch on the format version. v3 uses XChaCha20-Poly1305 with a 24-byte
    // base nonce; v2 (pre-#1506 archives) uses ChaCha20-Poly1305 with an 8-byte
    // base. The per-chunk loop (`decrypt_stream`) is shared so the two versions
    // cannot drift in their terminator / truncation handling — they differ only
    // in the cipher and the per-chunk nonce builder, passed in as a closure.
    match version[0] {
        FORMAT_VERSION => {
            let mut base = [0u8; BASE_NONCE_LEN_V3];
            reader.read_exact(&mut base)?;
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));
            decrypt_stream(
                &mut reader,
                &mut writer,
                &key_id_bytes,
                |counter, aad, ct| {
                    let nonce = chunk_xnonce(&base, counter);
                    cipher.decrypt(XNonce::from_slice(&nonce), Payload { msg: ct, aad })
                },
            )?;
        }
        FORMAT_VERSION_V2 => {
            let mut base = [0u8; BASE_NONCE_LEN_V2];
            reader.read_exact(&mut base)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));
            decrypt_stream(
                &mut reader,
                &mut writer,
                &key_id_bytes,
                |counter, aad, ct| {
                    let nonce = chunk_nonce(&base, counter);
                    cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad })
                },
            )?;
        }
        other => {
            return Err(EncryptError::Header(format!("unsupported version {other}")));
        }
    }

    writer.flush()?;
    Ok(())
}

/// Shared per-chunk decrypt loop for both archive format versions.
///
/// `decrypt_chunk(counter, aad, ciphertext)` opens a single AEAD chunk using
/// the caller's cipher and version-specific nonce. Everything else — the
/// length framing, the data-then-terminator AAD trial, the "no bytes after the
/// terminator" check, and unsealed-stream (`Truncated`) detection — lives here
/// so v2 and v3 share exactly one implementation and cannot diverge (#1506).
fn decrypt_stream<W, D>(
    reader: &mut BufReader<File>,
    writer: &mut W,
    key_id_bytes: &[u8],
    decrypt_chunk: D,
) -> Result<(), EncryptError>
where
    W: Write,
    D: Fn(u32, &[u8], &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error>,
{
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

        // Try data AAD first; if that fails, try terminator AAD.
        let mut aad_data = Vec::with_capacity(key_id_bytes.len() + 5);
        aad_data.extend_from_slice(key_id_bytes);
        aad_data.push(AAD_KIND_DATA);
        aad_data.extend_from_slice(&counter.to_be_bytes());

        match decrypt_chunk(counter, &aad_data, chunk.as_ref()) {
            Ok(plaintext) => {
                writer.write_all(&plaintext)?;
            }
            Err(_) => {
                // Maybe terminator
                let mut aad_term = Vec::with_capacity(key_id_bytes.len() + 5);
                aad_term.extend_from_slice(key_id_bytes);
                aad_term.push(AAD_KIND_TERMINATOR);
                aad_term.extend_from_slice(&counter.to_be_bytes());
                let plaintext = decrypt_chunk(counter, &aad_term, chunk.as_ref())
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
    Ok(())
}

/// Build the 12-byte ChaCha20-Poly1305 nonce (v2) from the file's 8-byte base
/// nonce and the chunk counter. Retained for the v2 read path only.
fn chunk_nonce(base: &[u8; BASE_NONCE_LEN_V2], counter: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(base);
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Build the 24-byte XChaCha20-Poly1305 nonce (v3) from the file's 24-byte base
/// nonce and the chunk counter: the leading 20 bytes are the per-file random
/// base; the trailing 4 bytes hold the big-endian chunk counter.
fn chunk_xnonce(base: &[u8; BASE_NONCE_LEN_V3], counter: u32) -> [u8; BASE_NONCE_LEN_V3] {
    let mut nonce = *base;
    nonce[20..].copy_from_slice(&counter.to_be_bytes());
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
        Self::create_for_tenant(path, key_ring, None)
    }

    /// Create a new shared writer at `path`, resolving the encryption key by
    /// `tenant`. See [`EncryptedWriter::create_for_tenant`] for the
    /// resolution semantics; `None` reproduces [`Self::create`].
    pub fn create_for_tenant(
        path: &Path,
        key_ring: &KeyRing,
        tenant: Option<&str>,
    ) -> Result<Self, EncryptError> {
        Ok(Self {
            inner: Mutex::new(EncryptedWriter::create_for_tenant(path, key_ring, tenant)?),
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
            key_expirations: BTreeMap::new(),
            key_derivations: BTreeMap::new(),
            tenant_key_map: BTreeMap::new(),
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

    /// A two-key ring with a tenant map: tenant-a is pinned to `ka`,
    /// everything else falls back to the active key `kactive`.
    fn tenant_ring_json() -> Vec<u8> {
        let json = serde_json::json!({
            "active_key_id": "kactive",
            "keys": {
                "kactive": hex::encode([0x01u8; 32]),
                "ka": hex::encode([0x0au8; 32]),
            },
            "tenant_key_map": { "tenant-a": "ka" },
        });
        serde_json::to_vec(&json).unwrap()
    }

    #[test]
    fn key_id_for_tenant_maps_and_falls_back() {
        let ring = KeyRing::from_bytes(&tenant_ring_json()).unwrap();
        // Mapped tenant resolves to its pinned key id.
        assert_eq!(ring.key_id_for_tenant(Some("tenant-a")), "ka");
        // Unmapped tenant and tenant-less traffic fall back to active.
        assert_eq!(ring.key_id_for_tenant(Some("tenant-z")), "kactive");
        assert_eq!(ring.key_id_for_tenant(None), "kactive");
        // key_for_tenant returns the matching material.
        let ka = ring.key_for_tenant(Some("tenant-a")).unwrap();
        let active = ring.key_for_tenant(None).unwrap();
        assert_eq!(**ka, [0x0au8; 32]);
        assert_eq!(**active, [0x01u8; 32]);
    }

    #[test]
    fn key_file_without_tenant_map_deserializes_and_round_trips() {
        // A key file with no `tenant_key_map` field must deserialize (serde
        // default) and behave exactly as before: every tenant resolves to
        // the active key.
        let json = serde_json::json!({
            "active_key_id": "k1",
            "keys": { "k1": hex::encode([0x11u8; 32]) },
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let ring = KeyRing::from_bytes(&bytes).unwrap();
        assert_eq!(ring.key_id_for_tenant(Some("anything")), "k1");
        assert_eq!(ring.key_id_for_tenant(None), "k1");

        // Empty tenant map is omitted on serialize (skip_serializing_if).
        let kf = KeyFile {
            active_key_id: "k1".to_string(),
            keys: {
                let mut m = BTreeMap::new();
                let _ = m.insert("k1".to_string(), hex::encode([0x11u8; 32]));
                m
            },
            key_expirations: BTreeMap::new(),
            key_derivations: BTreeMap::new(),
            tenant_key_map: BTreeMap::new(),
        };
        let out = serde_json::to_string(&kf).unwrap();
        assert!(
            !out.contains("tenant_key_map"),
            "empty tenant map must be omitted: {out}"
        );
    }

    #[test]
    fn tenant_key_map_referencing_unknown_id_is_rejected() {
        let json = serde_json::json!({
            "active_key_id": "k1",
            "keys": { "k1": hex::encode([0x11u8; 32]) },
            "tenant_key_map": { "tenant-a": "missing" },
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = KeyRing::from_bytes(&bytes).unwrap_err();
        match err {
            EncryptError::KeyFile(msg) => {
                assert!(msg.contains("tenant-a") && msg.contains("missing"), "{msg}");
            }
            other => panic!("expected KeyFile error, got {other:?}"),
        }
    }

    #[test]
    fn create_for_tenant_uses_independent_keys() {
        let dir = tempdir();
        let ring = KeyRing::from_bytes(&tenant_ring_json()).unwrap();

        // Encrypt tenant-a's data under its pinned key `ka`.
        let enc_path = dir.join("tenant-a.enc");
        let dec_path = dir.join("tenant-a.txt");
        {
            let mut w =
                EncryptedWriter::create_for_tenant(&enc_path, &ring, Some("tenant-a")).unwrap();
            w.write_chunk(b"secret-a\n").unwrap();
            w.finish().unwrap();
        }
        // Same full ring decrypts (the header names key id `ka`).
        decrypt_file(&enc_path, &dec_path, &ring).unwrap();
        assert_eq!(std::fs::read(&dec_path).unwrap(), b"secret-a\n");

        // A ring lacking `ka` cannot decrypt — proving cross-tenant keys
        // are cryptographically independent, not a shared active key.
        let stripped_json = serde_json::json!({
            "active_key_id": "kactive",
            "keys": { "kactive": hex::encode([0x01u8; 32]) },
        });
        let stripped = KeyRing::from_bytes(&serde_json::to_vec(&stripped_json).unwrap()).unwrap();
        let err = decrypt_file(&enc_path, &dir.join("nope.txt"), &stripped).unwrap_err();
        assert!(matches!(err, EncryptError::UnknownKeyId(_)), "{err:?}");
    }

    #[test]
    fn create_and_create_for_tenant_none_are_equivalent() {
        let dir = tempdir();
        let ring = KeyRing::from_bytes(&tenant_ring_json()).unwrap();

        // create() and create_for_tenant(.., None) must select the same
        // (active) key id, so a file written by one decrypts and reads the
        // same as a file written by the other.
        let p1 = dir.join("via-create.enc");
        let p2 = dir.join("via-none.enc");
        {
            let mut w = EncryptedWriter::create(&p1, &ring).unwrap();
            w.write_chunk(b"payload\n").unwrap();
            w.finish().unwrap();
        }
        {
            let mut w = EncryptedWriter::create_for_tenant(&p2, &ring, None).unwrap();
            w.write_chunk(b"payload\n").unwrap();
            w.finish().unwrap();
        }
        let d1 = dir.join("d1.txt");
        let d2 = dir.join("d2.txt");
        decrypt_file(&p1, &d1, &ring).unwrap();
        decrypt_file(&p2, &d2, &ring).unwrap();
        assert_eq!(std::fs::read(&d1).unwrap(), b"payload\n");
        assert_eq!(std::fs::read(&d2).unwrap(), std::fs::read(&d1).unwrap());
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
            not_after: BTreeMap::new(),
            tenant_key_map: BTreeMap::new(),
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
        // header = 8 magic + 1 version + 1 id_len + id_len + 24 base_nonce (v3)
        let id_len = data[9] as usize;
        let header_end = 8 + 1 + 1 + id_len + BASE_NONCE_LEN_V3;

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
        let header_end = 8 + 1 + 1 + id_len + BASE_NONCE_LEN_V3;

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

    #[test]
    fn v3_header_and_nonce_invariants() {
        let dir = tempdir();
        let enc = dir.join("h.enc");
        let ring = make_key_ring("k", &[("k", [0x55; 32])]);
        {
            let mut w = EncryptedWriter::create(&enc, &ring).unwrap();
            w.write_chunk(b"x").unwrap();
            w.finish().unwrap();
        }
        let data = std::fs::read(&enc).unwrap();
        assert_eq!(&data[..8], MAGIC);
        assert_eq!(data[8], FORMAT_VERSION, "writer must emit version 3");
        let id_len = data[9] as usize;
        let base = &data[10 + id_len..10 + id_len + BASE_NONCE_LEN_V3];
        assert_eq!(base.len(), 24);
        assert!(
            base[20..24].iter().all(|&b| b == 0),
            "v3 base-nonce counter region (bytes 20..24) must be zero on disk",
        );
        // The chunk nonce builder writes the big-endian counter into [20..24]
        // and leaves the random base intact, so consecutive chunks differ.
        let n0 = chunk_xnonce(&[7u8; BASE_NONCE_LEN_V3], 0);
        let n1 = chunk_xnonce(&[7u8; BASE_NONCE_LEN_V3], 1);
        let tail0: [u8; 4] = n0[20..24].try_into().unwrap();
        let tail1: [u8; 4] = n1[20..24].try_into().unwrap();
        assert_eq!(tail0, 0u32.to_be_bytes());
        assert_eq!(tail1, 1u32.to_be_bytes());
        assert_eq!(&n0[..20], &[7u8; 20]);
        assert_ne!(n0, n1);
    }

    #[test]
    fn v3_zero_data_chunk_round_trips() {
        // An immediate finish() with no data chunks: header + one terminator
        // chunk at counter 0. Mirrors the v2 empty-file path on v3.
        let dir = tempdir();
        let enc = dir.join("z.enc");
        let dec = dir.join("z.txt");
        let ring = make_key_ring("k", &[("k", [0x66; 32])]);
        {
            let mut w = EncryptedWriter::create(&enc, &ring).unwrap();
            w.finish().unwrap();
        }
        decrypt_file(&enc, &dec, &ring).unwrap();
        assert_eq!(std::fs::read(&dec).unwrap(), b"");
    }

    #[test]
    fn unsupported_version_rejected() {
        let dir = tempdir();
        let enc = dir.join("u.enc");
        let dec = dir.join("u.txt");
        let ring = make_key_ring("k", &[("k", [0x77; 32])]);
        {
            let mut w = EncryptedWriter::create(&enc, &ring).unwrap();
            w.write_chunk(b"q").unwrap();
            w.finish().unwrap();
        }
        let mut data = std::fs::read(&enc).unwrap();
        data[8] = 99; // bogus version byte
        std::fs::write(&enc, &data).unwrap();
        let err = decrypt_file(&enc, &dec, &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Header(_)), "got {err:?}");
    }

    #[test]
    fn truncated_v3_header_errors_cleanly() {
        // A file that claims v3 but is truncated inside the 24-byte base nonce
        // must surface a clean Io error, never a panic.
        let dir = tempdir();
        let enc = dir.join("t.enc");
        let dec = dir.join("t.txt");
        let ring = make_key_ring("k", &[("k", [0x88; 32])]);
        {
            let mut w = EncryptedWriter::create(&enc, &ring).unwrap();
            w.write_chunk(b"q").unwrap();
            w.finish().unwrap();
        }
        let data = std::fs::read(&enc).unwrap();
        let id_len = data[9] as usize;
        let cut = 10 + id_len + 4; // 4 bytes into the 24-byte base nonce
        std::fs::write(&enc, &data[..cut]).unwrap();
        let err = decrypt_file(&enc, &dec, &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Io(_)), "got {err:?}");
    }

    /// Test-only **independent** encoder for the legacy v2 wire format
    /// (ChaCha20-Poly1305, 8-byte base nonce). It emits the v2 bytes directly
    /// and shares no code with the production read path, so the back-compat
    /// test below cross-checks two implementations rather than round-tripping
    /// the shared `decrypt_stream` helper against itself (#1506).
    // Fixed inputs for the checked-in golden v2 fixture. ChaCha20-Poly1305 is
    // deterministic given a fixed (key, nonce), so these produce byte-identical
    // output every run — the fixture is regenerated only when the v2 wire format
    // legitimately changes (which, being frozen-on-disk, it must not).
    const GOLDEN_V2_KEY: [u8; 32] = [0x42; 32];
    const GOLDEN_V2_BASE8: [u8; 8] = [0xAB; 8];
    const GOLDEN_V2_KEY_ID: &str = "legacy";
    const GOLDEN_V2_PLAINTEXTS: &[&[u8]] = &[b"alpha", b"bravo", b"charlie"];

    // One-shot generator for `tests/fixtures/golden-v2.enc`. Ignored in normal
    // runs; re-run with `cargo nextest run -p rustgate-archive
    // emit_golden_v2_fixture --run-ignored all` only if the v2 format ever
    // legitimately changes. The committed bytes are what `v2_archive_still_*`
    // actually decrypt — a frozen fixture cannot co-drift with the reader.
    #[test]
    #[ignore = "regenerates the committed golden v2 fixture; not a real test"]
    fn emit_golden_v2_fixture() {
        let bytes = encode_v2_archive(
            &GOLDEN_V2_KEY,
            GOLDEN_V2_KEY_ID,
            &GOLDEN_V2_BASE8,
            GOLDEN_V2_PLAINTEXTS,
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/golden-v2.enc");
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
        std::fs::write(path, &bytes).unwrap();
    }

    fn encode_v2_archive(
        key: &[u8; 32],
        key_id: &str,
        base8: &[u8; 8],
        chunks: &[&[u8]],
    ) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let kid = key_id.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION_V2);
        out.push(kid.len() as u8);
        out.extend_from_slice(kid);
        out.extend_from_slice(base8);
        let seal = |counter: u32, kind: u8, msg: &[u8]| -> Vec<u8> {
            let nonce = chunk_nonce(base8, counter);
            let mut aad = Vec::new();
            aad.extend_from_slice(kid);
            aad.push(kind);
            aad.extend_from_slice(&counter.to_be_bytes());
            cipher
                .encrypt(Nonce::from_slice(&nonce), Payload { msg, aad: &aad })
                .unwrap()
        };
        let mut counter: u32 = 0;
        for ch in chunks {
            let ct = seal(counter, AAD_KIND_DATA, ch);
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(&ct);
            counter += 1;
        }
        let term = seal(counter, AAD_KIND_TERMINATOR, &[]);
        out.extend_from_slice(&(term.len() as u32).to_be_bytes());
        out.extend_from_slice(&term);
        out
    }

    /// The checked-in golden v2 archive (frozen bytes — see
    /// `emit_golden_v2_fixture`). Embedded at compile time so the back-compat
    /// tests decrypt the *exact* on-disk layout an older binary produced.
    const GOLDEN_V2_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/golden-v2.enc");

    #[test]
    fn v2_archive_still_decrypts_after_v3_bump() {
        // Back-compat: the CHECKED-IN golden v2 file must still decrypt through
        // the production version-dispatching `decrypt_file`. Using frozen
        // committed bytes (not a regenerated encoder) means a drift in the v2
        // nonce/AAD handling that happened to also corrupt the reader cannot
        // mask a regression.
        assert_eq!(
            GOLDEN_V2_FIXTURE[8], FORMAT_VERSION_V2,
            "fixture must be version 2"
        );

        let dir = tempdir();
        let enc = dir.join("legacy.enc");
        let dec = dir.join("legacy.txt");
        std::fs::write(&enc, GOLDEN_V2_FIXTURE).unwrap();
        let ring = make_key_ring(GOLDEN_V2_KEY_ID, &[(GOLDEN_V2_KEY_ID, GOLDEN_V2_KEY)]);
        decrypt_file(&enc, &dec, &ring).unwrap();

        let mut expected = Vec::new();
        for p in GOLDEN_V2_PLAINTEXTS {
            expected.extend_from_slice(p);
        }
        assert_eq!(std::fs::read(&dec).unwrap(), expected);
    }

    #[test]
    fn v2_tampered_chunk_rejected_after_v3_bump() {
        // The v2 read path still enforces integrity: flipping a ciphertext byte
        // in the committed v2 fixture fails decryption.
        let mut bytes = GOLDEN_V2_FIXTURE.to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let dir = tempdir();
        let enc = dir.join("legacy_tampered.enc");
        let dec = dir.join("legacy_tampered.txt");
        std::fs::write(&enc, &bytes).unwrap();
        let ring = make_key_ring(GOLDEN_V2_KEY_ID, &[(GOLDEN_V2_KEY_ID, GOLDEN_V2_KEY)]);
        let err = decrypt_file(&enc, &dec, &ring).unwrap_err();
        assert!(matches!(err, EncryptError::Aead(_)), "got {err:?}");
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

    mod key_expiration {
        use super::*;

        fn now_unix_seconds() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        }

        #[test]
        fn legacy_key_file_without_expirations_field_deserializes_cleanly() {
            // Pre-expiration key-file shape: no `key_expirations` field at
            // all. `#[serde(default)]` must supply an empty map so existing
            // key files keep loading without a migration.
            let json = br#"{
                "active_key_id": "k1",
                "keys": { "k1": "1111111111111111111111111111111111111111111111111111111111111111" }
            }"#;
            let ring = KeyRing::from_bytes(json).expect("legacy key file must load");
            assert_eq!(ring.active_key_id(), "k1");
            assert_eq!(ring.not_after("k1"), None);
            assert!(!ring.active_key_expired_at(i64::MAX));
        }

        #[test]
        fn key_expirations_field_is_parsed_and_exposed_via_accessor() {
            let json = br#"{
                "active_key_id": "k1",
                "keys": {
                    "k1": "1111111111111111111111111111111111111111111111111111111111111111",
                    "k2": "2222222222222222222222222222222222222222222222222222222222222222"
                },
                "key_expirations": { "k1": 2000000000, "k2": 3000000000 }
            }"#;
            let ring = KeyRing::from_bytes(json).expect("ring");
            assert_eq!(ring.not_after("k1"), Some(2000000000));
            assert_eq!(ring.not_after("k2"), Some(3000000000));
            assert_eq!(ring.not_after("unknown"), None);
        }

        #[test]
        fn key_expirations_referencing_unknown_id_is_rejected() {
            // A key_expirations entry that references an id not present in
            // `keys` is a config-file typo — refusing to load is safer than
            // silently ignoring it, because a typo in the active key's
            // expiration would otherwise leave the key never-expiring.
            let json = br#"{
                "active_key_id": "k1",
                "keys": { "k1": "1111111111111111111111111111111111111111111111111111111111111111" },
                "key_expirations": { "k2-typo": 2000000000 }
            }"#;
            let err = KeyRing::from_bytes(json).expect_err("must reject");
            let msg = err.to_string();
            assert!(
                msg.contains("k2-typo") && msg.contains("key_expirations"),
                "got {msg}"
            );
        }

        #[test]
        fn active_key_expired_at_boundary_is_exclusive_at_future_and_inclusive_at_past() {
            // not_after semantics: "key is unusable at and after this time."
            // Boundary cases matter because operators schedule rotations
            // precisely on the minute.
            let json = br#"{
                "active_key_id": "k1",
                "keys": { "k1": "1111111111111111111111111111111111111111111111111111111111111111" },
                "key_expirations": { "k1": 100 }
            }"#;
            let ring = KeyRing::from_bytes(json).expect("ring");
            assert!(!ring.active_key_expired_at(99), "before boundary");
            assert!(ring.active_key_expired_at(100), "at boundary (inclusive)");
            assert!(ring.active_key_expired_at(101), "past boundary");
        }

        #[test]
        fn active_key_without_expiration_never_reports_expired() {
            let ring = make_key_ring("k1", &[("k1", [0x11; 32])]);
            assert!(!ring.active_key_expired_at(i64::MAX));
        }

        #[test]
        fn encrypted_writer_create_refuses_when_active_key_is_expired() {
            // Core admission contract: a key that expired before "now" must
            // not be used for new writes. Historical data encrypted under
            // this key is still readable (active_key() itself does not
            // check expiration) — only the create() path is gated.
            let json = br#"{
                "active_key_id": "k1",
                "keys": { "k1": "1111111111111111111111111111111111111111111111111111111111111111" },
                "key_expirations": { "k1": 1 }
            }"#;
            let ring = KeyRing::from_bytes(json).expect("ring");
            let dir = tempdir();
            let enc_path = dir.join("expired.enc");
            let err = EncryptedWriter::create(&enc_path, &ring).expect_err("must refuse");
            match err {
                EncryptError::ActiveKeyExpired { id, not_after } => {
                    assert_eq!(id, "k1");
                    assert_eq!(not_after, 1);
                }
                other => panic!("expected ActiveKeyExpired, got {other:?}"),
            }
            // The refused create() must not have left any file on disk.
            assert!(
                !enc_path.exists(),
                "expired-key create() must not create file"
            );
        }

        #[test]
        fn encrypted_writer_create_succeeds_with_future_expiration() {
            let future = now_unix_seconds().saturating_add(3600);
            let json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "keys": {{ "k1": "1111111111111111111111111111111111111111111111111111111111111111" }},
                    "key_expirations": {{ "k1": {future} }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("ring");
            let dir = tempdir();
            let enc_path = dir.join("future.enc");
            let mut w = EncryptedWriter::create(&enc_path, &ring).expect("must succeed");
            w.write_chunk(b"payload").expect("write");
            w.finish().expect("finish");
            assert!(enc_path.exists());
        }

        #[test]
        fn non_active_key_expiration_does_not_block_active_key_writes() {
            // Expiration on a non-active key is tracked (useful for audit /
            // operator visibility) but does not gate writes — only the
            // active key's expiration matters for admission.
            let json = br#"{
                "active_key_id": "k1",
                "keys": {
                    "k1": "1111111111111111111111111111111111111111111111111111111111111111",
                    "k2": "2222222222222222222222222222222222222222222222222222222222222222"
                },
                "key_expirations": { "k2": 1 }
            }"#;
            let ring = KeyRing::from_bytes(json).expect("ring");
            assert_eq!(ring.not_after("k2"), Some(1));
            let dir = tempdir();
            let enc_path = dir.join("non_active.enc");
            let _ = EncryptedWriter::create(&enc_path, &ring).expect("active key not expired");
        }

        #[test]
        fn key_expirations_round_trip_through_serde_with_non_empty_map() {
            let mut keys = BTreeMap::new();
            let _ = keys.insert(
                "k1".to_string(),
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            );
            let mut expirations = BTreeMap::new();
            let _ = expirations.insert("k1".to_string(), 5_000_000_000i64);
            let kf = KeyFile {
                active_key_id: "k1".to_string(),
                keys,
                key_expirations: expirations,
                key_derivations: BTreeMap::new(),
                tenant_key_map: BTreeMap::new(),
            };
            let json = serde_json::to_vec(&kf).expect("serialize");
            let round: KeyFile = serde_json::from_slice(&json).expect("deserialize");
            assert_eq!(round.key_expirations.get("k1"), Some(&5_000_000_000));
        }

        #[test]
        fn key_expirations_is_omitted_from_serialization_when_empty() {
            // skip_serializing_if keeps the on-disk shape of legacy key
            // files stable — writing a KeyFile with no expirations produces
            // the same JSON shape pre-expiration builds would have written.
            let kf = KeyFile {
                active_key_id: "k1".to_string(),
                keys: {
                    let mut m = BTreeMap::new();
                    let _ = m.insert(
                        "k1".to_string(),
                        "1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    );
                    m
                },
                key_expirations: BTreeMap::new(),
                key_derivations: BTreeMap::new(),
                tenant_key_map: BTreeMap::new(),
            };
            let json = serde_json::to_string(&kf).expect("serialize");
            assert!(
                !json.contains("key_expirations"),
                "empty map must be omitted: {json}"
            );
        }
    }

    mod key_derivation {
        //! Tests for HKDF-derived key entries in `key_derivations`.
        //!
        //! The round-trip and overlap checks are the safety-critical
        //! cases — derived keys must be distinguishable from raw keys
        //! only at load time (they are identical at use time), and
        //! overlapping ids must be rejected before either entry takes
        //! effect.
        use super::*;

        /// 16-byte IKM (the configured minimum). Chosen to be
        /// recognizably not-random so a reader can tell at a glance
        /// this is test material.
        const TEST_IKM_16: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        /// 32-byte IKM for stronger-than-minimum tests.
        const TEST_IKM_32: &str =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        #[test]
        fn hkdf_sha256_matches_rfc_5869_test_case_3() {
            // RFC 5869 Appendix A Test Case 3 uses empty salt and
            // empty info with a 22-octet IKM of 0x0b repeated. We pin
            // the first 32 bytes of the 42-octet OKM, which is what a
            // 32-byte ChaCha20-Poly1305 key would consume. A
            // regression that silently swapped SHA-256 for another
            // hash, reversed the salt/IKM arguments to `Hkdf::new`,
            // or mis-handled the zero-length salt path would fail
            // here rather than encrypt everyone's data with a key the
            // archive cannot reproduce.
            //
            // Test Case 1 (non-empty info) is not used because our
            // API accepts `info` as free-form UTF-8, not hex-encoded
            // bytes — the RFC's canonical info octets are not a
            // valid UTF-8 string.
            let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"; // 22 bytes
            // First 32 bytes of the 42-byte OKM from RFC 5869 §A.3.
            let expected_hex = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d";

            let json = format!(
                r#"{{
                    "active_key_id": "k-derived",
                    "key_derivations": {{
                        "k-derived": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{ikm}",
                            "salt": "",
                            "info": ""
                        }}
                    }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("ring loads");
            let key = ring.active_key().expect("active key present");
            assert_eq!(hex::encode(**key), expected_hex);
        }

        #[test]
        fn hkdf_info_is_asciistring_bound_not_hex() {
            // `info` in RFC 5869 is a context octet string. We accept
            // it as a UTF-8 string (the serde shape) and pass its bytes
            // directly to HKDF — so changing the `info` text must
            // change the output. Two derivations identical except for
            // `info` should produce different keys.
            let json_a = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "",
                            "info": "ctx-a"
                        }}
                    }}
                }}"#
            );
            let json_b = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "",
                            "info": "ctx-b"
                        }}
                    }}
                }}"#
            );
            let a = KeyRing::from_bytes(json_a.as_bytes()).unwrap();
            let b = KeyRing::from_bytes(json_b.as_bytes()).unwrap();
            let key_a = a.active_key().unwrap();
            let key_b = b.active_key().unwrap();
            assert_ne!(&**key_a, &**key_b, "info separation must alter output");
        }

        #[test]
        fn derived_key_round_trips_through_encrypt_and_decrypt() {
            // The whole point of the KDF wiring: a derived key must be
            // indistinguishable from a raw key at use time. Encrypt a
            // payload with a derived active key, decrypt with the same
            // derivation parameters, and compare.
            let json = format!(
                r#"{{
                    "active_key_id": "k-derived",
                    "key_derivations": {{
                        "k-derived": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "cafef00d",
                            "info": "rustgate-archive/v1/k-derived"
                        }}
                    }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("ring");
            let dir = tempdir();
            let enc_path = dir.join("derived.enc");
            let mut w = EncryptedWriter::create(&enc_path, &ring).expect("writer");
            w.write_chunk(b"hello kdf world").expect("write");
            w.finish().expect("finish");

            let dec_path = dir.join("derived.txt");
            decrypt_file(&enc_path, &dec_path, &ring).expect("decrypt");
            let plain = std::fs::read(&dec_path).expect("read decrypted");
            assert_eq!(plain, b"hello kdf world");
        }

        #[test]
        fn mixed_raw_and_derived_entries_load_together() {
            // Common operational shape: one raw rotation key carried
            // forward for decryption, one newly-derived active key.
            // Both must be usable from the same KeyRing.
            let json = format!(
                r#"{{
                    "active_key_id": "k-derived",
                    "keys": {{
                        "k-raw": "1111111111111111111111111111111111111111111111111111111111111111"
                    }},
                    "key_derivations": {{
                        "k-derived": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "",
                            "info": "k-derived"
                        }}
                    }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("ring");
            assert!(ring.key("k-raw").is_some());
            assert!(ring.key("k-derived").is_some());
            assert_eq!(ring.active_key_id(), "k-derived");
        }

        #[test]
        fn overlapping_id_in_keys_and_key_derivations_is_rejected() {
            // A key id present in both maps is almost certainly a typo
            // — which entry should win is ambiguous and silently
            // preferring one would hide the mistake. The load must
            // refuse before any key material is decoded or derived.
            let json = format!(
                r#"{{
                    "active_key_id": "kdup",
                    "keys": {{
                        "kdup": "1111111111111111111111111111111111111111111111111111111111111111"
                    }},
                    "key_derivations": {{
                        "kdup": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "",
                            "info": ""
                        }}
                    }}
                }}"#
            );
            let err = KeyRing::from_bytes(json.as_bytes()).expect_err("overlap must fail");
            let msg = err.to_string();
            assert!(
                msg.contains("kdup"),
                "error must name the offending id: {msg}"
            );
            assert!(
                msg.contains("both") && msg.contains("key_derivations"),
                "error must explain the overlap: {msg}"
            );
        }

        #[test]
        fn ikm_shorter_than_sixteen_bytes_is_rejected() {
            // HKDF adds no entropy — a trivially short IKM would
            // compromise every derived key. The 16-byte floor catches
            // the obvious operator error of pasting in a truncated
            // secret.
            let short_ikm = "aabbccdd"; // 4 bytes
            let json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{short_ikm}",
                            "salt": "",
                            "info": ""
                        }}
                    }}
                }}"#
            );
            let err = KeyRing::from_bytes(json.as_bytes()).expect_err("must reject");
            match err {
                EncryptError::KeyDerivation { id, reason } => {
                    assert_eq!(id, "k1");
                    assert!(
                        reason.contains("16 bytes"),
                        "reason must cite the floor: {reason}"
                    );
                }
                other => panic!("expected KeyDerivation, got {other:?}"),
            }
        }

        #[test]
        fn invalid_hex_ikm_surfaces_as_key_derivation_error() {
            // A malformed hex IKM should produce a clear error naming
            // the id — not a generic JSON or key-material error —
            // because the user needs to know which derivation entry to
            // fix.
            let json = r#"{
                    "active_key_id": "k1",
                    "key_derivations": {
                        "k1": {
                            "kdf": "hkdf-sha256",
                            "ikm": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                            "salt": "",
                            "info": ""
                        }
                    }
                }"#;
            let _ = TEST_IKM_16; // silence dead-code when this test runs alone
            let err = KeyRing::from_bytes(json.as_bytes()).expect_err("must reject");
            match err {
                EncryptError::KeyDerivation { id, reason } => {
                    assert_eq!(id, "k1");
                    assert!(reason.contains("ikm"), "reason must cite ikm: {reason}");
                }
                other => panic!("expected KeyDerivation, got {other:?}"),
            }
        }

        #[test]
        fn empty_salt_is_accepted_and_matches_no_salt_behavior() {
            // RFC 5869 § 3.1: zero-length salt is valid and HKDF
            // substitutes a hash-sized zero block. The load path must
            // not treat empty salt as an error.
            let json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "",
                            "info": "empty-salt-ok"
                        }}
                    }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("empty salt must load");
            assert!(ring.active_key().is_ok());
        }

        #[test]
        fn active_key_id_pointing_only_at_derived_entry_is_valid() {
            // An install that uses ONLY derived keys (no raw entries at
            // all) must be a valid configuration — the active key may
            // live in `key_derivations`.
            let json = format!(
                r#"{{
                    "active_key_id": "k-derived",
                    "key_derivations": {{
                        "k-derived": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "",
                            "info": "sole-derived"
                        }}
                    }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("ring");
            assert_eq!(ring.active_key_id(), "k-derived");
            assert!(ring.active_key().is_ok());
        }

        #[test]
        fn active_key_id_not_in_either_map_is_rejected_with_updated_message() {
            // The error message now mentions both maps so operators
            // who moved an id from `keys` to `key_derivations` (or
            // vice versa) get a useful hint.
            let json = br#"{
                "active_key_id": "missing",
                "keys": { "k1": "1111111111111111111111111111111111111111111111111111111111111111" }
            }"#;
            let err = KeyRing::from_bytes(json).expect_err("must reject");
            let msg = err.to_string();
            assert!(msg.contains("missing"), "names the id: {msg}");
            assert!(
                msg.contains("keys") && msg.contains("key_derivations"),
                "mentions both maps: {msg}"
            );
        }

        #[test]
        fn key_expirations_may_reference_derived_key_id() {
            // A derived key with a configured expiration must be
            // treated the same as a raw key for the admission check.
            let json = format!(
                r#"{{
                    "active_key_id": "k-derived",
                    "key_derivations": {{
                        "k-derived": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_32}",
                            "salt": "",
                            "info": "expiring"
                        }}
                    }},
                    "key_expirations": {{ "k-derived": 1 }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("ring");
            assert_eq!(ring.not_after("k-derived"), Some(1));
            assert!(
                ring.active_key_expired_at(2),
                "derived key honors expiration"
            );
        }

        #[test]
        fn unknown_kdf_variant_is_rejected_at_parse_time() {
            // `serde(tag = "kdf")` should reject an unknown KDF name
            // with a JSON-parse-level error — not silently fall back
            // to a default. This keeps future additions (e.g. a
            // hypothetical `scrypt` variant) from being silently
            // ignored by older binaries that don't support them.
            let json = br#"{
                "active_key_id": "k1",
                "key_derivations": {
                    "k1": {
                        "kdf": "scrypt",
                        "ikm": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                }
            }"#;
            let err = KeyRing::from_bytes(json).expect_err("must reject unknown kdf");
            let msg = err.to_string();
            assert!(
                msg.contains("scrypt") || msg.contains("variant"),
                "error should mention the unknown tag: {msg}"
            );
        }

        #[test]
        fn key_derivations_roundtrip_through_serde_with_non_empty_map() {
            let mut derivations = BTreeMap::new();
            let _ = derivations.insert(
                "k1".to_string(),
                Derivation::HkdfSha256 {
                    ikm: Some(TEST_IKM_32.to_string()),
                    ikm_from_env: None,
                    ikm_from_file: None,
                    salt: "deadbeef".to_string(),
                    info: "rt".to_string(),
                },
            );
            let kf = KeyFile {
                active_key_id: "k1".to_string(),
                keys: BTreeMap::new(),
                key_expirations: BTreeMap::new(),
                key_derivations: derivations,
                tenant_key_map: BTreeMap::new(),
            };
            let json = serde_json::to_vec(&kf).expect("serialize");
            let round: KeyFile = serde_json::from_slice(&json).expect("deserialize");
            match round.key_derivations.get("k1") {
                Some(Derivation::HkdfSha256 {
                    ikm,
                    ikm_from_env,
                    ikm_from_file,
                    salt,
                    info,
                }) => {
                    assert_eq!(ikm.as_deref(), Some(TEST_IKM_32));
                    assert!(ikm_from_env.is_none());
                    assert!(ikm_from_file.is_none());
                    assert_eq!(salt, "deadbeef");
                    assert_eq!(info, "rt");
                }
                Some(other) => panic!("expected HkdfSha256 round-trip, got {other:?}"),
                None => panic!("k1 round-trip lost"),
            }
        }

        #[test]
        fn key_derivations_is_omitted_from_serialization_when_empty() {
            // skip_serializing_if mirrors the `key_expirations`
            // treatment so pre-KDF key files remain byte-identical on
            // a round-trip through `serde`.
            let kf = KeyFile {
                active_key_id: "k1".to_string(),
                keys: {
                    let mut m = BTreeMap::new();
                    let _ = m.insert(
                        "k1".to_string(),
                        "1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    );
                    m
                },
                key_expirations: BTreeMap::new(),
                key_derivations: BTreeMap::new(),
                tenant_key_map: BTreeMap::new(),
            };
            let json = serde_json::to_string(&kf).expect("serialize");
            assert!(
                !json.contains("key_derivations"),
                "empty map must be omitted: {json}"
            );
        }
    }

    /// Tests for #883 sub-item 1: Argon2id KDF, env / file IKM sources,
    /// rotation-due audit emission, and the no-expirations tracing warn.
    ///
    /// These tests pin the new behaviour shipped with the KDF + key
    /// expiration work. The HKDF + raw-hex backward-compat surface is
    /// covered by the pre-existing `key_derivation` and `key_expiration`
    /// modules above.
    mod kdf_and_rotation {
        use super::*;

        /// 32-byte hex IKM, deliberately recognizable so a reader can
        /// tell at a glance this is test material.
        const TEST_IKM_HEX: &str =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        /// 16-byte hex salt — exactly meets the Argon2 minimum.
        const TEST_SALT_HEX: &str = "00112233445566778899aabbccddeeff";

        // 1. Argon2id derivation — same passphrase + salt + context
        //    produces the same 32-byte key. Round-trip with cheap
        //    parameters so the test is fast.
        #[test]
        fn argon2id_same_input_produces_same_key() {
            // Cheap-param Argon2 so the test does not allocate 19 MiB
            // and run for ~50ms — the determinism contract holds at
            // any work-factor, the high values are an attacker
            // mitigation, not a correctness invariant.
            let json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "argon2id",
                            "ikm": "{TEST_IKM_HEX}",
                            "salt": "{TEST_SALT_HEX}",
                            "params": {{ "m_cost_kib": 64, "t_cost": 1, "p_cost": 1 }}
                        }}
                    }}
                }}"#
            );
            let ring_a = KeyRing::from_bytes(json.as_bytes()).expect("a");
            let ring_b = KeyRing::from_bytes(json.as_bytes()).expect("b");
            let key_a = ring_a.active_key().expect("a key");
            let key_b = ring_b.active_key().expect("b key");
            assert_eq!(&**key_a, &**key_b, "argon2id is deterministic per input");
            // Sanity: the output is exactly the ChaCha20-Poly1305 key
            // length the rest of the archive expects.
            assert_eq!(key_a.len(), 32);
        }

        // 2. HKDF-SHA256 — known-answer test.
        //    The pre-existing `hkdf_sha256_matches_rfc_5869_test_case_3`
        //    test in `key_derivation::tests` already pins the RFC 5869
        //    Test Case 3 vector against the standard. Here we add a
        //    second self-consistency round-trip: same `(ikm, salt,
        //    info)` produces the same output across two independent
        //    `from_bytes` calls. A regression that swapped SHA-256 for
        //    SHA-512 or that misordered Hkdf::new's arguments would
        //    fail the RFC test; a regression that introduced
        //    nondeterminism (e.g. mixing in a timestamp) would fail
        //    here.
        #[test]
        fn hkdf_sha256_round_trip_is_deterministic() {
            let json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{TEST_IKM_HEX}",
                            "salt": "{TEST_SALT_HEX}",
                            "info": "rustgate-archive/v1/k1"
                        }}
                    }}
                }}"#
            );
            let ring_a = KeyRing::from_bytes(json.as_bytes()).expect("a");
            let ring_b = KeyRing::from_bytes(json.as_bytes()).expect("b");
            let key_a = ring_a.active_key().expect("a key");
            let key_b = ring_b.active_key().expect("b key");
            assert_eq!(&**key_a, &**key_b);
        }

        // 3. Key with `not_after` in the past is rejected on new write.
        //    The active-key-expired admission gate is the core
        //    fail-closed contract — pre-existing
        //    `encrypted_writer_create_refuses_when_active_key_is_expired`
        //    already covers this for the writer side; here we pin the
        //    `active_key_expired_at` accessor directly so a regression
        //    that decoupled the two paths would fail at the unit-level
        //    rather than only at the integration level.
        #[test]
        fn active_key_with_not_after_in_past_reports_expired() {
            let json = br#"{
                "active_key_id": "k1",
                "keys": {
                    "k1": "1111111111111111111111111111111111111111111111111111111111111111"
                },
                "key_expirations": { "k1": 1000 }
            }"#;
            let ring = KeyRing::from_bytes(json).expect("ring");
            assert!(ring.active_key_expired_at(1000));
            assert!(ring.active_key_expired_at(2000));
            assert!(!ring.active_key_expired_at(999));
        }

        /// `(event_type, kid, days_remaining)` extracted from an audit
        /// event by [`EventCapture::handle_event`]. Aliased to keep
        /// clippy's `type_complexity` lint quiet without an inline
        /// `#[allow]` annotation.
        type CapturedFields = (Option<String>, Option<String>, Option<i64>);

        /// Local `tracing_subscriber::Layer` that captures structured
        /// fields from events at a configurable target/level. Defined
        /// once and reused across the warn/audit tests below — this
        /// keeps the orphan-rule-friendly `impl Layer<S> for Self`
        /// pattern (no `Arc<Foreign>` blanket impls).
        struct EventCapture {
            target_match: &'static str,
            level_match: Option<tracing::Level>,
            event_type_match: Option<&'static str>,
            hits: std::sync::Mutex<Vec<CapturedFields>>,
        }

        impl EventCapture {
            fn new(
                target_match: &'static str,
                level_match: Option<tracing::Level>,
                event_type_match: Option<&'static str>,
            ) -> Self {
                Self {
                    target_match,
                    level_match,
                    event_type_match,
                    hits: std::sync::Mutex::new(Vec::new()),
                }
            }
        }

        impl EventCapture {
            fn handle_event<S>(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) where
                S: tracing::Subscriber,
            {
                let meta = event.metadata();
                if meta.target() != self.target_match {
                    return;
                }
                if let Some(level) = self.level_match
                    && *meta.level() != level
                {
                    return;
                }

                struct Visit {
                    event_type: Option<String>,
                    kid: Option<String>,
                    days_remaining: Option<i64>,
                }
                impl tracing::field::Visit for Visit {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        match field.name() {
                            "event_type" => self.event_type = Some(value.to_string()),
                            "kid" => self.kid = Some(value.to_string()),
                            _ => {}
                        }
                    }
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        match field.name() {
                            "event_type" => self.event_type = Some(format!("{value:?}")),
                            "kid" => self.kid = Some(format!("{value:?}")),
                            _ => {}
                        }
                    }
                    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                        if field.name() == "days_remaining" {
                            self.days_remaining = Some(value);
                        }
                    }
                }
                let mut visit = Visit {
                    event_type: None,
                    kid: None,
                    days_remaining: None,
                };
                event.record(&mut visit);
                if let Some(et) = self.event_type_match
                    && visit.event_type.as_deref() != Some(et)
                {
                    return;
                }
                let mut hits = self.hits.lock().expect("event capture mutex");
                hits.push((visit.event_type, visit.kid, visit.days_remaining));
            }
        }

        impl<S> tracing_subscriber::Layer<S> for EventCapture
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                cx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.handle_event(event, cx);
            }
        }

        // `tracing_subscriber::registry().with(...)` and
        // `with_default(...)` require an owned `Layer`. We want the
        // capture to outlive the subscriber so the test can inspect
        // its `hits`, so we pass a `&'static EventCapture` leaked
        // for the test's lifetime. This blanket impl forwards
        // `Layer<S>` from the static reference to the underlying
        // capture.
        impl<S> tracing_subscriber::Layer<S> for &'static EventCapture
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                cx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                (*self).handle_event(event, cx);
            }
        }

        // 4. Key without `not_after` loads (backward compat) and emits
        //    a tracing warn so operators are nudged toward setting
        //    rotation. The warn-emission is observed via the
        //    `EventCapture` layer above filtering on
        //    `target = "rustgate_archive::encrypted"`.
        #[test]
        fn key_without_not_after_loads_and_emits_rotation_hygiene_warn() {
            use tracing_subscriber::layer::SubscriberExt;

            // Leak the capture into a `&'static` so the layer impl
            // satisfies `Layer<S>: 'static` without an Arc<Foreign>
            // blanket impl. Test-only — short-lived process means
            // the leak is benign.
            let layer_ref: &'static EventCapture = Box::leak(Box::new(EventCapture::new(
                "rustgate_archive::encrypted",
                Some(tracing::Level::WARN),
                None,
            )));

            let subscriber = tracing_subscriber::registry().with(layer_ref);
            tracing::subscriber::with_default(subscriber, || {
                let json = br#"{
                    "active_key_id": "k1",
                    "keys": { "k1": "1111111111111111111111111111111111111111111111111111111111111111" }
                }"#;
                let ring = KeyRing::from_bytes(json).expect("legacy key file must load");
                assert_eq!(ring.active_key_id(), "k1");
                // Confirm the key is usable — the warn is hygiene
                // signalling, not a refusal.
                assert!(ring.active_key().is_ok());
            });

            let hits = layer_ref.hits.lock().expect("warn capture mutex");
            assert!(
                !hits.is_empty(),
                "loading a key file with no key_expirations must emit a tracing warn"
            );
        }

        // 5. Active key with `not_after` ≤ 14 days from now emits the
        //    `archive.key_rotation_due` audit event with the right
        //    `kid` and `days_remaining`. Uses the doc-hidden
        //    `emit_rotation_signals_at` accessor with a synthetic clock
        //    so the test does not depend on wall-clock time.
        #[test]
        fn active_key_within_rotation_window_emits_rotation_due_audit() {
            use tracing_subscriber::layer::SubscriberExt;

            // Leak the capture into a `&'static` so the layer impl
            // satisfies `Layer<S>: 'static` without an Arc<Foreign>
            // blanket impl. Test-only — short-lived process means
            // the leak is benign.
            let layer_ref: &'static EventCapture = Box::leak(Box::new(EventCapture::new(
                "audit",
                None,
                Some("archive.key_rotation_due"),
            )));

            // not_after is 7 days after the synthetic now.
            let now: i64 = 1_700_000_000;
            let not_after = now + 7 * 86_400;
            let json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "keys": {{ "k1": "1111111111111111111111111111111111111111111111111111111111111111" }},
                    "key_expirations": {{ "k1": {not_after} }}
                }}"#
            );
            let ring = KeyRing::from_bytes(json.as_bytes()).expect("ring");

            let subscriber = tracing_subscriber::registry().with(layer_ref);
            tracing::subscriber::with_default(subscriber, || {
                ring.emit_rotation_signals_at(now);
            });

            let hits = layer_ref.hits.lock().expect("audit capture mutex");
            assert_eq!(
                hits.len(),
                1,
                "exactly one rotation_due audit event must fire for a key 7 days out"
            );
            let (event_type, kid, days_remaining) = &hits[0];
            assert_eq!(
                event_type.as_deref(),
                Some("archive.key_rotation_due"),
                "event_type must match"
            );
            assert_eq!(*days_remaining, Some(7), "days_remaining must be 7");
            assert!(
                kid.as_ref().is_some_and(|k| k.contains("k1")),
                "kid must name the active key: {kid:?}"
            );
        }

        // 6. Existing test fixtures (raw hex-key path) still pass. The
        //    full encrypted-tests module already runs against the
        //    pre-PR shape — we re-pin the no-expirations + raw-hex
        //    happy path here so a future refactor that mistakenly
        //    drops backward compat trips a test in this module rather
        //    than in the unrelated `tests::key_file_validation` block.
        #[test]
        fn raw_hex_key_without_expirations_or_derivations_loads_and_writes() {
            let json = br#"{
                "active_key_id": "k1",
                "keys": { "k1": "1111111111111111111111111111111111111111111111111111111111111111" }
            }"#;
            let ring = KeyRing::from_bytes(json).expect("legacy ring");
            assert_eq!(ring.active_key_id(), "k1");
            assert!(ring.active_key().is_ok());

            // Round-trip a small payload so the writer path is
            // exercised end-to-end.
            let dir = tempdir();
            let enc_path = dir.join("legacy.enc");
            let dec_path = dir.join("legacy.txt");
            {
                let mut w = EncryptedWriter::create(&enc_path, &ring).expect("writer");
                w.write_chunk(b"legacy-fixture").expect("write");
                w.finish().expect("finish");
            }
            decrypt_file(&enc_path, &dec_path, &ring).expect("decrypt");
            assert_eq!(std::fs::read(&dec_path).unwrap(), b"legacy-fixture");
        }

        // 7. Passphrase material from `ikm_from_file` is wrapped in
        //    `Zeroizing` for the lifetime of derivation. We cannot
        //    directly observe memory wipe in safe Rust, but we can
        //    pin the functional contract that the file-IKM source
        //    produces the same key as the inline-hex IKM source for
        //    the same plaintext. The zeroize-on-drop guarantee is
        //    provided by `Zeroizing<T>` on the resolved-IKM buffer
        //    (`ResolvedIkm::bytes`); the test exercises the file
        //    path so a future refactor that accidentally swapped
        //    `Zeroizing<Vec<u8>>` for a bare `Vec<u8>` would fail
        //    review even if it compiled. (We avoid `ikm_from_env`
        //    here because Rust 2024 made `std::env::set_var` unsafe
        //    and the workspace forbids `unsafe` code.)
        #[test]
        fn ikm_from_file_yields_same_key_as_inline_hex() {
            // Choose a 32-byte fixture so the inline-hex spelling
            // is unambiguous for round-trip comparison.
            let passphrase = b"rustgate-test-passphrase-32-byte";
            assert_eq!(passphrase.len(), 32, "fixture must be exactly 32 bytes");
            let inline_hex = hex::encode(passphrase);

            // Write the passphrase to a 0o600 file so
            // `read_secret_file` accepts it.
            let dir = tempdir();
            let secret_path = dir.join("kdf-passphrase");
            std::fs::write(&secret_path, passphrase).expect("write secret");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&secret_path).unwrap().permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&secret_path, perms).expect("chmod 0600");
            }

            let inline_json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "hkdf-sha256",
                            "ikm": "{inline_hex}",
                            "salt": "{TEST_SALT_HEX}",
                            "info": "leak-test"
                        }}
                    }}
                }}"#
            );
            let path_string = secret_path.display().to_string();
            let file_json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "hkdf-sha256",
                            "ikm_from_file": "{path_string}",
                            "salt": "{TEST_SALT_HEX}",
                            "info": "leak-test"
                        }}
                    }}
                }}"#
            );

            let ring_inline = KeyRing::from_bytes(inline_json.as_bytes()).expect("inline");
            let ring_file = KeyRing::from_bytes(file_json.as_bytes()).expect("file");
            let key_inline = ring_inline.active_key().expect("inline key");
            let key_file = ring_file.active_key().expect("file key");
            assert_eq!(
                &**key_inline, &**key_file,
                "file IKM must produce the same derived key as inline IKM for the same plaintext"
            );
        }

        // Bonus: HKDF / Argon2id refuse a derivation entry with no IKM
        //    source at all, because the legacy default-string path
        //    (empty hex decodes to zero bytes, which then fails the
        //    16-byte floor) is no longer the only failure mode — an
        //    operator who omits all three must hit the new
        //    "no IKM source set" error rather than the older
        //    less-actionable "ikm too short" message.
        #[test]
        fn derivation_without_any_ikm_source_is_rejected() {
            let json = br#"{
                "active_key_id": "k1",
                "key_derivations": {
                    "k1": {
                        "kdf": "hkdf-sha256",
                        "salt": ""
                    }
                }
            }"#;
            let err = KeyRing::from_bytes(json).expect_err("must reject");
            match err {
                EncryptError::KeyDerivation { id, reason } => {
                    assert_eq!(id, "k1");
                    assert!(
                        reason.contains("no IKM source"),
                        "reason should name the missing source: {reason}"
                    );
                }
                other => panic!("expected KeyDerivation, got {other:?}"),
            }
        }

        // Bonus: Argon2id with a too-short salt is rejected. The
        //    salt floor is part of the security posture, not just
        //    operator hygiene.
        #[test]
        fn argon2id_short_salt_is_rejected() {
            let json = format!(
                r#"{{
                    "active_key_id": "k1",
                    "key_derivations": {{
                        "k1": {{
                            "kdf": "argon2id",
                            "ikm": "{TEST_IKM_HEX}",
                            "salt": "0011",
                            "params": {{ "m_cost_kib": 64, "t_cost": 1, "p_cost": 1 }}
                        }}
                    }}
                }}"#
            );
            let err = KeyRing::from_bytes(json.as_bytes()).expect_err("must reject");
            match err {
                EncryptError::KeyDerivation { id, reason } => {
                    assert_eq!(id, "k1");
                    assert!(
                        reason.contains("8 bytes"),
                        "reason should cite the 8-byte floor: {reason}"
                    );
                }
                other => panic!("expected KeyDerivation, got {other:?}"),
            }
        }
    }
}
