// Copyright © 2026 Roberto Chiofalo.

//! MAVLink v2 message signing: verification, re-signing, and replay
//! defence.
//!
//! MAVLink v2 carries an optional 13-byte signature trailer
//! (`LINK_ID(1) + TIMESTAMP(6) + SIGNATURE(6)`) when the `SIGNED`
//! INCOMPAT flag is set. The [`crate::frame::MavlinkFrameCodec`] slices
//! these frames out of the byte stream and enforces *presence* of the
//! trailer; this module enforces its *validity*.
//!
//! # The signature algorithm
//!
//! Despite the umbrella issue describing it as "HMAC-SHA256", MAVLink v2
//! signing is **not** RFC 2104 HMAC. The spec computes:
//!
//! ```text
//! signature = SHA-256(secret_key ‖ frame_without_signature)[..6]
//! ```
//!
//! where `frame_without_signature` is every byte from the `STX` through
//! the 6-byte `TIMESTAMP` — i.e. the whole frame except the trailing
//! 6-byte signature. The 32-byte `secret_key` is simply prepended to the
//! hash input. We implement the real spec algorithm (not HMAC) so that
//! frames round-trip against MAVProxy / pymavlink reference captures,
//! which is the acceptance criterion for this work.
//!
//! # Replay defence
//!
//! The 48-bit `TIMESTAMP` counts 10-microsecond ticks since
//! 2015-01-01T00:00:00Z. The spec requires it to advance monotonically
//! per signing stream. We pin replay rejection to the
//! `(system_id, component_id, link_id)` tuple — a sender that reuses or
//! rewinds a timestamp on a tuple we have already seen is rejected. The
//! seen-timestamp table is a bounded LRU (default
//! [`DEFAULT_REPLAY_CAPACITY`]) so a hostile sender spraying synthetic
//! tuples cannot drive unbounded memory growth; the cost of eviction is
//! that a long-idle tuple can replay one stale frame after its entry is
//! evicted, which is an acceptable trade against the memory bound.
//!
//! # Outbound: re-signing
//!
//! [`SigningKeyStore::resign`] takes an already-signed v2 frame and
//! replaces its trailer with a fresh `(link_id, timestamp, signature)`
//! computed under a store key. It deliberately does **not** turn an
//! unsigned frame into a signed one: setting the `SIGNED` INCOMPAT bit
//! after the fact would invalidate the frame's CRC (the CRC covers the
//! INCOMPAT byte), which would require re-running the per-`MSG_ID`
//! CRC-EXTRA computation. Frames the router forwards already arrive
//! signed (the codec rejects unsigned v2 by default), so re-signing the
//! trailer in place is the path that matters.

use std::collections::HashMap;
use std::num::NonZeroUsize;

use bytes::Bytes;
use lru::LruCache;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::frame::{
    MAVLINK_CRC_LEN, MAVLINK_IFLAG_SIGNED, MAVLINK_SIGNATURE_LEN, MAVLINK_V2_HEADER_LEN,
    MAVLINK_V2_MAGIC,
};

/// Length of a MAVLink v2 signing secret key, in bytes.
pub const SIGNING_KEY_LEN: usize = 32;

/// Length of the truncated SHA-256 signature on the wire, in bytes.
pub const SIGNATURE_LEN: usize = 6;

/// Length of the 48-bit signing timestamp on the wire, in bytes.
const TIMESTAMP_LEN: usize = 6;

/// Byte offset of the `SYSID` field in a v2 header.
const V2_SYSID_OFFSET: usize = 5;

/// Byte offset of the `COMPID` field in a v2 header.
const V2_COMPID_OFFSET: usize = 6;

/// Byte offset of the `INCOMPAT_FLAGS` field in a v2 header.
const V2_INCOMPAT_OFFSET: usize = 2;

/// Default capacity of the per-tuple replay-timestamp LRU.
///
/// Matches ADR 0020 decision 3. One `u64` per `(sysid, compid, link_id)`
/// tuple; 1024 tuples comfortably covers a tactical fleet while bounding
/// the table to a few tens of kilobytes.
pub const DEFAULT_REPLAY_CAPACITY: usize = 1024;

/// MAVLink signing epoch: seconds from the Unix epoch to
/// 2015-01-01T00:00:00Z. The 48-bit timestamp counts 10-µs ticks from
/// this instant.
const MAVLINK_EPOCH_UNIX_SECS: u64 = 1_420_070_400;

/// A 32-byte MAVLink v2 signing key, wrapped so its bytes are wiped on
/// drop.
pub type SigningKey = Zeroizing<[u8; SIGNING_KEY_LEN]>;

/// Replay-table key: a signing stream is identified by the originating
/// system, component, and link.
type StreamId = (u8, u8, u8);

/// Errors produced while verifying or re-signing a MAVLink v2 frame.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// The frame's leading byte is not the v2 magic (`0xFD`). v1 frames
    /// have no signature field and are handled by the codec's v1 policy,
    /// not here.
    #[error("not a MAVLink v2 frame (magic 0x{magic:02X})")]
    NotV2 { magic: u8 },

    /// The frame's `SIGNED` INCOMPAT bit is clear, so there is no
    /// signature trailer to verify.
    #[error("MAVLink v2 frame is not signed (SIGNED INCOMPAT bit clear)")]
    NotSigned,

    /// The frame is shorter than the minimum signed v2 frame
    /// (`header + CRC + signature trailer`).
    #[error("MAVLink v2 signed frame too short: {len} bytes (min {min})")]
    TooShort { len: usize, min: usize },

    /// No signing key is registered for the frame's `LINK_ID`.
    #[error("no signing key registered for LINK_ID {link_id}")]
    UnknownLinkId { link_id: u8 },

    /// The computed signature does not match the trailer's signature.
    /// Compared in constant time so a mismatch reveals nothing about how
    /// many leading bytes were correct.
    #[error("MAVLink v2 signature mismatch")]
    SignatureMismatch,

    /// The frame's timestamp does not advance past the last accepted
    /// timestamp for its `(system_id, component_id, link_id)` stream.
    #[error(
        "replayed MAVLink timestamp for stream ({system_id}, {component_id}, {link_id}): \
         got {timestamp}, last accepted {last}"
    )]
    ReplayedTimestamp {
        system_id: u8,
        component_id: u8,
        link_id: u8,
        timestamp: u64,
        last: u64,
    },
}

/// The identity-bearing fields recovered from a successfully verified
/// signed frame.
///
/// PR 2's UDP/TCP listener maps `link_id` (and, where configured,
/// `system_id` / `component_id`) onto a rustgate `Identity` via the
/// signing manifest described in ADR 0020. Returning these from
/// [`SigningKeyStore::verify`] keeps the listener from re-walking the
/// header byte offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedFrame {
    /// `SYSID` from the v2 header.
    pub system_id: u8,
    /// `COMPID` from the v2 header.
    pub component_id: u8,
    /// `LINK_ID` from the signature trailer.
    pub link_id: u8,
    /// 48-bit signing timestamp from the trailer (10-µs ticks since
    /// 2015-01-01T00:00:00Z).
    pub timestamp: u64,
}

/// Per-link MAVLink v2 signing keys plus a bounded replay-timestamp
/// table.
///
/// Keys are looked up by `LINK_ID`: a MAVLink link is the unit a single
/// secret key protects, and the `LINK_ID` byte in the signature trailer
/// names which link signed the frame. Construct with [`Self::new`],
/// register keys with [`Self::insert_key`], then verify inbound frames
/// with [`Self::verify`] and re-sign outbound frames with
/// [`Self::resign`].
pub struct SigningKeyStore {
    keys: HashMap<u8, SigningKey>,
    replay: Mutex<LruCache<StreamId, u64>>,
}

impl std::fmt::Debug for SigningKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material. The link IDs are not secret; the keys
        // they map to are.
        let mut link_ids: Vec<u8> = self.keys.keys().copied().collect();
        link_ids.sort_unstable();
        f.debug_struct("SigningKeyStore")
            .field("link_ids", &link_ids)
            .field("keys", &"[REDACTED]")
            .field("replay_len", &self.replay.lock().len())
            .finish()
    }
}

impl Default for SigningKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningKeyStore {
    /// Create an empty store with the default replay capacity
    /// ([`DEFAULT_REPLAY_CAPACITY`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_replay_capacity(
            NonZeroUsize::new(DEFAULT_REPLAY_CAPACITY).unwrap_or(NonZeroUsize::MIN),
        )
    }

    /// Create an empty store with a caller-chosen replay-table capacity.
    #[must_use]
    pub fn with_replay_capacity(capacity: NonZeroUsize) -> Self {
        Self {
            keys: HashMap::new(),
            replay: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Register (or replace) the signing key for a `LINK_ID`.
    ///
    /// The previous key, if any, is wiped on drop because it lives behind
    /// [`Zeroizing`].
    pub fn insert_key(&mut self, link_id: u8, key: [u8; SIGNING_KEY_LEN]) {
        let _ = self.keys.insert(link_id, Zeroizing::new(key));
    }

    /// Whether a signing key is registered for `link_id`.
    #[must_use]
    pub fn contains_link(&self, link_id: u8) -> bool {
        self.keys.contains_key(&link_id)
    }

    /// Number of registered links.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no signing keys are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verify a signed MAVLink v2 frame and record its timestamp.
    ///
    /// On success the frame's signature matched the registered key for
    /// its `LINK_ID` and its timestamp advanced past the last accepted
    /// timestamp for its stream; the stream's last-seen timestamp is
    /// updated. On any failure the replay table is left unchanged.
    ///
    /// # Errors
    ///
    /// - [`SigningError::NotV2`] / [`SigningError::NotSigned`] /
    ///   [`SigningError::TooShort`] — the frame is not a well-formed
    ///   signed v2 frame.
    /// - [`SigningError::UnknownLinkId`] — no key for the trailer's
    ///   `LINK_ID`.
    /// - [`SigningError::SignatureMismatch`] — the signature is invalid.
    /// - [`SigningError::ReplayedTimestamp`] — the timestamp did not
    ///   advance.
    pub fn verify(&self, frame: &[u8]) -> Result<VerifiedFrame, SigningError> {
        let parts = SignedFrameParts::parse(frame)?;

        let key = self
            .keys
            .get(&parts.link_id)
            .ok_or(SigningError::UnknownLinkId {
                link_id: parts.link_id,
            })?;

        let expected = compute_signature(key, parts.signed_prefix);
        // Constant-time compare: a timing-variable `==` would leak how
        // many leading signature bytes an attacker guessed correctly.
        if expected.ct_eq(parts.signature).unwrap_u8() != 1 {
            return Err(SigningError::SignatureMismatch);
        }

        // Signature is valid; enforce monotonic timestamp last so a forged
        // frame can never perturb the replay table.
        let stream = (parts.system_id, parts.component_id, parts.link_id);
        let mut replay = self.replay.lock();
        if let Some(&last) = replay.peek(&stream)
            && parts.timestamp <= last
        {
            return Err(SigningError::ReplayedTimestamp {
                system_id: parts.system_id,
                component_id: parts.component_id,
                link_id: parts.link_id,
                timestamp: parts.timestamp,
                last,
            });
        }
        let _ = replay.put(stream, parts.timestamp);

        Ok(VerifiedFrame {
            system_id: parts.system_id,
            component_id: parts.component_id,
            link_id: parts.link_id,
            timestamp: parts.timestamp,
        })
    }

    /// Re-sign an already-signed v2 frame with a fresh `link_id` and
    /// `timestamp`, returning the rebuilt frame.
    ///
    /// The header (including the `SIGNED` INCOMPAT bit) and CRC are
    /// copied verbatim — only the 13-byte trailer is replaced — so the
    /// frame's CRC stays valid without re-running the CRC-EXTRA
    /// computation. The signature is computed under the store key
    /// registered for `link_id`.
    ///
    /// # Errors
    ///
    /// - [`SigningError::NotV2`] / [`SigningError::NotSigned`] /
    ///   [`SigningError::TooShort`] — `frame` is not a well-formed signed
    ///   v2 frame.
    /// - [`SigningError::UnknownLinkId`] — no key for the requested
    ///   outbound `link_id`.
    pub fn resign(&self, frame: &[u8], link_id: u8, timestamp: u64) -> Result<Bytes, SigningError> {
        let parts = SignedFrameParts::parse(frame)?;
        let key = self
            .keys
            .get(&link_id)
            .ok_or(SigningError::UnknownLinkId { link_id })?;

        // `signed_prefix` is STX..CRC (everything before the trailer).
        // Strip the original `(link_id, timestamp)` — the trailing 7
        // bytes of `signed_prefix` — to recover the header+payload+CRC,
        // then rebuild the trailer.
        let through_crc = &parts.signed_prefix[..parts.signed_prefix.len() - (1 + TIMESTAMP_LEN)];
        Ok(sign_through_crc(key, through_crc, link_id, timestamp))
    }
}

/// Borrowed view over the fields of a signed v2 frame.
struct SignedFrameParts<'a> {
    system_id: u8,
    component_id: u8,
    link_id: u8,
    timestamp: u64,
    /// Every byte hashed for the signature: `STX` through `TIMESTAMP`
    /// (the whole frame minus the trailing 6-byte signature).
    signed_prefix: &'a [u8],
    /// The 6-byte signature on the wire.
    signature: &'a [u8],
}

impl<'a> SignedFrameParts<'a> {
    fn parse(frame: &'a [u8]) -> Result<Self, SigningError> {
        let min = MAVLINK_V2_HEADER_LEN + MAVLINK_CRC_LEN + MAVLINK_SIGNATURE_LEN;
        match frame.first() {
            Some(&MAVLINK_V2_MAGIC) => {}
            Some(&magic) => return Err(SigningError::NotV2 { magic }),
            None => return Err(SigningError::TooShort { len: 0, min }),
        }
        if frame.len() < min {
            return Err(SigningError::TooShort {
                len: frame.len(),
                min,
            });
        }
        if frame[V2_INCOMPAT_OFFSET] & MAVLINK_IFLAG_SIGNED == 0 {
            return Err(SigningError::NotSigned);
        }

        let total = frame.len();
        let sig_start = total - SIGNATURE_LEN;
        let ts_start = sig_start - TIMESTAMP_LEN;
        let link_id = frame[ts_start - 1];

        let mut ts = 0u64;
        for (i, &b) in frame[ts_start..sig_start].iter().enumerate() {
            ts |= u64::from(b) << (8 * i);
        }

        Ok(Self {
            system_id: frame[V2_SYSID_OFFSET],
            component_id: frame[V2_COMPID_OFFSET],
            link_id,
            timestamp: ts,
            signed_prefix: &frame[..sig_start],
            signature: &frame[sig_start..],
        })
    }
}

/// Compute the 6-byte MAVLink v2 signature over an already-assembled
/// signed prefix (`STX` … `TIMESTAMP`).
///
/// `signed_prefix` must be every frame byte except the trailing 6-byte
/// signature. Exposed for known-answer tests and for callers assembling
/// frames by hand.
#[must_use]
pub fn compute_signature(key: &[u8; SIGNING_KEY_LEN], signed_prefix: &[u8]) -> [u8; SIGNATURE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_slice());
    hasher.update(signed_prefix);
    let digest = hasher.finalize();
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(&digest[..SIGNATURE_LEN]);
    sig
}

/// Build a signed v2 frame from a header-through-CRC body, appending the
/// `(link_id, timestamp, signature)` trailer.
///
/// `through_crc` is the frame from `STX` through the 2-byte CRC, with the
/// `SIGNED` INCOMPAT bit already set and the CRC already valid.
fn sign_through_crc(
    key: &[u8; SIGNING_KEY_LEN],
    through_crc: &[u8],
    link_id: u8,
    timestamp: u64,
) -> Bytes {
    let mut buf = Vec::with_capacity(through_crc.len() + MAVLINK_SIGNATURE_LEN);
    buf.extend_from_slice(through_crc);
    buf.push(link_id);
    buf.extend_from_slice(&timestamp.to_le_bytes()[..TIMESTAMP_LEN]);
    let sig = compute_signature(key, &buf);
    buf.extend_from_slice(&sig);
    Bytes::from(buf)
}

/// Convert a wall-clock instant into a MAVLink 48-bit signing timestamp
/// (10-µs ticks since 2015-01-01T00:00:00Z).
///
/// Returns `None` for instants before the MAVLink epoch or beyond the
/// 48-bit range. Callers that need a monotonic source should track the
/// last value they emitted and advance by at least one tick.
#[must_use]
pub fn signing_timestamp(now: std::time::SystemTime) -> Option<u64> {
    let unix = now.duration_since(std::time::UNIX_EPOCH).ok()?;
    let ticks_since_unix = unix.as_micros() / 10;
    let epoch_ticks = u128::from(MAVLINK_EPOCH_UNIX_SECS) * 100_000;
    let ticks = ticks_since_unix.checked_sub(epoch_ticks)?;
    // The wire field is 48 bits.
    if ticks >= (1u128 << 48) {
        return None;
    }
    u64::try_from(ticks).ok()
}

/// Build a complete signed v2 frame from scratch — header (SIGNED bit
/// set), `payload_len` payload bytes, an opaque 2-byte CRC, and a trailer
/// signed under `key`.
///
/// Test-only helper shared with the `listener` module's tests; the CRC is
/// not a real MAVLink CRC because the signing path never inspects it.
#[cfg(test)]
pub(crate) fn sign_through_crc_for_test(
    key: &[u8; SIGNING_KEY_LEN],
    system_id: u8,
    component_id: u8,
    link_id: u8,
    timestamp: u64,
    payload_len: u8,
) -> Bytes {
    let mut through_crc = vec![
        MAVLINK_V2_MAGIC,     // STX
        payload_len,          // LEN
        MAVLINK_IFLAG_SIGNED, // INCOMPAT (signed)
        0x00,                 // COMPAT
        0x07,                 // SEQ
        system_id,
        component_id,
        0x00,
        0x00,
        0x00, // MSGID = 0 (HEARTBEAT)
    ];
    through_crc.extend(std::iter::repeat_n(0xAB, payload_len as usize)); // payload
    through_crc.extend_from_slice(&[0xDE, 0xAD]); // CRC (opaque to signing)
    sign_through_crc(key, &through_crc, link_id, timestamp)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    const KEY_A: [u8; 32] = [0x11; 32];
    const KEY_B: [u8; 32] = [0x22; 32];

    /// Build a minimal valid signed v2 frame: 10-byte header (SIGNED bit
    /// set), `payload_len` payload bytes, 2-byte CRC, then a trailer
    /// signed under `key`.
    fn make_signed_frame(
        key: &[u8; 32],
        system_id: u8,
        component_id: u8,
        link_id: u8,
        timestamp: u64,
        payload_len: u8,
    ) -> Vec<u8> {
        let mut through_crc = vec![
            MAVLINK_V2_MAGIC,     // STX
            payload_len,          // LEN
            MAVLINK_IFLAG_SIGNED, // INCOMPAT (signed)
            0x00,                 // COMPAT
            0x07,                 // SEQ
            system_id,
            component_id,
            0x00,
            0x00,
            0x00, // MSGID = 0 (HEARTBEAT)
        ];
        through_crc.extend(std::iter::repeat_n(0xAB, payload_len as usize)); // payload
        through_crc.extend_from_slice(&[0xDE, 0xAD]); // CRC (opaque to signing)

        let signed = sign_through_crc(key, &through_crc, link_id, timestamp);
        signed.to_vec()
    }

    #[test]
    fn verify_accepts_a_correctly_signed_frame() {
        let mut store = SigningKeyStore::new();
        store.insert_key(3, KEY_A);

        let frame = make_signed_frame(&KEY_A, 42, 1, 3, 1000, 9);
        let verified = store.verify(&frame).unwrap();

        assert_eq!(
            verified,
            VerifiedFrame {
                system_id: 42,
                component_id: 1,
                link_id: 3,
                timestamp: 1000,
            }
        );
    }

    #[test]
    fn verify_rejects_a_wrong_key() {
        let mut store = SigningKeyStore::new();
        store.insert_key(3, KEY_B); // store has B, frame signed with A

        let frame = make_signed_frame(&KEY_A, 42, 1, 3, 1000, 4);
        assert!(matches!(
            store.verify(&frame),
            Err(SigningError::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_rejects_a_flipped_payload_byte() {
        let mut store = SigningKeyStore::new();
        store.insert_key(0, KEY_A);

        let mut frame = make_signed_frame(&KEY_A, 1, 1, 0, 500, 6);
        // Flip a payload byte; the signature covers the payload.
        frame[MAVLINK_V2_HEADER_LEN] ^= 0xFF;
        assert!(matches!(
            store.verify(&frame),
            Err(SigningError::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_rejects_unknown_link_id() {
        let mut store = SigningKeyStore::new();
        store.insert_key(1, KEY_A);

        let frame = make_signed_frame(&KEY_A, 1, 1, 9, 500, 2);
        assert!(matches!(
            store.verify(&frame),
            Err(SigningError::UnknownLinkId { link_id: 9 })
        ));
    }

    #[test]
    fn verify_rejects_an_unsigned_frame() {
        let mut store = SigningKeyStore::new();
        store.insert_key(0, KEY_A);

        let mut frame = make_signed_frame(&KEY_A, 1, 1, 0, 500, 2);
        frame[V2_INCOMPAT_OFFSET] = 0x00; // clear SIGNED bit
        assert!(matches!(store.verify(&frame), Err(SigningError::NotSigned)));
    }

    #[test]
    fn verify_rejects_a_v1_frame() {
        let store = SigningKeyStore::new();
        let frame = vec![0xFE; MAVLINK_V2_HEADER_LEN + MAVLINK_CRC_LEN + MAVLINK_SIGNATURE_LEN];
        assert!(matches!(
            store.verify(&frame),
            Err(SigningError::NotV2 { magic: 0xFE })
        ));
    }

    #[test]
    fn verify_rejects_a_too_short_frame() {
        let store = SigningKeyStore::new();
        let frame = vec![MAVLINK_V2_MAGIC; 5];
        assert!(matches!(
            store.verify(&frame),
            Err(SigningError::TooShort { .. })
        ));
    }

    #[test]
    fn replay_rejects_a_non_advancing_timestamp() {
        let mut store = SigningKeyStore::new();
        store.insert_key(2, KEY_A);

        let first = make_signed_frame(&KEY_A, 7, 1, 2, 100, 3);
        store.verify(&first).unwrap();

        // Same timestamp again → replay.
        let replayed = make_signed_frame(&KEY_A, 7, 1, 2, 100, 3);
        assert!(matches!(
            store.verify(&replayed),
            Err(SigningError::ReplayedTimestamp { last: 100, .. })
        ));

        // An older timestamp → replay.
        let older = make_signed_frame(&KEY_A, 7, 1, 2, 50, 3);
        assert!(matches!(
            store.verify(&older),
            Err(SigningError::ReplayedTimestamp { .. })
        ));
    }

    #[test]
    fn replay_accepts_an_advancing_timestamp() {
        let mut store = SigningKeyStore::new();
        store.insert_key(2, KEY_A);

        for ts in [10u64, 11, 100, 5000] {
            let frame = make_signed_frame(&KEY_A, 7, 1, 2, ts, 3);
            assert!(store.verify(&frame).is_ok(), "ts {ts} should be accepted");
        }
    }

    #[test]
    fn replay_is_keyed_per_stream() {
        let mut store = SigningKeyStore::new();
        store.insert_key(2, KEY_A);

        // Two different system_ids share link 2 but are independent streams.
        let a = make_signed_frame(&KEY_A, 7, 1, 2, 100, 3);
        let b = make_signed_frame(&KEY_A, 8, 1, 2, 100, 3);
        store.verify(&a).unwrap();
        // Same timestamp on a different stream is fine.
        assert!(store.verify(&b).is_ok());
    }

    #[test]
    fn replay_table_does_not_update_on_signature_failure() {
        let mut store = SigningKeyStore::new();
        store.insert_key(2, KEY_A);

        let good = make_signed_frame(&KEY_A, 7, 1, 2, 100, 3);
        store.verify(&good).unwrap();

        // A forged frame with a huge timestamp must not poison the table.
        let forged = make_signed_frame(&KEY_B, 7, 1, 2, 9999, 3);
        assert!(store.verify(&forged).is_err());

        // The legitimate next frame (ts 101) is still accepted because the
        // forged ts 9999 was never recorded.
        let next = make_signed_frame(&KEY_A, 7, 1, 2, 101, 3);
        assert!(store.verify(&next).is_ok());
    }

    #[test]
    fn resign_produces_a_frame_the_target_key_verifies() {
        let mut store = SigningKeyStore::new();
        store.insert_key(1, KEY_A); // inbound link
        store.insert_key(5, KEY_B); // outbound link

        let inbound = make_signed_frame(&KEY_A, 12, 1, 1, 200, 7);
        store.verify(&inbound).unwrap();

        let outbound = store.resign(&inbound, 5, 201).unwrap();

        // A fresh store holding only the outbound key must accept it.
        let mut verifier = SigningKeyStore::new();
        verifier.insert_key(5, KEY_B);
        let v = verifier.verify(&outbound).unwrap();
        assert_eq!(v.link_id, 5);
        assert_eq!(v.timestamp, 201);
        assert_eq!(v.system_id, 12);
        assert_eq!(v.component_id, 1);
    }

    #[test]
    fn resign_preserves_header_and_payload() {
        let mut store = SigningKeyStore::new();
        store.insert_key(1, KEY_A);
        store.insert_key(2, KEY_A);

        let inbound = make_signed_frame(&KEY_A, 12, 3, 1, 200, 11);
        let outbound = store.resign(&inbound, 2, 201).unwrap();

        // Everything through the CRC is byte-identical; only the trailer
        // differs.
        let through_crc = MAVLINK_V2_HEADER_LEN + 11 + MAVLINK_CRC_LEN;
        assert_eq!(&inbound[..through_crc], &outbound[..through_crc]);
        assert_eq!(inbound.len(), outbound.len());
    }

    #[test]
    fn resign_rejects_unknown_target_link() {
        let mut store = SigningKeyStore::new();
        store.insert_key(1, KEY_A);
        let inbound = make_signed_frame(&KEY_A, 1, 1, 1, 10, 2);
        assert!(matches!(
            store.resign(&inbound, 9, 11),
            Err(SigningError::UnknownLinkId { link_id: 9 })
        ));
    }

    #[test]
    fn compute_signature_matches_manual_sha256() {
        // Known-answer: SHA-256(key ‖ prefix)[..6].
        let prefix = b"\xfd\x00\x01\x00\x00\x01\x01\x00\x00\x00";
        let sig = compute_signature(&KEY_A, prefix);

        let mut h = Sha256::new();
        h.update(KEY_A);
        h.update(prefix);
        let want = &h.finalize()[..6];
        assert_eq!(&sig, want);
    }

    #[test]
    fn signing_timestamp_is_zero_at_the_mavlink_epoch() {
        let epoch = UNIX_EPOCH + Duration::from_secs(MAVLINK_EPOCH_UNIX_SECS);
        assert_eq!(signing_timestamp(epoch), Some(0));
    }

    #[test]
    fn signing_timestamp_counts_ten_microsecond_ticks() {
        // 1 second after the epoch = 100_000 ticks of 10 µs.
        let t = UNIX_EPOCH + Duration::from_secs(MAVLINK_EPOCH_UNIX_SECS + 1);
        assert_eq!(signing_timestamp(t), Some(100_000));
    }

    #[test]
    fn signing_timestamp_rejects_pre_epoch_instants() {
        let before = UNIX_EPOCH + Duration::from_secs(MAVLINK_EPOCH_UNIX_SECS - 1);
        assert_eq!(signing_timestamp(before), None);
    }

    #[test]
    fn store_debug_redacts_key_material() {
        let mut store = SigningKeyStore::new();
        store.insert_key(7, KEY_A);
        let rendered = format!("{store:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(rendered.contains('7')); // link id is not secret
        assert!(!rendered.contains("17, 17")); // raw 0x11 bytes must not leak
    }

    #[test]
    fn timestamp_decode_is_little_endian_48_bit() {
        let mut store = SigningKeyStore::new();
        store.insert_key(0, KEY_A);
        // Largest 48-bit value round-trips through encode → decode.
        let ts = (1u64 << 48) - 1;
        let frame = make_signed_frame(&KEY_A, 1, 1, 0, ts, 2);
        assert_eq!(store.verify(&frame).unwrap().timestamp, ts);
    }
}
