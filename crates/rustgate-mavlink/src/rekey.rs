// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Post-quantum distribution of MAVLink v2 signing keys (ADR 0020 §4–§6).
//!
//! MAVLink v2 signing keys are symmetric 32-byte values. Operators
//! distribute them out-of-band today and rotate them by hand; an
//! adversary who records the distribution channel can recover today's
//! traffic once classical ECDH falls. This module gives operators a
//! post-quantum confidential rekey channel (harvest-now-decrypt-later
//! resistant while the decap key stays secret): the new signing key
//! travels inside an ML-KEM-768 (FIPS 203) encapsulation, so a recorded
//! envelope cannot be opened by a future quantum adversary holding only
//! the long-term bootstrap secret.
//!
//! # Wire format (ADR 0020 §5)
//!
//! ```text
//! offset  size   field
//! 0       1      algorithm_id   (0x01 = ML-KEM-768)
//! 1       1088   mlkem_ct       (ML-KEM-768 ciphertext)
//! 1089    12     nonce          (ChaCha20-Poly1305 nonce, random)
//! 1101    var    aead_ct‖tag    (sealed CBOR MavlinkRekeyPayload + tag)
//! ```
//!
//! The algorithm-id prefix is the crypto-agility hook: a future
//! ML-KEM-1024 migration allocates `0x02` and changes the AAD shape,
//! so old and new envelopes never cross-decode.
//!
//! # Key schedule (ADR 0020 §4)
//!
//! ```text
//! shared_secret = ML-KEM-768::decapsulate(decap_key, mlkem_ct)   // 32 B
//! wrap_key      = HKDF-SHA256(salt = bootstrap_secret,           // 32 B PSK
//!                             ikm  = shared_secret,
//!                             info = "rustgate-mavlink-rekey-v1",
//!                             len  = 32)
//! ```
//!
//! The 32-byte bootstrap secret is used **only** as the HKDF salt — it
//! authenticates the wrap (an attacker without it cannot derive the wrap
//! key even with a valid ML-KEM ciphertext) but is never itself the
//! session key. This design is **not** forward-secret: the ML-KEM
//! decapsulation key is the receiver's long-term static PQ identity, not
//! an ephemeral key, so an attacker who records envelopes and later
//! compromises that decap key recovers every wrapped key. Compromising
//! only the bootstrap secret does not, by itself, reveal past wrap keys —
//! but the decap key does. Decap-key rotation is the forward-secrecy
//! lever: rotating it bounds the set of past envelopes a single decap-key
//! compromise can open. The decap key's on-disk provisioning is wired in
//! the server crate (PR 6). This module operates on in-memory keys.
//!
//! # AEAD binding
//!
//! The ChaCha20-Poly1305 AAD is `algorithm_id ‖ SHA-256(mlkem_ct)[..8]`,
//! binding the sealed payload to both the algorithm slot and the specific
//! KEM output — defence in depth against algorithm-confusion and
//! ciphertext-substitution.
//!
//! # Replay
//!
//! `MavlinkRekeyPayload::key_epoch` is monotonic per `link_id`. A
//! [`RekeyReceiver`] keeps the last accepted epoch per link and rejects an
//! envelope whose epoch does not strictly advance, so a recorded rekey
//! cannot be replayed to pin a stale (potentially compromised) signing
//! key.

use std::collections::HashMap;
use std::fmt;

use aws_lc_rs::kem::{
    Algorithm, AlgorithmId, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::signing::SIGNING_KEY_LEN;

/// Algorithm-id byte for ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305.
pub const ALG_ML_KEM_768: u8 = 0x01;

/// ML-KEM-768 ciphertext length (FIPS 203).
pub const ML_KEM_768_CT_LEN: usize = 1088;

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// ChaCha20-Poly1305 authentication tag length.
const AEAD_TAG_LEN: usize = 16;

/// Bytes of `SHA-256(mlkem_ct)` folded into the AEAD AAD.
const AAD_CT_HASH_LEN: usize = 8;

/// HKDF `info` string binding the derivation to this protocol + version.
const HKDF_INFO: &[u8] = b"rustgate-mavlink-rekey-v1";

/// Offset of the ML-KEM ciphertext in the envelope.
const CT_OFFSET: usize = 1;
/// Offset of the nonce in the envelope.
const NONCE_OFFSET: usize = CT_OFFSET + ML_KEM_768_CT_LEN;
/// Offset of the AEAD ciphertext (with appended tag) in the envelope.
const AEAD_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;

/// Smallest possible well-formed envelope: header + ct + nonce + a tag
/// with an empty (degenerate) AEAD body.
const MIN_ENVELOPE_LEN: usize = AEAD_OFFSET + AEAD_TAG_LEN;

/// The cleartext a rekey envelope carries (ADR 0020 §5).
///
/// Serialized as CBOR inside the AEAD ciphertext. `new_key` is secret;
/// the struct zeroizes on drop and its [`fmt::Debug`] redacts the key.
#[derive(Clone, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MavlinkRekeyPayload {
    /// 10-µs ticks since 2015-01-01T00:00:00Z (same epoch as MAVLink v2
    /// signing). Advisory freshness marker for operators.
    pub timestamp: u64,
    /// Target signing slot the new key is installed into.
    pub link_id: u8,
    /// The new 32-byte MAVLink v2 HMAC signing key.
    pub new_key: [u8; SIGNING_KEY_LEN],
    /// Monotonic per-`link_id` epoch; the replay defence.
    pub key_epoch: u32,
}

impl fmt::Debug for MavlinkRekeyPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MavlinkRekeyPayload")
            .field("timestamp", &self.timestamp)
            .field("link_id", &self.link_id)
            .field("new_key", &"[REDACTED]")
            .field("key_epoch", &self.key_epoch)
            .finish()
    }
}

/// Errors produced while sealing or opening a rekey envelope.
#[derive(Debug, thiserror::Error)]
pub enum RekeyError {
    /// The envelope is shorter than the minimum well-formed length.
    #[error("rekey envelope too short: {len} bytes (min {min})")]
    TooShort { len: usize, min: usize },

    /// The algorithm-id byte is not one this build understands.
    #[error("unsupported rekey algorithm id 0x{id:02X}")]
    UnsupportedAlgorithm { id: u8 },

    /// An ML-KEM key could not be loaded from its byte encoding.
    #[error("ML-KEM key rejected: {0}")]
    KeyRejected(String),

    /// ML-KEM encapsulation failed.
    #[error("ML-KEM encapsulation failed")]
    Encapsulation,

    /// ML-KEM decapsulation failed.
    #[error("ML-KEM decapsulation failed")]
    Decapsulation,

    /// The wrap key could not be derived (HKDF expand failure or bad
    /// length).
    #[error("rekey wrap-key derivation failed")]
    WrapKeyDerivation,

    /// The AEAD seal step failed.
    #[error("rekey AEAD seal failed")]
    AeadSeal,

    /// The AEAD open step failed — wrong wrap key, tampered ciphertext, or
    /// wrong AAD.
    #[error("rekey AEAD open failed")]
    AeadOpen,

    /// The CBOR payload could not be encoded.
    #[error("rekey payload encode failed: {0}")]
    PayloadEncode(String),

    /// The CBOR payload could not be decoded.
    #[error("rekey payload decode failed: {0}")]
    PayloadDecode(String),

    /// The payload's `key_epoch` did not advance past the last accepted
    /// epoch for its `link_id`.
    #[error("replayed rekey epoch for link_id {link_id}: got {key_epoch}, last accepted {last}")]
    ReplayedEpoch {
        link_id: u8,
        key_epoch: u32,
        last: u32,
    },

    /// The system RNG failed while generating a nonce.
    #[error("rekey RNG failure")]
    Rng,
}

/// Generate a fresh ML-KEM-768 keypair.
///
/// Returns the [`DecapsulationKey`] (the receiver's long-term PQ private
/// identity — keep it secret) and the encapsulation (public) key bytes to
/// hand to senders.
///
/// # Errors
///
/// Returns [`RekeyError`] if key generation or public-key extraction
/// fails inside aws-lc-rs.
pub fn generate_keypair() -> Result<(DecapsulationKey<AlgorithmId>, Vec<u8>), RekeyError> {
    let decap = DecapsulationKey::generate(algorithm()).map_err(|_| RekeyError::Encapsulation)?;
    let encap = decap
        .encapsulation_key()
        .map_err(|_| RekeyError::Encapsulation)?;
    let pub_bytes = encap
        .key_bytes()
        .map_err(|_| RekeyError::Encapsulation)?
        .as_ref()
        .to_vec();
    Ok((decap, pub_bytes))
}

/// The ML-KEM-768 algorithm handle.
fn algorithm() -> &'static Algorithm<AlgorithmId> {
    &ML_KEM_768
}

/// Compute the AEAD AAD: `algorithm_id ‖ SHA-256(mlkem_ct)[..8]`.
fn rekey_aad(algorithm_id: u8, mlkem_ct: &[u8]) -> [u8; 1 + AAD_CT_HASH_LEN] {
    let digest = Sha256::digest(mlkem_ct);
    let mut aad = [0u8; 1 + AAD_CT_HASH_LEN];
    aad[0] = algorithm_id;
    aad[1..].copy_from_slice(&digest[..AAD_CT_HASH_LEN]);
    aad
}

/// Derive the 32-byte wrap key from the bootstrap PSK and the KEM shared
/// secret (ADR 0020 §4).
fn derive_wrap_key(
    bootstrap_secret: &[u8],
    shared_secret: &[u8],
) -> Result<Zeroizing<[u8; 32]>, RekeyError> {
    let hk = Hkdf::<Sha256>::new(Some(bootstrap_secret), shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut_slice())
        .map_err(|_| RekeyError::WrapKeyDerivation)?;
    Ok(okm)
}

/// Seal a rekey payload into an envelope for a receiver identified by its
/// ML-KEM-768 encapsulation (public) key bytes.
///
/// This is the sender side of the channel (a key-distribution authority).
/// A fresh random nonce is generated per call.
///
/// # Errors
///
/// Returns [`RekeyError`] on key load, encapsulation, payload encode,
/// nonce RNG, or AEAD seal failure.
pub fn seal(
    payload: &MavlinkRekeyPayload,
    encap_key_bytes: &[u8],
    bootstrap_secret: &[u8; 32],
) -> Result<Vec<u8>, RekeyError> {
    let encap = EncapsulationKey::new(algorithm(), encap_key_bytes)
        .map_err(|e| RekeyError::KeyRejected(e.to_string()))?;
    let (ciphertext, shared_secret) = encap.encapsulate().map_err(|_| RekeyError::Encapsulation)?;
    let mlkem_ct = ciphertext.as_ref();

    let wrap_key = derive_wrap_key(bootstrap_secret, shared_secret.as_ref())?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(wrap_key.as_slice()).map_err(|_| RekeyError::AeadSeal)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce_bytes).map_err(|_| RekeyError::Rng)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext = Vec::new();
    ciborium::into_writer(payload, &mut plaintext)
        .map_err(|e| RekeyError::PayloadEncode(e.to_string()))?;

    let aad = rekey_aad(ALG_ML_KEM_768, mlkem_ct);
    let aead_ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| RekeyError::AeadSeal)?;
    plaintext.zeroize();

    let mut envelope = Vec::with_capacity(AEAD_OFFSET + aead_ct.len());
    envelope.push(ALG_ML_KEM_768);
    envelope.extend_from_slice(mlkem_ct);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&aead_ct);
    Ok(envelope)
}

/// Receiver for MAVLink rekey envelopes.
///
/// Holds the ML-KEM-768 decapsulation key (long-term PQ identity), the
/// 32-byte bootstrap PSK, and a per-`link_id` epoch high-water table for
/// replay defence.
pub struct RekeyReceiver {
    decap_key: DecapsulationKey<AlgorithmId>,
    bootstrap_secret: Zeroizing<[u8; 32]>,
    epochs: Mutex<HashMap<u8, u32>>,
}

impl fmt::Debug for RekeyReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RekeyReceiver")
            .field("decap_key", &"[REDACTED]")
            .field("bootstrap_secret", &"[REDACTED]")
            .field("tracked_links", &self.epochs.lock().len())
            .finish()
    }
}

impl RekeyReceiver {
    /// Build a receiver from an in-memory decapsulation key and bootstrap
    /// secret.
    #[must_use]
    pub fn new(decap_key: DecapsulationKey<AlgorithmId>, bootstrap_secret: [u8; 32]) -> Self {
        Self {
            decap_key,
            bootstrap_secret: Zeroizing::new(bootstrap_secret),
            epochs: Mutex::new(HashMap::new()),
        }
    }

    /// Build a receiver from the decapsulation key's byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`RekeyError::KeyRejected`] if the bytes are not a valid
    /// ML-KEM-768 decapsulation key.
    pub fn from_decap_bytes(
        decap_bytes: &[u8],
        bootstrap_secret: [u8; 32],
    ) -> Result<Self, RekeyError> {
        let decap_key = DecapsulationKey::new(algorithm(), decap_bytes)
            .map_err(|e| RekeyError::KeyRejected(e.to_string()))?;
        Ok(Self::new(decap_key, bootstrap_secret))
    }

    /// Open and authenticate a rekey envelope, returning the delivered
    /// payload.
    ///
    /// On success the payload's signature and AAD verified, and its
    /// `key_epoch` advanced past the last accepted epoch for its
    /// `link_id` (which is then updated). On any failure the epoch table
    /// is left unchanged.
    ///
    /// # Errors
    ///
    /// See [`RekeyError`] — malformed envelope, unsupported algorithm,
    /// decapsulation/AEAD failure, payload decode failure, or replayed
    /// epoch.
    pub fn open(&self, envelope: &[u8]) -> Result<MavlinkRekeyPayload, RekeyError> {
        if envelope.len() < MIN_ENVELOPE_LEN {
            return Err(RekeyError::TooShort {
                len: envelope.len(),
                min: MIN_ENVELOPE_LEN,
            });
        }
        let algorithm_id = envelope[0];
        if algorithm_id != ALG_ML_KEM_768 {
            return Err(RekeyError::UnsupportedAlgorithm { id: algorithm_id });
        }

        let mlkem_ct = &envelope[CT_OFFSET..NONCE_OFFSET];
        let nonce_bytes = &envelope[NONCE_OFFSET..AEAD_OFFSET];
        let aead_ct = &envelope[AEAD_OFFSET..];

        let shared_secret = self
            .decap_key
            .decapsulate(Ciphertext::from(mlkem_ct))
            .map_err(|_| RekeyError::Decapsulation)?;

        let wrap_key = derive_wrap_key(self.bootstrap_secret.as_slice(), shared_secret.as_ref())?;
        let cipher = ChaCha20Poly1305::new_from_slice(wrap_key.as_slice())
            .map_err(|_| RekeyError::WrapKeyDerivation)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let aad = rekey_aad(algorithm_id, mlkem_ct);

        let mut plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: aead_ct,
                    aad: &aad,
                },
            )
            .map_err(|_| RekeyError::AeadOpen)?;

        let payload: MavlinkRekeyPayload = ciborium::from_reader(plaintext.as_slice())
            .map_err(|e| RekeyError::PayloadDecode(e.to_string()))?;
        plaintext.zeroize();

        // Enforce epoch monotonicity only after the payload authenticates,
        // so a forged envelope can never perturb the high-water table.
        let mut epochs = self.epochs.lock();
        if let Some(&last) = epochs.get(&payload.link_id)
            && payload.key_epoch <= last
        {
            return Err(RekeyError::ReplayedEpoch {
                link_id: payload.link_id,
                key_epoch: payload.key_epoch,
                last,
            });
        }
        let _ = epochs.insert(payload.link_id, payload.key_epoch);

        Ok(payload)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    const BOOTSTRAP: [u8; 32] = [0x77; 32];

    fn payload(link_id: u8, epoch: u32) -> MavlinkRekeyPayload {
        MavlinkRekeyPayload {
            timestamp: 123_456,
            link_id,
            new_key: [0xAB; SIGNING_KEY_LEN],
            key_epoch: epoch,
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let (decap, encap_pub) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, BOOTSTRAP);

        let envelope = seal(&payload(0x42, 1), &encap_pub, &BOOTSTRAP).unwrap();
        // The signing key never appears on the wire.
        assert!(
            !envelope
                .windows(SIGNING_KEY_LEN)
                .any(|w| w == [0xAB; SIGNING_KEY_LEN])
        );

        let opened = receiver.open(&envelope).unwrap();
        assert_eq!(opened.link_id, 0x42);
        assert_eq!(opened.key_epoch, 1);
        assert_eq!(opened.new_key, [0xAB; SIGNING_KEY_LEN]);
    }

    #[test]
    fn envelope_layout_matches_adr() {
        let (_, encap_pub) = generate_keypair().unwrap();
        let envelope = seal(&payload(1, 1), &encap_pub, &BOOTSTRAP).unwrap();
        assert_eq!(envelope[0], ALG_ML_KEM_768);
        // header(1) + ct(1088) + nonce(12) + aead(>= tag 16)
        assert!(envelope.len() >= MIN_ENVELOPE_LEN);
        assert_eq!(&envelope[CT_OFFSET..NONCE_OFFSET].len(), &ML_KEM_768_CT_LEN);
    }

    #[test]
    fn wrong_bootstrap_secret_fails_to_open() {
        let (decap, encap_pub) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, [0x00; 32]); // different PSK
        let envelope = seal(&payload(1, 1), &encap_pub, &BOOTSTRAP).unwrap();
        assert!(matches!(
            receiver.open(&envelope),
            Err(RekeyError::AeadOpen)
        ));
    }

    #[test]
    fn wrong_decap_key_fails_to_open() {
        let (_decap_a, encap_pub_a) = generate_keypair().unwrap();
        let (decap_b, _encap_pub_b) = generate_keypair().unwrap();
        // Sealed to A's public key, opened with B's private key.
        let receiver = RekeyReceiver::new(decap_b, BOOTSTRAP);
        let envelope = seal(&payload(1, 1), &encap_pub_a, &BOOTSTRAP).unwrap();
        // ML-KEM decapsulation is implicit-reject: it yields a different
        // shared secret rather than erroring, so the AEAD open fails.
        assert!(matches!(
            receiver.open(&envelope),
            Err(RekeyError::AeadOpen)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_aad() {
        let (decap, encap_pub) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, BOOTSTRAP);
        let mut envelope = seal(&payload(1, 1), &encap_pub, &BOOTSTRAP).unwrap();
        // Flip a byte in the ML-KEM ciphertext: the AAD binds it, and the
        // decapsulated secret changes, so open fails.
        envelope[CT_OFFSET] ^= 0xFF;
        assert!(receiver.open(&envelope).is_err());
    }

    #[test]
    fn unsupported_algorithm_id_rejected() {
        let (decap, encap_pub) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, BOOTSTRAP);
        let mut envelope = seal(&payload(1, 1), &encap_pub, &BOOTSTRAP).unwrap();
        envelope[0] = 0x02; // reserved/future
        assert!(matches!(
            receiver.open(&envelope),
            Err(RekeyError::UnsupportedAlgorithm { id: 0x02 })
        ));
    }

    #[test]
    fn too_short_envelope_rejected() {
        let (decap, _) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, BOOTSTRAP);
        assert!(matches!(
            receiver.open(&[ALG_ML_KEM_768; 10]),
            Err(RekeyError::TooShort { .. })
        ));
    }

    #[test]
    fn epoch_must_advance_per_link() {
        let (decap, encap_pub) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, BOOTSTRAP);

        receiver
            .open(&seal(&payload(5, 10), &encap_pub, &BOOTSTRAP).unwrap())
            .unwrap();
        // Same epoch → replay.
        assert!(matches!(
            receiver.open(&seal(&payload(5, 10), &encap_pub, &BOOTSTRAP).unwrap()),
            Err(RekeyError::ReplayedEpoch { last: 10, .. })
        ));
        // Lower epoch → replay.
        assert!(matches!(
            receiver.open(&seal(&payload(5, 9), &encap_pub, &BOOTSTRAP).unwrap()),
            Err(RekeyError::ReplayedEpoch { .. })
        ));
        // Higher epoch → accepted.
        assert!(
            receiver
                .open(&seal(&payload(5, 11), &encap_pub, &BOOTSTRAP).unwrap())
                .is_ok()
        );
    }

    #[test]
    fn epoch_is_per_link_independent() {
        let (decap, encap_pub) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, BOOTSTRAP);
        receiver
            .open(&seal(&payload(1, 100), &encap_pub, &BOOTSTRAP).unwrap())
            .unwrap();
        // A different link starting at a low epoch is fine.
        assert!(
            receiver
                .open(&seal(&payload(2, 1), &encap_pub, &BOOTSTRAP).unwrap())
                .is_ok()
        );
    }

    #[test]
    fn from_decap_bytes_round_trips() {
        let (decap, encap_pub) = generate_keypair().unwrap();
        let decap_bytes = decap.key_bytes().unwrap().as_ref().to_vec();
        let receiver = RekeyReceiver::from_decap_bytes(&decap_bytes, BOOTSTRAP).unwrap();
        let envelope = seal(&payload(7, 1), &encap_pub, &BOOTSTRAP).unwrap();
        assert_eq!(receiver.open(&envelope).unwrap().link_id, 7);
    }

    #[test]
    fn debug_redacts_payload_key() {
        let rendered = format!("{:?}", payload(1, 1));
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("171")); // raw 0xAB byte must not leak
    }

    #[test]
    fn debug_redacts_receiver_secrets() {
        let (decap, _) = generate_keypair().unwrap();
        let receiver = RekeyReceiver::new(decap, BOOTSTRAP);
        let rendered = format!("{receiver:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("119")); // raw 0x77 bootstrap byte
    }
}
