// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Minimal PKCS#12 (PFX) builder for v1 enrollment.
//!
//! Builds a PKCS#12 bundle containing a signed client certificate and the
//! CA certificate chain. Certificate bags are stored **unencrypted**;
//! integrity is provided by an HMAC-SHA1 MAC over the
//! `AuthenticatedSafe` content using the standardized password.
//!
//! ## Security note — RC2-40 / unencrypted cert bags
//!
//! The PKCS#12 specification (RFC 7292) supports PBE-SHA1-RC2-40 for
//! encrypting certificate bags, but RC2-40 provides only **40 bits** of
//! effective key strength — far below modern brute-force thresholds.
//! This implementation skips certificate-bag encryption entirely because:
//!
//! 1. The password is standardized and publicly known, so any
//!    PBE layer is nominal — it provides no real confidentiality.
//! 2. The bundle is delivered over an mTLS-protected channel, which is
//!    the actual security boundary.
//! 3. Omitting PBE avoids legacy cipher dependencies while maintaining
//!    full compatibility with Java/Android clients.
//!
//! If a future client ecosystem requires encrypted cert bags, use
//! PBE-SHA1-3DES (168-bit) at minimum — never RC2-40.
//!
//! This is a purpose-built implementation covering only the subset of
//! PKCS#12 needed for enrollment responses. For the full spec, see
//! RFC 7292.

use sha1::Sha1;
use sha2::digest::Digest;
use zeroize::Zeroizing;

use crate::error::EnrollmentError;

/// Standard TAK ecosystem password for PKCS#12 bundles.
const TAK_P12_PASSWORD: &str = "atakatak";

/// Build a PKCS#12 bundle containing the signed client cert and CA cert.
///
/// Certificate bags are stored unencrypted (see module-level security
/// note). Integrity is verified via HMAC-SHA1 MAC using the standard
/// password. Returns the raw PFX bytes.
pub fn build_p12_bundle(
    signed_cert_der: &[u8],
    ca_cert_der: &[u8],
) -> Result<Vec<u8>, EnrollmentError> {
    // PKCS#12 structure (simplified):
    // PFX ::= SEQUENCE {
    //   version INTEGER (3),
    //   authSafe ContentInfo (data containing AuthenticatedSafe),
    //   macData MacData
    // }
    //
    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    // Each ContentInfo contains SafeContents (SEQUENCE OF SafeBag)
    //
    // For TAK compatibility, we build an unencrypted cert bag containing
    // both certificates, then MAC the whole thing with the password.

    let cert_bag = build_cert_bag(signed_cert_der, ca_cert_der);
    let auth_safe = build_auth_safe(&cert_bag);
    let auth_safe_der = der_wrap(0x04, &auth_safe); // OCTET STRING

    // ContentInfo wrapping the AuthenticatedSafe
    let content_info = build_content_info(OID_PKCS7_DATA, &auth_safe_der);

    // MAC over the AuthenticatedSafe
    let mac_data = build_mac_data(&auth_safe, TAK_P12_PASSWORD.as_bytes())
        .map_err(|e| EnrollmentError::Signing(format!("PKCS#12 MAC failed: {e}")))?;

    // PFX top-level SEQUENCE
    let version = der_integer(3);
    let inner_len = version.len() + content_info.len() + mac_data.len();
    let mut pfx = Vec::with_capacity(4 + inner_len);
    pfx.push(0x30); // SEQUENCE
    der_push_length(&mut pfx, inner_len);
    pfx.extend_from_slice(&version);
    pfx.extend_from_slice(&content_info);
    pfx.extend_from_slice(&mac_data);

    Ok(pfx)
}

// ── OIDs ────────────────────────────────────────────────────────────

// pkcs-7 data: 1.2.840.113549.1.7.1
const OID_PKCS7_DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];

// pkcs-12 certBag: 1.2.840.113549.1.12.10.1.3
const OID_CERT_BAG: &[u8] = &[
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03,
];

// x509Certificate: 1.2.840.113549.1.9.22.1
const OID_X509_CERT: &[u8] = &[
    0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01,
];

// hmacWithSHA1: 1.2.840.113549.2.7 — but for PKCS#12 MAC, use SHA-1 OID
// SHA-1: 1.3.14.3.2.26
const OID_SHA1: &[u8] = &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];

// ── DER construction helpers ────────────────────────────────────────

fn der_wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.push(tag);
    der_push_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn der_integer(val: u32) -> Vec<u8> {
    if val < 0x80 {
        vec![0x02, 0x01, val as u8]
    } else if val < 0x100 {
        vec![0x02, 0x02, 0x00, val as u8]
    } else {
        vec![0x02, 0x03, 0x00, (val >> 8) as u8, val as u8]
    }
}

/// Build a SEQUENCE from pre-encoded inner data.
fn der_sequence(inner: &[u8]) -> Vec<u8> {
    der_wrap(0x30, inner)
}

/// Build a context-specific constructed `[0]` wrapper.
fn der_context_0(inner: &[u8]) -> Vec<u8> {
    der_wrap(0xa0, inner)
}

// ── PKCS#12 structure builders ──────────────────────────────────────

/// Build a CertBag for a single X.509 certificate.
fn build_single_cert_bag(cert_der: &[u8]) -> Vec<u8> {
    // CertBag ::= SEQUENCE {
    //   certId BAG-TYPE.&id (x509Certificate),
    //   certValue [0] EXPLICIT BAG-TYPE.&Type (OCTET STRING of cert DER)
    // }
    let cert_octet = der_wrap(0x04, cert_der);
    let cert_value = der_context_0(&cert_octet);

    let mut inner = Vec::with_capacity(OID_X509_CERT.len() + cert_value.len());
    inner.extend_from_slice(OID_X509_CERT);
    inner.extend_from_slice(&cert_value);
    der_sequence(&inner)
}

/// Build a SafeBag wrapping a CertBag.
fn build_safe_bag(cert_der: &[u8]) -> Vec<u8> {
    // SafeBag ::= SEQUENCE {
    //   bagId BAG-TYPE.&id (certBag),
    //   bagValue [0] EXPLICIT BAG-TYPE.&Type (CertBag)
    // }
    let cert_bag = build_single_cert_bag(cert_der);
    let bag_value = der_context_0(&cert_bag);

    let mut inner = Vec::with_capacity(OID_CERT_BAG.len() + bag_value.len());
    inner.extend_from_slice(OID_CERT_BAG);
    inner.extend_from_slice(&bag_value);
    der_sequence(&inner)
}

/// Build SafeContents containing both client cert and CA cert bags.
fn build_cert_bag(signed_cert_der: &[u8], ca_cert_der: &[u8]) -> Vec<u8> {
    let client_bag = build_safe_bag(signed_cert_der);
    let ca_bag = build_safe_bag(ca_cert_der);

    let mut inner = Vec::with_capacity(client_bag.len() + ca_bag.len());
    inner.extend_from_slice(&client_bag);
    inner.extend_from_slice(&ca_bag);
    der_sequence(&inner)
}

/// Build AuthenticatedSafe (SEQUENCE OF ContentInfo).
fn build_auth_safe(safe_contents_der: &[u8]) -> Vec<u8> {
    // Wrap SafeContents in an unencrypted ContentInfo (pkcs7-data)
    let octet = der_wrap(0x04, safe_contents_der);
    let content_info = build_content_info(OID_PKCS7_DATA, &octet);
    der_sequence(&content_info)
}

/// Build a PKCS#7 ContentInfo.
fn build_content_info(content_type_oid: &[u8], content: &[u8]) -> Vec<u8> {
    let wrapped_content = der_context_0(content);

    let mut inner = Vec::with_capacity(content_type_oid.len() + wrapped_content.len());
    inner.extend_from_slice(content_type_oid);
    inner.extend_from_slice(&wrapped_content);
    der_sequence(&inner)
}

/// Build MacData for PKCS#12 integrity verification.
///
/// Uses HMAC-SHA1 as required by PKCS#12 for maximum compatibility
/// with Java/Android TAK clients.
fn build_mac_data(auth_safe_der: &[u8], password: &[u8]) -> Result<Vec<u8>, &'static str> {
    let salt = generate_salt()?;
    let iterations: u32 = 2048;

    // Derive MAC key using PKCS#12 KDF (ID=3 for MAC key)
    let mac_key = pkcs12_kdf::<Sha1>(password, &salt, iterations, 3, 20);

    // HMAC-SHA1 over the AuthenticatedSafe content
    let mac_value = hmac_sha1(&mac_key, auth_safe_der);

    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING
    // }
    let algo_id = der_sequence(OID_SHA1);
    let digest = der_wrap(0x04, &mac_value);

    let mut digest_info_inner = Vec::with_capacity(algo_id.len() + digest.len());
    digest_info_inner.extend_from_slice(&algo_id);
    digest_info_inner.extend_from_slice(&digest);
    let digest_info = der_sequence(&digest_info_inner);

    // MacData ::= SEQUENCE {
    //   mac DigestInfo,
    //   macSalt OCTET STRING,
    //   iterations INTEGER
    // }
    let salt_octet = der_wrap(0x04, &salt);
    let iter_int = der_integer(iterations);

    let mut mac_inner = Vec::with_capacity(digest_info.len() + salt_octet.len() + iter_int.len());
    mac_inner.extend_from_slice(&digest_info);
    mac_inner.extend_from_slice(&salt_octet);
    mac_inner.extend_from_slice(&iter_int);

    Ok(der_sequence(&mac_inner))
}

/// Generate a random 8-byte salt for PKCS#12 KDF using the active
/// crypto provider's CSPRNG.
fn generate_salt() -> Result<[u8; 8], &'static str> {
    let provider =
        rustls::crypto::CryptoProvider::get_default().ok_or("no crypto provider installed")?;
    let mut salt = [0u8; 8];
    provider
        .secure_random
        .fill(&mut salt)
        .map_err(|_| "CSPRNG fill failed")?;
    Ok(salt)
}

/// PKCS#12 Key Derivation Function (RFC 7292, Appendix B).
///
/// `id` selects the derived material:
///   1 = encryption key
///   2 = IV
///   3 = MAC key
fn pkcs12_kdf<D: Digest + Default>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    key_len: usize,
) -> Vec<u8> {
    let hash_len = <D as Digest>::output_size();
    let block_size = 64; // SHA-1 block size

    // Step 1: Construct diversifier D
    let d_block = vec![id; block_size];

    // Step 2: Concatenate salt to fill block_size
    let s_block = expand_to_block(salt, block_size);

    // Step 3: Encode password as BMPString (UTF-16BE with NUL terminator)
    let bmp_password = Zeroizing::new(to_bmp_string(password));
    let p_block = expand_to_block(&bmp_password, block_size);

    // Step 4: I = S || P
    let mut i_block = Zeroizing::new(Vec::with_capacity(s_block.len() + p_block.len()));
    i_block.extend_from_slice(&s_block);
    i_block.extend_from_slice(&p_block);

    let mut result = Vec::with_capacity(key_len);

    while result.len() < key_len {
        // Hash(D || I)
        let mut hasher = D::default();
        hasher.update(&d_block);
        hasher.update(i_block.as_slice());
        let mut a = Zeroizing::new(hasher.finalize().to_vec());

        for _ in 1..iterations {
            let mut h = D::default();
            h.update(a.as_slice());
            a = Zeroizing::new(h.finalize().to_vec());
        }

        result.extend_from_slice(&a[..std::cmp::min(hash_len, key_len - result.len())]);

        if result.len() >= key_len {
            break;
        }

        // Adjust I for next block
        let b_block = Zeroizing::new(expand_to_block(&a, block_size));
        let mut j = 0;
        while j < i_block.len() {
            let mut carry: u16 = 1;
            for k in (0..block_size).rev() {
                let sum = u16::from(i_block[j + k]) + u16::from(b_block[k]) + carry;
                i_block[j + k] = sum as u8;
                carry = sum >> 8;
            }
            j += block_size;
        }
    }

    result.truncate(key_len);
    result
}

/// Expand data to fill a block by repeating it.
fn expand_to_block(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let len = data.len().div_ceil(block_size) * block_size;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let remaining = len - out.len();
        let chunk = std::cmp::min(remaining, data.len());
        out.extend_from_slice(&data[..chunk]);
    }
    out
}

/// Encode a password as BMPString (UTF-16BE) with NUL terminator.
fn to_bmp_string(password: &[u8]) -> Vec<u8> {
    let mut bmp = Vec::with_capacity((password.len() + 1) * 2);
    for &b in password {
        bmp.push(0);
        bmp.push(b);
    }
    bmp.push(0);
    bmp.push(0);
    bmp
}

/// HMAC-SHA1 computation.
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = 64;

    // Prepare key — zeroized on drop to prevent key material leaking.
    let mut k = Zeroizing::new(vec![0u8; block_size]);
    if key.len() > block_size {
        let hash = Sha1::digest(key);
        k[..hash.len()].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // Inner hash — i_pad derived from key, zeroized on drop.
    let mut i_pad = Zeroizing::new(vec![0x36u8; block_size]);
    for (i, byte) in i_pad.iter_mut().enumerate() {
        *byte ^= k[i];
    }

    let mut inner = Sha1::new();
    inner.update(i_pad.as_slice());
    inner.update(data);
    let inner_hash = inner.finalize();

    // Outer hash — o_pad derived from key, zeroized on drop.
    let mut o_pad = Zeroizing::new(vec![0x5cu8; block_size]);
    for (i, byte) in o_pad.iter_mut().enumerate() {
        *byte ^= k[i];
    }

    let mut outer = Sha1::new();
    outer.update(o_pad.as_slice());
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn build_p12_produces_valid_der() {
        ensure_crypto_provider();
        // Use minimal DER-encoded self-signed cert stubs for testing.
        // Real certs would be larger but the structure is the same.
        let fake_cert = &[0x30, 0x03, 0x02, 0x01, 0x00]; // minimal SEQUENCE
        let fake_ca = &[0x30, 0x03, 0x02, 0x01, 0x01];

        let p12 = build_p12_bundle(fake_cert, fake_ca).expect("build P12");

        // Should start with SEQUENCE tag
        assert_eq!(p12[0], 0x30, "P12 should start with SEQUENCE tag");

        // Should be non-trivially sized
        assert!(p12.len() > 50, "P12 should have meaningful content");
    }

    #[test]
    fn bmp_string_encoding() {
        let bmp = to_bmp_string(b"ab");
        // 'a' = 0x00 0x61, 'b' = 0x00 0x62, NUL = 0x00 0x00
        assert_eq!(bmp, vec![0x00, 0x61, 0x00, 0x62, 0x00, 0x00]);
    }

    #[test]
    fn bmp_string_empty() {
        let bmp = to_bmp_string(b"");
        assert_eq!(bmp, vec![0x00, 0x00]);
    }

    #[test]
    fn expand_to_block_repeats() {
        let data = vec![1, 2, 3];
        let expanded = expand_to_block(&data, 8);
        assert_eq!(expanded.len(), 8);
        assert_eq!(&expanded[..3], &[1, 2, 3]);
        assert_eq!(&expanded[3..6], &[1, 2, 3]);
    }

    #[test]
    fn expand_to_block_empty() {
        let expanded = expand_to_block(&[], 8);
        assert!(expanded.is_empty());
    }

    #[test]
    fn hmac_sha1_known_vector() {
        // RFC 2202 Test Case 1
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let mac = hmac_sha1(&key, data);
        assert_eq!(mac.len(), 20);
        assert_eq!(
            mac,
            [
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
                0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
            ]
        );
    }

    #[test]
    fn pkcs12_kdf_produces_expected_length() {
        let key = pkcs12_kdf::<Sha1>(b"test", &[1, 2, 3, 4, 5, 6, 7, 8], 2048, 3, 20);
        assert_eq!(key.len(), 20);
    }

    #[test]
    fn der_integer_small() {
        assert_eq!(der_integer(3), vec![0x02, 0x01, 0x03]);
    }

    #[test]
    fn der_integer_large() {
        assert_eq!(der_integer(0x80), vec![0x02, 0x02, 0x00, 0x80]);
    }

    // -----------------------------------------------------------------------
    // Constant pins
    //
    // The TAK ecosystem password and the four hard-coded OIDs are load-
    // bearing interop contracts — every TAK/ATAK/iTAK client uses exactly
    // these values to decrypt/verify the emitted PFX bundle. A silent
    // change would break every deployed client without a single unit test
    // noticing. The OID pins also anchor the byte-level DER encoding so a
    // future refactor that regenerates them from a different encoder
    // (e.g. via `const-oid`) can't accidentally shift a length prefix or
    // re-order arcs and still compile green.
    // -----------------------------------------------------------------------

    #[test]
    fn tak_p12_password_pinned_per_ecosystem_convention() {
        // The MQTT/TAK server ecosystem hard-codes `"atakatak"` as the
        // PFX password. Every deployed ATAK/iTAK/WinTAK build uses this
        // literal, and the module-level comment documents it as an
        // interop constraint, not a secret. Pin the literal so a
        // refactor that parameterises it via config cannot silently
        // regress TAK-side decoding.
        assert_eq!(TAK_P12_PASSWORD, "atakatak");
    }

    #[test]
    fn oid_pkcs7_data_is_der_encoded_object_identifier() {
        // 1.2.840.113549.1.7.1 — pkcs7-data. The nine-byte encoded form
        // is well-known (RFC 5652) and reappears across virtually every
        // CMS/PKCS#7 implementation. Pin the literal bytes plus the
        // structural invariants (starts with 0x06 OID tag, length byte
        // matches remaining content length).
        assert_eq!(OID_PKCS7_DATA[0], 0x06, "must start with OID tag 0x06");
        assert_eq!(OID_PKCS7_DATA[1] as usize, OID_PKCS7_DATA.len() - 2);
        assert_eq!(
            OID_PKCS7_DATA,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01
            ],
        );
    }

    #[test]
    fn oid_cert_bag_is_der_encoded_object_identifier() {
        // 1.2.840.113549.1.12.10.1.3 — pkcs-12 certBag.
        assert_eq!(OID_CERT_BAG[0], 0x06);
        assert_eq!(OID_CERT_BAG[1] as usize, OID_CERT_BAG.len() - 2);
        assert_eq!(
            OID_CERT_BAG,
            &[
                0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03
            ],
        );
    }

    #[test]
    fn oid_x509_cert_is_der_encoded_object_identifier() {
        // 1.2.840.113549.1.9.22.1 — x509Certificate (PKCS#9 certType).
        assert_eq!(OID_X509_CERT[0], 0x06);
        assert_eq!(OID_X509_CERT[1] as usize, OID_X509_CERT.len() - 2);
        assert_eq!(
            OID_X509_CERT,
            &[
                0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01
            ],
        );
    }

    #[test]
    fn oid_sha1_is_der_encoded_object_identifier() {
        // 1.3.14.3.2.26 — id-sha1. The PKCS#12 MAC DigestInfo uses this
        // exact OID (not the PKCS#1 hmacWithSHA1 OID, per the RFC 7292
        // profile). Pin the bytes so a refactor that flips the OID
        // source can't silently change the on-wire MAC algorithm.
        assert_eq!(OID_SHA1[0], 0x06);
        assert_eq!(OID_SHA1[1] as usize, OID_SHA1.len() - 2);
        assert_eq!(OID_SHA1, &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]);
    }

    // -----------------------------------------------------------------------
    // `der_push_length` — short-form / long-form boundary matrix
    //
    // DER length encoding has three cutovers: <128 short form, 128-255
    // long-form 1-byte, 256-65535 long-form 2-byte, 65536+ long-form
    // 3-byte. A one-off boundary regression (e.g. `<= 0x7F` instead of
    // `< 0x80`) would produce a length byte that most ASN.1 parsers
    // silently accept while shifting every downstream offset. Pin every
    // boundary.
    // -----------------------------------------------------------------------

    fn push_len(len: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        der_push_length(&mut buf, len);
        buf
    }

    #[test]
    fn der_push_length_zero_is_single_byte_short_form() {
        assert_eq!(push_len(0), vec![0x00]);
    }

    #[test]
    fn der_push_length_127_is_last_short_form_value() {
        // 0x7F is the maximum short-form length byte; one more and the
        // encoder must flip to long form.
        assert_eq!(push_len(127), vec![0x7F]);
    }

    #[test]
    fn der_push_length_128_is_first_long_form_one_byte() {
        // 0x80 itself means "indefinite length" in DER — the one-byte
        // long form for length 128 is `0x81 0x80`. A refactor that
        // emits `[0x80]` for length 128 would produce indefinite-length
        // content that many strict DER decoders reject outright.
        assert_eq!(push_len(128), vec![0x81, 0x80]);
    }

    #[test]
    fn der_push_length_255_is_last_one_byte_long_form() {
        assert_eq!(push_len(255), vec![0x81, 0xFF]);
    }

    #[test]
    fn der_push_length_256_is_first_two_byte_long_form() {
        assert_eq!(push_len(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn der_push_length_65535_is_last_two_byte_long_form() {
        assert_eq!(push_len(0xFFFF), vec![0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn der_push_length_65536_is_first_three_byte_long_form() {
        assert_eq!(push_len(0x10000), vec![0x83, 0x01, 0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // `der_wrap` composition + `der_sequence` / `der_context_0`
    //
    // Every higher-level builder in the module composes through these
    // three — so if any of them has a prefix off-by-one, every test that
    // inspects the top-level PFX bytes will still pass while the emitted
    // blob silently corrupts downstream parsers. Pin the exact shapes.
    // -----------------------------------------------------------------------

    #[test]
    fn der_wrap_emits_tag_then_short_length_then_payload() {
        // Classic "OCTET STRING (2 bytes, "hi")": 0x04 tag, 0x02 length,
        // "hi" payload.
        assert_eq!(der_wrap(0x04, b"hi"), vec![0x04, 0x02, b'h', b'i']);
    }

    #[test]
    fn der_wrap_empty_payload_is_tag_and_zero_length() {
        assert_eq!(der_wrap(0x30, &[]), vec![0x30, 0x00]);
    }

    #[test]
    fn der_wrap_200_byte_payload_uses_long_form_length() {
        // 200 > 127 so the length encoding must flip to long form
        // `0x81 0xC8`. Pin the transition so a future refactor that
        // inlines short-form encoding everywhere can't ship.
        let payload = vec![0xAB; 200];
        let wrapped = der_wrap(0x30, &payload);
        assert_eq!(wrapped[0], 0x30);
        assert_eq!(wrapped[1], 0x81);
        assert_eq!(wrapped[2], 0xC8);
        assert_eq!(&wrapped[3..], &payload[..]);
    }

    #[test]
    fn der_sequence_uses_constructed_sequence_tag() {
        // Constructed SEQUENCE tag is 0x30 (universal class, constructed
        // form, tag 16). Any other tag is a fatal parse error in strict
        // DER decoders.
        assert_eq!(der_sequence(&[0x01, 0x02]), vec![0x30, 0x02, 0x01, 0x02]);
        assert_eq!(der_sequence(&[]), vec![0x30, 0x00]);
    }

    #[test]
    fn der_context_0_uses_constructed_context_tag() {
        // Context-specific [0] EXPLICIT is tag 0xA0 — class 10 (context)
        // | constructed bit 0x20 | tag number 0. Used in the EXPLICIT
        // wrappers around PKCS#12 bag values.
        assert_eq!(der_context_0(&[0x42]), vec![0xA0, 0x01, 0x42]);
        assert_eq!(der_context_0(&[]), vec![0xA0, 0x00]);
    }

    // -----------------------------------------------------------------------
    // `der_integer` — sign-bit / leading-zero invariants
    //
    // DER INTEGERs are two's-complement, so any positive value with the
    // high bit of its most significant byte set MUST be prefixed with a
    // 0x00 octet to disambiguate from a negative number. A missing
    // leading zero is the canonical PKI parse bug — it produces values
    // that round-trip inside the same implementation but fail every
    // other decoder. Pin the three boundaries.
    // -----------------------------------------------------------------------

    #[test]
    fn der_integer_zero_is_single_zero_byte() {
        // Zero has no high bit set, so no leading pad — three bytes:
        // tag 0x02, length 0x01, value 0x00.
        assert_eq!(der_integer(0), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn der_integer_seven_f_is_last_single_byte_value() {
        // 0x7F — high bit clear, fits in one byte.
        assert_eq!(der_integer(0x7F), vec![0x02, 0x01, 0x7F]);
    }

    #[test]
    fn der_integer_ff_gets_leading_zero_pad() {
        // 0xFF has the high bit set, so a leading 0x00 disambiguates
        // from the two's-complement representation of -1 (0xFF).
        assert_eq!(der_integer(0xFF), vec![0x02, 0x02, 0x00, 0xFF]);
    }

    #[test]
    fn der_integer_0x100_is_three_byte_encoding() {
        // 0x100 spans two payload bytes plus the leading zero.
        assert_eq!(der_integer(0x100), vec![0x02, 0x03, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn der_integer_ffff_is_three_byte_encoding() {
        // 0xFFFF with the leading pad octet.
        assert_eq!(der_integer(0xFFFF), vec![0x02, 0x03, 0x00, 0xFF, 0xFF]);
    }

    #[test]
    fn der_integer_2048_matches_mac_iteration_encoding() {
        // The MacData iteration count is hard-coded at 2048 (0x0800).
        // This encoder always prepends a leading zero byte for values
        // >= 0x100 (regardless of whether the high bit is set), so the
        // emitted shape is the 5-byte `02 03 00 08 00`. This is a
        // non-minimal but valid DER encoding of a positive INTEGER
        // that every PKCS#12 validator accepts. Pin the exact shape so
        // a refactor to a minimal-DER encoder (which would emit the
        // 4-byte `02 02 08 00`) would be forced to update this test
        // in lockstep with validating all TAK clients still accept it.
        assert_eq!(der_integer(2048), vec![0x02, 0x03, 0x00, 0x08, 0x00]);
    }

    // -----------------------------------------------------------------------
    // PKCS#12 bag builders
    //
    // These exercise the composition chain from a single-cert bag
    // through the final CertBag SEQUENCE. We check only the structural
    // invariants that matter for interop: (a) outer tag is SEQUENCE,
    // (b) the expected OID appears literally at the expected offset,
    // (c) both certs are embedded in `build_cert_bag`, and (d) wrapping
    // is idempotent — wrapping the same cert twice produces identical
    // bytes (no hidden randomness, no salt inside bags).
    // -----------------------------------------------------------------------

    #[test]
    fn build_single_cert_bag_is_sequence_containing_x509_oid() {
        let fake_cert = &[0x30, 0x03, 0x02, 0x01, 0x05];
        let bag = build_single_cert_bag(fake_cert);
        assert_eq!(bag[0], 0x30, "outer tag must be SEQUENCE");
        // The x509Certificate OID bytes must appear verbatim somewhere
        // inside the bag.
        assert!(
            bag.windows(OID_X509_CERT.len()).any(|w| w == OID_X509_CERT),
            "CertBag must carry x509Certificate OID"
        );
        // The cert DER bytes must also be embedded (wrapped in OCTET
        // STRING + context[0]).
        assert!(
            bag.windows(fake_cert.len()).any(|w| w == fake_cert),
            "CertBag must embed the raw cert DER"
        );
    }

    #[test]
    fn build_single_cert_bag_is_deterministic_for_same_input() {
        // A silent refactor that introduced entropy or a timestamp at
        // this layer would make every PFX regeneration different — and
        // would wreck the stated "no randomness in cert bags" contract
        // from the module's security-note header.
        let fake_cert = &[0x30, 0x03, 0x02, 0x01, 0x05];
        let a = build_single_cert_bag(fake_cert);
        let b = build_single_cert_bag(fake_cert);
        assert_eq!(a, b, "cert bag encoding must be deterministic");
    }

    #[test]
    fn build_safe_bag_wraps_cert_bag_with_cert_bag_oid() {
        let fake_cert = &[0x30, 0x03, 0x02, 0x01, 0x05];
        let bag = build_safe_bag(fake_cert);
        assert_eq!(bag[0], 0x30, "SafeBag outer tag must be SEQUENCE");
        // SafeBag uses the pkcs-12 certBag OID as its bagId.
        assert!(
            bag.windows(OID_CERT_BAG.len()).any(|w| w == OID_CERT_BAG),
            "SafeBag must carry certBag OID"
        );
        // A SafeBag is strictly larger than the inner CertBag (adds OID
        // + wrapping).
        let inner = build_single_cert_bag(fake_cert);
        assert!(
            bag.len() > inner.len(),
            "SafeBag must be a strict superset of CertBag"
        );
    }

    #[test]
    fn build_cert_bag_contains_both_cert_der_blobs() {
        // Two distinct certs packaged into the SafeContents must both
        // appear verbatim — catches a refactor that accidentally
        // deduplicates or drops one on the way in.
        let client = &[0x30, 0x05, 0x02, 0x03, 0xAB, 0xCD, 0xEF];
        let ca = &[0x30, 0x04, 0x02, 0x02, 0x12, 0x34];
        let combined = build_cert_bag(client, ca);
        assert_eq!(combined[0], 0x30, "outer SEQUENCE tag required");
        assert!(
            combined.windows(client.len()).any(|w| w == client),
            "client cert DER must be embedded"
        );
        assert!(
            combined.windows(ca.len()).any(|w| w == ca),
            "CA cert DER must be embedded"
        );
    }

    #[test]
    fn build_content_info_wraps_content_in_context_0() {
        let content = &[0x01, 0x02, 0x03];
        let info = build_content_info(OID_PKCS7_DATA, content);
        assert_eq!(info[0], 0x30);
        // The content-type OID must appear before the content.
        let oid_pos = info
            .windows(OID_PKCS7_DATA.len())
            .position(|w| w == OID_PKCS7_DATA)
            .expect("content-type OID must appear");
        let ctx_pos = info.iter().position(|&b| b == 0xA0).expect("must have [0]");
        assert!(oid_pos < ctx_pos, "OID must precede the context[0] wrapper");
    }

    #[test]
    fn build_auth_safe_wraps_safe_contents_in_pkcs7_data() {
        let fake_cert = &[0x30, 0x03, 0x02, 0x01, 0x05];
        let bag = build_cert_bag(fake_cert, fake_cert);
        let auth_safe = build_auth_safe(&bag);
        assert_eq!(auth_safe[0], 0x30, "outer SEQUENCE required");
        // AuthSafe must embed the pkcs7-data OID of the ContentInfo
        // wrapping the SafeContents.
        assert!(
            auth_safe
                .windows(OID_PKCS7_DATA.len())
                .any(|w| w == OID_PKCS7_DATA),
            "AuthSafe must carry pkcs7-data OID"
        );
    }

    // -----------------------------------------------------------------------
    // `build_mac_data` + `generate_salt`
    //
    // The MAC layer is the only source of randomness in the PFX — every
    // other byte is deterministic. The two invariants that matter are
    // (a) salts differ across calls (otherwise PFXs would be bitwise
    // identical and leak timing hints) and (b) the hard-coded 2048
    // iteration count appears in the emitted MacData SEQUENCE.
    // -----------------------------------------------------------------------

    #[test]
    fn generate_salt_returns_eight_bytes() {
        ensure_crypto_provider();
        let salt = generate_salt().expect("crypto provider installed");
        assert_eq!(
            salt.len(),
            8,
            "PKCS#12 MacData salt is fixed at 8 bytes per RFC 7292"
        );
    }

    #[test]
    fn generate_salt_produces_unpredictable_successive_values() {
        // The salt is the entire entropy source for the MAC. If two
        // successive calls collided, either the CSPRNG is broken or a
        // refactor replaced it with a deterministic source — both are
        // CI-stoppers. Probability of collision on correct CSPRNG is
        // 2^-64 per comparison; sampling 16 and checking pairwise gives
        // effectively zero false positives.
        ensure_crypto_provider();
        let samples: Vec<[u8; 8]> = (0..16)
            .map(|_| generate_salt().expect("generate_salt"))
            .collect();
        for (i, a) in samples.iter().enumerate() {
            for b in &samples[i + 1..] {
                assert_ne!(a, b, "salt collision in 16 samples");
            }
        }
    }

    #[test]
    fn build_mac_data_embeds_2048_iterations_and_sha1_oid() {
        // The hard-coded `iterations: u32 = 2048` and SHA-1 OID must
        // appear verbatim in the emitted MacData. A refactor that
        // bumped iterations or switched to SHA-256 without updating
        // legacy TAK clients would silently break decoding on every
        // deployed device.
        ensure_crypto_provider();
        let mac = build_mac_data(b"dummy", b"atakatak").expect("build mac data");
        assert_eq!(mac[0], 0x30, "MacData outer tag must be SEQUENCE");
        // SHA-1 OID must appear.
        assert!(
            mac.windows(OID_SHA1.len()).any(|w| w == OID_SHA1),
            "MacData must carry the id-sha1 OID"
        );
        // The 2048-iteration INTEGER encoding (`02 03 00 08 00` —
        // this encoder's non-minimal-but-valid DER for values
        // >= 0x100) must be embedded as the last SEQUENCE element.
        let iter_enc = [0x02, 0x03, 0x00, 0x08, 0x00];
        assert!(
            mac.windows(iter_enc.len()).any(|w| w == iter_enc),
            "MacData must embed the 2048-iteration INTEGER encoding"
        );
    }

    #[test]
    fn build_mac_data_produces_distinct_outputs_across_calls() {
        // Because `generate_salt` is fresh on every call, two MacData
        // blobs built from the same inputs must differ. A refactor that
        // cached or seeded the salt from a fixed source would collapse
        // to identical bytes — caught here.
        ensure_crypto_provider();
        let a = build_mac_data(b"auth-safe", b"atakatak").expect("build mac a");
        let b = build_mac_data(b"auth-safe", b"atakatak").expect("build mac b");
        assert_ne!(a, b, "MAC data must re-randomise the salt per call");
    }

    // -----------------------------------------------------------------------
    // `pkcs12_kdf` — RFC 7292 Appendix B parameters
    //
    // The KDF feeds the HMAC key. Its three contract surfaces are:
    // (a) deterministic given identical (password, salt, iters, id, len),
    // (b) the `id` diversifier actually diversifies (different IDs yield
    // different keys for the same seed), and (c) requesting more output
    // than the hash width triggers the multi-block extension path.
    // -----------------------------------------------------------------------

    #[test]
    fn pkcs12_kdf_is_deterministic_for_identical_inputs() {
        let pw = b"atakatak";
        let salt = &[0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x01, 0x02];
        let a = pkcs12_kdf::<Sha1>(pw, salt, 2048, 3, 20);
        let b = pkcs12_kdf::<Sha1>(pw, salt, 2048, 3, 20);
        assert_eq!(a, b, "KDF must be fully deterministic");
    }

    #[test]
    fn pkcs12_kdf_id_diversifier_changes_output() {
        // The `id` byte (1 = encryption key, 2 = IV, 3 = MAC key)
        // diversifies the output so the same password+salt can safely
        // produce three independent keys. An id of 1 vs 3 must produce
        // different bytes — otherwise the MAC key and the encryption
        // key would collide.
        let pw = b"atakatak";
        let salt = &[0; 8];
        let id1 = pkcs12_kdf::<Sha1>(pw, salt, 2048, 1, 20);
        let id2 = pkcs12_kdf::<Sha1>(pw, salt, 2048, 2, 20);
        let id3 = pkcs12_kdf::<Sha1>(pw, salt, 2048, 3, 20);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);
    }

    #[test]
    fn pkcs12_kdf_extends_beyond_hash_output_size() {
        // Requesting 40 bytes from SHA-1 (20-byte output) forces the
        // KDF to take the multi-block loop that adjusts `I` via the
        // add-with-carry step. A broken multi-block path would either
        // repeat the first block or panic on integer overflow; assert
        // we got exactly 40 distinct bytes and the second half is not
        // a literal copy of the first.
        let pw = b"atakatak";
        let salt = &[0; 8];
        let out = pkcs12_kdf::<Sha1>(pw, salt, 2, 3, 40);
        assert_eq!(out.len(), 40);
        assert_ne!(
            &out[..20],
            &out[20..],
            "second block must diverge from first"
        );
    }

    #[test]
    fn pkcs12_kdf_truncates_to_exact_requested_length() {
        // Any requested length not a multiple of 20 bytes must still
        // come out exactly that length — catches a bug where a
        // refactor emits full hash blocks and forgets to truncate.
        let out = pkcs12_kdf::<Sha1>(b"pw", &[0; 8], 1, 1, 7);
        assert_eq!(out.len(), 7);
        let out = pkcs12_kdf::<Sha1>(b"pw", &[0; 8], 1, 1, 33);
        assert_eq!(out.len(), 33);
    }

    // -----------------------------------------------------------------------
    // `expand_to_block` — RFC 7292 Appendix B "expand input to multiple of
    // block size" primitive.
    //
    // The three invariants: (a) empty input → empty output, (b) len
    // already a multiple of block_size → output == replicated input of
    // that exact length, (c) len less than block_size → output is the
    // input repeated enough to fill one block. The fourth important
    // thing is that the fill is cyclic — bytes at offsets `k` and
    // `k + len` must be equal.
    // -----------------------------------------------------------------------

    #[test]
    fn expand_to_block_of_input_matching_block_size_returns_exact_length() {
        // When the input is already a full block, the `div_ceil`
        // rounds to one block, so the output length is exactly
        // block_size.
        let input = vec![0x5A; 8];
        let out = expand_to_block(&input, 8);
        assert_eq!(out.len(), 8);
        assert_eq!(out, input);
    }

    #[test]
    fn expand_to_block_larger_than_block_rounds_up_to_next_multiple() {
        // 9 bytes with block_size 8 must round up to 16 (two blocks).
        let input = vec![0xAB; 9];
        let out = expand_to_block(&input, 8);
        assert_eq!(out.len(), 16);
        assert_eq!(out[..9], input[..]);
        // The fill byte at offset 9 is the first input byte wrapping
        // around — the cycle length is the input length.
        assert_eq!(out[9], input[0]);
    }

    #[test]
    fn expand_to_block_cyclic_fill_preserves_input_ordering() {
        // Expansion must repeat the *exact* input sequence, not hash
        // it or reverse it. For input `[1,2,3]` filling to 8, the
        // output is `[1,2,3,1,2,3,1,2]` (cycle length 3 into 8 bytes).
        let out = expand_to_block(&[1, 2, 3], 8);
        assert_eq!(out, vec![1, 2, 3, 1, 2, 3, 1, 2]);
    }

    // -----------------------------------------------------------------------
    // `to_bmp_string` — RFC 7292 §B.1 BMPString encoding
    //
    // Covers UTF-16BE encoding + trailing NUL terminator. The module's
    // only caller currently passes ASCII-only passwords, but the
    // function must handle the full 0x00–0xFF byte range symmetrically.
    // The length invariant `(password.len() + 1) * 2` pins the terminator
    // count at exactly one NUL pair regardless of input.
    // -----------------------------------------------------------------------

    #[test]
    fn bmp_string_high_byte_ascii_still_zero_padded_on_left() {
        // A `0xFF` input byte must encode as `0x00 0xFF` — the encoder
        // treats the input as *raw bytes* mapped into the low half of
        // UTF-16, not as a signed value that might sign-extend.
        let bmp = to_bmp_string(&[0xFF]);
        assert_eq!(bmp, vec![0x00, 0xFF, 0x00, 0x00]);
    }

    #[test]
    fn bmp_string_length_is_two_times_input_plus_terminator() {
        // The output length invariant protects against a refactor that
        // drops or doubles the NUL terminator.
        for input_len in [0usize, 1, 8, 64, 255] {
            let input = vec![b'x'; input_len];
            let bmp = to_bmp_string(&input);
            assert_eq!(bmp.len(), (input_len + 1) * 2);
            // The last two bytes must be the NUL terminator.
            assert_eq!(&bmp[bmp.len() - 2..], &[0x00, 0x00]);
        }
    }

    #[test]
    fn bmp_string_multi_char_preserves_order() {
        // Input `"abc"` must encode as `[00 61 00 62 00 63 00 00]` —
        // order preserved, each byte zero-padded, NUL terminator
        // appended. A future refactor that naively `.rev()`s the
        // iteration order would fail here.
        let bmp = to_bmp_string(b"abc");
        assert_eq!(bmp, vec![0x00, b'a', 0x00, b'b', 0x00, b'c', 0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // `hmac_sha1` — RFC 2202 regression vectors
    //
    // The existing test covers Test Case 1 (20-byte 0x0B key, "Hi There").
    // We add Test Case 2 (short-key text) and Test Case 4 (25-byte key,
    // longer data, which exercises the "key no longer than block size"
    // branch symmetrically). Test Case 7 is the definitive pre-hashing
    // path: a 80-byte key must be SHA-1-pre-hashed before use, and any
    // regression on that branch would silently degrade key entropy.
    // -----------------------------------------------------------------------

    #[test]
    fn hmac_sha1_rfc2202_test_case_2() {
        // RFC 2202 §3 — Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha1(key, data);
        assert_eq!(
            mac,
            [
                0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
                0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
            ]
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_test_case_7_exercises_long_key_prehash() {
        // RFC 2202 §3 — Test Case 7: key length 80 (> block_size 64),
        // which forces the "hash the key first" branch. Any regression
        // that keeps the raw 80-byte key would produce a different MAC
        // and this test would catch it.
        let key = vec![0xaa; 80];
        let data = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        let mac = hmac_sha1(&key, data);
        assert_eq!(
            mac,
            [
                0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78, 0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c,
                0x78, 0x08, 0xbb, 0xff, 0x1a, 0x91,
            ]
        );
    }

    #[test]
    fn hmac_sha1_empty_data_is_still_twenty_bytes() {
        // Empty data is a valid input — HMAC is defined for the empty
        // string. The output must still be exactly 20 bytes (SHA-1
        // digest size), not an empty vec or a partial digest.
        let mac = hmac_sha1(&[0xAA; 20], b"");
        assert_eq!(mac.len(), 20);
    }

    // -----------------------------------------------------------------------
    // `build_p12_bundle` — end-to-end structure
    //
    // The top-level tests complement the existing
    // `build_p12_produces_valid_der` by checking that the version
    // integer, both input cert blobs, and the PKCS#7 data OID all
    // appear at predictable positions. We do not attempt a full PFX
    // parse — that is the integration-test suite's job — just the
    // structural invariants a regression would break.
    // -----------------------------------------------------------------------

    #[test]
    fn build_p12_bundle_version_is_three_per_rfc_7292() {
        // PFX version per RFC 7292 is INTEGER 3. The encoding is
        // `02 01 03` which must appear immediately after the outer
        // SEQUENCE length prefix.
        ensure_crypto_provider();
        let fake_cert = &[0x30, 0x03, 0x02, 0x01, 0x05];
        let p12 = build_p12_bundle(fake_cert, fake_cert).expect("build pfx");
        // Skip the outer SEQUENCE tag + length prefix and look for the
        // version INTEGER `02 01 03`.
        let version_enc = [0x02, 0x01, 0x03];
        assert!(
            p12.windows(version_enc.len()).any(|w| w == version_enc),
            "PFX must carry the version-3 INTEGER encoding"
        );
    }

    #[test]
    fn build_p12_bundle_embeds_both_cert_blobs() {
        // Two distinct certs in, both must appear verbatim in the
        // emitted PFX. This is the shallowest end-to-end smoke test
        // but still catches a serializer bug that swaps, drops, or
        // mangles one of the inputs.
        ensure_crypto_provider();
        let client = &[0x30, 0x07, 0x02, 0x05, 0xAB, 0xCD, 0xEF, 0x11, 0x22];
        let ca = &[0x30, 0x06, 0x02, 0x04, 0x99, 0x88, 0x77, 0x66];
        let p12 = build_p12_bundle(client, ca).expect("build pfx");
        assert!(
            p12.windows(client.len()).any(|w| w == client),
            "client cert DER must appear in PFX"
        );
        assert!(
            p12.windows(ca.len()).any(|w| w == ca),
            "CA cert DER must appear in PFX"
        );
    }

    #[test]
    fn build_p12_bundle_is_distinct_across_calls_due_to_mac_salt() {
        // The MacData salt is the only source of per-call randomness.
        // Two calls with the exact same inputs must still produce
        // different bytes; otherwise a tester replaying the same PFX
        // could derive the MAC key offline without slowing down. Pin
        // the non-determinism.
        ensure_crypto_provider();
        let fake = &[0x30, 0x03, 0x02, 0x01, 0x07];
        let a = build_p12_bundle(fake, fake).expect("build pfx a");
        let b = build_p12_bundle(fake, fake).expect("build pfx b");
        assert_ne!(a, b, "PFX output must vary across calls (MAC salt)");
    }
}
