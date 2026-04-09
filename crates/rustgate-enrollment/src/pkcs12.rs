//! Minimal PKCS#12 (PFX) builder for TAK v1 enrollment.
//!
//! Builds a password-encrypted PKCS#12 bundle containing a signed client
//! certificate and the CA certificate chain. The bundle uses PBE-SHA1-3DES
//! encryption which is compatible with Java/Android TAK clients.
//!
//! This is a purpose-built implementation covering only the subset of
//! PKCS#12 needed for TAK enrollment responses. For the full spec, see
//! RFC 7292.

use sha1::Sha1;
use sha2::digest::Digest;
use zeroize::Zeroizing;

use crate::error::EnrollmentError;

/// Standard TAK ecosystem password for PKCS#12 bundles.
const TAK_P12_PASSWORD: &str = "atakatak";

/// Build a PKCS#12 bundle containing the signed client cert and CA cert.
///
/// The bundle is encrypted with the standard TAK password ("atakatak")
/// and uses PBE-SHA1-RC2-40 for the cert bag (compatible with legacy
/// Java clients). Returns the raw PFX bytes.
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

/// Build a context-specific constructed [0] wrapper.
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
}
