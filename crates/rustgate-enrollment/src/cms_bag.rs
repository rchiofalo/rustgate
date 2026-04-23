// Copyright © 2026 Roberto Chiofalo.

//! PKCS#7 certs-only bag construction for EST responses.
//!
//! Builds a degenerate CMS [`SignedData`] (RFC 5652) containing only
//! certificates and no signers. This is the response format required by
//! EST ([RFC 7030]) for `/cacerts` and `/simpleenroll` endpoints.
//!
//! [`SignedData`]: cms::signed_data::SignedData
//! [RFC 7030]: https://www.rfc-editor.org/rfc/rfc7030

use cms::content_info::ContentInfo;
use der::{Decode, Encode};
use rustgate_core::b64;
use x509_cert::Certificate;

use crate::error::EnrollmentError;

/// Build a PKCS#7 certs-only bag from one or more DER-encoded X.509
/// certificates and return the result as DER bytes.
///
/// The output is a CMS `ContentInfo` wrapping a degenerate `SignedData`
/// with zero signers and zero digest algorithms — exactly the format
/// EST mandates for CA certificate distribution and enrollment responses.
pub fn build_certs_only_bag(certs_der: &[&[u8]]) -> Result<Vec<u8>, EnrollmentError> {
    if certs_der.is_empty() {
        return Err(EnrollmentError::Signing(
            "cannot build PKCS#7 bag with zero certificates".into(),
        ));
    }

    let certs: Vec<Certificate> = certs_der
        .iter()
        .map(|der| {
            Certificate::from_der(der).map_err(|e| {
                EnrollmentError::Signing(format!("failed to parse certificate DER: {e}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let content_info = ContentInfo::try_from(certs).map_err(|e| {
        EnrollmentError::Signing(format!("failed to build PKCS#7 certs-only bag: {e}"))
    })?;

    content_info
        .to_der()
        .map_err(|e| EnrollmentError::Signing(format!("failed to DER-encode PKCS#7 bag: {e}")))
}

/// Build a PKCS#7 certs-only bag and return it as base64-encoded text.
///
/// This is the final wire format for EST responses: DER → base64 per
/// RFC 4648 Section 4 (standard alphabet, no line wrapping required).
pub fn build_certs_only_base64(certs_der: &[&[u8]]) -> Result<String, EnrollmentError> {
    let der = build_certs_only_bag(certs_der)?;
    Ok(b64::encode(der))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use cms::cert::CertificateChoices;
    use cms::content_info::CmsVersion;
    use cms::signed_data::SignedData;
    use der::Decode as _;

    use super::*;

    /// id-signedData OID per RFC 5652 Section 5.1. Every EST `/cacerts`
    /// and `/simpleenroll` response MUST use this OID as the outer
    /// `ContentInfo.contentType`; any other value is a wire-format bug
    /// that EST clients will reject.
    const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

    /// id-data OID per RFC 5652 Section 4. The degenerate certs-only
    /// `SignedData` encapsulates an empty `id-data` content — the
    /// payload is the cert set, not an encapsulated document.
    const OID_DATA: &str = "1.2.840.113549.1.7.1";

    /// Build a self-signed test certificate DER for unit tests.
    fn test_cert_der() -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    /// Build a self-signed test cert with a distinct CN, so the test
    /// can tell two generated certs apart by subject content.
    fn test_cert_der_with_cn(cn: &str) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    /// Decode the outer `ContentInfo` and project the inner
    /// `SignedData` so tests can assert structural invariants of the
    /// degenerate bag without re-implementing the decoder.
    fn decode_signed_data(bag: &[u8]) -> SignedData {
        let ci = ContentInfo::from_der(bag).unwrap();
        let inner_der = ci.content.to_der().unwrap();
        SignedData::from_der(&inner_der).unwrap()
    }

    #[test]
    fn single_cert_round_trips() {
        let cert_der = test_cert_der();
        let bag = build_certs_only_bag(&[&cert_der]).unwrap();

        // Verify we can parse it back as ContentInfo
        let ci = ContentInfo::from_der(&bag).unwrap();
        assert_eq!(
            ci.content_type,
            der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2"),
        );
    }

    #[test]
    fn multiple_certs_round_trips() {
        let cert1 = test_cert_der();
        let cert2 = test_cert_der();
        let bag = build_certs_only_bag(&[&cert1, &cert2]).unwrap();

        let ci = ContentInfo::from_der(&bag).unwrap();
        assert_eq!(
            ci.content_type,
            der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2")
        );
    }

    #[test]
    fn base64_output_is_valid() {
        let cert_der = test_cert_der();
        let b64 = build_certs_only_base64(&[&cert_der]).unwrap();

        // Verify base64 decodes back to valid DER
        let decoded = b64::decode(&b64).unwrap();
        let ci = ContentInfo::from_der(&decoded).unwrap();
        assert_eq!(
            ci.content_type,
            der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2")
        );
    }

    #[test]
    fn empty_certs_fails() {
        let result = build_certs_only_bag(&[]);
        // Empty PkiPath (Vec<Certificate>) should fail the TryFrom conversion
        assert!(result.is_err());
    }

    #[test]
    fn invalid_der_fails() {
        let result = build_certs_only_bag(&[b"not a certificate"]);
        assert!(result.is_err());
    }

    // ── OID pins ────────────────────────────────────────────────────

    /// The outer `ContentInfo.contentType` is the RFC 5652 id-signedData
    /// OID. EST clients dispatch on this byte-exact value; drifting to
    /// a sibling OID (id-data, id-envelopedData) would produce a bag
    /// that decodes but fails dispatch at every known EST client.
    #[test]
    fn outer_content_type_is_id_signed_data() {
        let bag = build_certs_only_bag(&[&test_cert_der()]).unwrap();
        let ci = ContentInfo::from_der(&bag).unwrap();
        assert_eq!(
            ci.content_type,
            der::oid::ObjectIdentifier::new_unwrap(OID_SIGNED_DATA),
            "outer ContentInfo.contentType must be RFC 5652 id-signedData",
        );
    }

    /// The inner `encapContentInfo.eContentType` is id-data, and
    /// `eContent` is absent. This is the wire shape of a degenerate
    /// certs-only bag: the encapsulated content slot advertises "data"
    /// but carries nothing, because the payload lives in the
    /// `certificates` field instead.
    #[test]
    fn encap_content_is_id_data_with_absent_econtent() {
        let bag = build_certs_only_bag(&[&test_cert_der()]).unwrap();
        let sd = decode_signed_data(&bag);
        assert_eq!(
            sd.encap_content_info.econtent_type,
            der::oid::ObjectIdentifier::new_unwrap(OID_DATA),
            "eContentType must be id-data for a degenerate certs-only bag",
        );
        assert!(
            sd.encap_content_info.econtent.is_none(),
            "eContent must be absent — the certs-only bag carries no encapsulated document",
        );
    }

    // ── SignedData structural invariants ────────────────────────────

    /// A certs-only bag has no signers, so CMS version MUST be v1 per
    /// RFC 5652 §5.1. v3+ is only reached when SignerInfo carries v3
    /// attributes; drifting higher breaks EST clients that validate
    /// the version field as an allow list.
    #[test]
    fn signed_data_version_is_v1_for_degenerate_bag() {
        let bag = build_certs_only_bag(&[&test_cert_der()]).unwrap();
        let sd = decode_signed_data(&bag);
        assert_eq!(
            sd.version,
            CmsVersion::V1,
            "a zero-signer bag pins the RFC 5652 degenerate form at CMSVersion=v1",
        );
    }

    /// The `digestAlgorithms` set is empty because there are no
    /// signers to hash anything with. A non-empty set here would
    /// imply the bag had a signer we forgot to populate — tripping
    /// verifiers that enforce the RFC 5652 "if empty, no signers"
    /// coupling.
    #[test]
    fn digest_algorithms_set_is_empty() {
        let bag = build_certs_only_bag(&[&test_cert_der()]).unwrap();
        let sd = decode_signed_data(&bag);
        assert_eq!(
            sd.digest_algorithms.len(),
            0,
            "digestAlgorithms must be empty when signerInfos is empty (RFC 5652 §5.1)",
        );
    }

    /// The `signerInfos` set is empty — this IS the defining property
    /// of a "degenerate" SignedData. If a signer ever leaks in (e.g.
    /// from a copy-paste of a signing path), EST clients will try to
    /// verify it and fail the whole enrollment.
    #[test]
    fn signer_infos_set_is_empty() {
        let bag = build_certs_only_bag(&[&test_cert_der()]).unwrap();
        let sd = decode_signed_data(&bag);
        assert_eq!(
            sd.signer_infos.0.len(),
            0,
            "signerInfos must be empty for a degenerate certs-only SignedData",
        );
    }

    /// The `certificates` field is present (not `None`), because the
    /// bag exists solely to transport them. A `None` here would
    /// succeed DER encoding but silently deliver zero certs to the
    /// client — worse than an error, because it looks valid on the
    /// wire.
    #[test]
    fn certificates_field_is_present_not_absent() {
        let bag = build_certs_only_bag(&[&test_cert_der()]).unwrap();
        let sd = decode_signed_data(&bag);
        assert!(
            sd.certificates.is_some(),
            "certificates slot must be Some — the point of the bag is to carry certs",
        );
    }

    // ── Certificate count preservation ──────────────────────────────

    /// N input certs produce a bag whose `certificates` set contains
    /// exactly N entries, for several values of N. DER SETs
    /// deduplicate structurally identical members, so each input cert
    /// must be distinct (different key material) — we get that for
    /// free from `rcgen::KeyPair::generate()`.
    #[test]
    fn certificate_count_is_preserved_for_various_sizes() {
        for n in [1usize, 2, 3, 5, 10] {
            let ders: Vec<Vec<u8>> = (0..n).map(|_| test_cert_der()).collect();
            let refs: Vec<&[u8]> = ders.iter().map(|v| v.as_slice()).collect();
            let bag = build_certs_only_bag(&refs).unwrap();
            let sd = decode_signed_data(&bag);
            let certs = sd.certificates.expect("certificates slot must be Some");
            assert_eq!(
                certs.0.len(),
                n,
                "N={n} input certs must produce N entries in the certificate SET",
            );
        }
    }

    /// Each input certificate appears verbatim in the output bag.
    /// DER SETs are sorted by encoded value, so the order may shift,
    /// but membership MUST be preserved — losing a cert silently
    /// would break EST chain completion at the client.
    #[test]
    fn every_input_certificate_appears_in_output() {
        let cert_a = test_cert_der_with_cn("host-a.example");
        let cert_b = test_cert_der_with_cn("host-b.example");
        let cert_c = test_cert_der_with_cn("host-c.example");
        let bag = build_certs_only_bag(&[&cert_a, &cert_b, &cert_c]).unwrap();
        let sd = decode_signed_data(&bag);
        let certs = sd.certificates.expect("certificates slot must be Some");

        let encoded: Vec<Vec<u8>> = certs
            .0
            .iter()
            .map(|choice| match choice {
                CertificateChoices::Certificate(c) => c.to_der().unwrap(),
                _ => panic!("unexpected CertificateChoices variant in bag"),
            })
            .collect();

        for (label, input) in [("A", &cert_a), ("B", &cert_b), ("C", &cert_c)] {
            assert!(
                encoded.iter().any(|out| out == input),
                "input cert {label} missing from output bag",
            );
        }
    }

    // ── Base64 wire format ──────────────────────────────────────────

    /// Per RFC 4648 §4 the base64 alphabet is `A-Z a-z 0-9 + /` with
    /// `=` padding — nothing else. URL-safe chars (`-`, `_`) or
    /// whitespace/newlines would fail strict EST client decoders
    /// and indicate the wrong base64 helper was wired in.
    #[test]
    fn base64_output_uses_standard_alphabet_only() {
        let out = build_certs_only_base64(&[&test_cert_der()]).unwrap();
        assert!(!out.is_empty(), "base64 output must not be empty");
        for (idx, c) in out.chars().enumerate() {
            let ok = c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=';
            assert!(
                ok,
                "byte {idx} is {c:?}, not in the RFC 4648 standard base64 alphabet",
            );
        }
    }

    /// No CR/LF/whitespace in the output — EST transports the bag as
    /// an HTTP body with `Content-Transfer-Encoding: base64`, and
    /// per RFC 7030 §3.2.4 servers SHOULD NOT wrap, since some clients
    /// parse line-by-line and would misalign on soft breaks.
    #[test]
    fn base64_output_has_no_whitespace_or_newlines() {
        let out = build_certs_only_base64(&[&test_cert_der()]).unwrap();
        for (idx, c) in out.chars().enumerate() {
            assert!(
                !c.is_whitespace(),
                "byte {idx} is whitespace {c:?}; EST base64 bag must be unwrapped",
            );
        }
    }

    /// Building the bag twice from the same input certs produces
    /// byte-identical DER — DER is canonical, so any non-determinism
    /// here would point at an encoder bug, not a legitimate
    /// representation choice.
    #[test]
    fn bag_bytes_are_deterministic_for_same_input() {
        let cert = test_cert_der();
        let bag1 = build_certs_only_bag(&[&cert]).unwrap();
        let bag2 = build_certs_only_bag(&[&cert]).unwrap();
        assert_eq!(
            bag1, bag2,
            "DER encoding is canonical — repeated calls with the same cert must agree byte-for-byte",
        );
    }

    /// The base64 helper is a thin DER → base64 shim, so its output
    /// MUST be the standard-alphabet base64 of the DER bytes. Testing
    /// both forms against each other catches accidental drift between
    /// the two helpers (e.g. if one gained a wrapping / padding quirk
    /// the other lacked).
    #[test]
    fn base64_helper_matches_standard_encoding_of_der_helper() {
        let cert = test_cert_der();
        let der = build_certs_only_bag(&[&cert]).unwrap();
        let b64_out = build_certs_only_base64(&[&cert]).unwrap();
        assert_eq!(
            b64_out,
            b64::encode(&der),
            "base64 helper must equal the standard-alphabet encoding of the DER helper output",
        );
    }

    // ── Error shape ─────────────────────────────────────────────────

    /// The empty-certs branch returns a `Signing` error with a
    /// diagnostic string that names the condition. The message is
    /// surfaced through the EST HTTP error path and is the first
    /// thing an operator greps for when an enrollment 500s; changing
    /// it silently would break runbooks.
    #[test]
    fn empty_certs_returns_signing_error_with_named_message() {
        let err = build_certs_only_bag(&[]).expect_err("empty certs must error");
        match err {
            EnrollmentError::Signing(msg) => {
                assert!(
                    msg.contains("zero certificates"),
                    "empty-certs error message should name the condition; got {msg:?}",
                );
            }
            other => panic!("expected Signing variant, got {other:?}"),
        }
    }

    /// Invalid DER bytes produce a `Signing` error whose message names
    /// the parse-failure path. This is the error operators see when a
    /// CA bundle is corrupted or the wrong file was loaded; the
    /// message has to point at the certificate layer, not the outer
    /// bag, so on-call knows where to look.
    #[test]
    fn invalid_der_returns_signing_error_with_parse_context() {
        let err =
            build_certs_only_bag(&[b"definitely not a cert"]).expect_err("bad DER must error");
        match err {
            EnrollmentError::Signing(msg) => {
                assert!(
                    msg.contains("parse certificate DER"),
                    "bad-DER error should name the certificate parse step; got {msg:?}",
                );
            }
            other => panic!("expected Signing variant, got {other:?}"),
        }
    }

    /// Truncating a valid cert still fails, and the failure emerges
    /// from the certificate parse step (not some outer framing check).
    /// This pins the invariant that a prefix of valid DER is not
    /// accidentally accepted — a real risk if the parser short-
    /// circuits on the outer SEQUENCE header before validating
    /// tail bytes.
    #[test]
    fn truncated_cert_der_fails_at_parse_step() {
        let good = test_cert_der();
        let truncated = &good[..good.len() / 2];
        let err = build_certs_only_bag(&[truncated]).expect_err("truncated DER must error");
        match err {
            EnrollmentError::Signing(msg) => {
                assert!(
                    msg.contains("parse certificate DER"),
                    "truncated-DER error should name the certificate parse step; got {msg:?}",
                );
            }
            other => panic!("expected Signing variant, got {other:?}"),
        }
    }

    /// Mixing one good cert and one bad cert still fails — the
    /// function is all-or-nothing. A partial-success mode would emit
    /// a bag missing the bad cert, which the CA operator never asked
    /// for; failing loudly is the only safe default.
    #[test]
    fn mixed_valid_and_invalid_input_fails_whole_call() {
        let good = test_cert_der();
        let bad: &[u8] = b"nope";
        let err = build_certs_only_bag(&[&good, bad]).expect_err("mixed good/bad input must error");
        assert!(
            matches!(err, EnrollmentError::Signing(_)),
            "mixed-input error must be a Signing variant",
        );
    }

    /// Single-byte garbage input is rejected — this is the smallest
    /// possible invalid DER and guards against a parser that accepts
    /// anything shorter than its minimum-field threshold without
    /// checking structure.
    #[test]
    fn single_byte_garbage_fails() {
        let err = build_certs_only_bag(&[&[0x00]]).expect_err("single byte must error");
        assert!(
            matches!(err, EnrollmentError::Signing(_)),
            "single-byte error must be a Signing variant",
        );
    }
}
