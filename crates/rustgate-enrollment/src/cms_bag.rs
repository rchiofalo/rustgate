//! PKCS#7 certs-only bag construction for EST responses.
//!
//! Builds a degenerate CMS [`SignedData`] (RFC 5652) containing only
//! certificates and no signers. This is the response format required by
//! EST ([RFC 7030]) for `/cacerts` and `/simpleenroll` endpoints.
//!
//! [`SignedData`]: cms::signed_data::SignedData
//! [RFC 7030]: https://www.rfc-editor.org/rfc/rfc7030

use base64::Engine as _;
use cms::content_info::ContentInfo;
use der::{Decode, Encode};
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
    Ok(base64::engine::general_purpose::STANDARD.encode(der))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use der::Decode as _;

    use super::*;

    /// Build a self-signed test certificate DER for unit tests.
    fn test_cert_der() -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
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
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
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
}
