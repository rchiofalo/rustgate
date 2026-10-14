// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Enrollment response formatters.
//!
//! Produces the JSON and XML response bodies for the Marti v2 enrollment API,
//! and the certificate configuration XML for `/Marti/api/tls/config`.

use rustgate_core::b64;

/// Encode raw DER bytes as base64 with 64-character line wrapping.
///
/// Matches TAK Server's output format: standard base64 (no PEM headers),
/// with newline-separated 64-character lines. TAK clients strip newlines
/// before decoding.
pub fn base64_wrap(der: &[u8]) -> String {
    let encoded = b64::encode(der);
    let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 64 + 1);
    for (i, chunk) in encoded.as_bytes().chunks(64).enumerate() {
        if i > 0 {
            wrapped.push('\n');
        }
        // base64 output is always valid ASCII, so this is infallible
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    wrapped
}

/// Build the JSON v2 enrollment response.
///
/// Contains the signed client cert and CA cert(s) as base64-encoded DER
/// with 64-char line wrapping embedded in the JSON string values.
pub fn json_response(signed_cert_der: &[u8], ca_cert_der: &[u8]) -> String {
    let signed = base64_wrap(signed_cert_der);
    let ca = base64_wrap(ca_cert_der);

    // Serialize with serde_json to ensure proper escaping of \n in values
    serde_json::json!({
        "signedCert": signed,
        "ca0": ca,
        "ca1": ca,
    })
    .to_string()
}

/// Build the XML v2 enrollment response.
pub fn xml_response(signed_cert_der: &[u8], ca_cert_der: &[u8]) -> String {
    let signed = base64_wrap(signed_cert_der);
    let ca = base64_wrap(ca_cert_der);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <enrollment>\
         <signedCert>{signed}</signedCert>\
         <ca>{ca}</ca>\
         </enrollment>"
    )
}

/// Build the `/Marti/api/tls/config` XML response.
///
/// Tells TAK clients which O (Organization) and OU values to include
/// in their certificate signing request.
pub fn tls_config_xml(organization: &str) -> String {
    let escaped = xml_escape(organization);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <certificateConfig xmlns=\"http://bbn.com/marti/xml/config\">\n  \
         <nameEntries>\n    \
         <nameEntry name=\"O\" value=\"{escaped}\"/>\n    \
         <nameEntry name=\"OU\" value=\"rustgate\"/>\n  \
         </nameEntries>\n\
         </certificateConfig>"
    )
}

/// Escape XML special characters in attribute values.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_wrap_64_char_lines() {
        // 100 bytes → 136 base64 chars → 3 lines (64 + 64 + 8)
        let data = vec![0xABu8; 100];
        let wrapped = base64_wrap(&data);
        for line in wrapped.lines() {
            assert!(line.len() <= 64, "line too long: {} chars", line.len());
        }
    }

    #[test]
    fn base64_wrap_round_trips() {
        let data = b"test certificate DER bytes here";
        let wrapped = base64_wrap(data);
        let stripped: String = wrapped.chars().filter(|c| *c != '\n').collect();
        let decoded = b64::decode(&stripped).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_wrap_empty() {
        assert_eq!(base64_wrap(b""), "");
    }

    #[test]
    fn base64_wrap_short() {
        let wrapped = base64_wrap(b"hi");
        assert!(!wrapped.contains('\n'));
        assert_eq!(wrapped, "aGk=");
    }

    #[test]
    fn json_response_has_required_keys() {
        let cert = b"fake-cert-der";
        let ca = b"fake-ca-der";
        let json = json_response(cert, ca);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed.get("signedCert").is_some());
        assert!(parsed.get("ca0").is_some());
        assert!(parsed.get("ca1").is_some());
    }

    #[test]
    fn json_response_certs_decode() {
        let cert = b"signed-cert-bytes";
        let ca = b"ca-cert-bytes";
        let json = json_response(cert, ca);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        let signed_b64 = parsed["signedCert"].as_str().expect("string");
        let stripped: String = signed_b64.chars().filter(|c| *c != '\n').collect();
        let decoded = b64::decode(&stripped).expect("decode");
        assert_eq!(decoded, cert);
    }

    #[test]
    fn xml_response_structure() {
        let xml = xml_response(b"cert", b"ca");
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<enrollment>"));
        assert!(xml.contains("<signedCert>"));
        assert!(xml.contains("<ca>"));
        assert!(xml.contains("</enrollment>"));
    }

    #[test]
    fn tls_config_xml_has_org() {
        let xml = tls_config_xml("MyOrg");
        assert!(xml.contains("\"MyOrg\""));
        assert!(xml.contains("\"rustgate\""));
        assert!(xml.contains("certificateConfig"));
        assert!(xml.contains("nameEntry"));
    }
}
