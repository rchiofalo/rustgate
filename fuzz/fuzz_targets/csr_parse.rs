// Copyright © 2026 Roberto Chiofalo.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rcgen::CertificateSigningRequestParams;

fuzz_target!(|data: &[u8]| {
    // Fuzz CSR PEM parsing with raw bytes wrapped in PEM headers.
    // This exercises rcgen's PKCS#10 parser with arbitrary data.
    if let Ok(text) = std::str::from_utf8(data) {
        // Try with PEM headers added (simulates ensure_pem_headers path)
        let pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{text}\n-----END CERTIFICATE REQUEST-----"
        );
        let _ = CertificateSigningRequestParams::from_pem(&pem);

        // Also try raw input in case it already has headers
        let _ = CertificateSigningRequestParams::from_pem(text);
    }
});
