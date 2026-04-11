// Copyright © 2026 Roberto Chiofalo.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::pem::PemObject;

fuzz_target!(|data: &[u8]| {
    // Fuzz CRL PEM parsing — the path used by TlsConfig::with_crls.
    let crls: Vec<CertificateRevocationListDer<'static>> =
        CertificateRevocationListDer::pem_slice_iter(data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default();

    // Also attempt to parse raw DER as a CRL
    let _ = CertificateRevocationListDer::from(data.to_vec());
});
