//! TLS configuration for mTLS server.

use std::io::BufReader;
use std::sync::Arc;

use rustgate_core::error::{Result, RustgateError};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};

#[derive(Debug)]
pub struct TlsConfig {
    server_certs: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca_store: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
}

impl TlsConfig {
    pub fn from_pem(
        server_cert_pem: &str,
        server_key_pem: &str,
        client_ca_pem: &str,
    ) -> Result<Self> {
        let server_certs = Self::parse_certs(server_cert_pem)?;
        let server_key = Self::parse_key(server_key_pem)?;
        let client_ca_store = Self::parse_ca_store(client_ca_pem)?;

        Ok(Self {
            server_certs,
            server_key,
            client_ca_store: Arc::new(client_ca_store),
            crls: Vec::new(),
        })
    }

    /// Load Certificate Revocation Lists from PEM data.
    ///
    /// CRLs are checked during the TLS handshake — connections using
    /// revoked certificates will be rejected before reaching the
    /// application layer.
    pub fn with_crls(mut self, crl_pem: &str) -> Result<Self> {
        let mut reader = BufReader::new(crl_pem.as_bytes());
        let crls: Vec<CertificateRevocationListDer<'static>> = rustls_pemfile::crls(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| RustgateError::Config(format!("failed to parse CRL PEM: {e}")))?;

        if crls.is_empty() {
            return Err(RustgateError::Config(
                "no CRLs found in PEM data".to_string(),
            ));
        }

        tracing::info!(count = crls.len(), "loaded certificate revocation lists");
        self.crls = crls;
        Ok(self)
    }

    pub fn build_server_config(&self) -> Result<rustls::ServerConfig> {
        let mut verifier_builder = WebPkiClientVerifier::builder(self.client_ca_store.clone());

        if !self.crls.is_empty() {
            verifier_builder = verifier_builder.with_crls(self.crls.clone());
        }

        let client_verifier = verifier_builder
            .build()
            .map_err(|e| RustgateError::Config(format!("failed to build client verifier: {e}")))?;

        let mut config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(self.server_certs.clone(), self.server_key.clone_key())
            .map_err(|e| RustgateError::Config(format!("invalid server certificate: {e}")))?;

        // Disable TLS session resumption. The rustls default caches 256 sessions,
        // allowing resumed connections to skip client certificate re-validation.
        // For an mTLS server this means a revoked or rotated client certificate
        // could still authenticate via a cached session — the same vulnerability
        // class as CVE-2025-23419. Disabling session storage forces a full
        // handshake (with certificate verification) on every connection.
        config.session_storage = Arc::new(NoServerSessionStorage {});

        Ok(config)
    }

    fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
        let mut reader = BufReader::new(pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| RustgateError::Config(format!("failed to parse certificates: {e}")))?;

        if certs.is_empty() {
            return Err(RustgateError::Config(
                "no certificates found in PEM".to_string(),
            ));
        }

        Ok(certs)
    }

    fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
        let mut reader = BufReader::new(pem.as_bytes());

        rustls_pemfile::private_key(&mut reader)
            .map_err(|e| RustgateError::Config(format!("failed to parse private key: {e}")))?
            .ok_or_else(|| RustgateError::Config("no private key found in PEM".to_string()))
    }

    fn parse_ca_store(pem: &str) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();
        let mut reader = BufReader::new(pem.as_bytes());

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| RustgateError::Config(format!("failed to parse CA certificates: {e}")))?;

        if certs.is_empty() {
            return Err(RustgateError::Config(
                "no CA certificates found in PEM".to_string(),
            ));
        }

        for cert in certs {
            store
                .add(cert)
                .map_err(|e| RustgateError::Config(format!("failed to add CA certificate: {e}")))?;
        }

        Ok(store)
    }
}

/// Install the FIPS 140-3 validated crypto provider (aws-lc-rs).
///
/// Must be called once before any TLS operations. Replaces the default
/// `ring` backend with `aws-lc-rs` in FIPS mode, restricting cipher
/// suites and key exchange algorithms to the FIPS-approved set.
///
/// Returns an error if a crypto provider is already installed.
#[cfg(feature = "fips")]
pub fn install_fips_provider() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|_| RustgateError::Config("crypto provider already installed".to_string()))?;

    // Verify the installed provider actually reports FIPS mode.
    // This catches build misconfigurations where aws-lc-rs was compiled
    // without its FIPS module.
    if !is_fips_provider_active() {
        return Err(RustgateError::Config(
            "aws-lc-rs provider installed but does not report FIPS mode — \
             check that aws-lc-fips-sys built correctly"
                .to_string(),
        ));
    }

    tracing::info!("FIPS 140-3 crypto provider (aws-lc-rs) installed and verified");
    Ok(())
}

/// Returns `true` if the FIPS crypto provider is the active default.
///
/// Checks whether a crypto provider is installed and whether it uses
/// the `aws-lc-rs` FIPS backend. Use with `--fips-required` to fail
/// startup when FIPS mode is expected but not active.
pub fn is_fips_provider_active() -> bool {
    rustls::crypto::CryptoProvider::get_default()
        .map(|p| p.fips())
        .unwrap_or(false)
}
