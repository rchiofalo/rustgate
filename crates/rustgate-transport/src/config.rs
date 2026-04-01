//! TLS configuration for mTLS server.

use std::sync::Arc;

use rustgate_core::error::{Result, RustgateError};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls_pki_types::pem::PemObject;

/// Minimum TLS protocol version the server will accept.
///
/// Controls which TLS versions are offered during the handshake. Setting
/// `Tls13` disables TLS 1.2 entirely, which may reject older clients but
/// provides stronger security guarantees (no CBC ciphers, mandatory PFS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMinVersion {
    /// Accept TLS 1.2 and above (default).
    Tls12,
    /// Accept TLS 1.3 only.
    Tls13,
}

impl TlsMinVersion {
    /// Parse a version string into a `TlsMinVersion`.
    ///
    /// Accepts `"1.2"` and `"1.3"`. Returns an error for any other value.
    pub fn from_str_version(s: &str) -> Result<Self> {
        match s {
            "1.2" => Ok(Self::Tls12),
            "1.3" => Ok(Self::Tls13),
            other => Err(RustgateError::Config(format!(
                "unsupported TLS minimum version '{other}': expected '1.2' or '1.3'"
            ))),
        }
    }

    /// Return the `rustls` protocol versions matching this minimum.
    fn protocol_versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        static TLS12_AND_13: &[&rustls::SupportedProtocolVersion] =
            &[&rustls::version::TLS12, &rustls::version::TLS13];
        static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

        match self {
            Self::Tls12 => TLS12_AND_13,
            Self::Tls13 => TLS13_ONLY,
        }
    }
}

#[derive(Debug)]
pub struct TlsConfig {
    server_certs: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca_store: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    tls_min_version: TlsMinVersion,
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
            tls_min_version: TlsMinVersion::Tls12,
        })
    }

    /// Load Certificate Revocation Lists from PEM data.
    ///
    /// CRLs are checked during the TLS handshake — connections using
    /// revoked certificates will be rejected before reaching the
    /// application layer.
    pub fn with_crls(mut self, crl_pem: &str) -> Result<Self> {
        let crls: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(crl_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| RustgateError::Config(format!("failed to parse CRL PEM: {e}")))?;

        if crls.is_empty() {
            return Err(RustgateError::Config(
                "no CRLs found in PEM data".to_string(),
            ));
        }

        let count = crls.len();
        tracing::info!(count = count, "loaded certificate revocation lists");
        rustgate_core::audit::crl_reload_success(count, "pem_data");
        self.crls = crls;
        Ok(self)
    }

    /// Set the minimum TLS protocol version.
    ///
    /// Defaults to TLS 1.2. Set to [`TlsMinVersion::Tls13`] to reject
    /// all TLS 1.2 connections.
    pub fn with_tls_min_version(mut self, version: TlsMinVersion) -> Self {
        self.tls_min_version = version;
        self
    }

    pub fn build_server_config(&self) -> Result<rustls::ServerConfig> {
        let mut verifier_builder = WebPkiClientVerifier::builder(self.client_ca_store.clone());

        if !self.crls.is_empty() {
            verifier_builder = verifier_builder.with_crls(self.crls.clone());
        }

        let client_verifier = verifier_builder
            .build()
            .map_err(|e| RustgateError::Config(format!("failed to build client verifier: {e}")))?;

        let mut config = rustls::ServerConfig::builder_with_protocol_versions(
            self.tls_min_version.protocol_versions(),
        )
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
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
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
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|e| RustgateError::Config(format!("failed to parse private key: {e}")))
    }

    fn parse_ca_store(pem: &str) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parse_tls_min_version_1_2() {
        let v = TlsMinVersion::from_str_version("1.2").unwrap();
        assert_eq!(v, TlsMinVersion::Tls12);
    }

    #[test]
    fn parse_tls_min_version_1_3() {
        let v = TlsMinVersion::from_str_version("1.3").unwrap();
        assert_eq!(v, TlsMinVersion::Tls13);
    }

    #[test]
    fn parse_tls_min_version_invalid() {
        let result = TlsMinVersion::from_str_version("1.1");
        assert!(result.is_err());
    }

    #[test]
    fn parse_tls_min_version_empty() {
        let result = TlsMinVersion::from_str_version("");
        assert!(result.is_err());
    }
}
