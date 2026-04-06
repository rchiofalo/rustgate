//! TLS configuration for mTLS server.

use std::sync::Arc;

use rustgate_core::error::{ConfigError, Result, RustgateError};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls_pki_types::pem::PemObject;
use x509_parser::prelude::*;

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
            other => Err(ConfigError::TlsVersion {
                version: other.to_string(),
            }
            .into()),
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
    warn_stale_crl: bool,
}

impl TlsConfig {
    pub fn from_pem(
        server_cert_pem: &str,
        server_key_pem: &str,
        client_ca_pem: &str,
    ) -> Result<Self> {
        let server_certs = crate::pem::parse_certs(server_cert_pem)?;
        let server_key = crate::pem::parse_key(server_key_pem)?;
        let client_ca_store = crate::pem::parse_ca_store(client_ca_pem)?;

        Ok(Self {
            server_certs,
            server_key,
            client_ca_store: Arc::new(client_ca_store),
            crls: Vec::new(),
            tls_min_version: TlsMinVersion::Tls12,
            warn_stale_crl: true,
        })
    }

    /// Control whether stale CRL warnings are emitted.
    ///
    /// When `true` (the default), loading a CRL whose `nextUpdate` field
    /// is in the past will produce a warning log. Set to `false` to
    /// suppress these warnings when stale CRLs are intentional.
    ///
    /// Can also be controlled via the `RUSTGATE_CRL_WARN_STALE`
    /// environment variable (set to `"false"` to disable).
    pub fn with_crl_warn_stale(mut self, warn: bool) -> Self {
        self.warn_stale_crl = warn;
        self
    }

    /// Load Certificate Revocation Lists from PEM data.
    ///
    /// CRLs are checked during the TLS handshake — connections using
    /// revoked certificates will be rejected before reaching the
    /// application layer.
    ///
    /// After loading, each CRL is checked for freshness. If a CRL's
    /// `nextUpdate` field is in the past, a warning is logged (unless
    /// stale CRL warnings are disabled via [`Self::with_crl_warn_stale`]).
    pub fn with_crls(mut self, crl_pem: &str) -> Result<Self> {
        let crls: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(crl_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| {
                    RustgateError::from(ConfigError::PemParse {
                        kind: "CRL".to_string(),
                        reason: e.to_string(),
                    })
                })?;

        if crls.is_empty() {
            return Err(ConfigError::EmptyPem {
                kind: "CRLs".to_string(),
            }
            .into());
        }

        let count = crls.len();
        tracing::info!(count = count, "loaded certificate revocation lists");
        rustgate_core::audit::crl_reload_success(count, "pem_data");

        if self.warn_stale_crl {
            let _ = check_crl_freshness(&crls);
        }

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
        let client_verifier = self.build_default_verifier()?;
        self.build_server_config_with_verifier(client_verifier)
    }

    /// Build a `rustls::ServerConfig` using a custom client certificate verifier.
    ///
    /// This is the entry point for dynamic TLS configurations where the
    /// verifier queries a live trust store on each handshake, allowing
    /// CA certificates to be added or removed at runtime.
    pub fn build_server_config_with_verifier(
        &self,
        verifier: Arc<dyn ClientCertVerifier>,
    ) -> Result<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::builder_with_protocol_versions(
            self.tls_min_version.protocol_versions(),
        )
        .with_client_cert_verifier(verifier)
        .with_single_cert(self.server_certs.clone(), self.server_key.clone_key())
        .map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "invalid server certificate: {e}"
            )))
        })?;

        // Disable TLS session resumption. The rustls default caches 256 sessions,
        // allowing resumed connections to skip client certificate re-validation.
        // For an mTLS server this means a revoked or rotated client certificate
        // could still authenticate via a cached session — the same vulnerability
        // class as CVE-2025-23419. Disabling session storage forces a full
        // handshake (with certificate verification) on every connection.
        config.session_storage = Arc::new(NoServerSessionStorage {});

        Ok(config)
    }

    /// Build the default `WebPkiClientVerifier` from the configured CA store and CRLs.
    ///
    /// Use this when you need the verifier separately from the server config,
    /// for example when combining it with a custom certificate resolver via
    /// [`build_reloadable_server_config`](Self::build_reloadable_server_config).
    pub fn build_default_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>> {
        let mut verifier_builder = WebPkiClientVerifier::builder(self.client_ca_store.clone());

        if !self.crls.is_empty() {
            verifier_builder = verifier_builder.with_crls(self.crls.clone());
        }

        verifier_builder.build().map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to build client verifier: {e}"
            )))
        })
    }

    /// Build a `rustls::ServerConfig` using a custom client certificate verifier
    /// and a dynamic certificate resolver.
    ///
    /// This is the entry point for server certificate hot-reload. The resolver
    /// (typically a [`CertReloader`](crate::CertReloader)) supplies the server
    /// certificate on each handshake, allowing zero-downtime rotation without
    /// rebuilding the `ServerConfig`.
    pub fn build_reloadable_server_config(
        &self,
        verifier: Arc<dyn ClientCertVerifier>,
        resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    ) -> Result<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::builder_with_protocol_versions(
            self.tls_min_version.protocol_versions(),
        )
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);

        config.session_storage = Arc::new(NoServerSessionStorage {});

        Ok(config)
    }

    /// Get a reference to the client CA root store.
    ///
    /// Used by consumers that need to build a
    /// [`DynamicCertVerifier`](crate::DynamicCertVerifier)
    /// with the base CA store as a starting point.
    pub fn client_ca_store(&self) -> &Arc<RootCertStore> {
        &self.client_ca_store
    }

    /// Get a clone of the loaded CRLs.
    ///
    /// Used by consumers that need to pass CRLs to a
    /// [`DynamicCertVerifier`](crate::DynamicCertVerifier).
    pub fn crls(&self) -> &[CertificateRevocationListDer<'static>] {
        &self.crls
    }
}

/// Check freshness of loaded CRLs by examining the `nextUpdate` field.
///
/// For each CRL whose `nextUpdate` timestamp is in the past, a warning
/// is logged. Stale CRLs are not rejected — operators may intentionally
/// use them — but the warning helps detect misconfiguration.
///
/// Returns the number of stale CRLs detected.
pub fn check_crl_freshness(crls: &[CertificateRevocationListDer<'static>]) -> usize {
    let now = ASN1Time::now();
    let mut stale_count: usize = 0;

    for (i, crl_der) in crls.iter().enumerate() {
        match parse_x509_crl(crl_der.as_ref()) {
            Ok((_, crl)) => {
                if let Some(next_update) = crl.next_update() {
                    if next_update < now {
                        stale_count += 1;
                        tracing::warn!(
                            crl_index = i,
                            next_update = %next_update,
                            "CRL is stale — nextUpdate is in the past; \
                             revoked certificates may not be detected"
                        );
                    } else {
                        tracing::debug!(
                            crl_index = i,
                            next_update = %next_update,
                            "CRL freshness check passed"
                        );
                    }
                } else {
                    tracing::debug!(
                        crl_index = i,
                        "CRL has no nextUpdate field — freshness check skipped"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    crl_index = i,
                    error = %e,
                    "failed to parse CRL for freshness check — skipping"
                );
            }
        }
    }

    stale_count
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
        .map_err(|_| {
            RustgateError::from(ConfigError::Other(
                "crypto provider already installed".to_string(),
            ))
        })?;

    // Verify the installed provider actually reports FIPS mode.
    // This catches build misconfigurations where aws-lc-rs was compiled
    // without its FIPS module.
    if !is_fips_provider_active() {
        return Err(ConfigError::Other(
            "aws-lc-rs provider installed but does not report FIPS mode — \
             check that aws-lc-fips-sys built correctly"
                .to_string(),
        )
        .into());
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

/// Install the post-quantum crypto provider (aws-lc-rs with ML-KEM key exchange).
///
/// Uses `X25519MLKEM768` as the highest-priority key exchange group when
/// `prefer-post-quantum` is enabled in rustls. Clients that don't support
/// ML-KEM fall back to X25519 transparently.
///
/// Must be called once before any TLS operations. Replaces the default
/// `ring` backend with `aws-lc-rs`.
///
/// Returns an error if a crypto provider is already installed.
#[cfg(feature = "post-quantum")]
pub fn install_pq_provider() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|_| {
            RustgateError::from(ConfigError::Other(
                "crypto provider already installed".to_string(),
            ))
        })?;

    tracing::info!("post-quantum crypto provider (aws-lc-rs) installed — X25519MLKEM768 preferred");
    Ok(())
}

/// Install a crypto provider with a custom key exchange group preference order.
///
/// Parses group names from a comma-separated string and builds a
/// `CryptoProvider` with those groups in the specified order.
/// Requires `--features post-quantum` for PQ groups.
///
/// Returns an error if a group name is unrecognized or if a crypto provider
/// is already installed.
#[cfg(feature = "post-quantum")]
pub fn install_provider_with_kx_groups(groups: &str) -> Result<()> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let kx_groups = parse_kx_groups(groups)?;
    provider.kx_groups = kx_groups;

    rustls::crypto::CryptoProvider::install_default(provider).map_err(|_| {
        RustgateError::from(ConfigError::Other(
            "crypto provider already installed".to_string(),
        ))
    })?;

    tracing::info!(groups = %groups, "crypto provider installed with custom key exchange groups");
    Ok(())
}

/// Parse a comma-separated list of key exchange group names into rustls
/// `SupportedKxGroup` references.
///
/// Group names are case-insensitive. Available groups depend on the compiled
/// crypto backend.
#[cfg(feature = "post-quantum")]
fn parse_kx_groups(groups: &str) -> Result<Vec<&'static dyn rustls::crypto::SupportedKxGroup>> {
    use rustls::crypto::aws_lc_rs::kx_group;

    let mut result = Vec::new();
    for name in groups.split(',') {
        let name = name.trim();
        let group: &'static dyn rustls::crypto::SupportedKxGroup =
            match name.to_uppercase().as_str() {
                "X25519MLKEM768" => kx_group::X25519MLKEM768,
                "SECP256R1MLKEM768" => kx_group::SECP256R1MLKEM768,
                "MLKEM768" => kx_group::MLKEM768,
                "MLKEM1024" => kx_group::MLKEM1024,
                "X25519" => kx_group::X25519,
                "SECP256R1" => kx_group::SECP256R1,
                "SECP384R1" => kx_group::SECP384R1,
                _ => {
                    return Err(ConfigError::Other(format!(
                        "unknown key exchange group: {name}. Available groups: \
                     X25519MLKEM768, SECP256R1MLKEM768, MLKEM768, MLKEM1024, \
                     X25519, secp256r1, secp384r1"
                    ))
                    .into());
                }
            };
        result.push(group);
    }

    if result.is_empty() {
        return Err(ConfigError::Other("--kx-groups must not be empty".to_string()).into());
    }

    Ok(result)
}

/// Returns `true` if the installed crypto provider supports post-quantum
/// key exchange groups (specifically `X25519MLKEM768`).
pub fn is_pq_provider_active() -> bool {
    rustls::crypto::CryptoProvider::get_default()
        .map(|p| {
            p.kx_groups
                .iter()
                .any(|g| (*g).name() == rustls::NamedGroup::X25519MLKEM768)
        })
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
