// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
        let server_certs = crate::pem::parse_certs(server_cert_pem.as_bytes())?;
        let server_key = crate::pem::parse_key(server_key_pem.as_bytes())?;
        let client_ca_store = crate::pem::parse_ca_store(client_ca_pem.as_bytes())?;

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

    /// Build a hot-swappable client-cert verifier backed by `crl_store`.
    ///
    /// Unlike [`build_default_verifier`](Self::build_default_verifier) — a
    /// static `WebPkiClientVerifier` whose CRL list is frozen at boot — this
    /// returns a [`crate::DynamicCertVerifier`] that pulls the CRL list from the
    /// generation-counted [`crate::CrlStore`] on every handshake's rebuild
    /// check. A freshly-published CRL (file replaced, or pushed via the
    /// management API) therefore takes effect on the *next* handshake with no
    /// restart, fixing the restart-gated-revocation defect (#1496, ADR 0025).
    ///
    /// The root store is the (static, single-CA) client CA store, snapshot at a
    /// constant generation `0`, so only CRL changes drive a verifier rebuild.
    /// The CRL `snapshot` closure is a read-lock + two `Arc` clones — cheap
    /// enough to run on the rustls handshake worker thread.
    pub fn build_dynamic_crl_verifier(
        &self,
        crl_store: &Arc<crate::crl_store::CrlStore>,
    ) -> Result<Arc<crate::verifier::DynamicCertVerifier>> {
        self.build_dynamic_crl_verifier_with_gate(crl_store, None)
    }

    /// Like [`build_dynamic_crl_verifier`](Self::build_dynamic_crl_verifier),
    /// but attaches the opt-in fail-closed staleness gate
    /// ([`crate::FailClosedGate`]). When `fail_closed` is `Some`, the returned
    /// verifier rejects **all** client-certificate handshakes while the gate is
    /// engaged (every parsed CRL stale past the grace window). `None` preserves
    /// the fail-open behavior (#1496, ADR-0025 Piece 2).
    ///
    /// Returns the concrete [`crate::verifier::DynamicCertVerifier`] (rather
    /// than an `Arc<dyn ClientCertVerifier>`) so the caller can reach
    /// [`crate::verifier::DynamicCertVerifier::fail_closed_gate`] to drive the
    /// watcher observer.
    pub fn build_dynamic_crl_verifier_with_gate(
        &self,
        crl_store: &Arc<crate::crl_store::CrlStore>,
        fail_closed: Option<Arc<crate::verifier::FailClosedGate>>,
    ) -> Result<Arc<crate::verifier::DynamicCertVerifier>> {
        let root_store = Arc::clone(&self.client_ca_store);
        let root_provider: crate::verifier::RootStoreProvider =
            Box::new(move || (0, (*root_store).clone()));
        let store = Arc::clone(crl_store);
        let crl_provider: crate::verifier::CrlProvider = Box::new(move || store.snapshot());
        crate::verifier::DynamicCertVerifier::with_crl_provider_and_gate(
            root_provider,
            crl_provider,
            fail_closed,
        )
        .map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to build dynamic client verifier: {e}"
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

    /// Re-read and validate a CRL PEM file from disk.
    ///
    /// Parses the PEM blocks, runs freshness checks, and emits the same
    /// audit events that [`Self::with_crls`] does. Returns a
    /// [`CrlFileSummary`] with the CRL count and the age (in seconds)
    /// of the stalest CRL on success.
    ///
    /// Used by SIGHUP-driven config reload to detect operator errors in
    /// CRL files without restarting the server. The active TLS listener
    /// does not currently swap CRLs at runtime — applying CRL changes to
    /// in-flight handshakes still requires a server restart.
    pub fn validate_crl_file(path: &str) -> Result<CrlFileSummary> {
        let crl_pem = std::fs::read_to_string(path).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to read CRL file {path}: {e}"
            )))
        })?;
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
        // Note: do NOT emit a `crl_reload_success` audit event here. The
        // canonical reload audit record is emitted by the caller
        // (`reload_all_configs` in rustgate-server) so we avoid duplicate
        // events when this fn is invoked from the SIGHUP path.
        //
        // `check_crl_freshness` already logs structured `tracing::warn!`
        // entries for any stale CRLs, so we ignore its return value but
        // additionally surface an audit-style warning so operators can
        // correlate it with the outer config.reload event. We deliberately
        // do not turn freshness failures into hard errors — operators may
        // intentionally use stale CRLs.
        let stale = check_crl_freshness(&crls);
        if stale > 0 {
            tracing::warn!(
                target: "audit",
                event_type = "config.reload",
                component = "crl",
                result = "warning",
                reason = "expired",
                stale_count = stale as u64,
                path = %path,
                "CRL file contains stale entries (nextUpdate in the past)"
            );
        }
        Ok(CrlFileSummary {
            count,
            max_age_seconds: crl_max_age_seconds(&crls),
        })
    }

    /// Get a clone of the loaded CRLs.
    ///
    /// Used by consumers that need to pass CRLs to a
    /// [`DynamicCertVerifier`](crate::DynamicCertVerifier).
    pub fn crls(&self) -> &[CertificateRevocationListDer<'static>] {
        &self.crls
    }

    /// Return the age in seconds of the oldest loaded CRL.
    ///
    /// Convenience wrapper around [`crl_max_age_seconds`] for callers
    /// that already own a built `TlsConfig`. Returns `None` when no
    /// CRLs are configured or when every loaded CRL fails to re-parse.
    pub fn crl_max_age_seconds(&self) -> Option<i64> {
        crl_max_age_seconds(&self.crls)
    }
}

/// Result of [`TlsConfig::validate_crl_file`].
///
/// Carries the entry count plus the age in seconds of the stalest
/// parsed CRL (the largest `now - thisUpdate` across all loaded
/// entries). Callers wire the age into
/// `rustgate_crl_age_seconds` so operators can alert when a CRL
/// publisher has stopped refreshing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrlFileSummary {
    /// Number of CRL PEM blocks parsed from the file.
    pub count: usize,
    /// Age in seconds of the stalest CRL's `thisUpdate`, or `None`
    /// when none of the loaded entries could be re-parsed for the
    /// `thisUpdate` timestamp (the freshness warning path has already
    /// surfaced the parse failure).
    pub max_age_seconds: Option<i64>,
}

/// Return the age in seconds of the "stalest" loaded CRL — the largest
/// elapsed time since any CRL's `thisUpdate` field.
///
/// This is the worst-case freshness signal: if two CRLs are loaded and
/// one was issued 1h ago and the other 3d ago, this returns 3d
/// (≈259 200s). Operators wire this into a gauge like
/// `rustgate_crl_age_seconds` and alert when it exceeds the CRL
/// refresh SLO (typically 24h) to detect a CRL publisher that has
/// stopped updating.
///
/// Returns `None` when the slice is empty or every entry fails to
/// parse (so no meaningful age can be computed). Individual parse
/// failures are silently skipped so a single malformed CRL does not
/// erase the signal from sibling CRLs.
pub fn crl_max_age_seconds(crls: &[CertificateRevocationListDer<'static>]) -> Option<i64> {
    if crls.is_empty() {
        return None;
    }
    let now_ts = ASN1Time::now().timestamp();
    let mut max_age: Option<i64> = None;
    for crl_der in crls {
        if let Ok((_, crl)) = parse_x509_crl(crl_der.as_ref()) {
            // x509-parser names the accessor `last_update()`; the
            // ASN.1 field it returns is `thisUpdate` from RFC 5280 §5.1.
            let age = now_ts.saturating_sub(crl.last_update().timestamp());
            max_age = Some(max_age.map_or(age, |m| m.max(age)));
        }
    }
    max_age
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

/// The stock `aws-lc-rs` provider with every ML-DSA signature algorithm removed.
///
/// rustls 0.23.46 added ML-DSA-44/65/87 to the aws-lc-rs provider's default
/// verification set. rustgate keeps acceptance of ML-DSA-signed certificate
/// chains opt-in (`--features mldsa-certs` plus `--mldsa-client-certs`, #501),
/// so every aws-lc-rs provider it installs starts from this one, and the opt-in
/// adds ML-DSA-87 back. Cipher suites, key-exchange groups and the classical
/// algorithms (in their original order) are untouched.
#[cfg(any(feature = "fips", feature = "post-quantum", feature = "mldsa-certs"))]
#[must_use]
pub fn aws_lc_rs_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        signature_verification_algorithms: *CLASSICAL_SIG_ALGS,
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// The stock aws-lc-rs verification algorithms without ML-DSA. Derived from the
/// upstream provider, not hand-listed, so classical algorithms rustls adds
/// later still carry through.
#[cfg(any(feature = "fips", feature = "post-quantum", feature = "mldsa-certs"))]
pub(crate) static CLASSICAL_SIG_ALGS: std::sync::LazyLock<
    rustls::crypto::WebPkiSupportedAlgorithms,
> = std::sync::LazyLock::new(|| {
    use rustls::SignatureScheme;
    use rustls_pki_types::alg_id;

    let base = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
    let mldsa = [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];
    let all: Vec<_> = base
        .all
        .iter()
        .copied()
        .filter(|alg| !mldsa.contains(&alg.public_key_alg_id()))
        .collect();
    let mapping: Vec<_> = base
        .mapping
        .iter()
        .copied()
        .filter(|(scheme, _)| {
            !matches!(
                scheme,
                SignatureScheme::ML_DSA_44
                    | SignatureScheme::ML_DSA_65
                    | SignatureScheme::ML_DSA_87
            )
        })
        .collect();
    // `WebPkiSupportedAlgorithms` holds `&'static` slices and this set is
    // only known at run time, so it is leaked once, here, via `LazyLock`.
    rustls::crypto::WebPkiSupportedAlgorithms {
        all: all.leak(),
        mapping: mapping.leak(),
    }
});

/// Install the FIPS 140-3 crypto provider (aws-lc-rs).
///
/// Must be called once before any TLS operations. Replaces the default
/// `ring` backend with `aws-lc-rs` in FIPS mode, restricting cipher
/// suites and key exchange algorithms to the FIPS-approved set.
///
/// Returns an error if a crypto provider is already installed.
#[cfg(feature = "fips")]
pub fn install_fips_provider() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(aws_lc_rs_provider()).map_err(|_| {
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
    rustls::crypto::CryptoProvider::install_default(pq_provider()).map_err(|_| {
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
    let provider = pq_provider_with_kx_groups(groups)?;

    rustls::crypto::CryptoProvider::install_default(provider).map_err(|_| {
        RustgateError::from(ConfigError::Other(
            "crypto provider already installed".to_string(),
        ))
    })?;

    tracing::info!(groups = %groups, "crypto provider installed with custom key exchange groups");
    Ok(())
}

/// Build (but do not install) the post-quantum `aws-lc-rs` provider.
///
/// Separate from [`install_pq_provider`] so callers that need to augment the
/// provider before installing — for example adding ML-DSA certificate
/// verification (`mldsa-certs`, #501) — can compose one value and call
/// `install_default` exactly once. Installing twice silently loses the second
/// provider.
#[cfg(feature = "post-quantum")]
#[must_use]
pub fn pq_provider() -> rustls::crypto::CryptoProvider {
    aws_lc_rs_provider()
}

/// Build (but do not install) a provider with a custom key-exchange group
/// preference order. See [`pq_provider`] for why the build and install steps
/// are separable.
///
/// # Errors
///
/// Returns an error if a group name is unrecognized.
#[cfg(feature = "post-quantum")]
pub fn pq_provider_with_kx_groups(groups: &str) -> Result<rustls::crypto::CryptoProvider> {
    let mut provider = aws_lc_rs_provider();
    provider.kx_groups = parse_kx_groups(groups)?;
    Ok(provider)
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

    /// rustls 0.23.46 puts ML-DSA into the stock aws-lc-rs provider; rustgate's
    /// aws-lc-rs provider must remove exactly those entries and nothing else,
    /// so ML-DSA acceptance stays behind `--mldsa-client-certs` (#501).
    #[cfg(any(feature = "fips", feature = "post-quantum", feature = "mldsa-certs"))]
    #[test]
    fn aws_lc_rs_provider_removes_only_mldsa() {
        use rustls::SignatureScheme;
        use rustls_pki_types::alg_id;

        let is_mldsa_scheme = |s: &SignatureScheme| {
            matches!(
                s,
                SignatureScheme::ML_DSA_44
                    | SignatureScheme::ML_DSA_65
                    | SignatureScheme::ML_DSA_87
            )
        };
        let mldsa_ids = [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];

        let stock = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        let ours = aws_lc_rs_provider().signature_verification_algorithms;

        let stock_schemes: Vec<_> = stock.mapping.iter().map(|(s, _)| *s).collect();
        let our_schemes: Vec<_> = ours.mapping.iter().map(|(s, _)| *s).collect();
        let expected: Vec<_> = stock_schemes
            .iter()
            .copied()
            .filter(|s| !is_mldsa_scheme(s))
            .collect();
        assert_eq!(
            our_schemes, expected,
            "classical schemes kept, in order; ML-DSA removed"
        );

        assert!(
            ours.all
                .iter()
                .all(|alg| !mldsa_ids.contains(&alg.public_key_alg_id())),
            "no ML-DSA verification algorithm may remain in `all`"
        );
        assert_eq!(
            ours.all.len(),
            stock
                .all
                .iter()
                .filter(|alg| !mldsa_ids.contains(&alg.public_key_alg_id()))
                .count(),
            "every classical verification algorithm is kept"
        );
    }

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

    #[test]
    fn tls_min_version_protocol_versions_tls12_includes_both() {
        // `Tls12` means "accept TLS 1.2 AND 1.3" — the static slice must
        // carry both protocol-version handles so rustls's handshake can
        // negotiate either one. A regression that accidentally drops TLS13
        // from this slice silently pins every handshake to TLS12 even when
        // the peer offers TLS13, which would be a security downgrade.
        let versions = TlsMinVersion::Tls12.protocol_versions();
        assert_eq!(versions.len(), 2, "Tls12 must advertise two versions");
        let versions_set: Vec<rustls::ProtocolVersion> =
            versions.iter().map(|v| v.version).collect();
        assert!(
            versions_set.contains(&rustls::ProtocolVersion::TLSv1_2),
            "Tls12 slice must include TLS 1.2: {versions_set:?}"
        );
        assert!(
            versions_set.contains(&rustls::ProtocolVersion::TLSv1_3),
            "Tls12 slice must include TLS 1.3: {versions_set:?}"
        );
    }

    #[test]
    fn tls_min_version_protocol_versions_tls13_only() {
        // `Tls13` means "reject TLS 1.2 at handshake-start" — the static
        // slice must be exactly one element and must be TLS13. A regression
        // that leaks TLS12 into this slice lets legacy clients establish
        // sessions on a server that was configured to forbid them.
        let versions = TlsMinVersion::Tls13.protocol_versions();
        assert_eq!(
            versions.len(),
            1,
            "Tls13 must advertise exactly one version, got {}",
            versions.len()
        );
        assert_eq!(
            versions[0].version,
            rustls::ProtocolVersion::TLSv1_3,
            "Tls13's single version must be TLS 1.3"
        );
    }

    #[test]
    fn tls_min_version_derives_are_complete() {
        // Pins `#[derive(Debug, Clone, Copy, PartialEq, Eq)]` on
        // `TlsMinVersion`. The builder API treats it as a value type and
        // relies on `Copy` for `with_tls_min_version(self, version)` to
        // avoid moving an owned value at every call site; downgrading to
        // `Clone`-only would silently break 20+ call sites.
        fn assert_bounds<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        assert_bounds::<TlsMinVersion>();
        let v = TlsMinVersion::Tls13;
        let copied = v;
        // explicit Copy exercise: original is still usable
        assert_eq!(v, copied);
        assert_eq!(v, TlsMinVersion::Tls13);
        assert_ne!(v, TlsMinVersion::Tls12);
        assert!(format!("{v:?}").contains("Tls13"));
    }

    #[test]
    fn crl_file_summary_derives_are_complete() {
        // Pins the derive set on `CrlFileSummary`. It is returned from
        // `validate_crl_file` and surfaced to the Prometheus CRL-age
        // gauge; `Copy + Eq` are relied on by the reload-diffing logic in
        // `rustgate-server`'s `reload_all_configs` path.
        fn assert_bounds<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        assert_bounds::<CrlFileSummary>();
        let a = CrlFileSummary {
            count: 3,
            max_age_seconds: Some(42),
        };
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.count, 3);
        assert_eq!(a.max_age_seconds, Some(42));
        let c = CrlFileSummary {
            count: 3,
            max_age_seconds: None,
        };
        assert_ne!(a, c);
        assert!(format!("{a:?}").contains("count"));
    }

    #[test]
    fn from_pem_defaults_to_tls12_and_empty_crls() {
        // Pins the default post-`from_pem` state: TLS 1.2 minimum, no CRLs
        // loaded, stale-CRL warnings enabled. These defaults are
        // load-bearing for the happy-path server boot, where `from_pem`
        // is the sole constructor before optional `with_*` chain calls.
        let ca = rustgate_test_utils::certs::TestCa::new("config-defaults-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg =
            TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).expect("from_pem");
        assert_eq!(cfg.tls_min_version, TlsMinVersion::Tls12);
        assert!(
            cfg.crls().is_empty(),
            "from_pem must not load any CRLs by default"
        );
        assert!(
            cfg.warn_stale_crl,
            "warn_stale_crl default must be true (opt-out, not opt-in)"
        );
        assert_eq!(
            cfg.client_ca_store().len(),
            1,
            "CA store must hold exactly the issuer"
        );
    }

    #[test]
    fn from_pem_rejects_garbage_server_cert_pem() {
        // Pins that `from_pem` bubbles up `parse_certs` errors rather than
        // silently constructing a half-initialised `TlsConfig`. A broken
        // cert PEM would otherwise produce a config that *looks* valid
        // but fails at `build_server_config` time, far from the caller.
        let ca = rustgate_test_utils::certs::TestCa::new("config-rej-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let result = TlsConfig::from_pem(
            "-----BEGIN CERTIFICATE-----\nnot-der\n-----END CERTIFICATE-----\n",
            &server.key_pem,
            &ca.cert_pem,
        );
        assert!(result.is_err(), "malformed cert PEM must error at from_pem");
    }

    #[test]
    fn with_crl_warn_stale_flag_round_trips() {
        // Pins the builder flag semantics: `with_crl_warn_stale(false)`
        // must make `with_crls` quiet about expired CRLs (the deliberate
        // opt-out path for environments with stale-by-design CRLs).
        let ca = rustgate_test_utils::certs::TestCa::new("warn-stale-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("from_pem")
            .with_crl_warn_stale(false);
        assert!(!cfg.warn_stale_crl);
        // Round-trip the flag once more in the other direction.
        let cfg = cfg.with_crl_warn_stale(true);
        assert!(cfg.warn_stale_crl);
    }

    #[test]
    fn with_tls_min_version_round_trips() {
        // Pins that the builder mutation survives into `tls_min_version`,
        // which is what `build_server_config_with_verifier` reads to pick
        // the protocol-version slice. A regression that silently dropped
        // the value would leak the default (TLS 1.2) even when an
        // operator explicitly asked for TLS 1.3 only.
        let ca = rustgate_test_utils::certs::TestCa::new("version-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("from_pem")
            .with_tls_min_version(TlsMinVersion::Tls13);
        assert_eq!(cfg.tls_min_version, TlsMinVersion::Tls13);
    }

    #[test]
    fn with_crls_rejects_empty_pem_with_crls_kind() {
        // `with_crls("")` produces zero PEM blocks; the defensive check
        // must fire with `ConfigError::EmptyPem { kind: "CRLs" }` so
        // operators see *which* PEM bundle was empty. A silent Ok(self)
        // here would cause the handshake path to accept revoked certs.
        let ca = rustgate_test_utils::certs::TestCa::new("empty-crl-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("from_pem")
            .with_crls("");
        let err = cfg.expect_err("empty CRL PEM must error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("CRLs") || msg.contains("EmptyPem"),
            "error must identify empty-CRLs source: {msg}"
        );
    }

    #[test]
    fn with_crls_rejects_unparseable_pem() {
        // Pins that broken PEM surfaces as an error rather than an empty
        // CRL set. The outer `EmptyPem` check only fires when the
        // iterator is *empty*; a single garbage PEM block must hit the
        // `PemParse` arm instead.
        let ca = rustgate_test_utils::certs::TestCa::new("garbage-crl-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("from_pem")
            .with_crls("-----BEGIN X509 CRL-----\nnot-base64!\n-----END X509 CRL-----\n");
        assert!(cfg.is_err(), "unparseable CRL PEM must error at with_crls");
    }

    #[test]
    fn with_crls_accepts_real_crl_and_stores_count() {
        // End-to-end round-trip through `TestCa::generate_crl` —
        // confirms the constructor path that SIGHUP-driven reload and
        // the config-file loader both rely on. After a successful
        // `with_crls`, the `crls()` accessor must show exactly one entry
        // and `crl_max_age_seconds()` must report a small, fresh age.
        let ca = rustgate_test_utils::certs::TestCa::new("real-crl-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let victim = ca.issue_client_cert("victim", &["users"]);
        let crl_pem = ca.generate_crl(&[&victim.cert_pem]);
        let cfg = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("from_pem")
            .with_crls(&crl_pem)
            .expect("with_crls");
        assert_eq!(cfg.crls().len(), 1);
        let age = cfg.crl_max_age_seconds().expect("fresh CRL has age");
        assert!(
            (0..=60).contains(&age),
            "fresh CRL age {age}s out of expected 0..=60 band"
        );
    }

    #[test]
    fn client_ca_store_accessor_returns_loaded_roots() {
        // Pins the `&Arc<RootCertStore>` accessor shape used by
        // `DynamicCertVerifier` and the listener bootstrap to enumerate
        // trust anchors. The returned `Arc` must be shareable across
        // threads without cloning the underlying store.
        let ca = rustgate_test_utils::certs::TestCa::new("store-accessor-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg =
            TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).expect("from_pem");
        let store = cfg.client_ca_store();
        assert_eq!(store.len(), 1);
        // Cloning the `Arc` must not deep-clone the store — strong-count
        // increases, the pointee is shared.
        let cloned = std::sync::Arc::clone(store);
        assert_eq!(cloned.len(), 1);
        assert!(std::sync::Arc::ptr_eq(store, &cloned));
    }

    #[test]
    fn crls_accessor_returns_empty_slice_by_default() {
        // Pins that `crls()` on a freshly-built `TlsConfig` (no
        // `with_crls` call) is an empty slice — not an `Option`, not a
        // panic. The hot path relies on `!crls.is_empty()` to gate
        // `WebPkiClientVerifier::with_crls`; swapping the default to a
        // sentinel non-empty value would silently enable CRL checking.
        let ca = rustgate_test_utils::certs::TestCa::new("crls-empty-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg =
            TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).expect("from_pem");
        assert!(cfg.crls().is_empty());
        assert_eq!(cfg.crl_max_age_seconds(), None);
    }

    #[test]
    fn validate_crl_file_rejects_missing_path() {
        // Pins the error-surface contract: a nonexistent path must
        // produce an `Err` containing the path, so operators have a
        // grep-able diagnostic. A silent `Ok(CrlFileSummary { count: 0, .. })`
        // here would make SIGHUP reload appear successful while
        // actually leaving revocation checks disabled.
        let missing = "/definitely/not/a/real/crl/path.pem";
        let result = TlsConfig::validate_crl_file(missing);
        let err = result.expect_err("missing file must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("/definitely/not/a/real/crl/path.pem") || msg.contains("failed to read"),
            "error must mention the offending path: {msg}"
        );
    }

    #[test]
    fn validate_crl_file_rejects_empty_file() {
        // Pins the `EmptyPem { kind: "CRLs" }` arm on a literally-empty
        // CRL file. Distinct from `rejects_missing_path` because we want
        // to differentiate "file gone" from "file present but useless".
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.crl.pem");
        std::fs::write(&path, "").expect("write empty crl");
        let result = TlsConfig::validate_crl_file(path.to_str().unwrap());
        assert!(result.is_err(), "empty file must error");
    }

    #[test]
    fn validate_crl_file_succeeds_and_returns_summary() {
        // End-to-end path through disk: write a real CRL PEM, validate,
        // check that count + max_age_seconds agree with what the
        // in-memory `with_crls` path produced. Protects against a
        // regression where the disk path silently drifts from the
        // in-memory path in terms of parsing semantics.
        let ca = rustgate_test_utils::certs::TestCa::new("validate-file-ca");
        let victim = ca.issue_client_cert("victim", &["alpha"]);
        let crl_pem = ca.generate_crl(&[&victim.cert_pem]);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("real.crl.pem");
        std::fs::write(&path, &crl_pem).expect("write crl");

        let summary =
            TlsConfig::validate_crl_file(path.to_str().unwrap()).expect("validate succeeds");
        assert_eq!(summary.count, 1, "exactly one CRL block parsed");
        let age = summary.max_age_seconds.expect("fresh CRL has age");
        assert!(
            (0..=60).contains(&age),
            "fresh-CRL age {age}s outside 0..=60 band"
        );
    }

    #[test]
    fn check_crl_freshness_reports_zero_stale_on_fresh_crl() {
        // Baseline for the stale-counter: a freshly generated CRL must
        // produce a stale-count of zero. Anchors the dual-branch logic
        // (fresh vs stale) that shares one loop; a regression in the
        // `next_update > now` comparison would flip every CRL to stale.
        let ca = rustgate_test_utils::certs::TestCa::new("fresh-crl-ca");
        let victim = ca.issue_client_cert("victim", &["alpha"]);
        let crl_pem = ca.generate_crl(&[&victim.cert_pem]);
        let crls: Vec<_> = CertificateRevocationListDer::pem_slice_iter(crl_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(check_crl_freshness(&crls), 0);
    }

    #[test]
    fn check_crl_freshness_counts_expired_crl() {
        // Pins the stale-CRL path. `TestCa::generate_expired_crl` mints a
        // CRL with `nextUpdate` 30 days in the past, which must count as
        // one stale entry. The audit/logging side-effect (warn! log) is
        // not asserted — we only pin the integer return so the
        // stale-count gauge in the server metrics stays accurate.
        let ca = rustgate_test_utils::certs::TestCa::new("expired-crl-ca");
        let victim = ca.issue_client_cert("victim", &["alpha"]);
        let expired_pem = ca.generate_expired_crl(&[&victim.cert_pem]);
        let crls: Vec<_> = CertificateRevocationListDer::pem_slice_iter(expired_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(check_crl_freshness(&crls), 1);
    }

    #[test]
    fn check_crl_freshness_silently_skips_garbage_entries() {
        // A CRL slice that fails `parse_x509_crl` must not panic and must
        // not count toward the stale total — the parse-failure arm logs
        // a warn and continues. Anchors the "don't let one bad CRL
        // contaminate the signal from siblings" invariant.
        let bogus = CertificateRevocationListDer::from(vec![0x30, 0x00]);
        assert_eq!(
            check_crl_freshness(&[bogus]),
            0,
            "unparseable CRL must not count as stale"
        );
    }

    #[test]
    fn check_crl_freshness_sums_across_mixed_input() {
        // Mix one fresh and one expired CRL and verify the counter
        // reports exactly one stale. Protects against loop-variable bugs
        // (e.g. early-return on first stale, skipping remaining).
        let ca = rustgate_test_utils::certs::TestCa::new("mixed-crl-ca");
        let victim = ca.issue_client_cert("victim", &["alpha"]);
        let fresh_pem = ca.generate_crl(&[&victim.cert_pem]);
        let expired_pem = ca.generate_expired_crl(&[&victim.cert_pem]);
        let mut crls: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(fresh_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
        crls.extend(
            CertificateRevocationListDer::pem_slice_iter(expired_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap(),
        );
        assert_eq!(check_crl_freshness(&crls), 1);
    }

    #[test]
    fn build_default_verifier_without_crls_succeeds() {
        // Pins the "no CRLs loaded" build path. The builder takes the
        // `else` branch of `if !self.crls.is_empty()`, skipping
        // `with_crls`. A regression that always attaches an empty Vec of
        // CRLs would invoke a different rustls code path and cause
        // behavioural drift on test vs production servers.
        let ca = rustgate_test_utils::certs::TestCa::new("no-crls-verifier-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg =
            TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).expect("from_pem");
        let _verifier = cfg
            .build_default_verifier()
            .expect("default verifier builds without CRLs");
    }

    #[test]
    fn build_default_verifier_with_crls_succeeds() {
        // Pins the "CRLs loaded" branch. `WebPkiClientVerifier::with_crls`
        // is the hot-path entry to revocation enforcement; this ensures
        // the builder correctly threads loaded CRLs into the verifier.
        let ca = rustgate_test_utils::certs::TestCa::new("with-crls-verifier-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let victim = ca.issue_client_cert("victim", &["users"]);
        let crl_pem = ca.generate_crl(&[&victim.cert_pem]);
        let cfg = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("from_pem")
            .with_crls(&crl_pem)
            .expect("with_crls");
        let _verifier = cfg
            .build_default_verifier()
            .expect("default verifier builds with CRLs");
    }

    #[test]
    fn build_server_config_disables_tls_session_resumption() {
        // Tier-1 CVE-2025-23419-style defense: the rustls default is to
        // cache 256 resumable sessions, which lets a revoked client cert
        // re-authenticate via cached ticket without a fresh cert check.
        // We pin that the built `ServerConfig` installs
        // `NoServerSessionStorage`, observable as `can_cache() == false`.
        // A regression here re-opens the class of revoke-bypass bugs that
        // this code was specifically written to close.
        let ca = rustgate_test_utils::certs::TestCa::new("session-storage-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg =
            TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).expect("from_pem");
        let built = cfg.build_server_config().expect("build_server_config");
        assert!(
            !built.session_storage.can_cache(),
            "session_storage must be NoServerSessionStorage (can_cache=false)"
        );
        // Also pin that `put` returns false so even if a client somehow
        // attempts to cache, the storage is a no-op sink.
        assert!(
            !built
                .session_storage
                .put(b"ticket-id".to_vec(), b"secret".to_vec()),
            "NoServerSessionStorage::put must return false"
        );
    }

    #[test]
    fn build_reloadable_server_config_disables_tls_session_resumption() {
        // Same CVE-2025-23419-style pin but on the hot-reload code path.
        // Both builders must agree — one path that forgets to disable
        // session storage (and the other that disables it) is the
        // classic "tests happy, production vulnerable" regression.
        let ca = rustgate_test_utils::certs::TestCa::new("reloadable-session-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg =
            TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).expect("from_pem");
        let verifier = cfg.build_default_verifier().expect("default verifier");

        // Minimal inline stub: resolves nothing. We only need a valid
        // `ResolvesServerCert` trait object so the builder type-checks;
        // we don't drive an actual handshake.
        #[derive(Debug)]
        struct NopResolver;
        impl rustls::server::ResolvesServerCert for NopResolver {
            fn resolve(
                &self,
                _client_hello: rustls::server::ClientHello<'_>,
            ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
                None
            }
        }
        let resolver = std::sync::Arc::new(NopResolver);

        let built = cfg
            .build_reloadable_server_config(verifier, resolver)
            .expect("build_reloadable_server_config");
        assert!(
            !built.session_storage.can_cache(),
            "reloadable build path must also disable session storage"
        );
    }

    #[test]
    fn build_server_config_tls13_only_restricts_protocol_slice() {
        // End-to-end version pin: the slice picked by
        // `tls_min_version.protocol_versions()` must make its way into
        // rustls's offered versions. We can't inspect the built
        // `ServerConfig`'s version list directly (private field), so we
        // instead verify that the build succeeds and that a second build
        // with default versions also succeeds — absence of panic is the
        // observable.
        let ca = rustgate_test_utils::certs::TestCa::new("tls13-build-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let cfg = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("from_pem")
            .with_tls_min_version(TlsMinVersion::Tls13);
        let _built = cfg
            .build_server_config()
            .expect("build succeeds with TLS 1.3 only");
    }

    #[test]
    fn is_fips_provider_active_is_false_under_ring_default() {
        // `TestCa::new` installs `ring` as the default provider (not the
        // FIPS-validated `aws-lc-rs` with FIPS feature). The FIPS
        // accessor must report `false` so operators relying on
        // `--fips-required` get a clean fail-closed signal. A regression
        // that returned `true` for non-FIPS providers would silently
        // mark a non-FIPS build as compliant.
        let _ca = rustgate_test_utils::certs::TestCa::new("fips-probe-ca");
        assert!(
            !is_fips_provider_active(),
            "ring default provider must not report FIPS mode"
        );
    }

    #[test]
    fn is_pq_provider_active_is_false_under_ring_default() {
        // Same logic as FIPS: `ring` does not advertise `X25519MLKEM768`,
        // so the PQ detection accessor must report false. This is what
        // the `/status` endpoint reads — a false positive would make
        // operators believe PQ key exchange is live when it isn't.
        let _ca = rustgate_test_utils::certs::TestCa::new("pq-probe-ca");
        assert!(
            !is_pq_provider_active(),
            "ring default provider must not advertise X25519MLKEM768"
        );
    }

    #[cfg(feature = "post-quantum")]
    mod kx_groups {
        use super::super::parse_kx_groups;

        #[test]
        fn parse_single_group() {
            let groups = parse_kx_groups("X25519").unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].name(), rustls::NamedGroup::X25519);
        }

        #[test]
        fn parse_multiple_groups() {
            let groups = parse_kx_groups("X25519MLKEM768,X25519,secp256r1").unwrap();
            assert_eq!(groups.len(), 3);
            assert_eq!(groups[0].name(), rustls::NamedGroup::X25519MLKEM768);
            assert_eq!(groups[1].name(), rustls::NamedGroup::X25519);
            assert_eq!(groups[2].name(), rustls::NamedGroup::secp256r1);
        }

        #[test]
        fn parse_case_insensitive() {
            let groups = parse_kx_groups("x25519mlkem768").unwrap();
            assert_eq!(groups[0].name(), rustls::NamedGroup::X25519MLKEM768);

            let groups = parse_kx_groups("mlkem1024").unwrap();
            assert_eq!(groups[0].name(), rustls::NamedGroup::MLKEM1024);
        }

        #[test]
        fn parse_trims_whitespace() {
            let groups = parse_kx_groups("  X25519 , MLKEM768 ").unwrap();
            assert_eq!(groups.len(), 2);
            assert_eq!(groups[0].name(), rustls::NamedGroup::X25519);
            assert_eq!(groups[1].name(), rustls::NamedGroup::MLKEM768);
        }

        #[test]
        fn parse_unknown_group_errors() {
            let result = parse_kx_groups("NOTAGROUP");
            assert!(result.is_err());
            let err = format!("{}", result.unwrap_err());
            assert!(
                err.contains("unknown key exchange group"),
                "error should mention unknown group: {err}"
            );
        }

        #[test]
        fn parse_empty_string_errors() {
            let result = parse_kx_groups("");
            assert!(result.is_err());
        }

        #[test]
        fn parse_all_pq_groups() {
            let groups =
                parse_kx_groups("X25519MLKEM768,SECP256R1MLKEM768,MLKEM768,MLKEM1024").unwrap();
            assert_eq!(groups.len(), 4);
            assert_eq!(groups[0].name(), rustls::NamedGroup::X25519MLKEM768);
        }
    }

    mod crl_age {
        use rustgate_test_utils::certs::TestCa;
        use rustls_pki_types::pem::PemObject;

        #[test]
        fn empty_slice_returns_none() {
            assert_eq!(super::super::crl_max_age_seconds(&[]), None);
        }

        #[test]
        fn fresh_crl_reports_small_age() {
            let ca = TestCa::new("crl-age-ca");
            let client = ca.issue_client_cert("victim", &["alpha"]);
            let crl_pem = ca.generate_crl(&[&client.cert_pem]);
            let crls: Vec<_> =
                rustls::pki_types::CertificateRevocationListDer::pem_slice_iter(crl_pem.as_bytes())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
            let age = super::super::crl_max_age_seconds(&crls).unwrap();
            assert!((0..=60).contains(&age), "fresh CRL age {age}s out of band");
        }

        #[test]
        fn malformed_crl_bytes_suppress_entry_but_keep_siblings() {
            // Mix a real CRL with a bogus DER blob and confirm the real
            // one still anchors the age. Ensures `crl_max_age_seconds`
            // silently skips parse failures rather than collapsing the
            // signal to `None` when even one sibling is valid.
            let ca = TestCa::new("crl-age-sibling-ca");
            let client = ca.issue_client_cert("victim", &["alpha"]);
            let crl_pem = ca.generate_crl(&[&client.cert_pem]);
            let real =
                rustls::pki_types::CertificateRevocationListDer::pem_slice_iter(crl_pem.as_bytes())
                    .next()
                    .unwrap()
                    .unwrap();

            let bogus = rustls::pki_types::CertificateRevocationListDer::from(vec![
                0x30, 0x00, // minimal SEQUENCE, not a valid CRL
            ]);

            let crls = vec![real, bogus];
            let age = super::super::crl_max_age_seconds(&crls).unwrap();
            assert!(age >= 0);
        }

        #[test]
        fn all_unparseable_returns_none() {
            let bogus = rustls::pki_types::CertificateRevocationListDer::from(vec![0x30, 0x00]);
            assert_eq!(super::super::crl_max_age_seconds(&[bogus]), None);
        }
    }
}
