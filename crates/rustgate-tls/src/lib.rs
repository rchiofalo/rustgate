// Copyright © 2026 Roberto Chiofalo.

//! TLS/mTLS configuration, certificate handling, OCSP stapling, SPIFFE
//! workload identity, and TCP listeners.
//!
//! Extracted from `rustgate-transport` (#890) to scope the cross-cutting
//! TLS feature matrix (`fips`, `post-quantum`, `ocsp`, `spiffe`) to a
//! single crate. `rustgate-transport` now focuses on routing, session
//! management, dedup, ACL, codecs, store-and-forward, throttling, and
//! UDP — pure transport-layer post-handshake.
//!
//! Modules:
//!
//! * [`cert_reloader`] — atomic certificate hot-swap.
//! * [`config`] — `TlsConfig`, `TlsMinVersion`, CRL loading.
//! * [`verifier`] — `DynamicCertVerifier`, `RootStoreProvider`.
//! * [`extract`] — X.509 identity extraction (`extract_identity`).
//! * [`listener`] — `TlsListener` and handshake-error callbacks.
//! * [`pem`] — PEM parsing helpers.
//! * [`plaintext`] — `PlaintextListener` for unauthenticated bridges.
//!
//! Optional modules behind feature flags:
//!
//! * `ocsp` / `client_ocsp` — OCSP stapling and verification (feature `ocsp`).
//! * `spiffe` — SPIFFE Workload API integration (feature `spiffe`).

#![forbid(unsafe_code)]

pub mod cert_reloader;
pub mod config;
pub mod crl_store;
pub mod extract;
pub mod listener;
pub mod pem;
pub mod plaintext;
pub mod session;
pub mod verifier;

#[cfg(feature = "ocsp")]
pub mod client_ocsp;
#[cfg(feature = "ocsp")]
pub mod ocsp;
#[cfg(feature = "spiffe")]
pub mod spiffe;

pub use cert_reloader::CertReloader;
#[cfg(feature = "ocsp")]
pub use client_ocsp::{ClientOcspVerifier, FetchFuture, OcspFetcher, OcspStaplerFetcher};
#[cfg(feature = "fips")]
pub use config::install_fips_provider;
pub use config::{
    CrlFileSummary, TlsConfig, TlsMinVersion, check_crl_freshness, crl_max_age_seconds,
    is_fips_provider_active, is_pq_provider_active,
};
#[cfg(feature = "post-quantum")]
pub use config::{install_pq_provider, install_provider_with_kx_groups};
pub use crl_store::{CrlHealth, CrlStore};
pub use extract::{ExpectedKeyUsage, extract_identity, validate_key_usage};
pub use listener::{DEFAULT_MAX_HANDSHAKES, OnHandshakeError, TlsListener};
pub use plaintext::{PlaintextIdentityConfig, PlaintextListener, PlaintextSession};
pub use session::{AuthenticatedSession, SessionReader, SessionWriter};
#[cfg(feature = "spiffe")]
pub use spiffe::{SpiffeConfig, SpiffeHooks, SpiffeIdentity};
pub use verifier::{CrlProvider, DynamicCertVerifier, RootStoreProvider};
