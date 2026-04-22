// Copyright © 2026 Roberto Chiofalo.

//! Server startup and subsystem initialization.
//!
//! Extracts the setup logic from `run()` into focused functions for each
//! subsystem: TLS, NATS, enrollment, federation, metrics, WebSocket,
//! plaintext TCP, and UDP.

#[cfg(feature = "federation")]
use std::collections::BTreeSet;
use std::sync::Arc;
#[cfg(feature = "federation")]
use std::time::SystemTime;

use anyhow::Context;
#[cfg(feature = "federation")]
use rustgate_core::identity::Identity;
#[cfg(feature = "federation")]
use rustgate_core::message::RoutableMessage;
#[cfg(feature = "federation")]
use rustgate_core::message::{Destination, Metadata};
use rustgate_core::tasks::SubsystemHandle;
// Used only inside feature-gated subsystem setup functions (nats,
// enrollment, metrics, federation*). The websocket and UDP setup paths
// also call `spawn_background`, but only inside nested
// `#[cfg(feature = "nats")]` blocks — so `nats` alone covers those.
// Gated to keep the no-features and nats-less builds warning-clean.
#[cfg(any(
    feature = "nats",
    feature = "enrollment",
    feature = "metrics",
    feature = "federation",
    feature = "federation-ha",
))]
use rustgate_core::tasks::spawn_background;
use rustgate_transport::{
    CertReloader, Router, ThrottleConfig, TlsConfig, TlsListener, TlsMinVersion,
};
use tokio::sync::Semaphore;

use crate::cli::{Cli, Encoding, Framing};
#[cfg(feature = "metrics")]
use crate::metrics;
#[cfg(feature = "http")]
use crate::session::HttpForwardFn;
use crate::session::{FedForwardFn, NatsPublish, PlaintextTcpConfig};

/// Load group access control policy from a JSON configuration file.
///
/// Returns `(None, None)` if no ACL file is configured (open mode).
/// When an ACL file is loaded, also returns the SHA-256 hash of the raw
/// file contents so the hot-reloader can detect subsequent changes.
pub(crate) async fn load_group_acl(
    cli: &Cli,
) -> anyhow::Result<(
    Option<rustgate_transport::GroupAclPolicy>,
    Option<[u8; 32]>,
    Option<crate::acl_config::GroupAclFile>,
)> {
    let Some(ref acl_file) = cli.group_acl_file else {
        return Ok((None, None, None));
    };

    let data = tokio::fs::read_to_string(acl_file)
        .await
        .context("reading group ACL file")?;

    let hash = crate::acl_reloader::AclReloader::compute_hash(data.as_bytes());

    let config: crate::acl_config::GroupAclFile =
        serde_json::from_str(&data).context("parsing group ACL file")?;

    // Reject reserved-sentinel group ids (`__*__`) before the policy
    // reaches the router. See `GroupAclFile::validate_operator_policy`
    // for the threat model — a policy keyed by `__plaintext__` would
    // silently apply to every anonymous plaintext session.
    if let Err(msg) = config.validate_operator_policy() {
        anyhow::bail!("invalid group ACL file: {msg}");
    }

    let mut groups = std::collections::HashMap::new();
    for (group_id, entry) in &config.groups {
        let _ = groups.insert(
            group_id.clone(),
            rustgate_transport::GroupAcl::with_deny(
                entry.send.iter().map(|s| s.to_ascii_lowercase()).collect(),
                entry
                    .receive
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                entry
                    .deny_send
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                entry
                    .deny_receive
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
            ),
        );
    }

    let policy = rustgate_transport::GroupAclPolicy::new(groups);
    tracing::info!(groups = policy.len(), "loaded group access control policy");
    Ok((Some(policy), Some(hash), Some(config)))
}

/// Build the TLS configuration from CLI flags.
///
/// Returns the `TlsConfig`, the raw PEM strings (needed by enrollment and
/// federation setup), and — when SPIFFE is enabled — the already-fetched
/// `SpiffeIdentity` so that `bind_tls_listener` can reuse it without
/// hitting the Workload API a second time.
pub(crate) async fn build_tls_config(cli: &Cli) -> anyhow::Result<TlsConfigBuild> {
    #[cfg(feature = "spiffe")]
    if cli.spiffe {
        let spiffe_cfg = rustgate_transport::spiffe::SpiffeConfig {
            workload_api_socket: cli.spiffe_workload_api_socket.clone(),
            expected_trust_domain: cli.spiffe_trust_domain.clone(),
            refresh_interval: std::time::Duration::from_secs(cli.spiffe_refresh_interval),
        };
        let identity = rustgate_transport::spiffe::fetch_initial_identity(&spiffe_cfg)
            .await
            .context("fetching initial SPIFFE X.509-SVID")?;

        let tls_min_version = TlsMinVersion::from_str_version(&cli.tls_min_version)
            .context("parsing TLS minimum version")?;
        let mut tls_config = TlsConfig::from_pem(
            &identity.cert_pem,
            &identity.key_pem,
            &identity.trust_bundle_pem,
        )
        .context("building SPIFFE-backed TLS config")?;
        tls_config = tls_config.with_tls_min_version(tls_min_version);
        tls_config = tls_config.with_crl_warn_stale(cli.crl_warn_stale);

        // CRL support via SPIFFE is not defined by the SPIFFE spec; operators
        // that need CRLs can still point `--crl` at a static file alongside
        // `--spiffe`. This mirrors how OCSP stapling coexists with SPIFFE.
        // Note: the CRL is loaded once at startup and does not hot-reload
        // under `--spiffe`; restart to pick up new CRLs.
        if let Some(ref crl_path) = cli.crl {
            let crl_pem = tokio::fs::read_to_string(crl_path)
                .await
                .context("reading CRL file")?;
            tls_config = tls_config.with_crls(&crl_pem).context("loading CRL data")?;
        }

        return Ok(TlsConfigBuild {
            tls_config,
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            ca_pem: identity.trust_bundle_pem.clone(),
            spiffe_identity: Some(identity),
        });
    }

    #[cfg(not(feature = "spiffe"))]
    if cli.spiffe {
        anyhow::bail!(
            "--spiffe was set but rustgate was built without the `spiffe` feature; \
             rebuild with --features spiffe to enable SPIFFE workload identity"
        );
    }

    let cert_pem = tokio::fs::read_to_string(&cli.cert)
        .await
        .context("reading server certificate")?;
    let key_pem = zeroize::Zeroizing::new(
        tokio::fs::read_to_string(&cli.key)
            .await
            .context("reading server private key")?,
    );
    let ca_pem = tokio::fs::read_to_string(&cli.ca)
        .await
        .context("reading CA certificate")?;

    let tls_min_version = TlsMinVersion::from_str_version(&cli.tls_min_version)
        .context("parsing TLS minimum version")?;

    let mut tls_config =
        TlsConfig::from_pem(&cert_pem, &key_pem, &ca_pem).context("building TLS config")?;
    tls_config = tls_config.with_tls_min_version(tls_min_version);
    tls_config = tls_config.with_crl_warn_stale(cli.crl_warn_stale);

    if let Some(ref crl_path) = cli.crl {
        let crl_pem = tokio::fs::read_to_string(crl_path)
            .await
            .context("reading CRL file")?;
        tls_config = tls_config.with_crls(&crl_pem).context("loading CRL data")?;
    }

    Ok(TlsConfigBuild {
        tls_config,
        cert_pem,
        key_pem,
        ca_pem,
        #[cfg(feature = "spiffe")]
        spiffe_identity: None,
    })
}

/// Result of [`build_tls_config`]. Carries the PEM strings consumed by the
/// rest of the server plus, under `--spiffe`, the already-fetched
/// `SpiffeIdentity` so `bind_tls_listener` can reuse the initial SVID
/// and `CertReloader` without a second Workload API round-trip.
pub(crate) struct TlsConfigBuild {
    pub(crate) tls_config: TlsConfig,
    pub(crate) cert_pem: String,
    /// Wrapped in `Zeroizing` so the private key PEM is wiped from memory on drop.
    pub(crate) key_pem: zeroize::Zeroizing<String>,
    pub(crate) ca_pem: String,
    #[cfg(feature = "spiffe")]
    pub(crate) spiffe_identity: Option<rustgate_transport::spiffe::SpiffeIdentity>,
}

/// Bind the TLS listener with a handshake concurrency limit.
///
/// When `cert_reload_interval > 0`, the server uses a [`CertReloader`] as the
/// certificate resolver so that the TLS certificate can be rotated on disk
/// without restarting the server. A background watcher task polls for changes.
pub(crate) async fn bind_tls_listener(
    cli: &Cli,
    tls_config: &TlsConfig,
    #[cfg(feature = "spiffe")] spiffe_identity: Option<rustgate_transport::spiffe::SpiffeIdentity>,
) -> anyhow::Result<TlsListenerHandle> {
    // When SPIFFE is enabled, reuse the `SpiffeIdentity` already fetched by
    // `build_tls_config` so we do not double-fetch from the Workload API at
    // startup (which would briefly leave the TlsConfig and CertReloader
    // tracking two different SVIDs).
    #[cfg(feature = "spiffe")]
    let reloader = if cli.spiffe {
        let identity = spiffe_identity
            .ok_or_else(|| anyhow::anyhow!("SPIFFE enabled but no preloaded identity passed"))?;
        let spiffe_cfg = rustgate_transport::spiffe::SpiffeConfig {
            workload_api_socket: cli.spiffe_workload_api_socket.clone(),
            expected_trust_domain: cli.spiffe_trust_domain.clone(),
            refresh_interval: std::time::Duration::from_secs(cli.spiffe_refresh_interval),
        };
        let reloader = identity.cert_reloader.clone();

        #[cfg(feature = "metrics")]
        let hooks = Some(rustgate_transport::spiffe::SpiffeHooks {
            on_success: Arc::new(|expiry| {
                metrics::spiffe_refresh_total()
                    .with_label_values(&["success"])
                    .inc();
                metrics::spiffe_svid_expiry_seconds().set(expiry);
            }),
            on_failure: Arc::new(|| {
                metrics::spiffe_refresh_total()
                    .with_label_values(&["failure"])
                    .inc();
            }),
        });
        #[cfg(not(feature = "metrics"))]
        let hooks: Option<rustgate_transport::spiffe::SpiffeHooks> = None;

        rustgate_transport::spiffe::spawn_refresh_task(
            Arc::downgrade(&reloader),
            spiffe_cfg,
            hooks,
        );
        tracing::info!(
            spiffe_id = %identity.spiffe_id,
            trust_domain = %identity.trust_domain,
            "SPIFFE workload identity active"
        );
        reloader
    } else {
        CertReloader::new(&cli.cert, &cli.key).context("initializing certificate reloader")?
    };

    #[cfg(not(feature = "spiffe"))]
    let reloader =
        CertReloader::new(&cli.cert, &cli.key).context("initializing certificate reloader")?;

    let inner_verifier = tls_config.build_default_verifier()?;

    // Optionally wrap the inner verifier with the client-cert OCSP
    // verifier so revoked client certificates can be detected
    // near-real-time without waiting for the next CRL refresh. The
    // wrapper is gated on `--features ocsp` because it reuses the
    // OCSP fetcher from the same upstream crate as server stapling.
    #[cfg(feature = "ocsp")]
    let verifier: std::sync::Arc<dyn rustgate_transport::ClientCertVerifier> = if cli.client_ocsp {
        #[cfg(feature = "metrics")]
        let on_hit: Option<rustgate_transport::client_ocsp::OnCacheHit> =
            Some(std::sync::Arc::new(|| {
                if let Some(c) = metrics::client_ocsp_cache_hits() {
                    c.inc();
                }
            }));
        #[cfg(feature = "metrics")]
        let on_miss: Option<rustgate_transport::client_ocsp::OnCacheMiss> =
            Some(std::sync::Arc::new(|| {
                if let Some(c) = metrics::client_ocsp_cache_misses() {
                    c.inc();
                }
            }));
        #[cfg(not(feature = "metrics"))]
        let on_hit: Option<rustgate_transport::client_ocsp::OnCacheHit> = None;
        #[cfg(not(feature = "metrics"))]
        let on_miss: Option<rustgate_transport::client_ocsp::OnCacheMiss> = None;

        let fetcher: std::sync::Arc<dyn rustgate_transport::OcspFetcher> =
            std::sync::Arc::new(rustgate_transport::OcspStaplerFetcher::default());
        let wrapped =
            rustgate_transport::ClientOcspVerifier::new(inner_verifier, fetcher, on_hit, on_miss);
        tracing::info!(
            "client certificate OCSP verification enabled (Tier 1, fail-open, SKI cache)"
        );
        wrapped as std::sync::Arc<dyn rustgate_transport::ClientCertVerifier>
    } else {
        inner_verifier
    };

    #[cfg(not(feature = "ocsp"))]
    let verifier = inner_verifier;
    #[cfg(not(feature = "ocsp"))]
    if cli.client_ocsp {
        tracing::warn!(
            "--client-ocsp set but the ocsp feature is not compiled in; \
             rebuild with --features ocsp to enable client OCSP verification"
        );
    }

    // OCSP stapling sits on the *resolver* (server certificate) side of the
    // handshake; the existing CRL verifier sits on the *client certificate*
    // side. The two layers are independent and may be enabled together.
    #[cfg(feature = "ocsp")]
    let (resolver, ocsp_stapler): (
        std::sync::Arc<dyn rustgate_transport::ResolvesServerCert>,
        Option<std::sync::Arc<rustgate_transport::ocsp::Stapler>>,
    ) = if cli.ocsp_stapling {
        let stapler = rustgate_transport::ocsp::wrap_resolver(reloader.clone());
        // Preload the active certificate so the stapler queues its first
        // OCSP fetch immediately rather than waiting for the inaugural
        // handshake to surface it. This shrinks (but does not eliminate)
        // the unstapled window at startup; the background fetcher still
        // needs one cycle (up to ~60s) to actually populate the cache.
        if let Some(ckey) = reloader.certified_key() {
            rustgate_transport::ocsp::preload(&stapler, ckey);
        }
        tracing::info!("OCSP stapling enabled for server certificate");
        (stapler.clone(), Some(stapler))
    } else {
        (reloader.clone(), None)
    };

    #[cfg(not(feature = "ocsp"))]
    let resolver: std::sync::Arc<dyn rustgate_transport::ResolvesServerCert> = reloader.clone();

    #[cfg(not(feature = "ocsp"))]
    if cli.ocsp_stapling {
        tracing::warn!(
            "--ocsp-stapling set but the ocsp feature is not compiled in; \
             rebuild with --features ocsp to enable OCSP stapling"
        );
    }

    let server_config = tls_config
        .build_reloadable_server_config(verifier, resolver)
        .context("building reloadable server config")?;

    if cli.cert_reload_interval > 0 {
        let interval = std::time::Duration::from_secs(cli.cert_reload_interval);
        reloader.spawn_watcher(interval);
        tracing::info!(
            interval_secs = cli.cert_reload_interval,
            "certificate hot-reload polling enabled"
        );
    } else {
        tracing::info!(
            "certificate hot-reload polling disabled; SIGHUP can still rotate certificates"
        );
    }

    // `mut` is only needed when `metrics` is enabled (for `set_on_handshake_error`).
    #[allow(unused_mut)]
    let mut listener = TlsListener::bind_with_server_config(
        &cli.bind,
        Arc::new(server_config),
        cli.max_concurrent_handshakes,
    )
    .await
    .context("binding TLS listener with cert reloader")?;
    let cert_reloader = Some(reloader);

    #[cfg(feature = "metrics")]
    listener.set_on_handshake_error(Arc::new(|_peer_addr, error| {
        let reason = metrics::classify_handshake_error(error);
        metrics::accept_errors().inc();
        metrics::handshake_failures()
            .with_label_values(&[reason])
            .inc();
        // Tier 2 per-identity handshake failures: identity is unknown
        // because the handshake failed, so all events bucket under "other".
        if let Some(c) = metrics::per_identity_handshake_failures() {
            c.with_label_values(&["other"]).inc();
        }
    }));

    Ok(TlsListenerHandle {
        listener,
        cert_reloader,
        #[cfg(feature = "ocsp")]
        ocsp_stapler,
    })
}

/// Handle returned by [`bind_tls_listener`] grouping the bound TLS listener
/// with the optional cert reloader and (when the `ocsp` feature is enabled)
/// the OCSP stapler whose background task must be stopped at shutdown.
pub(crate) struct TlsListenerHandle {
    pub(crate) listener: TlsListener,
    pub(crate) cert_reloader: Option<Arc<CertReloader>>,
    #[cfg(feature = "ocsp")]
    pub(crate) ocsp_stapler: Option<Arc<rustgate_transport::ocsp::Stapler>>,
}

/// Validate framing/encoding feature requirements and consistency at startup.
///
/// Rejects proto-dependent framing or encoding when the `proto` feature is not
/// compiled in, and rejects ambiguous flag combinations where `--framing` and
/// `--encoding` disagree on the wire protocol.
pub(crate) fn validate_framing(cli: &Cli) -> anyhow::Result<()> {
    #[cfg(not(feature = "proto"))]
    if matches!(cli.framing, Framing::TakProtobuf | Framing::TakNegotiate)
        || matches!(cli.encoding, Encoding::TakProtobuf)
    {
        anyhow::bail!("TAK protobuf support requires --features proto");
    }

    // Reject ambiguous combinations where framing and encoding disagree on
    // the wire protocol. --encoding tak-protobuf implies 0xBF+varint framing,
    // which conflicts with non-protobuf --framing values.
    if matches!(cli.encoding, Encoding::TakProtobuf)
        && !matches!(cli.framing, Framing::TakProtobuf | Framing::TakNegotiate)
    {
        anyhow::bail!(
            "--encoding tak-protobuf requires --framing tak-protobuf or --framing tak-negotiate; \
             got --framing {:?}",
            cli.framing
        );
    }

    // Suppress unused-variable warning when proto is enabled
    let _ = &cli;

    Ok(())
}

/// Build per-client rate-limiting configuration (if enabled).
pub(crate) fn build_throttle_config(cli: &Cli) -> Option<ThrottleConfig> {
    if cli.client_message_rate > 0 {
        tracing::info!(
            rate = cli.client_message_rate,
            burst = cli.client_burst,
            "per-client rate limiting enabled"
        );
        Some(ThrottleConfig::new(
            cli.client_message_rate,
            cli.client_burst,
        ))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// NATS
// ---------------------------------------------------------------------------

/// Connect to NATS, run JetStream replay, and spawn the subscriber task.
///
/// Returns the publisher handle if connection succeeds, `None` otherwise.
#[cfg(feature = "nats")]
pub(crate) async fn connect_nats(
    cli: &Cli,
    router: &Arc<Router>,
) -> Option<rustgate_nats::NatsPublisher> {
    let nats_url = cli.nats_url.as_ref()?;

    let config = rustgate_nats::NatsConfig {
        url: nats_url.clone(),
        credentials_file: cli.nats_credentials.clone(),
        tls: rustgate_nats::NatsTlsConfig {
            client_cert: cli.nats_tls_cert.clone(),
            client_key: cli.nats_tls_key.clone(),
            ca_cert: cli.nats_tls_ca.clone(),
            required: cli.nats_tls_required,
        },
        subscription_capacity: cli.nats_subscription_capacity,
        live_stream: cli.nats_live_stream.clone(),
        max_ack_pending: cli.nats_max_ack_pending,
        checkpoint_path: cli
            .nats_checkpoint_path
            .as_ref()
            .map(std::path::PathBuf::from),
        ..Default::default()
    };

    match rustgate_nats::NatsAdapter::connect(config).await {
        Ok(adapter) => {
            // Run JetStream replay to populate position cache before accepting clients
            let replay = adapter.jetstream_replay();
            match replay.replay(Arc::clone(router)).await {
                Ok(count) => tracing::info!(count, "JetStream SA replay loaded"),
                Err(e) => {
                    tracing::warn!(error = %e, "JetStream replay failed (continuing without history)")
                }
            }

            // Spawn NATS subscriber as a background task
            #[cfg_attr(not(feature = "metrics"), allow(unused_mut))]
            let mut subscriber = adapter.subscriber();
            #[cfg(feature = "metrics")]
            {
                use rustgate_nats::{LagCallback, LagSnapshot, LatencyCallback};
                let cb: LagCallback = std::sync::Arc::new(|snap: LagSnapshot| {
                    if let Some(g) = crate::metrics::nats_consumer_pending() {
                        g.set(snap.num_pending as i64);
                    }
                    if let Some(g) = crate::metrics::nats_consumer_num_redelivered() {
                        g.set(snap.num_redelivered as i64);
                    }
                    if let Some(g) = crate::metrics::nats_consumer_ack_floor_stream_seq() {
                        g.set(snap.ack_floor_stream_seq as i64);
                    }
                });
                let lat_cb: LatencyCallback = std::sync::Arc::new(|d: std::time::Duration| {
                    if let Some(h) = crate::metrics::nats_consumer_info_seconds() {
                        h.observe(d.as_secs_f64());
                    }
                });
                subscriber = subscriber
                    .with_lag_callback(cb, None)
                    .with_latency_callback(lat_cb);
            }
            let sub_router = Arc::clone(router);
            spawn_background("nats-subscriber", async move {
                if let Err(e) = subscriber.run(sub_router).await {
                    tracing::warn!(error = %e, "NATS subscriber ended with error");
                }
            });

            Some(adapter.publisher())
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to connect to NATS (continuing without bridge)");
            None
        }
    }
}

/// Stub for when the `nats` feature is disabled.
#[cfg(not(feature = "nats"))]
pub(crate) fn warn_nats_disabled(cli: &Cli) {
    if cli.nats_url.is_some() {
        tracing::warn!("--nats-url requires --features nats; ignoring");
    }
}

// ---------------------------------------------------------------------------
// HTTP Egress
// ---------------------------------------------------------------------------

/// Build and start the HTTP egress publisher.
///
/// Reads the TOML config file, validates, constructs the publisher with
/// per-target clients, and returns the forward callback plus the publisher
/// handle for shutdown.
#[cfg(feature = "http")]
pub(crate) async fn connect_http(
    cli: &Cli,
) -> Option<(crate::session::HttpForwardFn, rustgate_http::HttpPublisher)> {
    let config_path = cli.http_config_file.as_ref()?;
    let config_str = match tokio::fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(path = %config_path, error = %e, "failed to read HTTP config");
            return None;
        }
    };
    let config: rustgate_http::HttpConfig = match toml::from_str(&config_str) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse HTTP config");
            return None;
        }
    };
    match rustgate_http::HttpPublisher::new(config) {
        Ok(publisher) => {
            let p = publisher.clone();
            let fwd: crate::session::HttpForwardFn = std::sync::Arc::new(move |msg| {
                p.publish(&msg);
            });
            tracing::info!("HTTP egress bridge started");
            Some((fwd, publisher))
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to initialize HTTP publisher");
            None
        }
    }
}

/// Warn when --http-config is set but the `http` feature is disabled.
#[cfg(not(feature = "http"))]
pub(crate) fn warn_http_disabled(cli: &Cli) {
    if cli.http_config_file.is_some() {
        tracing::warn!("--http-config requires --features http; ignoring");
    }
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/// Start the enrollment HTTPS server for client certificate provisioning.
#[cfg(feature = "enrollment")]
pub(crate) async fn start_enrollment(
    cli: &Cli,
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
    router: &Arc<Router>,
) -> anyhow::Result<()> {
    let enrollment_bind = match cli.enrollment_bind.as_ref() {
        Some(b) => b,
        None => return Ok(()),
    };

    let ca_key_path = cli
        .ca_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--ca-key is required when --enrollment-bind is set"))?;
    let enrollment_user = cli.enrollment_user.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--enrollment-user is required when --enrollment-bind is set")
    })?;
    let enrollment_password = cli.enrollment_password.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--enrollment-password is required when --enrollment-bind is set")
    })?;

    let ca_key_pem = zeroize::Zeroizing::new(
        tokio::fs::read_to_string(ca_key_path)
            .await
            .context("reading CA private key for enrollment")?,
    );

    let signer =
        rustgate_enrollment::CsrSigner::from_pem(ca_pem, &ca_key_pem, &cli.ca_organization)
            .context("building CSR signer for enrollment")?;
    let credentials = rustgate_enrollment::Credentials::new(
        enrollment_user.to_string(),
        zeroize::Zeroizing::new(enrollment_password.to_string()),
    );
    let enrollment_router = Arc::clone(router);
    let contacts_provider: rustgate_enrollment::ContactsProvider = Arc::new(move || {
        let r = Arc::clone(&enrollment_router);
        Box::pin(async move {
            r.connected_clients()
                .await
                .into_iter()
                .map(|id| rustgate_enrollment::ContactInfo {
                    uid: id.cn.clone(),
                    callsign: id.cn.clone(),
                    groups: id.groups.iter().cloned().collect(),
                    last_status: "Connected".to_string(),
                })
                .collect()
        })
    });

    let contacts_provider = rustgate_enrollment::cached_contacts_provider(
        contacts_provider,
        std::time::Duration::from_secs(30),
    );

    let rate_window = std::time::Duration::from_secs(60);
    // 0 disables the throttle by treating it as effectively unbounded.
    let rate_limit = if cli.enrollment_rate_limit == 0 {
        usize::MAX
    } else {
        cli.enrollment_rate_limit as usize
    };

    let mut enrollment_server = rustgate_enrollment::EnrollmentServer::new(signer, credentials)
        .with_contacts_provider(contacts_provider)
        .with_rate_limit(rate_limit, rate_window);

    #[cfg(feature = "est")]
    if cli.est_enabled {
        enrollment_server = enrollment_server.with_est();
        tracing::info!("EST (RFC 7030) endpoints enabled");
    }

    #[cfg(feature = "metrics")]
    {
        enrollment_server = enrollment_server.with_rate_limit_callback(std::sync::Arc::new(|| {
            crate::metrics::enrollment_rate_limited().inc();
        }));
        // Issue #767 / F-41: expose rate-limiter mutex poison as a
        // dedicated counter so operators can alert separately from
        // rate-limit rejections (both surface as HTTP 503 otherwise).
        enrollment_server =
            enrollment_server.with_rate_limit_poison_callback(std::sync::Arc::new(|| {
                crate::metrics::enrollment_rate_limit_poison().inc();
            }));
    }

    tracing::info!(
        max_per_minute = cli.enrollment_rate_limit,
        "enrollment CSR signing rate limit configured"
    );

    if let Some(ref pkg_dir) = cli.data_package_dir {
        let mut store =
            rustgate_enrollment::DataPackageStore::new(std::path::PathBuf::from(pkg_dir))
                .await
                .context("initializing data package store")?;

        if cli.package_strict_signatures && cli.package_signature_ca.is_none() {
            anyhow::bail!("--package-strict-signatures requires --package-signature-ca to be set");
        }

        store = store.with_strict_signatures(cli.package_strict_signatures);

        if let Some(ref ca_path) = cli.package_signature_ca {
            let pem_data = tokio::fs::read_to_string(ca_path)
                .await
                .context("reading --package-signature-ca")?;
            let ca_der: Vec<u8> = {
                use rustls_pki_types::pem::PemObject;
                let cert = rustls_pki_types::CertificateDer::from_pem_slice(pem_data.as_bytes())
                    .context("parsing package signature CA PEM")?;
                cert.to_vec()
            };
            store = store
                .with_signing_ca(&ca_der)
                .context("configuring package signature CA")?;
        }

        enrollment_server = enrollment_server.with_packages(store);
        tracing::info!(dir = %pkg_dir, "data package storage enabled");
    }

    if let Some(ref db_path) = cli.revocation_db {
        let revocation_store = rustgate_enrollment::RevocationStore::new(
            std::path::PathBuf::from(db_path),
            cert_pem,
            key_pem,
        )
        .await
        .context("initializing revocation store")?
        .with_crl_validity_days(cli.crl_validity_days);

        let revoked_count = revocation_store.count().await;
        enrollment_server = enrollment_server.with_revocation(revocation_store);
        tracing::info!(
            db = %db_path,
            revoked = revoked_count,
            crl_validity_days = cli.crl_validity_days,
            "certificate revocation enabled"
        );
    }

    let bind_addr: std::net::SocketAddr = enrollment_bind
        .parse()
        .context("parsing --enrollment-bind address")?;

    let enrollment_cert = cert_pem.to_string();
    let enrollment_key = zeroize::Zeroizing::new(key_pem.to_string());

    spawn_background("enrollment-server", async move {
        if let Err(e) = enrollment_server
            .run(bind_addr, &enrollment_cert, &enrollment_key)
            .await
        {
            tracing::error!(error = %e, "enrollment server failed");
        }
    });

    tracing::info!(addr = %enrollment_bind, "enrollment server started");
    Ok(())
}

/// Warn when enrollment is requested without the feature.
#[cfg(not(feature = "enrollment"))]
pub(crate) fn warn_enrollment_disabled(cli: &Cli) {
    if cli.enrollment_bind.is_some() {
        tracing::warn!("--enrollment-bind requires --features enrollment; ignoring");
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Initialize and optionally start the Prometheus metrics HTTP server.
///
/// Also constructs the [`metrics::MetricsIdentity`] used by the session
/// layer to bucket per-identity labels and (optionally) record Tier 2
/// per-identity metrics. Returns the identity wrapped in an `Arc` so it
/// can be cheaply shared across spawned session tasks.
#[cfg(feature = "metrics")]
pub(crate) async fn start_metrics(
    cli: &Cli,
    health: &Arc<metrics::HealthState>,
    readiness: &Arc<metrics::ReadinessState>,
    #[cfg(feature = "federation")] fed_api_slot: &Arc<std::sync::OnceLock<metrics::FedApiHandler>>,
    acl_api_slot: &Arc<std::sync::OnceLock<metrics::AclApiHandler>>,
    router_slot: &metrics::RouterSlot,
) -> anyhow::Result<Arc<metrics::MetricsIdentity>> {
    metrics::init().context("registering metrics")?;

    #[cfg(feature = "federation")]
    rustgate_federation::metrics::init().context("registering federation metrics")?;

    #[cfg(all(feature = "http", feature = "metrics"))]
    rustgate_http::metrics::init().context("registering HTTP egress metrics")?;

    // Load the optional CN allowlist for per-identity metric label
    // bucketing. When unset, all CNs collapse to the literal "other"
    // label, capping cardinality at 1.
    let allowlist = if let Some(ref path) = cli.metrics_identity_allowlist {
        let set = metrics::load_identity_allowlist(path)
            .with_context(|| format!("loading metrics identity allowlist {}", path.display()))?;
        tracing::info!(
            path = %path.display(),
            count = set.len(),
            "loaded per-identity metrics allowlist"
        );
        Some(set)
    } else {
        None
    };

    if cli.metrics_per_identity {
        metrics::init_per_identity().context("registering per-identity metrics")?;
        tracing::info!("Tier 2 per-identity metrics enabled");
    }

    let identity = Arc::new(metrics::MetricsIdentity::new(
        allowlist,
        cli.metrics_per_identity,
    ));

    // Load the optional metrics bearer token from file. When set,
    // requests to `/metrics` must present this token; when unset the
    // endpoint remains unauthenticated for backward compatibility.
    let metrics_token: Option<Arc<zeroize::Zeroizing<Vec<u8>>>> =
        if let Some(ref token_file) = cli.metrics_token_file {
            let raw = tokio::fs::read_to_string(token_file).await.map_err(|e| {
                anyhow::anyhow!("failed to read metrics token file {token_file}: {e}")
            })?;
            let token = raw.trim().as_bytes().to_vec();
            if token.is_empty() {
                anyhow::bail!("metrics token file {token_file} is empty");
            }
            crate::acl_api::validate_bearer_token_length(&token, "metrics bearer")
                .map_err(|e| anyhow::anyhow!("{e} (from {token_file})"))?;
            tracing::info!("metrics endpoint authentication enabled via --metrics-token-file");
            Some(Arc::new(zeroize::Zeroizing::new(token)))
        } else {
            None
        };

    if let Some(ref metrics_bind) = cli.metrics_bind {
        let bind_addr: std::net::SocketAddr = metrics_bind
            .parse()
            .context("parsing --metrics-bind address")?;

        let health_for_metrics = Arc::clone(health);
        let readiness_for_metrics = Arc::clone(readiness);
        #[cfg(feature = "federation")]
        let fed_api_for_metrics = Arc::clone(fed_api_slot);
        let acl_api_for_metrics = Arc::clone(acl_api_slot);
        let metrics_token_for_server = metrics_token.clone();
        let router_for_metrics = Arc::clone(router_slot);
        let max_http_connections = cli.metrics_max_connections;
        spawn_background("metrics-server", async move {
            if let Err(e) = metrics::serve(
                bind_addr,
                health_for_metrics,
                readiness_for_metrics,
                #[cfg(feature = "federation")]
                fed_api_for_metrics,
                acl_api_for_metrics,
                metrics_token_for_server,
                router_for_metrics,
                max_http_connections,
            )
            .await
            {
                tracing::error!(error = %e, "metrics server failed");
            }
        });
    }

    Ok(identity)
}

/// Warn when metrics is requested without the feature.
#[cfg(not(feature = "metrics"))]
pub(crate) fn warn_metrics_disabled(cli: &Cli) {
    if cli.metrics_bind.is_some() {
        tracing::warn!("--metrics-bind requires --features metrics; ignoring");
    }
    if cli.metrics_token_file.is_some() {
        tracing::warn!("--metrics-token-file requires --features metrics; ignoring");
    }
    if cli.metrics_per_identity {
        tracing::warn!("--metrics-per-identity requires --features metrics; ignoring");
    }
    if cli.metrics_identity_allowlist.is_some() {
        tracing::warn!("--metrics-identity-allowlist requires --features metrics; ignoring");
    }
}

// ---------------------------------------------------------------------------
// Federation
// ---------------------------------------------------------------------------

/// Build the federation configuration from CLI flags and peer config file.
#[cfg(feature = "federation")]
async fn build_federation_config(
    cli: &Cli,
    bind_addr: std::net::SocketAddr,
) -> anyhow::Result<rustgate_federation::config::FederationConfig> {
    let peers = if let Some(ref peers_file) = cli.federation_peers_file {
        let data = tokio::fs::read_to_string(peers_file)
            .await
            .context("reading federation peers file")?;
        serde_json::from_str::<Vec<rustgate_federation::config::PeerConfig>>(&data)
            .context("parsing federation peers file")?
    } else {
        Vec::new()
    };

    let (v2_enabled, v2_listen_addr) = if let Some(ref v2_bind) = cli.federation_v2_bind {
        let addr: std::net::SocketAddr = v2_bind
            .parse()
            .context("parsing --federation-v2-bind address")?;
        (true, addr)
    } else {
        (
            false,
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                9001,
            )),
        )
    };

    Ok(rustgate_federation::config::FederationConfig {
        federate_id: cli.federation_id.clone(),
        v1_enabled: true,
        v1_listen_addr: bind_addr,
        v2_enabled,
        v2_listen_addr,
        peers,
        max_hops: cli.federation_max_hops,
        skip_hostname_verify: cli.federation_skip_hostname_verify,
        cert_file: cli.cert.clone().into(),
        key_file: cli.key.clone().into(),
        ca_file: cli.ca.clone().into(),
        store_path: cli.federation_store_path.clone().map(Into::into),
        trust_store_dir: cli.federation_trust_store_dir.clone().map(Into::into),
        circuit_breaker_threshold: cli.federation_circuit_breaker_threshold,
        circuit_breaker_timeout: std::time::Duration::from_secs(
            cli.federation_circuit_breaker_timeout,
        ),
        replay_buffer_capacity: cli.federation_replay_buffer_size,
        replay_buffer_dir: cli.federation_replay_dir.clone(),
        replay_max_bytes: cli.federation_replay_max_bytes,
        pod_id: cli.federation_pod_id.clone().or_else(|| {
            cli.federation_ha_nats_url
                .as_ref()
                .map(|_| cli.federation_id.clone())
        }),
        ha_nats_url: cli.federation_ha_nats_url.clone(),
        local_region: cli.federation_region.clone(),
        max_groups_per_peer: cli.federation_max_groups_per_peer,
        max_group_name_length: cli.federation_max_group_name_length,
        trust_peer_groups: cli.federation_trust_peer_groups,
        ..rustgate_federation::config::FederationConfig::default()
    })
}

/// Wire the federation REST API handler into the metrics HTTP server.
#[cfg(all(feature = "federation", feature = "metrics"))]
fn wire_federation_api(
    cli: &Cli,
    rwlock: &Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
    fed_api_slot: &Arc<std::sync::OnceLock<metrics::FedApiHandler>>,
) -> anyhow::Result<()> {
    use rustgate_federation::api::{ApiState, PeerStatusFn};
    use rustgate_federation::store::file::FileStore;
    use rustgate_federation::trust_store::TrustStore;

    let store = Arc::new(std::sync::RwLock::new(FileStore::new(
        cli.federation_store_path.clone().map(Into::into),
    )));
    let trust_store = Arc::new(if let Some(ref dir) = cli.federation_trust_store_dir {
        TrustStore::load_from_directory(std::path::Path::new(dir))?
    } else {
        TrustStore::new(None)
    });

    let rwlock_for_status = Arc::clone(rwlock);
    let status_fn: Arc<dyn Fn() -> rustgate_federation::manager::FederationStatus + Send + Sync> =
        Arc::new(move || match rwlock_for_status.try_read() {
            Ok(mgr) => mgr.status(),
            Err(_) => rustgate_federation::manager::FederationStatus {
                running: true,
                v1_server_active: false,
                v2_server_active: false,
                total_peers: 0,
                connected_peers: 0,
                peers: vec![],
                ha_enabled: false,
                pod_id: None,
            },
        });

    let rwlock_for_peer = Arc::clone(rwlock);
    let peer_status_fn: PeerStatusFn = Arc::new(move |id| match rwlock_for_peer.try_read() {
        Ok(mgr) => mgr.peer_status(id),
        Err(_) => None,
    });

    let api_state = Arc::new(ApiState {
        store,
        trust_store,
        status_fn,
        peer_status_fn,
    });

    let handler: metrics::FedApiHandler = Arc::new(move |method, path, body| {
        rustgate_federation::api::handle_request(method, path, body, &api_state)
    });

    let _ = fed_api_slot.set(handler);
    tracing::info!("federation REST API wired into metrics server");
    Ok(())
}

/// Spawn HA adoption and claim-lost handler tasks.
#[cfg(feature = "federation-ha")]
async fn setup_ha_handlers(
    rwlock: &Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
) {
    let (adopt_rx, lost_rx) = {
        let mut mgr = rwlock.write().await;
        mgr.take_ha_receivers()
    };

    if let Some(mut rx) = adopt_rx {
        let inner = Arc::clone(rwlock);
        spawn_background("federation-ha-adopt", async move {
            while let Some(peer_id) = rx.recv().await {
                tracing::info!(peer_id = %peer_id, "adopting orphaned peer");
                let mut mgr = inner.write().await;
                if let Err(e) = mgr.adopt_peer(&peer_id).await {
                    tracing::warn!(
                        peer_id = %peer_id,
                        error = %e,
                        "failed to adopt peer"
                    );
                }
            }
        });
    }

    if let Some(mut rx) = lost_rx {
        let inner = Arc::clone(rwlock);
        spawn_background("federation-ha-claim-lost", async move {
            while let Some(peer_id) = rx.recv().await {
                tracing::warn!(
                    peer_id = %peer_id,
                    "lost claim — disconnecting peer"
                );
                let mut mgr = inner.write().await;
                mgr.disconnect_peer(&peer_id).await;
            }
        });
    }
}

/// Start the federation subsystem and return the forwarding callback + shutdown handle.
#[cfg(feature = "federation")]
pub(crate) async fn start_federation(
    cli: &Cli,
    router: &Arc<Router>,
    #[cfg(feature = "metrics")] fed_api_slot: &Arc<std::sync::OnceLock<metrics::FedApiHandler>>,
) -> anyhow::Result<(
    Option<FedForwardFn>,
    Option<Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>>,
)> {
    let v1_bind = match cli.federation_v1_bind.as_ref() {
        Some(b) => b,
        None => return Ok((None, None)),
    };

    let bind_addr: std::net::SocketAddr = v1_bind
        .parse()
        .context("parsing --federation-v1-bind address")?;

    let config = build_federation_config(cli, bind_addr).await?;
    let mut manager = rustgate_federation::manager::FederationManager::new(config);

    // on_inbound: route messages from federation peers to local clients.
    //
    // Security note (issue #719): federated messages are handed to
    // `router.route()`, which re-runs the full PEP chain — Send-PEP with
    // the peer CN as subject, then per-recipient Receive-PEP with each
    // recipient's CN as subject. Obligations returned by the local
    // Receive-PEP are always applied on a per-recipient copy of the
    // envelope, regardless of what the upstream peer did.
    //
    // The V2 wire protocol does NOT carry the upstream peer's obligation
    // list: data-plane obligations (MaskPoint, MaskPayload) are baked
    // into the payload before forwarding, and audit-shaped obligations
    // are not serialized at all. Upstream obligations are therefore
    // advisory only — the local policy is authoritative. This defends
    // against a permissive upstream silently delivering coordinates
    // that the local policy would have masked.
    //
    // See `docs/federation.md` → "Cross-origin authz obligations" and
    // `crates/rustgate-transport/tests/authz_routing.rs`
    // (`federated_broadcast_*`) for the pinned guarantees.
    let router_for_fed = Arc::clone(router);
    let on_inbound: rustgate_federation::manager::OnInbound = Arc::new(move |peer_cn, payload| {
        let router = Arc::clone(&router_for_fed);
        spawn_background("federation-inbound", async move {
            let identity = match Identity::plaintext(peer_cn.clone(), BTreeSet::new()) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(peer_cn = %peer_cn, error = %e, "invalid federation peer identity");
                    return;
                }
            };
            let msg = RoutableMessage {
                source: identity,
                destination: Destination::Broadcast,
                payload,
                metadata: Metadata {
                    received_at: SystemTime::now(),
                    source_protocol: "federation".into(),
                    message_type: rustgate_core::message::MessageType::Other("federation".into()),
                    ttl: None,
                },
            };
            router.route(msg).await;
        });
    });

    manager
        .start(on_inbound)
        .await
        .context("starting federation manager")?;
    tracing::info!(addr = %bind_addr, id = %cli.federation_id, "federation started");

    let rwlock = Arc::new(tokio::sync::RwLock::new(manager));

    #[cfg(feature = "metrics")]
    wire_federation_api(cli, &rwlock, fed_api_slot)?;

    #[cfg(feature = "metrics")]
    {
        // Detached task; runs until process exit. We intentionally drop
        // the JoinHandle here.
        let handle = metrics::spawn_federation_lag_updater(
            Arc::clone(&rwlock),
            std::time::Duration::from_secs(1),
        );
        std::mem::drop(handle);
    }

    #[cfg(feature = "federation-ha")]
    setup_ha_handlers(&rwlock).await;

    let rwlock_for_forward = Arc::clone(&rwlock);
    let forward_fn: FedForwardFn = Arc::new(move |payload, groups, metadata| {
        let inner = Arc::clone(&rwlock_for_forward);
        spawn_background("federation-forward", async move {
            let mgr = inner.read().await;
            let _ = mgr
                .forward_with_metadata(payload, &groups, Some(&metadata))
                .await;
        });
    });

    Ok((Some(forward_fn), Some(rwlock)))
}

/// Warn when federation features are requested without the feature flags.
#[cfg(not(feature = "federation"))]
pub(crate) fn warn_federation_disabled(cli: &Cli) -> Option<FedForwardFn> {
    if cli.federation_v1_bind.is_some() {
        tracing::warn!("--federation-v1-bind requires --features federation; ignoring");
    }
    if cli.federation_v2_bind.is_some() {
        tracing::warn!("--federation-v2-bind requires --features federation; ignoring");
    }
    None
}

/// Spawn the federation peer discovery reconciler (issue #571).
///
/// Inspects `--federation-peer-discovery`; when set to a backend other than
/// `none`, constructs the corresponding `PeerDiscovery` implementation and
/// hands it to `rustgate_federation::discovery::reconciler` together with a
/// shutdown watch channel. Returns the shutdown sender so the main loop can
/// signal the reconciler to exit during graceful shutdown; returns `None`
/// when discovery is disabled.
///
/// Each backend's code path is gated behind its own sub-feature; selecting
/// a backend whose feature was not compiled in surfaces a clear
/// `anyhow::bail!` so misconfigured images fail fast at startup instead of
/// silently ignoring the setting.
#[cfg(feature = "federation")]
pub(crate) fn start_federation_peer_discovery(
    cli: &Cli,
    manager: &Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
) -> anyhow::Result<Option<tokio::sync::watch::Sender<bool>>> {
    use crate::cli::PeerDiscoveryBackend;

    if cli.federation_peer_discovery == PeerDiscoveryBackend::None {
        return Ok(None);
    }

    #[cfg(any(
        feature = "peer-discovery-dns-sd",
        feature = "peer-discovery-consul",
        feature = "peer-discovery-etcd"
    ))]
    {
        use rustgate_federation::discovery::PeerDiscovery;

        let source: Arc<dyn PeerDiscovery> = match cli.federation_peer_discovery {
            PeerDiscoveryBackend::None => {
                anyhow::bail!("peer discovery backend is None (should have been handled above)");
            }
            #[cfg(feature = "peer-discovery-dns-sd")]
            PeerDiscoveryBackend::DnsSd => {
                let svc = cli.federation_peer_discovery_dns_sd_service.clone();
                Arc::new(rustgate_federation::discovery::dns_sd::DnsSdDiscovery::new(
                    svc,
                )?)
            }
            #[cfg(not(feature = "peer-discovery-dns-sd"))]
            PeerDiscoveryBackend::DnsSd => {
                anyhow::bail!(
                    "--federation-peer-discovery=dns-sd requires --features peer-discovery-dns-sd"
                );
            }
            #[cfg(feature = "peer-discovery-consul")]
            PeerDiscoveryBackend::Consul => Arc::new(
                rustgate_federation::discovery::consul::ConsulDiscovery::new(
                    cli.federation_peer_discovery_consul_addr.clone(),
                    cli.federation_peer_discovery_consul_service.clone(),
                )?,
            ),
            #[cfg(not(feature = "peer-discovery-consul"))]
            PeerDiscoveryBackend::Consul => {
                anyhow::bail!(
                    "--federation-peer-discovery=consul requires --features peer-discovery-consul"
                );
            }
            #[cfg(feature = "peer-discovery-etcd")]
            PeerDiscoveryBackend::Etcd => {
                let endpoints: Vec<String> = cli
                    .federation_peer_discovery_etcd_endpoints
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if endpoints.is_empty() {
                    anyhow::bail!(
                        "--federation-peer-discovery-etcd-endpoints must contain at least one endpoint"
                    );
                }
                Arc::new(rustgate_federation::discovery::etcd::EtcdDiscovery::new(
                    endpoints,
                    cli.federation_peer_discovery_etcd_prefix.clone(),
                ))
            }
            #[cfg(not(feature = "peer-discovery-etcd"))]
            PeerDiscoveryBackend::Etcd => {
                anyhow::bail!(
                    "--federation-peer-discovery=etcd requires --features peer-discovery-etcd"
                );
            }
        };

        let interval = std::time::Duration::from_secs(cli.federation_peer_discovery_interval);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = rustgate_federation::discovery::reconciler(
            Arc::clone(manager),
            source,
            interval,
            shutdown_rx,
        );
        // Detached: the task owns itself until its shutdown receiver fires.
        std::mem::drop(handle);
        tracing::info!(
            backend = ?cli.federation_peer_discovery,
            interval_secs = cli.federation_peer_discovery_interval,
            "federation peer discovery reconciler started"
        );
        Ok(Some(shutdown_tx))
    }

    #[cfg(not(any(
        feature = "peer-discovery-dns-sd",
        feature = "peer-discovery-consul",
        feature = "peer-discovery-etcd"
    )))]
    {
        let _ = manager;
        anyhow::bail!(
            "--federation-peer-discovery requires one of --features peer-discovery, peer-discovery-dns-sd, peer-discovery-consul, peer-discovery-etcd"
        );
    }
}

/// Warn when peer-discovery flags are set but federation itself is disabled.
#[cfg(not(feature = "federation"))]
pub(crate) fn warn_federation_peer_discovery_disabled(cli: &Cli) {
    use crate::cli::PeerDiscoveryBackend;
    if cli.federation_peer_discovery != PeerDiscoveryBackend::None {
        tracing::warn!("--federation-peer-discovery requires --features federation; ignoring");
    }
}

/// Warn when federation-ha is requested without the feature.
#[cfg(not(feature = "federation-ha"))]
pub(crate) fn warn_federation_ha_disabled(cli: &Cli) {
    if cli.federation_ha_nats_url.is_some() {
        tracing::warn!("--federation-ha-nats-url requires --features federation-ha; ignoring");
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/// Configuration for starting the WebSocket listener.
#[cfg(feature = "websocket")]
pub(crate) struct WebSocketSetup<'a, P: NatsPublish> {
    pub(crate) cli: &'a Cli,
    pub(crate) tls_config: &'a TlsConfig,
    pub(crate) router: &'a Arc<Router>,
    pub(crate) connection_limit: &'a Arc<Semaphore>,
    pub(crate) codec: &'a Arc<dyn rustgate_core::codec::Codec>,
    pub(crate) nats_publisher: &'a Option<P>,
    pub(crate) fed_forward: &'a Option<FedForwardFn>,
    #[cfg(feature = "http")]
    pub(crate) http_forward: &'a Option<HttpForwardFn>,
    pub(crate) throttle_config: Option<ThrottleConfig>,
    pub(crate) replay_filter: &'a Option<Arc<rustgate_transport::ReplayFilter>>,
}

/// Start the WebSocket listener and return its subsystem handle.
#[cfg(feature = "websocket")]
pub(crate) fn start_websocket<P: NatsPublish + Send + Sync + 'static>(
    setup: WebSocketSetup<'_, P>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let WebSocketSetup {
        cli,
        tls_config,
        router,
        connection_limit,
        codec,
        nats_publisher,
        fed_forward,
        #[cfg(feature = "http")]
        http_forward,
        throttle_config,
        replay_filter,
    } = setup;
    let ws_bind = match cli.websocket_bind.as_ref() {
        Some(b) => b,
        None => return Ok(None),
    };

    let addr: std::net::SocketAddr = ws_bind
        .parse()
        .context("parsing --websocket-bind address")?;
    let ws_config = rustgate_websocket::WsListenerConfig {
        conn_rate_limit: cli.ws_conn_rate_limit,
        conn_rate_window: std::time::Duration::from_secs(cli.ws_conn_rate_window_secs),
        max_frame_size: cli.ws_max_frame_size,
        max_message_size: cli.ws_max_message_size,
    };
    let ws_listener =
        rustgate_websocket::WsListener::bind_with_config(addr, tls_config, ws_config)?;
    tracing::info!(addr = %ws_listener.local_addr()?, "WebSocket listener bound");

    let shutdown = Arc::new(tokio::sync::Notify::new());

    let nats_cb: Option<rustgate_websocket::OnNatsPublish> = {
        #[cfg(feature = "nats")]
        {
            nats_publisher
                .clone()
                .map(|p| -> rustgate_websocket::OnNatsPublish {
                    Arc::new(move |msg| {
                        let p = p.clone();
                        spawn_background("ws-nats-publish", async move {
                            p.publish(&msg).await;
                        });
                    })
                })
        }
        #[cfg(not(feature = "nats"))]
        {
            let _ = nats_publisher;
            None
        }
    };

    let config = rustgate_websocket::WsServerConfig {
        listener: ws_listener,
        router: Arc::clone(router),
        connection_limit: Arc::clone(connection_limit),
        codec: Arc::clone(codec),
        nats_publish: nats_cb,
        fed_forward: fed_forward.clone(),
        http_forward: {
            #[cfg(feature = "http")]
            {
                http_forward
                    .clone()
                    .map(|fwd| -> rustgate_websocket::OnHttpForward { fwd })
            }
            #[cfg(not(feature = "http"))]
            {
                None
            }
        },
        throttle_config,
        replay_filter: replay_filter.clone(),
        circuit_breaker_threshold: cli.circuit_breaker_threshold,
        ws_max_frames_per_sec: cli.ws_max_frames_per_sec,
        ws_max_bytes_per_sec: cli.ws_max_bytes_per_sec,
        ws_max_violations: cli.ws_max_violations,
        max_write_buffer_bytes: cli.ws_max_write_buffer_bytes,
        health_check: rustgate_websocket::health::HealthCheckConfig {
            ping_interval: std::time::Duration::from_secs(cli.ws_ping_interval_secs),
            pong_timeout: std::time::Duration::from_secs(cli.ws_pong_timeout_secs),
        },
        shutdown: Arc::clone(&shutdown),
    };
    let task = tokio::spawn(async move {
        rustgate_websocket::WebSocketServer::run(config).await;
    });
    Ok(Some(SubsystemHandle::new(shutdown, task)))
}

/// Warn when websocket is requested without the feature.
#[cfg(not(feature = "websocket"))]
pub(crate) fn warn_websocket_disabled(cli: &Cli) {
    if cli.websocket_bind.is_some() {
        tracing::warn!("--websocket-bind requires --features websocket; ignoring");
    }
}

// ---------------------------------------------------------------------------
// MQTT
// ---------------------------------------------------------------------------

/// Start the MQTT listener and return its subsystem handle.
#[cfg(feature = "mqtt")]
pub(crate) fn start_mqtt(
    cli: &Cli,
    tls_config: &TlsConfig,
    router: &Arc<Router>,
    connection_limit: &Arc<Semaphore>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let mqtt_bind = match cli.mqtt_bind.as_ref() {
        Some(b) => b,
        None => return Ok(None),
    };

    if let Some(prefix) = cli.mqtt_topic_prefix.as_deref() {
        rustgate_mqtt::validate_topic_prefix(prefix)
            .map_err(|e| anyhow::anyhow!("invalid --mqtt-topic-prefix: {e}"))?;
    }

    let addr: std::net::SocketAddr = mqtt_bind.parse().context("parsing --mqtt-bind address")?;
    let mqtt_listener = rustgate_mqtt::MqttListener::bind(addr, tls_config)?;
    tracing::info!(addr = %mqtt_listener.local_addr()?, "MQTT listener bound");

    let shutdown = Arc::new(tokio::sync::Notify::new());

    let config = rustgate_mqtt::MqttServerConfig {
        listener: mqtt_listener,
        router: Arc::clone(router),
        connection_limit: Arc::clone(connection_limit),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: cli.mqtt_topic_prefix.clone(),
        max_packet_size: cli.mqtt_max_packet_size,
        min_keep_alive_secs: cli.mqtt_min_keep_alive_secs,
        response_channel_capacity: cli.mqtt_response_channel_capacity,
        wildcard_policy: cli.mqtt_wildcard_policy.into(),
    };
    let task = tokio::spawn(async move {
        rustgate_mqtt::MqttServer::run(config).await;
    });
    Ok(Some(SubsystemHandle::new(shutdown, task)))
}

/// Warn when MQTT is requested without the feature.
#[cfg(not(feature = "mqtt"))]
pub(crate) fn warn_mqtt_disabled(cli: &Cli) {
    if cli.mqtt_bind.is_some() {
        tracing::warn!("--mqtt-bind requires --features mqtt; ignoring");
    }
}

// ---------------------------------------------------------------------------
// Plaintext TCP
// ---------------------------------------------------------------------------

/// Start the plaintext TCP listener and return its subsystem handle.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_plaintext_tcp<P: NatsPublish + Send + Sync + 'static>(
    cli: &Cli,
    router: &Arc<Router>,
    connection_limit: &Arc<Semaphore>,
    codec: &Arc<dyn rustgate_core::codec::Codec>,
    nats_publisher: &Option<P>,
    fed_forward: &Option<FedForwardFn>,
    #[cfg(feature = "http")] http_forward: &Option<HttpForwardFn>,
    throttle_config: Option<ThrottleConfig>,
    archiver: &Option<Arc<crate::archive::CotArchiver>>,
    replay_filter: &Option<Arc<rustgate_transport::ReplayFilter>>,
    #[cfg(feature = "metrics")] metrics_identity: &Arc<metrics::MetricsIdentity>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let tcp_bind = match cli.tcp_bind.as_ref() {
        Some(b) => b,
        None => return Ok(None),
    };

    let addr: std::net::SocketAddr = tcp_bind.parse().context("parsing --tcp-bind address")?;

    tracing::warn!(addr = %addr, "plaintext TCP input enabled — traffic is NOT encrypted");

    let identity_config = rustgate_transport::PlaintextIdentityConfig {
        cn: cli.plaintext_cn.clone(),
        default_group: cli.plaintext_group.clone(),
    };

    let pt_listener = rustgate_transport::PlaintextListener::bind(addr, identity_config)
        .await
        .context("binding plaintext TCP listener")?;

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);

    #[allow(clippy::clone_on_copy)]
    let pt_nats = nats_publisher.clone();
    let config = PlaintextTcpConfig {
        listener: pt_listener,
        router: Arc::clone(router),
        connection_limit: Arc::clone(connection_limit),
        codec: Arc::clone(codec),
        nats_publisher: pt_nats,
        fed_forward: fed_forward.clone(),
        #[cfg(feature = "http")]
        http_forward: http_forward.clone(),
        throttle_config,
        archiver: archiver.clone(),
        replay_filter: replay_filter.clone(),
        circuit_breaker_threshold: cli.circuit_breaker_threshold,
        delta_config: crate::session::DeltaConfig {
            enabled: cli.cot_delta_encoding,
            cache_size: cli.cot_delta_cache_size,
            epsilon_meters: cli.cot_delta_epsilon_meters,
        },
        shutdown: shutdown_clone,
        #[cfg(feature = "metrics")]
        metrics_identity: Arc::clone(metrics_identity),
    };

    let task = tokio::spawn(async move {
        crate::session::run_plaintext_tcp(config).await;
    });

    Ok(Some(SubsystemHandle::new(shutdown, task)))
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// Start the UDP input listener and return its subsystem handle.
pub(crate) async fn start_udp<P: NatsPublish + Send + Sync + 'static>(
    cli: &Cli,
    router: &Arc<Router>,
    nats_publisher: &Option<P>,
    fed_forward: &Option<FedForwardFn>,
    replay_filter: &Option<Arc<rustgate_transport::ReplayFilter>>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let udp_bind = match cli.udp_bind.as_ref() {
        Some(b) => b,
        None => return Ok(None),
    };

    let addr: std::net::SocketAddr = udp_bind.parse().context("parsing --udp-bind address")?;

    tracing::warn!(addr = %addr, "UDP input enabled — datagrams are NOT encrypted");

    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .context("binding UDP socket")?;

    let mut config = rustgate_transport::UdpInputConfig {
        cn: cli.plaintext_cn.clone(),
        default_group: cli.plaintext_group.clone(),
        ..Default::default()
    };

    // Apply CLI rate-limit flag (0 = disabled).
    if cli.udp_rate_limit > 0 {
        config.max_pps = Some(cli.udp_rate_limit as usize);
    }

    // Parse and apply CIDR allowlist from comma-separated string.
    if let Some(ref cidrs_str) = cli.udp_allowed_cidrs {
        let mut cidrs = Vec::new();
        for entry in cidrs_str.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cidr: rustgate_transport::CidrPrefix = trimmed.parse().map_err(|e| {
                anyhow::anyhow!("invalid --udp-allowed-cidrs entry '{trimmed}': {e}")
            })?;
            cidrs.push(cidr);
        }
        if !cidrs.is_empty() {
            config.allowed_cidrs = Some(cidrs);
        }
    }

    config.max_identities = cli.udp_max_identities;

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let udp_router = Arc::clone(router);

    let udp_nats_cb: Option<rustgate_transport::udp::OnNatsPublish> = {
        #[cfg(feature = "nats")]
        {
            nats_publisher
                .clone()
                .map(|p| -> rustgate_transport::udp::OnNatsPublish {
                    Arc::new(move |msg| {
                        let p = p.clone();
                        spawn_background("udp-nats-publish", async move {
                            p.publish(&msg).await;
                        });
                    })
                })
        }
        #[cfg(not(feature = "nats"))]
        {
            let _ = nats_publisher;
            None
        }
    };

    let udp_fed: Option<rustgate_transport::udp::OnFederationForward> =
        fed_forward
            .clone()
            .map(|fwd| -> rustgate_transport::udp::OnFederationForward {
                Arc::new(move |payload, groups, metadata| {
                    fwd(payload, groups, metadata);
                })
            });

    let udp_replay = replay_filter.clone();
    let task = tokio::spawn(async move {
        rustgate_transport::UdpInput::run(
            socket,
            udp_router,
            config,
            udp_nats_cb,
            udp_fed,
            udp_replay,
            shutdown_clone,
        )
        .await;
    });

    Ok(Some(SubsystemHandle::new(shutdown, task)))
}
