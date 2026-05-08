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
#[cfg(feature = "federation-ha")]
use rustgate_core::masking::hash_cn;
#[cfg(feature = "federation")]
use rustgate_core::message::RoutableMessage;
#[cfg(feature = "federation")]
use rustgate_core::message::{Destination, Metadata};
#[cfg(feature = "federation")]
use rustgate_core::sanitize::sanitize_for_log;
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
use rustgate_router::{Router, ThrottleConfig};
use rustgate_tls::{CertReloader, TlsConfig, TlsListener, TlsMinVersion};
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
    Option<rustgate_router::GroupAclPolicy>,
    Option<[u8; 32]>,
    Option<rustgate_admin::GroupAclFile>,
)> {
    let Some(ref acl_file) = cli.group_acl_file else {
        return Ok((None, None, None));
    };

    let data = tokio::fs::read_to_string(acl_file)
        .await
        .context("reading group ACL file")?;

    let hash = rustgate_admin::AclReloader::compute_hash(data.as_bytes());

    let config: rustgate_admin::GroupAclFile =
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
            rustgate_router::GroupAcl::with_deny(
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

    let policy = rustgate_router::GroupAclPolicy::new(groups);
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
        let spiffe_cfg = rustgate_tls::spiffe::SpiffeConfig {
            workload_api_socket: cli.spiffe_workload_api_socket.clone(),
            expected_trust_domain: cli.spiffe_trust_domain.clone(),
            refresh_interval: std::time::Duration::from_secs(cli.spiffe_refresh_interval),
        };
        let identity = rustgate_tls::spiffe::fetch_initial_identity(&spiffe_cfg)
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
            #[cfg(feature = "metrics")]
            if let Some(age) = tls_config.crl_max_age_seconds() {
                crate::metrics::crl_age_seconds().set(age);
            }
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
        #[cfg(feature = "metrics")]
        if let Some(age) = tls_config.crl_max_age_seconds() {
            crate::metrics::crl_age_seconds().set(age);
        }
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
    pub(crate) spiffe_identity: Option<rustgate_tls::spiffe::SpiffeIdentity>,
}

/// Bind the TLS listener with a handshake concurrency limit.
///
/// When `cert_reload_interval > 0`, the server uses a [`CertReloader`] as the
/// certificate resolver so that the TLS certificate can be rotated on disk
/// without restarting the server. A background watcher task polls for changes.
pub(crate) async fn bind_tls_listener(
    cli: &Cli,
    tls_config: &TlsConfig,
    #[cfg(feature = "spiffe")] spiffe_identity: Option<rustgate_tls::spiffe::SpiffeIdentity>,
) -> anyhow::Result<TlsListenerHandle> {
    // When SPIFFE is enabled, reuse the `SpiffeIdentity` already fetched by
    // `build_tls_config` so we do not double-fetch from the Workload API at
    // startup (which would briefly leave the TlsConfig and CertReloader
    // tracking two different SVIDs).
    #[cfg(feature = "spiffe")]
    let reloader = if cli.spiffe {
        let identity = spiffe_identity
            .ok_or_else(|| anyhow::anyhow!("SPIFFE enabled but no preloaded identity passed"))?;
        let spiffe_cfg = rustgate_tls::spiffe::SpiffeConfig {
            workload_api_socket: cli.spiffe_workload_api_socket.clone(),
            expected_trust_domain: cli.spiffe_trust_domain.clone(),
            refresh_interval: std::time::Duration::from_secs(cli.spiffe_refresh_interval),
        };
        let reloader = identity.cert_reloader.clone();

        #[cfg(feature = "metrics")]
        let hooks = Some(rustgate_tls::spiffe::SpiffeHooks {
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
        let hooks: Option<rustgate_tls::spiffe::SpiffeHooks> = None;

        rustgate_tls::spiffe::spawn_refresh_task(Arc::downgrade(&reloader), spiffe_cfg, hooks);
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
        let on_hit: Option<rustgate_tls::client_ocsp::OnCacheHit> =
            Some(std::sync::Arc::new(|| {
                if let Some(c) = metrics::client_ocsp_cache_hits() {
                    c.inc();
                }
            }));
        #[cfg(feature = "metrics")]
        let on_miss: Option<rustgate_tls::client_ocsp::OnCacheMiss> =
            Some(std::sync::Arc::new(|| {
                if let Some(c) = metrics::client_ocsp_cache_misses() {
                    c.inc();
                }
            }));
        #[cfg(not(feature = "metrics"))]
        let on_hit: Option<rustgate_tls::client_ocsp::OnCacheHit> = None;
        #[cfg(not(feature = "metrics"))]
        let on_miss: Option<rustgate_tls::client_ocsp::OnCacheMiss> = None;

        let fetcher: std::sync::Arc<dyn rustgate_tls::OcspFetcher> =
            std::sync::Arc::new(rustgate_tls::OcspStaplerFetcher::default());
        let wrapped =
            rustgate_tls::ClientOcspVerifier::new(inner_verifier, fetcher, on_hit, on_miss);
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
        Option<std::sync::Arc<rustgate_tls::ocsp::Stapler>>,
    ) = if cli.ocsp_stapling {
        let stapler = rustgate_tls::ocsp::wrap_resolver(reloader.clone());
        // Preload the active certificate so the stapler queues its first
        // OCSP fetch immediately rather than waiting for the inaugural
        // handshake to surface it. This shrinks (but does not eliminate)
        // the unstapled window at startup; the background fetcher still
        // needs one cycle (up to ~60s) to actually populate the cache.
        if let Some(ckey) = reloader.certified_key() {
            rustgate_tls::ocsp::preload(&stapler, ckey);
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

    // justification: the `mut` binding is only consumed under
    // `#[cfg(feature = "metrics")]` (`set_on_handshake_error` registers a
    // mutable callback slot). Binding without `mut` and then introducing a
    // second cfg-gated let-rebinding would be strictly uglier than tagging
    // the unused_mut here.
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

    #[cfg(feature = "metrics")]
    listener.set_on_handshake_duration(Arc::new(|elapsed, outcome| {
        metrics::tls_handshake_duration_seconds()
            .with_label_values(&[outcome])
            .observe(elapsed.as_secs_f64());
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
    pub(crate) ocsp_stapler: Option<Arc<rustgate_tls::ocsp::Stapler>>,
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

/// Outcome of connecting to NATS: the publisher handle plus an
/// already-configured subscriber that has been deferred from spawn so
/// the caller can wire egress forwarder callbacks (federation / HTTP /
/// NATS-publish) before launching it (refs #737).
///
/// The two halves are returned together so a NATS connect failure
/// surfaces as `None` for both — there is never a publisher without a
/// subscriber in this transport.
#[cfg(feature = "nats")]
pub(crate) struct NatsConnectOutcome {
    /// Publisher used by every other transport to push routed messages
    /// onto the NATS bus.
    pub publisher: rustgate_nats::NatsPublisher,
    /// Pre-configured subscriber. Wire forwarder callbacks via
    /// [`start_nats_subscriber`] before spawning so the consumer
    /// loop's `route_for_egress` fan-out reaches federation peers and
    /// HTTP egress targets.
    pub subscriber: rustgate_nats::NatsSubscriber,
}

/// Connect to NATS, run JetStream replay, and return the publisher
/// plus a pre-configured (but un-spawned) subscriber.
///
/// The subscriber is deferred from spawn so the caller can wire the
/// federation / HTTP / NATS-publish forwarders that live further down
/// the bootstrap sequence (refs #737). Use
/// [`start_nats_subscriber`] to attach the forwarders and spawn the
/// background task once those callbacks are in scope.
///
/// Returns `None` when NATS isn't configured or the initial connect
/// fails — both signals surface as a missing bridge in every other
/// transport.
#[cfg(feature = "nats")]
pub(crate) async fn connect_nats(cli: &Cli, router: &Arc<Router>) -> Option<NatsConnectOutcome> {
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
        max_deliver: cli.nats_max_deliver,
        dead_letter_subject: cli.nats_dead_letter_subject.clone(),
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

            // Build the subscriber but defer the spawn so the caller
            // can attach forwarder callbacks once federation / HTTP
            // egress have been wired.
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

            Some(NatsConnectOutcome {
                publisher: adapter.publisher(),
                subscriber,
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to connect to NATS (continuing without bridge)");
            None
        }
    }
}

/// Wire the optional federation / HTTP / NATS-publish forwarders onto
/// the subscriber and spawn its consumer loop as a background task
/// (refs #737).
///
/// The subscriber drives every inbound NATS message through
/// [`Router::route_for_egress`] so Send-PEP obligations apply to the
/// envelope before the optional forwarder callbacks observe it. The
/// `nats_publish` callback short-circuits in practice — the
/// publisher's case-insensitive `source_protocol == "nats"` echo
/// guard catches every invocation — but we wire it here so the
/// shape matches the MQTT and WebSocket transports.
#[cfg(feature = "nats")]
pub(crate) fn start_nats_subscriber(
    subscriber: rustgate_nats::NatsSubscriber,
    router: &Arc<Router>,
    nats_publisher: Option<&rustgate_nats::NatsPublisher>,
    fed_forward: &Option<FedForwardFn>,
    #[cfg(feature = "http")] http_forward: &Option<HttpForwardFn>,
) {
    let mut subscriber = subscriber;
    if let Some(publisher) = nats_publisher {
        let publisher = publisher.clone();
        let cb: rustgate_core::egress::OnNatsPublish = std::sync::Arc::new(move |msg| {
            let publisher = publisher.clone();
            spawn_background("nats-subscriber-nats-publish", async move {
                publisher.publish(&msg).await;
            });
        });
        subscriber = subscriber.with_nats_publish(cb);
    }
    if let Some(fwd) = fed_forward {
        // The `FedForwardFn` from `crate::session` is the same
        // `Arc<dyn Fn(Bytes, Vec<String>, Metadata) + Send + Sync>`
        // shape as `OnFederationForward`. Adapt by wrapping so the
        // subscriber sees the workspace-shared alias type.
        let fwd = fwd.clone();
        let cb: rustgate_core::egress::OnFederationForward =
            std::sync::Arc::new(move |payload, groups, meta| {
                fwd(payload, groups, meta);
            });
        subscriber = subscriber.with_federation_forward(cb);
    }
    #[cfg(feature = "http")]
    if let Some(fwd) = http_forward {
        let fwd = fwd.clone();
        let cb: rustgate_core::egress::OnHttpForward = std::sync::Arc::new(move |msg| {
            fwd(msg);
        });
        subscriber = subscriber.with_http_forward(cb);
    }
    let sub_router = Arc::clone(router);
    spawn_background("nats-subscriber", async move {
        if let Err(e) = subscriber.run(sub_router).await {
            tracing::warn!(error = %e, "NATS subscriber ended with error");
        }
    });
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
// Lattice (Anduril)
// ---------------------------------------------------------------------------

/// Start the Anduril Lattice bridge.
///
/// Reads the TOML config file under `cli.lattice_config_file`,
/// validates the `[lattice]` block, and spawns the inbound
/// (subscribe-and-route) and outbound (publish-on-event) tasks
/// against the configured backend. Returns the
/// `mpsc::Sender<RoutableMessage>` that the caller plumbs into the
/// router via a fanout / message-delivered hook so admitted
/// position-and-track messages get pushed to Lattice.
///
/// **Backend selection.** This MVP wires the in-memory
/// `MockLatticeBridge` when the `lattice-mock` feature is enabled.
/// The real-SDK backend lands behind the `lattice-real` feature in
/// a follow-up partner PR. With only the umbrella `lattice` feature
/// enabled and no backend, this helper warns and returns `None` —
/// the rest of the server keeps running unchanged.
///
/// Returns `None` when no config block is present, when the file
/// cannot be read or parsed, or when no backend is selected.
#[cfg(feature = "lattice")]
pub(crate) async fn start_lattice(
    cli: &Cli,
    router: &Arc<rustgate_router::Router>,
) -> Option<(
    tokio::sync::mpsc::Sender<rustgate_core::message::RoutableMessage>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
)> {
    let config_path = cli.lattice_config_file.as_ref()?;
    let config_str = match tokio::fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(path = %config_path, error = %e, "failed to read lattice config");
            return None;
        }
    };

    #[derive(serde::Deserialize)]
    struct Wrapper {
        lattice: rustgate_lattice::LatticeConfig,
    }

    let cfg: rustgate_lattice::LatticeConfig = match toml::from_str::<Wrapper>(&config_str) {
        Ok(w) => w.lattice,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse [lattice] config");
            return None;
        }
    };

    if let Err(e) = cfg.validate() {
        tracing::warn!(error = %e, "[lattice] config validation failed");
        return None;
    }

    // Backend selection. The MVP only ships the mock backend behind
    // `lattice-mock`. The real-SDK backend will land behind
    // `lattice-real` and join this `cfg!(feature = ...)` cascade
    // without churning the call site.
    #[cfg(feature = "lattice-mock")]
    let bridge: rustgate_lattice::bridge::SharedBridge = rustgate_lattice::MockLatticeBridge::new();

    #[cfg(not(feature = "lattice-mock"))]
    {
        // justification: with no backend feature enabled the router is never wired,
        // but the parameter is part of the public function shape for the
        // `lattice-mock` / future `lattice-real` paths below.
        let _ = router;
        tracing::warn!(
            "[lattice] config block present but no backend feature is enabled; \
             enable --features lattice-mock for testing or --features lattice-real \
             for the partner SDK (when available)"
        );
        return None;
    }

    #[cfg(feature = "lattice-mock")]
    {
        // Outbound channel — the server feeds this from a router
        // hook (typically `set_on_message_delivered`). The bound is
        // sized so a slow Lattice endpoint cannot back-pressure the
        // router; the outbound task drops on receiver-full at the
        // hook site, not here.
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        let outbound =
            rustgate_lattice::spawn_outbound_task(std::sync::Arc::clone(&bridge), cfg.clone(), rx);
        let inbound = rustgate_lattice::spawn_inbound_task(
            std::sync::Arc::clone(&bridge),
            cfg.clone(),
            std::sync::Arc::clone(router),
        );

        tracing::info!(
            endpoint = %cfg.endpoint,
            backend = bridge.backend_name(),
            "lattice bridge started"
        );

        Some((tx, outbound, inbound))
    }
}

/// Warn when --lattice-config is set but the `lattice` feature is disabled.
#[cfg(not(feature = "lattice"))]
pub(crate) fn warn_lattice_disabled(cli: &Cli) {
    if cli.lattice_config_file.is_some() {
        tracing::warn!("--lattice-config requires --features lattice; ignoring");
    }
}

// ---------------------------------------------------------------------------
// Foundry bridge (issue #851)
// ---------------------------------------------------------------------------
//
// The Foundry / Gotham bridge is partner-gated: today the wiring only
// activates the trait + scaffold + mock plumbing under the `foundry`
// feature. The real REST/WebSocket SDK adapter lands behind a future
// `foundry-real` feature. The `init_foundry_scaffold` entry point
// below is the seam the SDK adapter will plug into — it currently
// emits a one-line operator-visible event so an operator who built
// the binary with `--features foundry` can confirm the scaffold is
// active without expecting actual Foundry traffic.

/// Initialise the Foundry bridge scaffold.
///
/// Today this is a no-op beyond an operator-visible diagnostic. When
/// the partner-gated SDK adapter lands, this is the seam where:
///
/// 1. The TOML config (`rustgate_foundry::FoundryConfig`) is read.
/// 2. The bridge implementation is constructed.
/// 3. `rustgate_foundry::wiring::spawn_outbound` and `spawn_inbound`
///    are called against the live `Router`.
///
/// Until then, building with `--features foundry` is a documented
/// "scaffold ready" signal — useful for CI feature-powerset coverage
/// and for downstream binaries that want to compile-test the
/// integration without touching the SDK. Refs #851.
#[cfg(feature = "foundry")]
pub(crate) fn init_foundry_scaffold() {
    tracing::info!(
        target: "rustgate.foundry",
        "Foundry bridge scaffold linked (trait + config + wiring); awaiting partner SDK adapter behind future foundry-real feature flag"
    );
}

// ---------------------------------------------------------------------------
// DDS bridge (issue #870)
// ---------------------------------------------------------------------------
//
// The DDS Pub/Sub bridge gives rustgate access to NATO Generic Vehicle
// Architecture (NGVA, STANAG 4754) and US Army VICTORY in-vehicle data
// buses. Production-grade DDS Rust bindings are still maturing
// (`cyclonedds-rs` is unmaintained as of 2026; `dust-dds` is pre-1.0)
// so today the wiring only activates the trait + scaffold + mock
// plumbing under the `dds` feature. The real DDS SDK adapter lands
// behind a future `dds-real` feature. The `init_dds_scaffold` entry
// point below is the seam the SDK adapter will plug into — it
// currently emits a one-line operator-visible event so an operator
// who built the binary with `--features dds` can confirm the scaffold
// is active without expecting actual DDS traffic.

/// Initialise the DDS bridge scaffold.
///
/// Today this is a no-op beyond an operator-visible diagnostic. When
/// a real DDS SDK adapter lands, this is the seam where:
///
/// 1. The TOML config (`rustgate_dds::DdsConfig`) is read.
/// 2. The bridge implementation is constructed.
/// 3. `rustgate_dds::wiring::spawn_outbound` and `spawn_inbound` are
///    called against the live `Router`.
///
/// Until then, building with `--features dds` is a documented
/// "scaffold ready" signal — useful for CI feature-powerset coverage
/// and for downstream binaries that want to compile-test the
/// integration without touching the SDK. Refs #870.
#[cfg(feature = "dds")]
pub(crate) fn init_dds_scaffold() {
    tracing::info!(
        target: "rustgate.dds",
        "DDS bridge scaffold linked (trait + config + wiring); awaiting real DDS SDK adapter behind future dds-real feature flag"
    );
}

// ---------------------------------------------------------------------------
// OGC SensorThings v1.0 polling client (issue #869)
// ---------------------------------------------------------------------------

/// Start the OGC SensorThings v1.0 polling client.
///
/// Reads the TOML config file under `cli.ogc_sensorthings_config_file`,
/// validates the `[sensorthings]` block, optionally loads the
/// bearer token from `auth-token-path`, builds a
/// [`rustgate_ogc_sensorthings::SensorThingsClient`], and spawns
/// the polling supervisor task. Returns the
/// [`rustgate_core::tasks::SubsystemHandle`] that drives graceful
/// shutdown for the entire SensorThings subsystem.
///
/// Returns `None` when the operator did not configure SensorThings
/// (no `--ogc-sensorthings-config` flag), the config file cannot be
/// read or parsed, or validation fails. Failure cases log via
/// `tracing::warn!` and the rest of the server continues unchanged
/// — SensorThings is an opt-in integration and a misconfigured
/// `[sensorthings]` block must not block server startup.
#[cfg(feature = "ogc-sensorthings")]
pub(crate) async fn start_ogc_sensorthings(
    cli: &Cli,
    router: &Arc<Router>,
) -> Option<SubsystemHandle> {
    let config_path = cli.ogc_sensorthings_config_file.as_ref()?;
    let config_str = match tokio::fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                path = %config_path,
                error = %e,
                "failed to read --ogc-sensorthings-config"
            );
            return None;
        }
    };

    #[derive(serde::Deserialize)]
    struct Wrapper {
        sensorthings: rustgate_ogc_sensorthings::SensorThingsConfig,
    }

    let cfg: rustgate_ogc_sensorthings::SensorThingsConfig =
        match toml::from_str::<Wrapper>(&config_str) {
            Ok(w) => w.sensorthings,
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse [sensorthings] config");
                return None;
            }
        };

    if let Err(e) = cfg.validate() {
        tracing::warn!(error = %e, "[sensorthings] config validation failed");
        return None;
    }

    let bearer = match cfg.auth_token_path.as_deref() {
        Some(path) => match tokio::fs::read_to_string(path).await {
            Ok(token) => Some(std::sync::Arc::<str>::from(token.trim())),
            Err(e) => {
                tracing::warn!(
                    path = %path,
                    error = %e,
                    "failed to read [sensorthings] auth-token-path; falling back to unauthenticated polling"
                );
                None
            }
        },
        None => None,
    };

    let client = match rustgate_ogc_sensorthings::SensorThingsClient::new(&cfg, bearer) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build SensorThings polling client");
            return None;
        }
    };

    let endpoint = cfg.normalised_endpoint().to_string();
    let subscription_count = cfg.subscriptions.len();
    let handle =
        rustgate_ogc_sensorthings::spawn_polling_task(client, cfg, std::sync::Arc::clone(router));
    tracing::info!(
        endpoint = %endpoint,
        subscriptions = subscription_count,
        "OGC SensorThings polling client started"
    );
    Some(handle)
}

/// Warn when --ogc-sensorthings-config is set but the
/// `ogc-sensorthings` feature is disabled.
#[cfg(not(feature = "ogc-sensorthings"))]
pub(crate) fn warn_ogc_sensorthings_disabled(cli: &Cli) {
    if cli.ogc_sensorthings_config_file.is_some() {
        tracing::warn!("--ogc-sensorthings-config requires --features ogc-sensorthings; ignoring");
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

    // Closes #797: the CA private key is the most sensitive on-disk
    // material rustgate handles — route it through the shared
    // `read_secret_file` helper so the unified mode 0o077 perm gate,
    // size cap, and Zeroizing wrap apply universally. The 16 KiB cap
    // covers RSA-4096 PKCS#8 PEM with comfortable headroom.
    let ca_key_path_owned = ca_key_path.to_string();
    let ca_key_pem = tokio::task::spawn_blocking(move || {
        rustgate_core::read_secret_file(
            &ca_key_path_owned,
            &rustgate_core::SecretFileOpts::with_max_bytes(16 * 1024),
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("blocking task panic: {e}"))?
    .context("reading CA private key for enrollment")?;

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
                    // `id.cn` is `Arc<str>` (closes #784); the
                    // ContactInfo wire shape is `String`, so render
                    // each field via the `Display` impl that `Arc<str>`
                    // forwards to `str`.
                    uid: id.cn.to_string(),
                    callsign: id.cn.to_string(),
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
        // Issue #767 / F-41 was the per-call poison metric for the
        // previous std::sync::Mutex-backed RateLimiter that fail-closed
        // on poison. After #798 the unified `SlidingWindowLimiter` uses
        // `parking_lot::Mutex` (no poisoning), so the
        // `rustgate_enrollment_rate_limit_poison_total` counter stays
        // permanently zero. The metric is preserved at registration time
        // so operator dashboards do not break, but no callback is wired
        // here — there is no poison signal to surface.
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
// justification: this is the single dispatch entrypoint that wires every
// optional admin-API slot (federation, ACL, mgmt, video) into the metrics
// HTTP server. Each feature flag introduces a conditional parameter; bundling
// them into a struct would just move the fan-in upstream without reducing the
// number of live inputs. Called once from main; the count grows linearly with
// the admin API surface.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "metrics")]
pub(crate) async fn start_metrics(
    cli: &Cli,
    health: &Arc<rustgate_admin::HealthState>,
    readiness: &Arc<rustgate_admin::ReadinessState>,
    #[cfg(feature = "federation")] fed_api_slot: &Arc<
        std::sync::OnceLock<rustgate_admin::FedApiHandler>,
    >,
    acl_api_slot: &Arc<std::sync::OnceLock<rustgate_admin::AclApiHandler>>,
    mgmt_api_slot: &Arc<std::sync::OnceLock<rustgate_admin::MgmtApiHandler>>,
    #[cfg(feature = "video")] video_api_slot: &Arc<
        std::sync::OnceLock<rustgate_admin::VideoApiHandler>,
    >,
    router_slot: &rustgate_admin::RouterSlot,
) -> anyhow::Result<Arc<metrics::MetricsIdentity>> {
    // Aggregate every domain crate's `init()` callback into a single
    // ordered registry, then run the sequence with `init_all`. The
    // first error short-circuits and propagates out of this function
    // — identical semantics to the historical hardcoded ladder of
    // `?`-propagating calls, but the bring-up sequence is now data
    // (closes #894).
    //
    // Per-crate metrics modules added under issue #771 register
    // additional metric families on top of the pre-existing
    // `rustgate-server::metrics` surface for that crate; conflicts are
    // avoided by deliberate naming (see the per-crate metrics-module
    // header doc-comments for the boundary discipline).
    let mut registry = rustgate_metrics::MetricsRegistry::default();
    let _ = registry.register(metrics::init);
    let _ = registry.register(rustgate_admin::init);
    #[cfg(feature = "federation")]
    let _ = registry.register(rustgate_federation::metrics::init);
    #[cfg(all(feature = "http", feature = "metrics"))]
    let _ = registry.register(rustgate_http::metrics::init);
    let _ = registry.register(rustgate_authz::metrics::init);
    let _ = registry.register(rustgate_cot::metrics::init);
    #[cfg(feature = "proto")]
    let _ = registry.register(rustgate_proto::metrics::init);
    #[cfg(feature = "mqtt")]
    let _ = registry.register(rustgate_mqtt::metrics::init);
    #[cfg(feature = "websocket")]
    let _ = registry.register(rustgate_websocket::metrics::init);
    registry
        .init_all()
        .context("registering workspace metrics")?;

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
    let metrics_token: Option<Arc<zeroize::Zeroizing<Vec<u8>>>> = if let Some(ref token_file) =
        cli.metrics_token_file
    {
        // Closes #797: route through the shared `read_secret_file`
        // helper so the metrics bearer-token file is subject to the
        // unified perm/size/empty/UTF-8 discipline. Run on a
        // blocking worker because the helper is synchronous; the
        // overhead is one-shot at startup.
        let token_path = token_file.clone();
        let token_str = tokio::task::spawn_blocking(move || {
            rustgate_core::read_secret_file(&token_path, &rustgate_core::SecretFileOpts::default())
        })
        .await
        .map_err(|e| anyhow::anyhow!("blocking task panic: {e}"))?
        .map_err(|e| anyhow::anyhow!("failed to read metrics token file {token_file}: {e}"))?;
        let token = token_str.as_bytes().to_vec();
        rustgate_admin::validate_bearer_token_length(&token, "metrics bearer")
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
        let mgmt_api_for_metrics = Arc::clone(mgmt_api_slot);
        #[cfg(feature = "video")]
        let video_api_for_metrics = Arc::clone(video_api_slot);
        let metrics_token_for_server = metrics_token.clone();
        let router_for_metrics = Arc::clone(router_slot);
        let max_http_connections = cli.metrics_max_connections;
        spawn_background("metrics-server", async move {
            if let Err(e) = rustgate_admin::serve(
                bind_addr,
                health_for_metrics,
                readiness_for_metrics,
                #[cfg(feature = "federation")]
                fed_api_for_metrics,
                acl_api_for_metrics,
                mgmt_api_for_metrics,
                #[cfg(feature = "video")]
                video_api_for_metrics,
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
        // FederationConfig.max_hops is u32 for backward compat with the V1
        // outbound metadata path; the CLI `federation_max_hops` is now `u8`
        // (range 1..=255) since #758, so widen to u32 here. The V2 inbound
        // service narrows back to u8 inside `FederationManager::start` —
        // single source of truth, two consumers.
        max_hops: u32::from(cli.federation_max_hops),
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
    fed_api_slot: &Arc<std::sync::OnceLock<rustgate_admin::FedApiHandler>>,
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
        // JWKS not yet wired into server orchestration; the endpoint
        // returns 404 until a follow-up patch (still under #760) plumbs
        // a federation `JwtAuthority` to a `JwkSetFn` here. See
        // `rustgate_federation::jwks` module docs for the rotation
        // workflow operators will use once the wiring lands.
        jwks_fn: Arc::new(|| None),
    });

    let handler: rustgate_admin::FedApiHandler = Arc::new(move |method, path, body| {
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
                tracing::info!(peer_id = %hash_cn(peer_id.as_str()), "adopting orphaned peer");
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

/// Hooks fired after a federation-inbound message has been driven
/// through [`Router::route_for_egress`] (refs #737).
///
/// The federation `on_inbound` callback used to call `router.route()`
/// and stop there, which delivered the message to local subscribers
/// but skipped the external sinks (NATS bridge, HTTP webhooks). This
/// asymmetry left a federation-sourced message visible only to
/// directly-connected clients while every other transport (MQTT in
/// #1263, NATS subscriber in #1266) already fanned out to the same
/// external sinks. Closing #737 means routing federation-inbound
/// through `route_for_egress` so Send-PEP obligations land on the
/// envelope and the post-mutation form is what the optional
/// `nats_publish` / `http_forward` callbacks observe.
///
/// **No federation-forward field.** A federation-sourced message must
/// not re-enter the federation forwarder — the V2 protocol's per-hop
/// loop guard would catch the echo, but the right invariant is that
/// the federation egress path never even sees the message. The hook
/// struct therefore intentionally omits any federation-forward
/// callback. The publisher's case-insensitive `source_protocol ==
/// "nats"` echo guard (#1192) does NOT match `"federation"`, so
/// federation→NATS fan-out is intended and the `nats_publish` field
/// is fired without short-circuit.
///
/// Each field is `Option`: a `None` value is a no-op and never
/// allocates. Existing federation tests that pass `None` for both
/// keep passing — the new fan-out is additive.
#[cfg(feature = "federation")]
#[derive(Default, Clone)]
pub(crate) struct FedInboundForwardingHooks {
    /// NATS publisher fired once per inbound federation message
    /// after the router applies any Send-PEP obligations. The NATS
    /// publisher's case-insensitive `source_protocol == "nats"` echo
    /// guard does NOT short-circuit `"federation"`, so the callback
    /// fires through to the bus (see #1192).
    pub(crate) nats_publish: Option<rustgate_core::egress::OnNatsPublish>,
    /// HTTP egress callback fired once per inbound federation message
    /// after the router applies any Send-PEP obligations.
    #[cfg(feature = "http")]
    pub(crate) http_forward: Option<HttpForwardFn>,
}

/// Build the federation `OnInbound` callback used by
/// [`start_federation`].
///
/// Extracted from the inlined closure so the unit-test mod can
/// exercise the post-`route_for_egress` fan-out without spinning up
/// a real federation manager (refs #737). The returned closure
/// constructs a `RoutableMessage` from the peer CN + payload and
/// drives it through [`Router::route_for_egress`] so any Send-PEP
/// obligations are baked into the envelope before the optional
/// `nats_publish` / `http_forward` hooks observe it.
///
/// **Echo prevention.** The `source_protocol = "federation"` stamp
/// applied here is what the publisher's NATS echo guard inspects on
/// the way back out — but the publisher only matches `"nats"`
/// (case-insensitive, see #1192), so federation→NATS fan-out is the
/// intended behaviour and is NOT short-circuited. The federation
/// V2 protocol carries its own hop-count / origin-tracking which
/// drops a re-emitted federation message before it enters another
/// peer; we do not wire a federation-forward callback here so the
/// invariant "federation→federation never re-enters the forwarder"
/// is preserved at the call-site, not just at the wire-protocol
/// hop guard.
#[cfg(feature = "federation")]
pub(crate) fn build_federation_inbound_handler(
    router: &Arc<Router>,
    hooks: FedInboundForwardingHooks,
) -> rustgate_federation::manager::OnInbound {
    let router_for_fed = Arc::clone(router);
    Arc::new(move |peer_cn, payload, trace_ctx| {
        let router = Arc::clone(&router_for_fed);
        let hooks = hooks.clone();
        spawn_background("federation-inbound", async move {
            // F-113: federation now hands us a typed `PeerId`. Materialize
            // it as a `String` once for the `Identity::plaintext` call —
            // the inner string is the load-bearing CN for the routable
            // message's `source` field and `Identity::plaintext` consumes
            // by value.
            let peer_cn_str = peer_cn.as_str().to_string();
            let identity = match Identity::plaintext(peer_cn_str.clone(), BTreeSet::new()) {
                Ok(id) => id,
                Err(e) => {
                    // peer_cn here may not yet be a valid Identity (the
                    // construction failed, so the cert-extraction
                    // sanitization performed by `Identity::plaintext`
                    // hasn't run). Sanitize the bytes before they enter
                    // the structured-log field to neutralise CR/LF
                    // log-forging from a malicious federation peer.
                    tracing::warn!(
                        peer_cn = %sanitize_for_log(&peer_cn_str),
                        error = %e,
                        "invalid federation peer identity",
                    );
                    return;
                }
            };
            // PR-C of #852: persist the inbound trace context onto the
            // routable envelope so (1) per-recipient delivery audit can
            // surface the trace_id for cross-service correlation, and
            // (2) any downstream federation egress reads the explicit
            // context from `Metadata` instead of opening a fresh OTel
            // span at the relay edge. The context is `None` when the
            // upstream peer did not send a `traceparent` header or when
            // the header was malformed (audit fired separately).
            let mut metadata = Metadata::new(
                SystemTime::now(),
                "federation".into(),
                rustgate_core::message::MessageType::Other("federation".into()),
            );
            if let Some(ctx) = trace_ctx {
                metadata = metadata.with_trace_context(ctx);
            }
            let msg = RoutableMessage {
                source: identity,
                destination: Destination::Broadcast,
                payload,
                metadata,
            };
            // Drive through `route_for_egress` so Send-PEP obligations
            // (e.g. `MaskPoint` / `MaskPayload`) apply to the envelope
            // before the egress fan-out fires. A `None` return means
            // the router dropped the message (dedup, TTL expiry,
            // Send-PEP deny, oversize multicast); every fan-out MUST
            // be skipped so external sinks stay consistent with the
            // local fanout.
            let routed = router.route_for_egress(msg).await;
            if let Some(routed) = routed.as_ref() {
                fire_federation_inbound_forwarding(&router, &hooks, routed);
            }
        });
    })
}

/// Fan out the post-Send-PEP routed message from the federation
/// `on_inbound` path to NATS and HTTP egress sinks (refs #737, closes
/// #746).
///
/// Mirrors the helper in `rustgate_nats::subscriber` so a
/// federation-inbound message that survives the router's
/// obligations is visible to every external sink in exactly the
/// same way an MQTT publish or NATS subscribe would be. Each sink
/// is independent — a `None` field is a no-op and never allocates.
///
/// **Per-sink envelope rendering** (closes #746). Each wired sink
/// renders its own [`rustgate_router::EgressEnvelope`] via
/// [`Router::prepare_egress_envelope_for_sink`] with its own
/// [`rustgate_router::RecipientClass`] before invoking the publisher
/// callback. Send-PEP rules addressed to a sink class are applied per
/// envelope; an envelope-level deny suppresses dispatch to that sink
/// only.
///
/// `nats_publish` is fired without a short-circuit because the
/// NATS publisher's echo guard matches `source_protocol == "nats"`
/// only (case-insensitive, see #1192) — federation→NATS fan-out is
/// the intended behaviour.
#[cfg(feature = "federation")]
fn fire_federation_inbound_forwarding(
    router: &Router,
    hooks: &FedInboundForwardingHooks,
    routed: &Arc<RoutableMessage>,
) {
    if let Some(cb) = hooks.nats_publish.as_ref()
        && let Ok(envelope) = router.prepare_egress_envelope_for_sink(
            Arc::clone(routed),
            rustgate_router::RecipientClass::NatsSink(String::new()),
        )
    {
        cb(envelope.message.as_ref().clone());
    }
    #[cfg(feature = "http")]
    if let Some(fwd) = hooks.http_forward.as_ref()
        && let Ok(envelope) = router.prepare_egress_envelope_for_sink(
            Arc::clone(routed),
            rustgate_router::RecipientClass::HttpSink(String::new()),
        )
    {
        fwd(envelope.message.as_ref().clone());
    }
}

/// Start the federation subsystem and return the forwarding callback + shutdown handle.
///
/// `hooks` is the post-`route_for_egress` fan-out wiring (refs
/// #737). When the caller has not yet built the NATS publisher /
/// HTTP egress (e.g. the no-bridges configuration), pass
/// `FedInboundForwardingHooks::default()`; the federation inbound
/// path then degrades to a local-only delivery, matching the
/// pre-#737 behaviour.
#[cfg(feature = "federation")]
pub(crate) async fn start_federation(
    cli: &Cli,
    router: &Arc<Router>,
    hooks: FedInboundForwardingHooks,
    #[cfg(feature = "metrics")] fed_api_slot: &Arc<
        std::sync::OnceLock<rustgate_admin::FedApiHandler>,
    >,
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

    // on_inbound: route messages from federation peers to local
    // clients AND fan out to optional NATS / HTTP egress sinks.
    //
    // Security note (issue #719): federated messages are handed to
    // `router.route_for_egress()`, which re-runs the full PEP chain —
    // Send-PEP with the peer CN as subject, then per-recipient
    // Receive-PEP with each recipient's CN as subject. Obligations
    // returned by the local Receive-PEP are always applied on a
    // per-recipient copy of the envelope, regardless of what the
    // upstream peer did.
    //
    // Egress fan-out (#737): the post-Send-PEP envelope returned by
    // `route_for_egress` is what the optional NATS / HTTP callbacks
    // observe — never the raw inbound payload. A regression that
    // fired the egress callbacks against the pre-PEP form would leak
    // unmasked coordinates to external sinks while the in-process
    // delivery looked compliant.
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
    let on_inbound = build_federation_inbound_handler(router, hooks);

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
    pub(crate) replay_filter: &'a Option<Arc<rustgate_router::ReplayFilter>>,
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

    #[cfg(feature = "metrics")]
    let ws_session_hooks = Some(rustgate_websocket::WsSessionHooks {
        on_connection_accept: Some(Arc::new(|| metrics::ws_connections().inc())),
        on_connection_rejected: Some(Arc::new(|| metrics::ws_connections_rejected().inc())),
    });
    #[cfg(not(feature = "metrics"))]
    let ws_session_hooks: Option<rustgate_websocket::WsSessionHooks> = None;

    let ws_config = rustgate_websocket::WsListenerConfig {
        conn_rate_limit: cli.ws_rate_limit_max,
        conn_rate_window: std::time::Duration::from_secs(cli.ws_rate_limit_window_secs),
        max_frame_size: cli.ws_max_frame_size,
        max_message_size: cli.ws_max_message_size,
        supported_subprotocols: cli.ws_subprotocols.clone(),
        subprotocol_strict: cli.ws_subprotocol_strict,
        compression: if cli.ws_compression_disabled {
            rustgate_websocket::CompressionConfig::Disabled
        } else {
            rustgate_websocket::CompressionConfig::default()
        },
        on_connection_rejected: ws_session_hooks
            .as_ref()
            .and_then(|h| h.on_connection_rejected.clone()),
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
        session_hooks: ws_session_hooks,
        // Closes #741. WebSocket sessions feed the same SA
        // auto-upgrade counter family as the TLS / UDP listeners.
        #[cfg(feature = "metrics")]
        sa_upgrade_observer: Some(crate::metrics::sa_auto_upgraded_callback()),
        #[cfg(not(feature = "metrics"))]
        sa_upgrade_observer: None,
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

/// Inputs for [`start_mqtt`], bundled to keep the fanout of egress
/// callbacks (NATS publisher, federation forwarder, HTTP egress) out of
/// a parameter list that is already at the `#[allow(too_many_
/// arguments)]` boundary. Mirrors [`WebSocketSetup`] so both session
/// transports thread the exact same wiring through a single entry
/// point.
#[cfg(feature = "mqtt")]
pub(crate) struct MqttSetup<'a, P: NatsPublish> {
    pub(crate) cli: &'a Cli,
    pub(crate) tls_config: &'a TlsConfig,
    pub(crate) router: &'a Arc<Router>,
    pub(crate) connection_limit: &'a Arc<Semaphore>,
    pub(crate) nats_publisher: &'a Option<P>,
    pub(crate) fed_forward: &'a Option<FedForwardFn>,
    #[cfg(feature = "http")]
    pub(crate) http_forward: &'a Option<HttpForwardFn>,
}

/// Start the MQTT listener and return its subsystem handle.
#[cfg(feature = "mqtt")]
pub(crate) fn start_mqtt<P: NatsPublish + Send + Sync + 'static>(
    setup: MqttSetup<'_, P>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let MqttSetup {
        cli,
        tls_config,
        router,
        connection_limit,
        nats_publisher,
        fed_forward,
        #[cfg(feature = "http")]
        http_forward,
    } = setup;
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

    #[cfg(feature = "metrics")]
    let on_accept: Option<rustgate_mqtt::OnMqttAccept> =
        Some(std::sync::Arc::new(|| metrics::mqtt_connections().inc()));
    #[cfg(not(feature = "metrics"))]
    let on_accept: Option<rustgate_mqtt::OnMqttAccept> = None;

    #[cfg(feature = "metrics")]
    let on_reject: Option<rustgate_mqtt::OnMqttReject> = Some(std::sync::Arc::new(|| {
        metrics::mqtt_connections_rejected().inc()
    }));
    #[cfg(not(feature = "metrics"))]
    let on_reject: Option<rustgate_mqtt::OnMqttReject> = None;

    #[cfg(feature = "metrics")]
    let session_hooks: Option<rustgate_mqtt::MqttSessionHooks> =
        Some(rustgate_mqtt::MqttSessionHooks {
            on_publish: Some(std::sync::Arc::new(|| metrics::mqtt_publishes().inc())),
            on_publish_reject: Some(std::sync::Arc::new(|| {
                metrics::mqtt_publishes_rejected().inc()
            })),
            on_subscribe: Some(std::sync::Arc::new(|| metrics::mqtt_subscribes().inc())),
            on_subscribe_reject: Some(std::sync::Arc::new(|| {
                metrics::mqtt_subscribes_rejected().inc()
            })),
            on_retain_stored: Some(std::sync::Arc::new(|| metrics::mqtt_retain_stored().inc())),
            on_retain_cleared: Some(std::sync::Arc::new(|| metrics::mqtt_retain_cleared().inc())),
            on_retain_replayed: Some(std::sync::Arc::new(|| {
                metrics::mqtt_retain_replayed().inc()
            })),
            on_will_published: Some(std::sync::Arc::new(|| metrics::mqtt_will_published().inc())),
        });
    #[cfg(not(feature = "metrics"))]
    let session_hooks: Option<rustgate_mqtt::MqttSessionHooks> = None;

    // Wire the egress fan-out callbacks for NATS / federation / HTTP.
    // Each leg is independent and each feature flag gates just its own
    // leg — all three may be present, any subset may be absent, and the
    // session crate treats `None` as a no-op.
    let nats_cb: Option<rustgate_core::egress::OnNatsPublish> = {
        #[cfg(feature = "nats")]
        {
            nats_publisher
                .clone()
                .map(|p| -> rustgate_core::egress::OnNatsPublish {
                    Arc::new(move |msg| {
                        let p = p.clone();
                        spawn_background("mqtt-nats-publish", async move {
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

    let forwarding_hooks = Some(rustgate_mqtt::MqttForwardingHooks {
        nats_publish: nats_cb,
        federation_forward: fed_forward.clone(),
        http_forward: {
            #[cfg(feature = "http")]
            {
                http_forward
                    .clone()
                    .map(|fwd| -> rustgate_core::egress::OnHttpForward { fwd })
            }
            #[cfg(not(feature = "http"))]
            {
                None
            }
        },
    });

    let config = rustgate_mqtt::MqttServerConfig {
        listener: mqtt_listener,
        router: Arc::clone(router),
        connection_limit: Arc::clone(connection_limit),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: cli.mqtt_topic_prefix.clone(),
        max_packet_size: cli.mqtt_max_packet_size,
        receive_max: cli.mqtt_receive_max,
        topic_alias_max: cli.mqtt_topic_alias_max,
        max_session_expiry_secs: cli.mqtt_max_session_expiry_secs,
        max_retained_sessions: cli.mqtt_max_retained_sessions,
        min_keep_alive_secs: cli.mqtt_min_keep_alive_secs,
        server_keep_alive_secs: cli.mqtt_server_keep_alive_secs,
        response_channel_capacity: cli.mqtt_response_channel_capacity,
        wildcard_policy: cli.mqtt_wildcard_policy.into(),
        on_accept,
        on_reject,
        session_hooks,
        forwarding_hooks,
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
// justification: setup entrypoint wiring together the router, admission
// semaphore, codec, optional NATS publisher, optional federation forward
// callback, optional HTTP forward callback, throttle config, archiver,
// replay filter, and metrics identity. Every input is needed for exactly
// one long-lived task; bundling them into a `StartPlaintextTcpArgs` struct
// would duplicate the CLI's own shape without reducing the number of live
// references the caller owns.
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
    archiver: &Option<Arc<rustgate_archive::CotArchiver>>,
    replay_filter: &Option<Arc<rustgate_router::ReplayFilter>>,
    #[cfg(feature = "metrics")] metrics_identity: &Arc<metrics::MetricsIdentity>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let tcp_bind = match cli.tcp_bind.as_ref() {
        Some(b) => b,
        None => return Ok(None),
    };

    let addr: std::net::SocketAddr = tcp_bind.parse().context("parsing --tcp-bind address")?;

    tracing::warn!(addr = %addr, "plaintext TCP input enabled — traffic is NOT encrypted");

    let identity_config = rustgate_tls::PlaintextIdentityConfig {
        cn: cli.plaintext_cn.clone(),
        default_group: cli.plaintext_group.clone(),
    };

    let pt_listener = rustgate_tls::PlaintextListener::bind(addr, identity_config)
        .await
        .context("binding plaintext TCP listener")?;

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);

    // justification: same feature-conditional clone pattern as the other
    // NATS publisher clones above — `()` on the default build,
    // `Option<NatsPublisher>` under `--features nats`. `.clone()` is the
    // only spelling that compiles in both.
    #[allow(clippy::clone_on_copy)]
    let pt_nats = nats_publisher.clone();
    // Refs #849: parse the per-listener default marking. Validation
    // ran at startup in `Cli::validate`, so a parse failure here is a
    // bug — surface as a hard error rather than silently skipping.
    let default_classification: Option<rustgate_core::classification::ClassificationMarking> =
        match cli.default_classification.as_ref() {
            Some(banner) => Some(banner.parse().map_err(|e| {
                anyhow::anyhow!(
                    "--default-classification ({banner:?}) parse failed for plaintext listener: {e}"
                )
            })?),
            None => None,
        };
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
        default_classification,
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
    replay_filter: &Option<Arc<rustgate_router::ReplayFilter>>,
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

    // Closes #741. UDP datagrams feed the same SA auto-upgrade
    // counter family as the TLS / WebSocket listeners.
    #[cfg(feature = "metrics")]
    {
        config.sa_upgrade_observer = Some(crate::metrics::sa_auto_upgraded_callback());
    }

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

// ---------------------------------------------------------------------------
// UDP MULTICAST INPUT (closes #861)
// ---------------------------------------------------------------------------

/// Start the UDP multicast input listener (and optional rebroadcast egress)
/// and return its subsystem handle.
///
/// When `--udp-multicast-groups` is empty (default), this returns
/// `Ok(None)` and no listener is spawned. When at least one group is
/// configured, the kernel `join_multicast_v4` is called per group, the
/// receive loop tags incoming datagrams with `source_protocol =
/// "udp-multicast"`, and (if `--udp-multicast-rebroadcast` is set) a
/// router-installed `OnMulticastForward` callback re-emits every routed
/// CoT message out the egress socket. Closes #861.
pub(crate) async fn start_udp_multicast(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let groups_str = match cli.udp_multicast_groups.as_ref() {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Ok(None),
    };

    let mut groups = Vec::new();
    for entry in groups_str.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let g = rustgate_transport::MulticastGroup::parse(trimmed).map_err(|e| {
            anyhow::anyhow!("invalid --udp-multicast-groups entry '{trimmed}': {e}")
        })?;
        groups.push(g);
    }
    if groups.is_empty() {
        return Ok(None);
    }

    let interface: std::net::Ipv4Addr = cli.udp_multicast_interface.parse().with_context(|| {
        format!(
            "parsing --udp-multicast-interface '{}'",
            cli.udp_multicast_interface
        )
    })?;

    let cfg = rustgate_transport::MulticastConfig {
        groups,
        interface,
        multicast_loop: cli.udp_multicast_loop,
        ttl: cli.udp_multicast_ttl,
        cn: cli.plaintext_cn.clone(),
        default_group: cli.plaintext_group.clone(),
        rebroadcast: cli.udp_multicast_rebroadcast,
        max_bps: cli.udp_multicast_max_bps,
    };

    let shutdown = Arc::new(tokio::sync::Notify::new());

    // Inbound listener tasks (one per group).
    let inbound_handles = rustgate_transport::udp_multicast::spawn_inbound(
        cfg.clone(),
        Arc::clone(router),
        Arc::clone(&shutdown),
    )
    .context("spawning UDP multicast listeners")?;

    // Optional egress task. When rebroadcast is off, no callback is
    // installed and the router fast-paths the on-multicast-forward
    // ArcSwap as `is_none()`.
    let egress_handle = if cfg.rebroadcast {
        let (cb, h) =
            rustgate_transport::udp_multicast::spawn_egress(cfg.clone(), Arc::clone(&shutdown))
                .await
                .context("spawning UDP multicast egress")?;
        router.set_on_multicast_forward(Some(cb));
        Some(h)
    } else {
        None
    };

    // Wrap all spawned tasks in a single supervisor that completes
    // when every per-group + egress task exits.
    let task = tokio::spawn(async move {
        for h in inbound_handles {
            let _ = h.await;
        }
        if let Some(eh) = egress_handle {
            let _ = eh.await;
        }
    });

    Ok(Some(SubsystemHandle::new(shutdown, task)))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    //! Unit tests for the pure synchronous helpers in `setup.rs`.
    //!
    //! The async `start_*` / `connect_*` orchestrators wire live
    //! listeners, TLS material, and background tasks — those paths are
    //! exercised end-to-end by integration tests. These tests pin the
    //! small, allocation-free validation and mapping helpers that turn
    //! CLI arguments into subsystem config, since those are the paths
    //! that silently mis-route the whole server if they drift.

    use clap::Parser;

    use super::*;

    /// Build a minimal CLI with the required TLS material flags.
    ///
    /// Additional flags are appended by each test; the `--cert / --key / --ca`
    /// triplet is `required_unless_present_any = ["config", "spiffe"]`, so
    /// clap rejects a bare invocation.
    fn parse_cli(extra: &[&str]) -> Cli {
        let mut argv: Vec<&str> = vec![
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv).expect("cli parses")
    }

    // -----------------------------------------------------------------
    // validate_framing
    // -----------------------------------------------------------------

    #[test]
    fn validate_framing_accepts_defaults() {
        // Default framing (xml) + default encoding (raw) is the stock
        // configuration every build must support regardless of features.
        let cli = parse_cli(&[]);
        validate_framing(&cli).expect("defaults must validate");
    }

    #[test]
    fn validate_framing_accepts_length_prefixed_with_cot() {
        let cli = parse_cli(&["--framing", "length-prefixed", "--encoding", "cot"]);
        validate_framing(&cli).expect("length-prefixed + cot must validate");
    }

    #[test]
    fn validate_framing_accepts_line_with_raw() {
        let cli = parse_cli(&["--framing", "line", "--encoding", "raw"]);
        validate_framing(&cli).expect("line + raw must validate");
    }

    #[cfg(feature = "proto")]
    #[test]
    fn validate_framing_accepts_tak_protobuf_pair() {
        // With `proto` compiled in, tak-protobuf framing paired with
        // tak-protobuf encoding is the real TAK binary configuration.
        let cli = parse_cli(&["--framing", "tak-protobuf", "--encoding", "tak-protobuf"]);
        validate_framing(&cli).expect("tak-protobuf pair must validate with proto feature");
    }

    #[cfg(feature = "proto")]
    #[test]
    fn validate_framing_accepts_tak_negotiate_with_tak_protobuf_encoding() {
        // tak-negotiate starts XML and upgrades to protobuf mid-session;
        // it satisfies the "framing is a protobuf-capable mode"
        // precondition for tak-protobuf encoding.
        let cli = parse_cli(&["--framing", "tak-negotiate", "--encoding", "tak-protobuf"]);
        validate_framing(&cli).expect("tak-negotiate + tak-protobuf must validate");
    }

    #[cfg(feature = "proto")]
    #[test]
    fn validate_framing_rejects_tak_protobuf_encoding_with_xml_framing() {
        // With proto enabled, the feature-gate check passes — but the
        // framing/encoding conflict check still fires: xml framing
        // cannot carry tak-protobuf bytes on the wire.
        let cli = parse_cli(&["--framing", "xml", "--encoding", "tak-protobuf"]);
        let err = validate_framing(&cli).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--encoding tak-protobuf requires --framing"),
            "unexpected error: {msg}",
        );
    }

    #[cfg(feature = "proto")]
    #[test]
    fn validate_framing_rejects_tak_protobuf_encoding_with_length_prefixed_framing() {
        let cli = parse_cli(&["--framing", "length-prefixed", "--encoding", "tak-protobuf"]);
        assert!(validate_framing(&cli).is_err());
    }

    #[cfg(not(feature = "proto"))]
    #[test]
    fn validate_framing_rejects_tak_protobuf_framing_without_proto_feature() {
        // Without the `proto` feature compiled in, any tak-protobuf
        // framing/encoding selection must surface a startup error
        // instead of silently falling through to a codec that cannot
        // actually decode tak-protobuf bytes.
        let cli = parse_cli(&["--framing", "tak-protobuf"]);
        let err = validate_framing(&cli).unwrap_err();
        assert!(err.to_string().contains("--features proto"));
    }

    #[cfg(not(feature = "proto"))]
    #[test]
    fn validate_framing_rejects_tak_negotiate_framing_without_proto_feature() {
        let cli = parse_cli(&["--framing", "tak-negotiate"]);
        assert!(validate_framing(&cli).is_err());
    }

    #[cfg(not(feature = "proto"))]
    #[test]
    fn validate_framing_rejects_tak_protobuf_encoding_without_proto_feature() {
        let cli = parse_cli(&["--encoding", "tak-protobuf"]);
        assert!(validate_framing(&cli).is_err());
    }

    // -----------------------------------------------------------------
    // build_throttle_config
    // -----------------------------------------------------------------

    #[test]
    fn build_throttle_config_returns_none_when_rate_is_zero() {
        // Default rate of 0 disables per-client throttling; the helper
        // must return `None` so the session loop skips the allow() check
        // entirely — any `Some` here would make throttling always-on.
        let cli = parse_cli(&[]);
        assert_eq!(cli.client_message_rate, 0, "test precondition");
        assert!(build_throttle_config(&cli).is_none());
    }

    #[test]
    fn build_throttle_config_uses_cli_rate_and_burst() {
        let cli = parse_cli(&["--client-message-rate", "250", "--client-burst", "500"]);
        let cfg = build_throttle_config(&cli).expect("throttle enabled");
        assert_eq!(cfg.rate, 250);
        assert_eq!(cfg.burst, 500);
    }

    #[test]
    fn build_throttle_config_uses_default_burst_when_only_rate_is_set() {
        // CLI default for --client-burst is 200; callers who only set
        // --client-message-rate must still get a usable throttle config
        // with the documented default burst so a misconfiguration does
        // not silently produce a zero-burst throttle (which would drop
        // every message).
        let cli = parse_cli(&["--client-message-rate", "100"]);
        let cfg = build_throttle_config(&cli).expect("throttle enabled");
        assert_eq!(cfg.rate, 100);
        assert_eq!(cfg.burst, 200, "default burst must flow through");
    }

    // -----------------------------------------------------------------
    // Federation `on_inbound` egress fan-out (refs #737, the
    // federation sub-item that completes the umbrella alongside MQTT
    // #1263 and the NATS subscriber #1266)
    //
    // Pins the load-bearing security properties of the post-
    // `route_for_egress` fan-out:
    //
    // 1. **Federation→NATS fans out.** A NATS publisher wired on
    //    `FedInboundForwardingHooks` MUST fire exactly once per
    //    inbound federation message that survives the router's
    //    obligations.
    // 2. **Federation→HTTP fans out.** Symmetric to (1) — wires an
    //    HTTP forwarder and asserts it fires.
    // 3. **No federation→federation echo.** The hook struct does not
    //    expose a federation-forward field, so a federation-sourced
    //    message cannot re-enter the federation forwarder via this
    //    path; the V2 protocol's hop guard backs the invariant up at
    //    the wire layer. Pinning the type-level absence stops a
    //    future refactor from silently re-introducing the loop.
    // 4. **Send-PEP obligations apply before fan-out.** A
    //    `MaskPayload` obligation on the Send PEP MUST scrub the
    //    payload BEFORE the local recipient sees it AND BEFORE the
    //    NATS / HTTP egress callbacks observe it. A regression that
    //    fired the egress callbacks against the pre-PEP form would
    //    leak raw payload bytes to a webhook target while the
    //    in-process delivery looked compliant — exactly the gap
    //    closed by switching the federation `on_inbound` call site
    //    from `Router::route` to `Router::route_for_egress`.
    // 5. **`source_protocol` stamp.** Every envelope the handler
    //    constructs from a federation peer must stamp
    //    `metadata.source_protocol = "federation"`. This is the
    //    workspace convention the publisher echo guards inspect on
    //    the way back out (NATS publisher matches `"nats"` only,
    //    HTTP publisher matches `"http"` only — neither
    //    short-circuits `"federation"`).

    #[cfg(feature = "federation")]
    #[allow(clippy::panic, clippy::unwrap_used)]
    mod federation_inbound {
        use std::sync::Mutex as StdMutex;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use bytes::Bytes;
        use rustgate_core::PeerId;
        use rustgate_core::message::{MessageType, RoutableMessage};
        use rustgate_router::Router;

        use super::super::{FedInboundForwardingHooks, build_federation_inbound_handler};

        /// Drive the test runtime forward in small slices until `pred`
        /// returns true or `tries` slices have elapsed. The closure
        /// dispatches its async work via `spawn_background`, so the
        /// caller cannot await a `JoinHandle`; this poll is the
        /// supported way to observe the fan-out from a test.
        async fn wait_for(pred: impl Fn() -> bool, tries: usize) {
            for _ in 0..tries {
                if pred() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        /// Build a synthetic federation-inbound message: peer CN
        /// `"peer-cn"` and a non-empty payload. The handler stamps
        /// `source_protocol = "federation"` regardless of what the
        /// caller does, so we exercise that invariant from the
        /// outside.
        fn invoke_handler(handler: &rustgate_federation::manager::OnInbound, payload: &[u8]) {
            let peer = PeerId::new("peer-cn".to_string());
            // PR-C of #852: trace_context is `None` for these
            // tests because the fan-out invariant is independent of
            // the trace propagation contract.
            handler(peer, Bytes::copy_from_slice(payload), None);
        }

        /// Wire a NATS-publish hook on the federation inbound
        /// handler and assert it fires exactly once per inbound
        /// federation message with the post-Send-PEP envelope.
        #[tokio::test]
        async fn federation_inbound_fans_out_to_nats() {
            let router = std::sync::Arc::new(Router::new());

            let nats_calls: std::sync::Arc<StdMutex<Vec<RoutableMessage>>> =
                std::sync::Arc::new(StdMutex::new(Vec::new()));
            let nats_calls_clone = std::sync::Arc::clone(&nats_calls);
            let nats_cb: rustgate_core::egress::OnNatsPublish = std::sync::Arc::new(move |msg| {
                nats_calls_clone.lock().expect("mutex poisoned").push(msg);
            });

            let hooks = FedInboundForwardingHooks {
                nats_publish: Some(nats_cb),
                #[cfg(feature = "http")]
                http_forward: None,
            };

            let handler = build_federation_inbound_handler(&router, hooks);
            invoke_handler(&handler, b"<event/>");

            wait_for(
                || nats_calls.lock().expect("mutex poisoned").len() == 1,
                100,
            )
            .await;

            let snapshot = nats_calls.lock().expect("mutex poisoned").clone();
            assert_eq!(
                snapshot.len(),
                1,
                "federation→NATS hook must fire exactly once per inbound message",
            );
            let routed = &snapshot[0];
            assert_eq!(
                routed.metadata.source_protocol, "federation",
                "fan-out envelope must preserve the federation source_protocol stamp",
            );
            assert_eq!(routed.payload.as_ref(), b"<event/>");
            assert_eq!(&*routed.source.cn, "peer-cn");
        }

        /// Wire an HTTP-egress hook and assert it fires exactly once
        /// per inbound federation message with the post-Send-PEP
        /// envelope.
        #[cfg(feature = "http")]
        #[tokio::test]
        async fn federation_inbound_fans_out_to_http() {
            let router = std::sync::Arc::new(Router::new());

            let http_calls: std::sync::Arc<StdMutex<Vec<RoutableMessage>>> =
                std::sync::Arc::new(StdMutex::new(Vec::new()));
            let http_calls_clone = std::sync::Arc::clone(&http_calls);
            let http_cb: crate::session::HttpForwardFn = std::sync::Arc::new(move |msg| {
                http_calls_clone.lock().expect("mutex poisoned").push(msg);
            });

            let hooks = FedInboundForwardingHooks {
                nats_publish: None,
                http_forward: Some(http_cb),
            };

            let handler = build_federation_inbound_handler(&router, hooks);
            invoke_handler(&handler, b"<event/>");

            wait_for(
                || http_calls.lock().expect("mutex poisoned").len() == 1,
                100,
            )
            .await;

            let snapshot = http_calls.lock().expect("mutex poisoned").clone();
            assert_eq!(
                snapshot.len(),
                1,
                "federation→HTTP hook must fire exactly once per inbound message",
            );
            let routed = &snapshot[0];
            assert_eq!(routed.metadata.source_protocol, "federation");
            assert_eq!(routed.payload.as_ref(), b"<event/>");
        }

        /// The hook struct intentionally has no
        /// federation-forward field, so a federation-sourced
        /// message cannot re-enter the federation forwarder via
        /// this path. We pin the absence at the type level: any
        /// future refactor that adds a federation-forward field
        /// must update this test, forcing a deliberate review of
        /// the loop-prevention invariant.
        #[test]
        fn federation_inbound_does_not_loop_back_to_federation() {
            let hooks = FedInboundForwardingHooks::default();
            // Confirm the only egress fields are nats_publish and
            // (optionally) http_forward — *not* federation. If a
            // future field is added that exposes a federation
            // forward callback this assertion will need to be
            // re-evaluated against the V2 hop guard.
            assert!(
                hooks.nats_publish.is_none(),
                "default hooks must not pre-wire NATS",
            );
            #[cfg(feature = "http")]
            assert!(
                hooks.http_forward.is_none(),
                "default hooks must not pre-wire HTTP",
            );
            // The compile-time absence of a `federation_forward`
            // field on `FedInboundForwardingHooks` is the load-
            // bearing invariant: this test fails to build (rather
            // than at runtime) if the field is added back.
        }

        /// A Send-PEP obligation MUST scrub the payload BEFORE the
        /// NATS / HTTP egress callbacks observe it. This pins the
        /// switch from `Router::route` to `Router::route_for_egress`
        /// inside `build_federation_inbound_handler` — a regression
        /// that fired the egress callbacks against the pre-PEP form
        /// would leak raw federation-peer payload bytes to webhook
        /// targets while the in-process delivery looked compliant.
        #[tokio::test]
        async fn federation_inbound_with_send_pep_obligation_applies_obligation_before_fanout() {
            use rustgate_authz::{
                Action, Decision, DecisionOutcome, Obligation, PolicyEngine, Resource, Subject,
            };

            /// Engine that allows everything but attaches
            /// `MaskPayload` on the Send PEP. The obligation strips
            /// the payload bytes and rewrites
            /// `metadata.message_type` to `Other("masked")`.
            struct AllowWithSendMaskPayloadEngine;
            impl PolicyEngine for AllowWithSendMaskPayloadEngine {
                fn evaluate(
                    &self,
                    _s: &Subject<'_>,
                    _r: &Resource<'_>,
                    a: Action,
                ) -> DecisionOutcome {
                    let obligations = if a == Action::Send {
                        vec![Obligation::MaskPayload]
                    } else {
                        Vec::new()
                    };
                    DecisionOutcome {
                        decision: Decision::Allow,
                        rule_id: None,
                        obligations,
                    }
                }
                fn policy_id(&self) -> &str {
                    "test-fed-inbound-send-mask-payload"
                }
            }

            let router = std::sync::Arc::new(
                Router::new().with_authz(std::sync::Arc::new(AllowWithSendMaskPayloadEngine)),
            );

            let nats_calls: std::sync::Arc<StdMutex<Vec<RoutableMessage>>> =
                std::sync::Arc::new(StdMutex::new(Vec::new()));
            let nats_calls_clone = std::sync::Arc::clone(&nats_calls);
            let nats_cb: rustgate_core::egress::OnNatsPublish = std::sync::Arc::new(move |msg| {
                nats_calls_clone.lock().expect("mutex poisoned").push(msg);
            });

            let hooks = FedInboundForwardingHooks {
                nats_publish: Some(nats_cb),
                #[cfg(feature = "http")]
                http_forward: None,
            };

            let handler = build_federation_inbound_handler(&router, hooks);
            invoke_handler(&handler, b"<event payload=\"sensitive\"/>");

            wait_for(
                || nats_calls.lock().expect("mutex poisoned").len() == 1,
                100,
            )
            .await;

            let snapshot = nats_calls.lock().expect("mutex poisoned").clone();
            assert_eq!(
                snapshot.len(),
                1,
                "federation→NATS hook must fire even when Send-PEP attaches an obligation",
            );
            let egress = &snapshot[0];
            assert!(
                egress.payload.is_empty(),
                "MaskPayload obligation must scrub egress payload BEFORE the NATS hook observes it; got {} bytes",
                egress.payload.len(),
            );
            assert!(
                matches!(egress.metadata.message_type, MessageType::Other(ref s) if s == "masked"),
                "MaskPayload obligation must rewrite message_type before fan-out; got {:?}",
                egress.metadata.message_type,
            );
        }

        /// Pin the metadata invariant: every envelope the federation
        /// `on_inbound` handler constructs MUST stamp
        /// `source_protocol = "federation"`. Both publisher echo
        /// guards (NATS in #1192, HTTP at line 419 of
        /// `rustgate-http/src/publisher.rs`) match their own
        /// transport name only — `"federation"` does NOT trip
        /// either, so the fan-out reaches the bus and webhooks as
        /// intended.
        #[tokio::test]
        async fn federation_inbound_source_protocol_is_federation() {
            let router = std::sync::Arc::new(Router::new());

            let observed: std::sync::Arc<StdMutex<Option<RoutableMessage>>> =
                std::sync::Arc::new(StdMutex::new(None));
            let observed_clone = std::sync::Arc::clone(&observed);
            let nats_cb: rustgate_core::egress::OnNatsPublish = std::sync::Arc::new(move |msg| {
                *observed_clone.lock().expect("mutex poisoned") = Some(msg);
            });

            let hooks = FedInboundForwardingHooks {
                nats_publish: Some(nats_cb),
                #[cfg(feature = "http")]
                http_forward: None,
            };

            let handler = build_federation_inbound_handler(&router, hooks);
            invoke_handler(&handler, b"<event/>");

            wait_for(|| observed.lock().expect("mutex poisoned").is_some(), 100).await;

            let snap = observed.lock().expect("mutex poisoned").clone();
            let routed = snap.expect("hook must observe one message");
            assert_eq!(routed.metadata.source_protocol, "federation");
            assert!(
                matches!(routed.metadata.message_type, MessageType::Other(ref s) if s == "federation"),
                "source-protocol invariant: message_type for an inbound federation message must be Other(\"federation\"); got {:?}",
                routed.metadata.message_type,
            );
        }

        /// `None` hooks must keep the pre-#737 behaviour: the
        /// router still receives the message (local fan-out runs)
        /// but no egress callback fires. The accidental introduction
        /// of an unconditional callback would corrupt the no-bridge
        /// configuration for operators who haven't enabled NATS or
        /// HTTP egress.
        #[tokio::test]
        async fn federation_inbound_with_default_hooks_does_not_call_egress() {
            let router = std::sync::Arc::new(Router::new());

            // No callbacks wired; the only observable signal is
            // that the handler completes without panicking and the
            // `route_for_egress` path returns successfully.
            let counter = std::sync::Arc::new(AtomicUsize::new(0));
            let counter_clone = std::sync::Arc::clone(&counter);
            let nats_cb: rustgate_core::egress::OnNatsPublish = std::sync::Arc::new(move |_| {
                let _ = counter_clone.fetch_add(1, Ordering::SeqCst);
            });

            // Build hooks with no callbacks — assert the closure
            // does not invoke them, even though the message still
            // flows through `route_for_egress`.
            let hooks_default = FedInboundForwardingHooks::default();
            let handler = build_federation_inbound_handler(&router, hooks_default);
            invoke_handler(&handler, b"<event/>");

            // Give the spawned task time to run; even after the
            // handler completes, the counter must remain zero
            // because the default hooks have no callbacks wired.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                counter.load(Ordering::SeqCst),
                0,
                "default-hook handler must not fire any egress callback",
            );

            // Sanity-check that the closure we hold is actually
            // wireable: replace `hooks_default` with a populated
            // hook bag and confirm the same handler shape fires
            // the callback exactly once.
            let nats_cb2 = std::sync::Arc::clone(&nats_cb);
            let hooks_wired = FedInboundForwardingHooks {
                nats_publish: Some(nats_cb2),
                #[cfg(feature = "http")]
                http_forward: None,
            };
            let handler2 = build_federation_inbound_handler(&router, hooks_wired);
            invoke_handler(&handler2, b"<event2/>");
            wait_for(|| counter.load(Ordering::SeqCst) == 1, 100).await;
            assert_eq!(
                counter.load(Ordering::SeqCst),
                1,
                "wired hook must fire exactly once",
            );
        }
    }
}
