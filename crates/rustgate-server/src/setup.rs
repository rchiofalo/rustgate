//! Server startup and subsystem initialization.
//!
//! Extracts the setup logic from `run()` into focused functions for each
//! subsystem: TLS, NATS, enrollment, federation, metrics, WebSocket,
//! plaintext TCP, and UDP.

#[cfg(feature = "federation")]
use std::collections::BTreeSet;
use std::sync::Arc;
#[cfg(feature = "metrics")]
use std::sync::atomic::AtomicBool;
#[cfg(feature = "federation")]
use std::time::SystemTime;

use anyhow::Context;
#[cfg(feature = "federation")]
use rustgate_core::identity::Identity;
#[cfg(feature = "federation")]
use rustgate_core::message::RoutableMessage;
#[cfg(feature = "federation")]
use rustgate_core::message::{Destination, Metadata};
use rustgate_transport::{
    CertReloader, Router, ThrottleConfig, TlsConfig, TlsListener, TlsMinVersion,
};
use tokio::sync::Semaphore;

use crate::cli::{Cli, Encoding, Framing};
#[cfg(feature = "metrics")]
use crate::metrics;
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

    let mut groups = std::collections::HashMap::new();
    for (group_id, entry) in &config.groups {
        let _ = groups.insert(
            group_id.clone(),
            rustgate_transport::GroupAcl::with_deny(
                entry.send.clone(),
                entry.receive.clone(),
                entry.deny_send.clone(),
                entry.deny_receive.clone(),
            ),
        );
    }

    let policy = rustgate_transport::GroupAclPolicy::new(groups);
    tracing::info!(groups = policy.len(), "loaded group access control policy");
    Ok((Some(policy), Some(hash), Some(config)))
}

/// Spawn a tokio task whose `JoinHandle` is intentionally not tracked.
///
/// Logs a warning if the task panics. Prefer this over bare `drop(tokio::spawn(...))`
/// so that panics in background tasks are observable.
pub(crate) fn spawn_background(
    name: &'static str,
    fut: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let handle = tokio::spawn(fut);
    drop(tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!(task = name, error = %e, "background task panicked");
        }
    }));
}

/// Handle for a subsystem that can be gracefully stopped.
///
/// Unlike `spawn_background`, subsystem handles allow the caller to signal
/// shutdown and then await the task's completion. Used for listener tasks
/// (WebSocket, plaintext TCP, UDP) so they stop accepting before connection
/// draining begins.
pub(crate) struct SubsystemHandle {
    pub(crate) shutdown: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

/// Signal a subsystem to stop and await its completion with a timeout.
pub(crate) async fn stop_subsystem(name: &str, handle: SubsystemHandle) {
    handle.shutdown.notify_one();
    match tokio::time::timeout(std::time::Duration::from_secs(5), handle.task).await {
        Ok(Ok(())) => tracing::info!(subsystem = name, "stopped"),
        Ok(Err(e)) => tracing::error!(subsystem = name, error = %e, "panicked during shutdown"),
        Err(_) => tracing::warn!(subsystem = name, "did not stop within 5s timeout"),
    }
}

/// Build the TLS configuration from CLI flags.
///
/// Returns the `TlsConfig` along with the raw PEM strings (needed by
/// enrollment and federation setup).
pub(crate) async fn build_tls_config(
    cli: &Cli,
) -> anyhow::Result<(TlsConfig, String, String, String)> {
    let cert_pem = tokio::fs::read_to_string(&cli.cert)
        .await
        .context("reading server certificate")?;
    let key_pem = tokio::fs::read_to_string(&cli.key)
        .await
        .context("reading server private key")?;
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

    Ok((tls_config, cert_pem, key_pem, ca_pem))
}

/// Bind the TLS listener with a handshake concurrency limit.
///
/// When `cert_reload_interval > 0`, the server uses a [`CertReloader`] as the
/// certificate resolver so that the TLS certificate can be rotated on disk
/// without restarting the server. A background watcher task polls for changes.
pub(crate) async fn bind_tls_listener(
    cli: &Cli,
    tls_config: &TlsConfig,
) -> anyhow::Result<TlsListenerHandle> {
    // Always construct the `CertReloader` when `--cert` and `--key` are
    // configured so that SIGHUP-driven reloads can rotate the certificate
    // regardless of whether the polling watcher is enabled. The polling
    // watcher itself is still only spawned when `cert_reload_interval > 0`.
    let reloader =
        CertReloader::new(&cli.cert, &cli.key).context("initializing certificate reloader")?;

    let verifier = tls_config.build_default_verifier()?;

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
            let subscriber = adapter.subscriber();
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

    let ca_key_pem = tokio::fs::read_to_string(ca_key_path)
        .await
        .context("reading CA private key for enrollment")?;

    let signer =
        rustgate_enrollment::CsrSigner::from_pem(ca_pem, &ca_key_pem, &cli.ca_organization)
            .context("building CSR signer for enrollment")?;
    let credentials = rustgate_enrollment::Credentials::new(
        enrollment_user.to_string(),
        enrollment_password.to_string(),
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

    let mut enrollment_server = rustgate_enrollment::EnrollmentServer::new(signer, credentials)
        .with_contacts_provider(contacts_provider);

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
    let enrollment_key = key_pem.to_string();

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
pub(crate) fn start_metrics(
    cli: &Cli,
    ready: &Arc<AtomicBool>,
    #[cfg(feature = "federation")] fed_api_slot: &Arc<std::sync::OnceLock<metrics::FedApiHandler>>,
    acl_api_slot: &Arc<std::sync::OnceLock<metrics::AclApiHandler>>,
) -> anyhow::Result<Arc<metrics::MetricsIdentity>> {
    metrics::init().context("registering metrics")?;

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

    if let Some(ref metrics_bind) = cli.metrics_bind {
        let bind_addr: std::net::SocketAddr = metrics_bind
            .parse()
            .context("parsing --metrics-bind address")?;

        let health_ready = Arc::clone(ready);
        #[cfg(feature = "federation")]
        let fed_api_for_metrics = Arc::clone(fed_api_slot);
        let acl_api_for_metrics = Arc::clone(acl_api_slot);
        spawn_background("metrics-server", async move {
            if let Err(e) = metrics::serve(
                bind_addr,
                health_ready,
                #[cfg(feature = "federation")]
                fed_api_for_metrics,
                acl_api_for_metrics,
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
        pod_id: cli.federation_pod_id.clone().or_else(|| {
            cli.federation_ha_nats_url
                .as_ref()
                .map(|_| cli.federation_id.clone())
        }),
        ha_nats_url: cli.federation_ha_nats_url.clone(),
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

    // on_inbound: route messages from federation peers to local clients
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
    let ws_listener = rustgate_websocket::WsListener::bind(addr, tls_config)?;
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
        throttle_config,
        replay_filter: replay_filter.clone(),
        circuit_breaker_threshold: cli.circuit_breaker_threshold,
        ws_max_frames_per_sec: cli.ws_max_frames_per_sec,
        ws_max_bytes_per_sec: cli.ws_max_bytes_per_sec,
        ws_max_violations: cli.ws_max_violations,
        shutdown: Arc::clone(&shutdown),
    };
    let task = tokio::spawn(async move {
        rustgate_websocket::WebSocketServer::run(config).await;
    });
    Ok(Some(SubsystemHandle { shutdown, task }))
}

/// Warn when websocket is requested without the feature.
#[cfg(not(feature = "websocket"))]
pub(crate) fn warn_websocket_disabled(cli: &Cli) {
    if cli.websocket_bind.is_some() {
        tracing::warn!("--websocket-bind requires --features websocket; ignoring");
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
        throttle_config,
        archiver: archiver.clone(),
        replay_filter: replay_filter.clone(),
        circuit_breaker_threshold: cli.circuit_breaker_threshold,
        shutdown: shutdown_clone,
        #[cfg(feature = "metrics")]
        metrics_identity: Arc::clone(metrics_identity),
    };

    let task = tokio::spawn(async move {
        crate::session::run_plaintext_tcp(config).await;
    });

    Ok(Some(SubsystemHandle { shutdown, task }))
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

    let config = rustgate_transport::UdpInputConfig {
        cn: cli.plaintext_cn.clone(),
        default_group: cli.plaintext_group.clone(),
    };

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

    Ok(Some(SubsystemHandle { shutdown, task }))
}
