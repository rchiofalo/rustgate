#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "federation")]
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(feature = "federation")]
use std::time::SystemTime;

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::{SinkExt, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing_subscriber::EnvFilter;

mod archive;
mod audit;
#[cfg(feature = "metrics")]
mod metrics;

/// Maximum time to wait for a complete frame from the client.
/// Covers both idle clients and partial-frame stalls (e.g. incomplete XML tag).
const READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Maximum time to wait for a write to complete. Drops slow consumers
/// that can't keep up with outbound message flow.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

use rustgate_core::identity::Identity;
#[cfg(any(feature = "metrics", feature = "federation"))]
use rustgate_core::message::Destination;
#[cfg(feature = "federation")]
use rustgate_core::message::Metadata;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::{FramingStrategy, HeaderSize};
use rustgate_cot::MessageBuilder;
use rustgate_transport::{
    AuthenticatedSession, CotEncoder, FramedCodec, MessageEncoder, RawEncoder, Router,
    SessionHandle, ThrottleConfig, TlsConfig, TlsListener,
};

/// Optional callback for forwarding messages to federation peers.
///
/// The closure receives `(payload, source_groups)` and spawns async work
/// internally (fire-and-forget). Defined unconditionally so the `Option`
/// type is available regardless of feature flags.
type FedForwardFn = Arc<dyn Fn(Bytes, Vec<String>) + Send + Sync>;

/// Shared dependencies passed to each session handler task.
struct SessionDeps<P: NatsPublish> {
    router: Arc<Router>,
    framing: Framing,
    encoding: Encoding,
    nats_publisher: Option<P>,
    fed_forward: Option<FedForwardFn>,
    throttle_config: Option<ThrottleConfig>,
    archiver: Option<Arc<archive::CotArchiver>>,
}

/// Runtime context for a connected session's read/write loops.
struct SessionContext<'a, P: NatsPublish> {
    identity: &'a Identity,
    router: &'a Router,
    framing: &'a FramingStrategy,
    nats_publisher: &'a Option<P>,
    fed_forward: &'a Option<FedForwardFn>,
    throttle: Option<rustgate_transport::ClientThrottle>,
    archiver: &'a Option<Arc<archive::CotArchiver>>,
}

#[derive(Parser)]
#[command(name = "rustgate", about = "Secure tactical message router")]
struct Cli {
    #[arg(short, long, default_value = "0.0.0.0:4433", env = "RUSTGATE_BIND")]
    bind: String,

    #[arg(long, env = "RUSTGATE_CERT")]
    cert: String,

    #[arg(long, env = "RUSTGATE_KEY")]
    key: String,

    #[arg(long, env = "RUSTGATE_CA")]
    ca: String,

    /// Path to PEM-encoded Certificate Revocation List file.
    /// Connections using revoked certificates will be rejected at the TLS handshake.
    #[arg(long, env = "RUSTGATE_CRL")]
    crl: Option<String>,

    /// Require FIPS 140-3 crypto provider. Startup fails if the FIPS provider
    /// is not active. Build with --features fips to enable.
    #[arg(long, default_value_t = false, env = "RUSTGATE_FIPS_REQUIRED")]
    fips_required: bool,

    #[arg(long, value_enum, default_value_t = Framing::Xml, env = "RUSTGATE_FRAMING")]
    framing: Framing,

    #[arg(long, value_enum, default_value_t = Encoding::Raw, env = "RUSTGATE_ENCODING")]
    encoding: Encoding,

    /// NATS server URL (enables NATS bridge when set). Requires --features nats.
    #[arg(long, env = "NATS_URL")]
    nats_url: Option<String>,

    /// Path to NATS credentials file for JWT/NKey auth.
    #[arg(long, env = "NATS_CREDENTIALS")]
    nats_credentials: Option<String>,

    /// Bind address for the enrollment HTTPS server (e.g. 0.0.0.0:8446).
    /// Requires --features enrollment.
    #[arg(long, env = "ENROLLMENT_BIND")]
    enrollment_bind: Option<String>,

    /// Path to the CA private key PEM file (used to sign client CSRs).
    #[arg(long, env = "RUSTGATE_CA_KEY")]
    ca_key: Option<String>,

    /// Username for enrollment HTTP Basic Auth.
    #[arg(long, env = "ENROLLMENT_USER")]
    enrollment_user: Option<String>,

    /// Password for enrollment HTTP Basic Auth.
    #[arg(long, env = "ENROLLMENT_PASSWORD")]
    enrollment_password: Option<String>,

    /// Organization name for issued client certificates.
    #[arg(long, default_value = "rustgate", env = "RUSTGATE_CA_ORG")]
    ca_organization: String,

    /// Directory for data package storage. Enables the Marti sync API
    /// endpoints when set. Requires --features enrollment.
    #[arg(long, env = "DATA_PACKAGE_DIR")]
    data_package_dir: Option<String>,

    /// Bind address for the Prometheus metrics HTTP server (e.g. 0.0.0.0:9090).
    /// Requires --features metrics.
    #[arg(long, env = "METRICS_BIND")]
    metrics_bind: Option<String>,

    /// Maximum concurrent TLS sessions. Prevents resource exhaustion
    /// from connection floods.
    #[arg(long, default_value_t = 1024, env = "RUSTGATE_MAX_CONNECTIONS")]
    max_connections: usize,

    /// Bind address for the WebSocket (wss://) listener (e.g. 0.0.0.0:8443).
    /// Requires --features websocket.
    #[arg(long, env = "WEBSOCKET_BIND")]
    websocket_bind: Option<String>,

    // ── Plaintext input flags ─────────────────────────────────────
    /// Bind address for plaintext TCP input (e.g. 0.0.0.0:8087).
    /// WARNING: connections are NOT encrypted. Use only on trusted networks.
    #[arg(long, env = "RUSTGATE_TCP_BIND")]
    tcp_bind: Option<String>,

    /// Bind address for UDP CoT input (e.g. 0.0.0.0:8087).
    /// WARNING: datagrams are NOT encrypted. Use only on trusted networks.
    #[arg(long, env = "RUSTGATE_UDP_BIND")]
    udp_bind: Option<String>,

    /// Default CN for plaintext (TCP/UDP) clients.
    #[arg(long, default_value = "anonymous", env = "RUSTGATE_PLAINTEXT_CN")]
    plaintext_cn: String,

    /// Default group for plaintext (TCP/UDP) clients.
    #[arg(
        long,
        default_value = "__plaintext__",
        env = "RUSTGATE_PLAINTEXT_GROUP"
    )]
    plaintext_group: String,

    // ── Federation flags ────────────────────────────────────────────
    /// V1 federation listen address (enables federation when set, e.g. 0.0.0.0:9000).
    /// Requires --features federation.
    #[arg(long, env = "FEDERATION_V1_BIND")]
    federation_v1_bind: Option<String>,

    /// V2 gRPC federation listen address (e.g. 0.0.0.0:9001).
    /// Enables V2 gRPC inbound server when set alongside --federation-v1-bind.
    /// Requires --features federation.
    #[arg(long, env = "FEDERATION_V2_BIND")]
    federation_v2_bind: Option<String>,

    /// Unique federation server identity.
    #[arg(long, default_value = "rustgate-federation-1", env = "FEDERATION_ID")]
    federation_id: String,

    /// Path to JSON file containing federation peer configurations.
    #[arg(long, env = "FEDERATION_PEERS_FILE")]
    federation_peers_file: Option<String>,

    /// Skip TLS hostname verification for federation peers.
    #[arg(long, default_value_t = false, env = "FEDERATION_SKIP_HOSTNAME_VERIFY")]
    federation_skip_hostname_verify: bool,

    /// Maximum federation hops before dropping a message (loop prevention).
    #[arg(long, default_value_t = 10, env = "FEDERATION_MAX_HOPS")]
    federation_max_hops: u32,

    /// Path to persistent federate store (JSON file).
    #[arg(long, env = "FEDERATION_STORE_PATH")]
    federation_store_path: Option<String>,

    /// Directory containing additional trusted CA certificates for federation.
    /// PEM/CRT files in this directory are merged with --ca for TLS verification.
    #[arg(long, env = "FEDERATION_TRUST_STORE_DIR")]
    federation_trust_store_dir: Option<String>,

    /// Consecutive send failures before tripping a federation peer's circuit breaker.
    #[arg(
        long,
        default_value_t = 5,
        env = "FEDERATION_CIRCUIT_BREAKER_THRESHOLD"
    )]
    federation_circuit_breaker_threshold: u32,

    /// Seconds to wait after a circuit breaker trips before probing a federation peer.
    #[arg(long, default_value_t = 60, env = "FEDERATION_CIRCUIT_BREAKER_TIMEOUT")]
    federation_circuit_breaker_timeout: u64,

    /// NATS URL for federation HA coordination (enables distributed peer ownership).
    /// When set, only one pod manages each outbound peer in a multi-pod deployment.
    /// Requires --features federation-ha.
    #[arg(long, env = "FEDERATION_HA_NATS_URL")]
    federation_ha_nats_url: Option<String>,

    /// Pod identifier for federation HA mode. Defaults to --federation-id if
    /// --federation-ha-nats-url is set.
    #[arg(long, env = "FEDERATION_POD_ID")]
    federation_pod_id: Option<String>,

    // ── QoS / rate limiting ──────────────────────────────────────────
    /// Maximum sustained messages per second per connected client (0 = disabled).
    #[arg(long, default_value_t = 0, env = "RUSTGATE_CLIENT_MSG_RATE")]
    client_message_rate: u32,

    /// Maximum burst size for per-client rate limiting.
    #[arg(long, default_value_t = 200, env = "RUSTGATE_CLIENT_BURST")]
    client_burst: u32,

    // ── Data retention / archival ─────────────────────────────────────
    /// Directory for CoT event archival (JSONL). Enables structured logging of
    /// all received CoT events to date-stamped files.
    #[arg(long, env = "RUSTGATE_ARCHIVE_DIR")]
    archive_dir: Option<String>,

    /// Maximum age (in hours) for uploaded data packages. Packages older than
    /// this are eligible for cleanup. 0 = no expiration.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_PACKAGE_MAX_AGE_HOURS")]
    package_max_age_hours: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Framing {
    Xml,
    LengthPrefixed,
    Line,
    /// TAK protobuf binary framing (0xBF + varint length). Requires --features proto.
    TakProtobuf,
    /// TAK protocol negotiation: starts XML, upgrades to protobuf if the client requests it.
    /// This is the mode real TAK clients expect. Requires --features proto.
    TakNegotiate,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Encoding {
    Raw,
    Cot,
    /// TAK protobuf encoding (proto <-> XML at session edge). Requires --features proto.
    TakProtobuf,
}

impl From<Framing> for FramingStrategy {
    fn from(f: Framing) -> Self {
        match f {
            Framing::Xml => FramingStrategy::XmlStream,
            Framing::LengthPrefixed => FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Four,
            },
            Framing::Line => FramingStrategy::LineDelimited,
            Framing::TakProtobuf => FramingStrategy::TakProtobuf,
            // TakNegotiate starts as XML; negotiation determines the actual framing.
            // This mapping is used as the initial framing before negotiation runs.
            Framing::TakNegotiate => FramingStrategy::XmlStream,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    #[cfg(feature = "fips")]
    rustgate_transport::install_fips_provider()?;

    if cli.fips_required && !rustgate_transport::is_fips_provider_active() {
        anyhow::bail!(
            "--fips-required is set but FIPS crypto provider is not active. \
             Build with --features fips to enable FIPS 140-3 mode."
        );
    }

    tracing::info!(bind = %cli.bind, "rustgate starting");
    audit::server_started(&cli.bind, env!("CARGO_PKG_VERSION"));

    tokio::runtime::Runtime::new()?.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let cert_pem = tokio::fs::read_to_string(&cli.cert).await?;
    let key_pem = tokio::fs::read_to_string(&cli.key).await?;
    let ca_pem = tokio::fs::read_to_string(&cli.ca).await?;

    let mut tls_config = TlsConfig::from_pem(&cert_pem, &key_pem, &ca_pem)?;

    if let Some(ref crl_path) = cli.crl {
        let crl_pem = tokio::fs::read_to_string(crl_path).await?;
        tls_config = tls_config.with_crls(&crl_pem)?;
    }

    let listener = TlsListener::bind(&cli.bind, &tls_config).await?;
    let framing = cli.framing;
    let encoding = cli.encoding;

    #[cfg(not(feature = "proto"))]
    if matches!(cli.framing, Framing::TakProtobuf | Framing::TakNegotiate)
        || matches!(encoding, Encoding::TakProtobuf)
    {
        anyhow::bail!("TAK protobuf support requires --features proto");
    }

    tracing::info!(addr = %listener.local_addr()?, framing = ?cli.framing, encoding = ?encoding, "listening");

    // Readiness flag: true when accepting connections, false during shutdown.
    // Used by the /readyz health endpoint to signal K8s readiness probes.
    let ready = Arc::new(AtomicBool::new(true));

    // Register Prometheus metrics (cheap; always active when compiled in)
    #[cfg(feature = "metrics")]
    metrics::init().map_err(|e| anyhow::anyhow!("failed to register metrics: {e}"))?;

    // Federation API handler placeholder — populated after federation manager starts.
    #[cfg(all(feature = "metrics", feature = "federation"))]
    let fed_api_slot: Arc<std::sync::OnceLock<metrics::FedApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    // Optionally start the Prometheus metrics / health HTTP server
    #[cfg(feature = "metrics")]
    if let Some(ref metrics_bind) = cli.metrics_bind {
        let bind_addr: std::net::SocketAddr = metrics_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --metrics-bind address: {e}"))?;

        let health_ready = Arc::clone(&ready);
        #[cfg(feature = "federation")]
        let fed_api_for_metrics = Arc::clone(&fed_api_slot);
        drop(tokio::spawn(async move {
            if let Err(e) = metrics::serve(
                bind_addr,
                health_ready,
                #[cfg(feature = "federation")]
                fed_api_for_metrics,
            )
            .await
            {
                tracing::error!(error = %e, "metrics server failed");
            }
        }));
    }

    #[cfg(not(feature = "metrics"))]
    if cli.metrics_bind.is_some() {
        tracing::warn!("--metrics-bind requires --features metrics; ignoring");
    }

    if cli.max_connections == 0 {
        anyhow::bail!("--max-connections must be at least 1");
    }
    let max_connections: u32 = cli
        .max_connections
        .try_into()
        .map_err(|_| anyhow::anyhow!("max_connections must fit in u32 (max {})", u32::MAX))?;
    let router = Arc::new(Router::new());
    let connection_limit = Arc::new(Semaphore::new(max_connections as usize));

    // Optionally connect to NATS for cross-instance message delivery
    #[cfg(feature = "nats")]
    let nats_publisher = if let Some(ref nats_url) = cli.nats_url {
        let config = rustgate_nats::NatsConfig {
            url: nats_url.clone(),
            credentials_file: cli.nats_credentials.clone(),
            ..Default::default()
        };

        match rustgate_nats::NatsAdapter::connect(config).await {
            Ok(adapter) => {
                // Run JetStream replay to populate position cache before accepting clients
                let replay = adapter.jetstream_replay();
                match replay.replay(Arc::clone(&router)).await {
                    Ok(count) => tracing::info!(count, "JetStream SA replay loaded"),
                    Err(e) => {
                        tracing::warn!(error = %e, "JetStream replay failed (continuing without history)")
                    }
                }

                // Spawn NATS subscriber as a background task
                let subscriber = adapter.subscriber();
                let sub_router = Arc::clone(&router);
                drop(tokio::spawn(async move {
                    if let Err(e) = subscriber.run(sub_router).await {
                        tracing::warn!(error = %e, "NATS subscriber ended with error");
                    }
                }));

                Some(adapter.publisher())
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to connect to NATS (continuing without bridge)");
                None
            }
        }
    } else {
        None
    };

    #[cfg(not(feature = "nats"))]
    let nats_publisher: Option<()> = {
        if cli.nats_url.is_some() {
            tracing::warn!("--nats-url requires --features nats; ignoring");
        }
        None
    };

    // Optionally start the enrollment HTTPS server for client certificate provisioning
    #[cfg(feature = "enrollment")]
    if let Some(ref enrollment_bind) = cli.enrollment_bind {
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

        let ca_key_pem = tokio::fs::read_to_string(ca_key_path).await?;

        let signer =
            rustgate_enrollment::CsrSigner::from_pem(&ca_pem, &ca_key_pem, &cli.ca_organization)?;
        let credentials = rustgate_enrollment::Credentials::new(
            enrollment_user.to_string(),
            enrollment_password.to_string(),
        );
        let enrollment_router = Arc::clone(&router);
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

        let mut enrollment_server = rustgate_enrollment::EnrollmentServer::new(signer, credentials)
            .with_contacts_provider(contacts_provider);

        if let Some(ref pkg_dir) = cli.data_package_dir {
            let store =
                rustgate_enrollment::DataPackageStore::new(std::path::PathBuf::from(pkg_dir))
                    .await
                    .map_err(|e| anyhow::anyhow!("data package store: {e}"))?;
            enrollment_server = enrollment_server.with_packages(store);
            tracing::info!(dir = %pkg_dir, "data package storage enabled");
        }

        let bind_addr: std::net::SocketAddr = enrollment_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --enrollment-bind address: {e}"))?;

        let enrollment_cert = cert_pem.clone();
        let enrollment_key = key_pem.clone();

        drop(tokio::spawn(async move {
            if let Err(e) = enrollment_server
                .run(bind_addr, &enrollment_cert, &enrollment_key)
                .await
            {
                tracing::error!(error = %e, "enrollment server failed");
            }
        }));

        tracing::info!(addr = %enrollment_bind, "enrollment server started");
    }

    #[cfg(not(feature = "enrollment"))]
    if cli.enrollment_bind.is_some() {
        tracing::warn!("--enrollment-bind requires --features enrollment; ignoring");
    }

    // Optionally start the federation subsystem for server-to-server message exchange
    #[cfg(feature = "federation")]
    let (fed_forward, fed_shutdown_handle): (
        Option<FedForwardFn>,
        Option<Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>>,
    ) = if let Some(ref v1_bind) = cli.federation_v1_bind {
        let bind_addr: std::net::SocketAddr = v1_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --federation-v1-bind: {e}"))?;

        // Load peers from optional JSON config file
        let peers = if let Some(ref peers_file) = cli.federation_peers_file {
            let data = tokio::fs::read_to_string(peers_file)
                .await
                .map_err(|e| anyhow::anyhow!("read federation peers file: {e}"))?;
            serde_json::from_str::<Vec<rustgate_federation::config::PeerConfig>>(&data)
                .map_err(|e| anyhow::anyhow!("parse federation peers file: {e}"))?
        } else {
            Vec::new()
        };

        let (v2_enabled, v2_listen_addr) = if let Some(ref v2_bind) = cli.federation_v2_bind {
            let addr: std::net::SocketAddr = v2_bind
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid --federation-v2-bind: {e}"))?;
            (true, addr)
        } else {
            (false, "0.0.0.0:9001".parse().expect("valid default addr"))
        };

        let config = rustgate_federation::config::FederationConfig {
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
            pod_id: cli.federation_pod_id.clone().or_else(|| {
                cli.federation_ha_nats_url
                    .as_ref()
                    .map(|_| cli.federation_id.clone())
            }),
            ha_nats_url: cli.federation_ha_nats_url.clone(),
            ..rustgate_federation::config::FederationConfig::default()
        };

        let mut manager = rustgate_federation::manager::FederationManager::new(config);

        // on_inbound: route messages from federation peers to local clients
        let router_for_fed = Arc::clone(&router);
        let on_inbound: rustgate_federation::manager::OnInbound =
            Arc::new(move |peer_cn, payload| {
                let router = Arc::clone(&router_for_fed);
                drop(tokio::spawn(async move {
                    let identity = Identity {
                        cn: peer_cn,
                        fingerprint: String::new(),
                        groups: BTreeSet::new(),
                    };
                    let msg = RoutableMessage {
                        source: identity,
                        destination: Destination::Broadcast,
                        payload,
                        metadata: Metadata {
                            received_at: SystemTime::now(),
                            source_protocol: "federation".into(),
                            message_type: rustgate_core::message::MessageType::Other(
                                "federation".into(),
                            ),
                            ttl: None,
                        },
                    };
                    router.route(msg).await;
                }));
            });

        manager.start(on_inbound).await?;
        tracing::info!(addr = %bind_addr, id = %cli.federation_id, "federation started");

        let rwlock = Arc::new(tokio::sync::RwLock::new(manager));
        let rwlock_for_forward = Arc::clone(&rwlock);

        // Wire up the federation REST API into the metrics HTTP server
        #[cfg(feature = "metrics")]
        {
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

            let rwlock_for_status = Arc::clone(&rwlock);
            let status_fn: Arc<
                dyn Fn() -> rustgate_federation::manager::FederationStatus + Send + Sync,
            > = Arc::new(move || {
                // Use try_read to avoid blocking; return default status if locked
                match rwlock_for_status.try_read() {
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
                }
            });

            let rwlock_for_peer = Arc::clone(&rwlock);
            let peer_status_fn: PeerStatusFn =
                Arc::new(move |id| match rwlock_for_peer.try_read() {
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
        }

        // ── HA adoption / claim-lost handler tasks ───────────────────
        #[cfg(feature = "federation-ha")]
        {
            let (adopt_rx, lost_rx) = {
                let mut mgr = rwlock.write().await;
                mgr.take_ha_receivers()
            };

            if let Some(mut rx) = adopt_rx {
                let inner = Arc::clone(&rwlock);
                drop(tokio::spawn(async move {
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
                }));
            }

            if let Some(mut rx) = lost_rx {
                let inner = Arc::clone(&rwlock);
                drop(tokio::spawn(async move {
                    while let Some(peer_id) = rx.recv().await {
                        tracing::warn!(
                            peer_id = %peer_id,
                            "lost claim — disconnecting peer"
                        );
                        let mut mgr = inner.write().await;
                        mgr.disconnect_peer(&peer_id).await;
                    }
                }));
            }
        }

        let forward_fn: FedForwardFn = Arc::new(move |payload, groups| {
            let inner = Arc::clone(&rwlock_for_forward);
            drop(tokio::spawn(async move {
                let mgr = inner.read().await;
                let _ = mgr.forward(payload, &groups).await;
            }));
        });

        (Some(forward_fn), Some(rwlock))
    } else {
        (None, None)
    };

    #[cfg(not(feature = "federation"))]
    let fed_forward: Option<FedForwardFn> = {
        if cli.federation_v1_bind.is_some() {
            tracing::warn!("--federation-v1-bind requires --features federation; ignoring");
        }
        if cli.federation_v2_bind.is_some() {
            tracing::warn!("--federation-v2-bind requires --features federation; ignoring");
        }
        None
    };

    #[cfg(not(feature = "federation-ha"))]
    if cli.federation_ha_nats_url.is_some() {
        tracing::warn!("--federation-ha-nats-url requires --features federation-ha; ignoring");
    }

    // ── WebSocket listener ──────────────────────────────────────────

    #[cfg(feature = "websocket")]
    let ws_shutdown = if let Some(ref ws_bind) = cli.websocket_bind {
        let addr: std::net::SocketAddr = ws_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid WebSocket bind address: {e}"))?;
        let ws_listener = rustgate_websocket::WsListener::bind(addr, &tls_config)?;
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
                            drop(tokio::spawn(async move { p.publish(&msg).await }));
                        })
                    })
            }
            #[cfg(not(feature = "nats"))]
            {
                None
            }
        };

        let ws_encoding = match encoding {
            Encoding::Raw | Encoding::TakProtobuf => rustgate_websocket::WsEncoding::Raw,
            Encoding::Cot => rustgate_websocket::WsEncoding::Cot,
        };

        let config = rustgate_websocket::WsServerConfig {
            listener: ws_listener,
            router: Arc::clone(&router),
            connection_limit: Arc::clone(&connection_limit),
            encoding: ws_encoding,
            nats_publish: nats_cb,
            fed_forward: fed_forward.clone(),
            shutdown: Arc::clone(&shutdown),
        };
        drop(tokio::spawn(rustgate_websocket::WebSocketServer::run(
            config,
        )));
        Some(shutdown)
    } else {
        None
    };

    #[cfg(not(feature = "websocket"))]
    if cli.websocket_bind.is_some() {
        tracing::warn!("--websocket-bind requires --features websocket; ignoring");
    }

    // ── Per-client rate limiting ─────────────────────────────────────
    let throttle_config = if cli.client_message_rate > 0 {
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
    };

    // ── CoT event archival ───────────────────────────────────────────
    let archiver = if let Some(ref dir) = cli.archive_dir {
        tracing::info!(dir = %dir, "CoT event archival enabled");
        Some(Arc::new(archive::CotArchiver::new(dir)))
    } else {
        None
    };

    // ── Plaintext TCP listener (opt-in, no TLS) ──────────────────

    let tcp_plaintext_shutdown = if let Some(ref tcp_bind) = cli.tcp_bind {
        let addr: std::net::SocketAddr = tcp_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --tcp-bind address: {e}"))?;

        tracing::warn!(addr = %addr, "plaintext TCP input enabled — traffic is NOT encrypted");

        let identity_config = rustgate_transport::PlaintextIdentityConfig {
            cn: cli.plaintext_cn.clone(),
            default_group: cli.plaintext_group.clone(),
        };

        let pt_listener = rustgate_transport::PlaintextListener::bind(addr, identity_config)
            .await
            .map_err(|e| anyhow::anyhow!("plaintext TCP bind failed: {e}"))?;

        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let pt_router = Arc::clone(&router);
        let pt_connection_limit = Arc::clone(&connection_limit);
        let pt_framing = framing;
        let pt_encoding = encoding;
        #[allow(clippy::clone_on_copy)]
        let pt_nats = nats_publisher.clone();
        let pt_fed = fed_forward.clone();

        drop(tokio::spawn(async move {
            run_plaintext_tcp(
                pt_listener,
                pt_router,
                pt_connection_limit,
                pt_framing,
                pt_encoding,
                pt_nats,
                pt_fed,
                shutdown_clone,
            )
            .await;
        }));

        Some(shutdown)
    } else {
        None
    };

    // ── UDP input listener (opt-in, no TLS) ──────────────────────

    let udp_shutdown = if let Some(ref udp_bind) = cli.udp_bind {
        let addr: std::net::SocketAddr = udp_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --udp-bind address: {e}"))?;

        tracing::warn!(addr = %addr, "UDP input enabled — datagrams are NOT encrypted");

        let socket = tokio::net::UdpSocket::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("UDP bind failed: {e}"))?;

        let config = rustgate_transport::UdpInputConfig {
            cn: cli.plaintext_cn.clone(),
            default_group: cli.plaintext_group.clone(),
        };

        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let udp_router = Arc::clone(&router);

        let udp_nats_cb: Option<rustgate_transport::udp::OnNatsPublish> = {
            #[cfg(feature = "nats")]
            {
                nats_publisher
                    .clone()
                    .map(|p| -> rustgate_transport::udp::OnNatsPublish {
                        Arc::new(move |msg| {
                            let p = p.clone();
                            drop(tokio::spawn(async move { p.publish(&msg).await }));
                        })
                    })
            }
            #[cfg(not(feature = "nats"))]
            {
                None
            }
        };

        let udp_fed: Option<rustgate_transport::udp::OnFederationForward> = fed_forward
            .clone()
            .map(|fwd| -> rustgate_transport::udp::OnFederationForward {
                Arc::new(move |payload, groups| {
                    fwd(payload, groups);
                })
            });

        drop(tokio::spawn(async move {
            rustgate_transport::UdpInput::run(
                socket,
                udp_router,
                config,
                udp_nats_cb,
                udp_fed,
                shutdown_clone,
            )
            .await;
        }));

        Some(shutdown)
    } else {
        None
    };

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        #[cfg(feature = "metrics")]
                        {
                            metrics::connections_accepted().inc();
                            metrics::connections_active().inc();
                        }

                        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                #[cfg(feature = "metrics")]
                                {
                                    metrics::connections_rejected().inc();
                                    metrics::connections_active().dec();
                                }
                                tracing::warn!(max = max_connections, "connection limit reached, rejecting");
                                audit::connection_rejected(session.peer_addr(), "connection limit reached");
                                continue;
                            }
                        };
                        let router = Arc::clone(&router);
                        #[allow(clippy::clone_on_copy)] // Type varies by feature flag
                        let publisher = nats_publisher.clone();
                        let fed = fed_forward.clone();
                        let tc = throttle_config;
                        let arch = archiver.clone();
                        let deps = SessionDeps {
                            router,
                            framing,
                            encoding,
                            nats_publisher: publisher,
                            fed_forward: fed,
                            throttle_config: tc,
                            archiver: arch,
                        };
                        drop(tokio::spawn(handle_session(session, deps, permit)));
                    }
                    Err(e) => {
                        #[cfg(feature = "metrics")]
                        metrics::accept_errors().inc();
                        tracing::warn!(error = %e, "accept error");
                    }
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal received");
                // Immediately mark as not-ready so the K8s readiness probe
                // returns 503 and the load balancer stops routing traffic
                // before we begin draining existing connections.
                ready.store(false, Ordering::Release);
                break;
            }
        }
    }

    // ── Federation shutdown ──────────────────────────────────────────

    #[cfg(feature = "federation")]
    if let Some(ref rwlock) = fed_shutdown_handle {
        let mut mgr = rwlock.write().await;
        mgr.shutdown().await;
        tracing::info!("federation shut down");
    }

    // ── WebSocket shutdown ────────────────────────────────────────────

    #[cfg(feature = "websocket")]
    if let Some(ref shutdown) = ws_shutdown {
        shutdown.notify_one();
        tracing::info!("WebSocket server signaled to stop");
    }

    // ── Plaintext TCP/UDP shutdown ──────────────────────────────────

    if let Some(ref shutdown) = tcp_plaintext_shutdown {
        shutdown.notify_one();
        tracing::info!("plaintext TCP listener signaled to stop");
    }
    if let Some(ref shutdown) = udp_shutdown {
        shutdown.notify_one();
        tracing::info!("UDP input signaled to stop");
    }

    // ── Connection draining ──────────────────────────────────────────

    let active = router.session_count().await;
    tracing::info!(sessions = active, "draining connections");

    // Wait for every session to finish (each holds a semaphore permit).
    // When all permits return to the semaphore, all sessions are done.
    // Leave 10 s margin inside the default K8s terminationGracePeriodSeconds (120 s).
    let drain_timeout = Duration::from_secs(110);
    let drain = connection_limit.acquire_many(max_connections);

    match tokio::time::timeout(drain_timeout, drain).await {
        Ok(Ok(_permits)) => tracing::info!("all sessions drained"),
        Ok(Err(_)) => tracing::warn!("semaphore closed during drain"),
        Err(_) => {
            tracing::warn!(
                sessions = router.session_count().await,
                "drain timeout reached, forcing exit"
            );
        }
    }

    Ok(())
}

/// Wait for SIGTERM or SIGINT (Ctrl-C).
///
/// K8s sends SIGTERM during pod eviction; SIGINT covers local development.
/// On non-Unix platforms only Ctrl-C is available.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn handle_session<P: NatsPublish + Send + Sync + 'static>(
    session: AuthenticatedSession,
    deps: SessionDeps<P>,
    _permit: OwnedSemaphorePermit, // Held for session lifetime; released on drop
) {
    let identity = session.identity_arc();
    let cn = identity.cn.clone();

    tracing::info!(cn = %cn, peer = %session.peer_addr(), "connected");
    audit::client_connected(&cn, session.peer_addr(), &identity.fingerprint);

    #[cfg(feature = "metrics")]
    metrics::sessions_active().inc();

    let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
    let handle = SessionHandle::new(Arc::clone(&identity), tx);
    let session_id = handle.id;
    deps.router.register(handle.clone()).await;
    deps.router.replay_positions(&handle).await;

    #[allow(unused_mut)] // Mutable borrows needed for proto negotiation
    let (mut reader, mut writer) = session.split();

    // Run protocol negotiation for TakNegotiate mode.
    // This may upgrade both framing and encoding from XML to protobuf.
    let (final_framing, final_encoding, read_buf) = match deps.framing {
        #[cfg(feature = "proto")]
        Framing::TakNegotiate => {
            match negotiate_tak_protocol(&mut reader, &mut writer, &cn).await {
                Ok(result) => {
                    let protocol = if matches!(result.1, Encoding::TakProtobuf) {
                        "protobuf"
                    } else {
                        "xml"
                    };
                    #[cfg(feature = "metrics")]
                    metrics::negotiations().with_label_values(&[protocol]).inc();
                    audit::negotiation_result(&cn, protocol, true);
                    result
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    metrics::negotiations().with_label_values(&["failed"]).inc();
                    tracing::debug!(cn = %cn, error = %e, "negotiation failed");
                    audit::negotiation_result(&cn, "tak", false);
                    deps.router.unregister(&cn, session_id).await;
                    #[cfg(feature = "metrics")]
                    {
                        metrics::sessions_active().dec();
                        metrics::connections_active().dec();
                    }
                    audit::client_disconnected(&cn);
                    tracing::info!(cn = %cn, "disconnected");
                    return;
                }
            }
        }
        _ => {
            let fs = FramingStrategy::from(deps.framing);
            (fs, deps.encoding, tokio_util::bytes::BytesMut::new())
        }
    };

    let throttle = deps.throttle_config.map(|tc| tc.build());
    let ctx = SessionContext {
        identity: &identity,
        router: &deps.router,
        framing: &final_framing,
        nats_publisher: &deps.nats_publisher,
        fed_forward: &deps.fed_forward,
        throttle,
        archiver: &deps.archiver,
    };

    let result = match final_encoding {
        Encoding::Raw => run_session_loops(reader, writer, rx, &ctx, &RawEncoder, read_buf).await,
        Encoding::Cot => run_session_loops(reader, writer, rx, &ctx, &CotEncoder, read_buf).await,
        #[cfg(feature = "proto")]
        Encoding::TakProtobuf => {
            run_session_loops(
                reader,
                writer,
                rx,
                &ctx,
                &rustgate_proto::TakProtobufEncoder,
                read_buf,
            )
            .await
        }
        #[cfg(not(feature = "proto"))]
        Encoding::TakProtobuf => {
            tracing::error!("--encoding tak-protobuf requires --features proto");
            return;
        }
    };

    if let Err(e) = result {
        tracing::debug!(cn = %cn, error = %e, "session error");
    }

    deps.router.unregister(&cn, session_id).await;
    #[cfg(feature = "metrics")]
    {
        metrics::sessions_active().dec();
        metrics::connections_active().dec();
    }
    audit::client_disconnected(&cn);
    tracing::info!(cn = %cn, "disconnected");
}

/// TAK protocol negotiation handshake.
///
/// Sends TakProtocolSupport advertisement, then peeks the first byte of the
/// client's response. If 0xBF (protobuf magic), completes the handshake and
/// upgrades to protobuf. Otherwise, stays XML.
///
/// Returns (final_framing, final_encoding, buffered_read_bytes).
#[cfg(feature = "proto")]
async fn negotiate_tak_protocol(
    reader: &mut rustgate_transport::SessionReader,
    writer: &mut rustgate_transport::SessionWriter,
    cn: &str,
) -> std::io::Result<(FramingStrategy, Encoding, tokio_util::bytes::BytesMut)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::bytes::BufMut;

    let server_uid = format!("rustgate-{cn}");

    // Step 1: Send TakProtocolSupport XML advertisement
    let advert = rustgate_proto::build_protocol_support_xml(&server_uid);
    writer.write_all(&advert).await?;
    writer.flush().await?;

    tracing::debug!(cn = %cn, "sent TakProtocolSupport advertisement");

    // Step 2: Peek the first byte to determine if client wants protobuf
    let mut peek = [0u8; 1];
    let n = reader.read(&mut peek).await?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client disconnected during negotiation",
        ));
    }

    if peek[0] == 0xBF {
        // Client is requesting protobuf upgrade.
        // Magic byte already consumed; read_tak_request handles varint + payload + validation.
        rustgate_proto::read_tak_request(reader).await?;

        tracing::info!(cn = %cn, "client requested protobuf upgrade");

        // Step 3: Send TakResponse (0xBF-framed TakControl acknowledgement)
        let response = rustgate_proto::build_tak_response();
        writer.write_all(&response).await?;
        writer.flush().await?;

        tracing::info!(cn = %cn, "protobuf negotiation complete");

        Ok((
            FramingStrategy::TakProtobuf,
            Encoding::TakProtobuf,
            tokio_util::bytes::BytesMut::new(),
        ))
    } else {
        // Client sent XML (legacy mode). Preserve the byte we already read.
        tracing::info!(cn = %cn, "client staying XML (no protobuf request)");

        let mut buf = tokio_util::bytes::BytesMut::with_capacity(64);
        buf.put_u8(peek[0]);
        Ok((FramingStrategy::XmlStream, Encoding::Cot, buf))
    }
}

async fn run_session_loops(
    reader: rustgate_transport::SessionReader,
    writer: rustgate_transport::SessionWriter,
    rx: mpsc::Receiver<RoutableMessage>,
    ctx: &SessionContext<'_, impl NatsPublish>,
    encoder: &impl MessageEncoder,
    read_buf: tokio_util::bytes::BytesMut,
) -> std::io::Result<()> {
    tokio::select! {
        r = read_loop(reader, ctx.identity, ctx.router, ctx.framing, ctx.nats_publisher, ctx.fed_forward, &ctx.throttle, ctx.archiver, read_buf) => r,
        r = write_loop(writer, rx, ctx.framing, encoder) => r,
    }
}

#[allow(clippy::too_many_arguments)]
async fn read_loop(
    reader: rustgate_transport::SessionReader,
    identity: &Identity,
    router: &Router,
    framing: &FramingStrategy,
    nats_publisher: &Option<impl NatsPublish>,
    fed_forward: &Option<FedForwardFn>,
    throttle: &Option<rustgate_transport::ClientThrottle>,
    archiver: &Option<Arc<archive::CotArchiver>>,
    prefix: tokio_util::bytes::BytesMut,
) -> std::io::Result<()> {
    let is_proto = matches!(framing, FramingStrategy::TakProtobuf);
    let codec = FramedCodec::from_strategy(framing);

    // When negotiation consumed a peek byte and fell back to XML,
    // we need to feed that byte to the codec before reading from the socket.
    let mut framed = if prefix.is_empty() {
        FramedRead::new(PrefixedReader::new(reader, None), codec)
    } else {
        FramedRead::new(PrefixedReader::new(reader, Some(prefix)), codec)
    };

    let mut msg_builder = MessageBuilder::new();

    loop {
        let frame = match tokio::time::timeout(READ_TIMEOUT, framed.next()).await {
            Ok(Some(result)) => result?,
            Ok(None) => break, // EOF — client closed cleanly
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read timeout: no complete frame received",
                ));
            }
        };

        // For protobuf sessions, convert proto -> XML to get the canonical format.
        // The RoutableMessage payload is always XML.
        let payload = if is_proto {
            #[cfg(feature = "proto")]
            {
                let xml_bytes = rustgate_proto::proto_to_xml(&frame)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Bytes::from(xml_bytes)
            }
            #[cfg(not(feature = "proto"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TakProtobuf framing requires the `proto` feature",
                ));
            }
        } else {
            frame.freeze()
        };

        #[cfg(feature = "metrics")]
        metrics::messages_received().inc();

        // Per-client rate limiting — drop excess messages
        if let Some(t) = throttle
            && !t.allow()
        {
            tracing::debug!(cn = %identity.cn, "message dropped: rate limit exceeded");
            #[cfg(feature = "metrics")]
            metrics::messages_dropped().inc();
            continue;
        }

        let msg = msg_builder.build(identity, payload, "tcp");

        // Archive to JSONL if enabled
        if let Some(arch) = archiver {
            arch.record(&msg).await;
        }

        #[cfg(feature = "metrics")]
        {
            let dest_label = match msg.destination {
                Destination::Broadcast => "broadcast",
                Destination::Group(_) => "group",
                Destination::Direct(_) => "direct",
            };
            metrics::messages_routed()
                .with_label_values(&[dest_label])
                .inc();
        }

        router.route(msg.clone()).await;

        // Publish to NATS after local routing (fire-and-forget)
        if let Some(publisher) = nats_publisher {
            #[cfg(feature = "metrics")]
            metrics::nats_publishes().inc();
            publisher.publish(&msg).await;
        }

        // Forward to federation peers (fire-and-forget)
        if let Some(fwd) = fed_forward {
            let groups: Vec<String> = msg.source.groups.iter().cloned().collect();
            fwd(msg.payload.clone(), groups);
        }
    }

    Ok(())
}

async fn write_loop(
    writer: rustgate_transport::SessionWriter,
    mut rx: mpsc::Receiver<RoutableMessage>,
    framing: &FramingStrategy,
    encoder: &impl MessageEncoder,
) -> std::io::Result<()> {
    let mut framed = FramedWrite::new(writer, FramedCodec::from_strategy(framing));

    while let Some(msg) = rx.recv().await {
        let encoded = encoder.encode(&msg)?;
        let send_fut = framed.send(tokio_util::bytes::BytesMut::from(encoded.as_ref()));

        match tokio::time::timeout(WRITE_TIMEOUT, send_fut).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "write timeout: slow consumer",
                ));
            }
        }
    }

    Ok(())
}

/// Accept loop for plaintext TCP connections.
///
/// Mirrors the main TLS accept loop but operates on unencrypted sockets.
/// Each connection gets a synthetic identity and participates in the same
/// router, NATS bridge, and federation forwarding as TLS sessions.
#[allow(clippy::too_many_arguments)]
async fn run_plaintext_tcp<P: NatsPublish + Send + Sync + 'static>(
    listener: rustgate_transport::PlaintextListener,
    router: Arc<Router>,
    connection_limit: Arc<Semaphore>,
    framing: Framing,
    encoding: Encoding,
    nats_publisher: Option<P>,
    fed_forward: Option<FedForwardFn>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!("plaintext TCP: connection limit reached, rejecting");
                                continue;
                            }
                        };

                        let identity = Arc::new(session.identity().clone());
                        let cn = identity.cn.clone();
                        let peer_addr = session.peer_addr();

                        tracing::info!(cn = %cn, peer = %peer_addr, "plaintext TCP connected");

                        let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
                        let handle = SessionHandle::new(Arc::clone(&identity), tx);
                        let session_id = handle.id;
                        router.register(handle.clone()).await;
                        router.replay_positions(&handle).await;

                        let (reader, writer) = session.into_split();

                        let session_router = Arc::clone(&router);
                        let fs = FramingStrategy::from(framing);
                        #[allow(clippy::clone_on_copy)]
                        let session_nats = nats_publisher.clone();
                        let session_fed = fed_forward.clone();

                        drop(tokio::spawn(async move {
                            let _permit = permit;

                            let result = run_plaintext_session_loops(
                                reader, writer, rx, &identity, &session_router,
                                &fs, encoding, &session_nats, &session_fed,
                            ).await;

                            if let Err(e) = result {
                                tracing::debug!(cn = %cn, error = %e, "plaintext TCP session error");
                            }

                            session_router.unregister(&cn, session_id).await;
                            tracing::info!(cn = %cn, "plaintext TCP disconnected");
                        }));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "plaintext TCP accept error");
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("plaintext TCP listener stopping");
                break;
            }
        }
    }
}

/// Read/write loops for a plaintext TCP session.
///
/// Uses the same codec and encoder pipeline as TLS sessions but operates
/// on a raw `TcpStream` split.
#[allow(clippy::too_many_arguments)]
async fn run_plaintext_session_loops<P: NatsPublish>(
    reader: tokio::io::ReadHalf<tokio::net::TcpStream>,
    writer: tokio::io::WriteHalf<tokio::net::TcpStream>,
    mut rx: mpsc::Receiver<RoutableMessage>,
    identity: &Identity,
    router: &Router,
    framing: &FramingStrategy,
    encoding: Encoding,
    nats_publisher: &Option<P>,
    fed_forward: &Option<FedForwardFn>,
) -> std::io::Result<()> {
    let codec = FramedCodec::from_strategy(framing);
    let mut framed_read = FramedRead::new(reader, codec);
    let mut msg_builder = MessageBuilder::new();

    let write_codec = FramedCodec::from_strategy(framing);
    let mut framed_write = FramedWrite::new(writer, write_codec);

    let encoder: Box<dyn MessageEncoder + Send + Sync> = match encoding {
        Encoding::Raw | Encoding::TakProtobuf => Box::new(RawEncoder),
        Encoding::Cot => Box::new(CotEncoder),
    };

    tokio::select! {
        r = async {
            loop {
                let frame = match tokio::time::timeout(READ_TIMEOUT, framed_read.next()).await {
                    Ok(Some(result)) => result?,
                    Ok(None) => break,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "read timeout",
                        ));
                    }
                };

                let payload = frame.freeze();
                let msg = msg_builder.build(identity, payload, "tcp-plaintext");
                router.route(msg.clone()).await;

                if let Some(publisher) = nats_publisher {
                    publisher.publish(&msg).await;
                }

                if let Some(fwd) = fed_forward {
                    let groups: Vec<String> = msg.source.groups.iter().cloned().collect();
                    fwd(msg.payload.clone(), groups);
                }
            }
            Ok(())
        } => r,
        r = async {
            while let Some(msg) = rx.recv().await {
                let encoded = encoder.encode(&msg)?;
                let send_fut = framed_write.send(tokio_util::bytes::BytesMut::from(encoded.as_ref()));
                match tokio::time::timeout(WRITE_TIMEOUT, send_fut).await {
                    Ok(result) => result?,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "write timeout: slow consumer",
                        ));
                    }
                }
            }
            Ok(())
        } => r,
    }
}

/// AsyncRead wrapper that yields prefix bytes before delegating to the inner reader.
///
/// Used after protocol negotiation to feed the peeked byte back to the codec
/// when the client stays in XML mode.
struct PrefixedReader<R> {
    inner: R,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<R> PrefixedReader<R> {
    fn new(inner: R, prefix: Option<tokio_util::bytes::BytesMut>) -> Self {
        let prefix = prefix.map_or_else(Vec::new, |b| b.to_vec());
        Self {
            inner,
            prefix,
            prefix_pos: 0,
        }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain prefix bytes first
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Trait for optional NATS publishing. Allows the server to compile with or
/// without the `nats` feature by abstracting over the publisher type.
trait NatsPublish: Clone {
    fn publish(&self, msg: &RoutableMessage) -> impl std::future::Future<Output = ()> + Send;
}

#[cfg(feature = "nats")]
impl NatsPublish for rustgate_nats::NatsPublisher {
    async fn publish(&self, msg: &RoutableMessage) {
        self.publish(msg).await;
    }
}

/// No-op publisher used when NATS is not enabled.
impl NatsPublish for () {
    async fn publish(&self, _msg: &RoutableMessage) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_defaults() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert_eq!(cli.bind, "0.0.0.0:4433");
        assert_eq!(cli.max_connections, 1024);
    }

    #[test]
    fn cli_max_connections_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--max-connections",
            "512",
        ])
        .expect("should parse");
        assert_eq!(cli.max_connections, 512);
    }

    #[test]
    fn cli_rejects_non_numeric_max_connections() {
        let result = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--max-connections",
            "abc",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_metrics_bind_optional() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(cli.metrics_bind.is_none());

        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--metrics-bind",
            "0.0.0.0:9090",
        ])
        .expect("should parse");
        assert_eq!(cli.metrics_bind.as_deref(), Some("0.0.0.0:9090"));
    }

    #[test]
    fn cli_env_vars_declared() {
        // Verify all expected env vars appear in clap's help output.
        // This ensures the env = "..." attributes are wired up correctly.
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();

        let expected_env_vars = [
            "RUSTGATE_BIND",
            "RUSTGATE_CERT",
            "RUSTGATE_KEY",
            "RUSTGATE_CA",
            "RUSTGATE_FRAMING",
            "RUSTGATE_ENCODING",
            "NATS_URL",
            "NATS_CREDENTIALS",
            "ENROLLMENT_BIND",
            "RUSTGATE_CA_KEY",
            "ENROLLMENT_USER",
            "ENROLLMENT_PASSWORD",
            "RUSTGATE_CA_ORG",
            "DATA_PACKAGE_DIR",
            "METRICS_BIND",
            "RUSTGATE_MAX_CONNECTIONS",
            "FEDERATION_V1_BIND",
            "FEDERATION_V2_BIND",
            "FEDERATION_ID",
            "FEDERATION_PEERS_FILE",
            "FEDERATION_SKIP_HOSTNAME_VERIFY",
            "FEDERATION_MAX_HOPS",
            "FEDERATION_STORE_PATH",
        ];

        for var in expected_env_vars {
            assert!(
                help.contains(var),
                "expected env var {var} not found in help output"
            );
        }
    }

    #[test]
    fn cli_all_flags_have_long_option() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        for arg in cmd.get_arguments() {
            if arg.get_id() == "help" || arg.get_id() == "version" {
                continue;
            }
            assert!(
                arg.get_long().is_some(),
                "arg {:?} missing --long flag",
                arg.get_id()
            );
        }
    }

    #[test]
    fn cli_federation_defaults() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(cli.federation_v1_bind.is_none());
        assert!(cli.federation_v2_bind.is_none());
        assert_eq!(cli.federation_id, "rustgate-federation-1");
        assert!(cli.federation_peers_file.is_none());
        assert!(!cli.federation_skip_hostname_verify);
        assert_eq!(cli.federation_max_hops, 10);
        assert!(cli.federation_store_path.is_none());
    }

    #[test]
    fn cli_federation_bind_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--federation-v1-bind",
            "0.0.0.0:9000",
            "--federation-v2-bind",
            "0.0.0.0:9001",
            "--federation-id",
            "my-fed-server",
            "--federation-max-hops",
            "5",
        ])
        .expect("should parse");
        assert_eq!(cli.federation_v1_bind.as_deref(), Some("0.0.0.0:9000"));
        assert_eq!(cli.federation_v2_bind.as_deref(), Some("0.0.0.0:9001"));
        assert_eq!(cli.federation_id, "my-fed-server");
        assert_eq!(cli.federation_max_hops, 5);
    }

    #[test]
    fn cli_federation_skip_hostname_verify() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--federation-skip-hostname-verify",
        ])
        .expect("should parse");
        assert!(cli.federation_skip_hostname_verify);
    }
}
