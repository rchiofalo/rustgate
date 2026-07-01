// Copyright © 2026 Roberto Chiofalo.

//! Reference client library for connecting to a rustgate server.
//!
//! `rustgate-client` provides a small, ergonomic API on top of the same
//! `rustgate-transport` codecs the server uses, so client code does not have
//! to re-implement TLS bring-up, mTLS configuration, framing, or
//! reconnection bookkeeping.
//!
//! ## Quick start
//!
//! ```no_run
//! use bytes::Bytes;
//! use futures::StreamExt;
//! use rustgate_client::{Client, ClientConfig, Codec};
//!
//! # async fn run() -> anyhow::Result<()> {
//! let config = ClientConfig::builder()
//!     .server_addr("127.0.0.1:8089")
//!     .mtls_pem_files("client.crt", "client.key", "ca.crt")
//!     .codec(Codec::LengthPrefixed4)
//!     .build()?;
//!
//! let client = Client::connect(config).await?;
//! let mut stream = client.subscribe();
//!
//! client.send(Bytes::from_static(b"hello")).await?;
//!
//! while let Some(msg) = stream.next().await {
//!     let msg = msg?;
//!     println!("got {} bytes", msg.payload.len());
//! }
//!
//! client.disconnect().await;
//! # Ok(())
//! # }
//! ```
//!
//! ## Wire protocol note
//!
//! The on-wire protocol is opaque framed bytes — the rustgate server
//! determines routing from the sender's certificate OUs, not from any
//! per-message tag. Sent payloads go to whichever destinations the
//! server's routing rules dictate, and subscribers receive every inbound
//! frame on the connection.
//!
//! ## Error handling
//!
//! This crate's error type is [`ClientError`]; downstream applications
//! propagate it via `?` and surface it through `anyhow::Error` (or their
//! own aggregator) at their orchestration layer.
//! [`rustgate_core::error::RustgateError`] is the boundary aggregator
//! used inside the server's `rustgate-core` / `rustgate-transport` slice
//! and is not automatically constructed from [`ClientError`].

#![deny(missing_docs)]

mod connect;
mod reconnect;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use zeroize::Zeroizing;

pub use crate::connect::ConnectOptions;
pub use crate::reconnect::ReconnectPolicy;

/// Errors that can occur while building, connecting, or operating a [`Client`].
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A required field was missing from [`ClientConfig`].
    #[error("client config missing required field: {0}")]
    MissingField(&'static str),

    /// `server_name` is not a valid TLS SNI server name (DNS name or IP
    /// address). Rejected at config build time rather than carried into
    /// the TLS handshake.
    #[error("invalid server_name: {0}")]
    InvalidServerName(String),

    /// I/O failure (TCP, TLS read/write, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// TLS configuration or handshake failure.
    #[error("tls: {0}")]
    Tls(String),

    /// Certificate or key parsing failure.
    #[error("certificate parse error: {0}")]
    CertParse(String),

    /// Secret-file load failed (private key on disk failed the
    /// shared `rustgate_core::secrets::read_secret_file` checks —
    /// size cap, mode 0o077 permission gate, owner UID, or empty file).
    #[error(transparent)]
    SecretFile(#[from] rustgate_core::SecretFileError),

    /// Connect timed out.
    #[error("connect timed out after {0:?}")]
    ConnectTimeout(Duration),

    /// The client has already been disconnected.
    #[error("client is disconnected")]
    Disconnected,

    /// Reconnect attempts were exhausted.
    #[error("reconnect attempts exhausted ({0} attempts)")]
    ReconnectExhausted(u32),

    /// Inbound subscriber lagged behind the broadcast buffer and dropped messages.
    #[error("subscriber lagged and dropped {dropped} messages")]
    Lagged {
        /// Number of messages dropped.
        dropped: u64,
    },
}

/// A `Result` alias parameterised by [`ClientError`].
pub type Result<T> = std::result::Result<T, ClientError>;

/// Wire framing strategy used by both encoder and decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// 1-byte length-prefixed frames.
    LengthPrefixed1,
    /// 2-byte length-prefixed frames.
    LengthPrefixed2,
    /// 4-byte length-prefixed frames (rustgate default).
    LengthPrefixed4,
    /// XML-stream framing (CoT-style).
    XmlStream,
    /// Newline-delimited frames.
    LineDelimited,
}

impl Codec {
    fn to_framed(self) -> rustgate_transport::FramedCodec {
        use rustgate_core::protocol::{FramingStrategy, HeaderSize};
        let strategy = match self {
            Self::LengthPrefixed1 => FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::One,
            },
            Self::LengthPrefixed2 => FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Two,
            },
            Self::LengthPrefixed4 => FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Four,
            },
            Self::XmlStream => FramingStrategy::XmlStream,
            Self::LineDelimited => FramingStrategy::LineDelimited,
        };
        rustgate_transport::FramedCodec::try_from_strategy(&strategy)
            .expect("rustgate-client Codec enum only exposes always-available strategies")
    }
}

/// Source of mTLS material — either filesystem paths or in-memory PEM bytes.
#[derive(Debug, Clone)]
pub enum TlsMaterial {
    /// PEM file paths on disk.
    PemFiles {
        /// Client certificate chain (PEM).
        cert: std::path::PathBuf,
        /// Client private key (PEM).
        key: std::path::PathBuf,
        /// Trusted CA bundle (PEM).
        ca: std::path::PathBuf,
    },
    /// In-memory PEM byte buffers.
    PemBytes {
        /// Client certificate chain.
        cert: Vec<u8>,
        /// Client private key. Zeroized on drop.
        key: Zeroizing<Vec<u8>>,
        /// Trusted CA bundle.
        ca: Vec<u8>,
    },
}

/// Configuration for a [`Client`]. Build with [`ClientConfig::builder`].
#[derive(Clone)]
pub struct ClientConfig {
    pub(crate) server_addr: String,
    pub(crate) server_name: String,
    pub(crate) tls: Option<TlsMaterial>,
    pub(crate) codec: Codec,
    pub(crate) plaintext: bool,
    /// Maximum time to wait for TCP connect + TLS handshake (default: 30 s).
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) reconnect: Option<ReconnectPolicy>,
}

impl ClientConfig {
    /// Start a new builder.
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server_addr", &self.server_addr)
            .field("server_name", &self.server_name)
            .field("tls", &"<redacted>")
            .field("codec", &self.codec)
            .field("plaintext", &self.plaintext)
            .field("connect_timeout", &self.connect_timeout)
            .field("reconnect", &self.reconnect)
            .finish()
    }
}

/// Builder for [`ClientConfig`].
#[derive(Debug, Default)]
pub struct ClientConfigBuilder {
    server_addr: Option<String>,
    server_name: Option<String>,
    tls: Option<TlsMaterial>,
    codec: Option<Codec>,
    plaintext: bool,
    connect_timeout: Option<Duration>,
    reconnect: Option<ReconnectPolicy>,
}

impl ClientConfigBuilder {
    /// Set the `host:port` of the server to dial.
    pub fn server_addr(mut self, addr: impl Into<String>) -> Self {
        self.server_addr = Some(addr.into());
        self
    }

    /// Override the SNI / server name presented during the TLS handshake.
    ///
    /// By default the client derives the server name from `server_addr`:
    ///
    /// * For hostnames, the host portion is used verbatim.
    /// * For IP literals (v4 or v6), the fallback is `"localhost"`,
    ///   because rustls refuses to emit an SNI extension for an IP
    ///   literal and the certificate's Common Name / SubjectAltName is
    ///   validated against this string.
    ///
    /// Call this method when the default derivation is wrong for your
    /// deployment. Common cases:
    ///
    /// * **Host-based routing**: the TCP endpoint is a load balancer
    ///   address (`10.0.0.5:9443`) but the backend certificate is
    ///   issued for a logical name (`tak.example.com`). Passing the
    ///   logical name here makes cert validation succeed.
    /// * **Multi-tenant SNI routing**: a single listener fronts several
    ///   logical services and selects the backend from the SNI hint.
    /// * **Test harnesses** that issue a certificate with a specific
    ///   SubjectAltName that does not match the dial address (e.g. the
    ///   fixtures in `rustgate-test-utils`).
    /// * **Wildcard certificates**: pin the client to one specific name
    ///   rather than whatever the TCP address resolves to.
    ///
    /// Passing a value that does not match any CN / SubjectAltName on
    /// the server certificate causes the TLS handshake to fail. The
    /// name must be a valid DNS name — rustls rejects IP literals
    /// through this channel.
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Configure mTLS using PEM files on disk.
    pub fn mtls_pem_files(
        mut self,
        cert: impl Into<std::path::PathBuf>,
        key: impl Into<std::path::PathBuf>,
        ca: impl Into<std::path::PathBuf>,
    ) -> Self {
        self.tls = Some(TlsMaterial::PemFiles {
            cert: cert.into(),
            key: key.into(),
            ca: ca.into(),
        });
        self
    }

    /// Configure mTLS using in-memory PEM byte buffers.
    pub fn mtls_pem_bytes(mut self, cert: Vec<u8>, key: Vec<u8>, ca: Vec<u8>) -> Self {
        self.tls = Some(TlsMaterial::PemBytes {
            cert,
            key: Zeroizing::new(key),
            ca,
        });
        self
    }

    /// Choose the wire codec. Defaults to [`Codec::LengthPrefixed4`].
    pub fn codec(mut self, codec: Codec) -> Self {
        self.codec = Some(codec);
        self
    }

    /// Disable TLS entirely. Intended for tests against a plaintext listener.
    pub fn plaintext(mut self, plaintext: bool) -> Self {
        self.plaintext = plaintext;
        self
    }

    /// Cap how long [`Client::connect`] will wait before erroring out.
    ///
    /// Defaults to 30 seconds if not set.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Enable auto-reconnect with the given backoff policy.
    pub fn reconnect(mut self, policy: ReconnectPolicy) -> Self {
        self.reconnect = Some(policy);
        self
    }

    /// Finalise the builder. Returns an error if required fields are missing
    /// or if a TLS-required combination is incomplete.
    pub fn build(self) -> Result<ClientConfig> {
        let server_addr = self
            .server_addr
            .ok_or(ClientError::MissingField("server_addr"))?;
        if !self.plaintext && self.tls.is_none() {
            return Err(ClientError::MissingField("tls (or call .plaintext(true))"));
        }
        let server_name = self.server_name.unwrap_or_else(|| {
            server_addr
                .rsplit_once(':')
                .map(|(host, _)| host.to_string())
                .unwrap_or_else(|| "localhost".to_string())
        });
        // Validate the SNI server name up front using rustls's own DNS-name /
        // IP-address parser — the same check the dial path applies — so a
        // malformed or attacker-controlled value (control characters, spaces,
        // path separators, injection attempts) is rejected at config-build
        // time with a clear error instead of being carried into the TLS
        // handshake (#1517). `{server_name:?}` Debug-escapes any control
        // characters so the error itself cannot forge log lines. The parsed
        // `ServerName` is only used to validate; the owned `server_name`
        // string is what we store, so the `Ok` value is intentionally dropped.
        let _ = rustls_pki_types::ServerName::try_from(server_name.as_str())
            .map_err(|e| ClientError::InvalidServerName(format!("{server_name:?}: {e}")))?;
        Ok(ClientConfig {
            server_addr,
            server_name,
            tls: self.tls,
            codec: self.codec.unwrap_or(Codec::LengthPrefixed4),
            plaintext: self.plaintext,
            connect_timeout: self.connect_timeout.or(Some(Duration::from_secs(30))),
            reconnect: self.reconnect,
        })
    }
}

/// A message received from the server.
#[derive(Debug, Clone)]
pub struct Message {
    /// Raw frame bytes as decoded by the configured [`Codec`].
    pub payload: Bytes,
}

type Outbound = Bytes;

/// A connected rustgate client.
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

#[derive(Debug)]
struct ClientInner {
    out_tx: mpsc::Sender<Outbound>,
    inbound: broadcast::Sender<Message>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown: Arc<tokio::sync::Notify>,
    disconnected: Arc<AtomicBool>,
}

impl Client {
    /// Connect to a rustgate server using the supplied configuration.
    ///
    /// On success, spawns background read and write tasks driving the
    /// connection. If `config.reconnect` is set, the read/write loop will
    /// be re-entered on transient I/O errors with exponential backoff.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let (out_tx, out_rx) = mpsc::channel::<Outbound>(64);
        let (in_tx, _) = broadcast::channel::<Message>(256);
        let shutdown = Arc::new(tokio::sync::Notify::new());

        // Establish the initial connection eagerly so callers see connect
        // failures up front rather than as a background error.
        let stream = connect::dial(&config).await?;

        let inbound = in_tx.clone();
        let shutdown_signal = Arc::clone(&shutdown);
        let cfg_for_task = config.clone();
        let disconnected = Arc::new(AtomicBool::new(false));
        let disconnected_for_task = Arc::clone(&disconnected);
        let task = tokio::spawn(async move {
            reconnect::run(
                cfg_for_task,
                stream,
                out_rx,
                inbound,
                shutdown_signal,
                disconnected_for_task,
            )
            .await;
        });

        Ok(Self {
            inner: Arc::new(ClientInner {
                out_tx,
                inbound: in_tx,
                tasks: Mutex::new(vec![task]),
                shutdown,
                disconnected,
            }),
        })
    }

    /// Send a payload to the server.
    pub async fn send(&self, payload: Bytes) -> Result<()> {
        if self.inner.disconnected.load(Ordering::Acquire) {
            return Err(ClientError::Disconnected);
        }
        self.inner
            .out_tx
            .send(payload)
            .await
            .map_err(|_| ClientError::Disconnected)
    }

    /// Subscribe to inbound messages. Returns a stream that yields every
    /// frame the server delivers on this connection.
    ///
    /// Multiple subscribers may coexist; each gets its own independent view
    /// of the inbound stream (broadcast semantics).
    pub fn subscribe(&self) -> impl Stream<Item = Result<Message>> + Send + 'static {
        use futures::StreamExt;
        let rx = self.inner.inbound.subscribe();
        BroadcastStream::new(rx).map(|res| {
            res.map_err(|BroadcastStreamRecvError::Lagged(dropped)| ClientError::Lagged { dropped })
        })
    }

    /// Gracefully disconnect: signal the background loop to shut down,
    /// flush pending writes, send a TLS close_notify, and await tasks.
    pub async fn disconnect(&self) {
        self.inner.disconnected.store(true, Ordering::Release);
        // `notify_one` (not `notify_waiters`) STORES a permit when the run
        // loop is not currently parked on `shutdown.notified()` — e.g. it is
        // mid-`dial()`, or between its per-iteration `disconnected` check and
        // the `select!`. That permit wakes the very next `notified()` poll,
        // closing the lost-wakeup window that could otherwise hang
        // `disconnect().await` on `task.await` for an idle connection
        // (#1497 H-9). Belt-and-suspenders with the `disconnected` flag the
        // run loop re-checks each iteration and after each dial.
        self.inner.shutdown.notify_one();
        let mut tasks = self.inner.tasks.lock().await;
        for task in tasks.drain(..) {
            let _ = task.await;
        }
    }
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        // `notify_one` stores a permit if the run loop is not parked, so the
        // shutdown signal is never lost even if drop races the loop between
        // its select points (#1497 H-9).
        self.shutdown.notify_one();
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use rustgate_core::protocol::{FramingStrategy, HeaderSize};

    use super::*;

    fn minimal_tls_material() -> TlsMaterial {
        // The build() tests only care that *some* TlsMaterial is present;
        // we never actually parse these bytes here. Parse validation lives
        // in `connect.rs::tests`.
        TlsMaterial::PemBytes {
            cert: b"placeholder".to_vec(),
            key: Zeroizing::new(b"placeholder".to_vec()),
            ca: b"placeholder".to_vec(),
        }
    }

    #[test]
    fn builder_requires_server_addr() {
        let err = ClientConfig::builder()
            .plaintext(true)
            .build()
            .expect_err("builder without server_addr must fail");
        match err {
            ClientError::MissingField("server_addr") => {}
            other => panic!("expected MissingField(server_addr), got {other:?}"),
        }
    }

    #[test]
    fn builder_requires_tls_unless_plaintext() {
        let err = ClientConfig::builder()
            .server_addr("example.test:9443")
            .build()
            .expect_err("non-plaintext builder without tls must fail");
        match err {
            // The field message must mention `.plaintext(true)` so users
            // know the escape hatch.
            ClientError::MissingField(msg) => {
                assert!(
                    msg.contains("tls") && msg.contains("plaintext"),
                    "MissingField message should guide user to plaintext(true); got {msg:?}",
                );
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn builder_rejects_invalid_server_name() {
        // #1517: malformed / attacker-controlled SNI values must be rejected
        // at build time, not carried into the TLS handshake.
        for bad in [
            "bad name",      // space
            "evil.com/path", // path separator
            "ctrl\u{0}name", // NUL control char
            "tab\tname",     // tab
            "back\\slash",   // backslash
            "",              // empty
        ] {
            let err = ClientConfig::builder()
                .server_addr("example.test:9443")
                .plaintext(true)
                .server_name(bad)
                .build()
                .expect_err("invalid server_name must be rejected at build");
            assert!(
                matches!(err, ClientError::InvalidServerName(_)),
                "expected InvalidServerName for {bad:?}, got {err:?}",
            );
        }
    }

    #[test]
    fn builder_accepts_valid_server_names() {
        // Valid DNS names AND IP literals must build — validating via rustls's
        // own parser (not a bespoke DNS-only check) keeps IP server names
        // working.
        for ok in [
            "example.com",
            "localhost",
            "test-host",
            "a.b.c.example.org",
            "192.168.1.1",
            "::1",
        ] {
            let cfg = ClientConfig::builder()
                .server_addr("example.test:9443")
                .plaintext(true)
                .server_name(ok)
                .build()
                .unwrap_or_else(|e| panic!("valid server_name {ok:?} must build, got {e:?}"));
            assert_eq!(cfg.server_name, ok);
        }
    }

    #[test]
    fn builder_plaintext_bypasses_tls_requirement() {
        let cfg = ClientConfig::builder()
            .server_addr("example.test:9443")
            .plaintext(true)
            .build()
            .expect("plaintext builder should succeed without TLS material");
        assert!(cfg.plaintext);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn builder_derives_server_name_from_host_portion() {
        let cfg = ClientConfig::builder()
            .server_addr("tak.example.test:9443")
            .mtls_pem_bytes(
                b"placeholder".to_vec(),
                b"placeholder".to_vec(),
                b"placeholder".to_vec(),
            )
            .build()
            .unwrap();
        assert_eq!(cfg.server_name, "tak.example.test");
    }

    #[test]
    fn builder_falls_back_to_localhost_when_addr_has_no_port() {
        // `rsplit_once(':')` returns None for addresses without a colon,
        // so the fallback path triggers. Pins the "localhost" default.
        let cfg = ClientConfig::builder()
            .server_addr("noport")
            .plaintext(true)
            .build()
            .unwrap();
        assert_eq!(cfg.server_name, "localhost");
    }

    #[test]
    fn builder_explicit_server_name_overrides_derivation() {
        let cfg = ClientConfig::builder()
            .server_addr("10.0.0.5:9443")
            .server_name("tak.example.test")
            .plaintext(true)
            .build()
            .unwrap();
        // Host-based routing case from the docstring: explicit SNI must
        // win over the address-derived default.
        assert_eq!(cfg.server_name, "tak.example.test");
    }

    #[test]
    fn builder_defaults_codec_to_length_prefixed4() {
        let cfg = ClientConfig::builder()
            .server_addr("host:1")
            .plaintext(true)
            .build()
            .unwrap();
        assert_eq!(cfg.codec, Codec::LengthPrefixed4);
    }

    #[test]
    fn builder_defaults_connect_timeout_to_thirty_seconds() {
        let cfg = ClientConfig::builder()
            .server_addr("host:1")
            .plaintext(true)
            .build()
            .unwrap();
        assert_eq!(cfg.connect_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn builder_preserves_explicit_codec_and_timeout() {
        let cfg = ClientConfig::builder()
            .server_addr("host:1")
            .plaintext(true)
            .codec(Codec::XmlStream)
            .connect_timeout(Duration::from_millis(750))
            .build()
            .unwrap();
        assert_eq!(cfg.codec, Codec::XmlStream);
        assert_eq!(cfg.connect_timeout, Some(Duration::from_millis(750)));
    }

    #[test]
    fn builder_stores_mtls_pem_bytes_wrapped_in_zeroizing() {
        // The key buffer must be wrapped in `Zeroizing<Vec<u8>>` so it is
        // wiped on drop. Assert on the enum shape — zeroize behaviour
        // itself is covered by the `zeroize` crate's own tests.
        let cfg = ClientConfig::builder()
            .server_addr("host:1")
            .mtls_pem_bytes(vec![0xAA], vec![0xBB], vec![0xCC])
            .build()
            .unwrap();
        match cfg.tls {
            Some(TlsMaterial::PemBytes { cert, key, ca }) => {
                assert_eq!(cert, vec![0xAA]);
                assert_eq!(ca, vec![0xCC]);
                assert_eq!(&**key, &[0xBB]);
            }
            other => panic!("expected PemBytes, got {other:?}"),
        }
    }

    #[test]
    fn builder_stores_mtls_pem_files_as_pathbufs() {
        let cfg = ClientConfig::builder()
            .server_addr("host:1")
            .mtls_pem_files("/tmp/cert.pem", "/tmp/key.pem", "/tmp/ca.pem")
            .build()
            .unwrap();
        match cfg.tls {
            Some(TlsMaterial::PemFiles { cert, key, ca }) => {
                assert_eq!(cert.to_string_lossy(), "/tmp/cert.pem");
                assert_eq!(key.to_string_lossy(), "/tmp/key.pem");
                assert_eq!(ca.to_string_lossy(), "/tmp/ca.pem");
            }
            other => panic!("expected PemFiles, got {other:?}"),
        }
    }

    #[test]
    fn client_config_debug_redacts_tls_material() {
        // Custom `Debug` impl must never expose the TLS material — pins
        // the security contract so a future refactor can't accidentally
        // leak key bytes via `{:?}` formatting in logs or error chains.
        let cfg = ClientConfig {
            server_addr: "host:1".to_string(),
            server_name: "host".to_string(),
            tls: Some(minimal_tls_material()),
            codec: Codec::LengthPrefixed4,
            plaintext: false,
            connect_timeout: Some(Duration::from_secs(30)),
            reconnect: None,
        };
        let rendered = format!("{cfg:?}");
        assert!(
            rendered.contains("<redacted>"),
            "ClientConfig Debug output must redact tls; got {rendered}"
        );
        assert!(
            !rendered.contains("placeholder"),
            "Debug output leaked TLS bytes: {rendered}"
        );
    }

    #[test]
    fn codec_to_framed_maps_every_variant() {
        // The round-trip through `FramingStrategy` is the contract
        // between user-facing `Codec` and internal `FramedCodec` —
        // if a new variant is added, this test forces a conscious
        // mapping decision.
        let cases: &[(Codec, FramingStrategy)] = &[
            (
                Codec::LengthPrefixed1,
                FramingStrategy::LengthPrefixed {
                    header_size: HeaderSize::One,
                },
            ),
            (
                Codec::LengthPrefixed2,
                FramingStrategy::LengthPrefixed {
                    header_size: HeaderSize::Two,
                },
            ),
            (
                Codec::LengthPrefixed4,
                FramingStrategy::LengthPrefixed {
                    header_size: HeaderSize::Four,
                },
            ),
            (Codec::XmlStream, FramingStrategy::XmlStream),
            (Codec::LineDelimited, FramingStrategy::LineDelimited),
        ];
        for (codec, expected) in cases {
            let framed = codec.to_framed();
            let roundtrip = rustgate_transport::FramedCodec::try_from_strategy(expected)
                .expect("expected FramingStrategy is always valid");
            assert_eq!(
                format!("{framed:?}"),
                format!("{roundtrip:?}"),
                "Codec::{codec:?} must map to {expected:?}",
            );
        }
    }
}
