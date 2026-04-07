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

    /// I/O failure (TCP, TLS read/write, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// TLS configuration or handshake failure.
    #[error("tls: {0}")]
    Tls(String),

    /// Certificate or key parsing failure.
    #[error("certificate parse error: {0}")]
    CertParse(String),

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
        rustgate_transport::FramedCodec::from_strategy(&strategy)
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
    /// Defaults to the hostname portion of `server_addr`, falling back to
    /// `"localhost"` for IP addresses.
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
        Ok(ClientConfig {
            server_addr,
            server_name,
            tls: self.tls,
            codec: self.codec.unwrap_or(Codec::LengthPrefixed4),
            plaintext: self.plaintext,
            connect_timeout: self.connect_timeout,
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
    disconnected: AtomicBool,
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
        let task = tokio::spawn(async move {
            reconnect::run(cfg_for_task, stream, out_rx, inbound, shutdown_signal).await;
        });

        Ok(Self {
            inner: Arc::new(ClientInner {
                out_tx,
                inbound: in_tx,
                tasks: Mutex::new(vec![task]),
                shutdown,
                disconnected: AtomicBool::new(false),
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
        self.inner.shutdown.notify_waiters();
        let mut tasks = self.inner.tasks.lock().await;
        for task in tasks.drain(..) {
            let _ = task.await;
        }
    }
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
    }
}
