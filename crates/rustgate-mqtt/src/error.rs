//! MQTT-specific error types with protocol reason code mapping.

/// Errors that can occur during MQTT session handling.
#[derive(Debug, thiserror::Error)]
pub enum MqttError {
    /// The client sent an unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocol(u8),

    /// The client requested persistent sessions (clean_session=false).
    #[error("persistent sessions are not supported")]
    PersistentSessionUnsupported,

    /// The client set the will flag, which is not supported in v1.
    #[error("will messages are not supported")]
    WillUnsupported,

    /// The client attempted QoS 2, which is not supported in v1.
    #[error("QoS 2 (exactly-once) is not supported")]
    Qos2Unsupported,

    /// The client is not authorized for the requested topic/action.
    #[error("not authorized for topic: {0}")]
    NotAuthorized(String),

    /// The topic failed validation (wildcards, invalid characters, etc.).
    #[error("invalid topic: {0}")]
    InvalidTopic(String),

    /// A packet exceeded the maximum allowed size.
    #[error("packet too large: {size} bytes exceeds {max} byte limit")]
    PacketTooLarge { size: usize, max: usize },

    /// The client sent a malformed packet.
    #[error("malformed packet: {0}")]
    Malformed(String),

    /// The CONNECT packet was not the first packet on the connection.
    #[error("expected CONNECT as first packet")]
    ConnectExpected,

    /// The MQTT client ID is already in use by a different mTLS identity.
    #[error("client ID `{0}` is already in use by another identity")]
    ClientIdInUse(String),

    /// The keep-alive timer expired without receiving any packet.
    #[error("keep-alive timeout ({0}s)")]
    KeepAliveTimeout(u16),

    /// An I/O error on the underlying TLS stream.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
