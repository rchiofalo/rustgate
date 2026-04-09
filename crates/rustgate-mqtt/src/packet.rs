//! MQTT packet framing over TLS streams.
//!
//! Wraps [`mqttbytes`] for codec operations and provides async read/write
//! helpers over [`tokio_rustls`] TLS streams. Supports both MQTT 5.0 and
//! 3.1.1 packet formats, selected per-session based on the CONNECT packet's
//! protocol level byte.
