// Copyright © 2026 Roberto Chiofalo.

//! Typed failure modes for the OGC SensorThings client.
//!
//! Polling failures fall into three categories: transport (the HTTP
//! request itself failed — DNS, TCP, TLS, or the server hung up),
//! protocol (the server responded but with a non-success status, e.g.
//! 401 / 404 / 5xx), and decode (the body parsed as JSON but did not
//! match the expected SensorThings shape). The wiring task surfaces
//! each variant differently — transport failures back off and retry,
//! decode failures log at warn and skip the offending document so a
//! single malformed observation cannot wedge the polling loop.

use std::time::Duration;

/// Fallible boundary for the SensorThings client and wiring tasks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SensorThingsError {
    /// The HTTP request itself failed before a response body could be
    /// inspected. Wraps the underlying [`reqwest::Error`] for
    /// diagnostics. The wiring task treats this as a transient
    /// failure and applies a backoff before the next poll.
    #[error("SensorThings HTTP request failed: {source}")]
    Transport {
        /// Underlying reqwest error (DNS, TCP, TLS, timeout, …).
        #[source]
        source: reqwest::Error,
    },

    /// The server responded with a non-success HTTP status. Distinct
    /// from `Transport` so the caller can branch on
    /// authentication failures (401), missing resources (404), and
    /// rate-limiting (429) separately from a connection-level
    /// failure.
    #[error("SensorThings server returned HTTP {status}: {message}")]
    HttpStatus {
        /// HTTP status code reported by the server.
        status: u16,
        /// Operator-readable summary — typically the body text or
        /// the status canonical reason. Not used for branching.
        message: String,
    },

    /// The response body failed to deserialize against the expected
    /// SensorThings v1.0 shape. The wiring task logs this at warn
    /// with the URL and skips the offending document; subsequent
    /// polls continue.
    #[error("SensorThings response could not be decoded: {message}")]
    Decode {
        /// Operator-readable description of what failed. Includes
        /// the underlying serde-json line/column when available.
        message: String,
    },

    /// The configured request timed out before the server returned a
    /// complete response. Distinct from `Transport` so the wiring
    /// task can surface "the server is slow" as a different signal
    /// from "the network is broken".
    #[error("SensorThings request timed out after {elapsed:?}")]
    Timeout {
        /// Configured per-request timeout that elapsed without a
        /// response.
        elapsed: Duration,
    },

    /// The configuration is structurally invalid — e.g. the
    /// configured endpoint URL did not parse, the auth-token file
    /// could not be read, or a subscription names a datastream id of
    /// zero. Distinct from the parse-time `serde::Deserialize`
    /// surface (which yields `toml::de::Error` at the binary's
    /// config-load boundary) because the failures captured here
    /// trip at runtime when the wiring task tries to use the
    /// already-parsed config.
    #[error("SensorThings configuration is invalid: {message}")]
    Config {
        /// Human-readable description of the configuration
        /// problem.
        message: String,
    },

    /// The MQTT push broker URI used the `mqtts://` scheme, which
    /// the MVP does not support. TLS for the MQTT push transport
    /// lands in a follow-up alongside CA-pin / mTLS / SNI override
    /// knobs — until then, configuring `mqtts://` fails fast at
    /// startup so operators do not silently fall back to plaintext.
    /// Feature-gated to keep this variant out of builds that have
    /// not opted into the MQTT push path.
    #[cfg(feature = "mqtt-push")]
    #[error(
        "SensorThings MQTT push broker URI uses `mqtts://`; TLS for the push transport is not yet supported (see #1380, follow-up)"
    )]
    MqttsNotSupported,
}

impl SensorThingsError {
    /// Returns `true` when the variant represents a transport-level
    /// failure that benefits from backoff + retry. Drives the
    /// polling task's backoff decision so a 401 / 404 (which will
    /// not get better on the next poll without operator action) is
    /// not retried at the same cadence as a transient TCP reset.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Transport { .. } | Self::Timeout { .. } => true,
            Self::HttpStatus { status, .. } => {
                // 408 Request Timeout, 429 Too Many Requests, 5xx
                // are server-side transient failures. 4xx client
                // errors (other than 408 / 429) are configuration
                // problems and not retryable.
                *status == 408 || *status == 429 || (500..600).contains(status)
            }
            Self::Decode { .. } | Self::Config { .. } => false,
            #[cfg(feature = "mqtt-push")]
            Self::MqttsNotSupported => false,
        }
    }
}
