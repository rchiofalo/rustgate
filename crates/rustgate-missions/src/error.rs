// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Error types for the data-package store.
//!
//! Every fallible operation in this crate returns [`MissionsError`].
//! The variants are deliberately concrete (`Io`, `Json`, `Hmac`,
//! `Manifest`, …) instead of a single opaque `Other` so the HTTP
//! layer in `rustgate-admin` can map them to RFC-7807 status codes
//! without string-matching.

use std::path::PathBuf;

use rustgate_core::crypto::HmacError;
use thiserror::Error;

/// All errors returned by the data-package store.
#[derive(Debug, Error)]
pub enum MissionsError {
    /// Filesystem-level failure (create-dir, read, write, rename,
    /// remove). The wrapped path is included in the display so
    /// operators can distinguish between a missing base directory
    /// and a missing sidecar.
    #[error("io error on {path}: {source}")]
    Io {
        /// Path that was being touched when the error occurred.
        path: PathBuf,
        /// Underlying [`std::io::Error`].
        #[source]
        source: std::io::Error,
    },

    /// JSON serialisation/deserialisation of the metadata sidecar
    /// failed. Triggered if a sidecar was hand-edited to an invalid
    /// shape, or if a future schema added a required field that the
    /// running binary does not recognise.
    #[error("metadata json error: {0}")]
    Json(#[from] serde_json::Error),

    /// HMAC tag computation or verification failed. A failure here
    /// means either the integrity key was empty (configuration
    /// error) or the tag stored in the sidecar does not match the
    /// metadata bytes (post-upload tampering). The download path
    /// returns this error and refuses to serve the body.
    #[error("integrity tag failure: {0}")]
    Hmac(#[from] HmacError),

    /// The supplied SHA-256 hash string was not exactly 64 lowercase
    /// hex characters. Surfaced for any operation that takes a
    /// caller-supplied hash (`download`, `delete`, `metadata`).
    /// Distinct from [`MissionsError::NotFound`] so the HTTP layer
    /// can return `400 Bad Request` for a malformed hash and
    /// `404 Not Found` for a well-formed hash that was never stored.
    #[error("invalid hash format: must be 64 lowercase hex characters")]
    InvalidHash,

    /// No package matched the supplied hash. Distinct from
    /// [`MissionsError::Io`] so the HTTP layer can return a clean
    /// 404 instead of leaking filesystem details to the client.
    #[error("package {hash} not found")]
    NotFound {
        /// The hash that was looked up.
        hash: String,
    },

    /// Upload was empty (zero bytes). Most TAK clients refuse to
    /// produce an empty Mission Package, so this almost always
    /// indicates a malformed multipart body.
    #[error("empty upload payload")]
    EmptyUpload,

    /// Upload would push a single package past
    /// [`crate::StoreLimits::max_package_bytes`]. The error carries
    /// both the offered size and the configured cap so operators can
    /// see whether to bump the cap or chunk the upload.
    #[error("package size {actual} exceeds per-package cap {limit}")]
    PackageTooLarge {
        /// Size of the rejected upload in bytes.
        actual: u64,
        /// Configured cap in bytes.
        limit: u64,
    },

    /// Upload would push the total on-disk store past
    /// [`crate::StoreLimits::max_total_bytes`]. Operators must
    /// either evict packages or raise the cap; the store does not
    /// silently drop existing entries to make room.
    #[error("store capacity {limit} exceeded by {actual}-byte upload (current usage: {current})")]
    CapacityExceeded {
        /// Size of the rejected upload in bytes.
        actual: u64,
        /// Sum of every currently-stored package in bytes.
        current: u64,
        /// Configured total cap in bytes.
        limit: u64,
    },

    /// Manifest validation failed. The upload body did not contain a
    /// recognisable `MANIFEST/manifest.xml` entry, the XML did not
    /// parse, or the parsed structure was missing required fields.
    /// Non-fatal at upload time when manifest validation is set to
    /// best-effort; fatal when strict validation is enabled.
    #[error("manifest validation failed: {0}")]
    Manifest(String),

    /// Configuration-time error: the integrity key was empty, the
    /// base directory could not be created, or the cap arithmetic
    /// overflowed. Distinct from [`MissionsError::Io`] because it
    /// signals a programming or operator error rather than a
    /// transient filesystem condition.
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl MissionsError {
    /// Build a [`MissionsError::Io`] tagged with the path being
    /// touched. Centralises the conversion so call sites do not
    /// repeat the `Io { path: …, source: e }` boilerplate.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Crate-local convenience alias.
pub type Result<T> = std::result::Result<T, MissionsError>;
