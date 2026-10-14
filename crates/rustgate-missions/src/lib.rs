// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! TAK-compatible **Data Package** storage.
//!
//! Implements the lightweight half of the TAK Mission Sync feature
//! family (issue #860, Feature 17): a content-addressed package store
//! that ATAK / WinTAK / iTAK clients can use to push and pull ZIP
//! files containing KML overlays, KMZ packages, GeoJSON, route plans,
//! tactical-graphics imagery, and pre-shared `truststore-root.p12` /
//! `server-connection.pref` bundles. Packages are keyed by the
//! SHA-256 hash of the ZIP body, so the same content uploaded twice
//! collapses to a single on-disk entry.
//!
//! # Wire-level scope
//!
//! ```text
//! POST   /api/packages          → upload (multipart/form-data, ZIP file)
//! GET    /api/packages          → list (JSON array of [`PackageMeta`])
//! GET    /api/packages/{hash}   → download by SHA-256 hash
//! DELETE /api/packages/{hash}   → remove
//! ```
//!
//! The HTTP surface itself lives in
//! [`rustgate-admin`](../rustgate_admin/index.html) under the
//! `missions` feature flag. This crate owns the on-disk store, the
//! manifest validation, and the integrity-tag discipline so the HTTP
//! layer can stay thin.
//!
//! # TAK package format
//!
//! ATAK / WinTAK / iTAK ship a Mission Package as a single ZIP with
//! the canonical layout below. The store accepts the ZIP body and
//! does best-effort manifest validation — clients that cannot
//! produce a manifest still upload, but a syntactically-valid
//! manifest is required to round-trip a package back to a TAK client
//! that expects one.
//!
//! ```text
//! package.zip
//! ├── MANIFEST/
//! │   └── manifest.xml       (MissionPackageManifest v2)
//! └── <hash-folder>/
//!     ├── truststore-root.p12
//!     ├── server-connection.pref
//!     └── overlay.kmz
//! ```
//!
//! See [`manifest::parse_manifest_xml`] for the subset of the v2
//! manifest schema this crate validates.
//!
//! # Integrity model
//!
//! Every stored package carries an HMAC-SHA256 tag computed over the
//! canonical metadata blob (`hash || size || name || creator_uid ||
//! upload_time`) under the store-local integrity key. The tag is
//! recomputed on every download and compared in constant time via
//! `subtle::ConstantTimeEq` so an attacker who tampers with the
//! sidecar JSON cannot redirect a download by rewriting the
//! [`PackageMeta::name`] or [`PackageMeta::size`] fields without also
//! producing a valid HMAC over the rewritten blob.
//!
//! The integrity key is supplied at construction time as raw bytes;
//! callers should hold it in a `zeroize::Zeroizing` buffer, exactly
//! as `rustgate-transport`'s store-and-forward layer does. The HMAC
//! construction itself goes through
//! [`rustgate_core::crypto::hmac_sha256_tag`] /
//! [`rustgate_core::crypto::hmac_sha256_verify`] so the timing-side-
//! channel discipline is centralised in one helper.
//!
//! # Encrypted body storage (deferred)
//!
//! The issue's longer-term design optionally wraps each on-disk ZIP
//! body in a `KeyRing`-keyed
//! `rustgate_archive::encrypted::EncryptedWriter`. That layer is
//! deliberately out of scope for the lightweight ship; the current
//! implementation writes plaintext bodies and reserves the seam for
//! a follow-up PR (a `Storage` enum with `Plain` / `Encrypted`
//! variants, switched at construction time). The integrity-tag layer
//! is independent and stays correct in either mode.
//!
//! # What is not here
//!
//! - **Mission objects** (Feature 6 of #860, deferred). The
//!   `/api/missions/{name}` endpoints, mission CoT events
//!   (`t-x-m-c`, `t-x-m-d`, `t-x-m-n`), the SSE change stream, and
//!   per-mission subscription bookkeeping land in a follow-up crate
//!   or follow-up modules here.
//! - **Authentication / authorisation**. The HTTP handler in
//!   `rustgate-admin` enforces bearer-token auth before delegating
//!   to this crate; the store itself trusts the caller.
//! - **Cluster replication**. A package uploaded to one server is
//!   not propagated to federation peers in this scope. The
//!   federation V2 protocol can be extended in a follow-up to fan
//!   the manifest plus a content URL across the mesh.

#![forbid(unsafe_code)]

pub mod error;
pub mod manifest;
pub mod multipart;
pub mod store;

pub use error::MissionsError;
pub use manifest::{ManifestContent, MissionPackageManifest, parse_manifest_xml};
pub use multipart::{extract_boundary, extract_multipart_field, extract_multipart_filename};
pub use store::{PackageMeta, PackageStore, StoreLimits};

/// Content-type label written into [`PackageMeta::mime_type`] and used
/// by the HTTP download handler when echoing the body back to a TAK
/// client. ATAK accepts `application/zip` and the legacy
/// `application/x-zip-compressed` interchangeably; we pick the
/// modern IANA-registered form.
pub const ZIP_MIME_TYPE: &str = "application/zip";

/// Default per-store size cap in bytes (1 GiB).
///
/// The cap is the sum of every package body currently in the store;
/// uploads that would push the total past this number are rejected
/// with [`MissionsError::CapacityExceeded`]. A 1 GiB default is
/// large enough for hundreds of typical KMZ overlays (≈1–5 MiB
/// each) but small enough to surface a configuration error before
/// it fills the operator's disk. Operators tune via
/// [`StoreLimits::with_max_total_bytes`].
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

/// Default per-package upload cap in bytes (50 MiB).
///
/// Matches the ceiling used by the legacy enrollment-server data-
/// package endpoint. Single Mission Packages larger than 50 MiB are
/// extremely rare in deployed TAK fleets — at that size operators
/// usually fall back to an out-of-band file share.
pub const DEFAULT_MAX_PACKAGE_BYTES: u64 = 50 * 1024 * 1024;
