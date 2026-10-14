// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed error surface for the correlation engine.
//!
//! Most failure modes are *soft* — a report whose position lies outside
//! every existing fused entity's spatial gate is not an error, it is a
//! [`crate::types::CorrelationOutcome::Created`] verdict. The variants
//! here cover the small set of conditions that warrant a typed
//! `Result::Err` rather than a normal-flow outcome: input that violates
//! the WGS-84 envelope, JSON serialisation failures when an attribute
//! cannot round-trip, and the (rare) case where the LRU eviction path
//! cannot identify a victim — for example, when the engine is empty.
//!
//! Following the workspace convention, [`CorrelationError`] is a
//! `thiserror::Error` enum with structured context fields. Callers map
//! it through `anyhow::Error` at the orchestration boundary.

use thiserror::Error;

/// Failure modes returned by the correlation engine.
#[derive(Debug, Error)]
pub enum CorrelationError {
    /// A submitted entity carried a position outside the WGS-84
    /// envelope — `lat` not in `[-90, 90]` or `lon` not in
    /// `[-180, 180]`. The codec is normally responsible for
    /// validating these, but the engine repeats the check at its
    /// boundary so a buggy or hostile codec cannot drive
    /// `RTree::insert` through invalid coordinates.
    #[error("invalid WGS-84 position: lat={lat}, lon={lon}")]
    InvalidPosition {
        /// Latitude that failed validation, verbatim.
        lat: f64,
        /// Longitude that failed validation, verbatim.
        lon: f64,
    },

    /// JSON serialisation of an entity attribute or fused entity
    /// payload failed. The router callback path swallows these (an
    /// unfusable report is logged at `tracing::debug!` and the
    /// underlying message routes normally), but the typed variant is
    /// retained so callers that funnel reports synchronously can
    /// surface the failure.
    #[error("serialise correlation payload: {source}")]
    Serialize {
        /// Underlying `serde_json` error.
        #[from]
        source: serde_json::Error,
    },
}

/// Crate-local `Result` alias.
pub type Result<T> = std::result::Result<T, CorrelationError>;
