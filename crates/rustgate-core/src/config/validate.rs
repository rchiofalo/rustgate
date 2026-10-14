// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Reusable validators for configuration values.
//!
//! Every crate in the workspace loads some shape of operator-supplied
//! configuration: TOML files, JSON peer registries, CLI flags merged
//! against env-vars. The shape of the config struct is per-crate, but
//! the *kinds* of checks applied to its fields — port range, duration
//! range, path exists, string non-empty — are the same everywhere.
//! Pre-this-module each crate inlined these checks in slightly
//! divergent ways: `if port == 0 { ... }` here, `if port > 65535 { ... }`
//! there (impossible — `u16` already enforces it), `if s.is_empty()`
//! vs `if s.trim().is_empty()`. The drift made the operator-facing
//! error messages inconsistent and made the workspace-wide validation
//! discipline harder to audit.
//!
//! This module provides four small validators that downstream
//! `validate(&self)` methods delegate to. The error type
//! [`ConfigValidateError`] carries the field name so the caller can
//! propagate a clean message into its own error type. The validators
//! return `Result<(), ConfigValidateError>` rather than mutating their
//! input — they never normalise (e.g. trim) the value, so the caller's
//! struct contract is preserved.
//!
//! # Conventions
//!
//! - `field_name` is always supplied verbatim by the caller, e.g.
//!   `"--bind port"`, `"http.timeout-secs"`, `"federation.peer.address"`.
//!   Callers are responsible for using a name that maps back to the
//!   place the operator set the value (CLI flag name, TOML key, env
//!   var, etc.) so the resulting error is actionable.
//! - The validators do not log or audit; they return errors. Callers
//!   decide whether the error becomes an `anyhow::bail!`, a
//!   crate-typed error, or a tracing event.
//! - Whitespace policy: [`validate_non_empty`] rejects strings that
//!   are empty *or* whitespace-only. The `is_empty()` check alone
//!   would let `"   "` slip through, which is a common copy-paste /
//!   env-var-rendered-as-spaces footgun.
//! - The validators are `#[must_use]` via the `Result` return type;
//!   ignoring the result is a clippy warning at the call site.

use std::path::Path;

/// Error type returned by every validator in this module.
///
/// One variant per validation kind so callers can match on the failure
/// shape if they want to (e.g. to translate a port error differently
/// from a path error). All variants carry the offending field name so
/// the operator can locate the bad value without consulting the source.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigValidateError {
    /// A port-typed field held an invalid value (e.g. `0`).
    #[error("config field `{field}`: port must be in 1..=65535, got {value}")]
    InvalidPort {
        /// Caller-supplied field identifier.
        field: String,
        /// The rejected port value.
        value: u32,
    },

    /// A duration-secs field was outside the permitted range.
    #[error("config field `{field}`: duration must be in {min}..={max} seconds, got {value}")]
    DurationOutOfRange {
        /// Caller-supplied field identifier.
        field: String,
        /// The rejected duration value, in seconds.
        value: u64,
        /// The minimum permitted value.
        min: u64,
        /// The maximum permitted value.
        max: u64,
    },

    /// A path-typed field referenced a file the validator could not see.
    ///
    /// The validator only checks existence, not readability or contents
    /// — callers that need stricter checks (e.g. permission bits)
    /// layer their own checks on top.
    #[error("config field `{field}`: path does not exist: {path}")]
    PathNotFound {
        /// Caller-supplied field identifier.
        field: String,
        /// The rejected path.
        path: String,
    },

    /// A string-typed field was empty or whitespace-only.
    #[error("config field `{field}`: must not be empty")]
    Empty {
        /// Caller-supplied field identifier.
        field: String,
    },
}

/// Validate that a port value is non-zero.
///
/// `u16` already constrains the upper bound at the type level, so the
/// only check is the zero-port rejection. Port 0 has the special
/// meaning of "let the OS pick" in Berkeley sockets, which is never
/// what an operator-supplied config wants — explicit binds must name
/// a concrete port. Returning a typed error here lets the caller
/// surface "port must be in 1..=65535" verbatim instead of the OS's
/// later `EADDRINUSE` / "address already in use" error.
///
/// # Examples
///
/// ```
/// use rustgate_core::config::validate::{validate_port, ConfigValidateError};
///
/// assert!(validate_port(4433, "--bind port").is_ok());
/// assert!(matches!(
///     validate_port(0, "--bind port"),
///     Err(ConfigValidateError::InvalidPort { .. })
/// ));
/// ```
pub fn validate_port(value: u16, field_name: &str) -> Result<(), ConfigValidateError> {
    if value == 0 {
        return Err(ConfigValidateError::InvalidPort {
            field: field_name.to_string(),
            value: value as u32,
        });
    }
    Ok(())
}

/// Validate that a duration (in seconds) is within the inclusive range
/// `min..=max`.
///
/// Both bounds are inclusive. `min == max` is permitted (pin to a single
/// value); `min > max` is a programmer error and produces an error that
/// reflects the supplied bounds — the validator does not panic on it
/// because callers may construct bounds from runtime config and a
/// panic in validation would mask the real misconfiguration.
///
/// # Examples
///
/// ```
/// use rustgate_core::config::validate::{validate_duration_secs_in_range, ConfigValidateError};
///
/// // In range — accepted.
/// assert!(validate_duration_secs_in_range(30, 1, 300, "timeout-secs").is_ok());
/// // Boundary cases — both bounds are inclusive.
/// assert!(validate_duration_secs_in_range(1, 1, 300, "timeout-secs").is_ok());
/// assert!(validate_duration_secs_in_range(300, 1, 300, "timeout-secs").is_ok());
/// // Out of range — rejected.
/// assert!(matches!(
///     validate_duration_secs_in_range(0, 1, 300, "timeout-secs"),
///     Err(ConfigValidateError::DurationOutOfRange { .. })
/// ));
/// assert!(matches!(
///     validate_duration_secs_in_range(301, 1, 300, "timeout-secs"),
///     Err(ConfigValidateError::DurationOutOfRange { .. })
/// ));
/// ```
pub fn validate_duration_secs_in_range(
    value: u64,
    min: u64,
    max: u64,
    field_name: &str,
) -> Result<(), ConfigValidateError> {
    if value < min || value > max {
        return Err(ConfigValidateError::DurationOutOfRange {
            field: field_name.to_string(),
            value,
            min,
            max,
        });
    }
    Ok(())
}

/// Validate that a path refers to an existing filesystem entry.
///
/// Catches typos / missing volume mounts at config-load time so the
/// operator gets a clear error before the consuming subsystem (TLS
/// stack, store-and-forward, encrypted archive writer) hits a cryptic
/// I/O error during startup. The validator does NOT check readability
/// or permissions — pair this with the appropriate file-mode check
/// (`rustgate_core::secrets::read_secret_file`, etc.) for stricter
/// gates.
///
/// `Path::exists()` returns `false` on permission errors as well as
/// missing entries; that's the desired behaviour here, since either
/// case means startup will fail and the operator-facing message
/// "path does not exist" is the right starting point for triage.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use rustgate_core::config::validate::{validate_path_exists, ConfigValidateError};
///
/// // Hopefully every Unix host has /etc/hosts; if not, the test in
/// // this module uses a tempfile that definitely exists.
/// let p = Path::new("/path/that/does/not/exist");
/// assert!(matches!(
///     validate_path_exists(p, "--cert"),
///     Err(ConfigValidateError::PathNotFound { .. })
/// ));
/// ```
pub fn validate_path_exists(path: &Path, field_name: &str) -> Result<(), ConfigValidateError> {
    if !path.exists() {
        return Err(ConfigValidateError::PathNotFound {
            field: field_name.to_string(),
            path: path.display().to_string(),
        });
    }
    Ok(())
}

/// Validate that a string is non-empty after whitespace trimming.
///
/// The whitespace-trim policy guards against the common
/// env-var-rendered-as-spaces footgun (e.g. `RUSTGATE_FOO="   "` from
/// a misconfigured shell expansion) and copy-paste artifacts.
/// Operators who actually want a value of `"   "` can't have it — the
/// trim is intentional, not a normalisation step.
///
/// The function does NOT modify the input. If the caller wants to
/// store the trimmed form, they trim the value themselves *after* this
/// check passes; this validator never silently changes the data.
///
/// # Examples
///
/// ```
/// use rustgate_core::config::validate::{validate_non_empty, ConfigValidateError};
///
/// assert!(validate_non_empty("hello", "name").is_ok());
/// // Empty rejected.
/// assert!(matches!(
///     validate_non_empty("", "name"),
///     Err(ConfigValidateError::Empty { .. })
/// ));
/// // Whitespace-only rejected — same reason.
/// assert!(matches!(
///     validate_non_empty("   ", "name"),
///     Err(ConfigValidateError::Empty { .. })
/// ));
/// // Surrounding whitespace is fine as long as something non-blank
/// // is in the middle — the validator does not normalise.
/// assert!(validate_non_empty(" hi ", "name").is_ok());
/// ```
pub fn validate_non_empty(value: &str, field_name: &str) -> Result<(), ConfigValidateError> {
    if value.trim().is_empty() {
        return Err(ConfigValidateError::Empty {
            field: field_name.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---- validate_port ----

    #[test]
    fn validate_port_rejects_zero() {
        let err = validate_port(0, "--bind port").expect_err("zero must be rejected");
        match err {
            ConfigValidateError::InvalidPort { field, value } => {
                assert_eq!(field, "--bind port");
                assert_eq!(value, 0);
            }
            other => panic!("expected InvalidPort, got {other:?}"),
        }
    }

    #[test]
    fn validate_port_accepts_one() {
        // Port 1 is valid. The OS may reject it for unprivileged
        // processes, but that's a runtime concern — config validation
        // only enforces the wire-level non-zero rule.
        validate_port(1, "field").expect("1 should be valid");
    }

    #[test]
    fn validate_port_accepts_typical_value() {
        validate_port(4433, "--bind port").expect("4433 should be valid");
    }

    #[test]
    fn validate_port_accepts_max_u16() {
        // 65535 is the upper bound enforced by `u16`; this pin
        // catches a regression that introduces a tighter bound
        // without updating the docstring.
        validate_port(u16::MAX, "field").expect("u16::MAX should be valid");
    }

    #[test]
    fn validate_port_error_message_includes_field_and_value() {
        let err = validate_port(0, "my-port").expect_err("zero rejected");
        let msg = err.to_string();
        assert!(msg.contains("my-port"), "field name missing: {msg}");
        assert!(
            msg.contains("must be in 1..=65535"),
            "range hint missing: {msg}"
        );
        assert!(msg.contains("got 0"), "actual value missing: {msg}");
    }

    // ---- validate_duration_secs_in_range ----

    #[test]
    fn validate_duration_in_range_pin() {
        // In range — accepted at the lower bound, upper bound, and
        // anywhere inside.
        validate_duration_secs_in_range(1, 1, 300, "timeout").unwrap();
        validate_duration_secs_in_range(300, 1, 300, "timeout").unwrap();
        validate_duration_secs_in_range(150, 1, 300, "timeout").unwrap();

        // Below min — rejected.
        let below = validate_duration_secs_in_range(0, 1, 300, "timeout")
            .expect_err("0 below min must reject");
        match below {
            ConfigValidateError::DurationOutOfRange {
                field,
                value,
                min,
                max,
            } => {
                assert_eq!(field, "timeout");
                assert_eq!(value, 0);
                assert_eq!(min, 1);
                assert_eq!(max, 300);
            }
            other => panic!("expected DurationOutOfRange, got {other:?}"),
        }

        // Above max — rejected.
        let above = validate_duration_secs_in_range(301, 1, 300, "timeout")
            .expect_err("301 above max must reject");
        assert!(matches!(
            above,
            ConfigValidateError::DurationOutOfRange { .. }
        ));
    }

    #[test]
    fn validate_duration_min_equals_max_pins_single_value() {
        // `min == max` is a legitimate way to pin a duration to a
        // single permitted value — useful for "must be exactly N"
        // contracts in the federation heartbeat config.
        validate_duration_secs_in_range(30, 30, 30, "fixed").unwrap();
        assert!(validate_duration_secs_in_range(29, 30, 30, "fixed").is_err());
        assert!(validate_duration_secs_in_range(31, 30, 30, "fixed").is_err());
    }

    #[test]
    fn validate_duration_error_message_includes_bounds() {
        let err = validate_duration_secs_in_range(500, 10, 300, "timeout-secs")
            .expect_err("500 above 300 must reject");
        let msg = err.to_string();
        assert!(msg.contains("timeout-secs"), "field name missing: {msg}");
        assert!(msg.contains("10..=300"), "range missing: {msg}");
        assert!(msg.contains("500"), "actual value missing: {msg}");
    }

    #[test]
    fn validate_duration_inverted_bounds_does_not_panic() {
        // Programmer error: min > max. The validator must not panic
        // — it returns an error like any other out-of-range case so
        // a misconfigured caller surfaces the bug at config-load time
        // rather than crashing.
        let err = validate_duration_secs_in_range(50, 100, 10, "weird")
            .expect_err("inverted bounds: every value is out of range");
        assert!(matches!(
            err,
            ConfigValidateError::DurationOutOfRange { .. }
        ));
    }

    // ---- validate_path_exists ----

    #[test]
    fn validate_path_exists_returns_err_for_nonexistent() {
        // Use a path that almost certainly does not exist on any host.
        let path = Path::new("/this/path/should/not/exist/9f0e2c-rustgate-test");
        let err = validate_path_exists(path, "--cert").expect_err("missing path must reject");
        match err {
            ConfigValidateError::PathNotFound { field, path: p } => {
                assert_eq!(field, "--cert");
                assert!(
                    p.contains("rustgate-test"),
                    "path display should contain the input: {p}"
                );
            }
            other => panic!("expected PathNotFound, got {other:?}"),
        }
    }

    #[test]
    fn validate_path_exists_accepts_existing_file() {
        // Use a tempfile so we don't depend on host-specific paths.
        let f = tempfile::NamedTempFile::new().expect("create tempfile");
        validate_path_exists(f.path(), "tmp").expect("existing path must accept");
    }

    #[test]
    fn validate_path_exists_accepts_existing_directory() {
        // Directories count as "exists" for this validator. Stricter
        // checks (must-be-file / must-be-dir) layer on top.
        let d = tempfile::tempdir().expect("create tempdir");
        validate_path_exists(d.path(), "data-dir").expect("existing dir must accept");
    }

    #[test]
    fn validate_path_exists_error_message_shape() {
        let err = validate_path_exists(Path::new("/no/such/path"), "my-field")
            .expect_err("missing must reject");
        let msg = err.to_string();
        assert!(msg.contains("my-field"), "field name missing: {msg}");
        assert!(msg.contains("does not exist"), "reason missing: {msg}");
        assert!(msg.contains("/no/such/path"), "path missing: {msg}");
    }

    // ---- validate_non_empty ----

    #[test]
    fn validate_non_empty_pin() {
        // Non-empty content — accepted.
        validate_non_empty("ok", "name").unwrap();
        validate_non_empty("a", "name").unwrap();
        // Surrounding whitespace is allowed as long as something
        // non-blank is between the spaces — the validator does not
        // normalise the value.
        validate_non_empty(" hi ", "name").unwrap();
        // Multibyte content is fine.
        validate_non_empty("café", "name").unwrap();

        // Empty string — rejected.
        let empty_err = validate_non_empty("", "name").expect_err("empty must reject");
        match empty_err {
            ConfigValidateError::Empty { field } => assert_eq!(field, "name"),
            other => panic!("expected Empty, got {other:?}"),
        }

        // Whitespace-only — rejected (the env-var-as-spaces footgun).
        assert!(matches!(
            validate_non_empty("   ", "name"),
            Err(ConfigValidateError::Empty { .. })
        ));
        // Tabs and newlines too.
        assert!(matches!(
            validate_non_empty("\t\n", "name"),
            Err(ConfigValidateError::Empty { .. })
        ));
    }

    #[test]
    fn validate_non_empty_error_message_includes_field() {
        let err = validate_non_empty("", "my-name").expect_err("empty rejected");
        let msg = err.to_string();
        assert!(msg.contains("my-name"), "field name missing: {msg}");
        assert!(msg.contains("must not be empty"), "reason missing: {msg}");
    }

    // ---- ConfigValidateError trait pins ----

    #[test]
    fn error_implements_standard_traits() {
        // The error must be a `std::error::Error` so it can be wrapped
        // by `anyhow` / `thiserror::Error(transparent)`. PartialEq is
        // useful for assertion-based tests in callers. Send + Sync +
        // 'static is required for spawned-task return types.
        fn assert_bounds<T: std::error::Error + Send + Sync + 'static + PartialEq>() {}
        assert_bounds::<ConfigValidateError>();
    }

    #[test]
    fn errors_round_trip_via_question_mark_in_caller_result() {
        // Pin that callers can `?`-propagate validators into their own
        // `Result<(), ConfigValidateError>` chains without extra wiring
        // — the canonical call-site shape for a crate-local
        // `validate(&self) -> Result<(), ConfigValidateError>` method.
        fn caller() -> Result<(), ConfigValidateError> {
            validate_port(0, "--bind port")?;
            Ok(())
        }
        let err = caller().expect_err("validator failure must propagate");
        assert!(err.to_string().contains("--bind port"));
    }
}
