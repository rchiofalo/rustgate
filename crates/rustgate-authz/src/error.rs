// Copyright © 2026 Roberto Chiofalo.

//! Error types for the authz crate.

use thiserror::Error;

/// Errors produced while parsing, validating, or compiling a policy.
///
/// `#[non_exhaustive]` so additional failure modes (e.g. a dedicated
/// `Io` variant, per-rule limit violations) can be added without
/// breaking downstream `match` statements. Consumers must use a
/// wildcard arm when matching from outside the defining crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthzError {
    /// The input bytes were not valid JSON.
    #[error("invalid policy JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Policy failed a validation check.
    #[error("policy validation failed at {stage}: {message}")]
    Validation {
        /// Short identifier of the pipeline stage that rejected the policy.
        stage: &'static str,
        /// Human-readable explanation.
        message: String,
    },
}

impl AuthzError {
    /// Construct a validation error.
    pub fn validation(stage: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            stage,
            message: message.into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Display and conversion-shape tests for `AuthzError`.
    //!
    //! `AuthzError` is a small enum (currently two variants), but its
    //! Display template and `From<serde_json::Error>` impl are both
    //! load-bearing:
    //! - The `Validation { stage, message }` variant's Display is the
    //!   only place where the `stage` string is rendered to humans and
    //!   to the audit trail emitted by [`crate::parser::validate`]. A
    //!   downstream audit pipeline filters on the textual stage tag;
    //!   the parser tests pin the raw `stage` field, but only a
    //!   Display-shape test here guarantees the tag survives through
    //!   to the rendered message.
    //! - The `Json` variant is reached exclusively via the
    //!   `#[from] serde_json::Error` blanket conversion in `parse_json`
    //!   — nothing else constructs it. Pinning that `?`-driven path
    //!   catches a regression where the `#[from]` attribute is removed
    //!   and every JSON-level failure silently becomes an uncompiled
    //!   error.
    use super::*;

    #[test]
    fn validation_constructor_sets_both_fields() {
        // The `validation` ergonomics helper is the only constructor
        // parser/reloader/authz-reloader code uses (we don't ever
        // build a `Validation { ... }` struct literal outside tests).
        // Pinning the two-argument contract protects against a
        // refactor that changes the signature.
        let err = AuthzError::validation("version", "bad");
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(stage, "version");
                assert_eq!(message, "bad");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validation_constructor_accepts_owned_string() {
        // `impl Into<String>` accepts both `&str` and `String`. The
        // hot-path callers always pass `String` (from `format!`), so
        // pin that this works without any explicit conversion.
        let owned: String = format!("unsupported version {}", 2);
        let err = AuthzError::validation("version", owned);
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(stage, "version");
                assert!(message.contains('2'));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validation_display_includes_stage_and_message() {
        // Downstream audit records and tracing logs render
        // `AuthzError` via `{}`. The stage tag is what SIEM and
        // operator runbooks grep for when distinguishing "wrong
        // schema version" from "bad rule id" — and the only path
        // that exposes the stage through text is this Display
        // template. A refactor that inlined the stage out of the
        // template would fail this test instead of silently breaking
        // alert rules.
        let err = AuthzError::validation("version", "unsupported schema 2");
        let rendered = err.to_string();
        assert!(
            rendered.contains("policy validation failed"),
            "Validation variant must carry the canonical prefix: {rendered}"
        );
        assert!(
            rendered.contains("version"),
            "stage must appear in the rendered Display so audit filters can grep it: {rendered}"
        );
        assert!(
            rendered.contains("unsupported schema 2"),
            "message must survive into the rendered Display: {rendered}"
        );
    }

    #[test]
    fn validation_display_preserves_stage_for_rules_tag() {
        // Second arm of the same invariant — the `rules` stage (used
        // for duplicate-id and empty-id errors) must also survive
        // into Display. This is here separately from the `version`
        // test because the two stages feed different downstream
        // alerts.
        let err = AuthzError::validation("rules", "duplicate rule id `dup`");
        let rendered = err.to_string();
        assert!(rendered.contains("rules"));
        assert!(rendered.contains("dup"));
    }

    #[test]
    fn json_variant_from_serde_error_via_from_impl() {
        // `AuthzError::Json` is reached exclusively through the
        // `#[from] serde_json::Error` conversion in `parse_json`:
        // `serde_json::from_slice(bytes)?` desugars to
        // `AuthzError::from(serde_err)`. Pinning that this path
        // compiles and produces the right variant catches a
        // regression where the `#[from]` attribute is removed by
        // accident — the `?` then fails to compile, but if a
        // conversion helper elsewhere masked that, we'd silently
        // lose the wrapping.
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").expect_err("must fail");
        let wrapped: AuthzError = serde_err.into();
        match wrapped {
            AuthzError::Json(_) => {}
            other => panic!("expected Json variant, got {other:?}"),
        }
    }

    #[test]
    fn json_variant_display_prefixes_invalid_policy_json() {
        // Operators see "invalid policy JSON: <serde detail>" when a
        // malformed file is loaded. The prefix is the grep token
        // distinguishing JSON-level errors from validator errors
        // (which start with "policy validation failed at ...").
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").expect_err("must fail");
        let err = AuthzError::from(serde_err);
        let rendered = err.to_string();
        assert!(
            rendered.starts_with("invalid policy JSON"),
            "Json variant must carry its distinctive prefix so operators can separate parse \
             failures from validation failures at a glance: {rendered}"
        );
    }

    #[test]
    fn authz_error_is_send_and_sync() {
        // `AuthzError` crosses `tokio::spawn` and `Arc` boundaries
        // through the reloader and the startup path. A future
        // variant holding a !Send/!Sync field would fail to compile
        // in those contexts; this assertion makes the failure local.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuthzError>();
    }

    #[test]
    fn validation_stage_is_static_str_not_owned() {
        // The `stage` field is deliberately `&'static str` — it's
        // always a compile-time literal (`"version"`, `"rules"`,
        // and future additions like `"validate"` used by
        // authz_reloader). Pin the type so a refactor to `String`
        // would fail here rather than silently widening the enum
        // size and inviting operator-supplied data into a tag
        // that downstream code treats as trusted.
        let err = AuthzError::validation("version", "x");
        match err {
            AuthzError::Validation { stage, .. } => {
                // Rebind with an explicit type annotation; if the
                // field type drifts to `String` this assignment
                // fails to compile.
                let _: &'static str = stage;
            }
            _ => unreachable!(),
        }
    }
}
