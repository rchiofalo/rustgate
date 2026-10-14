// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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

    #[test]
    fn authz_error_implements_std_error_trait() {
        // The `?`-propagation chain from `parse_json` → router → server
        // relies on `AuthzError: std::error::Error` so the type can be
        // coerced into `Box<dyn Error + Send + Sync + 'static>` at the
        // `anyhow::Error::from` boundary. The `#[derive(Error)]` on the
        // enum emits this impl today; a regression that switched to a
        // manual Display-only impl (dropping the trait) would still
        // compile inside this crate but silently break the
        // `anyhow`-integration downstream. The compile-time bound
        // helper pins it here.
        fn assert_error_trait<T: std::error::Error>() {}
        assert_error_trait::<AuthzError>();
    }

    #[test]
    fn authz_error_is_static_lifetime_bound() {
        // The reloader and the startup path both stash `AuthzError`
        // values inside `Arc`s that cross spawned-task boundaries
        // (`tokio::spawn(async move { … })`), which requires
        // `'static`. The `Validation` variant is trivially `'static`
        // because `stage: &'static str` + `message: String`; the
        // `Json` variant is `'static` because `serde_json::Error`
        // itself is owned. A future `&'a str` field on either variant
        // would narrow the lifetime and fail here rather than at a
        // spawned-task call site.
        fn assert_static<T: 'static>() {}
        assert_static::<AuthzError>();
    }

    #[test]
    fn json_variant_source_chains_to_underlying_serde_error() {
        // `std::error::Error::source()` is the canonical way for
        // error-reporting layers (anyhow, eyre, tracing) to unwind
        // a cause chain. The `#[error("invalid policy JSON: {0}")]`
        // template plus the `#[from]` attribute on the inner field
        // are what make the source link present — a refactor that
        // changed the template to a literal message or replaced
        // `#[from]` with a manual conversion that dropped the
        // enclosed value would silently break the cause-chain
        // walk and operators would stop seeing the serde detail in
        // structured error reports. The test uses
        // `std::error::Error::source` so the intent is unambiguous.
        use std::error::Error;
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{not json").expect_err("must fail");
        let err: AuthzError = serde_err.into();
        let source = err.source();
        assert!(
            source.is_some(),
            "Json variant must chain to the wrapped serde error via Error::source"
        );
    }

    #[test]
    fn validation_variant_has_no_source() {
        // The `Validation` variant is self-contained — `message` is
        // the operator-facing detail and there is no wrapped cause.
        // Pinning `source() == None` here documents the asymmetry
        // with `Json` and catches a future refactor that added a
        // `#[source]` attribute to one of the fields (which would
        // change downstream error-chain walking behaviour without
        // any visible Display change).
        use std::error::Error;
        let err = AuthzError::validation("version", "bad");
        assert!(
            err.source().is_none(),
            "Validation variant carries no wrapped cause; source() must be None"
        );
    }

    #[test]
    fn authz_error_from_impl_is_present_for_serde_json_error() {
        // The `#[from] serde_json::Error` attribute in the `Json`
        // variant generates `impl From<serde_json::Error> for
        // AuthzError`. The `?`-propagation in `parse_json` desugars
        // to that conversion. A compile-time bound helper pins the
        // conversion trait's existence so a refactor that dropped
        // `#[from]` and required manual construction would fail at
        // this named test rather than at the first `?`-line in
        // `parse_json`.
        fn assert_from<T, U: From<T>>() {}
        assert_from::<serde_json::Error, AuthzError>();
    }

    #[test]
    fn validation_debug_exposes_both_field_values() {
        // Operators occasionally log `?error` (Debug) rather than
        // `%error` (Display) in development contexts. The derived
        // `Debug` impl for `Validation { stage, message }` formats
        // both fields; a future manual Debug impl that dropped one
        // (in a misguided attempt to trim noise) would silently
        // hide half the information from incident logs. Pin both
        // field values appear in the rendered output.
        let err = AuthzError::validation("rules", "duplicate rule `dup`");
        let debug = format!("{err:?}");
        assert!(
            debug.contains("Validation"),
            "Debug output must name the variant: {debug}"
        );
        assert!(
            debug.contains("rules"),
            "Debug output must include the stage field value: {debug}"
        );
        assert!(
            debug.contains("dup"),
            "Debug output must include the message field value: {debug}"
        );
    }

    #[test]
    fn json_variant_debug_names_variant() {
        // Symmetric to `validation_debug_exposes_both_field_values`
        // — pin that the `Json` variant's Debug render includes the
        // variant tag `Json`. A manual Debug impl that collapsed
        // both variants into a single render would silently make
        // incident logs ambiguous between "bad JSON" and "bad rule";
        // this test catches the collapse.
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").expect_err("must fail");
        let err: AuthzError = serde_err.into();
        let debug = format!("{err:?}");
        assert!(
            debug.contains("Json"),
            "Debug output must name the Json variant: {debug}"
        );
    }

    #[test]
    fn json_variant_display_delegates_to_wrapped_serde_error() {
        // The `#[error("invalid policy JSON: {0}")]` template uses
        // `{0}` (positional) which delegates to the wrapped type's
        // own Display. A refactor to `{0:?}` (Debug formatting)
        // would silently produce quoted/escaped output that breaks
        // operator grep patterns keyed on specific serde messages.
        // Trigger a known-shape serde error (leading `{` but no
        // closing brace) and assert the rendered AuthzError
        // contains text that only appears in serde's Display —
        // specifically, the "line N column M" fragment serde_json
        // emits for position reporting.
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{").expect_err("must fail");
        let serde_rendered = serde_err.to_string();
        let err: AuthzError = serde_err.into();
        let rendered = err.to_string();
        assert!(
            rendered.contains(&serde_rendered),
            "AuthzError Display must embed the serde error's own Display output verbatim \
             (the `{{0}}` positional delegates to Display). AuthzError: {rendered}; \
             serde: {serde_rendered}"
        );
    }

    #[test]
    fn validation_display_tolerates_empty_message() {
        // Edge case — `validation(stage, "")`. Callers in
        // `parser::validate` sometimes build the message via
        // `format!` where the inner component can be empty (e.g.
        // empty rule id list). The Display template must still
        // render the stage prefix without panicking or dropping
        // any segment; pin that the canonical prefix and the stage
        // name both appear in the output.
        let err = AuthzError::validation("rules", "");
        let rendered = err.to_string();
        assert!(
            rendered.contains("policy validation failed"),
            "prefix must survive empty message: {rendered}"
        );
        assert!(
            rendered.contains("rules"),
            "stage must survive empty message: {rendered}"
        );
    }

    #[test]
    fn validation_constructor_accepts_str_slice_input() {
        // Symmetric to `validation_constructor_accepts_owned_string`
        // — pin that `impl Into<String>` accepts a bare `&str`
        // literal at the call site. Several callsites in parser.rs
        // do exactly this: `AuthzError::validation("version", "msg")`
        // with string-literal arguments. A refactor that narrowed
        // the bound to `AsRef<str>` or an owned `String`-only
        // signature would force clone-site changes in the parser;
        // the test pins the current loose bound.
        let err = AuthzError::validation("version", "literal message");
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(stage, "version");
                assert_eq!(message, "literal message");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
