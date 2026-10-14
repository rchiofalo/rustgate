// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Request and response types for the federation REST API.

use serde::{Deserialize, Serialize};

use crate::config::RoutingMode;

/// Request body for creating a new federate.
///
/// Uses `deny_unknown_fields` to reject API requests containing
/// unexpected properties — typos or unsupported fields produce a
/// clear error instead of being silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFederateRequest {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub inbound_groups: Option<Vec<String>>,
    pub outbound_groups: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub is_outbound: bool,
    pub trust_cert_cn: Option<String>,
    #[serde(default)]
    pub routing_mode: RoutingMode,
}

fn default_true() -> bool {
    true
}

/// Request body for updating an existing federate.
///
/// Uses `deny_unknown_fields` so the API rejects requests containing
/// unexpected properties with a clear error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateFederateRequest {
    pub address: Option<String>,
    pub groups: Option<Vec<String>>,
    pub inbound_groups: Option<Option<Vec<String>>>,
    pub outbound_groups: Option<Option<Vec<String>>>,
    pub is_outbound: Option<bool>,
    pub trust_cert_cn: Option<Option<String>>,
}

/// Request body for setting routing mode.
///
/// Uses `deny_unknown_fields` so the API rejects requests containing
/// unexpected properties with a clear error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRoutingModeRequest {
    pub routing_mode: RoutingMode,
}

/// Standard JSON success envelope.
#[derive(Debug, Serialize)]
pub(crate) struct SuccessResponse<T: Serialize> {
    pub data: T,
}

/// Standard JSON error envelope.
#[derive(Debug, Serialize)]
pub(crate) struct ErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn create_federate_rejects_unknown_field() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001","extra":true}"#;
        let result = serde_json::from_str::<CreateFederateRequest>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}"
        );
    }

    #[test]
    fn update_federate_rejects_unknown_field() {
        let json = r#"{"address":"1.2.3.4:9001","bogus":42}"#;
        let result = serde_json::from_str::<UpdateFederateRequest>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}"
        );
    }

    #[test]
    fn set_routing_mode_rejects_unknown_field() {
        let json = r#"{"routing_mode":"matrix","extra":true}"#;
        let result = serde_json::from_str::<SetRoutingModeRequest>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}"
        );
    }

    /// `enabled` defaults to `true` when omitted — the `default_true` helper
    /// is the sole mechanism that makes newly-created federates start in the
    /// enabled state without requiring callers to thread the flag through on
    /// every POST. A silent flip to `false` (e.g. swapping to
    /// `#[serde(default)]` during a refactor) would leave every freshly
    /// created peer dormant until someone noticed the regression — this pin
    /// fails loud.
    #[test]
    fn create_federate_request_enabled_defaults_true() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001"}"#;
        let req: CreateFederateRequest =
            serde_json::from_str(json).expect("minimal body should parse");
        assert!(
            req.enabled,
            "omitted `enabled` must default to true via default_true()"
        );
    }

    /// `is_outbound` uses bare `#[serde(default)]`, so it defaults to `false`
    /// (bool's Default). The create API treats omission as "inbound peer"
    /// which matters because outbound peers drive reconnect loops the moment
    /// they're added — an unintended flip to `true` would spin up connection
    /// attempts for every inbound-only federate.
    #[test]
    fn create_federate_request_is_outbound_defaults_false() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001"}"#;
        let req: CreateFederateRequest =
            serde_json::from_str(json).expect("minimal body should parse");
        assert!(
            !req.is_outbound,
            "omitted `is_outbound` must default to false (bool::default)"
        );
    }

    /// Omitted `groups` must deserialize to an empty `Vec`, not reject the
    /// payload. `PeerConfig::groups` is the bidirectional fallback used when
    /// `inbound_groups` / `outbound_groups` are unset, so the default has
    /// direct ACL impact: empty means "no groups advertised", which is the
    /// conservative default a create-request without `groups` should produce.
    #[test]
    fn create_federate_request_groups_defaults_empty() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001"}"#;
        let req: CreateFederateRequest =
            serde_json::from_str(json).expect("minimal body should parse");
        assert!(
            req.groups.is_empty(),
            "omitted `groups` must default to an empty Vec"
        );
        assert!(
            req.inbound_groups.is_none(),
            "omitted `inbound_groups` stays None (not Some(vec![]))"
        );
        assert!(
            req.outbound_groups.is_none(),
            "omitted `outbound_groups` stays None (not Some(vec![]))"
        );
    }

    /// Omitted `routing_mode` must land on `RoutingMode::Matrix` (the enum's
    /// `#[default]`). Matrix routing is the safer default because it confines
    /// traffic to per-peer NATS subscriptions; a regression to `Broadcast`
    /// would silently fan out every federated event to every peer.
    #[test]
    fn create_federate_request_routing_mode_defaults_matrix() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001"}"#;
        let req: CreateFederateRequest =
            serde_json::from_str(json).expect("minimal body should parse");
        assert_eq!(
            req.routing_mode,
            RoutingMode::Matrix,
            "omitted `routing_mode` must default to Matrix (RoutingMode::default)"
        );
    }

    /// `trust_cert_cn` is a bare `Option<String>`, so an omitted field
    /// deserializes to `None`. There's no `#[serde(default)]` annotation on
    /// it — serde falls back to `Option::default()` regardless — but pinning
    /// the behavior prevents a well-meaning refactor from "fixing" the
    /// missing annotation and accidentally tightening the schema to require
    /// the field.
    #[test]
    fn create_federate_request_trust_cert_cn_defaults_none() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001"}"#;
        let req: CreateFederateRequest =
            serde_json::from_str(json).expect("minimal body should parse");
        assert!(
            req.trust_cert_cn.is_none(),
            "omitted `trust_cert_cn` must stay None"
        );
    }

    /// Explicit `"enabled": false` must override the `default_true` helper.
    /// This proves `default_true()` only fires on omission, not on any
    /// truthy-ish conversion serde might dream up.
    #[test]
    fn create_federate_request_enabled_explicit_false_overrides_default() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001","enabled":false}"#;
        let req: CreateFederateRequest = serde_json::from_str(json).expect("should parse");
        assert!(
            !req.enabled,
            "explicit `enabled: false` must override default_true()"
        );
    }

    /// The `Option<Option<T>>` double-option shape on [`UpdateFederateRequest::inbound_groups`]
    /// / `outbound_groups` / `trust_cert_cn` is pinned here as a **two-state**
    /// contract because stock serde (`serde_json`, no `deserialize_with`)
    /// treats a missing field and a JSON `null` identically — both land on
    /// outer `None` — and only a present value produces `Some(Some(v))`. The
    /// inner `Option` is therefore dead state as far as deserialization is
    /// concerned, but the type can't be narrowed to `Option<T>` without
    /// silently shifting its storage layout and breaking any call site that
    /// pattern-matches on `Some(Some(_))` / `Some(None)` / `None`.
    ///
    /// The three scenarios pinned here:
    ///
    /// 1. Field omitted       → outer `None` (no-op semantics).
    /// 2. Field present `null` → outer `None` (same as omitted under stock
    ///    serde — this is the gotcha operators need to know about; the PATCH
    ///    endpoint cannot "clear" a previously-set field by sending `null`).
    /// 3. Field present, value → `Some(Some(v))` (replace semantics).
    ///
    /// If someone adds `#[serde(deserialize_with = "...")]` later to
    /// distinguish null from omitted, scenario 2 will flip from `None` to
    /// `Some(None)` — this test fails loud, forcing the PR to explicitly
    /// update the contract and think about whether the downstream store
    /// update path handles `Some(None)` as "clear".
    #[test]
    fn update_federate_request_double_option_is_two_state_under_stock_serde() {
        // Scenario 1: omitted entirely → outer None.
        let omitted: UpdateFederateRequest =
            serde_json::from_str("{}").expect("empty body should parse");
        assert!(omitted.trust_cert_cn.is_none());
        assert!(omitted.inbound_groups.is_none());
        assert!(omitted.outbound_groups.is_none());

        // Scenario 2: explicit null → outer None (NOT Some(None) under stock
        // serde — no custom deserialize_with is wired up, so null collapses
        // to the missing-field case).
        let null_json = r#"{"trust_cert_cn":null,"inbound_groups":null,"outbound_groups":null}"#;
        let nulled: UpdateFederateRequest =
            serde_json::from_str(null_json).expect("explicit nulls should parse");
        assert!(
            nulled.trust_cert_cn.is_none(),
            "stock serde collapses null→None on Option<Option<T>>; flip to Some(None) \
             means someone added a custom deserializer and this contract moved"
        );
        assert!(nulled.inbound_groups.is_none());
        assert!(nulled.outbound_groups.is_none());

        // Scenario 3: present and set → Some(Some(v)) (replace semantics).
        let set_json = r#"{"trust_cert_cn":"peer-ca","inbound_groups":["Alpha"],"outbound_groups":["Bravo","Charlie"]}"#;
        let set: UpdateFederateRequest =
            serde_json::from_str(set_json).expect("values should parse");
        assert_eq!(
            set.trust_cert_cn,
            Some(Some("peer-ca".into())),
            "set trust_cert_cn must be Some(Some(v))"
        );
        assert_eq!(
            set.inbound_groups,
            Some(Some(vec!["Alpha".into()])),
            "set inbound_groups must be Some(Some(v))"
        );
        assert_eq!(
            set.outbound_groups,
            Some(Some(vec!["Bravo".into(), "Charlie".into()])),
            "set outbound_groups must be Some(Some(v))"
        );
    }

    /// `UpdateFederateRequest` uses a single-Option `Option<Vec<String>>` on
    /// `groups` rather than the double-Option pattern. This is deliberate —
    /// the bidirectional fallback list is never "cleared to null", only
    /// replaced with a (possibly empty) vec. Pin the asymmetry so nobody
    /// "normalizes" the schema to all-double-Options and changes the
    /// clear-semantics of the other fields.
    #[test]
    fn update_federate_request_groups_is_single_option_not_double() {
        // Explicit empty vec replaces → Some(vec![]).
        let json = r#"{"groups":[]}"#;
        let req: UpdateFederateRequest =
            serde_json::from_str(json).expect("empty groups should parse");
        assert_eq!(
            req.groups,
            Some(vec![]),
            "explicit empty groups must be Some(vec![]), not None"
        );

        // Omitted → None (no-op semantics).
        let omitted: UpdateFederateRequest =
            serde_json::from_str("{}").expect("empty body should parse");
        assert!(
            omitted.groups.is_none(),
            "omitted groups must be None (no-op)"
        );

        // Null is rejected — single Option<Vec> can't carry "clear" semantics
        // and serde_json surfaces that as a type error rather than
        // silently converting to Some(vec![]).
        let null_json = r#"{"groups":null}"#;
        let nulled: UpdateFederateRequest =
            serde_json::from_str(null_json).expect("null should parse as None");
        assert!(
            nulled.groups.is_none(),
            "null groups must parse as None via Option semantics"
        );
    }

    /// `UpdateFederateRequest::is_outbound` and `address` are bare
    /// `Option<T>` — omission = no-op, presence = replace. No double-Option
    /// because these fields can't be "cleared" (every peer must have an
    /// address and every peer must be inbound or outbound).
    #[test]
    fn update_federate_request_scalar_fields_single_option() {
        let req: UpdateFederateRequest =
            serde_json::from_str(r#"{"address":"10.0.0.1:9001","is_outbound":true}"#)
                .expect("should parse");
        assert_eq!(req.address, Some("10.0.0.1:9001".into()));
        assert_eq!(req.is_outbound, Some(true));
    }

    /// `SuccessResponse<T>` wraps its payload in a single `data` field —
    /// this is the on-the-wire envelope shape that callers (including
    /// the Helm chart's API probe) depend on. A silent rename or removal
    /// of the wrapper would break every REST consumer. The envelope is
    /// `pub(crate)`, which is why we pin it from within the same crate's
    /// test module rather than an integration test.
    #[test]
    fn success_response_serializes_as_data_wrapper() {
        let resp = SuccessResponse { data: "ok" };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(
            json, r#"{"data":"ok"}"#,
            "envelope shape must be {{\"data\": <payload>}}"
        );

        // Nested struct payload should serialize through unchanged — the
        // wrapper must not rename, flatten, or reorder inner fields.
        #[derive(serde::Serialize)]
        struct Inner {
            id: &'static str,
            count: u32,
        }
        let nested = SuccessResponse {
            data: Inner {
                id: "peer-1",
                count: 7,
            },
        };
        let json = serde_json::to_string(&nested).expect("serialize");
        assert_eq!(
            json, r#"{"data":{"id":"peer-1","count":7}}"#,
            "nested payload must serialize verbatim inside data wrapper"
        );
    }

    /// `ErrorResponse` is the paired failure envelope — a single `error`
    /// field carrying the message string. Pinning its shape prevents a
    /// refactor to `{ code, message }` or `{ errors: [...] }` that would
    /// silently break clients matching on the `error` key.
    #[test]
    fn error_response_serializes_as_error_string() {
        let resp = ErrorResponse {
            error: "peer not found".into(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(
            json, r#"{"error":"peer not found"}"#,
            "envelope shape must be {{\"error\": <message>}}"
        );
    }

    /// Debug derives on the three request types must not leak to
    /// `finish_non_exhaustive()` during a refactor — the API layer logs
    /// request envelopes on validation failures (with PII stripped at the
    /// layer above), and a `..` suffix would obscure which fields were
    /// present at the boundary. Smoke-check that Debug produces the
    /// expected struct-shape prefix.
    #[test]
    fn request_types_debug_shape() {
        let create = CreateFederateRequest {
            id: "p".into(),
            address: "1.2.3.4:9001".into(),
            groups: vec![],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::Matrix,
        };
        let dbg = format!("{create:?}");
        assert!(
            dbg.starts_with("CreateFederateRequest"),
            "Debug output should start with struct name, got: {dbg}"
        );
        assert!(
            !dbg.contains(".."),
            "Debug output must not use finish_non_exhaustive, got: {dbg}"
        );

        let update = UpdateFederateRequest {
            address: Some("1.2.3.4:9001".into()),
            groups: None,
            inbound_groups: None,
            outbound_groups: None,
            is_outbound: None,
            trust_cert_cn: None,
        };
        let dbg = format!("{update:?}");
        assert!(dbg.starts_with("UpdateFederateRequest"));

        let set = SetRoutingModeRequest {
            routing_mode: RoutingMode::Broadcast,
        };
        let dbg = format!("{set:?}");
        assert!(dbg.starts_with("SetRoutingModeRequest"));
    }

    /// `default_true()` is a free fn referenced via `#[serde(default =
    /// "default_true")]`. Call it directly to pin the return value
    /// independently of the serde plumbing — if someone "optimizes" this
    /// to `|| false` the serde-path test above catches it, but this
    /// direct test localizes the failure to the helper itself rather than
    /// forcing triangulation through a deserialization diff.
    #[test]
    fn default_true_helper_returns_true() {
        assert!(default_true(), "default_true() must return true");
    }
}
