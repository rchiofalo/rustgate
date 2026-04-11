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
}
