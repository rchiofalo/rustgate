//! Request and response types for the federation REST API.

use serde::{Deserialize, Serialize};

use crate::config::RoutingMode;

/// Request body for creating a new federate.
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
pub struct UpdateFederateRequest {
    pub address: Option<String>,
    pub groups: Option<Vec<String>>,
    pub inbound_groups: Option<Option<Vec<String>>>,
    pub outbound_groups: Option<Option<Vec<String>>>,
    pub is_outbound: Option<bool>,
    pub trust_cert_cn: Option<Option<String>>,
}

/// Request body for setting routing mode.
#[derive(Debug, Deserialize)]
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
