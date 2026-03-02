//! Contacts provider for Marti API compatibility.
//!
//! Defines the callback type and data structures used by the
//! `/Marti/api/contacts/all` and `/Marti/api/clientEndPoints` endpoints.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Information about a connected client, returned by the contacts API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContactInfo {
    /// Client UID (certificate CN).
    pub uid: String,
    /// Client callsign (same as CN for mTLS clients).
    pub callsign: String,
    /// Group memberships.
    pub groups: Vec<String>,
    /// Whether the client is currently connected.
    #[serde(rename = "lastStatus")]
    pub last_status: String,
}

/// Async callback that returns a snapshot of connected clients.
///
/// The enrollment server calls this when it receives a contacts or
/// clientEndPoints request. The callback is provided by the server
/// binary and typically queries the Router's session state.
pub type ContactsProvider =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Vec<ContactInfo>> + Send>> + Send + Sync>;
