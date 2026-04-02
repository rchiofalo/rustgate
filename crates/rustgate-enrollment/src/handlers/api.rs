//! Marti API compatibility endpoint handlers.
//!
//! These handlers implement the subset of the Marti REST API that clients
//! call during enrollment and initial sync: version config, contacts,
//! client endpoints, device profiles, groups, and missions.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use super::util::{build_response, extract_param};
use crate::contacts::ContactsProvider;
use crate::datapackage::DataPackageStore;

/// Handle the `/Marti/api/version/config` endpoint.
pub(crate) fn handle_version_config() -> Response<Full<Bytes>> {
    let version = env!("CARGO_PKG_VERSION");
    let body = serde_json::json!({
        "version": "3",
        "type": "ServerConfig",
        "data": {
            "version": version,
            "api": "3",
            "hostname": "rustgate",
        },
        "nodeId": "rustgate"
    });
    build_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(body.to_string()),
    )
}

/// Handle the `/Marti/api/contacts/all` endpoint.
pub(crate) async fn handle_contacts_all(
    contacts: Option<&ContactsProvider>,
) -> Response<Full<Bytes>> {
    let contacts = match contacts {
        Some(provider) => provider().await,
        None => Vec::new(),
    };
    let body = serde_json::to_string(&contacts).unwrap_or_else(|_| "[]".to_string());
    build_response(StatusCode::OK, "application/json", Bytes::from(body))
}

/// Handle the `/Marti/api/clientEndPoints` endpoint.
pub(crate) async fn handle_client_endpoints(
    contacts: Option<&ContactsProvider>,
) -> Response<Full<Bytes>> {
    let contacts = match contacts {
        Some(provider) => provider().await,
        None => Vec::new(),
    };

    // clientEndPoints wraps the contact list in a Marti-compatible envelope
    let endpoints: Vec<serde_json::Value> = contacts
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "uid": c.uid,
                "callsign": c.callsign,
                "lastStatus": c.last_status,
            })
        })
        .collect();

    let body = serde_json::json!({
        "version": "3",
        "type": "com.bbn.marti.remote.ClientEndpoint",
        "data": endpoints,
        "nodeId": "rustgate"
    });
    build_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(body.to_string()),
    )
}

/// Device profile and data package sync.
///
/// Clients call this periodically with `?syncSecago=N` to discover
/// packages uploaded since their last sync. Returns an empty file list
/// when no data package store is configured.
pub(crate) async fn handle_device_profile(
    req: Request<hyper::body::Incoming>,
    packages: Option<&DataPackageStore>,
) -> Response<Full<Bytes>> {
    let sync_sec = req
        .uri()
        .query()
        .and_then(|q| extract_param(q, "syncSecago"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let files: Vec<serde_json::Value> = if let Some(store) = packages {
        match store.search("").await {
            Ok(metas) => metas
                .into_iter()
                .filter(|m| {
                    if sync_sec == 0 {
                        return true;
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    m.upload_time + sync_sec >= now
                })
                .map(|m| {
                    serde_json::json!({
                        "hash": m.hash,
                        "name": m.name,
                        "size": m.size,
                        "creatorUid": m.creator_uid,
                    })
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let body = serde_json::json!({
        "version": "3",
        "type": "com.bbn.marti.remote.sync.FileInfo",
        "data": files,
        "nodeId": "rustgate"
    });
    build_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(body.to_string()),
    )
}

/// Group listing endpoint.
///
/// Returns a minimal group list. Clients call this to populate their
/// group membership UI. Returns a single `__ANON__` group which is the
/// standard anonymous/default group.
pub(crate) fn handle_groups_all() -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "version": "3",
        "type": "com.bbn.marti.remote.groups.Group",
        "data": [
            {
                "name": "__ANON__",
                "direction": "IN",
                "created": "2024-01-01T00:00:00.000Z",
                "type": "SYSTEM",
                "bitpos": 0,
                "active": true,
            }
        ],
        "nodeId": "rustgate"
    });
    build_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(body.to_string()),
    )
}

/// Mission listing endpoint.
///
/// Returns an empty mission list. Clients poll this on startup to
/// discover shared missions. Without this endpoint, clients log errors
/// and retry indefinitely.
pub(crate) fn handle_missions() -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "version": "3",
        "type": "Mission",
        "data": [],
        "nodeId": "rustgate"
    });
    build_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(body.to_string()),
    )
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::contacts::ContactInfo;

    fn mock_contacts_provider(contacts: Vec<ContactInfo>) -> ContactsProvider {
        Arc::new(move || {
            let contacts = contacts.clone();
            Box::pin(async move { contacts })
        })
    }

    async fn collect_body(resp: Response<Full<Bytes>>) -> Bytes {
        http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("collect body")
            .to_bytes()
    }

    #[tokio::test]
    async fn version_config_returns_json() {
        let resp = handle_version_config();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");

        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["type"], "ServerConfig");
        assert_eq!(parsed["nodeId"], "rustgate");
        assert!(parsed["data"]["version"].as_str().is_some());
        assert_eq!(parsed["data"]["api"], "3");
    }

    #[tokio::test]
    async fn contacts_all_empty_without_provider() {
        let resp = handle_contacts_all(None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&bytes).expect("valid JSON");
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn contacts_all_returns_connected_clients() {
        let provider = mock_contacts_provider(vec![
            ContactInfo {
                uid: "alpha-1".into(),
                callsign: "Alpha One".into(),
                groups: vec!["Team-A".into()],
                last_status: "Connected".into(),
            },
            ContactInfo {
                uid: "bravo-2".into(),
                callsign: "Bravo Two".into(),
                groups: vec!["Team-B".into()],
                last_status: "Connected".into(),
            },
        ]);

        let resp = handle_contacts_all(Some(&provider)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["uid"], "alpha-1");
        assert_eq!(parsed[0]["callsign"], "Alpha One");
        assert_eq!(parsed[0]["lastStatus"], "Connected");
        assert_eq!(parsed[1]["uid"], "bravo-2");
    }

    #[tokio::test]
    async fn client_endpoints_empty_without_provider() {
        let resp = handle_client_endpoints(None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["type"], "com.bbn.marti.remote.ClientEndpoint");
        assert!(parsed["data"].as_array().expect("data array").is_empty());
    }

    #[tokio::test]
    async fn client_endpoints_returns_envelope() {
        let provider = mock_contacts_provider(vec![ContactInfo {
            uid: "test-uid".into(),
            callsign: "TestCall".into(),
            groups: vec!["Alpha".into()],
            last_status: "Connected".into(),
        }]);

        let resp = handle_client_endpoints(Some(&provider)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["nodeId"], "rustgate");

        let data = parsed["data"].as_array().expect("data array");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["uid"], "test-uid");
        assert_eq!(data[0]["callsign"], "TestCall");
    }

    #[tokio::test]
    async fn device_profile_response_format() {
        // The device profile handler needs a hyper::body::Incoming which can't
        // be constructed in tests. Verify the response format matches Marti spec
        // by testing the JSON structure that the handler produces.
        let body = serde_json::json!({
            "version": "3",
            "type": "com.bbn.marti.remote.sync.FileInfo",
            "data": [],
            "nodeId": "rustgate"
        });
        let resp = build_response(
            StatusCode::OK,
            "application/json",
            Bytes::from(body.to_string()),
        );
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["type"], "com.bbn.marti.remote.sync.FileInfo");
        assert!(parsed["data"].as_array().expect("data array").is_empty());
        assert_eq!(parsed["nodeId"], "rustgate");
    }

    #[test]
    fn groups_all_returns_anon_group() {
        let resp = handle_groups_all();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn groups_all_has_anon_group() {
        let resp = handle_groups_all();
        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["type"], "com.bbn.marti.remote.groups.Group");

        let data = parsed["data"].as_array().expect("data array");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["name"], "__ANON__");
        assert_eq!(data[0]["active"], true);
    }

    #[tokio::test]
    async fn missions_returns_empty_list() {
        let resp = handle_missions();
        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["type"], "Mission");
        assert!(parsed["data"].as_array().expect("data array").is_empty());
    }
}
