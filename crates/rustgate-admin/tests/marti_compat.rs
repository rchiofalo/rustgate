// Copyright © 2026 Roberto Chiofalo.

#![cfg(feature = "marti-compat")]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the Marti API compatibility shim (#863).
//!
//! Exercise the `MartiCompatState` dispatcher against the public
//! `handle_request` API end-to-end so the field-stable JSON shapes ATAK
//! relies on are pinned by tests rather than just by inspection.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Method, StatusCode};
use rustgate_admin::marti_compat::{MARTI_PREFIX, MartiCompatState, handle_request};
use rustgate_admin::video::VideoStreamCatalog;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_enrollment::{ContactInfo, ContactsProvider, Credentials, CsrSigner};
use rustgate_missions::{PackageStore, StoreLimits};
use zeroize::Zeroizing;

fn mock_contacts(items: Vec<ContactInfo>) -> ContactsProvider {
    Arc::new(move || {
        let items = items.clone();
        Box::pin(async move { items })
    })
}

async fn body_json(
    resp: hyper::Response<http_body_util::Full<Bytes>>,
) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).expect("Marti response must be valid JSON");
    (status, parsed)
}

#[test]
fn marti_prefix_is_capital_m() {
    // Hard-coded constant — protects against accidental lowercase
    // refactors in case-insensitive editors/IDEs.
    assert_eq!(MARTI_PREFIX, "/Marti/");
}

#[tokio::test]
async fn end_to_end_full_state_round_trip() {
    use rustgate_test_utils::certs::TestCa;

    // CSR signer + credentials.
    let ca = TestCa::new("integration-marti-ca");
    let signer = Arc::new(
        CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "rustgate-int-test").expect("signer"),
    );
    let credentials = Arc::new(Credentials::new(
        "field-operator".to_string(),
        Zeroizing::new("integration-test-pwd-padding-32bytes".to_string()),
    ));

    // Missions package store with one uploaded package.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::new(
        dir.path().to_path_buf(),
        b"marti-int-key-32-byte-padding-12".to_vec(),
        StoreLimits::default(),
    )
    .await
    .unwrap();
    let _ = store
        .upload(b"PK\x03\x04integration-zip-body", "ops.zip", "uploader-cn")
        .await
        .unwrap();

    // Video catalog with one b-i-v event.
    let catalog = Arc::new(VideoStreamCatalog::new());
    let identity = Identity::plaintext("drone-cn".to_string(), BTreeSet::new()).unwrap();
    let payload = r#"<event uid="VID-INT" type="b-i-v-r"><point lat="35.5" lon="-100.2" hae="120"/><detail><__video url="rtsp://10.0.0.5/feed"/><sensor fov="42.5" azimuth="180" elevation="-15"/></detail></event>"#;
    let meta = Metadata::new(
        SystemTime::now(),
        "tcp".to_string(),
        MessageType::Other("b-i-v-r".to_string()),
    );
    catalog.observe(&RoutableMessage {
        source: identity,
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: meta,
    });

    let contacts = mock_contacts(vec![
        ContactInfo {
            uid: "alpha-1".into(),
            callsign: "Alpha-One".into(),
            groups: vec!["Team-Red".into(), "All".into()],
            last_status: "Connected".into(),
        },
        ContactInfo {
            uid: "bravo-2".into(),
            callsign: "Bravo-Two".into(),
            groups: vec!["Team-Blue".into()],
            last_status: "Connected".into(),
        },
    ]);

    let mut state = MartiCompatState::empty();
    state.signer = Some(Arc::clone(&signer));
    state.credentials = Some(Arc::clone(&credentials));
    state.contacts = Some(contacts);
    state.packages = Some(store);
    state.video = Some(catalog);

    // 1. /Marti/api/tls/config — open, returns CA + cipher list.
    let resp = handle_request(
        &Method::GET,
        "/Marti/api/tls/config",
        None,
        None,
        b"",
        &state,
    )
    .await
    .expect("matched");
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["type"], "TlsConfig");
    assert_eq!(json["data"]["organization"], "rustgate-int-test");
    assert!(!json["data"]["caCert"].as_str().unwrap().is_empty());
    assert!(!json["data"]["acceptedCiphers"].as_array().unwrap().is_empty());
    let versions = json["data"]["protocolVersions"].as_array().unwrap();
    assert!(versions.iter().any(|v| v == "TLSv1.3"));

    // 2. /Marti/api/contacts/all — ATAK shape.
    let resp = handle_request(
        &Method::GET,
        "/Marti/api/contacts/all",
        None,
        None,
        b"",
        &state,
    )
    .await
    .expect("matched");
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let alpha = arr
        .iter()
        .find(|c| c["uid"] == "alpha-1")
        .expect("alpha-1 contact");
    assert_eq!(alpha["callsign"], "Alpha-One");
    assert_eq!(alpha["team"], "Team-Red");
    assert_eq!(alpha["takv"], "rustgate");
    assert!(alpha["endpoint"].is_string());
    assert_eq!(alpha["lastStatus"], "Connected");
    let groups = alpha["filterGroups"].as_array().unwrap();
    assert!(groups.iter().any(|g| g == "Team-Red"));

    // 3. /Marti/api/missions — package list.
    let resp = handle_request(&Method::GET, "/Marti/api/missions", None, None, b"", &state)
        .await
        .expect("matched");
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["type"], "Mission");
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["name"], "ops.zip");
    assert_eq!(data[0]["creatorUid"], "uploader-cn");
    assert!(data[0]["hash"].as_str().unwrap().len() == 64);
    assert!(data[0]["size"].as_u64().unwrap() > 0);

    // 4. /Marti/api/video — Feed envelope.
    let resp = handle_request(&Method::GET, "/Marti/api/video", None, None, b"", &state)
        .await
        .expect("matched");
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["type"], "Feed");
    let feeds = json["data"].as_array().unwrap();
    assert_eq!(feeds.len(), 1);
    assert_eq!(feeds[0]["uid"], "VID-INT");
    assert_eq!(feeds[0]["url"], "rtsp://10.0.0.5/feed");
    assert_eq!(feeds[0]["protocol"], "rtsp");
    assert_eq!(feeds[0]["fov"], 42.5);
    assert_eq!(feeds[0]["lat"], 35.5);

    // 5. /Marti/api/tls/signClient — Basic auth → PKCS#12.
    let csr_keypair = rcgen::KeyPair::generate().expect("gen key");
    let mut csr_params = rcgen::CertificateParams::new(vec![]).expect("params");
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "field-operator");
    csr_params.distinguished_name = dn;
    let csr_pem = csr_params
        .serialize_request(&csr_keypair)
        .expect("serialize CSR")
        .pem()
        .expect("PEM");

    let basic = rustgate_core::b64::encode(b"field-operator:integration-test-pwd-padding-32bytes");
    let auth = format!("Basic {basic}");

    let resp = handle_request(
        &Method::POST,
        "/Marti/api/tls/signClient",
        Some(&auth),
        None,
        csr_pem.as_bytes(),
        &state,
    )
    .await
    .expect("matched");
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "application/x-pkcs12");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    // PKCS#12 starts with `0x30 0x82` (SEQUENCE, long-form length).
    assert!(bytes.len() > 16);
    assert_eq!(bytes[0], 0x30);
    assert_eq!(bytes[1], 0x82);

    // 6. /Marti/api/tls/signClient with bad auth → 401 + WWW-Authenticate.
    let resp = handle_request(
        &Method::POST,
        "/Marti/api/tls/signClient",
        Some("Basic d3JvbmctdXNlcjp3cm9uZy1wYXNz"),
        None,
        csr_pem.as_bytes(),
        &state,
    )
    .await
    .expect("matched");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers().get("WWW-Authenticate").is_some(),
        "401 from signClient must include WWW-Authenticate so ATAK retries"
    );
}

#[tokio::test]
async fn empty_state_yields_quiet_success_envelopes() {
    // The compat shim must not error a deployment that has not wired
    // up every subsystem yet — empty state surfaces as silent-success
    // envelopes so ATAK does not spin in retry loops.
    let state = MartiCompatState::empty();

    let resp = handle_request(&Method::GET, "/Marti/api/missions", None, None, b"", &state)
        .await
        .unwrap();
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"].as_array().unwrap().is_empty());

    let resp = handle_request(
        &Method::GET,
        "/Marti/api/contacts/all",
        None,
        None,
        b"",
        &state,
    )
    .await
    .unwrap();
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.as_array().unwrap().is_empty());

    let resp = handle_request(&Method::GET, "/Marti/api/video", None, None, b"", &state)
        .await
        .unwrap();
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"].as_array().unwrap().is_empty());

    // signClient is the exception — it returns 503 because there is no
    // sensible empty PKCS#12 to ship.
    let resp = handle_request(
        &Method::POST,
        "/Marti/api/tls/signClient",
        Some("Basic dGVzdDp0ZXN0"),
        None,
        b"",
        &state,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn signclient_trailing_slash_is_accepted() {
    // ATAK builds the URL with a trailing slash; pre-2024 TAK Server
    // ships the route both ways. Mirror that.
    let state = MartiCompatState::empty();

    let resp = handle_request(
        &Method::POST,
        "/Marti/api/tls/signClient/",
        Some("Basic dGVzdDp0ZXN0"),
        None,
        b"",
        &state,
    )
    .await
    .unwrap();
    // 503 because no signer is wired (state is empty), but the route
    // matched — that's what we're testing here.
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn bearer_token_gates_read_only_endpoints() {
    let mut state = MartiCompatState::empty();
    state.auth_token = Some(Zeroizing::new(
        b"marti-integration-bearer-padding-32-bytes".to_vec(),
    ));

    for path in [
        "/Marti/api/missions",
        "/Marti/api/contacts/all",
        "/Marti/api/video",
    ] {
        let resp = handle_request(&Method::GET, path, None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{} must require bearer when token configured",
            path
        );

        let auth = format!(
            "Bearer {}",
            String::from_utf8(b"marti-integration-bearer-padding-32-bytes".to_vec()).unwrap()
        );
        let resp = handle_request(&Method::GET, path, Some(&auth), None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // /Marti/api/tls/config is documented as the unauthenticated
    // preflight endpoint — TAK clients hit it before they have a
    // truststore, let alone an admin token. Stay open.
    let resp = handle_request(
        &Method::GET,
        "/Marti/api/tls/config",
        None,
        None,
        b"",
        &state,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
