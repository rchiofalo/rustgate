// Copyright © 2026 Roberto Chiofalo.

//! End-to-end integration coverage for [`PackageStore`].
//!
//! These tests live outside `src/` so they exercise the public API
//! exactly as the HTTP layer in `rustgate-admin` will. Anything
//! tested here must remain stable across follow-up refactors of the
//! crate internals.

#![allow(clippy::panic, clippy::unwrap_used)]

use rustgate_missions::{
    DEFAULT_MAX_PACKAGE_BYTES, DEFAULT_MAX_TOTAL_BYTES, PackageStore, StoreLimits,
    parse_manifest_xml,
};

fn key() -> Vec<u8> {
    b"integration-test-key-32-bytes-long!".to_vec()
}

#[tokio::test]
async fn upload_persists_across_store_reopen() {
    let dir = tempfile::tempdir().unwrap();

    // Open, upload, drop.
    let meta = {
        let store = PackageStore::new(dir.path().to_path_buf(), key(), StoreLimits::default())
            .await
            .unwrap();
        store
            .upload(b"persisted-zip-body", "a.zip", "operator-1")
            .await
            .unwrap()
    };

    // Re-open the store on the same directory; the existing entry
    // must be visible and the capacity counter must reflect it.
    let store = PackageStore::new(dir.path().to_path_buf(), key(), StoreLimits::default())
        .await
        .unwrap();
    assert_eq!(store.current_total_bytes().await, meta.size);
    let listed = store.list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].hash, meta.hash);

    let (got_meta, got_body) = store.download(&meta.hash).await.unwrap();
    assert_eq!(got_meta, meta);
    assert_eq!(got_body, b"persisted-zip-body");
}

#[tokio::test]
async fn second_store_with_different_key_skips_existing_entries() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = PackageStore::new(dir.path().to_path_buf(), key(), StoreLimits::default())
        .await
        .unwrap();
    let _meta = store_a.upload(b"alpha-body", "a.zip", "op").await.unwrap();
    drop(store_a);

    let other_key = b"a-different-integrity-key-for-test!".to_vec();
    let store_b = PackageStore::new(dir.path().to_path_buf(), other_key, StoreLimits::default())
        .await
        .unwrap();
    // The on-disk sidecar's HMAC was produced with the first key, so
    // the second store cannot verify it. The listing must silently
    // skip it (logged at warn) instead of returning a corrupt entry.
    let listed = store_b.list().await.unwrap();
    assert!(
        listed.is_empty(),
        "entries with foreign-key sidecars must not surface"
    );
    // The capacity counter must also start clean — verification
    // failures at construction time skip the entry.
    assert_eq!(store_b.current_total_bytes().await, 0);
}

#[tokio::test]
async fn default_limits_match_module_constants() {
    let limits = StoreLimits::default();
    assert_eq!(limits.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
    assert_eq!(limits.max_package_bytes, DEFAULT_MAX_PACKAGE_BYTES);
}

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<MissionPackageManifest version="2">
  <Configuration>
    <Parameter name="uid" value="11111111-2222-3333-4444-555555555555"/>
    <Parameter name="name" value="overlay-bundle"/>
    <Parameter name="onReceiveImport" value="true"/>
  </Configuration>
  <Contents>
    <Content ignore="false" zipEntry="overlay/main.kml">
      <Parameter name="contentType" value="kml"/>
    </Content>
    <Content ignore="false" zipEntry="overlay/icon.png">
      <Parameter name="contentType" value="image/png"/>
    </Content>
  </Contents>
</MissionPackageManifest>"#;

#[test]
fn manifest_round_trip_picks_up_known_fields() {
    let m = parse_manifest_xml(MANIFEST.as_bytes()).unwrap();
    assert_eq!(m.version, "2");
    assert_eq!(
        m.configuration.get("uid").unwrap(),
        "11111111-2222-3333-4444-555555555555"
    );
    assert_eq!(m.configuration.get("name").unwrap(), "overlay-bundle");
    assert_eq!(m.contents.len(), 2);
    assert_eq!(m.contents[0].content_type.as_deref(), Some("kml"));
    assert_eq!(m.contents[1].content_type.as_deref(), Some("image/png"));
}
