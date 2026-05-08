// Copyright © 2026 Roberto Chiofalo.

//! Minimal MissionPackageManifest v2 XML parser.
//!
//! TAK Mission Packages carry a `MANIFEST/manifest.xml` inside the
//! ZIP body that describes the package contents and its intended
//! use. The wire schema is informally documented across ATAK CIV,
//! WinTAK, and iTAK source drops; the version-2 form has been
//! stable since 2018. The full schema covers a wide surface
//! (configuration parameters, content entries, role-based
//! visibility, expiration timestamps, mission-package types) but
//! only a small subset is required to validate that a TAK client
//! produced a syntactically-correct manifest.
//!
//! This parser decodes just enough to:
//!
//! 1. Confirm the document is a `<MissionPackageManifest version="2">`.
//! 2. Pull out the `<Configuration>` parameters as a flat
//!    `name → value` map (`uid`, `name`, `onReceiveImport`,
//!    `onReceiveDelete`, etc).
//! 3. Pull out each `<Content>` entry's `zipEntry` and `contentType`.
//!
//! Everything else is intentionally ignored — a future PR can
//! widen the surface (e.g. parsing `<Parameter>` entries inside a
//! `<Content>` for per-asset tagging) without breaking the v2
//! envelope. The parser is fail-soft: unrecognised elements,
//! attribute orderings, and trailing whitespace do not cause a
//! rejection.
//!
//! # Wire example
//!
//! ```xml
//! <MissionPackageManifest version="2">
//!   <Configuration>
//!     <Parameter name="uid" value="11111111-1111-1111-1111-111111111111"/>
//!     <Parameter name="name" value="overlay-bundle"/>
//!     <Parameter name="onReceiveImport" value="true"/>
//!     <Parameter name="onReceiveDelete" value="false"/>
//!   </Configuration>
//!   <Contents>
//!     <Content ignore="false" zipEntry="overlay/main.kml">
//!       <Parameter name="contentType" value="kml"/>
//!     </Content>
//!     <Content ignore="false" zipEntry="overlay/icon.png">
//!       <Parameter name="contentType" value="image/png"/>
//!     </Content>
//!   </Contents>
//! </MissionPackageManifest>
//! ```
//!
//! [`parse_manifest_xml`] is intentionally pure (`&[u8]` → `Result`)
//! so callers can feed it from a memory-mapped ZIP entry, a hot-cache
//! buffer, or a unit-test literal without any IO indirection.

use std::collections::BTreeMap;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{MissionsError, Result};

/// Parsed representation of a TAK MissionPackageManifest v2.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MissionPackageManifest {
    /// Manifest version, parsed from
    /// `<MissionPackageManifest version="…">`. Always `"2"` for the
    /// supported wire form; mismatches surface as a
    /// [`MissionsError::Manifest`] error so a v1 or future-v3
    /// document rejects loudly.
    pub version: String,
    /// Flat key → value map of every `<Parameter name="…" value="…">`
    /// inside `<Configuration>`. Common keys: `uid`, `name`,
    /// `hash`, `onReceiveImport`, `onReceiveDelete`. Values are
    /// passed through verbatim — no boolean coercion, no UID-shape
    /// validation — so a future addition to the schema rides through
    /// without a parser change.
    pub configuration: BTreeMap<String, String>,
    /// Each `<Content zipEntry="…">` entry. The MVP exposes the
    /// archive-relative path and the optional `contentType`
    /// parameter; per-content `<Parameter>` siblings are dropped
    /// because no MVP consumer reads them. A follow-up can widen
    /// this struct without breaking the `version`/`configuration`
    /// surface.
    pub contents: Vec<ManifestContent>,
}

/// Single `<Content>` entry inside a parsed manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestContent {
    /// Archive-relative path to the asset (e.g. `overlay/main.kml`).
    pub zip_entry: String,
    /// Value of the `<Parameter name="contentType" value="…"/>`
    /// child if present; otherwise `None`. ATAK uses this to choose
    /// the import path on receive (KML → overlay manager, image →
    /// gallery, etc.).
    pub content_type: Option<String>,
    /// Value of the `ignore` attribute on the `<Content>` tag if
    /// present, parsed as a string so a future tri-state value does
    /// not need a parser revision. Defaults to `None`, which TAK
    /// clients treat as "process this entry".
    pub ignore: Option<String>,
}

/// Parse a raw `manifest.xml` byte slice into a
/// [`MissionPackageManifest`].
///
/// The parser walks the document with [`quick_xml::Reader`] in
/// streaming mode so manifests of any reasonable size decode in a
/// single pass with no intermediate string allocations beyond the
/// returned struct.
///
/// # Errors
///
/// - [`MissionsError::Manifest`] if the document is not well-formed
///   XML, the root element is not `<MissionPackageManifest>`, the
///   `version` attribute is missing or not `"2"`, or no `<Content>`
///   entries are present (a TAK Mission Package always has at least
///   one).
pub fn parse_manifest_xml(bytes: &[u8]) -> Result<MissionPackageManifest> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);

    let mut version: Option<String> = None;
    let mut configuration: BTreeMap<String, String> = BTreeMap::new();
    let mut contents: Vec<ManifestContent> = Vec::new();

    // State flags — quick_xml fires SAX-like start/end events, so we
    // track which sub-tree we are inside without building a DOM.
    let mut in_root = false;
    let mut in_configuration = false;
    let mut in_contents = false;
    let mut current_content: Option<ManifestContent> = None;

    let mut buf: Vec<u8> = Vec::with_capacity(256);
    loop {
        let event = match reader.read_event_into(&mut buf) {
            Err(e) => {
                return Err(MissionsError::Manifest(format!("xml parse error: {e}")));
            }
            Ok(ev) => ev,
        };

        // Helper closure factored over Start/Empty so a self-closing
        // `<Content zipEntry="…"/>` is treated identically to its
        // long-form `<Content …></Content>` counterpart. Returns
        // `(name, attrs, is_empty)`.
        let mut handle_open =
            |start: &quick_xml::events::BytesStart<'_>, is_empty: bool| -> Result<()> {
                let name_bytes = start.name();
                let name = std::str::from_utf8(name_bytes.as_ref())
                    .map_err(|e| MissionsError::Manifest(format!("non-utf8 element name: {e}")))?
                    .to_string();
                let attrs = start
                    .attributes()
                    .filter_map(std::result::Result::ok)
                    .filter_map(|attr| {
                        let key = std::str::from_utf8(attr.key.as_ref()).ok()?.to_string();
                        let value = std::str::from_utf8(attr.value.as_ref()).ok()?.to_string();
                        Some((key, value))
                    })
                    .collect::<BTreeMap<String, String>>();

                match name.as_str() {
                    "MissionPackageManifest" => {
                        in_root = true;
                        if version.is_none() {
                            version = attrs.get("version").cloned();
                        }
                    }
                    "Configuration" if in_root => {
                        in_configuration = true;
                        if is_empty {
                            in_configuration = false;
                        }
                    }
                    "Contents" if in_root => {
                        in_contents = true;
                        if is_empty {
                            in_contents = false;
                        }
                    }
                    "Parameter" => {
                        // Parameter is reused inside both Configuration
                        // and Content; route based on which subtree we
                        // are currently inside.
                        if in_configuration
                            && let (Some(key), Some(val)) = (attrs.get("name"), attrs.get("value"))
                        {
                            let _ = configuration.insert(key.clone(), val.clone());
                        } else if let Some(content) = current_content.as_mut()
                            && let (Some(key), Some(val)) = (attrs.get("name"), attrs.get("value"))
                            && key == "contentType"
                        {
                            content.content_type = Some(val.clone());
                        }
                    }
                    "Content" if in_contents => {
                        let zip_entry = attrs.get("zipEntry").cloned().unwrap_or_default();
                        let ignore = attrs.get("ignore").cloned();
                        let entry = ManifestContent {
                            zip_entry,
                            content_type: None,
                            ignore,
                        };
                        if is_empty {
                            // Self-closing `<Content zipEntry="…"/>` —
                            // push immediately, no End event to anchor it.
                            contents.push(entry);
                        } else {
                            current_content = Some(entry);
                        }
                    }
                    _ => {}
                }
                Ok(())
            };

        match event {
            Event::Eof => break,
            Event::Start(start) => {
                handle_open(&start, false)?;
            }
            Event::Empty(start) => {
                handle_open(&start, true)?;
            }
            Event::End(end) => {
                let name_bytes = end.name();
                let name = std::str::from_utf8(name_bytes.as_ref())
                    .map_err(|e| MissionsError::Manifest(format!("non-utf8 element name: {e}")))?
                    .to_string();
                match name.as_str() {
                    "Configuration" => in_configuration = false,
                    "Contents" => in_contents = false,
                    "Content" => {
                        if let Some(c) = current_content.take() {
                            contents.push(c);
                        }
                    }
                    "MissionPackageManifest" => in_root = false,
                    _ => {}
                }
            }
            _ => {}
        }
        buf.clear();
    }

    let version =
        version.ok_or_else(|| MissionsError::Manifest("missing version attribute".to_string()))?;
    if version != "2" {
        return Err(MissionsError::Manifest(format!(
            "unsupported manifest version `{version}` (expected `2`)"
        )));
    }
    if contents.is_empty() {
        return Err(MissionsError::Manifest(
            "manifest contains zero <Content> entries".to_string(),
        ));
    }

    Ok(MissionPackageManifest {
        version,
        configuration,
        contents,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    const VALID: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<MissionPackageManifest version="2">
  <Configuration>
    <Parameter name="uid" value="abc-123"/>
    <Parameter name="name" value="sample"/>
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
    fn parses_valid_manifest() {
        let m = parse_manifest_xml(VALID.as_bytes()).unwrap();
        assert_eq!(m.version, "2");
        assert_eq!(m.configuration.get("uid").unwrap(), "abc-123");
        assert_eq!(m.configuration.get("name").unwrap(), "sample");
        assert_eq!(m.contents.len(), 2);
        assert_eq!(m.contents[0].zip_entry, "overlay/main.kml");
        assert_eq!(m.contents[0].content_type.as_deref(), Some("kml"));
        assert_eq!(m.contents[0].ignore.as_deref(), Some("false"));
        assert_eq!(m.contents[1].zip_entry, "overlay/icon.png");
        assert_eq!(m.contents[1].content_type.as_deref(), Some("image/png"));
    }

    #[test]
    fn rejects_wrong_version() {
        let bad = VALID.replace("version=\"2\"", "version=\"1\"");
        let err = parse_manifest_xml(bad.as_bytes()).unwrap_err();
        match err {
            MissionsError::Manifest(msg) => {
                assert!(msg.contains("unsupported manifest version"))
            }
            other => panic!("expected Manifest error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_version() {
        let bad = VALID.replace("version=\"2\"", "");
        let err = parse_manifest_xml(bad.as_bytes()).unwrap_err();
        match err {
            MissionsError::Manifest(msg) => {
                assert!(msg.contains("missing version"))
            }
            other => panic!("expected Manifest error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_contents() {
        let bad = r#"<?xml version="1.0"?>
<MissionPackageManifest version="2">
  <Configuration>
    <Parameter name="uid" value="x"/>
  </Configuration>
  <Contents></Contents>
</MissionPackageManifest>"#;
        let err = parse_manifest_xml(bad.as_bytes()).unwrap_err();
        match err {
            MissionsError::Manifest(msg) => assert!(msg.contains("zero <Content>")),
            other => panic!("expected Manifest error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_xml() {
        let err = parse_manifest_xml(b"<MissionPackageManifest>").unwrap_err();
        match err {
            MissionsError::Manifest(_) => {}
            other => panic!("expected Manifest error, got {other:?}"),
        }
    }

    #[test]
    fn parameter_outside_configuration_is_ignored() {
        let weird = r#"<?xml version="1.0"?>
<MissionPackageManifest version="2">
  <Parameter name="rogue" value="should-not-survive"/>
  <Configuration>
    <Parameter name="uid" value="ok"/>
  </Configuration>
  <Contents>
    <Content zipEntry="a.kml"/>
  </Contents>
</MissionPackageManifest>"#;
        let m = parse_manifest_xml(weird.as_bytes()).unwrap();
        assert!(!m.configuration.contains_key("rogue"));
        assert_eq!(m.configuration.get("uid").unwrap(), "ok");
    }
}
