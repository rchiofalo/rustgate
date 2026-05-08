// Copyright © 2026 Roberto Chiofalo.

//! NFFI (NATO Friendly Force Information, STANAG 5527) XML codec.
//!
//! NFFI — *NATO Friendly Force Information* — is the XML schema
//! family standardised under STANAG 5527 for allied Blue Force
//! Tracking (BFT) interop. NFFI v2.0/v1.3 is adopted across NATO
//! command-and-control suites (Systematic SitaWare, Norwegian
//! NORCCIS, MIP-compliant national systems) as the wire form for
//! exchanging friendly-force position, identification, and
//! operational status across coalition boundaries.
//!
//! This crate ships a pure encode/decode library for that wire
//! form. The transport layer (DDS, SOAP, REST) is the
//! responsibility of a listener crate — this crate accepts an
//! XML payload `&[u8]` and emits / decodes one or more
//! [`NffiTrack`] records without any I/O. The crate also
//! implements the canonical [`rustgate_core::entity::EntityCodec`]
//! trait so the router can fan an entity out across NFFI
//! alongside CoT XML, MAVLink, ASTERIX, STANAG-4586, Meshtastic,
//! VMF, SAPIENT, DIS, and Link 16.
//!
//! # Wire form (STANAG 5527 v2.0)
//!
//! ```xml
//! <nffi xmlns="urn:nato:stanag:5527:nffi:2.0:1">
//!   <track>
//!     <positionalData>
//!       <wgs84Position lat="…" lon="…" alt="…"/>
//!       <kinematics speed="…" course="…" accuracy="…"/>
//!       <datetime>2026-05-08T12:00:00Z</datetime>
//!     </positionalData>
//!     <identificationData>
//!       <sidc>SFGPUCI-----C--</sidc>  <!-- 15-char APP-6A SIDC -->
//!       <unitName>Alpha-1</unitName>
//!       <nationality>USA</nationality>
//!     </identificationData>
//!     <operStatusData>…</operStatusData>
//!   </track>
//! </nffi>
//! ```
//!
//! Coordinate fields ride as IEEE-754 doubles in decimal degrees;
//! altitude rides as a signed metre value. Same-codec round-trip
//! is bit-exact for every wire-format scalar that fits in an
//! `f64`.
//!
//! # MVP scope
//!
//! - **Fully decoded:** the `<nffi>` document envelope, every
//!   `<track>` element under it, the `<positionalData>` block
//!   (`<wgs84Position>`, `<kinematics>`, `<datetime>`), the
//!   `<identificationData>` block (`<sidc>`, `<unitName>`,
//!   `<nationality>`), and a placeholder for `<operStatusData>`
//!   carried verbatim through the [`UnknownElement`] passthrough.
//! - **Carried opaque (round-trip preserving):** every
//!   unrecognised child element under `<track>` is preserved as
//!   an [`UnknownElement`] with its attributes and text body
//!   intact, so a future codec revision that lifts e.g.
//!   `<operStatusData>` into typed fields does not change the
//!   wire form for callers.
//! - **APP-6A SIDC parsing:** the 15-character APP-6A Symbol
//!   Identification Code (`<sidc>` element body) is decoded
//!   into [`AppSixA`] — coding scheme, affiliation, battle
//!   dimension, status — and round-tripped on encode. NFFI
//!   payloads use the legacy APP-6A 15-char form rather than
//!   the MIL-STD-2525D 30-char form; the `Entity::mil_std_2525_sidc`
//!   carry is the verbatim 15-char string so MIL-STD-2525C
//!   consumers can reuse it without a translation step.
//!
//! # Forward compatibility
//!
//! Unknown XML elements under `<track>` are preserved verbatim
//! through [`UnknownElement`] — attributes, text body, and
//! element name all round-trip. A future STANAG 5527 revision
//! that adds (for example) a `<communicationsStatus>` element
//! stays decodable. Malformed XML, invalid lat/lon ranges, and
//! invalid SIDC strings surface as typed [`NffiError`] variants
//! rather than panicking.
//!
//! # What is deliberately absent
//!
//! - **Transport binding.** NFFI rides over DDS topics, SOAP
//!   over HTTP, or REST endpoints depending on the deployment.
//!   The codec consumes / emits the XML payload only — the
//!   transport adapter is the responsibility of the listener
//!   crate that wires NFFI into the routing pipeline.
//! - **`<operStatusData>` typed decode.** Operational-status
//!   fields (fuel, ammunition, casualty count, mission state)
//!   round-trip verbatim through [`UnknownElement`]. A typed
//!   schema is deferred to a follow-up so the MVP wire shape
//!   stays small.
//! - **Schema validation against the STANAG 5527 XSD.** The
//!   parser accepts well-formed XML but does not validate
//!   against the upstream XSD — strict validation belongs in a
//!   policy layer.
//!
//! # Error handling
//!
//! This crate's error type is [`NffiError`]; binary callers
//! propagate it via `?` and map it through `anyhow::Error` at
//! the orchestration layer. The
//! `rustgate_core::error::RustgateError` boundary aggregator
//! (used in the `rustgate-core` / `rustgate-router` slice) is
//! not automatically constructed from [`NffiError`].

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod codec;
pub mod error;
pub mod sidc;

pub use codec::{
    NffiCodec, NffiDocument, NffiTrack, UnknownElement, decode_document, encode_document,
};
pub use error::NffiError;
pub use sidc::{Affiliation, AppSixA, BattleDimension, CodingScheme, Status};

/// Default XML namespace URI for STANAG 5527 NFFI v2.0 payloads.
///
/// Emitted on the root `<nffi>` element by [`encode_document`] when
/// the source document does not carry a namespace. The decoder
/// accepts payloads with or without an explicit namespace — coalition
/// peers in the wild are inconsistent about whether the `xmlns`
/// attribute is present, and refusing payloads without it would break
/// interop with otherwise valid feeds.
pub const NFFI_NAMESPACE: &str = "urn:nato:stanag:5527:nffi:2.0:1";

/// Defense-in-depth cap on total decoded payload size in bytes.
///
/// Bounds an attacker's ability to drive the parser into a runaway
/// allocation via a maliciously large `<nffi>` document. Real
/// coalition NFFI feeds are kilobyte-class — even a track-rich
/// frame rarely exceeds 32 KiB — so the 16 MiB ceiling is far
/// above any legitimate payload while still bounding pathological
/// input.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
