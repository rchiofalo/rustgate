// Copyright © 2026 Roberto Chiofalo.

//! Declarative schema format and generic codec for wire-format codec
//! authoring without writing Rust per protocol.
//!
//! Inspired by the OMG XTCE (XML Telemetric and Command Exchange)
//! spec used by NASA / ESA mission control software (Yamcs, Open MCT)
//! and the spirit of CCSDS Space Packet Protocol descriptors. The
//! rustgate-codec-schema crate is *not* a full XTCE implementation —
//! XTCE is a 200+ page standard with dozens of optional features
//! (algorithmic calibration, container inheritance, parameter
//! aggregation, derived parameters, …). Tonight's scope ships the
//! 80% of practical wire-format definitions in a much smaller
//! surface:
//!
//! - **Fixed-offset binary fields** with little- and big-endian
//!   primitive types (`u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`,
//!   `i64`, `f32`, `f64`) and fixed-length byte slices / UTF-8
//!   strings.
//! - **Linear calibration** (`physical = raw * scale + offset`) for
//!   real-world units, applied during decode and reversed on
//!   encode.
//! - **Field-to-[`Entity`](rustgate_core::entity::Entity)
//!   projection** via dotted-path mapping rules — the same path
//!   vocabulary used by the existing rustgate property mappers in
//!   `rustgate-dds`, `rustgate-foundry`, and `rustgate-ogc-sensorthings`.
//! - **Round-trip discipline** — a payload that decodes to an
//!   `Entity` re-encodes to the byte-identical payload, modulo
//!   fields the [`Entity`](rustgate_core::entity::Entity) shape
//!   does not carry (those round-trip via
//!   `Entity::attributes` under a `schema.<message-type>.<field>`
//!   key).
//!
//! ## Out of scope (for now)
//!
//! - XML-shaped wire formats (NFFI, raw CoT XML, OGC SensorThings
//!   responses). Those need a richer schema grammar with
//!   xpath-style anchors and recursive element trees. Future
//!   schema versions can layer this on top of the binary-first
//!   v1.
//! - Polynomial / spline calibration. Linear gets us 95% of
//!   sensor wire formats.
//! - Variable-shift conditional fields (the kind where the field
//!   actually disappears from the wire when absent, and subsequent
//!   offsets slide). The v3 grammar ships the sparse-projection
//!   interpretation via [`schema::PresentIfSpec`]: the byte
//!   range stays fixed-offset whether the field is "present" or
//!   not, only the `Entity` projection is gated. Real variable-
//!   shift semantics are a separate v4 feature.
//! - Bit-packed fields. The existing hand-rolled `rustgate-vmf`
//!   and `rustgate-link16` codecs use bit-level FPI / FRI / GPI
//!   indicators that don't fit a fixed-offset / fixed-length
//!   model. Schema-driven ports of those codecs land after we
//!   add bit-field support.
//!
//! ## Two-PR rollout
//!
//! This crate is the foundation. The follow-up PR ports
//! `rustgate-nffi` to schema-driven (NFFI is XML so the
//! schema-driven path will need the XML extensions first — and
//! `rustgate-meshtastic` may end up being the first real port
//! since it's a binary protobuf-like wire that fits the fixed-
//! offset model better). The order is determined by which codec
//! is easiest to port given the schema surface this crate ships.

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod codec;
pub mod error;
pub mod schema;

pub use codec::SchemaCodec;
pub use error::{SchemaCodecError, SchemaError};
pub use schema::{
    Calibration, Endian, FieldDef, FieldType, MessageType, PresentIfSpec, Range, Schema,
    SchemaVersion, ValueMapping,
};
