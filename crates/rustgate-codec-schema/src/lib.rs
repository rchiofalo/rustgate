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
//! ## Grammar overview
//!
//! See [`docs/codec-schema-grammar.md`][grammar-docs] for the single-
//! reference guide to every grammar feature. Brief summary of what
//! the runtime accepts today:
//!
//! - **v1** (#1352): Fixed-offset primitives + linear calibration +
//!   range guards + `entity-path` projection.
//! - **v2** (#1370): Multi-message dispatch via a discriminator byte;
//!   `value-mapping` (typed enum projection).
//! - **v3** (#1383 / #1385 / #1387 / #1389): `present-if` sparse-
//!   projection; `repeat` count-driven byte arrays; bit-packed sub-
//!   byte fields constrained to one byte.
//! - **v4** (#1402): Cross-byte bit spans (`bit_offset + bit_width >
//!   8` now legal) and bit-packed `u16` / `u32` / `u64`.
//! - **v4.1** (#1404): Signed bit-packed types (`i8` / `i16` / `i32`
//!   / `i64`) with two's-complement sign-extension on decode.
//!
//! [grammar-docs]: ../../docs/codec-schema-grammar.md
//!
//! ## Out of scope (tracked)
//!
//! - XML-shaped wire formats (NFFI, raw CoT XML, OGC SensorThings
//!   responses). Those need a richer schema grammar with
//!   xpath-style anchors and recursive element trees. Future
//!   schema versions can layer this on top of the binary-first
//!   v1.
//! - Polynomial / spline calibration. Linear gets us 95% of
//!   sensor wire formats.
//! - **Variable-shift conditional fields** (the kind where the field
//!   actually disappears from the wire when absent, and subsequent
//!   offsets slide). The current `present-if` ships the sparse-
//!   projection interpretation via [`schema::PresentIfSpec`]: the
//!   byte range stays fixed-offset whether the field is "present"
//!   or not, only the `Entity` projection is gated. Real variable-
//!   shift semantics — needed for VMF K05.1's FPI cascade
//!   (#1396) — are a separate v5 feature.
//! - Nested typed-record arrays. [`schema::RepeatSpec`] handles
//!   count-driven byte arrays (`Bytes`-only, surfaced as a single
//!   byte slice the consumer parses themselves) — enough for DIS
//!   articulation params, ASTERIX repetitive items, MAVLink v2
//!   payloads, and Link 16 word-3 extensions. Per-record field-list
//!   schemas where each element carries its own decode pipeline are
//!   a v6 feature.
//! - Schema chaining (one schema dispatching into another based on a
//!   discriminator). Compose at the call site in the wrapper until
//!   the grammar grows native support.
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
    Calibration, Endian, FieldDef, FieldType, MessageType, PresentIfSpec, Range, RepeatSpec,
    Schema, SchemaVersion, ShiftMode, ValueMapping,
};
