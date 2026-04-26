// Copyright © 2026 Roberto Chiofalo.

//! STANAG 4586 LOI 4 route upload command message.
//!
//! Carries the fifth **command-side** message in the
//! `rustgate-stanag4586` crate, following waypoint upload
//! ([`crate::waypoint_command`]), sensor pointing
//! ([`crate::sensor_pointing_command`]), mission abort
//! ([`crate::mission_abort_command`]), and GCS handover
//! ([`crate::gcs_handover_command`]). Where the prior four
//! command-side frames each carry a fixed 32-byte payload,
//! `RouteUploadCommand` is the first **variable-length** LOI 4 frame:
//! it carries an ordered sequence of waypoint references that together
//! form the active mission route. A Ground Control Station emits one
//! `RouteUploadCommand` to load (or replace, or extend) the platform's
//! current route in a single round trip rather than streaming the
//! constituent waypoints one-at-a-time across N
//! [`crate::waypoint_command`] frames.
//!
//! # Operational model
//!
//! Routes are how a UAS expresses "fly this multi-leg mission" — a
//! sequence of waypoint references the platform navigates in order. A
//! typical workflow looks like:
//!
//! 1. The GCS uploads each constituent waypoint individually via
//!    [`crate::waypoint_command`] (or via a pre-loaded mission package
//!    that the platform already knows about). Each waypoint has a
//!    deployment-defined identifier — opaque to this codec.
//! 2. The GCS then emits a `RouteUploadCommand` carrying the ordered
//!    list of waypoint identifiers as `waypoint_indices`. The platform
//!    looks each identifier up locally against its waypoint store and
//!    applies the route per the chosen [`RouteKind`]
//!    ([`RouteKind::Replace`] for "this is the active route now,
//!    discard whatever was previously there", [`RouteKind::Append`] for
//!    "extend the existing route with these waypoints",
//!    [`RouteKind::Insert`] for "splice these into the existing route"
//!    — semantics on where to splice are deployment-defined and out of
//!    scope for the codec).
//! 3. The platform begins executing the route at `start_unix_ms` (or
//!    immediately if the field is `0`) and abandons it at
//!    `expiry_unix_ms` (or never, if that field is `0`).
//!
//! An **empty route** (`waypoint_count == 0`) is the documented
//! "clear active route" operation: the platform discards its current
//! route bookkeeping and reverts to whatever its no-route default
//! behaviour is (typically loiter-at-present-position pending operator
//! input). The codec accepts the empty case cleanly — pinned by
//! `decode_accepts_empty_route_with_zero_waypoint_count` — rather than
//! treating it as a wire-format defect.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is **variable**: a fixed [`ROUTE_UPLOAD_HEADER_LEN`] = 32
//! byte header followed by exactly `2 * waypoint_count` bytes of
//! u16 big-endian waypoint indices.
//!
//! ```text
//! offset │ size      │ field           │ type
//! ───────┼───────────┼─────────────────┼──────────────────────────
//!   0    │     4     │ vehicle_id      │ u32  big-endian
//!   4    │     4     │ route_id        │ u32  big-endian
//!   8    │     2     │ waypoint_count  │ u16  big-endian (≤ 256)
//!  10    │     1     │ route_kind      │ u8   enum value (see below)
//!  11    │     5     │ reserved        │ zero-padded — must be 0 on encode
//!  16    │     8     │ start_unix_ms   │ u64  big-endian (Unix epoch ms)
//!  24    │     8     │ expiry_unix_ms  │ u64  big-endian (Unix epoch ms)
//!  32    │ 2 × N     │ waypoint_indices│ N × u16 big-endian, N = waypoint_count
//! ```
//!
//! The reserved block is zero-filled on encode. The decoder does NOT
//! validate that it is zero on the wire so a future spec revision that
//! allocates the bytes (e.g. a route-priority byte, a per-route flags
//! word, or a command sequence number for matching against the future
//! response message) stays backward-compatible at the frame-length
//! level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames and the LOI
//!   4 [`crate::waypoint_command`] /
//!   [`crate::sensor_pointing_command`] /
//!   [`crate::mission_abort_command`] /
//!   [`crate::gcs_handover_command`] frames so a GCS can correlate
//!   "which route did I upload to which platform" against "which
//!   platform's telemetry am I currently displaying" by direct byte
//!   comparison without an intermediate lookup table.
//! - `route_id` — operator-supplied route identifier. Opaque to the
//!   codec — the wire byte is whatever the deployment's route-numbering
//!   scheme uses. Typically used by the platform to correlate a route
//!   upload with later telemetry that references the active route by
//!   ID, or by the GCS to discriminate "did the platform accept the
//!   route I just uploaded, or am I looking at a stale one from a
//!   previous mission".
//! - `waypoint_count` — number of waypoint references that follow the
//!   header. Range-checked on decode: `<= MAX_ROUTE_WAYPOINTS = 256`.
//!   The cap is a sanity bound rather than a spec ceiling — a route
//!   with more than 256 hops is operationally implausible and a client
//!   sending a larger count is likely a misconfiguration or a
//!   wire-format mismatch (a length field that has been byte-swapped,
//!   a wrong message type, …) so failing fast is more useful than
//!   accepting a 65535-waypoint route and tying up the platform's
//!   waypoint resolution path. An empty route (`count == 0`) is
//!   explicitly accepted as the "clear active route" operation.
//! - `route_kind` — which route-load semantics the platform should
//!   apply. See [`RouteKind`].
//! - `start_unix_ms` — when the route should begin executing,
//!   milliseconds since the Unix epoch. **`0` is the documented
//!   "immediate" sentinel** — a regression that rejected `0` as
//!   "off the Unix epoch" or required a future time would silently
//!   drop every immediate route upload (the most common operational
//!   case). The codec does not validate the value otherwise.
//! - `expiry_unix_ms` — when the route should be abandoned,
//!   milliseconds since the Unix epoch. **`0` is the documented
//!   "never expires" sentinel**. The codec does not validate the
//!   value (an expiry that precedes `start_unix_ms` is the platform's
//!   mission-management layer's problem rather than a codec concern).
//! - `waypoint_indices` — the ordered sequence of waypoint
//!   identifiers, each a `u16` big-endian. Each value is an opaque
//!   reference looked up locally against the platform's waypoint
//!   store; **the codec does not validate that the referenced
//!   waypoints exist** — that gate lives at the platform's mission-
//!   management layer. Cross-frame correlation: the values typically
//!   reference waypoints previously uploaded via
//!   [`crate::waypoint_command`] (`waypoint_id` field), but the codec
//!   does not enforce that relationship — a route can equally
//!   reference waypoints from a pre-loaded mission package that the
//!   platform already had in memory before the GCS connected.
//!
//! # What is deliberately absent
//!
//! - **Other LOI 4 commands** — payload control, mode change. Each is
//!   a separate follow-up PR with its own wire format and validation
//!   rules.
//! - **Response / acknowledgement messages** — the bidirectional
//!   command-response handshake (the platform's "route accepted,
//!   N/M waypoints resolved" or "route rejected, waypoint id 0x42
//!   unknown" reply) is a separate follow-up PR.
//! - **Per-waypoint inline payloads** — a future spec revision could
//!   inline full waypoint definitions (lat/lon/alt) instead of
//!   referencing them by ID; this codec ships the reference-by-ID
//!   form only, matching the current spec's separation between
//!   "upload waypoint" and "upload route" messages.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of the route upload command header.
///
/// The full frame is `ROUTE_UPLOAD_HEADER_LEN + 2 * waypoint_count`
/// bytes — the variable trailer carries the u16 big-endian waypoint
/// indices.
pub const ROUTE_UPLOAD_HEADER_LEN: usize = 32;

/// Maximum supported number of waypoint references in a single route.
///
/// Sanity bound rather than a spec ceiling — see the module-level
/// docs' discussion of `waypoint_count` for the rationale. A decoder
/// that observes a `waypoint_count` greater than this cap returns
/// [`Stanag4586Error::FieldOutOfRange`] rather than allocating an
/// arbitrary-sized buffer for the trailer.
pub const MAX_ROUTE_WAYPOINTS: usize = 256;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_ROUTE_ID: usize = 4;
const OFF_WAYPOINT_COUNT: usize = 8;
const OFF_ROUTE_KIND: usize = 10;
// 11..16 reserved (5 bytes)
const OFF_START_UNIX_MS: usize = 16;
const OFF_EXPIRY_UNIX_MS: usize = 24;

/// Which route-load semantics the platform should apply.
///
/// The three named variants cover the LOI 4 route-upload minimum-
/// viable semantics vocabulary: discard the existing route and install
/// the uploaded sequence as the new active route ([`RouteKind::Replace`]),
/// extend the existing route with the uploaded waypoints appended at
/// the end ([`RouteKind::Append`]), or splice the uploaded waypoints
/// into the existing route at a deployment-defined position
/// ([`RouteKind::Insert`]). [`RouteKind::Other`] preserves any
/// unrecognised wire byte so a future spec revision that allocates a
/// new route-load semantics (a `Prepend`, a `ReplaceAfterCurrent`, a
/// merge-with-conflict-resolution variant) stays decodable on a
/// receiver running today's build — matches the same forward-compat
/// discipline used by every sibling LOI 2-3 / LOI 4 frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant       |
/// |-------|---------------|
/// | `0x01`| `Replace`     |
/// | `0x02`| `Append`      |
/// | `0x03`| `Insert`      |
/// | other | `Other(byte)` |
///
/// `0x00` deliberately falls into [`RouteKind::Other`] rather than
/// having its own "Unknown" variant — the encode side never emits
/// `0x00` for a named variant, so observing one on decode means the
/// upstream sent something unintended and the operator should be able
/// to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// Discard the existing route and install the uploaded sequence
    /// as the new active route.
    Replace,
    /// Extend the existing route with the uploaded waypoints appended
    /// at the end.
    Append,
    /// Splice the uploaded waypoints into the existing route at a
    /// deployment-defined position.
    Insert,
    /// Forward-compat catch-all for route-kind bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl RouteKind {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Replace,
            0x02 => Self::Append,
            0x03 => Self::Insert,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Replace => 0x01,
            Self::Append => 0x02,
            Self::Insert => 0x03,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 route upload command message.
///
/// First variable-length LOI 4 frame: the wire payload is a
/// [`ROUTE_UPLOAD_HEADER_LEN`]-byte header followed by exactly
/// `2 * waypoint_indices.len()` bytes of u16 big-endian waypoint
/// indices.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteUploadCommand {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Operator-supplied route identifier. Opaque to the codec.
    pub route_id: u32,
    /// Which route-load semantics the platform should apply.
    pub route_kind: RouteKind,
    /// When the route should begin executing, milliseconds since the
    /// Unix epoch. `0` represents an immediate start.
    pub start_unix_ms: u64,
    /// When the route should be abandoned, milliseconds since the
    /// Unix epoch. `0` represents "never expires".
    pub expiry_unix_ms: u64,
    /// Ordered sequence of waypoint identifiers. Each is an opaque
    /// reference resolved locally by the platform against its waypoint
    /// store. Empty means "clear active route". Length is capped at
    /// [`MAX_ROUTE_WAYPOINTS`] on decode.
    pub waypoint_indices: Vec<u16>,
}

impl RouteUploadCommand {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a route upload command frame into a freshly allocated
/// `Vec<u8>`.
#[must_use]
pub fn encode(msg: &RouteUploadCommand) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(ROUTE_UPLOAD_HEADER_LEN + 2 * msg.waypoint_indices.len());
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends `ROUTE_UPLOAD_HEADER_LEN + 2 *
/// msg.waypoint_indices.len()` bytes; does not clear or truncate
/// `buf`.
///
/// # Encoding semantics
///
/// The encoder writes `msg.waypoint_indices.len()` into the
/// `waypoint_count` wire field, **saturating at `u16::MAX` on
/// overflow** (a `Vec::len()` value above `u16::MAX` is rejected by
/// truncation rather than panicking, which preserves the no-panics-
/// in-production discipline; in practice no caller should approach
/// this since [`MAX_ROUTE_WAYPOINTS`] is 256). The encoder does NOT
/// enforce the [`MAX_ROUTE_WAYPOINTS`] cap — that gate lives on the
/// decode path, so a sending peer that wants to ship more than 256
/// waypoints can do so, but its receiver will reject the frame.
pub fn encode_into(msg: &RouteUploadCommand, buf: &mut BytesMut) {
    let count = u16::try_from(msg.waypoint_indices.len()).unwrap_or(u16::MAX);
    buf.reserve(ROUTE_UPLOAD_HEADER_LEN + 2 * usize::from(count));
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.route_id);
    buf.put_u16(count);
    buf.put_u8(msg.route_kind.to_byte());
    // 5 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u64(msg.start_unix_ms);
    buf.put_u64(msg.expiry_unix_ms);
    for idx in msg.waypoint_indices.iter().take(usize::from(count)) {
        buf.put_u16(*idx);
    }
}

/// Decode a route upload command frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() <
///   ROUTE_UPLOAD_HEADER_LEN` (the header itself is truncated).
/// - [`Stanag4586Error::FieldOutOfRange`] if the declared
///   `waypoint_count` exceeds [`MAX_ROUTE_WAYPOINTS`].
/// - [`Stanag4586Error::FrameTooShort`] if the buffer is shorter than
///   `ROUTE_UPLOAD_HEADER_LEN + 2 * declared_count` (the trailer is
///   truncated relative to the count the header advertised).
///
/// Trailing bytes beyond the declared frame length
/// (`ROUTE_UPLOAD_HEADER_LEN + 2 * declared_count`) are ignored; the
/// decoder reads exactly the declared payload and silently discards
/// the rest. A future protocol revision that appends a per-frame
/// trailer keeps decoding the prefix unchanged.
///
/// Unrecognised `route_kind` bytes do NOT cause an error — they
/// surface as [`RouteKind::Other`] for forward compatibility.
///
/// All other numeric fields accept any wire value — `vehicle_id` and
/// `route_id` are opaque deployment-defined identifiers, the two
/// timestamps are not range-checked (`0` is the documented sentinel
/// for "immediate start" / "never expires"), and the waypoint
/// indices themselves are opaque references that the platform
/// resolves against its local waypoint store rather than the codec.
pub fn decode(bytes: &[u8]) -> Result<RouteUploadCommand, Stanag4586Error> {
    if bytes.len() < ROUTE_UPLOAD_HEADER_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: ROUTE_UPLOAD_HEADER_LEN,
        });
    }

    let mut cursor = &bytes[..ROUTE_UPLOAD_HEADER_LEN];
    let vehicle_id = cursor.get_u32();
    let route_id = cursor.get_u32();
    let waypoint_count = cursor.get_u16();
    let route_kind = RouteKind::from_byte(cursor.get_u8());
    // Skip 5-byte reserved region.
    cursor.advance(5);
    let start_unix_ms = cursor.get_u64();
    let expiry_unix_ms = cursor.get_u64();

    debug_assert!(
        cursor.is_empty(),
        "fixed-size header should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_ROUTE_ID;
    let _ = OFF_WAYPOINT_COUNT;
    let _ = OFF_ROUTE_KIND;
    let _ = OFF_START_UNIX_MS;
    let _ = OFF_EXPIRY_UNIX_MS;

    let count_usize = usize::from(waypoint_count);
    if count_usize > MAX_ROUTE_WAYPOINTS {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "waypoint_count",
            value: waypoint_count.to_string(),
        });
    }

    let expected_total = ROUTE_UPLOAD_HEADER_LEN + 2 * count_usize;
    if bytes.len() < expected_total {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: expected_total,
        });
    }

    let mut waypoint_indices = Vec::with_capacity(count_usize);
    let mut trailer = &bytes[ROUTE_UPLOAD_HEADER_LEN..expected_total];
    for _ in 0..count_usize {
        waypoint_indices.push(trailer.get_u16());
    }

    Ok(RouteUploadCommand {
        vehicle_id,
        route_id,
        route_kind,
        start_unix_ms,
        expiry_unix_ms,
        waypoint_indices,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Empty-route fixture (`waypoint_count == 0`) — exercises the
    /// documented "clear active route" operation.
    fn empty_route_command() -> RouteUploadCommand {
        RouteUploadCommand {
            vehicle_id: 0xA1B2_C3D4,
            route_id: 0x0102_0304,
            route_kind: RouteKind::Replace,
            start_unix_ms: 0,
            expiry_unix_ms: 0,
            waypoint_indices: Vec::new(),
        }
    }

    /// Single-waypoint fixture — minimum non-empty route. Exercises
    /// the trailer-with-exactly-one-index path.
    fn single_waypoint_route_command() -> RouteUploadCommand {
        RouteUploadCommand {
            vehicle_id: 0xDEAD_BEEF,
            route_id: 7,
            route_kind: RouteKind::Append,
            start_unix_ms: 0x0000_0001_700A_BCDE,
            expiry_unix_ms: 0,
            waypoint_indices: vec![0x0042],
        }
    }

    /// Five-waypoint fixture — typical small route. Exercises the
    /// trailer-with-multiple-indices path and pins the index-ordering
    /// contract (the wire trailer round-trips in the same order the
    /// `Vec` was authored, not sorted, deduped, or reversed).
    fn five_waypoint_route_command() -> RouteUploadCommand {
        RouteUploadCommand {
            vehicle_id: 0x1122_3344,
            route_id: 0xAABB_CCDD,
            route_kind: RouteKind::Insert,
            start_unix_ms: 0x0000_0001_600F_1234,
            expiry_unix_ms: 0x0000_0001_601F_1234,
            waypoint_indices: vec![0x0001, 0x0042, 0x0FFF, 0xBEEF, 0xFFFE],
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_empty_route_fixture() {
        // Empty route is the documented "clear active route"
        // operation. Round-trip MUST hold even at this corner — a
        // regression that rejected count=0 as "what's the point of an
        // empty route" would silently drop every clear-route command.
        let msg = empty_route_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), ROUTE_UPLOAD_HEADER_LEN);
        let decoded = decode(&bytes).expect("empty route round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_single_waypoint_route_fixture() {
        let msg = single_waypoint_route_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), ROUTE_UPLOAD_HEADER_LEN + 2);
        let decoded = decode(&bytes).expect("single-waypoint round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_five_waypoint_route_fixture() {
        let msg = five_waypoint_route_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), ROUTE_UPLOAD_HEADER_LEN + 2 * 5);
        let decoded = decode(&bytes).expect("five-waypoint round-trip");
        assert_eq!(decoded, msg);
        // Pin index ordering — the wire trailer must not reorder.
        assert_eq!(
            decoded.waypoint_indices,
            vec![0x0001_u16, 0x0042, 0x0FFF, 0xBEEF, 0xFFFE]
        );
    }

    // ---- Empty-route accepted ----

    #[test]
    fn decode_accepts_empty_route_with_zero_waypoint_count() {
        // Pin the clear-active-route contract: senders write
        // `waypoint_count == 0` to instruct the platform to discard
        // its current route bookkeeping. A regression that rejected
        // count=0 at the codec layer would silently drop these
        // clear-route operations and leave the platform executing a
        // stale route.
        let bytes = encode(&empty_route_command());
        let decoded = decode(&bytes).expect("empty route must decode cleanly");
        assert!(decoded.waypoint_indices.is_empty());
        assert_eq!(decoded, empty_route_command());
    }

    // ---- Golden-fixture decode ----

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-built golden fixture that pins every header field at
        // its documented byte offset AND a known sequence of three
        // u16 waypoint indices in the trailer. The big-endian byte
        // sequences for the two u64 timestamps and the trailer
        // indices are computed in the test source so a regression
        // that swapped to little-endian could pass round-trip and
        // proptest but would still fail this byte-pinning check.
        //
        // Field values:
        //   vehicle_id       = 0x1122_3344
        //   route_id         = 0xAABB_CCDD
        //   waypoint_count   = 3
        //   route_kind       = 0x01 (Replace)
        //   start_unix_ms    = 0x0123_4567_89AB_CDEF
        //   expiry_unix_ms   = 0xFEDC_BA98_7654_3210
        //   waypoint_indices = [0x0001, 0x0042, 0x0FFF]
        let msg = RouteUploadCommand {
            vehicle_id: 0x1122_3344,
            route_id: 0xAABB_CCDD,
            route_kind: RouteKind::Replace,
            start_unix_ms: 0x0123_4567_89AB_CDEF,
            expiry_unix_ms: 0xFEDC_BA98_7654_3210,
            waypoint_indices: vec![0x0001, 0x0042, 0x0FFF],
        };
        let bytes = encode(&msg);
        let expected: [u8; ROUTE_UPLOAD_HEADER_LEN + 2 * 3] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // route_id = 0xAABB_CCDD (big-endian)
            0xAA, 0xBB, 0xCC, 0xDD, //
            // waypoint_count = 3 (big-endian u16)
            0x00, 0x03, //
            // route_kind = 0x01 (Replace)
            0x01, //
            // 5 reserved zero bytes
            0x00, 0x00, 0x00, 0x00, 0x00, //
            // start_unix_ms = 0x0123_4567_89AB_CDEF (big-endian)
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, //
            // expiry_unix_ms = 0xFEDC_BA98_7654_3210 (big-endian)
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, //
            // waypoint_indices: 0x0001, 0x0042, 0x0FFF (big-endian)
            0x00, 0x01, //
            0x00, 0x42, //
            0x0F, 0xFF,
        ];
        assert_eq!(
            bytes.as_slice(),
            &expected[..],
            "encoded bytes must match the documented byte layout"
        );
        let decoded = decode(&expected).expect("golden decode");
        assert_eq!(decoded, msg);
    }

    // ---- Truncation sweep ----

    #[test]
    fn decode_truncation_sweep_returns_frame_too_short_below_header() {
        // Header truncation — every below-header-length input must
        // surface as `FrameTooShort { actual, expected: 32 }` because
        // we cannot read the count field to compute a more specific
        // expectation. The boundary set covers every documented
        // header offset plus the just-below-header 31-byte case.
        for &len in &[0_usize, 1, 8, 16, 24, 31] {
            let bytes = vec![0u8; len];
            let err = decode(&bytes).expect_err("header truncation must error");
            match err {
                Stanag4586Error::FrameTooShort { actual, expected } => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, ROUTE_UPLOAD_HEADER_LEN);
                }
                other => panic!("expected FrameTooShort, got {other:?}"),
            }
        }
    }

    #[test]
    fn decode_truncation_below_declared_trailer_returns_frame_too_short() {
        // Body truncation — declare waypoint_count = 5 in the header
        // but only ship 32 + 8 bytes (need 32 + 10 for five u16
        // indices). The decoder MUST surface
        // `FrameTooShort { actual: 40, expected: 42 }` so the caller
        // sees both the actual buffer size and the size implied by
        // the declared count.
        let mut bytes = encode(&five_waypoint_route_command());
        // Confirm the round-trip baseline first so the test actually
        // exercises the truncation path rather than passing
        // vacuously on a degenerate buffer.
        assert_eq!(bytes.len(), ROUTE_UPLOAD_HEADER_LEN + 10);
        bytes.truncate(ROUTE_UPLOAD_HEADER_LEN + 8);
        let err = decode(&bytes).expect_err("body truncation must error");
        match err {
            Stanag4586Error::FrameTooShort { actual, expected } => {
                assert_eq!(actual, ROUTE_UPLOAD_HEADER_LEN + 8);
                assert_eq!(expected, ROUTE_UPLOAD_HEADER_LEN + 10);
            }
            other => panic!("expected FrameTooShort, got {other:?}"),
        }
    }

    // ---- Trailing-bytes-ignored ----

    #[test]
    fn decode_extra_trailing_bytes_are_ignored() {
        // Declare `waypoint_count = 2` (4 bytes of trailer) but
        // supply 32 + 4 + 8 = 44 bytes. The decoder MUST read the
        // first two indices and silently discard the trailing 8
        // bytes so a future protocol revision that appends a per-
        // frame trailer keeps decoding the prefix unchanged.
        let msg = RouteUploadCommand {
            vehicle_id: 0xCAFE_BABE,
            route_id: 0xF00D_BABE,
            route_kind: RouteKind::Append,
            start_unix_ms: 1,
            expiry_unix_ms: 2,
            waypoint_indices: vec![0x0010, 0x0020],
        };
        let mut bytes = encode(&msg);
        assert_eq!(bytes.len(), ROUTE_UPLOAD_HEADER_LEN + 4);
        bytes.extend_from_slice(&[0xAA; 8]);
        assert_eq!(bytes.len(), ROUTE_UPLOAD_HEADER_LEN + 4 + 8);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.waypoint_indices.len(), 2);
    }

    // ---- Excessive-count rejection ----

    #[test]
    fn decode_rejects_waypoint_count_above_256() {
        // waypoint_count = 257 — exactly one above the cap. The
        // decoder MUST surface `FieldOutOfRange { field:
        // "waypoint_count", value: "257" }` BEFORE attempting to
        // read the trailer; a regression that allocated a 257-entry
        // Vec and then errored on truncation would still pass the
        // truncation sweep but tie up a buffer the cap exists to
        // prevent.
        let mut bytes = vec![0u8; ROUTE_UPLOAD_HEADER_LEN];
        // Write waypoint_count = 257 at offset 8 (big-endian u16).
        bytes[8] = 0x01;
        bytes[9] = 0x01;
        let err = decode(&bytes).expect_err("count above cap must error");
        match err {
            Stanag4586Error::FieldOutOfRange { field, value } => {
                assert_eq!(field, "waypoint_count");
                assert_eq!(value, "257");
            }
            other => panic!("expected FieldOutOfRange/waypoint_count, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_waypoint_count_at_u16_max() {
        // The maximum u16 (65535) — a far more dramatic over-cap
        // value that would tie up a ~131 KiB allocation if accepted.
        // Pin the same FieldOutOfRange path here so a regression
        // that special-cased the just-over-cap boundary check still
        // fails on a wildly-out-of-range count.
        let mut bytes = vec![0u8; ROUTE_UPLOAD_HEADER_LEN];
        bytes[8] = 0xFF;
        bytes[9] = 0xFF;
        let err = decode(&bytes).expect_err("u16::MAX count must error");
        match err {
            Stanag4586Error::FieldOutOfRange { field, value } => {
                assert_eq!(field, "waypoint_count");
                assert_eq!(value, "65535");
            }
            other => panic!("expected FieldOutOfRange/waypoint_count, got {other:?}"),
        }
    }

    #[test]
    fn decode_accepts_waypoint_count_at_cap() {
        // Boundary check the other way: count = MAX_ROUTE_WAYPOINTS
        // (256) is the largest legal value. A regression that used
        // a strict `>=` comparison instead of `>` would reject the
        // cap-equal value here.
        let msg = RouteUploadCommand {
            vehicle_id: 1,
            route_id: 2,
            route_kind: RouteKind::Replace,
            start_unix_ms: 0,
            expiry_unix_ms: 0,
            waypoint_indices: (0..MAX_ROUTE_WAYPOINTS as u16).collect(),
        };
        let bytes = encode(&msg);
        assert_eq!(
            bytes.len(),
            ROUTE_UPLOAD_HEADER_LEN + 2 * MAX_ROUTE_WAYPOINTS
        );
        let decoded = decode(&bytes).expect("count == cap must decode cleanly");
        assert_eq!(decoded, msg);
    }

    // ---- RouteKind enum round-trip ----

    #[test]
    fn route_kind_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, RouteKind)] = &[
            (0x01, RouteKind::Replace),
            (0x02, RouteKind::Append),
            (0x03, RouteKind::Insert),
            (0xFF, RouteKind::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = RouteKind::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        // Unknown bytes outside the named table also round-trip via
        // `Other`. 0x00 is in this set — the encode side never emits
        // it for a named variant, so observing it on decode means
        // the upstream sent something unintended.
        for byte in [0x00u8, 0x04, 0x42, 0xEE] {
            let decoded = RouteKind::from_byte(byte);
            assert_eq!(decoded, RouteKind::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Convenience method parity ----

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = five_waypoint_route_command();
        assert_eq!(msg.encode_to_vec(), encode(&msg));
    }

    #[test]
    fn encode_into_appends_without_clearing_destination() {
        // `encode_into` is documented as additive — it must not
        // truncate or reorder existing bytes in `buf`. Pin that the
        // prefix bytes survive intact and the appended frame starts
        // at the original length.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        encode_into(&five_waypoint_route_command(), &mut buf);
        assert_eq!(
            buf.len(),
            3 + ROUTE_UPLOAD_HEADER_LEN + 2 * 5,
            "additive append must not clear the destination"
        );
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&five_waypoint_route_command());
        assert_eq!(&buf[3..], &standalone[..]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // Property test: any valid struct round-trips byte-for-byte.
        // Variable-length variant — `waypoint_count` ranges over the
        // full legal `[0, MAX_ROUTE_WAYPOINTS]` interval, the
        // route_kind byte covers every u8 value (named variants
        // 0x01–0x03, `Other` for the rest), and the u32/u64 fields
        // are unconstrained because the codec applies no range
        // checks to them.
        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            route_id in any::<u32>(),
            kind_byte in any::<u8>(),
            start_unix_ms in any::<u64>(),
            expiry_unix_ms in any::<u64>(),
            waypoint_indices in proptest::collection::vec(any::<u16>(), 0..=MAX_ROUTE_WAYPOINTS),
        ) {
            let original = RouteUploadCommand {
                vehicle_id,
                route_id,
                route_kind: RouteKind::from_byte(kind_byte),
                start_unix_ms,
                expiry_unix_ms,
                waypoint_indices,
            };
            let bytes = encode(&original);
            prop_assert_eq!(
                bytes.len(),
                ROUTE_UPLOAD_HEADER_LEN + 2 * original.waypoint_indices.len()
            );
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
