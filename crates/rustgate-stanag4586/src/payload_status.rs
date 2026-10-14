// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! STANAG 4586 LOI 2-3 payload-status telemetry message.
//!
//! Carries the payload bay's recording / streaming health state,
//! disambiguating between "the sensor optics are OK"
//! ([`crate::sensor_status::SensorStatus`]) and "the recorder behind
//! the sensor is OK". Operationally these are distinct concerns: a
//! healthy EO turret can still be mid-recording-failure (storage
//! full, streaming bandwidth lost, link congested) and the operator
//! needs to see that signal independently of whether the sensor
//! itself is `Operational`.
//!
//! Typically streamed at 1–5 Hz like
//! [`crate::sensor_status::SensorStatus`] — payload health state
//! changes far less frequently than position. The three telemetry
//! frames (`VehiclePosition`, `SensorStatus`, `PayloadStatus`)
//! together form the LOI 2-3 read-side surface that any deployment
//! needs before it can graduate to LOI 4+ command-side work.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`PAYLOAD_STATUS_FRAME_LEN`] = 32 bytes.
//!
//! ```text
//! offset │ size │ field                  │ type
//! ───────┼──────┼────────────────────────┼──────────────────────────
//!   0    │  4   │ payload_id             │ u32  big-endian
//!   4    │  1   │ payload_kind           │ u8   enum value (see below)
//!   5    │  1   │ recording_state        │ u8   enum value (see below)
//!   6    │  1   │ streaming_state        │ u8   enum value (see below)
//!   7    │  1   │ reserved               │ zero-padded — must be 0 on encode
//!   8    │  4   │ storage_used_pct       │ f32  big-endian IEEE-754
//!  12    │  4   │ link_bandwidth_kbps    │ f32  big-endian IEEE-754
//!  16    │  4   │ link_latency_ms        │ f32  big-endian IEEE-754
//!  20    │  4   │ reserved               │ zero-padded — must be 0 on encode
//!  24    │  8   │ timestamp_unix_ms      │ u64  big-endian
//! ```
//!
//! The two reserved blocks are zero-filled on encode. The decoder
//! does NOT validate them — a future protocol revision that
//! allocates them stays backward-compatible at the frame-length
//! level.
//!
//! # Field semantics
//!
//! - `payload_id` — opaque platform-assigned identifier for this
//!   payload bay. Distinct from the parent `vehicle_id` and from
//!   `sensor_id` so an EO/IR turret with two distinct sensors and a
//!   single shared recorder can be modelled accurately.
//! - `payload_kind` — what the payload **is**. See [`PayloadKind`].
//!   This is orthogonal to
//!   [`crate::sensor_status::SensorType`]: a payload may be a
//!   `Recorder` whose upstream sensor is `Infrared`, or a `Streamer`
//!   whose upstream is a fused multi-sensor track.
//! - `recording_state` — local-storage write side. See
//!   [`RecordingState`].
//! - `streaming_state` — downlink / network-stream side. See
//!   [`StreamingState`].
//! - `storage_used_pct` — fraction of local storage currently in
//!   use, expressed as a percentage in `[0.0, 100.0]`. Range-
//!   checked on decode (a value outside `[0, 100]` or NaN is a
//!   wire-format mismatch — silent acceptance would mask the
//!   upstream defect).
//! - `link_bandwidth_kbps` — measured downlink bandwidth in
//!   kilobits/sec. Strictly non-negative on decode (negative is
//!   meaningless); NaN is rejected.
//! - `link_latency_ms` — measured downlink one-way latency in
//!   milliseconds. Strictly non-negative on decode; NaN is rejected.
//! - `timestamp_unix_ms` — milliseconds since the Unix epoch.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a payload-status frame.
pub const PAYLOAD_STATUS_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_PAYLOAD_ID: usize = 0;
const OFF_PAYLOAD_KIND: usize = 4;
const OFF_RECORDING_STATE: usize = 5;
const OFF_STREAMING_STATE: usize = 6;
// 7..8 reserved (1 byte)
const OFF_STORAGE_USED: usize = 8;
const OFF_LINK_BANDWIDTH: usize = 12;
const OFF_LINK_LATENCY: usize = 16;
// 20..24 reserved (4 bytes)
const OFF_TIMESTAMP: usize = 24;

/// What the payload **is**, independent of its current health.
///
/// # Wire byte values
///
/// | byte  | variant         |
/// |-------|-----------------|
/// | `0x01`| `Recorder`      |
/// | `0x02`| `Streamer`      |
/// | `0x03`| `Combined`      |
/// | `0x04`| `Relay`         |
/// | other | `Other(byte)`   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadKind {
    /// Local-storage recorder (writes to onboard media, no live
    /// downlink).
    Recorder,
    /// Live downlink streamer (no local storage; data flows out the
    /// link).
    Streamer,
    /// Both recorder AND streamer — the typical operational
    /// configuration for ISR platforms that record-and-stream.
    Combined,
    /// Relay payload — forwards a feed from another source rather
    /// than producing one locally.
    Relay,
    /// Forward-compat catch-all.
    Other(u8),
}

impl PayloadKind {
    /// Map a wire byte into the typed enum.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Recorder,
            0x02 => Self::Streamer,
            0x03 => Self::Combined,
            0x04 => Self::Relay,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Recorder => 0x01,
            Self::Streamer => 0x02,
            Self::Combined => 0x03,
            Self::Relay => 0x04,
            Self::Other(b) => b,
        }
    }
}

/// Local-storage recorder state.
///
/// # Wire byte values
///
/// | byte  | variant         |
/// |-------|-----------------|
/// | `0x01`| `Idle`          |
/// | `0x02`| `Recording`     |
/// | `0x03`| `Paused`        |
/// | `0x04`| `Full`          |
/// | `0x05`| `Failed`        |
/// | other | `Other(byte)`   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordingState {
    /// Recorder is idle / not recording.
    Idle,
    /// Actively recording to local storage.
    Recording,
    /// Recording paused by operator command.
    Paused,
    /// Local storage is full — new data is being dropped.
    Full,
    /// Recorder hardware reports a fault.
    Failed,
    /// Forward-compat catch-all.
    Other(u8),
}

impl RecordingState {
    /// Map a wire byte into the typed enum.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Idle,
            0x02 => Self::Recording,
            0x03 => Self::Paused,
            0x04 => Self::Full,
            0x05 => Self::Failed,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Idle => 0x01,
            Self::Recording => 0x02,
            Self::Paused => 0x03,
            Self::Full => 0x04,
            Self::Failed => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// Live-downlink streamer state.
///
/// # Wire byte values
///
/// | byte  | variant            |
/// |-------|--------------------|
/// | `0x01`| `Idle`             |
/// | `0x02`| `Streaming`        |
/// | `0x03`| `Buffering`        |
/// | `0x04`| `LinkLost`         |
/// | `0x05`| `Failed`           |
/// | other | `Other(byte)`      |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamingState {
    /// Streamer is idle / not transmitting.
    Idle,
    /// Actively streaming over the downlink.
    Streaming,
    /// Buffering due to transient bandwidth shortfall — data is
    /// queueing locally and will resume streaming when the link
    /// recovers.
    Buffering,
    /// Downlink unreachable. Data is being dropped or queued
    /// indefinitely depending on the streamer's configured policy.
    LinkLost,
    /// Streamer hardware reports a fault.
    Failed,
    /// Forward-compat catch-all.
    Other(u8),
}

impl StreamingState {
    /// Map a wire byte into the typed enum.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Idle,
            0x02 => Self::Streaming,
            0x03 => Self::Buffering,
            0x04 => Self::LinkLost,
            0x05 => Self::Failed,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Idle => 0x01,
            Self::Streaming => 0x02,
            Self::Buffering => 0x03,
            Self::LinkLost => 0x04,
            Self::Failed => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// LOI 2-3 payload-status telemetry message.
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadStatus {
    /// Platform-assigned payload-bay identifier.
    pub payload_id: u32,
    /// What the payload is.
    pub payload_kind: PayloadKind,
    /// Local-storage recorder state.
    pub recording_state: RecordingState,
    /// Live-downlink streamer state.
    pub streaming_state: StreamingState,
    /// Fraction of local storage in use, percentage `[0.0, 100.0]`.
    pub storage_used_pct: f32,
    /// Measured downlink bandwidth, kbps. Non-negative.
    pub link_bandwidth_kbps: f32,
    /// Measured downlink latency, milliseconds. Non-negative.
    pub link_latency_ms: f32,
    /// Milliseconds since the Unix epoch.
    pub timestamp_unix_ms: u64,
}

impl PayloadStatus {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a payload-status frame into a freshly allocated `Vec<u8>`.
pub fn encode(msg: &PayloadStatus) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(PAYLOAD_STATUS_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
pub fn encode_into(msg: &PayloadStatus, buf: &mut BytesMut) {
    buf.put_u32(msg.payload_id);
    buf.put_u8(msg.payload_kind.to_byte());
    buf.put_u8(msg.recording_state.to_byte());
    buf.put_u8(msg.streaming_state.to_byte());
    buf.put_u8(0); // 1 reserved byte
    buf.put_f32(msg.storage_used_pct);
    buf.put_f32(msg.link_bandwidth_kbps);
    buf.put_f32(msg.link_latency_ms);
    buf.put_u32(0); // 4 reserved bytes
    buf.put_u64(msg.timestamp_unix_ms);
}

/// Decode a payload-status frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `storage_used_pct` is
///   outside `[0.0, 100.0]` or NaN, or if `link_bandwidth_kbps` /
///   `link_latency_ms` is negative or NaN.
pub fn decode(bytes: &[u8]) -> Result<PayloadStatus, Stanag4586Error> {
    if bytes.len() < PAYLOAD_STATUS_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: PAYLOAD_STATUS_FRAME_LEN,
        });
    }
    let mut cursor = &bytes[..PAYLOAD_STATUS_FRAME_LEN];
    let payload_id = cursor.get_u32();
    let payload_kind = PayloadKind::from_byte(cursor.get_u8());
    let recording_state = RecordingState::from_byte(cursor.get_u8());
    let streaming_state = StreamingState::from_byte(cursor.get_u8());
    let _ = cursor.get_u8(); // reserved
    let storage_used_pct = cursor.get_f32();
    let link_bandwidth_kbps = cursor.get_f32();
    let link_latency_ms = cursor.get_f32();
    let _ = cursor.get_u32(); // reserved
    let timestamp_unix_ms = cursor.get_u64();

    if !storage_used_pct.is_finite() || !(0.0..=100.0).contains(&storage_used_pct) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "storage_used_pct",
            value: storage_used_pct.to_string(),
        });
    }
    if !link_bandwidth_kbps.is_finite() || link_bandwidth_kbps < 0.0 {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "link_bandwidth_kbps",
            value: link_bandwidth_kbps.to_string(),
        });
    }
    if !link_latency_ms.is_finite() || link_latency_ms < 0.0 {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "link_latency_ms",
            value: link_latency_ms.to_string(),
        });
    }

    debug_assert_eq!(cursor.remaining(), 0);
    let _ = OFF_PAYLOAD_ID;
    let _ = OFF_PAYLOAD_KIND;
    let _ = OFF_RECORDING_STATE;
    let _ = OFF_STREAMING_STATE;
    let _ = OFF_STORAGE_USED;
    let _ = OFF_LINK_BANDWIDTH;
    let _ = OFF_LINK_LATENCY;
    let _ = OFF_TIMESTAMP;

    Ok(PayloadStatus {
        payload_id,
        payload_kind,
        recording_state,
        streaming_state,
        storage_used_pct,
        link_bandwidth_kbps,
        link_latency_ms,
        timestamp_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn fixture() -> PayloadStatus {
        PayloadStatus {
            payload_id: 0xCAFE_BABE,
            payload_kind: PayloadKind::Combined,
            recording_state: RecordingState::Recording,
            streaming_state: StreamingState::Streaming,
            storage_used_pct: 42.5,
            link_bandwidth_kbps: 8192.0,
            link_latency_ms: 25.0,
            timestamp_unix_ms: 0xDEAD_BEEF_0000_0042,
        }
    }

    #[test]
    fn round_trip_full_fixture() {
        let msg = fixture();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), PAYLOAD_STATUS_FRAME_LEN);
        let decoded = decode(&bytes).expect("decode round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn encode_to_vec_method_matches_free_function() {
        assert_eq!(fixture().encode_to_vec(), encode(&fixture()));
    }

    #[test]
    fn encode_into_appends_without_clearing_destination() {
        let mut buf = BytesMut::from(&b"prefix-"[..]);
        encode_into(&fixture(), &mut buf);
        assert!(buf.starts_with(b"prefix-"));
        assert_eq!(buf.len(), 7 + PAYLOAD_STATUS_FRAME_LEN);
    }

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        let msg = PayloadStatus {
            payload_id: 1,
            payload_kind: PayloadKind::Recorder,
            recording_state: RecordingState::Idle,
            streaming_state: StreamingState::Idle,
            storage_used_pct: 50.0,
            link_bandwidth_kbps: 1024.0,
            link_latency_ms: 10.0,
            timestamp_unix_ms: 0x0011_2233_4455_6677,
        };
        let bytes = encode(&msg);
        assert_eq!(&bytes[0..4], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(bytes[4], 0x01); // Recorder
        assert_eq!(bytes[5], 0x01); // Idle
        assert_eq!(bytes[6], 0x01); // Idle
        assert_eq!(bytes[7], 0x00); // reserved
        // 50.0 f32 BE: 0x42480000
        assert_eq!(&bytes[8..12], &[0x42, 0x48, 0x00, 0x00]);
        // 1024.0 f32 BE: 0x44800000
        assert_eq!(&bytes[12..16], &[0x44, 0x80, 0x00, 0x00]);
        // 10.0 f32 BE: 0x41200000
        assert_eq!(&bytes[16..20], &[0x41, 0x20, 0x00, 0x00]);
        // 4 reserved zeros
        assert_eq!(&bytes[20..24], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            &bytes[24..32],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
    }

    #[test]
    fn decode_rejects_storage_above_100_percent() {
        let mut msg = fixture();
        msg.storage_used_pct = 100.001;
        let bytes = encode(&msg);
        let err = decode(&bytes).expect_err("over-100% must be rejected");
        match err {
            Stanag4586Error::FieldOutOfRange { field, .. } => {
                assert_eq!(field, "storage_used_pct");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_negative_storage() {
        let mut msg = fixture();
        msg.storage_used_pct = -0.001;
        assert!(matches!(
            decode(&encode(&msg)),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_rejects_nan_storage() {
        let mut msg = fixture();
        msg.storage_used_pct = f32::NAN;
        assert!(matches!(
            decode(&encode(&msg)),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_rejects_negative_bandwidth() {
        let mut msg = fixture();
        msg.link_bandwidth_kbps = -1.0;
        assert!(matches!(
            decode(&encode(&msg)),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_rejects_nan_bandwidth() {
        let mut msg = fixture();
        msg.link_bandwidth_kbps = f32::NAN;
        assert!(matches!(
            decode(&encode(&msg)),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_rejects_negative_latency() {
        let mut msg = fixture();
        msg.link_latency_ms = -0.001;
        assert!(matches!(
            decode(&encode(&msg)),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_rejects_nan_latency() {
        let mut msg = fixture();
        msg.link_latency_ms = f32::NAN;
        assert!(matches!(
            decode(&encode(&msg)),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_truncation_returns_dedicated_variant() {
        for n in [0, 1, 7, 16, 23, 31] {
            let bytes = vec![0u8; n];
            match decode(&bytes) {
                Err(Stanag4586Error::FrameTooShort { actual, expected }) => {
                    assert_eq!(actual, n);
                    assert_eq!(expected, PAYLOAD_STATUS_FRAME_LEN);
                }
                other => panic!("got {other:?} for {n} bytes"),
            }
        }
    }

    #[test]
    fn decode_extra_trailing_bytes_are_ignored() {
        let msg = fixture();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(b"future-trailer");
        let decoded = decode(&bytes).expect("trailing bytes ignored");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn payload_kind_round_trips_for_all_named_variants() {
        for v in [
            PayloadKind::Recorder,
            PayloadKind::Streamer,
            PayloadKind::Combined,
            PayloadKind::Relay,
        ] {
            assert_eq!(PayloadKind::from_byte(v.to_byte()), v);
        }
    }

    #[test]
    fn payload_kind_other_round_trips_arbitrary_byte() {
        for b in [0x00, 0x05, 0x10, 0x42, 0xFF] {
            let v = PayloadKind::from_byte(b);
            assert_eq!(v, PayloadKind::Other(b));
            assert_eq!(v.to_byte(), b);
        }
    }

    #[test]
    fn recording_state_round_trips_for_all_named_variants() {
        for v in [
            RecordingState::Idle,
            RecordingState::Recording,
            RecordingState::Paused,
            RecordingState::Full,
            RecordingState::Failed,
        ] {
            assert_eq!(RecordingState::from_byte(v.to_byte()), v);
        }
    }

    #[test]
    fn streaming_state_round_trips_for_all_named_variants() {
        for v in [
            StreamingState::Idle,
            StreamingState::Streaming,
            StreamingState::Buffering,
            StreamingState::LinkLost,
            StreamingState::Failed,
        ] {
            assert_eq!(StreamingState::from_byte(v.to_byte()), v);
        }
    }

    #[test]
    fn recording_and_streaming_state_other_round_trip_arbitrary_byte() {
        for b in [0x00, 0x06, 0x10, 0xFF] {
            let r = RecordingState::from_byte(b);
            assert_eq!(r, RecordingState::Other(b));
            assert_eq!(r.to_byte(), b);
            let s = StreamingState::from_byte(b);
            assert_eq!(s, StreamingState::Other(b));
            assert_eq!(s.to_byte(), b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn round_trip_via_proptest(
            payload_id in any::<u32>(),
            kind_byte in any::<u8>(),
            rec_byte in any::<u8>(),
            stream_byte in any::<u8>(),
            storage_used_pct in 0.0_f32..=100.0_f32,
            link_bandwidth_kbps in 0.0_f32..1_000_000.0_f32,
            link_latency_ms in 0.0_f32..10_000.0_f32,
            timestamp_unix_ms in any::<u64>(),
        ) {
            let msg = PayloadStatus {
                payload_id,
                payload_kind: PayloadKind::from_byte(kind_byte),
                recording_state: RecordingState::from_byte(rec_byte),
                streaming_state: StreamingState::from_byte(stream_byte),
                storage_used_pct,
                link_bandwidth_kbps,
                link_latency_ms,
                timestamp_unix_ms,
            };
            let bytes = encode(&msg);
            prop_assert_eq!(bytes.len(), PAYLOAD_STATUS_FRAME_LEN);
            let decoded = decode(&bytes).unwrap();
            prop_assert_eq!(decoded, msg);
        }
    }
}
