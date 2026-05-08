// Copyright © 2026 Roberto Chiofalo.

//! J-series message bodies carried inside a JREAP-C
//! [`crate::header::JreapMessageType::JseriesData`] frame.
//!
//! MIL-STD-6016 defines roughly 80 J-series messages organised into
//! "labels" (the leading byte of the message body) and "sublabels"
//! (the second byte). The MVP decodes label/sublabel `2.2` (Air Track)
//! into the typed [`J2_2AirTrack`] shape; every other label is
//! preserved as opaque bytes via [`JseriesMessage::Other`] so the
//! frame layer can still walk a multi-message body and a follow-up PR
//! can extend the typed coverage one J-series message at a time.
//!
//! The wire form of each J-series message is its own bit-packed shape;
//! the MVP uses byte-aligned fields throughout so the codec stays
//! simple and reviewable. A reviewer with access to MIL-STD-6016 can
//! correct individual bit widths without reshuffling the surrounding
//! enum / struct shape.

mod j2_2;

use bytes::Bytes;
pub use j2_2::{IffCodes, J2_2AirTrack, JseriesKinematics, PlatformType};

use crate::error::Link16Error;

/// J-series message body decoded from the JREAP-C frame body.
///
/// The variant set is deliberately small in the MVP: typed
/// [`JseriesMessage::J2_2AirTrack`] for the canonical "where is the
/// fighter / how fast is it going" payload, and
/// [`JseriesMessage::Other`] for every other message label so a
/// multi-message frame still parses without losing data.
#[derive(Debug, Clone, PartialEq)]
pub enum JseriesMessage {
    /// J2.2 Air Track — track number, geodetic position, IFF status,
    /// platform type, kinematics. The workhorse of every Link 16
    /// exercise.
    J2_2AirTrack(J2_2AirTrack),
    /// Any J-series message label the MVP does not yet decode.
    /// `label` is the leading byte of the body so callers can dispatch
    /// numerically while the follow-up PRs land typed shapes for
    /// J3.2 (Air PPLI), J3.5 (Land Point), J7.0 (Track Management),
    /// J13.2 (Air Platform & System Status); `body` carries the
    /// verbatim bytes including the label byte for round-trip
    /// fidelity.
    Other {
        /// Leading message-label byte (and sublabel, packed into the
        /// low nibble per MIL-STD-6016). Zero indicates an empty body.
        label: u8,
        /// Verbatim body bytes including the label.
        body: Bytes,
    },
}

impl JseriesMessage {
    /// Decode a J-series message from a frame-body slice.
    ///
    /// Walks the leading label byte and dispatches to the typed
    /// decoder for J2.2; every other label is wrapped in
    /// [`JseriesMessage::Other`] verbatim.
    pub fn decode(body: &[u8]) -> Result<Self, Link16Error> {
        if body.is_empty() {
            return Ok(Self::Other {
                label: 0,
                body: Bytes::new(),
            });
        }
        let label = body[0];
        if label == J2_2AirTrack::LABEL {
            let track = J2_2AirTrack::decode(body)?;
            return Ok(Self::J2_2AirTrack(track));
        }
        Ok(Self::Other {
            label,
            body: Bytes::copy_from_slice(body),
        })
    }

    /// Encode the J-series message into the supplied byte sink.
    ///
    /// Writes the message body without any JREAP-C header — the
    /// caller wraps the result in [`crate::header::JreapFrame`] before
    /// putting bytes on the wire.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Link16Error> {
        match self {
            Self::J2_2AirTrack(track) => track.encode_into(out),
            Self::Other { body, .. } => {
                out.extend_from_slice(body);
                Ok(())
            }
        }
    }
}
