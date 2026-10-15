// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! IEEE 1278.1 Entity State PDU (clause 5.3.3.1).
//!
//! The Entity State PDU is the workhorse of every DIS exercise: every
//! simulated entity emits one whenever its state (position, velocity,
//! orientation, appearance bitfield) changes more than the dead-
//! reckoning algorithm can extrapolate. The PDU shape is the most
//! complex of the IEEE 1278.1 PDU set, with a 144-byte fixed prefix
//! plus a variable-length tail of articulation-parameter records.
//!
//! # Wire layout (variable, ≥ 144 bytes)
//!
//! Positions are byte offsets from the start of the PDU body (after
//! the 12-byte common header).
//!
//! | Offset | Size | Field                              |
//! |--------|------|------------------------------------|
//! |   0    |  6   | Entity ID (site, app, entity)      |
//! |   6    |  1   | Force ID                           |
//! |   7    |  1   | num_articulation_parameters        |
//! |   8    |  8   | Entity Type (kind/domain/...)      |
//! |  16    |  8   | Alternative Entity Type            |
//! |  24    | 12   | Entity Linear Velocity (3×f32)     |
//! |  36    | 24   | Entity Location ECEF (3×f64)       |
//! |  60    | 12   | Entity Orientation (3×f32 Euler)   |
//! |  72    |  4   | Entity Appearance bitfield (u32)   |
//! |  76    | 40   | Dead Reckoning Parameters          |
//! |        |      |   - algorithm: u8                  |
//! |        |      |   - dr_other_parameters: 15 bytes  |
//! |        |      |   - linear_acceleration: 3×f32     |
//! |        |      |   - angular_velocity: 3×f32        |
//! |  116   | 12   | Entity Marking (1 charset + 11 ASCII) |
//! |  128   |  4   | Capabilities bitfield (u32)        |
//! |  132   |  N×variable | Articulation Parameter records (16 bytes each) |

use crate::error::DisError;
use crate::header::{HEADER_LEN, PduHeader, PduType, ProtocolFamily};

/// Fixed-prefix length of an Entity State PDU body, excluding any
/// articulation-parameter records. Sums the offset table above for
/// the body fields (entity id through capabilities) → 132 bytes.
pub const ENTITY_STATE_FIXED_BODY_LEN: usize = 132;

/// Each articulation parameter record is 16 bytes. The number of
/// records is given by `num_articulation_parameters` in the body.
pub const ARTICULATION_PARAMETER_LEN: usize = 16;

/// Length of the entity-marking field (1 character-set byte + 11
/// marking bytes). IEEE 1278.1 § 5.3.3.1 specifies the marking string
/// as 1 + 11 = 12 bytes; the codec preserves the charset byte
/// verbatim and decodes the 11 marking bytes as ASCII (with the
/// optional trailing NUL trimmed).
pub const MARKING_TOTAL_LEN: usize = 12;

/// Length of the dead-reckoning-parameters field per IEEE 1278.1
/// § 5.3.3.1.4. 1 byte algorithm + 15 bytes algorithm-specific
/// parameters + 12 bytes linear acceleration (3×f32) + 12 bytes
/// angular velocity (3×f32) = 40 bytes.
pub const DEAD_RECKONING_LEN: usize = 40;

/// IEEE 1278.1 Entity ID — the canonical (site, application, entity)
/// triple that uniquely identifies an entity within a federation.
///
/// Two entities sharing a site but differing in application are
/// emitted by separate simulators on the same machine; entities
/// sharing site + application but differing in entity number are
/// distinct platforms within one simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntityId {
    /// Site identifier — the host or LAN segment producing the PDU.
    pub site: u16,
    /// Application identifier — the simulator process within the
    /// site.
    pub application: u16,
    /// Entity identifier — the platform within the application.
    pub entity: u16,
}

impl EntityId {
    /// Decode the 6-byte wire form from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, DisError> {
        if buf.len() < 6 {
            return Err(DisError::Truncated {
                field: "EntityId",
                needed: 6,
                available: buf.len(),
            });
        }
        Ok(Self {
            site: u16::from_be_bytes([buf[0], buf[1]]),
            application: u16::from_be_bytes([buf[2], buf[3]]),
            entity: u16::from_be_bytes([buf[4], buf[5]]),
        })
    }

    /// Append the 6-byte wire form to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.site.to_be_bytes());
        out.extend_from_slice(&self.application.to_be_bytes());
        out.extend_from_slice(&self.entity.to_be_bytes());
    }
}

/// IEEE 1278.1 Force ID. The force the entity belongs to in the
/// scenario — used for friend / foe filtering on visualisations.
///
/// Numeric values are pinned per IEEE 1278.1 § 5.2.20. Generic
/// terminology used here matches the workspace convention (see
/// `CLAUDE.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceId {
    /// Wire byte 0 — neither friendly nor opposing (uncommitted).
    Other,
    /// Wire byte 1 — friendly force (own / coalition).
    Friendly,
    /// Wire byte 2 — opposing force.
    Opposing,
    /// Wire byte 3 — neutral non-combatant force.
    Neutral,
    /// Any value outside the IEEE 1278.1 enumeration. The wrapped
    /// byte is the wire value.
    Unknown(u8),
}

impl ForceId {
    /// Decode a wire byte into a typed [`ForceId`].
    #[must_use]
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            0 => Self::Other,
            1 => Self::Friendly,
            2 => Self::Opposing,
            3 => Self::Neutral,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the wire byte. Round-trips
    /// `from_u8(x).to_u8() == x` for every byte value.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Other => 0,
            Self::Friendly => 1,
            Self::Opposing => 2,
            Self::Neutral => 3,
            Self::Unknown(v) => v,
        }
    }
}

/// IEEE 1278.1 Entity Type — the 8-byte tuple identifying the
/// platform model.
///
/// See SISO-REF-010 ("Reference for Enumerations for Simulation
/// Interoperability") for the published catalogue of `kind / domain /
/// country / category / subcategory / specific / extra` combinations
/// — there are tens of thousands of entries covering ground vehicles,
/// aircraft, ships, munitions, sensors, and life-forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityType {
    /// Top-level kind: 1 platform, 2 munition, 3 life form, …
    pub kind: u8,
    /// Domain within the kind: for kind=1 (platform), 1=land, 2=air,
    /// 3=surface, 4=subsurface, 5=space.
    pub domain: u8,
    /// Country code per ISO 3166 numeric (with extensions).
    pub country: u16,
    /// Category within the kind/domain.
    pub category: u8,
    /// Sub-category within the category.
    pub subcategory: u8,
    /// Specific platform within the sub-category.
    pub specific: u8,
    /// Extra discriminator (configuration variant).
    pub extra: u8,
}

impl EntityType {
    /// Decode the 8-byte wire form from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, DisError> {
        if buf.len() < 8 {
            return Err(DisError::Truncated {
                field: "EntityType",
                needed: 8,
                available: buf.len(),
            });
        }
        Ok(Self {
            kind: buf[0],
            domain: buf[1],
            country: u16::from_be_bytes([buf[2], buf[3]]),
            category: buf[4],
            subcategory: buf[5],
            specific: buf[6],
            extra: buf[7],
        })
    }

    /// Append the 8-byte wire form to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.push(self.domain);
        out.extend_from_slice(&self.country.to_be_bytes());
        out.push(self.category);
        out.push(self.subcategory);
        out.push(self.specific);
        out.push(self.extra);
    }
}

/// IEEE 1278.1 dead-reckoning parameters block (40 bytes total).
///
/// The MVP decodes the [`DeadReckoningParameters::algorithm`] tag and
/// preserves the rest as opaque bytes — implementing the full DR
/// algorithm catalogue (DRM_FPW, DRM_RPW, DRM_RVW, …) is deliberately
/// follow-up scope. Same-codec round-trip is byte-exact because the
/// opaque tail is preserved verbatim.
#[derive(Debug, Clone, PartialEq)]
pub struct DeadReckoningParameters {
    /// Algorithm tag per IEEE 1278.1 § 5.2.16. 0 = OTHER, 1 = STATIC,
    /// 2 = DRM_FPW, 3 = DRM_RPW, 4 = DRM_RVW, 5 = DRM_FVW, 6 = DRM_FPB,
    /// 7 = DRM_RPB, 8 = DRM_RVB, 9 = DRM_FVB.
    pub algorithm: u8,
    /// 15 bytes of algorithm-specific opaque parameters (the
    /// "dr_other_parameters" field). Preserved verbatim for round-trip
    /// even though the MVP does not interpret them.
    pub other_parameters: [u8; 15],
    /// Linear acceleration in entity coordinates (X, Y, Z) — m/s².
    pub linear_acceleration: [f32; 3],
    /// Angular velocity in entity coordinates (X, Y, Z) — rad/s.
    pub angular_velocity: [f32; 3],
}

impl DeadReckoningParameters {
    /// Decode the 40-byte wire form from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, DisError> {
        if buf.len() < DEAD_RECKONING_LEN {
            return Err(DisError::Truncated {
                field: "DeadReckoningParameters",
                needed: DEAD_RECKONING_LEN,
                available: buf.len(),
            });
        }
        let algorithm = buf[0];
        let mut other_parameters = [0u8; 15];
        other_parameters.copy_from_slice(&buf[1..16]);
        let linear_acceleration = [
            f32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            f32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
            f32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]),
        ];
        let angular_velocity = [
            f32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]),
            f32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]),
            f32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]),
        ];
        Ok(Self {
            algorithm,
            other_parameters,
            linear_acceleration,
            angular_velocity,
        })
    }

    /// Append the 40-byte wire form to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.algorithm);
        out.extend_from_slice(&self.other_parameters);
        for v in &self.linear_acceleration {
            out.extend_from_slice(&v.to_be_bytes());
        }
        for v in &self.angular_velocity {
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

/// IEEE 1278.1 articulation-parameter record (16 bytes).
///
/// Articulated parts of a platform (turrets, hatches, weapons) are
/// represented as a list of these records appended to the Entity
/// State PDU. The MVP preserves them as opaque bytes for round-trip
/// fidelity; full decoding (parameter type metric vs. attached parts,
/// parameter-value f32 vs. EntityType union) is follow-up scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArticulationParameter {
    /// Raw 16 bytes per IEEE 1278.1 § 5.3.3.1.5. Preserved verbatim.
    pub raw: [u8; ARTICULATION_PARAMETER_LEN],
}

/// IEEE 1278.1 Entity State PDU.
///
/// Decoded by [`Self::decode`]; encoded by [`Self::encode`]. The
/// header is exposed alongside the body so callers that frame
/// multi-PDU datagrams can dispatch on the type byte without a
/// second header parse.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityStatePdu {
    /// Common header. The encoder fills `length` automatically; the
    /// caller's `length` value is overwritten on encode.
    pub header: PduHeader,
    /// Entity ID (site, app, entity).
    pub entity_id: EntityId,
    /// Force the entity belongs to.
    pub force_id: ForceId,
    /// Entity type (kind/domain/country/category/subcategory/specific/extra).
    pub entity_type: EntityType,
    /// Alternative entity type — the type a different observer might
    /// classify this entity as. Often equal to `entity_type` for
    /// own-force entities.
    pub alternative_entity_type: EntityType,
    /// Linear velocity in entity coordinates — m/s.
    pub linear_velocity: [f32; 3],
    /// Position in ECEF metres. Convert with
    /// [`crate::coord::ecef_to_wgs84`] for geodetic display.
    pub location_ecef: [f64; 3],
    /// Euler orientation `(psi, theta, phi)` in radians per IEEE
    /// 1278.1 § 1.5.2.5 (the world-coordinate yaw / pitch / roll
    /// triplet).
    pub orientation: [f32; 3],
    /// Appearance bitfield. Domain-specific layout per IEEE 1278.1
    /// § 4.3.5; preserved verbatim.
    pub appearance: u32,
    /// Dead-reckoning parameters block.
    pub dead_reckoning: DeadReckoningParameters,
    /// Marking-charset byte. 1 = ASCII, 2 = Army Marking, 3 = Digit
    /// Chevron. The codec preserves the byte but only ASCII is
    /// validated.
    pub marking_charset: u8,
    /// Marking string (ASCII). Up to 11 characters; trailing NUL
    /// bytes are stripped on decode and re-padded on encode.
    pub marking: String,
    /// Capabilities bitfield. Bitwise capabilities the entity claims
    /// (ammunition supply, fuel supply, recovery, repair). Preserved
    /// verbatim.
    pub capabilities: u32,
    /// Optional articulation-parameter records appended to the PDU.
    /// IEEE 1278.1 § 5.3.3.1.5; the MVP preserves them as opaque
    /// 16-byte records for round-trip fidelity.
    pub articulation_parameters: Vec<ArticulationParameter>,
}

impl EntityStatePdu {
    /// Decode an Entity State PDU (header + body) from `buf`.
    ///
    /// The buffer must include the 12-byte common header; the
    /// decoder reads the header's `length` field and validates that
    /// `buf` carries exactly that many bytes (no trailing slack and
    /// no truncation).
    pub fn decode(buf: &[u8]) -> Result<Self, DisError> {
        let header = PduHeader::decode(buf)?;
        if header.pdu_type != PduType::EntityState {
            return Err(DisError::UnexpectedPduType {
                expected: PduType::ENTITY_STATE,
                got: header.pdu_type.to_u8(),
            });
        }
        let declared_len = usize::from(header.length);
        if buf.len() != declared_len {
            return Err(DisError::LengthMismatch {
                declared: declared_len,
                actual: buf.len(),
            });
        }
        let body = &buf[HEADER_LEN..];
        if body.len() < ENTITY_STATE_FIXED_BODY_LEN {
            return Err(DisError::Truncated {
                field: "EntityStatePdu body",
                needed: ENTITY_STATE_FIXED_BODY_LEN,
                available: body.len(),
            });
        }

        let entity_id = EntityId::decode(&body[0..6])?;
        let force_id = ForceId::from_u8(body[6]);
        let num_articulation_parameters = usize::from(body[7]);
        let entity_type = EntityType::decode(&body[8..16])?;
        let alternative_entity_type = EntityType::decode(&body[16..24])?;
        let linear_velocity = [
            f32::from_be_bytes([body[24], body[25], body[26], body[27]]),
            f32::from_be_bytes([body[28], body[29], body[30], body[31]]),
            f32::from_be_bytes([body[32], body[33], body[34], body[35]]),
        ];
        let location_ecef = [
            f64::from_be_bytes([
                body[36], body[37], body[38], body[39], body[40], body[41], body[42], body[43],
            ]),
            f64::from_be_bytes([
                body[44], body[45], body[46], body[47], body[48], body[49], body[50], body[51],
            ]),
            f64::from_be_bytes([
                body[52], body[53], body[54], body[55], body[56], body[57], body[58], body[59],
            ]),
        ];
        let orientation = [
            f32::from_be_bytes([body[60], body[61], body[62], body[63]]),
            f32::from_be_bytes([body[64], body[65], body[66], body[67]]),
            f32::from_be_bytes([body[68], body[69], body[70], body[71]]),
        ];
        let appearance = u32::from_be_bytes([body[72], body[73], body[74], body[75]]);
        let dead_reckoning = DeadReckoningParameters::decode(&body[76..116])?;
        let marking_charset = body[116];
        let marking = decode_marking(&body[117..128])?;
        let capabilities = u32::from_be_bytes([body[128], body[129], body[130], body[131]]);

        let articulation_bytes = num_articulation_parameters
            .checked_mul(ARTICULATION_PARAMETER_LEN)
            .ok_or(DisError::Truncated {
                field: "ArticulationParameter list",
                needed: usize::MAX,
                available: body.len() - ENTITY_STATE_FIXED_BODY_LEN,
            })?;
        let tail = &body[ENTITY_STATE_FIXED_BODY_LEN..];
        if tail.len() < articulation_bytes {
            return Err(DisError::Truncated {
                field: "ArticulationParameter list",
                needed: articulation_bytes,
                available: tail.len(),
            });
        }
        let mut articulation_parameters = Vec::with_capacity(num_articulation_parameters);
        let (records, _) = tail.as_chunks::<ARTICULATION_PARAMETER_LEN>();
        for raw in records.iter().take(num_articulation_parameters) {
            articulation_parameters.push(ArticulationParameter { raw: *raw });
        }

        Ok(Self {
            header,
            entity_id,
            force_id,
            entity_type,
            alternative_entity_type,
            linear_velocity,
            location_ecef,
            orientation,
            appearance,
            dead_reckoning,
            marking_charset,
            marking,
            capabilities,
            articulation_parameters,
        })
    }

    /// Encode the Entity State PDU into a freshly-allocated `Vec<u8>`.
    ///
    /// The header's `length` field is overwritten with the actual
    /// encoded byte count so receivers can frame multi-PDU datagrams
    /// correctly; the `pdu_type` and `protocol_family` are likewise
    /// pinned to Entity State / Entity Information Interaction.
    pub fn encode(&self) -> Result<Vec<u8>, DisError> {
        let articulation_bytes = self.articulation_parameters.len() * ARTICULATION_PARAMETER_LEN;
        let total_len = HEADER_LEN + ENTITY_STATE_FIXED_BODY_LEN + articulation_bytes;
        let length_u16 = u16::try_from(total_len).map_err(|_| DisError::LengthMismatch {
            declared: total_len,
            actual: usize::from(u16::MAX),
        })?;
        let num_params = u8::try_from(self.articulation_parameters.len()).map_err(|_| {
            DisError::LengthMismatch {
                declared: self.articulation_parameters.len(),
                actual: usize::from(u8::MAX),
            }
        })?;

        let mut out = Vec::with_capacity(total_len);
        let mut header = self.header;
        header.pdu_type = PduType::EntityState;
        header.protocol_family = ProtocolFamily::EntityInformationInteraction;
        header.length = length_u16;
        header.encode_into(&mut out);

        // Body — byte offsets per the wire-layout table in the module
        // doc-comment.
        self.entity_id.encode_into(&mut out); // 0..6
        out.push(self.force_id.to_u8()); // 6
        out.push(num_params); // 7
        self.entity_type.encode_into(&mut out); // 8..16
        self.alternative_entity_type.encode_into(&mut out); // 16..24
        for v in &self.linear_velocity {
            out.extend_from_slice(&v.to_be_bytes());
        } // 24..36
        for v in &self.location_ecef {
            out.extend_from_slice(&v.to_be_bytes());
        } // 36..60
        for v in &self.orientation {
            out.extend_from_slice(&v.to_be_bytes());
        } // 60..72
        out.extend_from_slice(&self.appearance.to_be_bytes()); // 72..76
        self.dead_reckoning.encode_into(&mut out); // 76..116
        out.push(self.marking_charset); // 116
        encode_marking(&self.marking, &mut out); // 117..128
        out.extend_from_slice(&self.capabilities.to_be_bytes()); // 128..132
        for ap in &self.articulation_parameters {
            out.extend_from_slice(&ap.raw);
        }

        debug_assert_eq!(out.len(), total_len);
        Ok(out)
    }
}

/// Decode the 11-byte marking field as ASCII, stripping trailing
/// NUL padding. Errors if any byte is non-ASCII.
fn decode_marking(buf: &[u8]) -> Result<String, DisError> {
    debug_assert_eq!(buf.len(), 11);
    for (idx, &b) in buf.iter().enumerate() {
        if b != 0 && !b.is_ascii() {
            return Err(DisError::InvalidMarking { byte_index: idx });
        }
    }
    // Trim trailing NULs only — internal NULs surface as empty
    // characters, which is technically permitted by the spec.
    let end = buf.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Encode the marking string into 11 bytes, NUL-padding short
/// strings and truncating strings longer than 11 ASCII characters.
fn encode_marking(marking: &str, out: &mut Vec<u8>) {
    let mut bytes = [0u8; 11];
    let truncated = marking
        .as_bytes()
        .iter()
        .take(11)
        .copied()
        .collect::<Vec<_>>();
    bytes[..truncated.len()].copy_from_slice(&truncated);
    out.extend_from_slice(&bytes);
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_entity_type(seed: u8) -> EntityType {
        EntityType {
            kind: 1,
            domain: 2,
            country: 225,
            category: seed,
            subcategory: seed.wrapping_add(1),
            specific: seed.wrapping_add(2),
            extra: seed.wrapping_add(3),
        }
    }

    fn sample_pdu() -> EntityStatePdu {
        EntityStatePdu {
            header: PduHeader::new(
                PduType::EntityState,
                ProtocolFamily::EntityInformationInteraction,
                0, // overwritten on encode
            ),
            entity_id: EntityId {
                site: 1,
                application: 2,
                entity: 100,
            },
            force_id: ForceId::Friendly,
            entity_type: sample_entity_type(10),
            alternative_entity_type: sample_entity_type(20),
            linear_velocity: [10.0, 20.0, 30.0],
            location_ecef: [1_334_016.0, -4_654_292.0, 4_137_906.0],
            orientation: [0.1, 0.2, 0.3],
            appearance: 0xCAFE_BABE,
            dead_reckoning: DeadReckoningParameters {
                algorithm: 2, // DRM_FPW
                other_parameters: [0; 15],
                linear_acceleration: [0.0, -9.8, 0.0],
                angular_velocity: [0.01, 0.02, 0.03],
            },
            marking_charset: 1, // ASCII
            marking: "M1A2".into(),
            capabilities: 0x0000_000F,
            articulation_parameters: Vec::new(),
        }
    }

    #[test]
    fn entity_state_pdu_round_trips_through_encode_decode() {
        let pdu = sample_pdu();
        let bytes = pdu.encode().expect("encode");
        // Total length must be 12 (header) + 132 (fixed body) = 144 bytes.
        assert_eq!(bytes.len(), 144);
        let decoded = EntityStatePdu::decode(&bytes).expect("decode");
        // Header `length` is overwritten on encode; compare the rest.
        assert_eq!(decoded.entity_id, pdu.entity_id);
        assert_eq!(decoded.force_id, pdu.force_id);
        assert_eq!(decoded.entity_type, pdu.entity_type);
        assert_eq!(decoded.alternative_entity_type, pdu.alternative_entity_type);
        assert_eq!(decoded.linear_velocity, pdu.linear_velocity);
        assert_eq!(decoded.location_ecef, pdu.location_ecef);
        assert_eq!(decoded.orientation, pdu.orientation);
        assert_eq!(decoded.appearance, pdu.appearance);
        assert_eq!(decoded.dead_reckoning, pdu.dead_reckoning);
        assert_eq!(decoded.marking, pdu.marking);
        assert_eq!(decoded.capabilities, pdu.capabilities);
    }

    #[test]
    fn entity_state_pdu_with_articulation_parameters_round_trips() {
        let mut pdu = sample_pdu();
        pdu.articulation_parameters = vec![
            ArticulationParameter {
                raw: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F,
                ],
            },
            ArticulationParameter {
                raw: [
                    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC,
                    0xFD, 0xFE, 0xFF,
                ],
            },
        ];
        let bytes = pdu.encode().expect("encode");
        // Must be 144 + 2 × 16 = 176 bytes.
        assert_eq!(bytes.len(), 176);
        let decoded = EntityStatePdu::decode(&bytes).expect("decode");
        assert_eq!(decoded.articulation_parameters, pdu.articulation_parameters);
    }

    #[test]
    fn entity_state_pdu_decode_rejects_wrong_pdu_type() {
        let pdu = sample_pdu();
        let mut bytes = pdu.encode().expect("encode");
        // Force PDU type byte to 2 (Fire PDU) — the decoder must reject.
        bytes[2] = 2;
        let err = EntityStatePdu::decode(&bytes).expect_err("must fail");
        match err {
            DisError::UnexpectedPduType { expected, got } => {
                assert_eq!(expected, PduType::ENTITY_STATE);
                assert_eq!(got, 2);
            }
            other => panic!("expected UnexpectedPduType, got {other:?}"),
        }
    }

    #[test]
    fn entity_state_pdu_decode_rejects_length_mismatch() {
        let pdu = sample_pdu();
        let mut bytes = pdu.encode().expect("encode");
        // Truncate by 1 byte without rewriting the header length —
        // decoder must reject.
        let _ = bytes.pop();
        let err = EntityStatePdu::decode(&bytes).expect_err("must fail");
        assert!(matches!(err, DisError::LengthMismatch { .. }));
    }

    #[test]
    fn entity_state_pdu_decode_rejects_truncated_body() {
        // A buffer with a valid 12-byte header declaring 144-byte
        // length but only 50 body bytes — must surface a typed
        // truncation.
        let mut bytes = vec![0u8; 12];
        bytes[0] = 7; // protocol version
        bytes[2] = 1; // pdu_type Entity State
        bytes[3] = 1; // protocol_family Entity Info / Interaction
        bytes[8..10].copy_from_slice(&62u16.to_be_bytes()); // length 62 = 12 + 50
        bytes.extend_from_slice(&[0u8; 50]);
        let err = EntityStatePdu::decode(&bytes).expect_err("must fail");
        assert!(matches!(err, DisError::Truncated { .. }));
    }

    #[test]
    fn marking_decode_strips_trailing_nuls() {
        let mut bytes = [0u8; 11];
        bytes[..4].copy_from_slice(b"M1A2");
        let s = decode_marking(&bytes).expect("decode");
        assert_eq!(s, "M1A2");
    }

    #[test]
    fn marking_decode_rejects_non_ascii() {
        let mut bytes = [0u8; 11];
        bytes[0] = 0xC3; // start of UTF-8 sequence — non-ASCII
        let err = decode_marking(&bytes).expect_err("must fail");
        assert!(matches!(err, DisError::InvalidMarking { byte_index: 0 }));
    }

    #[test]
    fn marking_encode_pads_short_strings_with_nul() {
        let mut buf = Vec::new();
        encode_marking("AB", &mut buf);
        assert_eq!(buf.len(), 11);
        assert_eq!(buf[0], b'A');
        assert_eq!(buf[1], b'B');
        for &b in &buf[2..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn marking_encode_truncates_long_strings() {
        // 12 ASCII characters; only 11 should make it onto the wire.
        let mut buf = Vec::new();
        encode_marking("ABCDEFGHIJKL", &mut buf);
        assert_eq!(buf.len(), 11);
        assert_eq!(&buf[..], b"ABCDEFGHIJK");
    }

    #[test]
    fn force_id_round_trips_for_all_byte_values() {
        for byte in 0u8..=255u8 {
            assert_eq!(ForceId::from_u8(byte).to_u8(), byte);
        }
    }

    #[test]
    fn entity_id_round_trips() {
        let id = EntityId {
            site: 0xCAFE,
            application: 0xBABE,
            entity: 0xDEAD,
        };
        let mut buf = Vec::new();
        id.encode_into(&mut buf);
        assert_eq!(buf.len(), 6);
        let decoded = EntityId::decode(&buf).expect("decode");
        assert_eq!(decoded, id);
    }

    #[test]
    fn entity_type_round_trips() {
        let t = sample_entity_type(33);
        let mut buf = Vec::new();
        t.encode_into(&mut buf);
        assert_eq!(buf.len(), 8);
        let decoded = EntityType::decode(&buf).expect("decode");
        assert_eq!(decoded, t);
    }

    #[test]
    fn dead_reckoning_round_trips() {
        let dr = DeadReckoningParameters {
            algorithm: 4, // DRM_RVW
            other_parameters: [
                0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
                0xAE,
            ],
            linear_acceleration: [-1.0, 0.5, 9.81],
            angular_velocity: [0.001, -0.002, 0.003],
        };
        let mut buf = Vec::new();
        dr.encode_into(&mut buf);
        assert_eq!(buf.len(), DEAD_RECKONING_LEN);
        let decoded = DeadReckoningParameters::decode(&buf).expect("decode");
        assert_eq!(decoded, dr);
    }
}
