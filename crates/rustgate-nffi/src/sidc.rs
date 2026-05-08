// Copyright © 2026 Roberto Chiofalo.

//! APP-6A Symbol Identification Code (SIDC) parsing.
//!
//! NFFI `<sidc>` bodies are spec'd as exactly 15 ASCII characters
//! laid out per APP-6A (the NATO predecessor to MIL-STD-2525C, with
//! which it shares the same 15-character form). The four leading
//! positions carry the character set the canonical
//! [`rustgate_core::entity::Entity`] shape needs in order to
//! classify a track:
//!
//! ```text
//!   pos 1  coding scheme        (S = warfighting, …)
//!   pos 2  affiliation          (F = friend, H = hostile, N = neutral, U = unknown, …)
//!   pos 3  battle dimension     (G = ground, A = air, S = surface, U = subsurface, F = SOF, …)
//!   pos 4  status               (P = present, A = anticipated/planned, …)
//!   pos 5..10 function ID       (codec-opaque — preserved verbatim on the entity)
//!   pos 11..15 reserved         (often `-----`)
//! ```
//!
//! This module hand-rolls a small parser for positions 1-4 — the
//! positions the canonical `Entity` shape consumes for routing and
//! dashboards. Positions 5-15 ride opaque on the `mil_std_2525_sidc`
//! field of the entity (the SIDC string is preserved verbatim) so a
//! downstream consumer with a full APP-6A taxonomy can decode them
//! without help from this codec.
//!
//! Refusing to model the full APP-6A taxonomy here is a deliberate
//! choice: the full standard catalogues thousands of function IDs
//! across battle dimensions, the catalogue evolves with each
//! revision of the NATO standard, and the canonical `Entity`
//! shape only consumes the dimension byte for routing. A typed
//! function-ID enum would bloat this crate for no operational
//! signal at the routing layer.

use crate::error::NffiError;

/// Length of an APP-6A SIDC string in characters. STANAG 5527
/// `<sidc>` bodies are spec'd as exactly 15 characters; a shorter
/// or longer body is rejected at decode time.
pub const SIDC_LENGTH: usize = 15;

/// Parsed APP-6A Symbol Identification Code positions 1-4.
///
/// Positions 5-15 ride opaque on the source string (preserved
/// verbatim by the codec on the entity's `mil_std_2525_sidc`
/// field) — the canonical [`rustgate_core::entity::Entity`] shape
/// only consumes positions 1-4 for routing and classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSixA {
    /// Coding-scheme byte (position 1). `S` is the standard
    /// warfighting code that every coalition NFFI feed in the
    /// wild emits today; non-`S` values are accepted (NFFI is
    /// schema-permissive) and surface as
    /// [`CodingScheme::Other`].
    pub coding_scheme: CodingScheme,
    /// Affiliation byte (position 2). The canonical entity-kind
    /// dispatch consumes this byte to classify a track as
    /// friend / hostile / neutral / unknown for downstream
    /// routing and dashboards.
    pub affiliation: Affiliation,
    /// Battle dimension (position 3). Drives the coarse
    /// [`rustgate_core::entity::EntityKind`] dispatch — `G`
    /// → `Ground`, `A` → `Aircraft`, `S` / `U` → `Marine`,
    /// `P` → `Munition`, everything else → `Track`.
    pub battle_dimension: BattleDimension,
    /// Status byte (position 4). `P` (present) is the
    /// overwhelmingly common value on real BFT feeds; `A`
    /// (anticipated/planned) flags positions that are
    /// projected rather than observed. Other values surface as
    /// [`Status::Other`] without rejection.
    pub status: Status,
}

/// APP-6A coding scheme byte (position 1 of the 15-char SIDC).
///
/// The NATO standard catalogues several coding schemes (warfighting,
/// tactical-graphics, METOC, intelligence, stability operations);
/// this enum surfaces only the warfighting bucket explicitly because
/// NFFI is a friendly-force-tracking format and warfighting is the
/// only scheme observed on coalition BFT feeds in the wild. Non-`S`
/// values are accepted and surface as [`CodingScheme::Other`] so the
/// codec does not refuse otherwise-valid input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodingScheme {
    /// Warfighting (`S`). The standard scheme for tactical
    /// data-link feeds.
    Warfighting,
    /// Anything other than `S`. The raw byte is preserved on the
    /// variant so a downstream consumer with a full APP-6A
    /// catalogue can decode it without help from this codec.
    Other(char),
}

/// APP-6A affiliation byte (position 2 of the 15-char SIDC).
///
/// Drives the canonical
/// [`rustgate_core::entity::Entity`]'s implicit affiliation
/// classification. The vocabulary is the standard 11-affiliation
/// set carried by APP-6A and aligned with MIL-STD-2525C; non-spec
/// values surface as [`Affiliation::Other`] without rejection so the
/// codec stays interoperable with peers emitting vendor-specific
/// extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Affiliation {
    /// Pending (`P`).
    Pending,
    /// Unknown (`U`).
    Unknown,
    /// Assumed friend (`A`).
    AssumedFriend,
    /// Friend (`F`). The dominant value on coalition BFT feeds.
    Friend,
    /// Neutral (`N`).
    Neutral,
    /// Suspect (`S`).
    Suspect,
    /// Hostile (`H`).
    Hostile,
    /// Joker (`J`).
    Joker,
    /// Faker (`K`).
    Faker,
    /// None specified (`O`).
    NoneSpecified,
    /// Anything outside the standard 11-affiliation set. The raw
    /// byte is preserved on the variant.
    Other(char),
}

/// APP-6A battle dimension (position 3 of the 15-char SIDC).
///
/// This enum carries every dimension byte the canonical
/// [`rustgate_core::entity::EntityKind`] dispatch path consumes,
/// plus an [`BattleDimension::Other`] catch-all for forward
/// compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BattleDimension {
    /// Space (`P`).
    Space,
    /// Air (`A`). Dispatches to
    /// [`rustgate_core::entity::EntityKind::Aircraft`].
    Air,
    /// Ground (`G`). Dispatches to
    /// [`rustgate_core::entity::EntityKind::Ground`].
    Ground,
    /// Sea surface (`S`). Dispatches to
    /// [`rustgate_core::entity::EntityKind::Marine`].
    SeaSurface,
    /// Sea sub-surface (`U`). Dispatches to
    /// [`rustgate_core::entity::EntityKind::Marine`].
    SeaSubsurface,
    /// Special operations forces (`F`).
    Sof,
    /// Anything outside the standard dimension set. The raw
    /// byte is preserved on the variant.
    Other(char),
}

/// APP-6A status byte (position 4 of the 15-char SIDC).
///
/// Present (`P`) is the overwhelmingly common value on real BFT
/// feeds; anticipated / planned (`A`) flags positions that are
/// projected rather than observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Present (`P`).
    Present,
    /// Anticipated / planned (`A`).
    Anticipated,
    /// Anything other than `P` / `A`. The raw byte is preserved.
    Other(char),
}

impl AppSixA {
    /// Parse the four-position APP-6A header from a 15-character
    /// SIDC string. Positions 5-15 ride opaque on the caller's
    /// own copy of the SIDC — they are not consumed here.
    ///
    /// Returns [`NffiError::InvalidSidcLength`] when `s` is not
    /// exactly 15 ASCII characters. Non-spec bytes in positions
    /// 1-4 surface as `*::Other` variants on the parsed value
    /// rather than as parse errors — NFFI is schema-permissive
    /// in the wild and refusing otherwise-valid payloads on a
    /// vendor-specific affiliation byte would break interop with
    /// real coalition feeds.
    pub fn parse(s: &str) -> Result<Self, NffiError> {
        // Spec-mandated length is 15 characters. Use `chars().count()`
        // so a payload that smuggles non-ASCII (e.g. a smart-quote
        // copy-paste) reports the correct character count rather
        // than the byte length.
        let len = s.chars().count();
        if len != SIDC_LENGTH {
            return Err(NffiError::InvalidSidcLength { actual: len });
        }
        // Safe to index by `chars()` here — we just confirmed there
        // are 15. Defaults at every position guard against a future
        // change to the length check.
        let mut iter = s.chars();
        let coding_scheme = match iter.next().unwrap_or('-') {
            'S' => CodingScheme::Warfighting,
            other => CodingScheme::Other(other),
        };
        let affiliation = match iter.next().unwrap_or('-') {
            'P' => Affiliation::Pending,
            'U' => Affiliation::Unknown,
            'A' => Affiliation::AssumedFriend,
            'F' => Affiliation::Friend,
            'N' => Affiliation::Neutral,
            'S' => Affiliation::Suspect,
            'H' => Affiliation::Hostile,
            'J' => Affiliation::Joker,
            'K' => Affiliation::Faker,
            'O' => Affiliation::NoneSpecified,
            other => Affiliation::Other(other),
        };
        let battle_dimension = match iter.next().unwrap_or('-') {
            'P' => BattleDimension::Space,
            'A' => BattleDimension::Air,
            'G' => BattleDimension::Ground,
            'S' => BattleDimension::SeaSurface,
            'U' => BattleDimension::SeaSubsurface,
            'F' => BattleDimension::Sof,
            other => BattleDimension::Other(other),
        };
        let status = match iter.next().unwrap_or('-') {
            'P' => Status::Present,
            'A' => Status::Anticipated,
            other => Status::Other(other),
        };
        Ok(Self {
            coding_scheme,
            affiliation,
            battle_dimension,
            status,
        })
    }

    /// Map the battle-dimension byte to a canonical
    /// [`rustgate_core::entity::EntityKind`].
    ///
    /// `Air` → `Aircraft`, `Ground` → `Ground`, `SeaSurface` /
    /// `SeaSubsurface` → `Marine`, everything else → `Track`. The
    /// `Track` fallback keeps SOF / space / vendor-specific
    /// dimensions out of the platform-specific buckets while still
    /// surfacing them on the routed entity.
    pub fn entity_kind(&self) -> rustgate_core::entity::EntityKind {
        use rustgate_core::entity::EntityKind;
        match self.battle_dimension {
            BattleDimension::Air => EntityKind::Aircraft,
            BattleDimension::Ground => EntityKind::Ground,
            BattleDimension::SeaSurface | BattleDimension::SeaSubsurface => EntityKind::Marine,
            // Space, SOF, and `Other(_)` all collapse to `Track` —
            // they are valid APP-6A dimensions but do not fit the
            // strict-subset platform buckets the canonical entity
            // shape models. The verbatim SIDC is still preserved on
            // `Entity::mil_std_2525_sidc` so downstream dashboards
            // can group on the dimension byte directly.
            _ => EntityKind::Track,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_friendly_ground_sidc() {
        // SFGPUCI-----C-- — Warfighting / Friend / Ground /
        // Present, function-id "UCI" (infantry company), reserved
        // bits empty.
        let sidc = AppSixA::parse("SFGPUCI-----C--").expect("parse");
        assert_eq!(sidc.coding_scheme, CodingScheme::Warfighting);
        assert_eq!(sidc.affiliation, Affiliation::Friend);
        assert_eq!(sidc.battle_dimension, BattleDimension::Ground);
        assert_eq!(sidc.status, Status::Present);
    }

    #[test]
    fn parses_a_hostile_air_sidc() {
        // SHAPMFFJ-------- — Warfighting / Hostile / Air /
        // Present, fighter-jet function id.
        let sidc = AppSixA::parse("SHAPMFFJ-------").expect("parse");
        assert_eq!(sidc.affiliation, Affiliation::Hostile);
        assert_eq!(sidc.battle_dimension, BattleDimension::Air);
        assert_eq!(
            sidc.entity_kind(),
            rustgate_core::entity::EntityKind::Aircraft
        );
    }

    #[test]
    fn parses_a_neutral_sea_surface_sidc() {
        let sidc = AppSixA::parse("SNSPCMOH-------").expect("parse");
        assert_eq!(sidc.affiliation, Affiliation::Neutral);
        assert_eq!(sidc.battle_dimension, BattleDimension::SeaSurface);
        assert_eq!(
            sidc.entity_kind(),
            rustgate_core::entity::EntityKind::Marine
        );
    }

    #[test]
    fn rejects_short_sidc() {
        let err = AppSixA::parse("SFGP").expect_err("must reject");
        assert!(matches!(err, NffiError::InvalidSidcLength { actual: 4 }));
    }

    #[test]
    fn rejects_long_sidc() {
        // 16 characters — one over the spec.
        let err = AppSixA::parse("SFGPUCI-----C---").expect_err("must reject");
        assert!(matches!(err, NffiError::InvalidSidcLength { actual: 16 }));
    }

    #[test]
    fn vendor_specific_affiliation_byte_does_not_fail() {
        // `Q` is not in the standard affiliation vocabulary; the
        // parser must surface it as `Affiliation::Other('Q')`
        // rather than rejecting the whole SIDC.
        let sidc = AppSixA::parse("SQGPUCI-----C--").expect("parse");
        assert_eq!(sidc.affiliation, Affiliation::Other('Q'));
        assert_eq!(sidc.battle_dimension, BattleDimension::Ground);
    }

    #[test]
    fn unknown_battle_dimension_collapses_to_track_kind() {
        // `Z` is not a standard battle dimension. The parser
        // surfaces it as `BattleDimension::Other('Z')` and the
        // entity-kind dispatch collapses it to `Track`.
        let sidc = AppSixA::parse("SFZPUCI-----C--").expect("parse");
        assert_eq!(sidc.battle_dimension, BattleDimension::Other('Z'));
        assert_eq!(sidc.entity_kind(), rustgate_core::entity::EntityKind::Track);
    }

    #[test]
    fn anticipated_status_decodes() {
        let sidc = AppSixA::parse("SFGAUCI-----C--").expect("parse");
        assert_eq!(sidc.status, Status::Anticipated);
    }

    #[test]
    fn covers_full_appendix_a_affiliation_set() {
        // Every standard affiliation byte must round-trip without
        // collapsing into `Other`.
        let cases = [
            ('P', Affiliation::Pending),
            ('U', Affiliation::Unknown),
            ('A', Affiliation::AssumedFriend),
            ('F', Affiliation::Friend),
            ('N', Affiliation::Neutral),
            ('S', Affiliation::Suspect),
            ('H', Affiliation::Hostile),
            ('J', Affiliation::Joker),
            ('K', Affiliation::Faker),
            ('O', Affiliation::NoneSpecified),
        ];
        for (byte, expected) in cases {
            let sidc_str = format!("S{byte}GPUCI-----C--");
            let sidc = AppSixA::parse(&sidc_str).expect("parse");
            assert_eq!(sidc.affiliation, expected, "byte {byte}");
        }
    }
}
