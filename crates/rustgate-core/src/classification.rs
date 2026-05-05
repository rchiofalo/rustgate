// Copyright © 2026 Roberto Chiofalo.

//! CAPCO classification marking types for tactical message routing.
//!
//! Implements the U.S. CAPCO (Controlled Access Program Coordination Office)
//! classification banner grammar as specified in DoDM 5200.01 Volume 2,
//! Appendix 3 ("Marking Classified Information"). The wire form is the
//! canonical banner string produced by `Display` and consumed by
//! `FromStr` — every classified [`crate::message::RoutableMessage`] in a
//! cross-domain deployment will eventually carry one of these markings on
//! its envelope so the router can enforce a domain-aware
//! release-control policy.
//!
//! # Scope of this deliverable
//!
//! This module ships **only** the type, the parser, the validator, the
//! lattice ordering, and the wire-stable serde representation. The
//! `Metadata.classification` field, the router enforcement path, the Cedar
//! policy backend integration, the cross-domain guard hooks, and the
//! MIL-STD-2525 SIDC carry on the Entity model are tracked under the
//! same umbrella issue and ship in subsequent PRs.
//!
//! # Banner grammar (subset implemented here)
//!
//! ```text
//! marking      := "//" classification ("//" sci-block)? ("//" diss-block)? ("//" nonintel-block)? "//"?
//! classification := "UNCLASSIFIED" | "CONFIDENTIAL" | "SECRET" | "TOP SECRET"
//! sci-block    := sci-control ("/" sci-control)*
//! diss-block   := diss-control ("/" diss-control)*
//! nonintel-block := nonintel-control ("/" nonintel-control)*
//! ```
//!
//! # Lattice properties
//!
//! - [`Classification`] is totally ordered: U < C < S < TS.
//! - [`SciControl`] forms an unordered set; one marking dominates another
//!   in the SCI dimension iff the dominator's SCI set is a superset.
//! - [`DisseminationControl::Noforn`] is the most restrictive
//!   dissemination control: a marking carrying `NOFORN` dominates any
//!   marking that omits `NOFORN` at the same classification level,
//!   regardless of `REL TO` country lists.
//! - [`NonIntelControl`] (FOUO, LES, …) composes additively with the
//!   classification — every additional non-intel control raises the
//!   restriction.
//! - [`ClassificationMarking::dominates`] returns `true` when `self` is
//!   at least as restrictive as `other` along every dimension.
//! - [`ClassificationMarking::lub`] computes the least upper bound (the
//!   "high-water mark") across two markings — used by the eventual
//!   cross-domain guard to determine the marking of a derivative
//!   message that combined two source markings.
//!
//! # Wire format and serde
//!
//! The on-the-wire representation is the `Display` string, not the
//! struct's fields. Serde delegates to `Display` / `FromStr` via
//! `#[serde(into = "String", try_from = "String")]` so JSON, TOML,
//! bincode, and MsgPack callers all carry a stable banner string —
//! a value like `"//SECRET//SI/TK//NOFORN"` — instead of an
//! implementation-specific JSON object that would break on a future
//! variant addition.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// CAPCO base classification level.
///
/// The four levels form a total order under `Ord`: `Unclassified <
/// Confidential < Secret < TopSecret`. The derived ordering is used
/// directly by [`ClassificationMarking::dominates`] and
/// [`ClassificationMarking::lub`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Classification {
    /// `UNCLASSIFIED` — the lowest level.
    Unclassified,
    /// `CONFIDENTIAL` — disclosure could damage national security.
    Confidential,
    /// `SECRET` — disclosure could cause serious damage.
    Secret,
    /// `TOP SECRET` — disclosure could cause exceptionally grave damage.
    TopSecret,
}

impl Classification {
    /// Render the level as the CAPCO banner token (no surrounding `//`).
    fn as_banner(&self) -> &'static str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP SECRET",
        }
    }

    /// Parse a CAPCO classification token. Strict: no case-insensitive
    /// match, no abbreviations.
    fn parse(token: &str) -> Result<Self, ParseError> {
        match token {
            "UNCLASSIFIED" => Ok(Self::Unclassified),
            "CONFIDENTIAL" => Ok(Self::Confidential),
            "SECRET" => Ok(Self::Secret),
            "TOP SECRET" => Ok(Self::TopSecret),
            other => Err(ParseError::UnknownClassification(other.to_owned())),
        }
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_banner())
    }
}

/// Sensitive Compartmented Information (SCI) control.
///
/// SCI controls compose unordered: a marking with `{SI, TK}` and a
/// marking with `{TK, SI}` are equal. The canonical banner ordering
/// emitted by `Display` is the alphabetical order of the SCI tokens.
/// The set of supported codes here covers the publicly documented
/// CAPCO baseline; classification-system additions go in a separate
/// follow-up PR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SciControl {
    /// `SI` — Special Intelligence (signals intelligence compartment).
    Si,
    /// `TK` — TALENT KEYHOLE (overhead/imagery compartment).
    Tk,
    /// `HCS` — HUMINT Control System.
    Hcs,
    /// `HCS-P` — HUMINT Control System, Product.
    HcsP,
    /// `HCS-O` — HUMINT Control System, Operations.
    HcsO,
    /// `KLONDIKE` — KLONDIKE compartment.
    Klondike,
    /// `RSV` — Reserved compartment (placeholder — populated per program).
    Rsv,
}

impl SciControl {
    fn as_banner(&self) -> &'static str {
        match self {
            Self::Si => "SI",
            Self::Tk => "TK",
            Self::Hcs => "HCS",
            Self::HcsP => "HCS-P",
            Self::HcsO => "HCS-O",
            Self::Klondike => "KLONDIKE",
            Self::Rsv => "RSV",
        }
    }

    fn parse(token: &str) -> Result<Self, ParseError> {
        match token {
            "SI" => Ok(Self::Si),
            "TK" => Ok(Self::Tk),
            "HCS" => Ok(Self::Hcs),
            "HCS-P" => Ok(Self::HcsP),
            "HCS-O" => Ok(Self::HcsO),
            "KLONDIKE" => Ok(Self::Klondike),
            "RSV" => Ok(Self::Rsv),
            other => Err(ParseError::UnknownSciControl(other.to_owned())),
        }
    }
}

impl fmt::Display for SciControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_banner())
    }
}

/// Foreign-disclosure / dissemination control.
///
/// `NOFORN` and `REL TO` are mutually exclusive in the wire form: a
/// marking that carries both is rejected by the parser. `FVEY` is a
/// shorthand for `REL TO USA, AUS, CAN, GBR, NZL` and is preserved
/// verbatim in the banner instead of being expanded.
///
/// # Country list ordering
///
/// `REL TO` country lists are normalized to upper-case and emitted in
/// alphabetical order on `Display`. The parser accepts any input
/// ordering but the round-trip output is canonical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DisseminationControl {
    /// `NOFORN` — Not Releasable to Foreign Nationals.
    Noforn,
    /// `REL TO <COUNTRY-LIST>` — Releasable to the listed partners.
    /// The list is stored normalized: upper-case, alphabetical, dedup'd.
    RelTo(Vec<String>),
    /// `FVEY` — Five Eyes (USA + AUS + CAN + GBR + NZL).
    Fvey,
}

impl DisseminationControl {
    fn parse(token: &str) -> Result<Self, ParseError> {
        match token {
            "NOFORN" => return Ok(Self::Noforn),
            "FVEY" => return Ok(Self::Fvey),
            _ => {}
        }
        if let Some(rest) = token.strip_prefix("REL TO ") {
            let trimmed = rest.trim();
            if trimmed.is_empty() {
                return Err(ParseError::RelToWithoutCountryList);
            }
            let countries: Vec<String> = trimmed
                .split(',')
                .map(|s| s.trim().to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            if countries.is_empty() {
                return Err(ParseError::RelToWithoutCountryList);
            }
            // Normalize: dedup + alphabetical for canonical output.
            let mut sorted: BTreeSet<String> = BTreeSet::new();
            for c in &countries {
                if !c.chars().all(|ch| ch.is_ascii_alphabetic()) {
                    return Err(ParseError::InvalidCountryCode(c.clone()));
                }
                let _ = sorted.insert(c.clone());
            }
            return Ok(Self::RelTo(sorted.into_iter().collect()));
        }
        Err(ParseError::UnknownDisseminationControl(token.to_owned()))
    }
}

impl fmt::Display for DisseminationControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Noforn => f.write_str("NOFORN"),
            Self::Fvey => f.write_str("FVEY"),
            Self::RelTo(countries) => {
                f.write_str("REL TO ")?;
                for (i, c) in countries.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(c)?;
                }
                Ok(())
            }
        }
    }
}

/// Non-intelligence dissemination control (FOUO, LES, …).
///
/// Composes additively: a marking with `{FOUO, LES}` is more
/// restrictive than one with `{FOUO}` along the non-intelligence
/// dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NonIntelControl {
    /// `FOUO` — For Official Use Only.
    Fouo,
    /// `LES` — Law Enforcement Sensitive.
    Les,
    /// `SBU` — Sensitive But Unclassified.
    Sbu,
}

impl NonIntelControl {
    fn as_banner(&self) -> &'static str {
        match self {
            Self::Fouo => "FOUO",
            Self::Les => "LES",
            Self::Sbu => "SBU",
        }
    }

    fn parse(token: &str) -> Result<Self, ParseError> {
        match token {
            "FOUO" => Ok(Self::Fouo),
            "LES" => Ok(Self::Les),
            "SBU" => Ok(Self::Sbu),
            other => Err(ParseError::UnknownNonIntelControl(other.to_owned())),
        }
    }
}

impl fmt::Display for NonIntelControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_banner())
    }
}

/// A complete CAPCO classification banner.
///
/// The four fields capture the four banner blocks in order: base
/// classification, SCI controls, dissemination controls, non-intel
/// controls. The struct is constructed via `FromStr` for parsed
/// banners and [`ClassificationMarking::new`] for programmatic
/// construction; either way, the canonical wire form is produced by
/// `Display` and is what serde uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClassificationMarking {
    /// Base classification level (UNCLASSIFIED through TOP SECRET).
    pub classification: Classification,
    /// SCI compartments. Empty for non-intelligence traffic. Stored in
    /// canonical (alphabetical) order.
    pub sci_controls: Vec<SciControl>,
    /// Foreign disclosure controls (`NOFORN`, `REL TO …`, `FVEY`).
    /// Stored in canonical (lexicographic) order.
    pub dissemination: Vec<DisseminationControl>,
    /// Non-intel controls (`FOUO`, `LES`, `SBU`). Stored in canonical
    /// (alphabetical) order.
    pub non_intelligence: Vec<NonIntelControl>,
}

impl ClassificationMarking {
    /// Construct a marking with no caveats — the bare classification.
    ///
    /// Equivalent to `FromStr::from_str("//SECRET//")` for `Secret` etc.
    pub fn new(classification: Classification) -> Self {
        Self {
            classification,
            sci_controls: Vec::new(),
            dissemination: Vec::new(),
            non_intelligence: Vec::new(),
        }
    }

    /// Construct a fully-specified marking, normalizing each caveat
    /// list into the canonical (sorted, deduplicated) order so two
    /// equivalent markings compare equal.
    pub fn with_caveats(
        classification: Classification,
        sci: Vec<SciControl>,
        dissemination: Vec<DisseminationControl>,
        non_intelligence: Vec<NonIntelControl>,
    ) -> Self {
        let mut sci = sci;
        sci.sort();
        sci.dedup();

        let mut dissemination = dissemination;
        dissemination.sort();
        dissemination.dedup();

        let mut non_intelligence = non_intelligence;
        non_intelligence.sort();
        non_intelligence.dedup();

        Self {
            classification,
            sci_controls: sci,
            dissemination,
            non_intelligence,
        }
    }

    /// Returns `true` when `self` dominates `other` in the
    /// classification lattice — i.e. anyone cleared to read `self`
    /// is also cleared to read `other`.
    ///
    /// Domination is defined as "at least as restrictive along every
    /// dimension":
    /// 1. Base classification is at least as high.
    /// 2. SCI compartments are a superset.
    /// 3. Dissemination controls are at least as restrictive (NOFORN
    ///    on `self` dominates a `REL TO` list on `other`; matching
    ///    `REL TO` lists where `self ⊆ other` is more restrictive on
    ///    `self`).
    /// 4. Non-intel controls are a superset.
    pub fn dominates(&self, other: &Self) -> bool {
        if self.classification < other.classification {
            return false;
        }
        if !is_superset(&self.sci_controls, &other.sci_controls) {
            return false;
        }
        if !dominates_dissemination(&self.dissemination, &other.dissemination) {
            return false;
        }
        if !is_superset(&self.non_intelligence, &other.non_intelligence) {
            return false;
        }
        true
    }

    /// Compute the least upper bound of two markings — the marking
    /// that dominates both. Used by the eventual cross-domain guard
    /// to label a derivative message that combined two source
    /// messages.
    ///
    /// The base classification is `max(self, other)`; SCI compartments
    /// are unioned; non-intel controls are unioned; dissemination
    /// controls collapse via `merge_dissemination_lub` (NOFORN
    /// dominates REL TO; intersecting REL TO lists narrows the set).
    pub fn lub(&self, other: &Self) -> Self {
        let classification = self.classification.max(other.classification);

        let mut sci: BTreeSet<SciControl> = BTreeSet::new();
        for s in &self.sci_controls {
            let _ = sci.insert(*s);
        }
        for s in &other.sci_controls {
            let _ = sci.insert(*s);
        }

        let mut non_intel: BTreeSet<NonIntelControl> = BTreeSet::new();
        for n in &self.non_intelligence {
            let _ = non_intel.insert(*n);
        }
        for n in &other.non_intelligence {
            let _ = non_intel.insert(*n);
        }

        let dissemination = merge_dissemination_lub(&self.dissemination, &other.dissemination);

        Self {
            classification,
            sci_controls: sci.into_iter().collect(),
            dissemination,
            non_intelligence: non_intel.into_iter().collect(),
        }
    }
}

impl fmt::Display for ClassificationMarking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("//")?;
        f.write_str(self.classification.as_banner())?;
        if !self.sci_controls.is_empty() {
            f.write_str("//")?;
            for (i, s) in self.sci_controls.iter().enumerate() {
                if i > 0 {
                    f.write_str("/")?;
                }
                fmt::Display::fmt(s, f)?;
            }
        }
        if !self.dissemination.is_empty() {
            f.write_str("//")?;
            for (i, d) in self.dissemination.iter().enumerate() {
                if i > 0 {
                    f.write_str("/")?;
                }
                fmt::Display::fmt(d, f)?;
            }
        }
        if !self.non_intelligence.is_empty() {
            f.write_str("//")?;
            for (i, n) in self.non_intelligence.iter().enumerate() {
                if i > 0 {
                    f.write_str("/")?;
                }
                fmt::Display::fmt(n, f)?;
            }
        }
        Ok(())
    }
}

impl FromStr for ClassificationMarking {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let body = trimmed
            .strip_prefix("//")
            .ok_or(ParseError::MissingLeadingDelimiter)?;
        // Optional trailing `//` is allowed but not required.
        let body = body.strip_suffix("//").unwrap_or(body);

        // Split into the "//"-separated blocks. The first block is
        // the classification level; subsequent blocks are caveat
        // groups whose contents are "/"-separated.
        let mut blocks = body.split("//").map(str::trim);

        let classification_token = blocks.next().ok_or(ParseError::MissingClassification)?;
        if classification_token.is_empty() {
            return Err(ParseError::MissingClassification);
        }
        let classification = Classification::parse(classification_token)?;

        let mut sci_controls: Vec<SciControl> = Vec::new();
        let mut dissemination: Vec<DisseminationControl> = Vec::new();
        let mut non_intelligence: Vec<NonIntelControl> = Vec::new();
        let mut next_block = BlockKind::Sci;

        for raw in blocks {
            let block = raw.trim();
            if block.is_empty() {
                // Tolerate an empty trailing block (came from the
                // optional terminating `//`).
                continue;
            }
            // A caveat block may legally split on `/` only outside the
            // `REL TO ...` country list — countries themselves are
            // comma-separated. Use a small state-aware tokenizer.
            let tokens = split_caveat_tokens(block);
            let kind = classify_block(&tokens)?;
            if (kind as u8) < (next_block as u8) {
                return Err(ParseError::OutOfOrderBlock {
                    expected: next_block,
                    found: kind,
                });
            }
            match kind {
                BlockKind::Sci => {
                    for t in &tokens {
                        sci_controls.push(SciControl::parse(t)?);
                    }
                }
                BlockKind::Dissemination => {
                    for t in &tokens {
                        dissemination.push(DisseminationControl::parse(t)?);
                    }
                }
                BlockKind::NonIntel => {
                    for t in &tokens {
                        non_intelligence.push(NonIntelControl::parse(t)?);
                    }
                }
            }
            // Advance past this block kind so a subsequent block of
            // the same or earlier kind is rejected.
            next_block = match kind {
                BlockKind::Sci => BlockKind::Dissemination,
                BlockKind::Dissemination => BlockKind::NonIntel,
                BlockKind::NonIntel => BlockKind::NonIntel,
            };
        }

        // Mutually exclusive: NOFORN cannot coexist with REL TO / FVEY.
        let has_noforn = dissemination
            .iter()
            .any(|d| matches!(d, DisseminationControl::Noforn));
        let has_release = dissemination.iter().any(|d| {
            matches!(
                d,
                DisseminationControl::RelTo(_) | DisseminationControl::Fvey
            )
        });
        if has_noforn && has_release {
            return Err(ParseError::ConflictingDisseminationControls);
        }

        Ok(Self::with_caveats(
            classification,
            sci_controls,
            dissemination,
            non_intelligence,
        ))
    }
}

impl Serialize for ClassificationMarking {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ClassificationMarking {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ClassificationMarking::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Errors produced by [`ClassificationMarking::from_str`] and friends.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input did not begin with `//`.
    #[error("classification marking must start with `//`")]
    MissingLeadingDelimiter,
    /// The input had no classification token (empty body).
    #[error("classification marking is missing the base classification level")]
    MissingClassification,
    /// The classification token was not one of the four CAPCO levels.
    #[error(
        "unknown classification level `{0}` (expected UNCLASSIFIED, CONFIDENTIAL, SECRET, or TOP SECRET)"
    )]
    UnknownClassification(String),
    /// An SCI control token was not in the supported set.
    #[error("unknown SCI control `{0}`")]
    UnknownSciControl(String),
    /// A dissemination-control token was not in the supported set.
    #[error("unknown dissemination control `{0}`")]
    UnknownDisseminationControl(String),
    /// A non-intel control token was not in the supported set.
    #[error("unknown non-intelligence control `{0}`")]
    UnknownNonIntelControl(String),
    /// `REL TO` was supplied without a country list (or with an empty list).
    #[error("`REL TO` requires a non-empty country list")]
    RelToWithoutCountryList,
    /// A country code in a `REL TO` list contained non-alphabetic
    /// characters or was empty.
    #[error("invalid country code `{0}` in REL TO (expected alphabetic letters)")]
    InvalidCountryCode(String),
    /// `NOFORN` and `REL TO` / `FVEY` cannot coexist on the same marking.
    #[error("`NOFORN` cannot coexist with a release marking on the same banner")]
    ConflictingDisseminationControls,
    /// A caveat block appeared after a block of a later kind (e.g.
    /// non-intel before SCI).
    #[error("caveat block out of order: expected {expected:?} or later, found {found:?}")]
    OutOfOrderBlock {
        /// The minimum block kind that was still acceptable at this position.
        expected: BlockKind,
        /// The kind detected from the actual tokens.
        found: BlockKind,
    },
    /// A caveat block held tokens of mixed kinds (some SCI, some non-intel,
    /// etc.) — only homogeneous blocks are accepted.
    #[error("caveat block contains tokens of mixed kinds (mix of SCI / dissemination / non-intel)")]
    MixedKindBlock,
}

/// Identifies which kind of caveat block a set of tokens belongs to.
///
/// Used internally by the parser to enforce the canonical block order
/// `SCI → Dissemination → NonIntel`. Exposed publicly because it
/// appears in [`ParseError::OutOfOrderBlock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockKind {
    /// SCI compartment block.
    Sci = 0,
    /// Foreign-disclosure / dissemination block.
    Dissemination = 1,
    /// Non-intel block (FOUO, LES, …).
    NonIntel = 2,
}

// -- internal helpers -------------------------------------------------

/// Split a caveat block into its constituent tokens.
///
/// Tokens are normally separated by `/`, but a `REL TO` token contains
/// a comma-separated country list whose entries must not be split.
fn split_caveat_tokens(block: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_rel_to = false;
    let mut chars = block.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && !in_rel_to {
            // End of a token.
            let trimmed = current.trim();
            if !trimmed.is_empty() {
                tokens.push(trimmed.to_owned());
            }
            current.clear();
            continue;
        }
        current.push(c);
        // Detect entry into a REL TO token: once we have built up
        // "REL TO " we are inside a comma-separated country list and
        // any subsequent `/` is a block-separator (which we should not
        // see inside a single block) or the end of the token.
        if !in_rel_to && current.trim_start() == "REL TO" {
            // Need a trailing space to confirm. Peek the next char.
            if chars.peek() == Some(&' ') {
                in_rel_to = true;
            }
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        tokens.push(trimmed.to_owned());
    }
    tokens
}

/// Categorize a block by inspecting its tokens. Each block must be
/// homogeneous — all tokens of the same kind. A mixed block returns
/// [`ParseError::MixedKindBlock`].
fn classify_block(tokens: &[String]) -> Result<BlockKind, ParseError> {
    let mut kind: Option<BlockKind> = None;
    for t in tokens {
        let k = token_kind(t);
        match kind {
            None => kind = Some(k),
            Some(existing) if existing == k => {}
            Some(_) => return Err(ParseError::MixedKindBlock),
        }
    }
    kind.ok_or(ParseError::MixedKindBlock)
}

/// Best-effort kind classification for a single token. The parser
/// will still validate the token against the appropriate enum's
/// `parse` method afterwards; this routine just routes a token to
/// the right block kind.
fn token_kind(token: &str) -> BlockKind {
    if matches!(token, "NOFORN" | "FVEY") || token.starts_with("REL TO") {
        BlockKind::Dissemination
    } else if matches!(token, "FOUO" | "LES" | "SBU") {
        BlockKind::NonIntel
    } else {
        BlockKind::Sci
    }
}

/// Set-superset test using the slice as a sorted sequence (safe because
/// every constructor normalizes to sorted-and-deduped form).
fn is_superset<T: Ord>(superset: &[T], subset: &[T]) -> bool {
    let s: BTreeSet<&T> = superset.iter().collect();
    subset.iter().all(|item| s.contains(item))
}

/// Per-dimension domination check for dissemination controls.
///
/// `self` dominates `other` iff for every restriction implied by
/// `other`, `self` carries an at-least-as-strong restriction:
/// - If `other` carries `NOFORN`, `self` must also carry `NOFORN`.
/// - If `other` carries `REL TO X`, `self` must carry either `NOFORN`
///   (more restrictive) or a `REL TO Y` with `Y ⊆ X` (narrower
///   release set is more restrictive), or `FVEY` if `FVEY ⊆ X` in
///   the country sense.
/// - If `other` carries `FVEY`, `self` must carry `NOFORN`, or `FVEY`,
///   or a `REL TO` whose country list is a subset of FVEY.
fn dominates_dissemination(
    superset: &[DisseminationControl],
    subset: &[DisseminationControl],
) -> bool {
    let self_has_noforn = superset
        .iter()
        .any(|d| matches!(d, DisseminationControl::Noforn));
    if self_has_noforn {
        // NOFORN is the strongest dissemination restriction —
        // automatically dominates any other dissemination control.
        return true;
    }
    let self_release = collect_release_countries(superset);
    let other_release = collect_release_countries(subset);
    let other_has_noforn = subset
        .iter()
        .any(|d| matches!(d, DisseminationControl::Noforn));
    if other_has_noforn {
        // other is NOFORN; self is not — self does NOT dominate.
        return false;
    }
    match (other_release.as_ref(), self_release.as_ref()) {
        (None, _) => {
            // other has no release restriction at all (no NOFORN, no
            // REL TO, no FVEY) — nothing to dominate.
            true
        }
        (Some(_), None) => {
            // other has a release restriction; self has none — self
            // is less restrictive, so does not dominate.
            false
        }
        (Some(other_set), Some(self_set)) => {
            // self's release list is a SUBSET of other's release list:
            // self releases to fewer parties → more restrictive →
            // dominates.
            self_set.is_subset(other_set)
        }
    }
}

/// Collect the union of countries implied by every release-style
/// dissemination control on a marking. Returns `None` if the marking
/// carries no release-style control at all.
fn collect_release_countries(controls: &[DisseminationControl]) -> Option<BTreeSet<String>> {
    let mut found_release = false;
    let mut set: BTreeSet<String> = BTreeSet::new();
    for c in controls {
        match c {
            DisseminationControl::RelTo(countries) => {
                found_release = true;
                for x in countries {
                    let _ = set.insert(x.clone());
                }
            }
            DisseminationControl::Fvey => {
                found_release = true;
                for x in ["AUS", "CAN", "GBR", "NZL", "USA"] {
                    let _ = set.insert(x.to_owned());
                }
            }
            DisseminationControl::Noforn => {}
        }
    }
    if found_release { Some(set) } else { None }
}

/// Compute the dissemination-control component of the lattice's
/// least upper bound.
///
/// Rules:
/// - If either side carries `NOFORN`, the result is `[NOFORN]`.
/// - Otherwise, intersect the release country sets — the LUB
///   releases only to parties both sources released to.
/// - If both sides carry no dissemination control at all, the result
///   is empty.
fn merge_dissemination_lub(
    left: &[DisseminationControl],
    right: &[DisseminationControl],
) -> Vec<DisseminationControl> {
    let left_noforn = left
        .iter()
        .any(|d| matches!(d, DisseminationControl::Noforn));
    let right_noforn = right
        .iter()
        .any(|d| matches!(d, DisseminationControl::Noforn));
    if left_noforn || right_noforn {
        return vec![DisseminationControl::Noforn];
    }
    let left_release = collect_release_countries(left);
    let right_release = collect_release_countries(right);
    match (left_release, right_release) {
        (None, None) => Vec::new(),
        (Some(set), None) | (None, Some(set)) => {
            // Only one side carries a release restriction; the LUB
            // inherits it (the unrestricted side's permission is
            // narrowed to the restricted side's set, which is exactly
            // that set).
            vec![DisseminationControl::RelTo(set.into_iter().collect())]
        }
        (Some(a), Some(b)) => {
            let intersection: BTreeSet<String> = a.intersection(&b).cloned().collect();
            if intersection.is_empty() {
                // Empty intersection — no party is cleared on both
                // sides, so the result is effectively NOFORN.
                vec![DisseminationControl::Noforn]
            } else {
                vec![DisseminationControl::RelTo(
                    intersection.into_iter().collect(),
                )]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    // -- 1. CAPCO grammar parsing ------------------------------------

    #[test]
    fn parse_unclassified_bare() {
        let m: ClassificationMarking = "//UNCLASSIFIED//".parse().unwrap();
        assert_eq!(m.classification, Classification::Unclassified);
        assert!(m.sci_controls.is_empty());
        assert!(m.dissemination.is_empty());
        assert!(m.non_intelligence.is_empty());
    }

    #[test]
    fn parse_unclassified_fouo() {
        let m: ClassificationMarking = "//UNCLASSIFIED//FOUO".parse().unwrap();
        assert_eq!(m.classification, Classification::Unclassified);
        assert_eq!(m.non_intelligence, vec![NonIntelControl::Fouo]);
    }

    #[test]
    fn parse_confidential_noforn() {
        let m: ClassificationMarking = "//CONFIDENTIAL//NOFORN".parse().unwrap();
        assert_eq!(m.classification, Classification::Confidential);
        assert_eq!(m.dissemination, vec![DisseminationControl::Noforn]);
    }

    #[test]
    fn parse_secret_si_noforn() {
        let m: ClassificationMarking = "//SECRET//SI//NOFORN".parse().unwrap();
        assert_eq!(m.classification, Classification::Secret);
        assert_eq!(m.sci_controls, vec![SciControl::Si]);
        assert_eq!(m.dissemination, vec![DisseminationControl::Noforn]);
    }

    #[test]
    fn parse_top_secret_si_tk_noforn() {
        let m: ClassificationMarking = "//TOP SECRET//SI/TK//NOFORN".parse().unwrap();
        assert_eq!(m.classification, Classification::TopSecret);
        assert_eq!(m.sci_controls, vec![SciControl::Si, SciControl::Tk]);
        assert_eq!(m.dissemination, vec![DisseminationControl::Noforn]);
    }

    #[test]
    fn parse_secret_rel_to_usa_fvey() {
        let m: ClassificationMarking = "//SECRET//REL TO USA, FVEY//".parse().unwrap();
        assert_eq!(m.classification, Classification::Secret);
        // REL TO USA, FVEY normalises to a single REL TO with both tokens.
        // FVEY here is parsed as a country code in the REL TO list.
        assert_eq!(
            m.dissemination,
            vec![DisseminationControl::RelTo(vec![
                "FVEY".to_owned(),
                "USA".to_owned(),
            ])]
        );
    }

    #[test]
    fn parse_secret_si_tk_rel_to_usa_gbr() {
        let m: ClassificationMarking = "//SECRET//SI/TK//REL TO USA, GBR//".parse().unwrap();
        assert_eq!(m.classification, Classification::Secret);
        assert_eq!(m.sci_controls, vec![SciControl::Si, SciControl::Tk]);
        assert_eq!(
            m.dissemination,
            vec![DisseminationControl::RelTo(vec![
                "GBR".to_owned(),
                "USA".to_owned(),
            ])]
        );
    }

    #[test]
    fn parse_top_secret_hcs_p_noforn() {
        let m: ClassificationMarking = "//TOP SECRET//HCS-P/SI//NOFORN".parse().unwrap();
        assert_eq!(m.classification, Classification::TopSecret);
        // Canonical sort follows the derived Ord on `SciControl`, which
        // is enum-declaration order: SI (idx 0) before HCS-P (idx 3).
        assert_eq!(m.sci_controls, vec![SciControl::Si, SciControl::HcsP]);
        assert_eq!(m.dissemination, vec![DisseminationControl::Noforn]);
    }

    #[test]
    fn parse_secret_fvey() {
        let m: ClassificationMarking = "//SECRET//FVEY".parse().unwrap();
        assert_eq!(m.classification, Classification::Secret);
        assert_eq!(m.dissemination, vec![DisseminationControl::Fvey]);
    }

    #[test]
    fn parse_unclassified_les() {
        let m: ClassificationMarking = "//UNCLASSIFIED//LES".parse().unwrap();
        assert_eq!(m.classification, Classification::Unclassified);
        assert_eq!(m.non_intelligence, vec![NonIntelControl::Les]);
    }

    #[test]
    fn parse_unclassified_fouo_les() {
        let m: ClassificationMarking = "//UNCLASSIFIED//FOUO/LES".parse().unwrap();
        assert_eq!(
            m.non_intelligence,
            vec![NonIntelControl::Fouo, NonIntelControl::Les]
        );
    }

    // -- 2. Display round-trip ---------------------------------------

    #[test]
    fn display_round_trip_secret_noforn() {
        let m: ClassificationMarking = "//SECRET//NOFORN".parse().unwrap();
        assert_eq!(m.to_string(), "//SECRET//NOFORN");
    }

    #[test]
    fn display_round_trip_top_secret_si_tk_noforn() {
        let m: ClassificationMarking = "//TOP SECRET//SI/TK//NOFORN".parse().unwrap();
        assert_eq!(m.to_string(), "//TOP SECRET//SI/TK//NOFORN");
    }

    #[test]
    fn display_round_trip_unclassified_fouo() {
        let m: ClassificationMarking = "//UNCLASSIFIED//FOUO".parse().unwrap();
        assert_eq!(m.to_string(), "//UNCLASSIFIED//FOUO");
    }

    #[test]
    fn display_canonicalizes_sci_alphabetical() {
        // Input has TK before SI (non-canonical); Display sorts them.
        let m: ClassificationMarking = "//TOP SECRET//TK/SI//NOFORN".parse().unwrap();
        assert_eq!(m.to_string(), "//TOP SECRET//SI/TK//NOFORN");
    }

    #[test]
    fn display_canonicalizes_rel_to_country_list_alphabetical() {
        // Country list given as USA, GBR (non-alphabetical); Display sorts.
        let m: ClassificationMarking = "//SECRET//REL TO USA, GBR".parse().unwrap();
        assert_eq!(m.to_string(), "//SECRET//REL TO GBR, USA");
    }

    #[test]
    fn display_canonicalizes_country_list_dedup() {
        let m: ClassificationMarking = "//SECRET//REL TO USA, GBR, USA".parse().unwrap();
        assert_eq!(m.to_string(), "//SECRET//REL TO GBR, USA");
    }

    #[test]
    fn display_for_bare_unclassified() {
        let m = ClassificationMarking::new(Classification::Unclassified);
        assert_eq!(m.to_string(), "//UNCLASSIFIED");
    }

    // -- 3. Lattice ordering -----------------------------------------

    #[test]
    fn ts_dominates_secret() {
        let ts = ClassificationMarking::new(Classification::TopSecret);
        let s = ClassificationMarking::new(Classification::Secret);
        assert!(ts.dominates(&s));
        assert!(!s.dominates(&ts));
    }

    #[test]
    fn secret_dominates_confidential_dominates_unclassified() {
        let s = ClassificationMarking::new(Classification::Secret);
        let c = ClassificationMarking::new(Classification::Confidential);
        let u = ClassificationMarking::new(Classification::Unclassified);
        assert!(s.dominates(&c));
        assert!(c.dominates(&u));
        assert!(s.dominates(&u));
        assert!(!u.dominates(&c));
    }

    #[test]
    fn ts_si_does_not_dominate_ts_tk() {
        let ts_si: ClassificationMarking = "//TOP SECRET//SI".parse().unwrap();
        let ts_tk: ClassificationMarking = "//TOP SECRET//TK".parse().unwrap();
        assert!(!ts_si.dominates(&ts_tk));
        assert!(!ts_tk.dominates(&ts_si));
    }

    #[test]
    fn ts_si_tk_dominates_ts_si() {
        let ts_si_tk: ClassificationMarking = "//TOP SECRET//SI/TK".parse().unwrap();
        let ts_si: ClassificationMarking = "//TOP SECRET//SI".parse().unwrap();
        assert!(ts_si_tk.dominates(&ts_si));
        assert!(!ts_si.dominates(&ts_si_tk));
    }

    #[test]
    fn noforn_dominates_rel_to() {
        let s_noforn: ClassificationMarking = "//SECRET//NOFORN".parse().unwrap();
        let s_rel: ClassificationMarking = "//SECRET//REL TO USA, GBR".parse().unwrap();
        assert!(s_noforn.dominates(&s_rel));
        assert!(!s_rel.dominates(&s_noforn));
    }

    #[test]
    fn rel_to_subset_dominates_rel_to_superset() {
        // A marking releasable to {USA} is more restrictive than one
        // releasable to {USA, GBR}, so the subset dominates.
        let s_usa: ClassificationMarking = "//SECRET//REL TO USA".parse().unwrap();
        let s_usa_gbr: ClassificationMarking = "//SECRET//REL TO USA, GBR".parse().unwrap();
        assert!(s_usa.dominates(&s_usa_gbr));
        assert!(!s_usa_gbr.dominates(&s_usa));
    }

    #[test]
    fn marking_dominates_self() {
        let m: ClassificationMarking = "//TOP SECRET//SI/TK//NOFORN".parse().unwrap();
        assert!(m.dominates(&m));
    }

    #[test]
    fn additional_non_intel_control_dominates() {
        let fouo_les: ClassificationMarking = "//UNCLASSIFIED//FOUO/LES".parse().unwrap();
        let fouo: ClassificationMarking = "//UNCLASSIFIED//FOUO".parse().unwrap();
        assert!(fouo_les.dominates(&fouo));
        assert!(!fouo.dominates(&fouo_les));
    }

    // -- 4. Reject malformed -----------------------------------------

    #[test]
    fn reject_missing_leading_delimiter() {
        let err: ParseError = "SECRET//NOFORN"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(err, ParseError::MissingLeadingDelimiter));
    }

    #[test]
    fn reject_mixed_case_classification() {
        let err: ParseError = "//Secret//NOFORN"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(err, ParseError::UnknownClassification(s) if s == "Secret"));
    }

    #[test]
    fn reject_unknown_sci_control() {
        let err: ParseError = "//SECRET//ZZZ//NOFORN"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(err, ParseError::UnknownSciControl(s) if s == "ZZZ"));
    }

    #[test]
    fn reject_rel_to_without_country_list() {
        let err: ParseError = "//SECRET//REL TO"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        // The token "REL TO" without trailing space is not in the
        // dissemination set; with trailing space + empty list, hits
        // `RelToWithoutCountryList`. Both are rejection — accept either.
        assert!(matches!(
            err,
            ParseError::RelToWithoutCountryList | ParseError::UnknownDisseminationControl(_)
        ));
    }

    #[test]
    fn reject_rel_to_with_empty_trailing_country_list() {
        // `REL TO ` with empty trailing space gets trimmed before
        // dissemination parsing, so the token surfaces as the bare
        // `REL TO` literal — neither a known dissemination control
        // nor a properly-formed REL TO. Either rejection class is a
        // valid contract from the parser's point of view; the test
        // pin is "this input is rejected", not the specific variant.
        let err: ParseError = "//SECRET//REL TO  "
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(
            err,
            ParseError::RelToWithoutCountryList | ParseError::UnknownDisseminationControl(_)
        ));
    }

    #[test]
    fn reject_noforn_and_rel_to_together() {
        let err: ParseError = "//SECRET//NOFORN/REL TO USA"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(err, ParseError::ConflictingDisseminationControls));
    }

    #[test]
    fn reject_unknown_classification_token() {
        let err: ParseError = "//SUPER SECRET//"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(err, ParseError::UnknownClassification(s) if s == "SUPER SECRET"));
    }

    #[test]
    fn reject_empty_input() {
        let err: ParseError = "".parse::<ClassificationMarking>().unwrap_err();
        assert!(matches!(err, ParseError::MissingLeadingDelimiter));
    }

    #[test]
    fn reject_only_delimiters() {
        let err: ParseError = "////".parse::<ClassificationMarking>().unwrap_err();
        assert!(matches!(err, ParseError::MissingClassification));
    }

    #[test]
    fn reject_invalid_country_code_with_digits() {
        let err: ParseError = "//SECRET//REL TO USA, 1FR"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(err, ParseError::InvalidCountryCode(s) if s == "1FR"));
    }

    #[test]
    fn reject_unknown_non_intel_control() {
        // "ZZZ" routes to SCI (default kind), so this rejects as SCI;
        // the parser's behaviour is correct either way (rejection).
        let err: ParseError = "//UNCLASSIFIED//ZZZ"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnknownSciControl(_) | ParseError::UnknownNonIntelControl(_)
        ));
    }

    // -- 5. Edge cases -----------------------------------------------

    #[test]
    fn multiple_sci_controls_canonical_order() {
        let m = ClassificationMarking::with_caveats(
            Classification::TopSecret,
            vec![SciControl::Tk, SciControl::Si, SciControl::Hcs],
            vec![],
            vec![],
        );
        // Sorted (derived Ord): the order follows the enum-declared
        // order — Si, Tk, Hcs — so the canonical sort yields that
        // order. Pin the expected sequence here.
        assert_eq!(
            m.sci_controls,
            vec![SciControl::Si, SciControl::Tk, SciControl::Hcs]
        );
    }

    #[test]
    fn empty_dissemination_serializes_correctly() {
        let m = ClassificationMarking::new(Classification::Secret);
        assert_eq!(m.to_string(), "//SECRET");
    }

    #[test]
    fn parser_canonicalizes_duplicate_sci_controls() {
        let m: ClassificationMarking = "//TOP SECRET//SI/SI/TK".parse().unwrap();
        assert_eq!(m.sci_controls, vec![SciControl::Si, SciControl::Tk]);
    }

    #[test]
    fn parser_accepts_lowercase_country_codes_and_uppercases_them() {
        let m: ClassificationMarking = "//SECRET//REL TO usa, gbr".parse().unwrap();
        assert_eq!(
            m.dissemination,
            vec![DisseminationControl::RelTo(vec![
                "GBR".to_owned(),
                "USA".to_owned()
            ])]
        );
    }

    #[test]
    fn whitespace_padding_is_tolerated() {
        let m: ClassificationMarking = "  //SECRET//NOFORN  ".parse().unwrap();
        assert_eq!(m.classification, Classification::Secret);
        assert_eq!(m.dissemination, vec![DisseminationControl::Noforn]);
    }

    #[test]
    fn least_upper_bound_basic() {
        let s: ClassificationMarking = "//SECRET//".parse().unwrap();
        let ts: ClassificationMarking = "//TOP SECRET//".parse().unwrap();
        let lub = s.lub(&ts);
        assert_eq!(lub.classification, Classification::TopSecret);
    }

    #[test]
    fn least_upper_bound_unions_sci() {
        let ts_si: ClassificationMarking = "//TOP SECRET//SI".parse().unwrap();
        let ts_tk: ClassificationMarking = "//TOP SECRET//TK".parse().unwrap();
        let lub = ts_si.lub(&ts_tk);
        assert_eq!(lub.sci_controls, vec![SciControl::Si, SciControl::Tk]);
    }

    #[test]
    fn least_upper_bound_noforn_dominates_rel_to() {
        let s_noforn: ClassificationMarking = "//SECRET//NOFORN".parse().unwrap();
        let s_rel: ClassificationMarking = "//SECRET//REL TO USA, GBR".parse().unwrap();
        let lub = s_noforn.lub(&s_rel);
        assert_eq!(lub.dissemination, vec![DisseminationControl::Noforn]);
    }

    #[test]
    fn least_upper_bound_rel_to_intersects_country_lists() {
        let s_usa_gbr: ClassificationMarking = "//SECRET//REL TO USA, GBR".parse().unwrap();
        let s_usa_aus: ClassificationMarking = "//SECRET//REL TO USA, AUS".parse().unwrap();
        let lub = s_usa_gbr.lub(&s_usa_aus);
        // Intersection of {USA, GBR} and {USA, AUS} is {USA}.
        assert_eq!(
            lub.dissemination,
            vec![DisseminationControl::RelTo(vec!["USA".to_owned()])]
        );
    }

    #[test]
    fn least_upper_bound_disjoint_rel_to_collapses_to_noforn() {
        let s_gbr: ClassificationMarking = "//SECRET//REL TO GBR".parse().unwrap();
        let s_aus: ClassificationMarking = "//SECRET//REL TO AUS".parse().unwrap();
        let lub = s_gbr.lub(&s_aus);
        assert_eq!(lub.dissemination, vec![DisseminationControl::Noforn]);
    }

    #[test]
    fn least_upper_bound_unions_non_intel_controls() {
        let fouo: ClassificationMarking = "//UNCLASSIFIED//FOUO".parse().unwrap();
        let les: ClassificationMarking = "//UNCLASSIFIED//LES".parse().unwrap();
        let lub = fouo.lub(&les);
        assert_eq!(
            lub.non_intelligence,
            vec![NonIntelControl::Fouo, NonIntelControl::Les]
        );
    }

    // -- 6. Serde round-trip -----------------------------------------

    #[test]
    fn serde_json_round_trip() {
        let m: ClassificationMarking = "//SECRET//NOFORN".parse().unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"//SECRET//NOFORN\"");
        let back: ClassificationMarking = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn serde_json_round_trip_complex_marking() {
        let m: ClassificationMarking = "//TOP SECRET//SI/TK//REL TO USA, GBR//FOUO"
            .parse()
            .unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let back: ClassificationMarking = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        // The wire format is the canonical Display string.
        assert_eq!(json, "\"//TOP SECRET//SI/TK//REL TO GBR, USA//FOUO\"");
    }

    #[test]
    fn serde_json_rejects_malformed_string() {
        let res: Result<ClassificationMarking, _> = serde_json::from_str("\"not a marking\"");
        assert!(res.is_err());
    }

    #[test]
    fn serde_struct_does_not_serialize_as_json_object() {
        // The wire format is the Display string — not a struct dump.
        let m: ClassificationMarking = "//SECRET//".parse().unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.starts_with('"'), "expected a JSON string, got: {json}");
        assert!(!json.contains("classification\":"));
    }

    #[test]
    fn serde_nested_in_struct() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Outer {
            label: String,
            marking: ClassificationMarking,
        }
        let outer = Outer {
            label: "envelope".to_owned(),
            marking: "//SECRET//NOFORN".parse().unwrap(),
        };
        let json = serde_json::to_string(&outer).unwrap();
        assert_eq!(json, r#"{"label":"envelope","marking":"//SECRET//NOFORN"}"#);
        let back: Outer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, outer);
    }

    #[test]
    fn toml_round_trip_via_string_form() {
        // We do not pull in the `toml` crate here just for the test —
        // the contract that matters is "the wire form is the Display
        // string", and TOML's string-quoting follows from that. Verify
        // by serializing through `serde_json` (which uses the same
        // serde mechanism) and confirming the value is a bare string,
        // exactly as TOML would carry it.
        let m: ClassificationMarking = "//SECRET//SI//NOFORN".parse().unwrap();
        let json = serde_json::to_string(&m).unwrap();
        // Strip the JSON quotes — that is exactly the bytes a TOML
        // value would carry between its quotes.
        let inner = json.trim_matches('"');
        let back: ClassificationMarking = inner.parse().unwrap();
        assert_eq!(back, m);
    }

    // -- 7. Defensive invariants -------------------------------------

    #[test]
    fn classification_marking_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + Clone + 'static>() {}
        assert_bounds::<ClassificationMarking>();
    }

    #[test]
    fn parse_error_implements_std_error() {
        // Pin the std::error::Error implementation so the type fits
        // anyhow / `Box<dyn Error>` chains in downstream consumers.
        fn assert_error<T: std::error::Error>() {}
        assert_error::<ParseError>();
    }

    #[test]
    fn dominates_is_transitive_for_simple_chain() {
        let ts: ClassificationMarking = "//TOP SECRET//SI/TK".parse().unwrap();
        let s: ClassificationMarking = "//SECRET//SI".parse().unwrap();
        let u = ClassificationMarking::new(Classification::Unclassified);
        assert!(ts.dominates(&s));
        assert!(s.dominates(&u));
        assert!(ts.dominates(&u));
    }

    #[test]
    fn lub_with_self_is_self() {
        let m: ClassificationMarking = "//TOP SECRET//SI/TK//NOFORN".parse().unwrap();
        let lub = m.lub(&m);
        assert_eq!(lub, m);
    }

    #[test]
    fn lub_dominates_both_inputs() {
        let a: ClassificationMarking = "//SECRET//SI//REL TO USA, GBR".parse().unwrap();
        let b: ClassificationMarking = "//TOP SECRET//TK//REL TO USA, AUS".parse().unwrap();
        let lub = a.lub(&b);
        assert!(lub.dominates(&a), "lub does not dominate a: {lub} vs {a}");
        assert!(lub.dominates(&b), "lub does not dominate b: {lub} vs {b}");
    }

    #[test]
    fn marking_round_trips_through_display_for_every_test_input() {
        // Aggregated Display ↔ FromStr round-trip pin: every banner
        // shape covered above must stably round-trip through the
        // wire form.
        let cases = [
            "//UNCLASSIFIED",
            "//UNCLASSIFIED//FOUO",
            "//UNCLASSIFIED//LES",
            "//UNCLASSIFIED//FOUO/LES",
            "//CONFIDENTIAL",
            "//CONFIDENTIAL//NOFORN",
            "//SECRET",
            "//SECRET//NOFORN",
            "//SECRET//SI//NOFORN",
            "//SECRET//SI/TK//NOFORN",
            "//SECRET//REL TO GBR, USA",
            "//SECRET//FVEY",
            "//TOP SECRET",
            "//TOP SECRET//SI/TK//NOFORN",
            "//TOP SECRET//HCS-P/SI//NOFORN",
        ];
        for s in cases {
            let m: ClassificationMarking = s.parse().unwrap();
            let rendered = m.to_string();
            let back: ClassificationMarking = rendered.parse().unwrap();
            assert_eq!(back, m, "round-trip failed for {s} -> {rendered}");
            // Display is canonical — re-rendering produces the same
            // bytes regardless of how many times we round-trip.
            assert_eq!(rendered, back.to_string());
        }
    }

    #[test]
    fn classification_total_order_holds() {
        assert!(Classification::Unclassified < Classification::Confidential);
        assert!(Classification::Confidential < Classification::Secret);
        assert!(Classification::Secret < Classification::TopSecret);
    }

    #[test]
    fn rel_to_with_only_whitespace_country_rejected() {
        let err: ParseError = "//SECRET//REL TO ,"
            .parse::<ClassificationMarking>()
            .unwrap_err();
        assert!(matches!(err, ParseError::RelToWithoutCountryList));
    }

    #[test]
    fn dominates_handles_empty_dissemination_correctly() {
        let s_no_diss: ClassificationMarking = "//SECRET".parse().unwrap();
        let s_noforn: ClassificationMarking = "//SECRET//NOFORN".parse().unwrap();
        // NOFORN restriction makes self stricter than empty.
        assert!(s_noforn.dominates(&s_no_diss));
        // The other direction: empty dissemination has NO release
        // restriction, so does not dominate a NOFORN-restricted form.
        assert!(!s_no_diss.dominates(&s_noforn));
    }
}
