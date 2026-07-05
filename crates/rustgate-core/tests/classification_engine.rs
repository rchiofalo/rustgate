// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Regression pins for the first-class CAPCO classification marking
//! engine as a *public library surface* — the deliverable of the
//! roadmap item that asked for a marking engine usable beyond the
//! cross-domain guard (grammar, canonical banner form, and the
//! dominance/LUB lattice), shipped under the classification-marking
//! umbrella.
//!
//! Unlike the crate's inline unit tests, these exercise only the
//! public `rustgate_core::classification` API through a downstream
//! `use`, mirroring how `rustgate-authz`, `rustgate-router`, and the
//! server binary consume it. A refactor that made the parser, the
//! `Display` banner, or the lattice operators non-public — or that
//! regressed fail-closed parsing — would fail to compile or fail these
//! assertions.

use rustgate_core::classification::{Classification, ClassificationMarking};

/// The engine parses a full CAPCO banner (level + SCI + dissemination)
/// from a plain string and round-trips it back to the canonical banner
/// form. This is the core "usable as a library" contract: no guard, no
/// server, just the public type.
#[test]
fn public_capco_parse_and_banner_round_trip() {
    let banner = "//TOP SECRET//SI/TK//NOFORN";
    let marking: ClassificationMarking = banner.parse().unwrap();

    assert_eq!(marking.classification, Classification::TopSecret);
    assert_eq!(
        marking.to_string(),
        banner,
        "Display must reproduce the canonical banner it parsed"
    );
}

/// The lattice `dominates()` relation is reachable and correct through
/// the public surface: a higher, caveated marking dominates a lower
/// bare one, and the relation is strict (the lower does not dominate the
/// higher). This is what downstream Send-PEP enforcement leans on.
#[test]
fn public_dominance_is_strict_and_directional() {
    let high: ClassificationMarking = "//TOP SECRET//NOFORN".parse().unwrap();
    let low = ClassificationMarking::new(Classification::Secret);

    assert!(
        high.dominates(&low),
        "TOP SECRET//NOFORN must dominate bare SECRET"
    );
    assert!(
        !low.dominates(&high),
        "bare SECRET must not dominate TOP SECRET//NOFORN"
    );
    assert!(high.dominates(&high), "domination must be reflexive");
}

/// The least-upper-bound combinator produces a marking that dominates
/// both inputs — the invariant a cross-domain merge relies on. Pinned
/// via the public `lub()` so a regression that returned either operand
/// unchanged (instead of the join) would be caught outside the crate.
#[test]
fn public_lub_dominates_both_operands() {
    let a: ClassificationMarking = "//SECRET//SI".parse().unwrap();
    let b: ClassificationMarking = "//CONFIDENTIAL//NOFORN".parse().unwrap();

    let joined = a.lub(&b);

    assert!(joined.dominates(&a), "LUB must dominate its first operand");
    assert!(joined.dominates(&b), "LUB must dominate its second operand");
    assert_eq!(
        joined.classification,
        Classification::Secret,
        "LUB level is the max of the two operands"
    );
}

/// Parsing is fail-closed: a syntactically invalid marking is rejected
/// with an error rather than silently coerced to a permissive default.
/// This is the safety property that lets callers treat a parse failure
/// as a deny.
#[test]
fn public_parse_is_fail_closed_on_garbage() {
    let result: Result<ClassificationMarking, _> = "not a marking".parse();
    assert!(
        result.is_err(),
        "malformed banner must be rejected, not defaulted to a permissive marking"
    );
}
