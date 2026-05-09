// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the obligation application pipeline.
//!
//! `rustgate_router::obligations::apply_obligations` takes an
//! authz decision's obligation list and mutates the outbound
//! [`RoutableMessage`] in place: [`Obligation::MaskPoint`] zeros the
//! CoT coordinates via `strip_coordinates` (with fail-closed recovery
//! for XML-intent malformed input), [`Obligation::MaskPayload`]
//! replaces the body entirely, and the audit-only variants
//! (`TagClassified`, `AuditExtended`) are no-ops at the data plane.
//!
//! The fuzzer exercises:
//!
//! - arbitrary [`RoutableMessage`] shapes — the `Arbitrary` impl in
//!   `rustgate-core` (behind the `fuzz` feature) generates identities
//!   with random CNs, all four `Destination` variants, every
//!   `MessageType`, and payloads up to 1 KiB of random bytes.
//! - arbitrary obligation lists of length 0..=8 — mapping fuzz bytes
//!   onto the four concrete `Obligation` variants. Empty and
//!   repeated-same-variant lists are both in scope.
//! - the `MaskPoint` → CoT parse path in aggregate: the XML-intent
//!   fast-path is triggered by any payload starting with `<` after
//!   whitespace, which the `Arbitrary` impl will produce occasionally.
//!
//! This target complements `cot_mask_strip_coordinates.rs`: that one
//! exercises the masker on raw bytes, this one drives it through the
//! same dispatch wrapper the router uses on every per-recipient copy.
//!
//! A safety invariant this target enforces via assertion: after
//! `apply_obligations` runs with `MaskPayload` anywhere in the list,
//! the payload **must** be empty. A regression that skipped
//! `MaskPayload` because a preceding obligation succeeded first would
//! leak the original body to a recipient whose decision carried the
//! strongest masking flag.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rustgate_authz::Obligation;
use rustgate_core::message::RoutableMessage;
use rustgate_router::obligations::{UnknownObligationPolicy, apply_obligations};

/// Fuzz input envelope: a `RoutableMessage` plus raw bytes that are
/// mapped to an obligation list. Using `Vec<u8>` (rather than
/// `Vec<ObligationIndex>`) keeps the `arbitrary` surface stable against
/// future `Obligation` variant additions — adding a variant just widens
/// the modulo. Each byte maps to one of the four concrete variants.
#[derive(Debug, Arbitrary)]
struct Input {
    msg: RoutableMessage,
    obligation_bytes: Vec<u8>,
}

fn map_obligation(byte: u8) -> Obligation {
    // `Obligation` is `#[non_exhaustive]` — stale-transport vs.
    // new-policy skew exercises the `other => …` arm in
    // `apply_obligations`, but we cannot *construct* a future variant
    // from this side of the boundary. Four branches cover every variant
    // currently reachable by normal policy evaluation.
    match byte % 4 {
        0 => Obligation::MaskPoint,
        1 => Obligation::MaskPayload,
        2 => Obligation::TagClassified,
        _ => Obligation::AuditExtended,
    }
}

fuzz_target!(|input: Input| {
    let Input {
        mut msg,
        obligation_bytes,
    } = input;

    // Cap the obligation list at 8 entries. Real policies emit at most
    // a handful; an unbounded list would burn fuzzer cycles on
    // `apply_obligations`'s loop without exercising new code paths.
    let obligations: Vec<Obligation> = obligation_bytes
        .iter()
        .take(8)
        .map(|b| map_obligation(*b))
        .collect();

    let has_mask_payload = obligations.contains(&Obligation::MaskPayload);

    // The fuzzer can only map onto the four known variants (see
    // `map_obligation`), so the return value is always `Ok(())` —
    // but the policy argument is threaded through to exercise the
    // issue-#728 signature and to guard against future regressions
    // where a known variant accidentally returns Err.
    let result = apply_obligations(
        &mut msg,
        &obligations,
        UnknownObligationPolicy::FailClosed,
    );
    assert!(
        result.is_ok(),
        "apply_obligations returned Err for a known-variant-only list: {result:?}"
    );

    // Invariant: `MaskPayload` is the strongest masking obligation.
    // If it appears anywhere in the list, the delivered payload must
    // be empty regardless of ordering with weaker obligations. A
    // regression that short-circuited on `MaskPoint` (or skipped
    // `MaskPayload` after `MaskPoint` succeeded) would leak the body.
    if has_mask_payload {
        assert!(
            msg.payload.is_empty(),
            "MaskPayload left non-empty payload of {} bytes",
            msg.payload.len()
        );
    }
});
