// Copyright © 2026 Roberto Chiofalo.

//! Sharded decision cache.
//!
//! A small, fixed-capacity FIFO-eviction cache keyed on
//! `(SubjectHash, resource_hash, action, policy_epoch)`. The epoch is
//! bumped by the compiler every time a [`CompiledPolicy`] is built, so
//! swapping policies implicitly invalidates all prior cache entries
//! without any explicit `clear()` call.
//!
//! `SubjectHash` is a pair of 64-bit ahash outputs seeded with distinct
//! nothing-up-my-sleeve constants, giving 128 bits of collision
//! resistance against adversarial identities. A single 64-bit hash
//! would expose the cache to a birthday-bound attack at ~2^32 entries;
//! doubling the width makes collisions infeasible even when an
//! attacker controls CN/SAN contents through enrollment.
//!
//! The cache is sharded to reduce contention; each shard owns a
//! `parking_lot::Mutex`-guarded map plus a FIFO order queue used as a
//! cheap LRU approximation. On the hit path we clone a small
//! [`CachedOutcome`] (a `Decision` + optional rule id + usually-empty
//! `Vec<Obligation>`) and return it; no allocation or hashing of the
//! policy state is performed.
//!
//! FIFO eviction (rather than a full LRU) is an intentional trade-off:
//! decisions are typically hot for the lifetime of a session, a true
//! LRU would require touching the order queue on every hit (and taking
//! the lock for longer), and the win for a hit-rate-bound workload is
//! marginal. We can revisit if measurements ever show otherwise.
//!
//! [`CompiledPolicy`]: crate::compile::CompiledPolicy

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use ahash::AHashMap;
use parking_lot::Mutex;
use smol_str::SmolStr;

use crate::model::{Action, Decision, DecisionOutcome, Obligation, SubjectHash};

/// Composite key: 128-bit session-stable subject hash, per-call
/// resource hash, action, and the compiled policy epoch. Swapping the
/// policy bumps the epoch so stale entries are simply never looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DecisionKey {
    pub subject_hash: SubjectHash,
    pub resource_hash: u64,
    pub action: Action,
    pub policy_epoch: u32,
}

#[derive(Clone)]
struct CachedOutcome {
    decision: Decision,
    rule_id: Option<SmolStr>,
    obligations: Vec<Obligation>,
}

impl From<&DecisionOutcome> for CachedOutcome {
    fn from(o: &DecisionOutcome) -> Self {
        Self {
            decision: o.decision,
            rule_id: o.rule_id.clone(),
            obligations: o.obligations.clone(),
        }
    }
}

impl From<CachedOutcome> for DecisionOutcome {
    fn from(c: CachedOutcome) -> Self {
        DecisionOutcome {
            decision: c.decision,
            rule_id: c.rule_id,
            obligations: c.obligations,
        }
    }
}

struct Shard {
    map: AHashMap<DecisionKey, CachedOutcome>,
    order: VecDeque<DecisionKey>,
}

impl Shard {
    fn with_capacity(cap: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
        }
    }
}

/// Sharded, fixed-capacity decision cache.
pub(crate) struct DecisionCache {
    shards: Box<[Mutex<Shard>]>,
    shard_mask: usize,
    capacity_per_shard: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl std::fmt::Debug for DecisionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionCache")
            .field("shards", &self.shards.len())
            .field("capacity_per_shard", &self.capacity_per_shard)
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .finish()
    }
}

impl Clone for DecisionCache {
    fn clone(&self) -> Self {
        // Cloning an engine shouldn't carry over cached decisions — they
        // belong to the original engine's steady state. Create a fresh,
        // empty cache with the same sizing.
        Self::new(self.shards.len(), self.capacity_per_shard)
    }
}

impl Default for DecisionCache {
    fn default() -> Self {
        Self::new(16, 4096)
    }
}

impl DecisionCache {
    /// Build a cache with `shards` (rounded up to a power of two) and
    /// `capacity_per_shard` entries.
    pub(crate) fn new(shards: usize, capacity_per_shard: usize) -> Self {
        let shards = shards.max(1).next_power_of_two();
        let shard_mask = shards - 1;
        let shards_vec: Vec<Mutex<Shard>> = (0..shards)
            .map(|_| Mutex::new(Shard::with_capacity(capacity_per_shard)))
            .collect();
        Self {
            shards: shards_vec.into_boxed_slice(),
            shard_mask,
            capacity_per_shard,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    #[inline]
    fn shard_idx(&self, key: &DecisionKey) -> usize {
        // Mix both halves of the 128-bit subject hash plus the resource
        // hash into the shard index so that adversarial collisions on
        // any single component don't funnel traffic into one shard.
        let mixed = key.subject_hash.primary
            ^ key.subject_hash.secondary.rotate_left(17)
            ^ key.resource_hash.rotate_left(31);
        mixed as usize & self.shard_mask
    }

    /// Hit-path lookup. Returns a fresh [`DecisionOutcome`] on hit.
    pub(crate) fn get(&self, key: &DecisionKey) -> Option<DecisionOutcome> {
        let idx = self.shard_idx(key);
        let shard = &self.shards[idx];
        let guard = shard.lock();
        if let Some(cached) = guard.map.get(key) {
            let out: DecisionOutcome = cached.clone().into();
            drop(guard);
            let _ = self.hits.fetch_add(1, Ordering::Relaxed);
            Some(out)
        } else {
            drop(guard);
            let _ = self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert an outcome for `key`. Evicts the oldest entry in the
    /// target shard if it is already at capacity.
    pub(crate) fn insert(&self, key: DecisionKey, outcome: &DecisionOutcome) {
        let idx = self.shard_idx(&key);
        let mut guard = self.shards[idx].lock();
        if guard.map.contains_key(&key) {
            return;
        }
        if guard.map.len() >= self.capacity_per_shard
            && let Some(oldest) = guard.order.pop_front()
        {
            let _ = guard.map.remove(&oldest);
        }
        let _ = guard.map.insert(key, CachedOutcome::from(outcome));
        guard.order.push_back(key);
    }

    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub(crate) fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn key(s: u64, r: u64, epoch: u32) -> DecisionKey {
        DecisionKey {
            subject_hash: SubjectHash {
                primary: s,
                // Derive a deterministic secondary from the primary
                // so that two test keys with the same `s` still
                // compare equal in `DecisionKey::eq`.
                secondary: s.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            },
            resource_hash: r,
            action: Action::Send,
            policy_epoch: epoch,
        }
    }

    #[test]
    fn hit_miss_basic() {
        let cache = DecisionCache::new(4, 8);
        let k = key(1, 2, 7);
        assert!(cache.get(&k).is_none());
        cache.insert(k, &DecisionOutcome::allow());
        assert!(cache.get(&k).unwrap().is_allow());
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn epoch_change_invalidates() {
        let cache = DecisionCache::new(2, 8);
        let k1 = key(1, 2, 1);
        let k2 = key(1, 2, 2);
        cache.insert(k1, &DecisionOutcome::allow());
        assert!(cache.get(&k2).is_none());
    }

    #[test]
    fn fifo_evicts_oldest() {
        let cache = DecisionCache::new(1, 2);
        // Force all keys into the same shard.
        let a = key(0, 0, 1);
        let b = key(0, 1, 1);
        let c = key(0, 2, 1);
        cache.insert(a, &DecisionOutcome::allow());
        cache.insert(b, &DecisionOutcome::allow());
        cache.insert(c, &DecisionOutcome::allow());
        // `a` should have been evicted as the oldest.
        assert!(cache.get(&a).is_none());
        assert!(cache.get(&b).is_some());
        assert!(cache.get(&c).is_some());
    }

    #[test]
    fn new_rounds_shard_count_up_to_next_power_of_two() {
        // Non-power-of-two inputs round up; exact powers stay; `0` is
        // clamped to at least one shard by `.max(1)`. This is load-bearing:
        // `shard_mask = shards - 1` only behaves as a mask when `shards`
        // is a power of two — break the rounding and `shard_idx` silently
        // stops covering the full shard array.
        for (input, expected) in [(3, 4), (5, 8), (7, 8), (9, 16), (16, 16), (1, 1), (0, 1)] {
            let cache = DecisionCache::new(input, 4);
            assert_eq!(
                cache.shards.len(),
                expected,
                "new({input}, _) should produce {expected} shards"
            );
            assert_eq!(
                cache.shard_mask,
                expected - 1,
                "shard_mask must stay (shards - 1) so `idx & mask` indexes every shard"
            );
        }
    }

    #[test]
    fn default_cache_is_sized_16_by_4096_with_zero_counters() {
        // Pins `DecisionCache::default()` sizing — the sharding factor
        // and per-shard capacity are not just cosmetic; they set the
        // memory ceiling and contention floor for every engine that
        // does not explicitly size its cache.
        let cache = DecisionCache::default();
        assert_eq!(cache.shards.len(), 16);
        assert_eq!(cache.capacity_per_shard, 4096);
        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);
    }

    #[test]
    fn debug_output_exposes_shape_and_live_counters() {
        // Custom `Debug` impl must remain observable: it feeds metrics
        // dumps, diagnostic logs, and triage output. Pin the struct
        // name + four field labels and live counter values so that
        // changing the struct shape forces a deliberate update here.
        let cache = DecisionCache::new(4, 8);
        let k = key(11, 22, 33);
        let _ = cache.get(&k); // miss += 1
        cache.insert(k, &DecisionOutcome::allow());
        let _ = cache.get(&k); // hit += 1
        let s = format!("{cache:?}");
        assert!(
            s.starts_with("DecisionCache"),
            "Debug must begin with struct name: {s}"
        );
        assert!(s.contains("shards: 4"), "Debug missing shard count: {s}");
        assert!(
            s.contains("capacity_per_shard: 8"),
            "Debug missing per-shard cap: {s}"
        );
        assert!(s.contains("hits: 1"), "Debug missing live hit counter: {s}");
        assert!(
            s.contains("misses: 1"),
            "Debug missing live miss counter: {s}"
        );
    }

    #[test]
    fn clone_returns_empty_cache_with_same_sizing_and_zero_counters() {
        // The `Clone` impl intentionally does NOT carry over cached
        // entries or counters — cloning an engine produces a fresh
        // steady state. Pin both halves of that contract: entries are
        // dropped, counters reset, sizing preserved.
        let original = DecisionCache::new(4, 8);
        let k = key(1, 2, 3);
        let _ = original.get(&k); // source miss+=1
        original.insert(k, &DecisionOutcome::allow());
        let _ = original.get(&k); // source hit+=1
        assert_eq!(original.hits(), 1);
        assert_eq!(original.misses(), 1);

        let cloned = original.clone();
        assert!(
            cloned.get(&k).is_none(),
            "cloned cache must not carry entries from source"
        );
        // The lookup above on the clone bumped its miss counter to 1;
        // the hit counter must still be 0 because the entry was gone.
        assert_eq!(cloned.hits(), 0);
        assert_eq!(cloned.misses(), 1);
        assert_eq!(cloned.shards.len(), original.shards.len());
        assert_eq!(cloned.capacity_per_shard, original.capacity_per_shard);
    }

    #[test]
    fn insert_dedup_does_not_overwrite_or_bump_fifo_position() {
        // `insert` early-returns on a duplicate key — it neither
        // replaces the cached outcome nor touches the FIFO queue.
        // Both properties matter: overwriting would let a later caller
        // silently flip a rule's cached decision; bumping FIFO would
        // turn a dedup into a "touch" and degrade LRU-ish approximation
        // into something stranger.
        let cache = DecisionCache::new(1, 2);
        let a = key(0, 0, 1);
        let b = key(0, 1, 1);
        let c = key(0, 2, 1);
        cache.insert(a, &DecisionOutcome::allow());
        cache.insert(b, &DecisionOutcome::allow());

        // Dedup insert with a DIFFERENT outcome — must be a no-op.
        cache.insert(a, &DecisionOutcome::deny());
        assert!(
            cache.get(&a).expect("a still cached").is_allow(),
            "dedup insert must not overwrite the existing outcome"
        );

        // Now insert `c` — if the dedup had refreshed `a`'s FIFO
        // position, `b` would be evicted. Contract says `a` is oldest
        // and must be the one evicted.
        cache.insert(c, &DecisionOutcome::allow());
        assert!(
            cache.get(&a).is_none(),
            "a must be evicted as oldest — dedup insert did not refresh FIFO"
        );
        assert!(cache.get(&b).is_some(), "b must survive");
        assert!(cache.get(&c).is_some(), "c must be present");
    }

    #[test]
    fn cached_outcome_round_trip_preserves_rule_id_and_obligations() {
        // `CachedOutcome` is a hidden wire type between `insert` and
        // `get`. Every field of `DecisionOutcome` must survive the
        // round-trip — silent drops of `rule_id` or `obligations`
        // would change caller-visible behavior (masking, audit
        // extension, policy attribution).
        let cache = DecisionCache::new(1, 4);
        let k = key(7, 42, 1);
        let outcome = DecisionOutcome {
            decision: Decision::Allow,
            rule_id: Some(smol_str::SmolStr::new_inline("rule-42")),
            obligations: vec![Obligation::MaskPoint, Obligation::AuditExtended],
        };
        cache.insert(k, &outcome);
        let got = cache.get(&k).expect("should hit");
        assert!(matches!(got.decision, Decision::Allow));
        assert_eq!(got.rule_id.as_deref(), Some("rule-42"));
        assert_eq!(
            got.obligations,
            vec![Obligation::MaskPoint, Obligation::AuditExtended],
            "all obligations in original order must survive the round-trip"
        );
    }

    #[test]
    fn decision_key_distinct_secondary_hashes_do_not_collide() {
        // `SubjectHash` carries 128 bits specifically so that an
        // adversary who matches the primary cannot collide with a
        // privileged principal's cache entry. The Eq/Hash derive on
        // `DecisionKey` must consume both halves — drop `secondary`
        // from the derive (or the struct) and this test flips.
        let k1 = DecisionKey {
            subject_hash: SubjectHash {
                primary: 1,
                secondary: 2,
            },
            resource_hash: 3,
            action: Action::Send,
            policy_epoch: 4,
        };
        let k2 = DecisionKey {
            subject_hash: SubjectHash {
                primary: 1,
                secondary: 99,
            },
            resource_hash: 3,
            action: Action::Send,
            policy_epoch: 4,
        };
        assert_ne!(k1, k2, "distinct `secondary` must produce distinct keys");

        let cache = DecisionCache::new(1, 8);
        cache.insert(k1, &DecisionOutcome::allow());
        assert!(
            cache.get(&k2).is_none(),
            "cache lookup must differentiate on secondary hash"
        );
    }

    #[test]
    fn decision_key_action_and_resource_are_part_of_identity() {
        // Same subject, different action-or-resource = different key.
        // Folding either out of the key would let a Send decision
        // satisfy a Receive check (or vice-versa) — authz escape hatch.
        let base = key(1, 2, 3);
        let cache = DecisionCache::new(1, 8);
        cache.insert(base, &DecisionOutcome::allow());

        let different_action = DecisionKey {
            action: Action::Receive,
            ..base
        };
        assert!(
            cache.get(&different_action).is_none(),
            "distinct action must not hit"
        );

        let different_resource = DecisionKey {
            resource_hash: 999,
            ..base
        };
        assert!(
            cache.get(&different_resource).is_none(),
            "distinct resource must not hit"
        );
    }

    #[test]
    fn hits_and_misses_counters_track_independently() {
        // The two counters are read separately by metrics — a regression
        // that incremented `misses` on hit (or vice-versa) would only
        // show up as nonsense ratios in prod. Pin the independence.
        let cache = DecisionCache::new(2, 4);
        let k = key(1, 1, 1);
        assert!(cache.get(&k).is_none()); // miss 1
        assert!(cache.get(&k).is_none()); // miss 2
        cache.insert(k, &DecisionOutcome::allow());
        assert!(cache.get(&k).is_some()); // hit 1
        assert!(cache.get(&k).is_some()); // hit 2
        assert!(cache.get(&k).is_some()); // hit 3
        assert_eq!(cache.hits(), 3);
        assert_eq!(cache.misses(), 2);
    }

    #[test]
    fn shard_formula_consumes_secondary_hash_for_adversarial_resistance() {
        // Module contract: `shard_idx` mixes both halves of the subject
        // hash plus the resource hash, so an attacker pinning
        // `primary == 0` and `resource_hash == 0` cannot funnel all
        // keys into shard 0 by controlling `secondary` alone. If the
        // formula ever dropped `secondary`, every probe below would
        // land on shard 0 and this assertion would trip.
        //
        // `secondary` values chosen so that `rotate_left(17)` places a
        // non-zero low nibble — different values reach different shards
        // under a 16-shard mask.
        let cache = DecisionCache::new(16, 8);
        let mut shards_hit = std::collections::HashSet::new();
        for sec in [1u64 << 47, 1u64 << 48, 1u64 << 49, 1u64 << 50] {
            let k = DecisionKey {
                subject_hash: SubjectHash {
                    primary: 0,
                    secondary: sec,
                },
                resource_hash: 0,
                action: Action::Send,
                policy_epoch: 0,
            };
            let _ = shards_hit.insert(cache.shard_idx(&k));
        }
        assert!(
            shards_hit.len() > 1,
            "shard_idx dropped `secondary`: all adversary-crafted keys funnelled to {shards_hit:?}"
        );
    }
}
