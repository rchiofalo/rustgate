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
}
