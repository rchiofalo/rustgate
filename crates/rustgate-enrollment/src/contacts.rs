// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Contacts provider for Marti API compatibility.
//!
//! Defines the callback type and data structures used by the
//! `/Marti/api/contacts/all` and `/Marti/api/clientEndPoints` endpoints.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// Information about a connected client, returned by the contacts API.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct ContactInfo {
    /// Client UID (certificate CN).
    pub uid: String,
    /// Client callsign (same as CN for mTLS clients).
    pub callsign: String,
    /// Group memberships.
    pub groups: Vec<String>,
    /// Whether the client is currently connected.
    #[serde(rename = "lastStatus")]
    pub last_status: String,
}

/// Async callback that returns a snapshot of connected clients.
///
/// The enrollment server calls this when it receives a contacts or
/// clientEndPoints request. The callback is provided by the server
/// binary and typically queries the Router's session state.
pub type ContactsProvider =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Vec<ContactInfo>> + Send>> + Send + Sync>;

struct CachedEntry {
    contacts: Vec<ContactInfo>,
    fetched_at: Instant,
}

/// Wraps a [`ContactsProvider`] with a time-based cache.
///
/// Serves the cached result when the TTL has not expired, reducing
/// load on the router's session state. Thread-safe via `RwLock`
/// with a read-lock fast path and write-lock double-check pattern.
pub struct CachedContactsProvider {
    inner: ContactsProvider,
    cache: RwLock<Option<CachedEntry>>,
    ttl: Duration,
}

impl std::fmt::Debug for CachedContactsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedContactsProvider")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl CachedContactsProvider {
    /// Create a new caching wrapper with a custom TTL.
    pub fn new(inner: ContactsProvider, ttl: Duration) -> Self {
        Self {
            inner,
            cache: RwLock::new(None),
            ttl,
        }
    }

    /// Retrieve contacts, serving from cache when fresh.
    pub async fn get(&self) -> Vec<ContactInfo> {
        // Fast path: read lock
        {
            let guard = self.cache.read().await;
            if let Some(entry) = guard.as_ref()
                && entry.fetched_at.elapsed() < self.ttl
            {
                return entry.contacts.clone();
            }
        }

        // Slow path: write lock with double-check
        let mut guard = self.cache.write().await;
        if let Some(entry) = guard.as_ref()
            && entry.fetched_at.elapsed() < self.ttl
        {
            return entry.contacts.clone();
        }

        let contacts = (self.inner)().await;
        *guard = Some(CachedEntry {
            contacts: contacts.clone(),
            fetched_at: Instant::now(),
        });
        contacts
    }
}

/// Wrap a [`ContactsProvider`] with a TTL cache, returning a new [`ContactsProvider`].
///
/// The returned provider calls the inner provider at most once per `ttl` interval.
pub fn cached_contacts_provider(inner: ContactsProvider, ttl: Duration) -> ContactsProvider {
    let cached = Arc::new(CachedContactsProvider::new(inner, ttl));
    Arc::new(move || {
        let cached = Arc::clone(&cached);
        Box::pin(async move { cached.get().await })
    })
}

#[cfg(test)]
#[allow(unused_results)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[tokio::test]
    async fn cache_returns_same_result_within_ttl() {
        let call_count = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&call_count);
        let inner: ContactsProvider = Arc::new(move || {
            let count = Arc::clone(&count);
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                vec![ContactInfo {
                    uid: "alice".into(),
                    callsign: "alice".into(),
                    groups: vec![],
                    last_status: "Connected".into(),
                }]
            })
        });

        let cached = CachedContactsProvider::new(inner, Duration::from_secs(60));
        let first = cached.get().await;
        let second = cached.get().await;

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_refreshes_after_ttl() {
        let call_count = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&call_count);
        let inner: ContactsProvider = Arc::new(move || {
            let count = Arc::clone(&count);
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                vec![]
            })
        });

        let cached = CachedContactsProvider::new(inner, Duration::from_millis(50));
        let _ = cached.get().await;
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = cached.get().await;
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_returns_updated_data_after_ttl() {
        let call_count = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&call_count);
        let inner: ContactsProvider = Arc::new(move || {
            let count = Arc::clone(&count);
            Box::pin(async move {
                let n = count.fetch_add(1, Ordering::SeqCst);
                (0..=n)
                    .map(|i| ContactInfo {
                        uid: format!("user-{i}"),
                        callsign: format!("user-{i}"),
                        groups: vec![],
                        last_status: "Connected".into(),
                    })
                    .collect()
            })
        });

        let cached = CachedContactsProvider::new(inner, Duration::from_millis(50));
        let first = cached.get().await;
        assert_eq!(first.len(), 1);

        tokio::time::sleep(Duration::from_millis(100)).await;
        let second = cached.get().await;
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn contact_info_serializes_with_marti_compatible_last_status_field() {
        // `#[serde(rename = "lastStatus")]` is load-bearing for Marti
        // API compatibility — the iTAK and ATAK clients expect the
        // camelCase JSON key. A regression that dropped the rename
        // would still compile and still round-trip between rustgate
        // binaries, but break wire-compat with every Marti consumer.
        let info = ContactInfo {
            uid: "alpha-7".into(),
            callsign: "alpha-7".into(),
            groups: vec!["red".into(), "blue".into()],
            last_status: "Connected".into(),
        };
        let json = serde_json::to_value(&info).expect("serialize ContactInfo");
        let obj = json.as_object().expect("top-level JSON object");
        assert!(
            obj.contains_key("lastStatus"),
            "ContactInfo must serialize last_status as lastStatus (Marti-compatible), got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        assert!(
            !obj.contains_key("last_status"),
            "snake_case last_status must not appear — the rename would be silently broken"
        );
        assert_eq!(obj["uid"], "alpha-7");
        assert_eq!(obj["callsign"], "alpha-7");
        assert_eq!(obj["lastStatus"], "Connected");
        assert_eq!(
            obj["groups"].as_array().map(Vec::len),
            Some(2),
            "groups field should round-trip as a JSON array"
        );
    }

    #[test]
    fn contact_info_clone_and_partial_eq_round_trip() {
        // `#[derive(Clone, PartialEq)]` on ContactInfo is relied on by
        // the cache (`contacts.clone()` on every cache hit) and by
        // tests that compare snapshots — pin the derives so a refactor
        // that narrowed them fails here rather than at transitive
        // callers.
        let info = ContactInfo {
            uid: "bravo-3".into(),
            callsign: "bravo-3".into(),
            groups: vec!["squad-1".into()],
            last_status: "Connected".into(),
        };
        let cloned = info.clone();
        assert_eq!(info, cloned, "Clone should preserve all fields");

        let mut altered = cloned.clone();
        altered.last_status = "Disconnected".into();
        assert_ne!(info, altered, "PartialEq must distinguish last_status");
    }

    #[tokio::test]
    async fn cached_contacts_provider_debug_shows_ttl_but_not_inner() {
        // The custom Debug impl uses `finish_non_exhaustive()` so the
        // inner callback pointer never leaks into `tracing::debug!(?c, …)`
        // lines (closures are not Debug, and printing their address
        // would be low-value noise). Pin the contract: ttl is visible,
        // field count is bounded by `..` marker.
        let inner: ContactsProvider = Arc::new(|| Box::pin(async { Vec::new() }));
        let cached = CachedContactsProvider::new(Arc::clone(&inner), Duration::from_secs(37));
        let rendered = format!("{cached:?}");
        assert!(
            rendered.contains("CachedContactsProvider"),
            "Debug should mention the type name, got: {rendered}"
        );
        assert!(
            rendered.contains("ttl"),
            "Debug should expose the ttl field, got: {rendered}"
        );
        assert!(
            rendered.contains(".."),
            "Debug should use finish_non_exhaustive to avoid leaking the callback, got: {rendered}"
        );
        // The inner callback and the cache entry must never appear.
        assert!(
            !rendered.contains("inner"),
            "Debug should not surface the inner field, got: {rendered}"
        );
        assert!(
            !rendered.contains("cache"),
            "Debug should not surface the cache field, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn cached_contacts_provider_factory_function_wraps_with_ttl() {
        // The free function `cached_contacts_provider` is the shape
        // the server binary actually uses — it returns a
        // `ContactsProvider` rather than a concrete struct so callers
        // can swap cached/uncached without changing field types. The
        // existing suite only exercises `CachedContactsProvider::new`
        // directly, so a regression in the wrapper closure (e.g.
        // accidentally skipping the cache and always calling the
        // inner) would slip through.
        let call_count = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&call_count);
        let inner: ContactsProvider = Arc::new(move || {
            let count = Arc::clone(&count);
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                vec![ContactInfo {
                    uid: "charlie".into(),
                    callsign: "charlie".into(),
                    groups: vec![],
                    last_status: "Connected".into(),
                }]
            })
        });

        let wrapped = cached_contacts_provider(inner, Duration::from_secs(60));
        let first = wrapped().await;
        let second = wrapped().await;

        assert_eq!(first, second, "wrapper should return cached snapshot");
        assert_eq!(first.len(), 1);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "wrapper closure must route through the cache — inner called only once within ttl"
        );
    }

    #[tokio::test]
    async fn zero_ttl_always_invokes_inner_provider() {
        // Edge case: ttl = 0 means `elapsed() < ttl` is never true
        // (elapsed is always >= 0, and `0 < 0` is false). Both the
        // read-lock fast path and the write-lock double-check must
        // therefore fall through to inner on every call. Operators who
        // want "cache disabled" semantics rely on this — a regression
        // that treated 0 as a sentinel for "no expiry" would silently
        // pin the first snapshot forever.
        let call_count = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&call_count);
        let inner: ContactsProvider = Arc::new(move || {
            let count = Arc::clone(&count);
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                Vec::new()
            })
        });

        let cached = CachedContactsProvider::new(inner, Duration::ZERO);
        let _ = cached.get().await;
        let _ = cached.get().await;
        let _ = cached.get().await;
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "ttl=0 must disable caching — every get() invokes inner"
        );
    }

    #[tokio::test]
    async fn concurrent_gets_on_fresh_cache_invoke_inner_exactly_once() {
        // Two concurrent get() calls on an empty cache both pass the
        // read-lock fast path (cache is None), then race for the
        // write lock. The winner populates the cache; the loser takes
        // the write lock, hits the double-check arm, and returns the
        // freshly-stored snapshot. Inner must therefore be called
        // exactly once — the double-check pattern is the load-bearing
        // contract the fast path depends on to avoid a thundering-herd
        // fan-out into the router's session state under a spike of
        // concurrent Marti requests.
        let call_count = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&call_count);
        let inner: ContactsProvider = Arc::new(move || {
            let count = Arc::clone(&count);
            Box::pin(async move {
                // Sleep briefly so the second caller catches the
                // double-check branch rather than both returning
                // before either reaches the write lock.
                count.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                vec![ContactInfo {
                    uid: "delta".into(),
                    callsign: "delta".into(),
                    groups: vec![],
                    last_status: "Connected".into(),
                }]
            })
        });

        let cached = Arc::new(CachedContactsProvider::new(inner, Duration::from_secs(60)));
        let a = Arc::clone(&cached);
        let b = Arc::clone(&cached);
        let (first, second) = tokio::join!(a.get(), b.get());

        assert_eq!(
            first, second,
            "both concurrent callers should see the same snapshot"
        );
        assert_eq!(first.len(), 1);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "double-check pattern must coalesce concurrent misses into a single inner call"
        );
    }
}
