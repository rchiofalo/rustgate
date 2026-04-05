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

/// Default time-to-live for cached contacts data.
const DEFAULT_CONTACTS_TTL: Duration = Duration::from_secs(30);

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
            if let Some(entry) = guard.as_ref() {
                if entry.fetched_at.elapsed() < self.ttl {
                    return entry.contacts.clone();
                }
            }
        }

        // Slow path: write lock with double-check
        let mut guard = self.cache.write().await;
        if let Some(entry) = guard.as_ref() {
            if entry.fetched_at.elapsed() < self.ttl {
                return entry.contacts.clone();
            }
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
}
