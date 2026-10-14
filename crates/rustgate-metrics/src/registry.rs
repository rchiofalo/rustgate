// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Workspace-wide metrics-init aggregator.
//!
//! Each domain crate exposes a `pub fn init() -> prometheus::Result<()>`
//! that builds its [`OnceLock`]-backed metrics and registers them with
//! the Prometheus default registry. The server binary wires those
//! together — historically as a hardcoded sequence of calls. This
//! aggregator collects the closures into one ordered list so the
//! binary can express the bring-up sequence as data
//! (`registry.register(...).register(...).init_all()?`) instead of a
//! hand-written ladder of statements.
//!
//! The aggregator is intentionally minimal: it does not own metrics, it
//! does not interact with the Prometheus registry directly, and it does
//! not enforce any ordering beyond the order of insertion. Callers that
//! need ordering guarantees express them at the call site by the order
//! they call [`MetricsRegistry::register`]. Callers that don't care
//! about ordering — i.e. every initialiser is independent — get the
//! same behaviour as the old hardcoded sequence.
//!
//! [`OnceLock`]: std::sync::OnceLock

/// Boxed initialiser closure stored by [`MetricsRegistry`].
type InitFn = Box<dyn Fn() -> prometheus::Result<()> + Send + Sync>;

/// Aggregates `init()` callbacks from every domain crate so the server
/// binary wires the entire workspace with one call.
///
/// The aggregator preserves insertion order. The first error
/// short-circuits — subsequent initialisers are not invoked — and the
/// error is returned to the caller so the binary can fail fast at
/// startup. This matches the historical behaviour of the hardcoded
/// `init_a()?; init_b()?; init_c()?;` sequence.
///
/// # Example
///
/// ```ignore
/// use rustgate_metrics::MetricsRegistry;
///
/// let mut registry = MetricsRegistry::default();
/// registry.register(rustgate_server::metrics::init);
/// registry.register(rustgate_federation::metrics::init);
/// registry.register(rustgate_http::metrics::init);
/// registry.init_all()?;
/// ```
#[derive(Default)]
pub struct MetricsRegistry {
    initializers: Vec<InitFn>,
}

impl MetricsRegistry {
    /// Append a domain crate's `init()` to the registration sequence.
    ///
    /// Returns `&mut self` so callers can chain `register(...)` calls
    /// with a fluent builder style.
    pub fn register<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn() -> prometheus::Result<()> + Send + Sync + 'static,
    {
        self.initializers.push(Box::new(f));
        self
    }

    /// Run every registered initialiser in insertion order, stopping
    /// at the first error.
    ///
    /// Returns `Ok(())` when every initialiser succeeded. Returns the
    /// first `Err` encountered, leaving any later initialisers
    /// unexecuted. This mirrors the historical hardcoded sequence:
    /// failure-fast at startup, never partial registration.
    pub fn init_all(&self) -> prometheus::Result<()> {
        for f in &self.initializers {
            f()?;
        }
        Ok(())
    }

    /// Number of initialisers currently registered. Used by tests to
    /// assert the registry was populated as expected.
    #[must_use]
    pub fn len(&self) -> usize {
        self.initializers.len()
    }

    /// Returns `true` when no initialisers have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.initializers.is_empty()
    }
}

impl std::fmt::Debug for MetricsRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsRegistry")
            .field("initializers", &self.len())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn empty_registry_init_all_is_ok() {
        let registry = MetricsRegistry::default();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        registry.init_all().expect("empty init must succeed");
    }

    #[test]
    fn metrics_registry_init_all_runs_initialisers_in_insertion_order() {
        let log = Arc::new(parking_lot_replacement::Mutex::new(Vec::<u8>::new()));

        let l1 = log.clone();
        let l2 = log.clone();
        let l3 = log.clone();

        let mut registry = MetricsRegistry::default();
        let _ = registry
            .register(move || {
                l1.lock().push(1);
                Ok(())
            })
            .register(move || {
                l2.lock().push(2);
                Ok(())
            })
            .register(move || {
                l3.lock().push(3);
                Ok(())
            });

        assert_eq!(registry.len(), 3);
        registry.init_all().expect("init must succeed");
        assert_eq!(*log.lock(), vec![1, 2, 3]);
    }

    #[test]
    fn metrics_registry_init_all_propagates_first_error_and_short_circuits() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = counter.clone();
        let c2 = counter.clone();
        let c3 = counter.clone();

        let mut registry = MetricsRegistry::default();
        let _ = registry
            .register(move || {
                let _ = c1.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .register(move || {
                let _ = c2.fetch_add(1, Ordering::SeqCst);
                Err(prometheus::Error::Msg("boom".to_string()))
            })
            .register(move || {
                // Must not run — short-circuit on the previous error.
                let _ = c3.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });

        let err = registry.init_all().expect_err("must propagate error");
        match err {
            prometheus::Error::Msg(s) => assert_eq!(s, "boom"),
            other => panic!("unexpected error variant: {other:?}"),
        }
        // Only the first two initialisers ran. The third was skipped
        // because the second returned `Err`.
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn metrics_registry_debug_reports_initialiser_count() {
        let mut registry = MetricsRegistry::default();
        let _ = registry.register(|| Ok(()));
        let _ = registry.register(|| Ok(()));
        let debug = format!("{registry:?}");
        assert!(
            debug.contains("initializers: 2"),
            "debug output must report count, got: {debug}",
        );
    }

    /// Tiny in-test mutex shim. The crate intentionally avoids
    /// pulling in `parking_lot` (it would be the only non-prometheus
    /// runtime dep) — this minimal `Mutex<T>` is enough for the
    /// insertion-order test above and has no production code path.
    mod parking_lot_replacement {
        use std::sync::{Mutex as StdMutex, MutexGuard as StdGuard};

        pub struct Mutex<T> {
            inner: StdMutex<T>,
        }

        impl<T> Mutex<T> {
            pub fn new(t: T) -> Self {
                Self {
                    inner: StdMutex::new(t),
                }
            }

            pub fn lock(&self) -> StdGuard<'_, T> {
                // justification: tests only — `Mutex::lock` only
                // returns `Err` on poisoning, which would mean another
                // test in this module already panicked while holding
                // the guard. Either way we want the failure to surface
                // here, not be swallowed.
                #[allow(clippy::unwrap_used)]
                self.inner.lock().unwrap()
            }
        }
    }
}
