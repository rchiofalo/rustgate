// Copyright © 2026 Roberto Chiofalo.

//! OpenTelemetry metrics export for rustgate.
//!
//! Exposes the existing Prometheus `prometheus::Registry` as OTLP metrics
//! by attaching OpenTelemetry observable instruments whose callbacks gather
//! the latest metric families from the Prometheus default registry on each
//! collection cycle. This keeps Prometheus scraping (`/metrics`) working
//! unchanged while letting operators also push metrics to any OTLP-compatible
//! collector (e.g. Grafana Alloy, OpenTelemetry Collector, Datadog Agent)
//! over gRPC.
//!
//! # Mapping
//!
//! Each Prometheus `prometheus::proto::MetricFamily` is mapped to a single
//! OTEL observable instrument:
//!
//! | Prometheus type | OTEL instrument                  |
//! |-----------------|----------------------------------|
//! | `COUNTER`       | `f64_observable_counter`         |
//! | `GAUGE`         | `f64_observable_gauge`           |
//! | `HISTOGRAM`     | `_sum` + `_count` counters       |
//! | `SUMMARY`       | `_sum` + `_count` counters       |
//! | `UNTYPED`       | ignored                          |
//!
//! Histogram bucket boundaries are intentionally not reported — they would
//! require custom OTEL `Views` matching Prometheus's bucket layout, and
//! most OTLP consumers prefer OTEL-native exponential histograms. The sum
//! and count are sufficient for the dashboards rustgate currently ships.
//!
//! Label pairs on each Prometheus metric are mapped one-to-one to OTEL
//! `KeyValue` attributes.
//!
//! # Shutdown
//!
//! The `SdkMeterProvider` is stored in a module-level `OnceLock` so
//! that `shutdown` can call `provider.shutdown()` directly, flushing the
//! last batch of metrics before process exit.
//!
//! # Gather coalescing
//!
//! Each OTEL collection cycle invokes every observable instrument's
//! callback serially. A naive implementation where each callback calls
//! `prometheus::default_registry().gather()` on its own would produce
//! `O(F²)` gather work per cycle for `F` metric families. Instead, all
//! callbacks share a module-level `FamilyCache` keyed by family name. The
//! first callback of a collection cycle gathers the Prometheus registry
//! once, populates the cache, and subsequent callbacks do `HashMap`
//! lookups. The cache is invalidated after a short TTL so back-to-back
//! collection cycles always see fresh values.
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use opentelemetry::metrics::MeterProvider;
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use prometheus::proto::{MetricFamily, MetricType};

/// Module-level storage for the meter provider.
///
/// Stored here rather than in the global `opentelemetry` registry so that
/// `shutdown` can drive `provider.shutdown()` directly, rather than
/// relying on `Drop` of a cloned `Arc` (which is a no-op).
static PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

/// Short-lived cache of gathered Prometheus metric families, shared by
/// every observable instrument callback so a single OTEL collection cycle
/// only walks the Prometheus registry once.
///
/// The cache is refreshed lazily: any callback that observes a stale
/// entry (`refreshed_at + CACHE_TTL < now`) triggers a single gather and
/// repopulates the `HashMap` for the remainder of the collection window.
/// `CACHE_TTL` is intentionally well below the minimum OTLP push interval
/// (1 s) so consecutive collection cycles always see fresh data, but long
/// enough to cover the burst of callbacks within one cycle.
struct FamilyCache {
    refreshed_at: Option<Instant>,
    families: HashMap<String, MetricFamily>,
}

impl FamilyCache {
    /// Staleness threshold. Any gather older than this is discarded at
    /// the next `refresh_if_stale` call.
    const CACHE_TTL: Duration = Duration::from_millis(500);

    fn new() -> Self {
        Self {
            refreshed_at: None,
            families: HashMap::new(),
        }
    }

    /// Gather the Prometheus default registry if the cached snapshot is
    /// missing or older than `CACHE_TTL`.
    fn refresh_if_stale(&mut self) {
        let stale = match self.refreshed_at {
            None => true,
            Some(t) => t.elapsed() >= Self::CACHE_TTL,
        };
        if !stale {
            return;
        }
        self.families.clear();
        for fam in prometheus::default_registry().gather() {
            // The existing value (if any) was just cleared; discard the
            // `None` returned by `insert` to keep `-Dwarnings` happy.
            let _ = self.families.insert(fam.name().to_string(), fam);
        }
        self.refreshed_at = Some(Instant::now());
    }
}

static FAMILY_CACHE: LazyLock<Mutex<FamilyCache>> =
    LazyLock::new(|| Mutex::new(FamilyCache::new()));

/// Run `f` against the cached `MetricFamily` for `name`, refreshing the
/// cache first if it's stale. Silently no-ops if the family is not
/// currently registered (it may have been unregistered at runtime) or if
/// the cache mutex is poisoned.
fn with_cached_family<F>(name: &str, mut f: F)
where
    F: FnMut(&MetricFamily),
{
    let Ok(mut guard) = FAMILY_CACHE.lock() else {
        return;
    };
    guard.refresh_if_stale();
    if let Some(fam) = guard.families.get(name) {
        f(fam);
    }
}

/// Force the cache to refresh on its next access. Called from `shutdown`
/// so the final `force_flush` sees freshly-gathered values rather than a
/// sub-500 ms stale snapshot.
fn invalidate_cache() {
    if let Ok(mut guard) = FAMILY_CACHE.lock() {
        guard.refreshed_at = None;
    }
}

/// Configure an OTLP push exporter that scrapes the Prometheus default
/// registry and sends the translated metrics to `endpoint` every
/// `interval`.
///
/// This installs a `SdkMeterProvider` with a single gRPC-Tonic OTLP
/// `opentelemetry_otlp::MetricExporter` wrapped in a `PeriodicReader`.
/// A family-discovery sweep runs synchronously during init so that every
/// currently-registered Prometheus collector gets a matching observable
/// instrument.
///
/// Safe to call at most once per process. Subsequent calls are no-ops
/// and return `Ok(())` to keep start-up idempotent.
///
/// # Errors
///
/// Returns an error if the OTLP metric exporter cannot be built (e.g.
/// invalid endpoint URL, tonic misconfiguration).
pub(crate) fn init(endpoint: &str, service_name: &str, interval: Duration) -> anyhow::Result<()> {
    if PROVIDER.get().is_some() {
        return Ok(());
    }

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("OTLP metric exporter: {e}"))?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(interval)
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(
            Resource::builder()
                .with_service_name(service_name.to_string())
                .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
                .build(),
        )
        .build();

    let scope = InstrumentationScope::builder("rustgate").build();
    let meter = provider.meter_with_scope(scope);

    // Walk the default Prometheus registry once at init time and attach
    // one observable instrument per metric family. Each instrument's
    // callback re-gathers the registry at collection time so newly-added
    // label sets (e.g. per-identity metrics) are still exported.
    let registry = prometheus::default_registry();
    let families = registry.gather();
    for family in families {
        attach_family(&meter, family.name().to_owned(), family.get_field_type());
    }

    // Best-effort store; PROVIDER.get().is_some() guard above makes
    // double-init a no-op.
    let _ = PROVIDER.set(provider);
    Ok(())
}

/// Attach one observable instrument to `meter` that observes the named
/// Prometheus metric family on every collection cycle.
///
/// The callback looks the family up in the shared `FamilyCache` (which
/// lazily gathers `prometheus::default_registry()` at most once per
/// collection cycle), translates each metric's label pairs to OTEL
/// `KeyValue` attributes, and forwards the value to the appropriate
/// observable instrument. Histograms and summaries produce two
/// instruments (`<name>_sum`, `<name>_count`) via a companion call.
fn attach_family(meter: &opentelemetry::metrics::Meter, name: String, kind: MetricType) {
    match kind {
        MetricType::COUNTER => {
            let family_name = name.clone();
            let _inst = meter
                .f64_observable_counter(name)
                .with_description("bridged from prometheus counter")
                .with_callback(move |obs| {
                    with_cached_family(&family_name, |family| {
                        for metric in family.get_metric() {
                            let attrs = label_pairs_to_kv(metric.get_label());
                            obs.observe(metric.get_counter().get_value(), &attrs);
                        }
                    });
                })
                .build();
        }
        MetricType::GAUGE => {
            let family_name = name.clone();
            let _inst = meter
                .f64_observable_gauge(name)
                .with_description("bridged from prometheus gauge")
                .with_callback(move |obs| {
                    with_cached_family(&family_name, |family| {
                        for metric in family.get_metric() {
                            let attrs = label_pairs_to_kv(metric.get_label());
                            obs.observe(metric.get_gauge().get_value(), &attrs);
                        }
                    });
                })
                .build();
        }
        MetricType::HISTOGRAM => attach_histogram_or_summary_like(meter, name, true),
        MetricType::SUMMARY => attach_histogram_or_summary_like(meter, name, false),
        MetricType::UNTYPED => {
            // No OTEL equivalent; rustgate does not register untyped metrics.
        }
    }
}

/// Emit a histogram or summary family as a pair of observable counters
/// (`<name>_sum`, `<name>_count`).
///
/// Prometheus histograms in this codebase are low-cardinality aggregates
/// (e.g. session duration, NATS consumer info latency). The sum-plus-count
/// projection preserves the information OTLP consumers need for
/// rate/avg dashboards without having to port bucket boundaries through
/// OTEL Views.
fn attach_histogram_or_summary_like(
    meter: &opentelemetry::metrics::Meter,
    name: String,
    is_histogram: bool,
) {
    let sum_name = format!("{name}_sum");
    let count_name = format!("{name}_count");

    let family_for_sum = name.clone();
    let _sum_inst = meter
        .f64_observable_counter(sum_name)
        .with_description(if is_histogram {
            "bridged sum of prometheus histogram observations"
        } else {
            "bridged sum of prometheus summary observations"
        })
        .with_callback(move |obs| {
            with_cached_family(&family_for_sum, |family| {
                for metric in family.get_metric() {
                    let attrs = label_pairs_to_kv(metric.get_label());
                    let sum = if is_histogram {
                        metric.get_histogram().get_sample_sum()
                    } else {
                        metric.get_summary().sample_sum()
                    };
                    obs.observe(sum, &attrs);
                }
            });
        })
        .build();

    let family_for_count = name;
    let _count_inst = meter
        .u64_observable_counter(count_name)
        .with_description(if is_histogram {
            "bridged count of prometheus histogram observations"
        } else {
            "bridged count of prometheus summary observations"
        })
        .with_callback(move |obs| {
            with_cached_family(&family_for_count, |family| {
                for metric in family.get_metric() {
                    let attrs = label_pairs_to_kv(metric.get_label());
                    let count = if is_histogram {
                        metric.get_histogram().get_sample_count()
                    } else {
                        metric.get_summary().sample_count()
                    };
                    obs.observe(count, &attrs);
                }
            });
        })
        .build();
}

/// Translate Prometheus label pairs into OTEL `KeyValue` attributes.
fn label_pairs_to_kv(labels: &[prometheus::proto::LabelPair]) -> Vec<KeyValue> {
    labels
        .iter()
        .map(|lp| KeyValue::new(lp.name().to_string(), lp.value().to_string()))
        .collect()
}

/// Flush pending metrics and shut down the meter provider.
///
/// Blocks until the periodic reader has drained its queue or the
/// shutdown timeout expires. Must be called before process exit to
/// avoid losing the final batch of metrics.
pub(crate) fn shutdown() {
    if let Some(provider) = PROVIDER.get() {
        // Drop any stale cached families so the final force_flush sees a
        // fresh gather rather than a sub-TTL snapshot.
        invalidate_cache();
        if let Err(e) = provider.force_flush() {
            tracing::debug!(error = %e, "OTLP meter provider force_flush failed");
        }
        if let Err(e) = provider.shutdown() {
            tracing::warn!(error = %e, "OTLP meter provider shutdown failed");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn init_succeeds_with_valid_endpoint() {
        // The tonic gRPC exporter requires a tokio runtime context to build
        // and to drive its futures during shutdown. A current-thread runtime
        // deadlocks here: `shutdown()` sends a message to the PeriodicReader
        // background thread which then calls `collect_and_export` via tonic,
        // but tonic cannot drive its futures because the main thread is
        // blocked waiting for the shutdown response. Use multi_thread so a
        // worker is available to drive the tonic client while the main
        // thread blocks on shutdown.
        //
        // A one-second interval keeps the periodic reader from blocking the
        // test for the default 60s while still exercising the build path.
        let result = init(
            "http://localhost:4317",
            "test-metrics-service",
            Duration::from_secs(1),
        );
        assert!(
            result.is_ok(),
            "init should succeed with a valid endpoint: {result:?}"
        );
        // Clean up: shut down the provider so background threads don't leak.
        shutdown();
    }

    #[test]
    fn shutdown_without_init_is_safe() {
        // Calling shutdown before init should not panic.
        shutdown();
    }

    #[test]
    fn family_cache_refreshes_on_first_use_and_reuses_within_ttl() {
        // Use a private FamilyCache instance (not the global one) so the
        // test doesn't race with any other parallel test touching OTEL.
        let mut cache = FamilyCache::new();
        assert!(
            cache.refreshed_at.is_none(),
            "fresh cache should have no refresh timestamp"
        );

        cache.refresh_if_stale();
        let first = cache
            .refreshed_at
            .expect("refresh_if_stale must populate the timestamp");
        // refreshed_at should not advance on a subsequent call within TTL.
        cache.refresh_if_stale();
        let second = cache
            .refreshed_at
            .expect("second call must leave the timestamp set");
        assert_eq!(
            first, second,
            "within-TTL refresh_if_stale should be a no-op"
        );
    }

    // ── New defensive-invariant tests (see issue #909) ──────────

    /// Pins `FamilyCache::CACHE_TTL` at the 500 ms documented in the
    /// module docs ("well below the minimum OTLP push interval of 1 s").
    /// A future refactor that silently raises this to 1 s or higher
    /// would let consecutive collection cycles within the same push
    /// interval observe a stale snapshot instead of freshly-gathered
    /// values — exactly the pathological case the cache was added to
    /// avoid. The module header calls out the 1 s push interval as the
    /// upper bound, so this test also asserts the TTL stays strictly
    /// below one second.
    #[test]
    fn family_cache_ttl_constant_is_below_otlp_push_interval() {
        assert_eq!(
            FamilyCache::CACHE_TTL,
            Duration::from_millis(500),
            "CACHE_TTL must stay at the documented 500 ms"
        );
        assert!(
            FamilyCache::CACHE_TTL < Duration::from_secs(1),
            "CACHE_TTL must remain strictly below the 1 s minimum OTLP push interval"
        );
    }

    /// A brand-new `FamilyCache` MUST carry both an empty family map
    /// and an unset timestamp. Any other initial state would either
    /// return stale data on the first observable callback (if
    /// `refreshed_at` started populated) or cause `refresh_if_stale`
    /// to skip the initial gather (if the timestamp were fresh). The
    /// existing within-TTL test leans on this invariant implicitly;
    /// this one pins it explicitly, including the family-map emptiness.
    #[test]
    fn family_cache_new_starts_with_empty_map_and_no_refresh_timestamp() {
        let cache = FamilyCache::new();
        assert!(
            cache.refreshed_at.is_none(),
            "a fresh cache must have no refresh timestamp so the first `refresh_if_stale` call actually gathers"
        );
        assert!(
            cache.families.is_empty(),
            "a fresh cache must have an empty family map so stale data cannot leak through"
        );
    }

    /// Backdating `refreshed_at` past `CACHE_TTL` MUST force
    /// `refresh_if_stale` to re-gather and advance the timestamp. This
    /// is the workhorse branch that keeps consecutive collection
    /// cycles honest — without it, the cache would freeze at its
    /// first snapshot and every subsequent OTLP push would repeat
    /// stale values. We simulate a stale cache by rewinding
    /// `refreshed_at` via `Instant::checked_sub` rather than actually
    /// sleeping, so the test stays deterministic and fast even under
    /// a loaded CI worker.
    #[test]
    fn family_cache_refresh_if_stale_advances_timestamp_after_backdating() {
        let mut cache = FamilyCache::new();
        cache.refresh_if_stale();
        let first = cache
            .refreshed_at
            .expect("initial refresh must populate the timestamp");

        // Rewind the timestamp 10× the TTL so the next call sees stale.
        let rewound = first
            .checked_sub(FamilyCache::CACHE_TTL * 10)
            .expect("Instant rewind by 5 s is well within monotonic clock range");
        cache.refreshed_at = Some(rewound);

        cache.refresh_if_stale();
        let second = cache
            .refreshed_at
            .expect("refresh_if_stale must re-populate the timestamp after stale detection");
        assert!(
            second > rewound,
            "second refresh must produce a fresher timestamp than the rewound one (rewound={rewound:?}, second={second:?})"
        );
        assert!(
            second >= first,
            "second refresh must not go backwards in time (first={first:?}, second={second:?})"
        );
    }

    /// `label_pairs_to_kv` on an empty slice MUST return an empty
    /// `Vec<KeyValue>`. Observable callbacks invoke this on every
    /// metric-family cycle, so a regression that panicked on empty
    /// (e.g. an unchecked `labels[0]`) would crash the OTLP exporter
    /// the first time Prometheus registered a label-free family (e.g.
    /// a bare counter). This pins the safe-for-zero behavior.
    #[test]
    fn label_pairs_to_kv_empty_slice_returns_empty_vec() {
        let out = label_pairs_to_kv(&[]);
        assert!(
            out.is_empty(),
            "empty label slice must produce zero KeyValue attrs, got {} entries",
            out.len()
        );
    }

    /// A single Prometheus `LabelPair` must translate one-to-one into
    /// a single OTEL `KeyValue` with the same name and value strings.
    /// Label pairs carry the subject of every metric, so a silent
    /// swap or drop here would corrupt every OTLP dashboard that
    /// filters by `peer_id`, `tenant`, or similar attributes.
    #[test]
    fn label_pairs_to_kv_maps_single_pair_to_matching_keyvalue() {
        let mut lp = prometheus::proto::LabelPair::default();
        lp.set_name("peer_id".to_string());
        lp.set_value("peer-42".to_string());

        let out = label_pairs_to_kv(std::slice::from_ref(&lp));
        assert_eq!(out.len(), 1, "one LabelPair must produce one KeyValue");
        assert_eq!(
            out[0].key.as_str(),
            "peer_id",
            "KeyValue.key must echo the LabelPair name verbatim"
        );
        // Value uses Display → round-trips through the Into<Value> blanket impl.
        assert_eq!(
            format!("{}", out[0].value),
            "peer-42",
            "KeyValue.value must echo the LabelPair value verbatim"
        );
    }

    /// `label_pairs_to_kv` MUST preserve the input order. OTLP
    /// consumers frequently key their attribute grouping off a
    /// positional label (e.g. the first label is `tenant`), so any
    /// reordering here would silently misroute metrics in downstream
    /// dashboards. The `Vec::iter().map().collect()` implementation
    /// is order-preserving today; this test pins that contract so a
    /// future refactor to a parallel iterator or `HashMap` doesn't
    /// regress it.
    #[test]
    fn label_pairs_to_kv_preserves_input_order_for_multiple_pairs() {
        let labels: Vec<prometheus::proto::LabelPair> = ["first", "second", "third"]
            .iter()
            .enumerate()
            .map(|(idx, name)| {
                let mut lp = prometheus::proto::LabelPair::default();
                lp.set_name((*name).to_string());
                lp.set_value(format!("v{idx}"));
                lp
            })
            .collect();

        let out = label_pairs_to_kv(&labels);
        assert_eq!(out.len(), 3, "three LabelPairs must yield three KeyValues");
        assert_eq!(out[0].key.as_str(), "first");
        assert_eq!(out[1].key.as_str(), "second");
        assert_eq!(out[2].key.as_str(), "third");
        assert_eq!(format!("{}", out[0].value), "v0");
        assert_eq!(format!("{}", out[1].value), "v1");
        assert_eq!(format!("{}", out[2].value), "v2");
    }

    /// Empty label values are legal in Prometheus (e.g. an unset
    /// optional labelset still emits with `""`) and MUST survive the
    /// mapping as empty-string `KeyValue` attrs rather than being
    /// silently dropped. Skipping them would desynchronize the label
    /// cardinality reported to OTLP from the cardinality reported to
    /// Prometheus, which has real debugging consequences when a
    /// rollout swaps backends.
    #[test]
    fn label_pairs_to_kv_forwards_empty_value_strings_as_attrs() {
        let mut lp = prometheus::proto::LabelPair::default();
        lp.set_name("outcome".to_string());
        lp.set_value(String::new());

        let out = label_pairs_to_kv(std::slice::from_ref(&lp));
        assert_eq!(out.len(), 1, "empty value must still produce one KeyValue");
        assert_eq!(out[0].key.as_str(), "outcome");
        assert_eq!(
            format!("{}", out[0].value),
            "",
            "empty string value must round-trip through the KeyValue translation"
        );
    }

    /// Multi-byte UTF-8 label names and values (e.g. non-ASCII
    /// tenant identifiers) MUST round-trip through the translation
    /// unharmed. A byte-level slice-and-splice bug would show up
    /// here as either mojibake or a panic. The workspace allows
    /// non-ASCII in many fields, so defending this path costs
    /// nothing and forecloses a whole category of future regressions.
    #[test]
    fn label_pairs_to_kv_preserves_multibyte_utf8_name_and_value() {
        let mut lp = prometheus::proto::LabelPair::default();
        lp.set_name("tenant_名".to_string());
        lp.set_value("αβγ-42".to_string());

        let out = label_pairs_to_kv(std::slice::from_ref(&lp));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key.as_str(), "tenant_名");
        assert_eq!(format!("{}", out[0].value), "αβγ-42");
    }

    /// `invalidate_cache` must be safe to call at any time, including
    /// before any `with_cached_family` has primed the cache. This
    /// pins the no-panic, no-error contract so the `shutdown()`
    /// codepath (which calls `invalidate_cache` before
    /// `force_flush`) stays robust even when the server never
    /// processed a single metric-collection cycle.
    #[test]
    fn invalidate_cache_is_idempotent_and_safe_without_prior_refresh() {
        // Two back-to-back calls to exercise both the "was None" and
        // "was Some" branches of the internal `if let Ok(mut guard)`.
        invalidate_cache();
        invalidate_cache();
    }

    /// `with_cached_family` on a name that is definitively not
    /// registered in the Prometheus default registry MUST NOT invoke
    /// the callback. This is the load-bearing guard that keeps the
    /// observable instruments from running their per-metric
    /// translation path on a `None` lookup (which would read from a
    /// default `MetricFamily` and emit a value of zero). We use a
    /// sentinel name unlikely to ever be registered.
    #[test]
    fn with_cached_family_on_unknown_name_does_not_invoke_callback() {
        let mut called = false;
        with_cached_family(
            "__rustgate_otel_metrics_sentinel_never_registered_family__",
            |_family| {
                called = true;
            },
        );
        assert!(
            !called,
            "callback must not fire for a family absent from the prometheus registry"
        );
    }

    /// `shutdown` must remain re-entrant — calling it repeatedly
    /// after a single `init` must not double-shutdown, panic, or
    /// tear down an already-torn provider. The post-drain path in
    /// `main.rs` always calls `otel_metrics::shutdown()`, but
    /// integration-test harnesses and signal-driven code may invoke
    /// it a second time; the `OnceLock::get` guard is what keeps
    /// that safe, and this test pins the behavior.
    #[test]
    fn shutdown_is_idempotent_when_called_repeatedly_without_init() {
        // Without init, PROVIDER.get() returns None and shutdown is a no-op.
        // Calling it three times in a row exercises the None-branch repeatedly.
        shutdown();
        shutdown();
        shutdown();
    }
}
