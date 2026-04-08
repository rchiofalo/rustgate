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

use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::metrics::MeterProvider;
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use prometheus::proto::MetricType;

/// Module-level storage for the meter provider.
///
/// Stored here rather than in the global `opentelemetry` registry so that
/// `shutdown` can drive `provider.shutdown()` directly, rather than
/// relying on `Drop` of a cloned `Arc` (which is a no-op).
static PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

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

/// Attach one observable instrument to `meter` that gathers the named
/// Prometheus metric family on every collection cycle.
///
/// The callback filters `prometheus::gather()` output to the specific
/// family by name, translates each metric's label pairs to OTEL
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
                    let families = prometheus::default_registry().gather();
                    for family in families {
                        if family.name() != family_name {
                            continue;
                        }
                        for metric in family.get_metric() {
                            let attrs = label_pairs_to_kv(metric.get_label());
                            obs.observe(metric.get_counter().get_value(), &attrs);
                        }
                    }
                })
                .build();
        }
        MetricType::GAUGE => {
            let family_name = name.clone();
            let _inst = meter
                .f64_observable_gauge(name)
                .with_description("bridged from prometheus gauge")
                .with_callback(move |obs| {
                    let families = prometheus::default_registry().gather();
                    for family in families {
                        if family.name() != family_name {
                            continue;
                        }
                        for metric in family.get_metric() {
                            let attrs = label_pairs_to_kv(metric.get_label());
                            obs.observe(metric.get_gauge().get_value(), &attrs);
                        }
                    }
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
            let families = prometheus::default_registry().gather();
            for family in families {
                if family.name() != family_for_sum {
                    continue;
                }
                for metric in family.get_metric() {
                    let attrs = label_pairs_to_kv(metric.get_label());
                    let sum = if is_histogram {
                        metric.get_histogram().get_sample_sum()
                    } else {
                        metric.get_summary().sample_sum()
                    };
                    obs.observe(sum, &attrs);
                }
            }
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
            let families = prometheus::default_registry().gather();
            for family in families {
                if family.name() != family_for_count {
                    continue;
                }
                for metric in family.get_metric() {
                    let attrs = label_pairs_to_kv(metric.get_label());
                    let count = if is_histogram {
                        metric.get_histogram().get_sample_count()
                    } else {
                        metric.get_summary().sample_count()
                    };
                    obs.observe(count, &attrs);
                }
            }
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
}
