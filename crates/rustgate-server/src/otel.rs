// Copyright © 2026 Roberto Chiofalo.

//! OpenTelemetry tracing setup for OTLP trace export.
//!
//! Initializes an OpenTelemetry [`SdkTracerProvider`] that exports spans to an
//! OTLP-compatible collector (e.g. Jaeger, Grafana Tempo) via gRPC. The
//! provider is layered on top of the existing `tracing` subscriber so that
//! existing `tracing::info!` / `debug!` / `#[instrument]` spans are
//! transparently exported as distributed traces.
//!
//! The provider is stored in a module-level [`OnceLock`] so that [`shutdown`]
//! can call `provider.shutdown()` directly, ensuring all pending spans are
//! flushed before process exit.

use std::sync::OnceLock;

use opentelemetry::trace::TracerProvider;
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::Layer;

/// Module-level storage for the tracer provider.
///
/// Stored here rather than in the global `opentelemetry` registry so that
/// `shutdown()` can call `provider.shutdown()` directly to flush spans,
/// rather than relying on `Drop` of a cloned `Arc` (which is a no-op).
static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Initialize the OTel tracer provider and return a boxed layer.
///
/// The returned layer can be composed with any `tracing_subscriber::Registry`-
/// based subscriber via `.with()`. Call [`shutdown`] before process exit to
/// flush pending spans.
///
/// # Errors
///
/// Returns an error if the OTLP span exporter cannot be built (e.g., invalid
/// endpoint URL).
pub(crate) fn init_layer<S>(
    endpoint: &str,
    service_name: &str,
) -> anyhow::Result<Box<dyn Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber
        + for<'span> tracing_subscriber::registry::LookupSpan<'span>
        + Send
        + Sync,
{
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("OTLP span exporter: {e}"))?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_service_name(service_name.to_string())
                .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
                .build(),
        )
        .build();

    let scope = InstrumentationScope::builder("rustgate").build();
    let tracer = provider.tracer_with_scope(scope);

    // Store the provider so shutdown() can flush it. If init_layer is called
    // twice (shouldn't happen), the second call silently keeps the first
    // provider — the tracer still works because it holds its own Arc.
    let _ = PROVIDER.set(provider);

    Ok(Box::new(tracing_opentelemetry::layer().with_tracer(tracer)))
}

/// Flush pending spans and shut down the tracer provider.
///
/// Blocks until the batch exporter has drained its queue or the shutdown
/// timeout expires. Must be called before process exit to avoid losing
/// in-flight spans.
pub(crate) fn shutdown() {
    if let Some(provider) = PROVIDER.get()
        && let Err(e) = provider.shutdown()
    {
        tracing::warn!(error = %e, "OpenTelemetry provider shutdown failed");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn init_layer_succeeds_with_valid_endpoint() {
        // The tonic gRPC exporter requires a tokio runtime context to build.
        let result =
            init_layer::<tracing_subscriber::Registry>("http://localhost:4317", "test-service");
        assert!(
            result.is_ok(),
            "init_layer should succeed with a valid endpoint"
        );
        // Clean up: shut down the provider so background threads don't leak.
        shutdown();
    }

    #[test]
    fn shutdown_without_init_is_safe() {
        // Calling shutdown before init_layer should not panic.
        // Note: if the previous test already populated PROVIDER via OnceLock,
        // this test may hit the populated path — that's fine either way.
        shutdown();
    }

    /// An empty endpoint string is *accepted* by
    /// `opentelemetry_otlp::SpanExporter::builder().with_tonic()` —
    /// tonic treats it as "use the crate default endpoint" and defers
    /// resolution until a connection is attempted. The contract we pin
    /// here is therefore **no panic at layer construction**: a
    /// deployment that ships an unset `RUSTGATE_OTEL_ENDPOINT` starts
    /// cleanly and the connect failure surfaces later as a runtime
    /// export error, not a startup panic. A regression that added
    /// `assert!(!endpoint.is_empty())` upstream would break this
    /// contract.
    #[tokio::test]
    async fn init_layer_tolerates_empty_endpoint_without_panic() {
        let result = init_layer::<tracing_subscriber::Registry>("", "test-service");
        assert!(
            result.is_ok(),
            "empty endpoint must fall through to tonic's default URI rather than panicking",
        );
        shutdown();
    }

    /// A malformed endpoint (e.g. no scheme, stray whitespace, or a
    /// scheme tonic does not support) must return a `Result::Err`, not
    /// `panic!`. This pins the `map_err(|e| anyhow::anyhow!("OTLP span
    /// exporter: {e}"))` branch so a bad config file surfaces as a
    /// readable error in the startup log rather than a stack trace.
    #[tokio::test]
    async fn init_layer_rejects_malformed_endpoint_without_panic() {
        let result =
            init_layer::<tracing_subscriber::Registry>("not a valid uri at all", "test-service");
        assert!(
            result.is_err(),
            "init_layer must reject a clearly-malformed endpoint rather than panicking",
        );
    }

    /// The error message for a failed `init_layer` call must carry the
    /// `"OTLP span exporter"` prefix so operators can grep the startup
    /// log to distinguish this failure mode from other
    /// `tracing_subscriber` layer errors further down the init
    /// sequence. A silent drift of the prefix would break runbook
    /// regex patterns. We trigger the failure via a clearly-malformed
    /// URI (empty-string is tolerated by tonic — see sibling test) so
    /// this test focuses purely on the `map_err` formatting contract.
    #[tokio::test]
    async fn init_layer_error_message_names_otlp_span_exporter() {
        // Cannot use `.expect_err` because `Box<dyn Layer<_>>` has no
        // `Debug` impl; match on the result by hand instead.
        let result =
            init_layer::<tracing_subscriber::Registry>("not a valid uri at all", "test-service");
        let err = match result {
            Ok(_) => panic!("malformed endpoint must surface as Err"),
            Err(e) => e,
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("OTLP span exporter"),
            "error must carry the `OTLP span exporter` prefix for log-grep; got {rendered:?}",
        );
    }

    /// Calling `shutdown` multiple times after a failed-to-init path
    /// must stay panic-free. The failure path does not populate
    /// `PROVIDER`, so each `shutdown` hits the `OnceLock::get() ==
    /// None` branch — but the function still has to be a no-op rather
    /// than unwrap-on-nothing. A regression that changed
    /// `if let Some(provider)` to `.unwrap()` would fail here.
    #[test]
    fn shutdown_is_idempotent_across_repeated_calls() {
        for _ in 0..5 {
            shutdown();
        }
    }

    /// The `Layer<S>` returned by `init_layer` must satisfy `Send +
    /// Sync + 'static` so it can be composed into a
    /// `tracing_subscriber::Registry` that is then moved onto a
    /// background task. A refactor that introduced a non-`Send`
    /// temporary inside the layer chain would fail here at
    /// test-compile time rather than at the call site in
    /// `rustgate_server::setup`.
    #[tokio::test]
    async fn init_layer_returns_send_sync_static_layer() {
        fn assert_send_sync_static<T: Send + Sync + 'static + ?Sized>(_: &T) {}

        let layer = init_layer::<tracing_subscriber::Registry>(
            "http://localhost:4317",
            "bounds-check-service",
        )
        .expect("valid endpoint must succeed");
        assert_send_sync_static(layer.as_ref());
        shutdown();
    }

    /// `init_layer` must accept an empty service name without
    /// panicking — the OTel SDK treats the service name as an
    /// opaque string and will serialize whatever we hand it. A
    /// regression that added an `assert!(!service_name.is_empty())`
    /// would break deployments that key service.name off an env var
    /// that silently evaluated to empty.
    ///
    /// We cannot easily inspect the `Resource`'s `service.name`
    /// attribute after the fact from outside the OTel SDK, so the
    /// test's job is solely to pin "no panic, no error on empty
    /// name".
    #[tokio::test]
    async fn init_layer_accepts_empty_service_name_without_panic() {
        let result = init_layer::<tracing_subscriber::Registry>("http://localhost:4317", "");
        assert!(
            result.is_ok(),
            "empty service name must not block layer construction",
        );
        shutdown();
    }

    /// `init_layer` must accept a long service name — some
    /// deployments synthesize `service.name` from
    /// `cluster.namespace.pod` triplets that can easily exceed 128
    /// chars. The SDK does not document a cap, so the contract we
    /// pin is "any string that fits in a `String` flows through".
    #[tokio::test]
    async fn init_layer_accepts_long_service_name_without_truncation_error() {
        let long_name = "a".repeat(512);
        let result =
            init_layer::<tracing_subscriber::Registry>("http://localhost:4317", &long_name);
        assert!(
            result.is_ok(),
            "long service name must not trip an internal size check",
        );
        shutdown();
    }
}
