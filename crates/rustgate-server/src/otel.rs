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
}
