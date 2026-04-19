// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for the HTTP egress subsystem.
//!
//! Follows the server's `OnceLock` + `init()` + accessor pattern.
//! All metrics are registered centrally via [`init`] at startup.
//! Accessor functions return a `&'static` reference, falling back to
//! an unregistered metric if `init()` was not called.

use std::sync::OnceLock;

use prometheus::{Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts};

// ── Static Cells ───────────────────────────────────────────────────

static PUBLISHES: OnceLock<IntCounterVec> = OnceLock::new();
static ERRORS: OnceLock<IntCounterVec> = OnceLock::new();
static REQUEST_DURATION: OnceLock<Histogram> = OnceLock::new();
static CIRCUIT_STATE: OnceLock<IntGaugeVec> = OnceLock::new();
static RETRIES: OnceLock<IntCounterVec> = OnceLock::new();
static FILTERED: OnceLock<IntCounterVec> = OnceLock::new();
static QUEUE_DEPTH: OnceLock<IntGauge> = OnceLock::new();
static DROPPED: OnceLock<IntCounterVec> = OnceLock::new();

// ── Fallback constructors ──────────────────────────────────────────

fn fallback_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    match IntCounterVec::new(Opts::new(name, help), labels) {
        Ok(cv) => cv,
        Err(_) => std::process::abort(),
    }
}

fn fallback_gauge(name: &str, help: &str) -> IntGauge {
    match IntGauge::with_opts(Opts::new(name, help)) {
        Ok(g) => g,
        Err(_) => std::process::abort(),
    }
}

fn fallback_gauge_vec(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    match IntGaugeVec::new(Opts::new(name, help), labels) {
        Ok(gv) => gv,
        Err(_) => std::process::abort(),
    }
}

fn fallback_histogram(name: &str, help: &str) -> Histogram {
    match Histogram::with_opts(HistogramOpts::new(name, help)) {
        Ok(h) => h,
        Err(_) => std::process::abort(),
    }
}

// ── Registration ───────────────────────────────────────────────────

/// Register all HTTP egress metrics with the default Prometheus registry.
///
/// Must be called once at startup. If called multiple times, subsequent
/// calls will succeed but metrics may not be re-registered.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let publishes = IntCounterVec::new(
        Opts::new(
            "rustgate_http_publishes_total",
            "Successful HTTP egress deliveries",
        ),
        &["target"],
    )?;
    registry.register(Box::new(publishes.clone()))?;
    let _ = PUBLISHES.set(publishes);

    let errors = IntCounterVec::new(
        Opts::new(
            "rustgate_http_errors_total",
            "Failed HTTP egress deliveries",
        ),
        &["target", "reason"],
    )?;
    registry.register(Box::new(errors.clone()))?;
    let _ = ERRORS.set(errors);

    let request_duration = Histogram::with_opts(HistogramOpts::new(
        "rustgate_http_request_duration_seconds",
        "End-to-end HTTP request latency",
    ))?;
    registry.register(Box::new(request_duration.clone()))?;
    let _ = REQUEST_DURATION.set(request_duration);

    let circuit_state = IntGaugeVec::new(
        Opts::new(
            "rustgate_http_circuit_state",
            "Circuit breaker state per target (0=closed, 1=open, 2=half-open)",
        ),
        &["target"],
    )?;
    registry.register(Box::new(circuit_state.clone()))?;
    let _ = CIRCUIT_STATE.set(circuit_state);

    let retries = IntCounterVec::new(
        Opts::new(
            "rustgate_http_retries_total",
            "HTTP egress retry attempts (not initial attempts)",
        ),
        &["target"],
    )?;
    registry.register(Box::new(retries.clone()))?;
    let _ = RETRIES.set(retries);

    let filtered = IntCounterVec::new(
        Opts::new(
            "rustgate_http_filtered_total",
            "Messages filtered out before HTTP dispatch",
        ),
        &["target"],
    )?;
    registry.register(Box::new(filtered.clone()))?;
    let _ = FILTERED.set(filtered);

    let queue_depth = IntGauge::with_opts(Opts::new(
        "rustgate_http_queue_depth",
        "Current HTTP dispatch channel occupancy",
    ))?;
    registry.register(Box::new(queue_depth.clone()))?;
    let _ = QUEUE_DEPTH.set(queue_depth);

    let dropped = IntCounterVec::new(
        Opts::new(
            "rustgate_http_dropped_total",
            "Messages dropped before per-target dispatch (admission-queue \
             shed). Labelled by reason (`channel_full`, `channel_closed`).",
        ),
        &["reason"],
    )?;
    registry.register(Box::new(dropped.clone()))?;
    let _ = DROPPED.set(dropped);

    Ok(())
}

// ── Accessors ──────────────────────────────────────────────────────

/// Successful HTTP deliveries counter, labelled by target name.
pub fn publishes() -> &'static IntCounterVec {
    PUBLISHES.get_or_init(|| {
        fallback_counter_vec("rustgate_http_publishes_total", "fallback", &["target"])
    })
}

/// Failed HTTP deliveries counter, labelled by target and reason.
pub fn errors() -> &'static IntCounterVec {
    ERRORS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_http_errors_total",
            "fallback",
            &["target", "reason"],
        )
    })
}

/// HTTP request latency histogram.
pub fn request_duration() -> &'static Histogram {
    REQUEST_DURATION
        .get_or_init(|| fallback_histogram("rustgate_http_request_duration_seconds", "fallback"))
}

/// Circuit breaker state gauge, labelled by target.
pub fn circuit_state() -> &'static IntGaugeVec {
    CIRCUIT_STATE
        .get_or_init(|| fallback_gauge_vec("rustgate_http_circuit_state", "fallback", &["target"]))
}

/// Retry attempts counter, labelled by target.
pub fn retries() -> &'static IntCounterVec {
    RETRIES.get_or_init(|| {
        fallback_counter_vec("rustgate_http_retries_total", "fallback", &["target"])
    })
}

/// Filtered messages counter, labelled by target.
pub fn filtered() -> &'static IntCounterVec {
    FILTERED.get_or_init(|| {
        fallback_counter_vec("rustgate_http_filtered_total", "fallback", &["target"])
    })
}

/// Current dispatch channel occupancy gauge.
pub fn queue_depth() -> &'static IntGauge {
    QUEUE_DEPTH.get_or_init(|| fallback_gauge("rustgate_http_queue_depth", "fallback"))
}

/// Pre-dispatch admission-queue drops counter, labelled by reason.
///
/// Increments when a message is shed before reaching per-target
/// dispatch (e.g. the internal bounded channel is full or closed).
/// Paired with a DLQ entry under the synthetic `admission` target
/// when the DLQ is configured, so no drop is silent.
pub fn dropped() -> &'static IntCounterVec {
    DROPPED.get_or_init(|| {
        fallback_counter_vec("rustgate_http_dropped_total", "fallback", &["reason"])
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn accessors_return_without_init() {
        // Fallback metrics should work without init()
        let _ = publishes();
        let _ = errors();
        let _ = request_duration();
        let _ = circuit_state();
        let _ = retries();
        let _ = filtered();
        let _ = queue_depth();
    }

    #[test]
    fn publishes_can_increment() {
        let counter = publishes();
        if let Ok(child) = counter.get_metric_with_label_values(&["test-target"]) {
            child.inc();
            assert_eq!(child.get(), 1);
        }
    }

    #[test]
    fn errors_can_increment_with_reason() {
        let counter = errors();
        if let Ok(child) = counter.get_metric_with_label_values(&["test-target", "network"]) {
            child.inc();
            assert_eq!(child.get(), 1);
        }
    }

    #[test]
    fn circuit_state_can_set() {
        let gauge = circuit_state();
        if let Ok(child) = gauge.get_metric_with_label_values(&["test-target"]) {
            child.set(1); // open
            assert_eq!(child.get(), 1);
        }
    }

    #[test]
    fn queue_depth_can_set() {
        queue_depth().set(42);
        assert_eq!(queue_depth().get(), 42);
    }

    #[test]
    fn dropped_can_increment_with_reason() {
        let counter = dropped();
        if let Ok(child) = counter.get_metric_with_label_values(&["channel_full"]) {
            child.inc();
            assert!(child.get() >= 1);
        }
    }
}
