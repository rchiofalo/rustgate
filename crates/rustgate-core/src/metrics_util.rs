// Copyright © 2026 Roberto Chiofalo.

//! Shared Prometheus fallback constructors.
//!
//! Every crate that exposes Prometheus metrics follows the
//! `OnceLock` + `init()` + accessor pattern documented in
//! `rules/shared-infrastructure.md`. The accessor must return a valid
//! metric even when `init()` was never called (e.g. during unit tests
//! that never wire up the metrics subsystem); the fallback is an
//! unregistered metric created via `OnceLock::get_or_init()` so the
//! call site keeps a stable `&'static` reference and increments are
//! absorbed without effect.
//!
//! Before this module existed, each crate (`rustgate-server`,
//! `rustgate-federation`, `rustgate-http`) carried its own private copy
//! of `fallback_counter`, `fallback_gauge`, `fallback_counter_vec`,
//! `fallback_gauge_vec`, `fallback_histogram`, and
//! `fallback_histogram_vec`. The bodies were identical apart from the
//! type they returned. This module consolidates those into one shared
//! implementation behind the `metrics` feature.
//!
//! # Panic discipline
//!
//! These helpers are only reachable with hardcoded metric names that
//! have already been validated by the matching `init()` call site —
//! i.e. the constructor was successfully called once at startup with
//! the same name and label arity. Failure here would mean
//! `prometheus::Opts::new` rejected a name it had previously accepted,
//! which is a programmer error: an `expect()` is the correct sentinel.
//! This is the existing convention in the per-crate copies that this
//! module replaces (those used `std::process::abort()`); the panic
//! variant gives reviewers and panic-reporting infrastructure a usable
//! message instead of a silent SIGABRT.

use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};

/// Build an unregistered [`IntCounter`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
///
/// See module docs for the panic-discipline rationale.
pub fn fallback_counter(name: &str, help: &str) -> IntCounter {
    IntCounter::with_opts(Opts::new(name, help))
        .expect("fallback IntCounter constructor: hardcoded metric name must be valid")
}

/// Build an unregistered [`IntGauge`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
pub fn fallback_gauge(name: &str, help: &str) -> IntGauge {
    IntGauge::with_opts(Opts::new(name, help))
        .expect("fallback IntGauge constructor: hardcoded metric name must be valid")
}

/// Build an unregistered [`IntCounterVec`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
pub fn fallback_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    IntCounterVec::new(Opts::new(name, help), labels).expect(
        "fallback IntCounterVec constructor: hardcoded metric name and labels must be valid",
    )
}

/// Build an unregistered [`IntGaugeVec`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
pub fn fallback_gauge_vec(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    IntGaugeVec::new(Opts::new(name, help), labels)
        .expect("fallback IntGaugeVec constructor: hardcoded metric name and labels must be valid")
}

/// Build an unregistered [`Histogram`] (default buckets) for use as an
/// `OnceLock` fallback when `init()` has not been called.
pub fn fallback_histogram(name: &str, help: &str) -> Histogram {
    Histogram::with_opts(HistogramOpts::new(name, help))
        .expect("fallback Histogram constructor: hardcoded metric name must be valid")
}

/// Build an unregistered [`HistogramVec`] (default buckets) for use as
/// an `OnceLock` fallback when `init()` has not been called.
pub fn fallback_histogram_vec(name: &str, help: &str, labels: &[&str]) -> HistogramVec {
    HistogramVec::new(HistogramOpts::new(name, help), labels)
        .expect("fallback HistogramVec constructor: hardcoded metric name and labels must be valid")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fallback_counter_constructs_unregistered_metric_without_panic() {
        // Sunny path: `IntCounter::with_opts` accepts hardcoded names so
        // the helper must produce a callable counter that starts at 0
        // and increments monotonically. The error path is `expect()`,
        // which only fires on prometheus-internal validation failures —
        // it is intentionally untested here (it would mean prometheus is
        // broken, not that our wrapper is wrong).
        let c = fallback_counter("metrics_util_test_counter_a", "help");
        assert_eq!(c.get(), 0);
        c.inc();
        c.inc();
        assert_eq!(c.get(), 2);
    }

    #[test]
    fn fallback_counter_vec_creates_with_specified_labels() {
        // Pin the labels passed in are honoured: a child looked up by
        // the documented label name must exist and start at zero, and a
        // second distinct label must produce an independent child. A
        // regression that ignored the `labels` argument would make
        // every label collide on a single child.
        let cv = fallback_counter_vec("metrics_util_test_counter_vec_a", "help", &["target"]);
        let a = cv
            .get_metric_with_label_values(&["alpha"])
            .expect("alpha label ok");
        let b = cv
            .get_metric_with_label_values(&["beta"])
            .expect("beta label ok");
        assert_eq!(a.get(), 0);
        assert_eq!(b.get(), 0);
        a.inc();
        a.inc();
        b.inc();
        assert_eq!(a.get(), 2);
        assert_eq!(b.get(), 1);
    }

    #[test]
    fn fallback_gauge_increments_decrements() {
        // `IntGauge` is signed; the helper must preserve that contract.
        // Regression would surface as a switch to `IntCounter`, which
        // would fail on `dec()` at compile time, but pinning negative
        // values makes the intent explicit for future readers.
        let g = fallback_gauge("metrics_util_test_gauge_a", "help");
        assert_eq!(g.get(), 0);
        g.inc();
        g.inc();
        assert_eq!(g.get(), 2);
        g.dec();
        assert_eq!(g.get(), 1);
        g.set(-5);
        assert_eq!(g.get(), -5);
    }

    #[test]
    fn fallback_histogram_records_observations() {
        // Pin the two histogram fields dashboards rely on: the running
        // sample count and the cumulative sum across all observations.
        // A regression that swapped to `Counter` would fail at compile
        // time on `observe`, but pinning count + sum makes it explicit
        // that these are the only two numbers consumers depend on.
        let h = fallback_histogram("metrics_util_test_histogram_a", "help");
        h.observe(0.25);
        h.observe(0.75);
        h.observe(2.0);
        assert_eq!(h.get_sample_count(), 3);
        assert!((h.get_sample_sum() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fallback_gauge_vec_returns_callable_vec() {
        // Sibling to the counter-vec test: confirm gauge-vec children
        // are indexable by label and accept signed writes.
        let gv = fallback_gauge_vec("metrics_util_test_gauge_vec_a", "help", &["peer"]);
        let child = gv
            .get_metric_with_label_values(&["west-1"])
            .expect("label ok");
        assert_eq!(child.get(), 0);
        child.set(42);
        assert_eq!(child.get(), 42);
        child.set(-1);
        assert_eq!(child.get(), -1);
    }

    #[test]
    fn fallback_histogram_vec_records_per_label_observations() {
        // `HistogramVec` per-label children are independent. Pin that
        // behaviour: observations on one label must not bleed into
        // another.
        let hv =
            fallback_histogram_vec("metrics_util_test_histogram_vec_a", "help", &["operation"]);
        let read = hv.with_label_values(&["read"]);
        let write = hv.with_label_values(&["write"]);
        read.observe(1.0);
        read.observe(2.0);
        write.observe(0.5);
        assert_eq!(read.get_sample_count(), 2);
        assert_eq!(write.get_sample_count(), 1);
        assert!((read.get_sample_sum() - 3.0).abs() < f64::EPSILON);
        assert!((write.get_sample_sum() - 0.5).abs() < f64::EPSILON);
    }
}
