// Copyright © 2026 Roberto Chiofalo.

//! W3C Trace Context propagation across the V2 federation gRPC channel.
//!
//! This module provides the inject (outbound) and extract (inbound)
//! helpers that move the W3C `traceparent` and `tracestate` headers
//! across federation RPC boundaries via `tonic::metadata`. PR-B of
//! issue #852.
//!
//! # Wire-format compatibility
//!
//! The header is sent only when the local server has an active span
//! whose OpenTelemetry context is valid (which requires the `otel`
//! feature plus a configured tracer provider). Receivers gracefully
//! tolerate the header's absence — every existing federation peer
//! continues to interoperate cleanly. Malformed inbound headers are
//! audited via [`rustgate_core::audit::federation_traceparent_invalid`]
//! but do not fail the RPC: trace propagation is best-effort.
//!
//! # Local span linkage
//!
//! With the `otel` feature on, [`extract_into_current_span`] consults
//! the inbound `traceparent` and attaches the parsed parent context to
//! `tracing::Span::current()` via `tracing-opentelemetry`'s
//! `OpenTelemetrySpanExt::set_parent`. Downstream telemetry (Jaeger /
//! Tempo) sees the federation hop as a continuation of the upstream
//! trace.
//!
//! With `otel` off, the helper just records a `debug!` event with the
//! parsed header so log-only deployments retain the trace identifier
//! for grep-based correlation.

use rustgate_core::TraceContext;

/// gRPC metadata key for the W3C `traceparent` header.
pub(crate) const TRACEPARENT_HEADER: &str = "traceparent";

/// gRPC metadata key for the W3C `tracestate` companion header.
pub(crate) const TRACESTATE_HEADER: &str = "tracestate";

/// Inject the active `tracing::Span`'s OpenTelemetry trace context into
/// the supplied `tonic::Request` as a W3C `traceparent` (and optional
/// `tracestate`) metadata entry.
///
/// No-ops when no active span has a valid OTel context, or when the
/// `otel` feature is off. The function takes the request by mutable
/// reference so it composes with the existing tonic builder pattern
/// without surfacing an extra return-value indirection.
#[cfg(feature = "otel")]
pub(crate) fn inject_into_request<T>(request: &mut tonic::Request<T>) {
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let cx = tracing::Span::current().context();
    let sc = cx.span().span_context().clone();

    if !sc.is_valid() {
        return;
    }

    // Format `traceparent` directly from the OTel TraceId / SpanId
    // displays. They already render as fixed-width lowercase hex per
    // the OpenTelemetry SDK contract — same approach the HTTP publisher
    // (#917) uses.
    let flags: u8 = if sc.trace_flags().is_sampled() {
        0x01
    } else {
        0x00
    };
    let traceparent = format!("00-{}-{}-{flags:02x}", sc.trace_id(), sc.span_id());

    // Best-effort insertion: a malformed metadata value (would only
    // happen if the upstream OTel SDK emitted a non-ASCII trace id, a
    // contract violation we don't try to recover from) returns Err and
    // we drop the header rather than fail the RPC.
    if let Ok(value) = traceparent.parse::<tonic::metadata::AsciiMetadataValue>() {
        let _ = request.metadata_mut().insert(TRACEPARENT_HEADER, value);
    }

    let ts = sc.trace_state();
    let ts_header = ts.header();
    if !ts_header.is_empty()
        && ts_header.len() <= rustgate_core::MAX_TRACESTATE_BYTES
        && let Ok(value) = ts_header.parse::<tonic::metadata::AsciiMetadataValue>()
    {
        let _ = request.metadata_mut().insert(TRACESTATE_HEADER, value);
    }
}

/// Inject is a no-op when the `otel` feature is disabled. The function
/// is kept defined so call sites do not need their own `cfg` gate.
#[cfg(not(feature = "otel"))]
pub(crate) fn inject_into_request<T>(_request: &mut tonic::Request<T>) {}

/// Extract the W3C `traceparent` header from an inbound gRPC request,
/// parse it into a [`TraceContext`], and return it for the caller to
/// attach to the per-RPC span.
///
/// On malformed headers, emits
/// [`rustgate_core::audit::federation_traceparent_invalid`] tagged
/// with `peer_cn` and the parser error reason, then returns `None` so
/// the RPC continues with no remote parent. Trace-context propagation
/// is best-effort by construction — a misbehaving peer cannot prevent
/// federation traffic from flowing.
///
/// `peer_cn` is the connecting peer's CN extracted from the mTLS
/// client certificate by the FederationService handler; it is the
/// same identifier the rest of the audit pipeline correlates against.
pub(crate) fn extract_from_metadata(
    metadata: &tonic::metadata::MetadataMap,
    peer_cn: &str,
) -> Option<TraceContext> {
    let raw = metadata.get(TRACEPARENT_HEADER)?;
    let raw_str = match raw.to_str() {
        Ok(s) => s,
        Err(e) => {
            rustgate_core::audit::federation_traceparent_invalid(
                peer_cn,
                &format!("traceparent header is not ASCII: {e}"),
            );
            return None;
        }
    };

    let mut ctx: TraceContext = match raw_str.parse() {
        Ok(c) => c,
        Err(err) => {
            rustgate_core::audit::federation_traceparent_invalid(peer_cn, &err.to_string());
            return None;
        }
    };

    // tracestate is optional; an oversize value is rejected by the
    // type's setter and audited so the wire-format invariant lives in
    // exactly one place. `with_tracestate` consumes `self` and returns
    // a fresh `TraceContext`, so we hand it a clone and rebind on
    // success — on error we keep the original `ctx` (the parent
    // context survives even when the companion is dropped).
    if let Some(ts_raw) = metadata.get(TRACESTATE_HEADER) {
        match ts_raw.to_str() {
            Ok(ts_str) => match ctx.clone().with_tracestate(ts_str) {
                Ok(updated) => ctx = updated,
                Err(err) => {
                    rustgate_core::audit::federation_traceparent_invalid(peer_cn, &err.to_string());
                    // Drop the tracestate companion but keep the trace
                    // parent — the `traceparent` itself is well-formed.
                }
            },
            Err(e) => {
                rustgate_core::audit::federation_traceparent_invalid(
                    peer_cn,
                    &format!("tracestate header is not ASCII: {e}"),
                );
            }
        }
    }

    Some(ctx)
}

/// Inbound extraction + span-parent linkage. Reads the W3C trace
/// headers from the request's metadata, audits malformed input, and
/// (with the `otel` feature on) attaches the parsed parent context to
/// the current `tracing::Span` so the per-RPC handler's work appears
/// as a continuation of the upstream trace.
///
/// Returns the parsed [`TraceContext`] when a valid header was
/// present, or `None` when no header was present or it failed
/// validation. Callers may also use the returned value for log
/// correlation independently of the OTel SDK state.
pub(crate) fn extract_into_current_span<T>(
    request: &tonic::Request<T>,
    peer_cn: &str,
) -> Option<TraceContext> {
    let ctx = extract_from_metadata(request.metadata(), peer_cn)?;

    #[cfg(feature = "otel")]
    {
        link_into_current_span(&ctx);
    }

    #[cfg(not(feature = "otel"))]
    {
        // Log-only correlation when no OTel SDK is configured: the
        // banner string still flows into Loki / Elastic via the audit
        // / debug pipeline, so SIEM joins by trace_id remain possible.
        tracing::debug!(traceparent = %ctx, "federation peer trace context received");
    }

    Some(ctx)
}

/// Attach the parsed parent context to the active `tracing::Span` via
/// `tracing-opentelemetry::OpenTelemetrySpanExt::set_parent`. Reachable
/// only with the `otel` feature; pulled out as a free helper so the
/// extraction hot path stays free of OTel SDK references when the
/// feature is off.
#[cfg(feature = "otel")]
fn link_into_current_span(ctx: &TraceContext) {
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let trace_id = TraceId::from_bytes(ctx.trace_id);
    let span_id = SpanId::from_bytes(ctx.parent_span_id);
    let flags = TraceFlags::new(ctx.trace_flags);

    let trace_state = match ctx.tracestate.as_deref() {
        Some(s) => s.parse::<TraceState>().unwrap_or_default(),
        None => TraceState::default(),
    };

    let parent = SpanContext::new(
        trace_id,
        span_id,
        flags,
        /* is_remote = */ true,
        trace_state,
    );
    let parent_cx = opentelemetry::Context::new().with_remote_span_context(parent);

    // `set_parent` returns `Result<(), SetParentError>` — the only
    // failure path is "current span is disabled" (no subscriber, or
    // filter excluded), in which case there is nothing useful to do
    // with the parent context anyway. Discard the result rather than
    // surface the error: trace propagation is best-effort.
    let _ = tracing::Span::current().set_parent(parent_cx);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn sample_traceparent() -> &'static str {
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    }

    #[test]
    fn extract_returns_none_when_metadata_has_no_traceparent() {
        // Pin the absence-tolerant path: a request without the header
        // returns None and no audit event fires (the audit-emission
        // path is only on the malformed branch).
        let req: tonic::Request<()> = tonic::Request::new(());
        let got = extract_from_metadata(req.metadata(), "peer-cn");
        assert!(got.is_none());
    }

    #[test]
    fn extract_parses_well_formed_traceparent() {
        let mut req: tonic::Request<()> = tonic::Request::new(());
        let banner = sample_traceparent();
        let _ = req.metadata_mut().insert(
            TRACEPARENT_HEADER,
            banner
                .parse::<tonic::metadata::AsciiMetadataValue>()
                .unwrap(),
        );
        let got = extract_from_metadata(req.metadata(), "peer-cn").expect("parse");
        assert_eq!(got.to_string(), banner);
        assert!(got.tracestate.is_none());
    }

    #[test]
    fn extract_rejects_malformed_traceparent_and_returns_none() {
        // Malformed banner falls through to None without panicking.
        let mut req: tonic::Request<()> = tonic::Request::new(());
        let _ = req.metadata_mut().insert(
            TRACEPARENT_HEADER,
            "not-a-valid-traceparent"
                .parse::<tonic::metadata::AsciiMetadataValue>()
                .unwrap(),
        );
        let got = extract_from_metadata(req.metadata(), "peer-cn");
        assert!(
            got.is_none(),
            "malformed traceparent must yield None at the helper boundary"
        );
    }

    #[test]
    fn extract_carries_tracestate_alongside_well_formed_traceparent() {
        let mut req: tonic::Request<()> = tonic::Request::new(());
        let _ = req.metadata_mut().insert(
            TRACEPARENT_HEADER,
            sample_traceparent()
                .parse::<tonic::metadata::AsciiMetadataValue>()
                .unwrap(),
        );
        let _ = req.metadata_mut().insert(
            TRACESTATE_HEADER,
            "vendor=value,other=42"
                .parse::<tonic::metadata::AsciiMetadataValue>()
                .unwrap(),
        );
        let got = extract_from_metadata(req.metadata(), "peer-cn").expect("parse");
        assert_eq!(got.tracestate.as_deref(), Some("vendor=value,other=42"));
    }

    #[test]
    fn extract_drops_oversize_tracestate_but_keeps_traceparent() {
        // 513-byte tracestate exceeds the 512-byte W3C cap. Pin that
        // the parent context survives even when the companion is
        // dropped — propagation is best-effort, never all-or-nothing.
        let mut req: tonic::Request<()> = tonic::Request::new(());
        let _ = req.metadata_mut().insert(
            TRACEPARENT_HEADER,
            sample_traceparent()
                .parse::<tonic::metadata::AsciiMetadataValue>()
                .unwrap(),
        );
        let oversize = "x".repeat(rustgate_core::MAX_TRACESTATE_BYTES + 1);
        let _ = req.metadata_mut().insert(
            TRACESTATE_HEADER,
            oversize
                .parse::<tonic::metadata::AsciiMetadataValue>()
                .unwrap(),
        );
        let got = extract_from_metadata(req.metadata(), "peer-cn").expect("parse");
        assert!(got.tracestate.is_none(), "oversize tracestate must drop");
    }

    #[cfg(not(feature = "otel"))]
    #[test]
    fn inject_is_a_no_op_when_otel_feature_is_off() {
        // Wire-format compatibility for non-OTel builds: the inject
        // helper exists but inserts no metadata.
        let mut req: tonic::Request<()> = tonic::Request::new(());
        inject_into_request(&mut req);
        assert!(req.metadata().get(TRACEPARENT_HEADER).is_none());
        assert!(req.metadata().get(TRACESTATE_HEADER).is_none());
    }

    #[test]
    fn header_constants_are_lowercase() {
        // tonic ASCII metadata keys are case-insensitive but the
        // canonical form is lowercase. Pin both keys here so a future
        // refactor cannot regress the wire-form contract.
        assert_eq!(TRACEPARENT_HEADER, "traceparent");
        assert_eq!(TRACESTATE_HEADER, "tracestate");
    }
}
