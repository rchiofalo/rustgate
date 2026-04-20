// Copyright © 2026 Roberto Chiofalo.

//! Background read/write loop with optional exponential-backoff reconnect.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rustgate_core::constants::CLIENT_MAX_RECONNECT_DELAY;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, broadcast, mpsc};
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, warn};

use crate::connect::{Stream, dial};
use crate::{ClientConfig, ClientError, Message};

/// Exponential backoff policy for reconnect attempts.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// Initial delay before the first retry.
    pub initial_backoff: Duration,
    /// Maximum delay between retries.
    pub max_backoff: Duration,
    /// Maximum number of attempts before giving up. `0` means infinite.
    pub max_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(100),
            max_backoff: CLIENT_MAX_RECONNECT_DELAY,
            max_attempts: 10,
        }
    }
}

pub(crate) async fn run(
    config: ClientConfig,
    initial: Stream,
    mut out_rx: mpsc::Receiver<Bytes>,
    inbound: broadcast::Sender<Message>,
    shutdown: Arc<Notify>,
) {
    let mut current = Some(initial);
    let mut attempts: u32 = 0;
    let policy = config.reconnect;

    loop {
        // Acquire a stream — either the existing one or a freshly redialed one.
        let stream = match current.take() {
            Some(s) => s,
            None => match policy {
                None => {
                    debug!("client run loop exiting; reconnect disabled");
                    return;
                }
                Some(p) => {
                    attempts += 1;
                    if p.max_attempts != 0 && attempts > p.max_attempts {
                        warn!(attempts, "reconnect attempts exhausted");
                        return;
                    }
                    let backoff = compute_backoff(p, attempts);
                    debug!(?backoff, attempts, "client reconnecting after backoff");
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown.notified() => return,
                    }
                    match dial(&config).await {
                        Ok(s) => {
                            attempts = 0;
                            s
                        }
                        Err(e) => {
                            if is_fatal_dial_error(&e) {
                                warn!(error = %e, "client redial failed with fatal error; giving up");
                                return;
                            }
                            warn!(error = %e, "client redial failed");
                            continue;
                        }
                    }
                }
            },
        };

        let (read_half, write_half) = tokio::io::split(stream);
        let mut framed_read = FramedRead::new(read_half, config.codec.to_framed());
        let mut framed_write = FramedWrite::new(write_half, config.codec.to_framed());

        let exit_reason = tokio::select! {
            _ = shutdown.notified() => ExitReason::Shutdown,
            r = read_loop(&mut framed_read, &inbound) => r,
            r = write_loop(&mut framed_write, &mut out_rx) => r,
        };

        // Best-effort close_notify on graceful exit.
        if matches!(exit_reason, ExitReason::Shutdown) {
            let mut writer = framed_write.into_inner();
            let _ = writer.shutdown().await;
            return;
        }

        debug!(?exit_reason, "client connection lost");
        if policy.is_none() {
            return;
        }
    }
}

#[derive(Debug)]
enum ExitReason {
    Shutdown,
    ReadEnded,
    ReadError,
    WriteEnded,
    WriteError,
}

async fn read_loop<R>(
    framed: &mut FramedRead<R, rustgate_transport::FramedCodec>,
    inbound: &broadcast::Sender<Message>,
) -> ExitReason
where
    R: tokio::io::AsyncRead + Unpin,
{
    while let Some(frame) = framed.next().await {
        match frame {
            Ok(bytes) => {
                let msg = Message {
                    payload: bytes.freeze(),
                };
                // Ignore lag/no-receivers — broadcast keeps going.
                let _ = inbound.send(msg);
            }
            Err(e) => {
                warn!(error = %e, "client read error");
                return ExitReason::ReadError;
            }
        }
    }
    ExitReason::ReadEnded
}

async fn write_loop<W>(
    framed: &mut FramedWrite<W, rustgate_transport::FramedCodec>,
    out_rx: &mut mpsc::Receiver<Bytes>,
) -> ExitReason
where
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(payload) = out_rx.recv().await {
        let buf = BytesMut::from(payload.as_ref());
        if let Err(e) = framed.send(buf).await {
            warn!(error = %e, "client write error");
            return ExitReason::WriteError;
        }
    }
    ExitReason::WriteEnded
}

fn is_fatal_dial_error(e: &ClientError) -> bool {
    matches!(
        e,
        ClientError::Tls(_) | ClientError::CertParse(_) | ClientError::MissingField(_)
    )
}

fn compute_backoff(policy: ReconnectPolicy, attempt: u32) -> Duration {
    // 100ms, 200ms, 400ms, ... capped at max_backoff, with ±20% uniform jitter.
    let exp = attempt.saturating_sub(1).min(20);
    let multiplier = 1u64 << exp;
    let nanos = policy
        .initial_backoff
        .as_nanos()
        .saturating_mul(multiplier as u128);
    let dur = Duration::from_nanos(nanos.min(u64::MAX as u128) as u64);
    let capped = dur.min(policy.max_backoff);
    // ±20% jitter: multiply by a factor in [0.8, 1.2).
    let base_nanos = capped.as_nanos() as u64;
    if base_nanos == 0 {
        return capped;
    }
    let jitter_range = (base_nanos / 5).saturating_mul(2); // 40% of base
    let offset = fastrand::u64(0..=jitter_range);
    let jittered = base_nanos
        .saturating_sub(base_nanos / 5)
        .saturating_add(offset);
    Duration::from_nanos(jittered)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::clone_on_copy)]

    use super::*;

    fn in_jitter_range(actual: Duration, base_ms: u64) -> bool {
        let lo = Duration::from_nanos((base_ms * 1_000_000) * 80 / 100);
        let hi = Duration::from_nanos((base_ms * 1_000_000) * 120 / 100);
        actual >= lo && actual <= hi
    }

    #[test]
    fn backoff_grows_then_caps() {
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            max_attempts: 0,
        };
        // Sample several times; each call must stay within ±20% of the expected base.
        for _ in 0..32 {
            assert!(in_jitter_range(compute_backoff(p, 1), 100));
            assert!(in_jitter_range(compute_backoff(p, 2), 200));
            assert!(in_jitter_range(compute_backoff(p, 3), 400));
            assert!(in_jitter_range(compute_backoff(p, 20), 30_000));
        }
    }

    #[test]
    fn default_policy_matches_documented_values() {
        // The default policy is the surface every Client that takes
        // `.reconnect(Default::default())` inherits. Pin it so a later
        // change to the numbers is an explicit, reviewable diff rather
        // than a silent behaviour shift on every downstream caller.
        let p = ReconnectPolicy::default();
        assert_eq!(p.initial_backoff, Duration::from_millis(100));
        assert_eq!(p.max_backoff, CLIENT_MAX_RECONNECT_DELAY);
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.max_attempts, 10);
    }

    #[test]
    fn backoff_attempt_zero_uses_base_interval_without_shift() {
        // `attempt == 0` is an unusual call site — the production loop
        // always increments attempts to at least 1 before calling — but
        // the function must not panic on shift-by-underflow if a future
        // call site passes 0. `saturating_sub(1)` on a `u32` yields 0,
        // so the multiplier is `1 << 0 = 1` and the output equals the
        // base interval (before jitter). Pinning this guards against a
        // refactor that replaces the saturating sub with a plain `-`.
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            max_attempts: 0,
        };
        for _ in 0..32 {
            assert!(in_jitter_range(compute_backoff(p, 0), 100));
        }
    }

    #[test]
    fn backoff_clamps_shift_at_attempt_twenty_one() {
        // Exponential shift is clamped at `.min(20)` so the doubling
        // cannot overflow for very large attempt counts. At attempt 21
        // the multiplier must still be `2^20 = 1_048_576`, not `2^21`;
        // the cap-to-`max_backoff` then brings it back down to 30s
        // regardless. Pin this so a refactor that drops the `.min(20)`
        // (and therefore overflows `1u64 << attempt` at attempt 64)
        // fails CI.
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            max_attempts: 0,
        };
        for attempt in [21u32, 100, 1_000, u32::MAX] {
            for _ in 0..16 {
                // Must not panic, must cap at max_backoff with jitter.
                assert!(
                    in_jitter_range(compute_backoff(p, attempt), 30_000),
                    "attempt {attempt} produced out-of-range backoff",
                );
            }
        }
    }

    #[test]
    fn backoff_with_zero_initial_returns_zero() {
        // When the policy sets `initial_backoff = 0`, the computed
        // duration has zero nanos — the jitter helper short-circuits
        // to return the capped duration untouched. Without that early
        // return, `base_nanos / 5` would be 0 and `fastrand::u64(0..=0)`
        // would panic on `gen_range` with an empty range in older
        // `fastrand` versions. Pin the short-circuit so a library bump
        // that drops the early return surfaces here.
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_nanos(0),
            max_backoff: Duration::from_secs(30),
            max_attempts: 0,
        };
        assert_eq!(compute_backoff(p, 5), Duration::from_nanos(0));
    }

    #[test]
    fn backoff_with_zero_max_returns_zero() {
        // `max_backoff = 0` is a nonsensical-but-legal config. The
        // cap should flatten the output to zero before the jitter
        // step runs. Same justification as the zero-initial case —
        // we must not panic on empty-range jitter.
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_nanos(0),
            max_attempts: 0,
        };
        assert_eq!(compute_backoff(p, 3), Duration::from_nanos(0));
    }

    #[test]
    fn backoff_jitter_actually_varies_within_band() {
        // The jitter distribution is the whole point of the retry
        // primitive — multiple clients that fail at the same instant
        // must not redial in lockstep (thundering herd). Sample 64
        // draws at attempt 5 (base 1600ms under our policy) and assert
        // the output set spans a visible fraction of the ±20% band.
        // With `fastrand::u64(0..=jitter_range)`, the probability that
        // 64 draws all land within the middle 10% of the band is
        // astronomically small (< 2^-60), so a regression to constant
        // output almost-certainly fails this test. The bound is also
        // loose enough that natural seeded-RNG determinism in CI does
        // not flake it.
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            max_attempts: 0,
        };
        let samples: Vec<Duration> = (0..64).map(|_| compute_backoff(p, 5)).collect();
        let min = samples.iter().min().expect("non-empty");
        let max = samples.iter().max().expect("non-empty");
        // At attempt 5, base is 100ms * 2^4 = 1600ms. The ±20% band
        // spans 1280ms..=1920ms (640ms wide). Assert the observed
        // spread exceeds 100ms (~16% of the band).
        let spread = max.saturating_sub(*min);
        assert!(
            spread > Duration::from_millis(100),
            "jitter spread {spread:?} < 100ms (min {min:?}, max {max:?}); RNG regression?",
        );
    }

    #[test]
    fn is_fatal_dial_error_returns_true_for_tls_cert_and_missing_field() {
        // These three error kinds mean the client is structurally
        // misconfigured — retrying without operator intervention
        // cannot succeed. The reconnect loop must give up immediately
        // instead of spinning through the full retry budget and
        // emitting a log storm. Pin each variant so a future refactor
        // that narrows the match arm (e.g. removes `MissingField`)
        // fails CI.
        assert!(is_fatal_dial_error(&ClientError::Tls("bad root".into())));
        assert!(is_fatal_dial_error(&ClientError::CertParse(
            "not PEM".into()
        )));
        assert!(is_fatal_dial_error(&ClientError::MissingField(
            "server_addr",
        )));
    }

    #[test]
    fn is_fatal_dial_error_returns_false_for_transient_and_io_failures() {
        // Every non-fatal variant must keep the reconnect loop alive —
        // an `Io` error is almost always "connection refused" or
        // "network unreachable" while the server is restarting, and a
        // `ConnectTimeout` fires when the server is slow to accept on a
        // new port. Treating either as fatal would defeat the reason
        // the reconnect loop exists. `Disconnected`, `ReconnectExhausted`,
        // and `Lagged` are not produced by the dial path at all — they
        // come from the caller-side send/recv surface — but are pinned
        // here so a future classification refactor that accidentally
        // widens the fatal set (e.g. treats every non-network error
        // as fatal) fails.
        assert!(!is_fatal_dial_error(&ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ))));
        assert!(!is_fatal_dial_error(&ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::NetworkUnreachable,
            "unreachable",
        ))));
        assert!(!is_fatal_dial_error(&ClientError::ConnectTimeout(
            Duration::from_secs(5)
        )));
        assert!(!is_fatal_dial_error(&ClientError::Disconnected));
        assert!(!is_fatal_dial_error(&ClientError::ReconnectExhausted(10)));
        assert!(!is_fatal_dial_error(&ClientError::Lagged { dropped: 3 }));
    }

    #[test]
    fn reconnect_policy_is_copy_and_clone() {
        // The policy is carried by value through `ClientConfig` and the
        // reconnect loop dereferences it on every iteration. Losing
        // `Copy` would silently force a `.clone()` on every call site
        // and change the ergonomics of `.with_reconnect(Default::default())`
        // across the public API. Pin the traits with a move-then-use
        // pattern that only compiles while `Copy` is implemented.
        let p = ReconnectPolicy::default();
        let copy = p;
        let _after_move = p; // still usable only if `Copy`
        let cloned = copy.clone();
        assert_eq!(cloned.initial_backoff, p.initial_backoff);
        assert_eq!(cloned.max_backoff, p.max_backoff);
        assert_eq!(cloned.max_attempts, p.max_attempts);
    }

    #[test]
    fn reconnect_policy_debug_exposes_all_fields() {
        // Operators grep production logs for this debug repr when a
        // client misbehaves. Pin that all three fields appear in the
        // output so a future `#[derive(Debug)]` replacement with a
        // hand-rolled impl that accidentally omits a field fails CI.
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(42),
            max_attempts: 7,
        };
        let rendered = format!("{p:?}");
        assert!(
            rendered.contains("initial_backoff"),
            "debug output {rendered} missing initial_backoff",
        );
        assert!(
            rendered.contains("max_backoff"),
            "debug output {rendered} missing max_backoff",
        );
        assert!(
            rendered.contains("max_attempts"),
            "debug output {rendered} missing max_attempts",
        );
        assert!(
            rendered.contains('7'),
            "debug output {rendered} missing max_attempts value",
        );
    }
}
