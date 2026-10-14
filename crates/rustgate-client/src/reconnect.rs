// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Background read/write loop with optional exponential-backoff reconnect.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    disconnected: Arc<AtomicBool>,
) {
    let mut current = Some(initial);
    let mut attempts: u32 = 0;
    let policy = config.reconnect;
    // Message popped from `out_rx` but not yet confirmed written. Held across
    // a reconnect so a send that fails mid-frame is retried on the next
    // connection instead of being silently dropped (M-13).
    let mut pending: Option<Bytes> = None;

    loop {
        // `disconnect()` sets this flag *then* fires `notify_waiters()`. That
        // notify only wakes tasks currently parked in `shutdown.notified()`;
        // if it races with the loop being inside `dial()`/`read_loop`/
        // `write_loop`, the wakeup is lost and `disconnect().await` would hang
        // forever on `task.await`. Re-checking the flag at the top of every
        // iteration (Acquire pairs with the Release store in `disconnect()`)
        // closes that lost-wakeup window: whenever an inner future returns,
        // we observe the flag and exit (H-9).
        if disconnected.load(Ordering::Acquire) {
            debug!("client run loop exiting; disconnect requested");
            return;
        }

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

        // Second check, after (re)dialing: `notify_waiters()` stores no
        // permit, so a `disconnect()` that fired *while we were inside
        // `dial()`* would be lost by the `shutdown.notified()` branch below
        // and the select could park forever if the peer is idle. Re-reading
        // the flag here (Acquire) before entering the select guarantees we
        // never block on a connection the caller has already abandoned (H-9).
        if disconnected.load(Ordering::Acquire) {
            debug!("client run loop exiting; disconnect requested after dial");
            return;
        }

        let (read_half, write_half) = tokio::io::split(stream);
        let mut framed_read = FramedRead::new(read_half, config.codec.to_framed());
        let mut framed_write = FramedWrite::new(write_half, config.codec.to_framed());

        let exit_reason = tokio::select! {
            _ = shutdown.notified() => ExitReason::Shutdown,
            r = read_loop(&mut framed_read, &inbound) => r,
            r = write_loop(&mut framed_write, &mut out_rx, &mut pending) => r,
        };

        // Best-effort close_notify on graceful exit.
        if matches!(exit_reason, ExitReason::Shutdown) {
            let mut writer = framed_write.into_inner();
            let _ = writer.shutdown().await;
            return;
        }

        // A closed `out_rx` (all `Client` senders dropped) is permanent — no
        // reconnect can revive it, so treat it as terminal rather than
        // spinning the backoff loop against a dead channel forever (L-4).
        if matches!(exit_reason, ExitReason::WriteEnded) {
            debug!("client run loop exiting; outbound channel closed");
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
    pending: &mut Option<Bytes>,
) -> ExitReason
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        // Prefer a payload left over from a prior connection whose send did
        // not durably complete; only pull a fresh one from the channel when
        // the slot is empty.
        let payload = match pending.take() {
            Some(p) => p,
            None => match out_rx.recv().await {
                Some(p) => p,
                None => return ExitReason::WriteEnded,
            },
        };
        let buf = BytesMut::from(payload.as_ref());
        // Stash the in-flight payload in `pending` (owned by `run()`) BEFORE
        // the send await. If this future is CANCELLED mid-send — the read
        // side wins the `select!` in `run()` when the connection dies — the
        // payload survives in `pending` on `run()`'s stack instead of being
        // orphaned on this frame, and the next connection retries it. It is
        // cleared only once `send` durably returns `Ok` (M-13).
        *pending = Some(payload);
        if let Err(e) = framed.send(buf).await {
            warn!(error = %e, "client write error");
            // `pending` still holds the payload; the next connection retries.
            return ExitReason::WriteError;
        }
        *pending = None;
    }
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

    // ---- write_loop message-loss regression (M-13) ----

    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// An `AsyncWrite` whose first `poll_write` fails, simulating a
    /// connection that dies the instant we try to flush a frame.
    struct FailingWriter;

    impl tokio::io::AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "simulated connection reset",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A writer that always accepts and discards bytes — a black hole that
    /// lets `write_loop` drain the channel to completion without error.
    struct SinkWriter;

    impl tokio::io::AsyncWrite for SinkWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Writer whose `poll_write`/`poll_flush` never complete, so a
    /// `framed.send` parks forever — letting a test cancel `write_loop`
    /// mid-send (as `run()`'s `select!` does when the read side wins).
    struct BlockingWriter;

    impl tokio::io::AsyncWrite for BlockingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    fn test_codec() -> rustgate_transport::FramedCodec {
        use rustgate_core::protocol::{FramingStrategy, HeaderSize};
        rustgate_transport::FramedCodec::try_from_strategy(&FramingStrategy::LengthPrefixed {
            header_size: HeaderSize::Four,
        })
        .expect("length-prefixed strategy is always available")
    }

    #[tokio::test]
    async fn write_loop_preserves_message_when_send_fails() {
        // M-13: a payload popped from the channel whose `send` fails must be
        // stashed in `pending`, not dropped. Without the fix the byte string
        // would be lost the moment the connection reset.
        let (tx, mut rx) = mpsc::channel::<Bytes>(4);
        tx.send(Bytes::from_static(b"critical")).await.unwrap();
        drop(tx); // close the channel so the loop can't block waiting for more

        let mut framed = FramedWrite::new(FailingWriter, test_codec());
        let mut pending: Option<Bytes> = None;

        let reason = write_loop(&mut framed, &mut rx, &mut pending).await;

        assert!(
            matches!(reason, ExitReason::WriteError),
            "failing writer must surface WriteError, got {reason:?}",
        );
        assert_eq!(
            pending.as_deref(),
            Some(&b"critical"[..]),
            "the un-acked payload must be retained in `pending` for retry",
        );
    }

    #[tokio::test]
    async fn write_loop_drains_pending_before_channel() {
        // A payload left over from a prior failed connection (in `pending`)
        // must be sent on the next connection *before* any newer channel
        // messages, and cleared from the slot once written. This proves the
        // retry path actually retries rather than silently draining `pending`.
        let (tx, mut rx) = mpsc::channel::<Bytes>(4);
        tx.send(Bytes::from_static(b"fresh")).await.unwrap();
        drop(tx);

        let mut framed = FramedWrite::new(SinkWriter, test_codec());
        let mut pending: Option<Bytes> = Some(Bytes::from_static(b"retry-me"));

        let reason = write_loop(&mut framed, &mut rx, &mut pending).await;

        // Channel drained to completion (both the retried and fresh payload).
        assert!(
            matches!(reason, ExitReason::WriteEnded),
            "sink writer should drain the channel to WriteEnded, got {reason:?}",
        );
        assert!(
            pending.is_none(),
            "pending must be cleared once the retried payload is written",
        );
    }

    #[tokio::test]
    async fn write_loop_retains_payload_when_cancelled_mid_send() {
        // M-13 cancellation path: when the connection dies the read side wins
        // `run()`'s `select!` and `write_loop` is dropped mid-`send`. Because
        // the payload is stashed in `pending` (owned by `run()`) *before* the
        // send await, the cancellation must not orphan it — the next
        // connection retries it. This is the vector the send-error test alone
        // does not cover.
        let (tx, mut rx) = mpsc::channel::<Bytes>(4);
        tx.send(Bytes::from_static(b"in-flight")).await.unwrap();
        // Keep `tx` alive: the payload is already queued, and we want the send
        // (not the recv) to be the parked await when cancellation strikes.

        let mut framed = FramedWrite::new(BlockingWriter, test_codec());
        let mut pending: Option<Bytes> = None;

        // Poll `write_loop` until it parks on the blocking send, then cancel
        // it by dropping the future (the sleep branch wins).
        tokio::select! {
            _ = write_loop(&mut framed, &mut rx, &mut pending) => {
                panic!("write_loop must block on the send, not return");
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }

        assert_eq!(
            pending.as_deref(),
            Some(&b"in-flight"[..]),
            "the in-flight payload must be stashed in `pending` before the send \
             await so a mid-send cancellation does not drop it",
        );
        drop(tx);
    }
}
