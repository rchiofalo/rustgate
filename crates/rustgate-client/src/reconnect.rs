// Copyright © 2026 Roberto Chiofalo.

//! Background read/write loop with optional exponential-backoff reconnect.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
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
            max_backoff: Duration::from_secs(30),
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
    #![allow(clippy::panic, clippy::unwrap_used)]

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
}
