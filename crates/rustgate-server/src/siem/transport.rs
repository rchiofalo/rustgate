// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Syslog-over-TLS (RFC 5425) sender for the SIEM forwarder.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustgate_core::constants::{HANDSHAKE_TIMEOUT, WRITE_TIMEOUT};
use rustgate_core::secrets::{SecretFileOpts, read_secret_file};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{info, warn};

use super::format::{Format, syslog_frame};
use super::layer::{AuditRecord, Stats};
use super::redact::Redactor;

/// Delay before the first reconnect; doubles per consecutive failure up to
/// the shared cap (`rustgate_resilience::reconnect`).
const RECONNECT_BASE: Duration = Duration::from_secs(1);
/// A connection that stays up this long resets the backoff. A collector
/// that accepts and then drops every connection therefore backs off
/// instead of being redialled in a tight loop.
const HEALTHY_CONNECTION: Duration = Duration::from_secs(30);
/// Shutdown budget: flushing queued records, then closing. Together they
/// stay inside `stop_subsystem`'s 5 s limit.
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(3);
const SHUTDOWN_CLOSE: Duration = Duration::from_secs(1);

type Writer = WriteHalf<TlsStream<TcpStream>>;

/// Everything the sender needs, built and validated at startup.
pub(crate) struct Sender {
    pub(crate) endpoint: String,
    pub(crate) server_name: ServerName<'static>,
    pub(crate) connector: TlsConnector,
    pub(crate) format: Format,
    pub(crate) hostname: String,
    pub(crate) stats: Arc<Stats>,
    /// Pseudonymizes classification-linked events; `None` with
    /// `--siem-include-classified`.
    pub(crate) redactor: Option<Redactor>,
}

/// How a connection ended.
enum Ended {
    /// Shutdown was requested; nothing more to do.
    Shutdown,
    /// Every sender is gone (the subscriber was dropped).
    QueueClosed,
    /// The connection failed; reconnect.
    Failed(std::io::Error),
}

/// Build the TLS client config: trust only the certificates in `ca`, and
/// present `cert`/`key` when both are given.
pub(crate) fn client_config(
    ca: &Path,
    cert_and_key: Option<(&Path, &Path)>,
) -> anyhow::Result<rustls::ClientConfig> {
    let ca_pem = std::fs::read(ca)
        .map_err(|e| anyhow::anyhow!("failed to read --siem-ca {}: {e}", ca.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustgate_core::pem::parse_certs(&ca_pem)
        .map_err(|e| anyhow::anyhow!("failed to parse --siem-ca {}: {e}", ca.display()))?
    {
        roots
            .add(cert)
            .map_err(|e| anyhow::anyhow!("invalid certificate in --siem-ca: {e}"))?;
    }
    if roots.is_empty() {
        anyhow::bail!("--siem-ca {} contains no certificates", ca.display());
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let config = match cert_and_key {
        Some((cert, key)) => {
            let cert_pem = std::fs::read(cert).map_err(|e| {
                anyhow::anyhow!("failed to read --siem-cert {}: {e}", cert.display())
            })?;
            let certs = rustgate_core::pem::parse_certs(&cert_pem)
                .map_err(|e| anyhow::anyhow!("failed to parse --siem-cert: {e}"))?;
            let key_pem = read_secret_file(key, &SecretFileOpts::with_max_bytes(16 * 1024))
                .map_err(|e| anyhow::anyhow!("failed to read --siem-key: {e}"))?;
            let key = rustgate_core::pem::parse_key(key_pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("failed to parse --siem-key: {e}"))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("invalid --siem-cert/--siem-key pair: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(config)
}

impl Sender {
    /// Forward records until `shutdown` fires or every sender is gone.
    pub(crate) async fn run(self, mut rx: mpsc::Receiver<AuditRecord>, shutdown: Arc<Notify>) {
        let pid = std::process::id();
        let mut failures: u32 = 0;
        // A frame whose write failed; retried once on the next connection.
        let mut retry: Option<Vec<u8>> = None;

        loop {
            let connected = tokio::select! {
                () = shutdown.notified() => {
                    self.final_flush(&mut rx, retry.take(), pid).await;
                    return;
                }
                connected = self.connect() => connected,
            };
            let ended = match connected {
                Ok(stream) => {
                    let connected_at = Instant::now();
                    rustgate_core::audit::siem_connected(&self.endpoint);
                    #[cfg(feature = "metrics")]
                    crate::metrics::siem_connected().set(1);
                    let ended = self
                        .serve(stream, &mut rx, &mut retry, &shutdown, pid)
                        .await;
                    if let Ended::Failed(error) = &ended {
                        self.disconnected(error);
                        if connected_at.elapsed() >= HEALTHY_CONNECTION {
                            failures = 0;
                        }
                    }
                    ended
                }
                Err(error) => {
                    warn!(endpoint = %self.endpoint, error = %error, "SIEM connection failed");
                    Ended::Failed(error)
                }
            };
            match ended {
                Ended::Shutdown | Ended::QueueClosed => return,
                Ended::Failed(_) => {
                    let delay =
                        rustgate_resilience::reconnect::backoff_delay(RECONNECT_BASE, failures);
                    failures = failures.saturating_add(1);
                    tokio::select! {
                        () = shutdown.notified() => {
                            self.final_flush(&mut rx, retry.take(), pid).await;
                            return;
                        }
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
    }

    /// Write queued records to one connection until it fails, shutdown is
    /// requested, or the queue closes.
    async fn serve(
        &self,
        stream: TlsStream<TcpStream>,
        rx: &mut mpsc::Receiver<AuditRecord>,
        retry: &mut Option<Vec<u8>>,
        shutdown: &Notify,
        pid: u32,
    ) -> Ended {
        let (mut reader, mut writer) = tokio::io::split(stream);
        if let Some(frame) = retry.take() {
            tokio::select! {
                biased;
                () = shutdown.notified() => {
                    self.count_undelivered(1 + drain_count(rx));
                    return Ended::Shutdown;
                }
                written = self.write(&mut writer, &frame) => {
                    if let Err(error) = written {
                        // Second failure for this frame: give up on it.
                        self.count_undelivered(1);
                        return Ended::Failed(error);
                    }
                }
            }
        }
        let mut reported_drops = self.stats.dropped_queue_full.load(Ordering::Relaxed);
        let mut scratch = [0u8; 512];
        loop {
            let dropped = self.stats.dropped_queue_full.load(Ordering::Relaxed);
            if dropped > reported_drops {
                warn!(endpoint = %self.endpoint, dropped_total = dropped, "SIEM queue full; audit events dropped");
                reported_drops = dropped;
            }
            tokio::select! {
                biased;
                () = shutdown.notified() => {
                    self.flush(&mut writer, rx, pid).await;
                    close(&mut writer).await;
                    return Ended::Shutdown;
                }
                // The collector sends nothing, so a completed read means it
                // hung up or sent an alert. Watching for it catches a dead
                // connection before more records are written into it.
                read = reader.read(&mut scratch) => match read {
                    Ok(0) => {
                        return Ended::Failed(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "collector closed the connection",
                        ));
                    }
                    Ok(_) => {}
                    Err(error) => return Ended::Failed(error),
                },
                record = rx.recv() => {
                    let Some(record) = record else {
                        close(&mut writer).await;
                        return Ended::QueueClosed;
                    };
                    let frame = self.frame(record, pid);
                    tokio::select! {
                        biased;
                        // A stalled collector must not hold shutdown past its
                        // budget; the partly written frame is abandoned.
                        () = shutdown.notified() => {
                            self.count_undelivered(1 + drain_count(rx));
                            return Ended::Shutdown;
                        }
                        written = self.write(&mut writer, &frame) => {
                            if let Err(error) = written {
                                *retry = Some(frame);
                                return Ended::Failed(error);
                            }
                        }
                    }
                }
            }
        }
    }

    /// While disconnected at shutdown: one bounded attempt to connect and
    /// deliver the queue, so the final records (e.g. the audit-chain
    /// anchor) still reach a collector that has come back.
    async fn final_flush(
        &self,
        rx: &mut mpsc::Receiver<AuditRecord>,
        retry: Option<Vec<u8>>,
        pid: u32,
    ) {
        let mut lost = usize::from(retry.is_some());
        let delivered = tokio::time::timeout(SHUTDOWN_FLUSH, async {
            let stream = self.connect().await.ok()?;
            let (_reader, mut writer) = tokio::io::split(stream);
            if let Some(frame) = retry {
                self.write(&mut writer, &frame).await.ok()?;
            }
            lost = 0;
            while let Ok(record) = rx.try_recv() {
                // Counted as lost until written, so a timeout mid-write is
                // still counted.
                lost = 1;
                let frame = self.frame(record, pid);
                self.write(&mut writer, &frame).await.ok()?;
                lost = 0;
            }
            close(&mut writer).await;
            Some(())
        })
        .await;
        if !matches!(delivered, Ok(Some(()))) {
            warn!(
                endpoint = %self.endpoint,
                "SIEM collector unreachable at shutdown; queued audit events not forwarded"
            );
        }
        self.count_undelivered(lost + drain_count(rx));
    }

    /// Redact (unless `--siem-include-classified`) and frame one record.
    fn frame(&self, record: AuditRecord, pid: u32) -> Vec<u8> {
        let record = match &self.redactor {
            Some(redactor) => redactor.redact(record),
            None => record,
        };
        syslog_frame(&record, self.format, &self.hostname, pid)
    }

    async fn connect(&self) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(&self.endpoint))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP connect timed out")
            })??;
        rustgate_core::net::configure_tactical_socket(&tcp);
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out"))?
    }

    async fn write<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        frame: &[u8],
    ) -> std::io::Result<()> {
        let result = tokio::time::timeout(WRITE_TIMEOUT, async {
            writer.write_all(frame).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out"))?;
        if result.is_ok() {
            let _ = self.stats.sent.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "metrics")]
            crate::metrics::siem_events_sent().inc();
        }
        result
    }

    /// Write whatever is already queued, within [`SHUTDOWN_FLUSH`]; count
    /// anything left over as undelivered.
    async fn flush(&self, writer: &mut Writer, rx: &mut mpsc::Receiver<AuditRecord>, pid: u32) {
        // A record taken from the queue but not yet written; counted if the
        // write fails or the budget runs out mid-write.
        let mut in_flight = 0usize;
        let _ = tokio::time::timeout(SHUTDOWN_FLUSH, async {
            while let Ok(record) = rx.try_recv() {
                in_flight = 1;
                let frame = self.frame(record, pid);
                if self.write(writer, &frame).await.is_err() {
                    return;
                }
                in_flight = 0;
            }
        })
        .await;
        self.count_undelivered(in_flight + drain_count(rx));
        info!(
            endpoint = %self.endpoint,
            sent_total = self.stats.sent.load(Ordering::Relaxed),
            "SIEM forwarder stopped"
        );
    }

    fn disconnected(&self, error: &std::io::Error) {
        warn!(endpoint = %self.endpoint, error = %error, "SIEM connection lost");
        rustgate_core::audit::siem_disconnected(&self.endpoint, &error.to_string());
        #[cfg(feature = "metrics")]
        crate::metrics::siem_connected().set(0);
    }

    fn count_undelivered(&self, n: usize) {
        if n == 0 {
            return;
        }
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        let _ = self
            .stats
            .dropped_undelivered
            .fetch_add(n, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        crate::metrics::siem_events_dropped()
            .with_label_values(&["undelivered"])
            .inc_by(n);
    }
}

/// Send TLS close_notify, within [`SHUTDOWN_CLOSE`].
async fn close(writer: &mut Writer) {
    let _ = tokio::time::timeout(SHUTDOWN_CLOSE, writer.shutdown()).await;
}

fn drain_count(rx: &mut mpsc::Receiver<AuditRecord>) -> usize {
    let mut n = 0;
    while rx.try_recv().is_ok() {
        n += 1;
    }
    n
}
