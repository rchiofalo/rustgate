// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Forwards the audit trail to a SIEM over syslog-over-TLS (ADR 0038).
//!
//! Off unless `--siem-endpoint` is set. Every `target="audit"` event is
//! copied by [`SiemLayer`] into a bounded queue; a background task formats
//! each one (CEF or JSON inside an RFC 5424 message) and writes it to the
//! collector over TLS with RFC 5425 framing. The hash-chained
//! `--audit-log` file remains the authoritative record: this copy is
//! best-effort, and a slow or absent collector drops events (counted)
//! rather than slowing the router.
//!
//! Setup is split because the `tracing` subscriber is installed before
//! the async runtime and the crypto provider exist: [`layer()`] runs during
//! subscriber setup, and [`start()`] spawns the sender inside the runtime.

mod format;
mod layer;
mod transport;

use std::path::PathBuf;
use std::sync::Arc;

pub(crate) use format::Format;
pub(crate) use layer::{AUDIT_TARGET, SiemLayer};
use layer::{AuditRecord, Stats};
use rustgate_core::tasks::SubsystemHandle;
use tokio::sync::{Notify, mpsc};

/// The `--siem-*` settings, validated by `Cli::validate`.
#[derive(Debug, Clone)]
pub(crate) struct SiemSettings {
    /// Collector address, `host:port`.
    pub(crate) endpoint: String,
    /// CA certificates the collector's certificate must chain to.
    pub(crate) ca: PathBuf,
    /// Client certificate and key presented to the collector, if any.
    pub(crate) client_auth: Option<(PathBuf, PathBuf)>,
    pub(crate) format: Format,
    pub(crate) queue_size: usize,
    pub(crate) include_classified: bool,
}

/// The receiving half, held between subscriber setup and [`start`].
pub(crate) struct Pending {
    settings: SiemSettings,
    rx: mpsc::Receiver<AuditRecord>,
    stats: Arc<Stats>,
}

/// Build the capture layer and the queue it feeds.
pub(crate) fn layer(settings: SiemSettings) -> (SiemLayer, Pending) {
    let (tx, rx) = mpsc::channel(settings.queue_size.max(1));
    let stats = Arc::new(Stats::default());
    let layer = SiemLayer::new(tx, settings.include_classified, Arc::clone(&stats));
    (
        layer,
        Pending {
            settings,
            rx,
            stats,
        },
    )
}

/// Load the TLS material and spawn the sender. Must run inside the tokio
/// runtime, after the crypto provider is installed.
///
/// # Errors
///
/// Fails when the endpoint has no usable host or the TLS files cannot be
/// read or parsed, so a misconfigured forwarder stops startup instead of
/// silently sending nothing.
pub(crate) fn start(pending: Pending) -> anyhow::Result<SubsystemHandle> {
    let Pending {
        settings,
        rx,
        stats,
    } = pending;
    let host = rustgate_core::air_gap::extract_host(&settings.endpoint)
        .ok_or_else(|| anyhow::anyhow!("--siem-endpoint `{}` has no host", settings.endpoint))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| {
        anyhow::anyhow!("--siem-endpoint host `{host}` is not a valid TLS name: {e}")
    })?;
    let config = transport::client_config(
        &settings.ca,
        settings
            .client_auth
            .as_ref()
            .map(|(cert, key)| (cert.as_path(), key.as_path())),
    )?;
    let sender = transport::Sender {
        endpoint: settings.endpoint.clone(),
        server_name,
        connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        format: settings.format,
        hostname: format::syslog_hostname(&local_hostname()),
        stats,
    };
    tracing::info!(
        endpoint = %settings.endpoint,
        format = ?settings.format,
        queue_size = settings.queue_size,
        include_classified = settings.include_classified,
        "SIEM forwarding enabled"
    );
    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(sender.run(rx, Arc::clone(&shutdown)));
    Ok(SubsystemHandle::new(shutdown, task))
}

/// This machine's hostname for the RFC 5424 `HOSTNAME` field. `$HOSTNAME`
/// is a shell variable that is usually not exported (it is set in
/// containers), so the kernel's value is read first; empty means the field
/// is sent as the NILVALUE `-`.
fn local_hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|name| name.trim().to_owned())
        .find(|name| !name.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
