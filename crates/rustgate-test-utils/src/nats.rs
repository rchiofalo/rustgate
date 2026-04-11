// Copyright © 2026 Roberto Chiofalo.

//! Shared NATS test infrastructure.
//!
//! Provides [`TestNatsServer`] — a managed `nats-server` subprocess with
//! JetStream enabled on an ephemeral port.  The server is automatically killed
//! on drop and each instance gets its own JetStream store directory.
//!
//! Startup uses a retry loop with fast-fail on process exit to work around the
//! inherent TOCTOU race in ephemeral port selection.

#![allow(clippy::panic)]

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::io::AsyncReadExt;

/// Managed `nats-server` subprocess for integration tests.
///
/// Each instance runs on a unique ephemeral port with its own JetStream store
/// directory.  Automatically killed and cleaned up on drop.
#[derive(Debug)]
pub struct TestNatsServer {
    child: Child,
    port: u16,
    url: String,
    _store_dir: tempfile::TempDir,
}

impl TestNatsServer {
    /// Maximum number of startup attempts (port re-selection on conflict).
    const MAX_ATTEMPTS: u32 = 3;

    /// Per-attempt timeout for the server to become protocol-ready.
    const READY_TIMEOUT: Duration = Duration::from_secs(5);

    /// Polling interval between readiness checks.
    const POLL_INTERVAL: Duration = Duration::from_millis(50);

    /// Start a `nats-server` with JetStream on an ephemeral port.
    ///
    /// Returns `None` if the `nats-server` binary is not on `PATH`.
    /// Retries up to 3 times with a fresh port on each
    /// attempt to eliminate TOCTOU port-collision failures.
    pub async fn start() -> Option<Self> {
        // Quick check: is the binary available at all?
        if Command::new("nats-server")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return None;
        }

        for attempt in 0..Self::MAX_ATTEMPTS {
            match Self::try_start().await {
                Ok(server) => return Some(server),
                Err(msg) => {
                    eprintln!(
                        "nats-server start attempt {}/{} failed: {msg}",
                        attempt + 1,
                        Self::MAX_ATTEMPTS,
                    );
                }
            }
        }

        panic!(
            "nats-server failed to start after {} attempts",
            Self::MAX_ATTEMPTS,
        );
    }

    /// Single startup attempt.  Returns `Err(reason)` on failure.
    async fn try_start() -> Result<Self, String> {
        let port = Self::free_port();
        let store_dir = tempfile::tempdir().map_err(|e| format!("tmpdir: {e}"))?;

        let mut child = Command::new("nats-server")
            .args([
                "-p",
                &port.to_string(),
                "--jetstream",
                "--store_dir",
                store_dir
                    .path()
                    .to_str()
                    .ok_or_else(|| "non-UTF-8 tmpdir path".to_string())?,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;

        let deadline = tokio::time::Instant::now() + Self::READY_TIMEOUT;

        loop {
            // Fast-fail: if the process already exited (e.g. port conflict),
            // don't wait for the full timeout.
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!(
                    "process exited immediately with {status} (port {port})"
                ));
            }

            if tokio::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "readiness timeout after {}s on port {port}",
                    Self::READY_TIMEOUT.as_secs(),
                ));
            }

            // Check for protocol readiness: connect and verify "INFO " greeting.
            if let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                let mut buf = [0u8; 5];
                if stream.read_exact(&mut buf).await.is_ok() && &buf == b"INFO " {
                    return Ok(Self {
                        child,
                        port,
                        url: format!("nats://127.0.0.1:{port}"),
                        _store_dir: store_dir,
                    });
                }
            }

            tokio::time::sleep(Self::POLL_INTERVAL).await;
        }
    }

    /// Find a free TCP port by binding to `:0`.
    ///
    /// The port is released before returning so `nats-server` can bind it.
    /// This creates a TOCTOU window — the retry loop in [`Self::start`]
    /// compensates for potential collisions.
    fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.local_addr().expect("local addr").port()
    }

    /// NATS connection URL (e.g. `nats://127.0.0.1:4222`).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The TCP port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Create a JetStream context connected to this server.
    pub async fn jetstream(&self) -> async_nats::jetstream::Context {
        let client = async_nats::connect(&self.url)
            .await
            .expect("nats connect for jetstream");
        async_nats::jetstream::new(client)
    }
}

impl Drop for TestNatsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Skip the current test if `nats-server` is not available.
///
/// Returns a running [`TestNatsServer`] on success, or returns from the
/// enclosing function with a skip message on failure.
///
/// # Usage
///
/// ```ignore
/// #[tokio::test]
/// async fn my_test() {
///     let nats = require_nats!();
///     // use nats.url(), nats.jetstream(), etc.
/// }
/// ```
#[macro_export]
macro_rules! require_nats {
    () => {
        match $crate::nats::TestNatsServer::start().await {
            Some(server) => server,
            None => {
                eprintln!("SKIP: nats-server not found in PATH");
                return;
            }
        }
    };
}
