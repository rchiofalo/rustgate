// Copyright © 2026 Roberto Chiofalo.

//! `test-connection` — reach out to a remote endpoint without starting
//! the server and report whether the TCP or protocol handshake would
//! succeed.
//!
//! This is the break-glass pre-flight tool for "is the thing I'm trying
//! to reach actually reachable from this host?" It runs before any
//! configuration is parsed, requires no TLS material, and is intended
//! to be wired into cron / Ansible / systemd `ExecStartPre=` so an
//! operator can catch firewall, DNS, or service-outage problems before
//! the server itself fails to start.
//!
//! # Target types
//!
//! Exactly one of the target flags must be supplied:
//!
//! | Flag | Behaviour | Feature gate |
//! |------|-----------|--------------|
//! | `--tcp HOST:PORT` | TCP three-way handshake only | always |
//! | `--nats nats://HOST:PORT` | TCP + read NATS `INFO` line | `nats` |
//! | `--http URL` | HTTP `GET` and read the status line | `http` |
//!
//! The TCP probe is deliberately *dumb* — it does not send any bytes —
//! so it works against every listener type rustgate supports (plaintext,
//! TLS, WebSocket, MQTT, enrollment, metrics). The protocol probes are
//! useful when a TCP accept happens but the application layer rejects
//! (common with NATS when authentication is misconfigured).
//!
//! # Exit codes
//!
//! The exit codes form a monotonic severity ladder that downstream
//! scripts can branch on without parsing the report body:
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | Target accepted the connection (and, for protocol probes, responded sanely) |
//! | `1`  | Target refused the connection (TCP RST / ECONNREFUSED or protocol-level error response) |
//! | `2`  | Connection attempt timed out |
//! | `3`  | Anything else (DNS failure, unparseable target, unexpected I/O error) |
//!
//! Exit code `3` is the "something is off on this host" bucket and
//! should be investigated before rerunning.
//!
//! # JSON contract
//!
//! The top-level keys (`target_type`, `target`, `timeout_seconds`,
//! `status`, `elapsed_ms`, `error`) and the `status` values
//! (`connected`, `refused`, `timeout`, `error`) are pinned by the unit
//! tests in this module. Additions land at the end; renames or removals
//! are breaking.
//!
//! Addresses Finding F-181 (issue #900).

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Default connect timeout. Chosen to be generous enough that a slow
/// WAN link does not produce spurious failures, but short enough that
/// an operator running this from an interactive shell does not have to
/// wait on a stuck session.
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Result of a single connection attempt.
///
/// `connected`, `refused`, `timeout`, and `error` are the only four
/// values this enum serializes to — kept deliberately small so
/// downstream jq/grep scripts can pattern-match on a single string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeStatus {
    /// Handshake (and protocol response, where applicable) succeeded.
    Connected,
    /// Peer actively refused (TCP RST, or a protocol-level error
    /// response such as NATS `-ERR` or an HTTP 5xx).
    Refused,
    /// No response within the configured timeout.
    Timeout,
    /// Any other failure (DNS, bad target format, unexpected I/O).
    Error,
}

impl ProbeStatus {
    /// Map each status to the exit code documented at the top of the
    /// module. Kept here (rather than on the `Report`) so tests can
    /// pin the ladder independently of whichever status happened to
    /// be produced by the test clock.
    fn exit_code(self) -> i32 {
        match self {
            ProbeStatus::Connected => 0,
            ProbeStatus::Refused => 1,
            ProbeStatus::Timeout => 2,
            ProbeStatus::Error => 3,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ProbeStatus::Connected => "connected",
            ProbeStatus::Refused => "refused",
            ProbeStatus::Timeout => "timeout",
            ProbeStatus::Error => "error",
        }
    }
}

/// Which kind of target is being probed. The JSON value is used both
/// by the operator (to see at a glance what kind of check ran) and by
/// downstream tooling to know which fields to expect — currently they
/// are identical across target types, but leaving a discriminant in
/// the payload makes it forward-compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetType {
    Tcp,
    #[cfg(feature = "nats")]
    Nats,
    #[cfg(feature = "http")]
    Http,
}

impl TargetType {
    fn as_str(self) -> &'static str {
        match self {
            TargetType::Tcp => "tcp",
            #[cfg(feature = "nats")]
            TargetType::Nats => "nats",
            #[cfg(feature = "http")]
            TargetType::Http => "http",
        }
    }
}

/// The report emitted by a single run. Structure is the public JSON
/// contract — see the module docs. `error` is `Some` whenever `status`
/// is not `connected`; `None` on success.
#[derive(Debug, Serialize)]
pub(crate) struct ConnReport {
    pub(crate) target_type: TargetType,
    pub(crate) target: String,
    pub(crate) timeout_seconds: u64,
    pub(crate) status: ProbeStatus,
    /// Wall-clock time the probe took, in milliseconds. Useful for
    /// comparing link quality between DCs when the connection succeeds
    /// but feels slow.
    pub(crate) elapsed_ms: u128,
    pub(crate) error: Option<String>,
}

/// Enum driving [`run`] — the CLI layer translates its mutually
/// exclusive flags into one of these variants. Kept internal so the
/// JSON/CLI surface stays small: a new probe type means a new variant
/// here plus a new `--flag` in `cli.rs`, nothing else.
#[derive(Debug)]
pub(crate) enum Target {
    Tcp(String),
    #[cfg(feature = "nats")]
    Nats(String),
    #[cfg(feature = "http")]
    Http(String),
}

/// CLI entry point. Runs the probe, prints the report, and returns the
/// exit code the binary should use. Split from a `std::process::exit`
/// caller so tests can assert on the exit code directly without
/// shelling out.
pub(crate) fn run(target: Target, timeout_secs: u64, json: bool) -> Result<i32> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("build tokio runtime for test-connection: {e}"))?;

    let report = runtime.block_on(probe(target, timeout_secs));

    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| anyhow!("serialize test-connection report: {e}"))?;
        println!("{out}");
    } else {
        print!("{}", render_human(&report));
    }
    Ok(exit_code(&report))
}

/// Run the probe asynchronously and return a structured report. Pure
/// async function exposed at module level so integration tests can
/// drive it on their own runtime without going through [`run`]'s
/// blocking wrapper.
pub(crate) async fn probe(target: Target, timeout_secs: u64) -> ConnReport {
    match target {
        Target::Tcp(addr) => probe_tcp(addr, timeout_secs).await,
        #[cfg(feature = "nats")]
        Target::Nats(url) => probe_nats(url, timeout_secs).await,
        #[cfg(feature = "http")]
        Target::Http(url) => probe_http(url, timeout_secs).await,
    }
}

/// TCP probe: DNS-resolve, three-way handshake, report.
///
/// Deliberately does not send any application-layer bytes so it can be
/// pointed at any rustgate listener (plaintext, TLS, WebSocket, MQTT,
/// enrollment, metrics) without the far end rejecting a malformed
/// probe — all of those behave correctly when the client closes after
/// accept.
async fn probe_tcp(addr: String, timeout_secs: u64) -> ConnReport {
    let started = Instant::now();
    let deadline = Duration::from_secs(timeout_secs);
    let (status, error) = match timeout(deadline, TcpStream::connect(&addr)).await {
        // Tokio gives us `Result<Result<TcpStream, io::Error>, Elapsed>`:
        // outer `Err` == timeout, inner `Err` == I/O failure (refused,
        // DNS, etc.).
        Ok(Ok(_stream)) => (ProbeStatus::Connected, None),
        Ok(Err(e)) => classify_io_error(&e),
        Err(_) => (
            ProbeStatus::Timeout,
            Some(format!("connect timeout after {timeout_secs}s")),
        ),
    };
    ConnReport {
        target_type: TargetType::Tcp,
        target: addr,
        timeout_seconds: timeout_secs,
        status,
        elapsed_ms: started.elapsed().as_millis(),
        error,
    }
}

/// NATS probe: TCP connect, read the first line and require it to
/// start with `INFO ` (the NATS protocol server greeting). A listener
/// that accepts but returns something else — for example a raw HTTP
/// server misconfigured on the NATS port — is reported as `refused`.
#[cfg(feature = "nats")]
async fn probe_nats(url: String, timeout_secs: u64) -> ConnReport {
    use tokio::io::{AsyncBufReadExt as _, BufReader};

    let started = Instant::now();
    let deadline = Duration::from_secs(timeout_secs);

    // NATS URLs are `nats://host:port` — strip the scheme once so the
    // same probe works for both forms the operator is likely to type.
    let host_port = match strip_scheme(&url, "nats://") {
        Ok(hp) => hp,
        Err(msg) => {
            return error_report(TargetType::Nats, url, timeout_secs, msg, started);
        }
    };

    let fut = async {
        let stream = TcpStream::connect(host_port.as_ref()).await?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        // NATS greetings are single-line and typically under 1 KiB,
        // but we cap reads at the timeout to avoid a misbehaving peer
        // holding us open indefinitely.
        let _ = reader.read_line(&mut line).await?;
        Ok::<String, std::io::Error>(line)
    };

    let (status, error) = match timeout(deadline, fut).await {
        Ok(Ok(line)) if line.starts_with("INFO ") => (ProbeStatus::Connected, None),
        Ok(Ok(line)) => (
            ProbeStatus::Refused,
            Some(format!(
                "expected NATS INFO line, got: {:?}",
                line.trim_end()
            )),
        ),
        Ok(Err(e)) => classify_io_error(&e),
        Err(_) => (
            ProbeStatus::Timeout,
            Some(format!("NATS handshake timeout after {timeout_secs}s")),
        ),
    };

    ConnReport {
        target_type: TargetType::Nats,
        target: url,
        timeout_seconds: timeout_secs,
        status,
        elapsed_ms: started.elapsed().as_millis(),
        error,
    }
}

/// HTTP probe: plain TCP + minimal `GET / HTTP/1.0` and read the
/// status line. Deliberately does not use `reqwest` / `hyper` so the
/// probe works identically whether or not TLS is in the picture; the
/// goal is "is the HTTP server answering?", not full HTTP semantics.
#[cfg(feature = "http")]
async fn probe_http(url: String, timeout_secs: u64) -> ConnReport {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

    let started = Instant::now();
    let deadline = Duration::from_secs(timeout_secs);

    let parsed = match parse_http_url(&url) {
        Ok(p) => p,
        Err(msg) => {
            return error_report(TargetType::Http, url, timeout_secs, msg, started);
        }
    };

    // No TLS support here — see the module docs. An `https://` URL is
    // still usable by users who have their TLS-terminating proxy on a
    // different port; we just report the plaintext outcome against
    // whatever port they asked for.
    let fut = async {
        let mut stream = TcpStream::connect(parsed.host_port.as_str()).await?;
        let req = format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            parsed.path, parsed.host
        );
        stream.write_all(req.as_bytes()).await?;
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        let _ = reader.read_line(&mut status_line).await?;
        Ok::<String, std::io::Error>(status_line)
    };

    let (status, error) = match timeout(deadline, fut).await {
        Ok(Ok(line)) => classify_http_status_line(&line),
        Ok(Err(e)) => classify_io_error(&e),
        Err(_) => (
            ProbeStatus::Timeout,
            Some(format!("HTTP probe timeout after {timeout_secs}s")),
        ),
    };

    ConnReport {
        target_type: TargetType::Http,
        target: url,
        timeout_seconds: timeout_secs,
        status,
        elapsed_ms: started.elapsed().as_millis(),
        error,
    }
}

/// Split an `std::io::Error` into `(ProbeStatus, Option<String>)`.
/// Connection-refused is modelled as `refused` (exit 1, expected class
/// of failure); everything else bubbles up as `error` so operators
/// get a signal that something unusual happened.
fn classify_io_error(e: &std::io::Error) -> (ProbeStatus, Option<String>) {
    match e.kind() {
        ErrorKind::ConnectionRefused => (
            ProbeStatus::Refused,
            Some(format!("connection refused: {e}")),
        ),
        ErrorKind::TimedOut => (ProbeStatus::Timeout, Some(format!("kernel timeout: {e}"))),
        _ => (ProbeStatus::Error, Some(format!("{e}"))),
    }
}

/// Classify an HTTP/1.x status line. Any 2xx/3xx/4xx is treated as
/// `connected` (the server did answer); only 5xx maps to `refused`
/// since that is the HTTP-level "I received but refused" class.
#[cfg(feature = "http")]
fn classify_http_status_line(line: &str) -> (ProbeStatus, Option<String>) {
    let trimmed = line.trim_end();
    // Expected shape: "HTTP/1.1 200 OK"
    let code = trimmed
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    match code {
        Some(c) if (200..500).contains(&c) => (ProbeStatus::Connected, None),
        Some(c) if (500..600).contains(&c) => {
            (ProbeStatus::Refused, Some(format!("HTTP {c} from server")))
        }
        _ => (
            ProbeStatus::Error,
            Some(format!("unparseable HTTP status line: {trimmed:?}")),
        ),
    }
}

/// Build an `error` report for validation failures that never even
/// reached the network — bad URL, unresolvable scheme, etc. Kept as a
/// helper so every probe reports the same shape when it rejects input
/// without issuing a syscall.
///
/// Only compiled when at least one probe that can reject an input
/// *before* issuing a syscall is present; TCP has no pre-network
/// validation step.
#[cfg(any(feature = "nats", feature = "http"))]
fn error_report(
    target_type: TargetType,
    target: String,
    timeout_seconds: u64,
    msg: String,
    started: Instant,
) -> ConnReport {
    ConnReport {
        target_type,
        target,
        timeout_seconds,
        status: ProbeStatus::Error,
        elapsed_ms: started.elapsed().as_millis(),
        error: Some(msg),
    }
}

/// Strip a known scheme prefix or return the original string as-is.
/// Returns `Err` when the input contains `://` but not the expected
/// scheme — that catches typos like `tcp://` passed to `--nats`.
#[cfg(feature = "nats")]
fn strip_scheme<'a>(url: &'a str, scheme: &str) -> Result<std::borrow::Cow<'a, str>, String> {
    if let Some(rest) = url.strip_prefix(scheme) {
        Ok(std::borrow::Cow::Borrowed(rest))
    } else if url.contains("://") {
        Err(format!("expected {scheme}... URL, got {url:?}"))
    } else {
        Ok(std::borrow::Cow::Borrowed(url))
    }
}

/// Minimal HTTP URL parser. Intentionally tiny — we just need to
/// separate host, port, and path. Real parsing (query strings,
/// userinfo, IDN) is out of scope for a connectivity probe.
#[cfg(feature = "http")]
struct ParsedHttp {
    host: String,
    host_port: String,
    path: String,
}

#[cfg(feature = "http")]
fn parse_http_url(url: &str) -> Result<ParsedHttp, String> {
    let (default_port, rest) = if let Some(r) = url.strip_prefix("http://") {
        (80u16, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (443u16, r)
    } else {
        return Err(format!("expected http:// or https:// URL, got {url:?}"));
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("empty host in URL {url:?}"));
    }

    // Accept both `host` and `host:port` — IPv6 literals in brackets
    // are not handled (no rustgate deployment we support uses them and
    // the dependency on `http` / `url` to parse them is overkill).
    let (host, host_port) = if let Some((h, _p)) = authority.rsplit_once(':') {
        (h.to_string(), authority.to_string())
    } else {
        (authority.to_string(), format!("{authority}:{default_port}"))
    };

    Ok(ParsedHttp {
        host,
        host_port,
        path: path.to_string(),
    })
}

/// Map a report to the exit code contract documented in the module
/// docs. Public (crate-scoped) for tests.
pub(crate) fn exit_code(report: &ConnReport) -> i32 {
    report.status.exit_code()
}

/// Human-readable rendering of the report. Emphasises the status line
/// so an operator skimming the output catches pass/fail at a glance.
pub(crate) fn render_human(report: &ConnReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Target:  {} ({})",
        report.target,
        report.target_type.as_str()
    );
    let _ = writeln!(out, "Timeout: {}s", report.timeout_seconds);
    let _ = writeln!(out, "Elapsed: {}ms", report.elapsed_ms);
    let _ = writeln!(out, "Status:  {}", report.status.as_str());
    if let Some(err) = &report.error {
        let _ = writeln!(out, "Error:   {err}");
    }
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    // playbook-drift-ok: test-only fixtures for probe() — these TcpListeners never
    // accept production traffic, so keepalive/TCP_NODELAY hardening does not apply.
    use tokio::net::TcpListener;

    use super::*;

    // --- status → exit code ladder ---

    #[test]
    fn exit_code_ladder_is_monotonic() {
        assert_eq!(ProbeStatus::Connected.exit_code(), 0);
        assert_eq!(ProbeStatus::Refused.exit_code(), 1);
        assert_eq!(ProbeStatus::Timeout.exit_code(), 2);
        assert_eq!(ProbeStatus::Error.exit_code(), 3);
    }

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(ProbeStatus::Connected.as_str(), "connected");
        assert_eq!(ProbeStatus::Refused.as_str(), "refused");
        assert_eq!(ProbeStatus::Timeout.as_str(), "timeout");
        assert_eq!(ProbeStatus::Error.as_str(), "error");
    }

    // --- TCP probes ---

    #[tokio::test]
    async fn tcp_probe_connects_to_open_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept loop just to avoid log spam; we don't care what it reads.
        let _accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let report = probe(Target::Tcp(addr.to_string()), 5).await;
        assert_eq!(report.status, ProbeStatus::Connected, "{report:?}");
        assert_eq!(report.error, None);
        assert_eq!(exit_code(&report), 0);
    }

    #[tokio::test]
    async fn tcp_probe_reports_refused_when_nothing_is_listening() {
        // Bind, grab port, drop listener — the OS should now refuse
        // connections to that address.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let report = probe(Target::Tcp(addr.to_string()), 2).await;
        assert_eq!(report.status, ProbeStatus::Refused, "{report:?}");
        assert!(report.error.is_some());
        assert_eq!(exit_code(&report), 1);
    }

    #[tokio::test]
    async fn tcp_probe_reports_error_for_unparseable_target() {
        // An empty host → DNS lookup failure; kernel returns an error
        // straight away (no timeout involved).
        let report = probe(Target::Tcp("".to_string()), 2).await;
        assert_eq!(report.status, ProbeStatus::Error, "{report:?}");
        assert!(report.error.is_some());
        assert_eq!(exit_code(&report), 3);
    }

    // --- human + JSON rendering ---

    #[tokio::test]
    async fn render_human_includes_all_headline_fields() {
        let report = ConnReport {
            target_type: TargetType::Tcp,
            target: "example.com:443".to_string(),
            timeout_seconds: 5,
            status: ProbeStatus::Connected,
            elapsed_ms: 42,
            error: None,
        };
        let rendered = render_human(&report);
        assert!(rendered.contains("example.com:443"));
        assert!(rendered.contains("(tcp)"));
        assert!(rendered.contains("5s"));
        assert!(rendered.contains("42ms"));
        assert!(rendered.contains("connected"));
        assert!(!rendered.contains("Error:"));
    }

    #[tokio::test]
    async fn render_human_includes_error_line_when_present() {
        let report = ConnReport {
            target_type: TargetType::Tcp,
            target: "nope:1".to_string(),
            timeout_seconds: 5,
            status: ProbeStatus::Refused,
            elapsed_ms: 1,
            error: Some("connection refused".to_string()),
        };
        let rendered = render_human(&report);
        assert!(rendered.contains("Status:  refused"));
        assert!(rendered.contains("Error:   connection refused"));
    }

    #[test]
    fn json_contract_is_stable() {
        let report = ConnReport {
            target_type: TargetType::Tcp,
            target: "example.com:443".to_string(),
            timeout_seconds: 5,
            status: ProbeStatus::Connected,
            elapsed_ms: 42,
            error: None,
        };
        let json = serde_json::to_value(&report).unwrap();
        // Pin the key set so accidental renames break the test, not
        // downstream tooling.
        let obj = json.as_object().unwrap();
        let keys: std::collections::BTreeSet<&String> = obj.keys().collect();
        let expected: std::collections::BTreeSet<String> = [
            "target_type",
            "target",
            "timeout_seconds",
            "status",
            "elapsed_ms",
            "error",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let expected_refs: std::collections::BTreeSet<&String> = expected.iter().collect();
        assert_eq!(keys, expected_refs);
        assert_eq!(obj["target_type"], "tcp");
        assert_eq!(obj["status"], "connected");
    }

    // --- HTTP classification ---

    #[cfg(feature = "http")]
    #[test]
    fn http_status_line_classifier_buckets_correctly() {
        assert_eq!(
            classify_http_status_line("HTTP/1.1 200 OK\r\n").0,
            ProbeStatus::Connected
        );
        assert_eq!(
            classify_http_status_line("HTTP/1.1 404 Not Found\r\n").0,
            ProbeStatus::Connected,
            "4xx still means the server is answering"
        );
        assert_eq!(
            classify_http_status_line("HTTP/1.1 503 Service Unavailable\r\n").0,
            ProbeStatus::Refused
        );
        assert_eq!(
            classify_http_status_line("garbage\r\n").0,
            ProbeStatus::Error
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_url_parser_handles_default_ports_and_paths() {
        let p = parse_http_url("http://example.com/foo").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.host_port, "example.com:80");
        assert_eq!(p.path, "/foo");

        let p = parse_http_url("https://example.com:9443/").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.host_port, "example.com:9443");
        assert_eq!(p.path, "/");

        let p = parse_http_url("http://example.com").unwrap();
        assert_eq!(p.path, "/");

        assert!(parse_http_url("ftp://example.com/").is_err());
        assert!(parse_http_url("http:///path").is_err());
    }

    // --- NATS scheme strip ---

    #[cfg(feature = "nats")]
    #[test]
    fn nats_scheme_strip_rejects_wrong_scheme() {
        assert_eq!(strip_scheme("nats://h:4222", "nats://").unwrap(), "h:4222");
        assert_eq!(strip_scheme("h:4222", "nats://").unwrap(), "h:4222");
        assert!(strip_scheme("tcp://h:4222", "nats://").is_err());
    }
}
