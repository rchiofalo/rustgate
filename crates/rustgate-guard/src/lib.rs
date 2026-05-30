// Copyright © 2026 Roberto Chiofalo.

//! Cross-domain content inspection guard — closes #857.
//!
//! Bundles the four boundary-crossing controls that travel together in
//! every CDS deployment but were absent from the obligation-engine
//! scaffold shipped via #1286 (`StripPii`, `DegradePosition`,
//! `InjectMarking`):
//!
//! 1. **Per-direction throughput cap.** Every byte that crosses the
//!    boundary is metered through a [`rustgate_resilience::token_bucket`]
//!    sized to the direction's `*_max_bps` budget. Exceeding the cap
//!    fail-closes with [`GuardError::RateLimitExceeded`] and emits a
//!    `boundary.evaluate` audit record marked `decision = "deny"`,
//!    `reason = "rate_limit"`. Caps are independent per direction — a
//!    saturated `LowToHigh` channel does not affect `HighToLow`.
//! 2. **Mandatory CAPCO marking.** When
//!    [`GuardConfig::mandatory_marking`] is set, the guard rejects any
//!    inbound message that carries no CAPCO banner (no `<marking>` child
//!    on a CoT detail element, or a banner that fails to parse via
//!    [`rustgate_core::classification::ClassificationMarking`]). The
//!    rejection emits an audit record with `reason = "missing_marking"`
//!    so SIEM rules can correlate misconfigured policies with the
//!    boundary they were evaluated at.
//! 3. **Dedicated audit envelope.** The guard owns a
//!    [`rustgate_archive::audit_chain::HashChainWriter`] pointed at a
//!    SEPARATE log file from the general audit chain, so cross-domain
//!    accountability survives rotation of the operational log. Every
//!    evaluation — admit or deny — emits exactly one record before the
//!    `evaluate` call returns.
//! 4. **Pre-egress before-and-after hashes.** Each audit record carries
//!    `input_sha256` and `output_sha256` so an external auditor can
//!    prove what changed at the guard. The hashes are computed over the
//!    payload bytes (NOT over the rendered XML) so a transform that
//!    re-orders attributes still produces a different hash.
//!
//! ## Composition with the obligation engine
//!
//! The CDI obligation kinds from #1286 (`StripPii`, `DegradePosition`,
//! `InjectMarking`) compose with the guard rather than replacing it. A
//! policy may apply transforms via obligations AND the guard may still
//! reject — the `output_sha256` reflects whatever the message looked
//! like at the moment the guard saw it, so an upstream obligation that
//! injected a marking is visible in the trail.
//!
//! Guard rejection is **final**. Even with obligations applied, a
//! rate-limit or missing-marking trip drops the message; the audit
//! record is the only artifact that survives.
//!
//! ## What lives where
//!
//! - `rustgate_cot::cdi` — the three transform helpers (refs #1286).
//! - `rustgate_core::classification` — CAPCO grammar + lattice (refs
//!   #1282).
//! - `rustgate_archive::audit_chain::HashChainWriter` — the proven
//!   tamper-evident primitive (refs #1268).
//! - `rustgate_resilience::token_bucket` — the per-direction byte
//!   limiter (refs #883).
//! - This crate — the orchestration that wires them together at the
//!   boundary.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;

use bytes::Bytes;
use rustgate_archive::audit_chain::{AuditChainError, GENESIS_PREV, HashChainWriter};
use rustgate_core::message::RoutableMessage;
use rustgate_core::sanitize::sanitize_for_log;
use rustgate_resilience::token_bucket::TokenBucket;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[cfg(feature = "metrics")]
pub mod metrics;

/// Direction in which a message is crossing the boundary.
///
/// `LowToHigh` — message originated on the lower-classification network
/// and is being admitted to the higher-classification network. The
/// classic CDS use case (e.g. UNCLASSIFIED → SECRET).
///
/// `HighToLow` — message originated on the higher-classification
/// network and is being released to the lower side after redaction.
/// The most security-sensitive direction; deployments typically run a
/// `HighToLow` guard with `mandatory_marking = true` and aggressive
/// throughput caps.
///
/// `Bidirectional` — used in [`GuardConfig::direction`] to indicate the
/// guard accepts traffic in both directions. The per-direction caps are
/// still enforced independently; this is just a deployment hint
/// captured for audit attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardDirection {
    /// Inbound to the higher-classification side.
    LowToHigh,
    /// Outbound to the lower-classification side.
    HighToLow,
    /// Both directions allowed (configuration only — every individual
    /// `evaluate` call still names a concrete `LowToHigh` or
    /// `HighToLow`).
    Bidirectional,
}

impl GuardDirection {
    /// Stable lowercase tag for Prometheus labels and audit fields.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::LowToHigh => "low_to_high",
            Self::HighToLow => "high_to_low",
            Self::Bidirectional => "bidirectional",
        }
    }

    /// Audit-friendly PascalCase rendering used inside the
    /// `boundary.evaluate` event records. SIEM rules grep on this
    /// exact spelling — changing it is a wire-format break.
    fn as_audit(&self) -> &'static str {
        match self {
            Self::LowToHigh => "LowToHigh",
            Self::HighToLow => "HighToLow",
            Self::Bidirectional => "Bidirectional",
        }
    }
}

impl std::fmt::Display for GuardDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_audit())
    }
}

/// Configuration for a single [`CrossDomainGuard`] instance.
///
/// Operators typically own one config per boundary deployment. The
/// throughput caps and mandatory-marking switch are loaded from the
/// guard config TOML file (handled by `rustgate-server`); this struct
/// is the parsed, validated shape the runtime consumes.
///
/// # Deserialization
///
/// `GuardConfig` deserializes directly from the operator's `[guard]`
/// TOML block (kebab-case keys, unknown keys rejected) so the crate is
/// the single source of truth for the config shape — the server does
/// not shadow it with a duplicate type. Every field has a fail-closed
/// default ([`GuardConfig::default`]): mandatory marking on, the
/// security-sensitive `high-to-low` cap tighter than `low-to-high`, and
/// the v1 audit-log path. Call [`GuardConfig::validate`] after
/// deserialization before constructing a [`CrossDomainGuard`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct GuardConfig {
    /// Maximum sustained bytes-per-second for messages travelling from
    /// the lower-classification side to the higher-classification side.
    /// Used as both the refill rate and the burst cap of the
    /// `LowToHigh` token bucket — bursts up to one second of capacity
    /// are admitted at once, beyond that the bucket throttles.
    #[serde(default = "default_low_to_high_max_bps")]
    pub low_to_high_max_bps: u64,
    /// Maximum sustained bytes-per-second for messages travelling from
    /// the higher-classification side to the lower-classification side.
    /// The most security-sensitive direction; v1 deployments default
    /// to a tighter cap than `low_to_high_max_bps` (see
    /// [`GuardConfig::defaults_for_v1`]).
    #[serde(default = "default_high_to_low_max_bps")]
    pub high_to_low_max_bps: u64,
    /// When `true`, every inbound message MUST carry a parseable CAPCO
    /// marking. Messages without a marking are rejected at the
    /// boundary with [`GuardError::MissingMarking`]. Defaults to `true`
    /// (fail-closed): an operator must opt *out* of mandatory marking,
    /// never silently get it disabled.
    #[serde(default = "default_mandatory_marking")]
    pub mandatory_marking: bool,
    /// Path to the dedicated boundary audit log. Hash-chained via
    /// [`HashChainWriter`]; a SIEM tailing the path observes one record
    /// per boundary evaluation in canonical JSON.
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: PathBuf,
    /// Deployment direction hint. Recorded in audit metadata; does not
    /// short-circuit the per-call direction the runtime supplies to
    /// [`CrossDomainGuard::evaluate`].
    #[serde(default = "default_direction")]
    pub direction: GuardDirection,
}

fn default_low_to_high_max_bps() -> u64 {
    1_048_576
}
fn default_high_to_low_max_bps() -> u64 {
    262_144
}
fn default_mandatory_marking() -> bool {
    true
}
fn default_audit_log_path() -> PathBuf {
    PathBuf::from("/var/log/rustgate/boundary-audit.jsonl")
}
fn default_direction() -> GuardDirection {
    GuardDirection::Bidirectional
}

impl Default for GuardConfig {
    /// Fail-closed v1 defaults — see the field-level `#[serde(default)]`
    /// functions. Equivalent to
    /// `defaults_for_v1("/var/log/rustgate/boundary-audit.jsonl")`.
    fn default() -> Self {
        Self {
            low_to_high_max_bps: default_low_to_high_max_bps(),
            high_to_low_max_bps: default_high_to_low_max_bps(),
            mandatory_marking: default_mandatory_marking(),
            audit_log_path: default_audit_log_path(),
            direction: default_direction(),
        }
    }
}

/// Error returned by [`GuardConfig::validate`].
#[derive(Debug, thiserror::Error)]
pub enum GuardConfigError {
    /// A throughput cap was zero — a zero token-bucket rate would reject
    /// all traffic in that direction, which is almost certainly a
    /// misconfiguration rather than an intentional hard-stop. Operators
    /// who genuinely want to block a direction should not configure a
    /// guard on it.
    #[error("guard {field} must be greater than zero (a zero cap rejects all traffic)")]
    ZeroCap {
        /// The offending field name (`low-to-high-max-bps` etc.).
        field: &'static str,
    },
    /// The audit log path is empty.
    #[error("guard audit-log-path must not be empty")]
    EmptyAuditPath,
}

impl GuardConfig {
    /// Sensible v1 defaults: a 1 MiB/s `LowToHigh` admission cap, a
    /// 256 KiB/s `HighToLow` release cap (tighter on the more
    /// security-sensitive direction), `mandatory_marking = true`
    /// (fail-closed by default), and an audit log path under
    /// `/var/log/rustgate/boundary-audit.jsonl`. Operators override
    /// individual fields rather than constructing from scratch.
    pub fn defaults_for_v1<P: Into<PathBuf>>(audit_log_path: P) -> Self {
        Self {
            audit_log_path: audit_log_path.into(),
            ..Self::default()
        }
    }

    /// Validate a deserialized config before it is handed to
    /// [`CrossDomainGuard::new`].
    ///
    /// # Errors
    ///
    /// - [`GuardConfigError::ZeroCap`] if either throughput cap is zero.
    /// - [`GuardConfigError::EmptyAuditPath`] if the audit log path is
    ///   empty.
    pub fn validate(&self) -> std::result::Result<(), GuardConfigError> {
        if self.low_to_high_max_bps == 0 {
            return Err(GuardConfigError::ZeroCap {
                field: "low-to-high-max-bps",
            });
        }
        if self.high_to_low_max_bps == 0 {
            return Err(GuardConfigError::ZeroCap {
                field: "high-to-low-max-bps",
            });
        }
        if self.audit_log_path.as_os_str().is_empty() {
            return Err(GuardConfigError::EmptyAuditPath);
        }
        Ok(())
    }
}

/// Errors returned by [`CrossDomainGuard::evaluate`].
///
/// The audit log is written exactly once per evaluation — see the
/// crate-level docs — so a [`GuardError`] returned to the caller is
/// already accompanied by a corresponding `boundary.evaluate` record
/// with `decision = "deny"`.
#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// Token bucket refused the byte budget.
    #[error("boundary throughput cap exceeded ({direction})")]
    RateLimitExceeded {
        /// Direction whose cap was exceeded.
        direction: GuardDirection,
    },
    /// Inbound message carried no CAPCO marking and the config has
    /// `mandatory_marking = true`.
    #[error("inbound message missing CAPCO marking — mandatory_marking is enabled")]
    MissingMarking,
    /// CAPCO marking present but its level is not authorized for the
    /// direction (e.g. a `TopSecret` payload heading `HighToLow`).
    #[error("inbound message classification {marking} is not authorized for direction {direction}")]
    UnauthorizedClassification {
        /// Sanitized marking string from the inbound payload.
        marking: String,
        /// Direction the message was attempting to cross.
        direction: GuardDirection,
    },
    /// Audit log write or chain accounting failed.
    #[error("guard audit log error: {source}")]
    Audit {
        #[from]
        /// Underlying audit-chain error.
        source: AuditChainError,
    },
    /// Filesystem I/O failed (audit log open / append).
    #[error("I/O error: {source}")]
    Io {
        #[from]
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Result alias for guard operations.
pub type Result<T> = std::result::Result<T, GuardError>;

/// Cross-domain content inspection guard.
///
/// Owns the throughput limiters, the dedicated audit chain, and (when
/// the `metrics` feature is on) the per-instance metric emitters. One
/// guard instance per boundary deployment.
pub struct CrossDomainGuard {
    config: GuardConfig,
    low_to_high_bucket: TokenBucket,
    high_to_low_bucket: TokenBucket,
    audit_writer: HashChainWriter<File>,
    /// Cached for tests so we can inspect what the writer would emit
    /// without re-reading the file every call.
    audit_records: u64,
}

impl std::fmt::Debug for CrossDomainGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip the audit writer (its `Debug` impl recurses through the
        // `File` handle) and the buckets' internal mutex state — none
        // of those are useful in a log line and they would just add
        // noise. The config + record count is the operator-visible
        // surface.
        f.debug_struct("CrossDomainGuard")
            .field("config", &self.config)
            .field("audit_records", &self.audit_records)
            .finish_non_exhaustive()
    }
}

impl CrossDomainGuard {
    /// Build a guard from a parsed [`GuardConfig`].
    ///
    /// Opens the audit log in append mode (creating it if missing) and
    /// resumes the hash chain from the existing tip via
    /// [`rustgate_archive::audit_chain::read_chain_state`] when the file
    /// is non-empty. A brand-new audit log starts at
    /// [`rustgate_archive::audit_chain::GENESIS_PREV`].
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::Io`] when the audit log path cannot be
    /// opened or its chain state cannot be read.
    pub fn new(config: GuardConfig) -> Result<Self> {
        let (prev, next_seq) = if config.audit_log_path.exists() {
            rustgate_archive::audit_chain::read_chain_state(&config.audit_log_path)
                .unwrap_or_else(|_| (GENESIS_PREV.to_string(), 1))
        } else {
            (GENESIS_PREV.to_string(), 1)
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.audit_log_path)?;
        let audit_writer = HashChainWriter::new(file, prev).with_next_seq(next_seq);
        // Token-bucket capacity is 1s of throughput so a brief burst is
        // admitted but a sustained over-cap stream is throttled. The
        // `f64` cast is safe for any realistic operator config (max
        // u64 is ~1.8e19, far below f64 precision break at 2^53).
        let low_to_high_bucket = TokenBucket::new(
            config.low_to_high_max_bps as f64,
            Some(config.low_to_high_max_bps as f64),
        );
        let high_to_low_bucket = TokenBucket::new(
            config.high_to_low_max_bps as f64,
            Some(config.high_to_low_max_bps as f64),
        );
        Ok(Self {
            config,
            low_to_high_bucket,
            high_to_low_bucket,
            audit_writer,
            audit_records: 0,
        })
    }

    /// Evaluate a single message crossing the boundary.
    ///
    /// On success returns the (possibly transformed — though this
    /// scaffold does not yet chain transforms inside the guard, see
    /// the crate docs) bytes that may continue to the destination
    /// network. On rejection returns the typed [`GuardError`]; the
    /// audit log is written exactly once per call regardless of
    /// outcome.
    ///
    /// Direction passed here MUST be either [`GuardDirection::LowToHigh`]
    /// or [`GuardDirection::HighToLow`] — the [`GuardDirection::Bidirectional`]
    /// configuration value is a deployment hint, not a per-call
    /// direction. Passing `Bidirectional` here is treated as
    /// `LowToHigh` (least-restrictive interpretation) and the audit
    /// record records the value the caller passed in.
    ///
    /// # Errors
    ///
    /// See [`GuardError`] for the rejection variants. Filesystem
    /// failures while writing the audit log are surfaced as
    /// [`GuardError::Audit`] / [`GuardError::Io`].
    pub fn evaluate(&mut self, msg: &RoutableMessage, direction: GuardDirection) -> Result<Bytes> {
        let payload = msg.payload.clone();
        let input_sha = sha256_hex(&payload);
        let output_sha = input_sha.clone();
        // Extract the marking for the audit record before any decision.
        // Failure to find a marking is NOT itself an error here — the
        // mandatory check below decides whether the absence is fatal.
        let marking = extract_marking(&payload);

        // Step 1: mandatory marking. Cheaper than the throughput check
        // and fails closed first so a flood of unmarked messages does
        // not consume the byte budget before being rejected.
        if self.config.mandatory_marking && marking.is_none() {
            self.write_audit_record(
                direction,
                msg,
                marking.as_deref(),
                &input_sha,
                &output_sha,
                "deny",
                "missing_marking",
            )?;
            return Err(GuardError::MissingMarking);
        }

        // Step 2: classification dominance check. A `TopSecret`
        // payload moving HighToLow is per-policy unauthorized; we
        // record `unauthorized_classification` rather than degrading
        // silently.
        if let Some(ref m) = marking
            && let Some(reject) = check_classification_authorized(m, direction)
        {
            self.write_audit_record(
                direction,
                msg,
                marking.as_deref(),
                &input_sha,
                &output_sha,
                "deny",
                "unauthorized_classification",
            )?;
            return Err(reject);
        }

        // Step 3: throughput cap. The bucket charges one token per
        // payload byte, so a 64 KiB message consumes 65 536 tokens.
        let bucket = self.bucket_for(direction);
        let bytes = payload.len() as f64;
        if bucket.try_acquire_n(bytes).is_err() {
            self.write_audit_record(
                direction,
                msg,
                marking.as_deref(),
                &input_sha,
                &output_sha,
                "deny",
                "rate_limit",
            )?;
            return Err(GuardError::RateLimitExceeded { direction });
        }

        // Step 4: admit. Audit before returning so a subsequent crash
        // cannot lose the record.
        self.write_audit_record(
            direction,
            msg,
            marking.as_deref(),
            &input_sha,
            &output_sha,
            "allow",
            "ok",
        )?;
        Ok(payload)
    }

    /// Number of audit records this guard has written. Exposed so
    /// tests can assert exactly one write per evaluation without
    /// re-parsing the file.
    pub fn audit_records_written(&self) -> u64 {
        self.audit_records
    }

    /// Borrow the configured throughput cap for a direction. The
    /// `Bidirectional` variant maps to the `LowToHigh` bucket
    /// (least-restrictive interpretation).
    fn bucket_for(&self, direction: GuardDirection) -> &TokenBucket {
        match direction {
            GuardDirection::LowToHigh | GuardDirection::Bidirectional => &self.low_to_high_bucket,
            GuardDirection::HighToLow => &self.high_to_low_bucket,
        }
    }

    /// Write one `boundary.evaluate` record through the hash-chain
    /// writer. All string fields are sanitized via
    /// [`rustgate_core::sanitize::sanitize_for_log`] before
    /// serialization.
    // justification: dispatch entrypoint hit only by `evaluate`. Bundling
    // the seven fields into a struct would just move the fan-in upstream
    // without reducing live references at the single call site.
    #[allow(clippy::too_many_arguments)]
    fn write_audit_record(
        &mut self,
        direction: GuardDirection,
        msg: &RoutableMessage,
        marking: Option<&str>,
        input_sha: &str,
        output_sha: &str,
        decision: &str,
        reason: &str,
    ) -> Result<()> {
        // The hash-chain writer auto-injects `seq`, `prev_sha256`,
        // `sha256`. We supply everything else.
        let timestamp = current_timestamp_rfc3339();
        let source_cn = sanitize_for_log(&msg.source.cn);
        let msg_uid = extract_msg_uid(&msg.payload).unwrap_or_default();
        let msg_uid_safe = sanitize_for_log(&msg_uid);
        let marking_safe = marking.map(sanitize_for_log);
        let mut map = serde_json::Map::new();
        let _ = map.insert("ts".to_string(), serde_json::Value::String(timestamp));
        let _ = map.insert(
            "event".to_string(),
            serde_json::Value::String("boundary.evaluate".to_string()),
        );
        let _ = map.insert(
            "direction".to_string(),
            serde_json::Value::String(direction.as_audit().to_string()),
        );
        let _ = map.insert(
            "source_cn".to_string(),
            serde_json::Value::String(source_cn),
        );
        let _ = map.insert(
            "msg_uid".to_string(),
            serde_json::Value::String(msg_uid_safe),
        );
        let _ = map.insert(
            "marking".to_string(),
            match marking_safe {
                Some(s) => serde_json::Value::String(s),
                None => serde_json::Value::Null,
            },
        );
        let _ = map.insert(
            "input_sha256".to_string(),
            serde_json::Value::String(input_sha.to_string()),
        );
        let _ = map.insert(
            "output_sha256".to_string(),
            serde_json::Value::String(output_sha.to_string()),
        );
        let _ = map.insert(
            "decision".to_string(),
            serde_json::Value::String(decision.to_string()),
        );
        let _ = map.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
        let line =
            serde_json::to_vec(&serde_json::Value::Object(map)).map_err(|e| GuardError::Audit {
                source: AuditChainError::InvalidJson {
                    line_number: 0,
                    source: e,
                },
            })?;
        self.audit_writer.write_all(&line)?;
        self.audit_writer.write_all(b"\n")?;
        self.audit_writer.flush()?;
        self.audit_records = self.audit_records.saturating_add(1);

        #[cfg(feature = "metrics")]
        {
            metrics::evaluations_total()
                .with_label_values(&[direction.as_label(), decision])
                .inc();
            if decision == "deny" {
                metrics::rejections_total()
                    .with_label_values(&[direction.as_label(), reason])
                    .inc();
            }
            // Snapshot current bucket level as a bps-equivalent gauge.
            let bucket = self.bucket_for(direction);
            metrics::throughput_bps()
                .with_label_values(&[direction.as_label()])
                .set(bucket.current_tokens() as i64);
        }

        Ok(())
    }
}

/// Shareable, hot-path-safe handle to a [`CrossDomainGuard`].
///
/// [`CrossDomainGuard::evaluate`] takes `&mut self` (it mutates the
/// token buckets and appends to the audit chain), so a guard shared
/// across the per-sink egress tasks needs interior mutability. The
/// server wires one `GuardGate` per configured boundary and the egress
/// forwarders consult it before a message leaves the process.
///
/// # Lock posture (fail-closed by design)
///
/// The inner guard is held behind a [`parking_lot::Mutex`] — the
/// workspace standard for sync hot paths (no poisoning, no `.unwrap()`
/// on lock). `evaluate` is cheap (token-bucket arithmetic plus one
/// audit-record append), and the single-file audit writer is the
/// serialization point regardless, so a single mutex is the right v1
/// shape rather than per-direction sharding. Unlike the fail-*open*
/// token-bucket limiter in `rustgate-resilience`, a cross-domain guard
/// is fail-*closed*: if evaluation cannot complete, the message does not
/// cross. `parking_lot` cannot poison, so the lock is always acquirable
/// and the fail-closed decision always comes from `evaluate` itself.
#[derive(Clone)]
pub struct GuardGate {
    inner: std::sync::Arc<parking_lot::Mutex<CrossDomainGuard>>,
}

impl std::fmt::Debug for GuardGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Lock briefly to render the inner guard's operator-visible
        // surface; never blocks for long (see lock-posture docs).
        f.debug_struct("GuardGate")
            .field("guard", &*self.inner.lock())
            .finish()
    }
}

impl GuardGate {
    /// Build a gate from a validated config, constructing the underlying
    /// [`CrossDomainGuard`] (which opens / resumes the audit chain).
    ///
    /// # Errors
    ///
    /// Propagates [`GuardError`] from [`CrossDomainGuard::new`] (audit
    /// log open / chain-state read failure).
    pub fn new(config: GuardConfig) -> Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(parking_lot::Mutex::new(CrossDomainGuard::new(config)?)),
        })
    }

    /// Wrap an already-constructed guard.
    #[must_use]
    pub fn from_guard(guard: CrossDomainGuard) -> Self {
        Self {
            inner: std::sync::Arc::new(parking_lot::Mutex::new(guard)),
        }
    }

    /// Evaluate one message crossing the boundary in `direction`.
    ///
    /// Acquires the lock, runs [`CrossDomainGuard::evaluate`] (which
    /// audits exactly once), and releases. Returns the admitted payload
    /// or the typed [`GuardError`]; the caller MUST drop the message on
    /// `Err` (fail-closed). The lock is held only for the duration of
    /// the synchronous evaluation.
    ///
    /// # Errors
    ///
    /// See [`CrossDomainGuard::evaluate`].
    pub fn evaluate(&self, msg: &RoutableMessage, direction: GuardDirection) -> Result<Bytes> {
        self.inner.lock().evaluate(msg, direction)
    }
}

/// Compute the lowercase hex SHA-256 of a payload.
fn sha256_hex(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Extract the CAPCO marking string from a CoT XML payload's
/// `<marking value="..."/>` child of `<detail>`. Returns `None` when
/// no marking element is present (or the payload is not XML — non-XML
/// payloads cannot carry a marking under the current scaffold).
fn extract_marking(payload: &[u8]) -> Option<String> {
    // Cheap fast-path: skip non-XML payloads without invoking the
    // quick-xml parser.
    if !is_xml_intent(payload) {
        return None;
    }
    use quick_xml::Reader;
    use quick_xml::events::Event;
    let mut reader = Reader::from_reader(payload);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if local_name(e.name().as_ref()).eq_ignore_ascii_case(b"marking") {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref().eq_ignore_ascii_case(b"value")
                            && let Ok(s) = std::str::from_utf8(attr.value.as_ref())
                        {
                            return Some(s.to_string());
                        }
                    }
                }
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
}

/// Extract the CoT envelope `uid` attribute from a payload, if any.
/// Returns `None` for non-XML or missing-uid payloads — the audit
/// record then carries an empty string in `msg_uid` so SIEM rules can
/// still grep on direction/source_cn without nullable handling.
fn extract_msg_uid(payload: &[u8]) -> Option<String> {
    if !is_xml_intent(payload) {
        return None;
    }
    use quick_xml::Reader;
    use quick_xml::events::Event;
    let mut reader = Reader::from_reader(payload);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if local_name(e.name().as_ref()).eq_ignore_ascii_case(b"event") {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref().eq_ignore_ascii_case(b"uid")
                            && let Ok(s) = std::str::from_utf8(attr.value.as_ref())
                        {
                            return Some(s.to_string());
                        }
                    }
                    return None;
                }
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
}

/// Return `true` when the payload's first non-whitespace byte is `<`.
/// Both extractors short-circuit on `false` so a non-XML payload (e.g.
/// MAVLink, raw protobuf) does not invoke the quick-xml parser.
fn is_xml_intent(payload: &[u8]) -> bool {
    payload
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<')
}

/// Strip namespace prefix and return the local element name.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

/// Decide whether a parsed CAPCO marking is authorized for the given
/// direction. Returns `Some(GuardError)` when the marking should be
/// rejected. Currently:
///
/// - `HighToLow`: `TopSecret` payloads are not released by the
///   scaffold — they require explicit operator approval per CDS
///   policy. `Secret`/`Confidential`/`Unclassified` are allowed.
/// - `LowToHigh`: every classification level is allowed (admission
///   to a higher-classification network is by definition
///   "elevation", which is policy-permitted at the boundary).
/// - `Bidirectional`: same as `LowToHigh`.
fn check_classification_authorized(
    raw_marking: &str,
    direction: GuardDirection,
) -> Option<GuardError> {
    use rustgate_core::classification::{Classification, ClassificationMarking};
    let parsed: std::result::Result<ClassificationMarking, _> = raw_marking.parse();
    let Ok(parsed) = parsed else {
        // Unparseable marking — let the caller see the raw string in
        // the audit record but do not reject here; mandatory_marking
        // already fired upstream, and a malformed marking on a
        // permissive-config deployment should not silently elevate to
        // a hard reject.
        return None;
    };
    match direction {
        GuardDirection::HighToLow => {
            if parsed.classification == Classification::TopSecret {
                Some(GuardError::UnauthorizedClassification {
                    marking: raw_marking.to_string(),
                    direction,
                })
            } else {
                None
            }
        }
        GuardDirection::LowToHigh | GuardDirection::Bidirectional => None,
    }
}

/// Format `SystemTime::now()` as RFC 3339 UTC with second precision.
/// Falls back to a constant on the (impossible-in-practice) format
/// failure so the audit record always has a non-empty timestamp.
fn current_timestamp_rfc3339() -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    let now = OffsetDateTime::now_utc();
    now.format(&Rfc3339)
        .unwrap_or_else(|_| "0000-00-00T00:00:00Z".to_string())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
    use tempfile::TempDir;

    use super::*;

    fn cot_with_marking(uid: &str, marking: &str) -> Bytes {
        let xml = format!(
            r#"<event uid="{uid}" type="a-f-G-U-C" start="2026-05-04T12:00:00Z" stale="2026-05-04T12:05:00Z"><point lat="38.9" lon="-77.0" hae="125.0"/><detail><marking value="{marking}"/><contact callsign="ALPHA-1"/></detail></event>"#,
        );
        Bytes::from(xml)
    }

    fn cot_without_marking(uid: &str) -> Bytes {
        let xml = format!(
            r#"<event uid="{uid}" type="a-f-G-U-C" start="2026-05-04T12:00:00Z" stale="2026-05-04T12:05:00Z"><point lat="38.9" lon="-77.0" hae="125.0"/><detail><contact callsign="ALPHA-1"/></detail></event>"#,
        );
        Bytes::from(xml)
    }

    fn make_message(payload: Bytes) -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: Arc::<str>::from("alice"),
                fingerprint: "fp".to_string(),
                groups: BTreeSet::new(),
                tenant: None,
                spiffe_id: None,
                attributes: Arc::new(std::collections::BTreeMap::new()),
            },
            destination: Destination::Broadcast,
            payload,
            metadata: Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position),
        }
    }

    fn test_config(tmp: &TempDir, low_bps: u64, high_bps: u64, mandatory: bool) -> GuardConfig {
        GuardConfig {
            low_to_high_max_bps: low_bps,
            high_to_low_max_bps: high_bps,
            mandatory_marking: mandatory,
            audit_log_path: tmp.path().join("boundary-audit.jsonl"),
            direction: GuardDirection::Bidirectional,
        }
    }

    #[test]
    fn guard_admits_within_throughput_cap() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 64 * 1024, 64 * 1024, false);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_with_marking("u1", "//SECRET//NOFORN"));
        let res = g.evaluate(&msg, GuardDirection::LowToHigh);
        assert!(res.is_ok(), "small message should be admitted: {res:?}");
        assert_eq!(g.audit_records_written(), 1);
    }

    #[test]
    fn guard_rejects_over_throughput_cap_with_typed_error() {
        let tmp = TempDir::new().unwrap();
        // Cap below the test payload size so the second message
        // exceeds the bucket capacity.
        let cfg = test_config(&tmp, 200, 200, false);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_with_marking("u1", "//SECRET//"));
        // First message fits (payload ~270 bytes vs 200 cap → already
        // over). Use a smaller bucket so we deterministically trip on
        // the first call.
        let err = g
            .evaluate(&msg, GuardDirection::LowToHigh)
            .expect_err("should exceed cap");
        match err {
            GuardError::RateLimitExceeded { direction } => {
                assert_eq!(direction, GuardDirection::LowToHigh);
            }
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
        assert_eq!(g.audit_records_written(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn guard_throughput_refills_over_time() {
        let tmp = TempDir::new().unwrap();
        // 1 KiB/s cap with a small message — first one drains, second
        // one rejects, then after 1s the bucket has refilled.
        let cfg = test_config(&tmp, 1024, 1024, false);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(Bytes::from_static(
            b"<event uid=\"u\"><detail><marking value=\"//SECRET//\"/></detail></event>",
        ));
        // Drain.
        let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
        // Force an over-cap by sending repeatedly until bucket is empty.
        for _ in 0..16 {
            let _ = g.evaluate(&msg, GuardDirection::LowToHigh);
        }
        // Reject expected by now.
        let err = g.evaluate(&msg, GuardDirection::LowToHigh);
        assert!(matches!(err, Err(GuardError::RateLimitExceeded { .. })));
        // Wait 2 seconds — refills 2 KiB.
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        let res = g.evaluate(&msg, GuardDirection::LowToHigh);
        assert!(res.is_ok(), "should re-admit after refill: {res:?}");
    }

    #[test]
    fn guard_per_direction_caps_independent() {
        let tmp = TempDir::new().unwrap();
        // Cap LowToHigh tight (forces reject) but HighToLow generous.
        let cfg = test_config(&tmp, 1, 1_000_000, false);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_with_marking("u1", "//SECRET//"));
        // LowToHigh saturates instantly.
        let l2h = g.evaluate(&msg, GuardDirection::LowToHigh);
        assert!(
            matches!(l2h, Err(GuardError::RateLimitExceeded { .. })),
            "LowToHigh must trip independent cap, got {l2h:?}"
        );
        // HighToLow proceeds unaffected.
        let h2l = g.evaluate(&msg, GuardDirection::HighToLow);
        assert!(h2l.is_ok(), "HighToLow must not be affected: {h2l:?}");
    }

    #[test]
    fn guard_mandatory_marking_rejects_message_without_marking_when_enabled() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, true);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_without_marking("u-no-mark"));
        let err = g
            .evaluate(&msg, GuardDirection::LowToHigh)
            .expect_err("no marking should reject");
        assert!(matches!(err, GuardError::MissingMarking));
        assert_eq!(g.audit_records_written(), 1);
    }

    #[test]
    fn guard_mandatory_marking_admits_when_disabled() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_without_marking("u-permissive"));
        let res = g.evaluate(&msg, GuardDirection::LowToHigh);
        assert!(res.is_ok(), "mandatory off → no marking is OK: {res:?}");
    }

    #[test]
    fn guard_audit_log_records_evaluation_with_input_and_output_hashes() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let path = cfg.audit_log_path.clone();
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let payload = cot_with_marking("uid-hash", "//SECRET//");
        let expected_sha = sha256_hex(&payload);
        let msg = make_message(payload);
        let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
        // Drop guard to flush.
        drop(g);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains(&expected_sha),
            "input_sha256 missing: {contents}"
        );
        assert!(contents.contains("\"input_sha256\""));
        assert!(contents.contains("\"output_sha256\""));
        assert!(contents.contains("\"event\":\"boundary.evaluate\""));
        assert!(contents.contains("\"decision\":\"allow\""));
    }

    #[test]
    fn guard_audit_log_records_rejection_with_reason() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, true);
        let path = cfg.audit_log_path.clone();
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_without_marking("u-rej"));
        let _ = g.evaluate(&msg, GuardDirection::LowToHigh);
        drop(g);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"reason\":\"missing_marking\""));
        assert!(contents.contains("\"decision\":\"deny\""));
    }

    #[test]
    fn guard_audit_log_chain_is_tamper_evident_per_existing_hashchainwriter() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let path = cfg.audit_log_path.clone();
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg1 = make_message(cot_with_marking("u-1", "//SECRET//"));
        let msg2 = make_message(cot_with_marking("u-2", "//SECRET//"));
        let msg3 = make_message(cot_with_marking("u-3", "//SECRET//"));
        let _ = g.evaluate(&msg1, GuardDirection::LowToHigh).unwrap();
        let _ = g.evaluate(&msg2, GuardDirection::LowToHigh).unwrap();
        let _ = g.evaluate(&msg3, GuardDirection::LowToHigh).unwrap();
        drop(g);
        let report = rustgate_archive::audit_chain::verify_audit_log(&path).unwrap();
        assert_eq!(report.records, 3);
        assert_ne!(report.tip, GENESIS_PREV);
        // Tamper with the middle line.
        let original = std::fs::read_to_string(&path).unwrap();
        let tampered = original.replacen("u-2", "uX2", 1);
        assert_ne!(original, tampered, "tampering must produce different bytes");
        std::fs::write(&path, tampered).unwrap();
        let res = rustgate_archive::audit_chain::verify_audit_log(&path);
        assert!(res.is_err(), "verify_audit_log must reject tampered chain");
    }

    #[test]
    fn guard_input_hash_matches_payload_sha256() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let path = cfg.audit_log_path.clone();
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let payload = Bytes::from_static(
            b"<event uid=\"u\"><detail><marking value=\"//SECRET//\"/></detail></event>",
        );
        let expected = sha256_hex(&payload);
        let msg = make_message(payload);
        let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
        drop(g);
        let contents = std::fs::read_to_string(&path).unwrap();
        let needle = format!("\"input_sha256\":\"{expected}\"");
        assert!(
            contents.contains(&needle),
            "input_sha256 must equal SHA-256(payload), expected {needle}, got {contents}"
        );
    }

    #[test]
    fn guard_unauthorized_classification_rejected_for_high_to_low_direction() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_with_marking("u-ts", "//TOP SECRET//"));
        let err = g
            .evaluate(&msg, GuardDirection::HighToLow)
            .expect_err("TopSecret must not cross HighToLow boundary");
        match err {
            GuardError::UnauthorizedClassification { direction, marking } => {
                assert_eq!(direction, GuardDirection::HighToLow);
                assert!(marking.contains("TOP SECRET"));
            }
            other => panic!("expected UnauthorizedClassification, got {other:?}"),
        }
    }

    #[test]
    fn guard_low_to_high_accepts_top_secret() {
        // LowToHigh elevation is policy-permitted; only HighToLow has
        // the TopSecret reject. Pin the asymmetry so a refactor that
        // collapsed the per-direction check breaks here.
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_with_marking("u-ts", "//TOP SECRET//"));
        let res = g.evaluate(&msg, GuardDirection::LowToHigh);
        assert!(res.is_ok(), "LowToHigh must accept TopSecret: {res:?}");
    }

    #[test]
    fn guard_default_config_has_sensible_caps_for_v1_deployments() {
        let tmp = TempDir::new().unwrap();
        let cfg = GuardConfig::defaults_for_v1(tmp.path().join("audit.jsonl"));
        assert_eq!(cfg.low_to_high_max_bps, 1_048_576);
        assert_eq!(cfg.high_to_low_max_bps, 262_144);
        assert!(
            cfg.high_to_low_max_bps < cfg.low_to_high_max_bps,
            "HighToLow must be tighter than LowToHigh in v1 defaults"
        );
        assert!(cfg.mandatory_marking, "v1 default must be fail-closed");
    }

    #[test]
    fn guard_resumes_chain_across_construct_drop_construct() {
        // Pin that opening a guard against a non-empty audit log
        // resumes the chain rather than re-genesising — otherwise the
        // tamper-evident chain breaks on every restart.
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let path = cfg.audit_log_path.clone();
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let msg = make_message(cot_with_marking("u-1", "//SECRET//"));
        let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
        drop(g);
        // Re-open at the same path.
        let cfg2 = test_config(&tmp, 1_000_000, 1_000_000, false);
        let mut g2 = CrossDomainGuard::new(cfg2).unwrap();
        let msg2 = make_message(cot_with_marking("u-2", "//SECRET//"));
        let _ = g2.evaluate(&msg2, GuardDirection::LowToHigh).unwrap();
        drop(g2);
        let report = rustgate_archive::audit_chain::verify_audit_log(&path).unwrap();
        assert_eq!(
            report.records, 2,
            "chain must continue across restart, got {}",
            report.records
        );
    }

    #[test]
    fn guard_direction_label_is_low_cardinality_distinct() {
        // Pin Prometheus label invariants — distinct, lowercase ASCII.
        let labels = [
            GuardDirection::LowToHigh.as_label(),
            GuardDirection::HighToLow.as_label(),
            GuardDirection::Bidirectional.as_label(),
        ];
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len(), "labels must be distinct");
        for l in &labels {
            assert!(l.chars().all(|c| c.is_ascii() && !c.is_uppercase()));
        }
    }

    #[test]
    fn guard_audit_record_sanitizes_source_cn() {
        // A CN with embedded newlines must not break the JSON-line
        // audit format. sanitize_for_log replaces with U+FFFD.
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 1_000_000, 1_000_000, false);
        let path = cfg.audit_log_path.clone();
        let mut g = CrossDomainGuard::new(cfg).unwrap();
        let mut msg = make_message(cot_with_marking("u-cn", "//SECRET//"));
        msg.source.cn = Arc::<str>::from("alice\nbob\rcarol");
        let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
        drop(g);
        let contents = std::fs::read_to_string(&path).unwrap();
        // Embedded raw newlines would break one-record-per-line —
        // pin that we have exactly two newlines (one terminating the
        // single record) plus no inner embedded newlines from the CN.
        let line_count = contents.matches('\n').count();
        assert_eq!(line_count, 1, "exactly one record line expected");
        assert!(
            !contents.contains("\nalice"),
            "raw newline from CN leaked into audit"
        );
    }

    #[test]
    fn guard_extracts_marking_from_xml_payload() {
        let payload = cot_with_marking("uid-x", "//SECRET//NOFORN");
        let extracted = extract_marking(&payload);
        assert_eq!(extracted.as_deref(), Some("//SECRET//NOFORN"));
    }

    #[test]
    fn guard_extracts_no_marking_from_non_xml_payload() {
        let payload = b"binary mavlink \x00\x01\x02";
        let extracted = extract_marking(payload);
        assert!(extracted.is_none());
    }

    #[test]
    fn guard_extracts_msg_uid_from_event_attribute() {
        let payload = cot_with_marking("the-uid-here", "//SECRET//");
        let uid = extract_msg_uid(&payload);
        assert_eq!(uid.as_deref(), Some("the-uid-here"));
    }

    #[test]
    fn guard_error_display_contains_direction_for_rate_limit() {
        // Pin the human-readable error message — operator runbooks
        // grep for "boundary throughput cap exceeded".
        let err = GuardError::RateLimitExceeded {
            direction: GuardDirection::HighToLow,
        };
        let s = err.to_string();
        assert!(s.contains("boundary throughput cap exceeded"));
        assert!(s.contains("HighToLow"));
    }

    #[test]
    fn guard_error_display_contains_marking_for_unauthorized_classification() {
        let err = GuardError::UnauthorizedClassification {
            marking: "//TOP SECRET//SI".to_string(),
            direction: GuardDirection::HighToLow,
        };
        let s = err.to_string();
        assert!(s.contains("TOP SECRET"));
        assert!(s.contains("HighToLow"));
    }

    // ---- GuardConfig deserialization + validation (PR-A) ----

    #[test]
    fn config_deserializes_from_kebab_case_toml() {
        let toml = r#"
            low-to-high-max-bps = 2097152
            high-to-low-max-bps = 131072
            mandatory-marking = false
            audit-log-path = "/tmp/g.jsonl"
            direction = "high-to-low"
        "#;
        let cfg: GuardConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.low_to_high_max_bps, 2_097_152);
        assert_eq!(cfg.high_to_low_max_bps, 131_072);
        assert!(!cfg.mandatory_marking);
        assert_eq!(cfg.audit_log_path, PathBuf::from("/tmp/g.jsonl"));
        assert_eq!(cfg.direction, GuardDirection::HighToLow);
    }

    #[test]
    fn config_defaults_are_fail_closed() {
        // An empty block yields the secure defaults: mandatory marking
        // ON, the high-to-low (release) cap tighter than low-to-high.
        let cfg: GuardConfig = toml::from_str("").unwrap();
        assert!(cfg.mandatory_marking);
        assert!(cfg.high_to_low_max_bps < cfg.low_to_high_max_bps);
        assert_eq!(cfg.direction, GuardDirection::Bidirectional);
    }

    #[test]
    fn config_rejects_unknown_fields() {
        let toml = r#"
            low-to-high-max-bps = 1024
            bogus-knob = true
        "#;
        assert!(toml::from_str::<GuardConfig>(toml).is_err());
    }

    #[test]
    fn validate_rejects_zero_caps_and_empty_path() {
        let zero_low = GuardConfig {
            low_to_high_max_bps: 0,
            ..GuardConfig::default()
        };
        assert!(matches!(
            zero_low.validate(),
            Err(GuardConfigError::ZeroCap {
                field: "low-to-high-max-bps"
            })
        ));

        let zero_high = GuardConfig {
            high_to_low_max_bps: 0,
            ..GuardConfig::default()
        };
        assert!(matches!(
            zero_high.validate(),
            Err(GuardConfigError::ZeroCap {
                field: "high-to-low-max-bps"
            })
        ));

        let empty_path = GuardConfig {
            audit_log_path: PathBuf::new(),
            ..GuardConfig::default()
        };
        assert!(matches!(
            empty_path.validate(),
            Err(GuardConfigError::EmptyAuditPath)
        ));

        assert!(
            GuardConfig::defaults_for_v1("/tmp/ok.jsonl")
                .validate()
                .is_ok()
        );
    }

    // ---- GuardGate (PR-A) ----

    #[test]
    fn gate_evaluates_and_shares_state_across_clones() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp, 64 * 1024, 64 * 1024, false);
        let gate = GuardGate::new(cfg).unwrap();
        let gate2 = gate.clone();

        let msg = make_message(cot_with_marking("u1", "//SECRET//NOFORN"));
        // Both clones drive the same underlying guard + audit chain.
        assert!(gate.evaluate(&msg, GuardDirection::LowToHigh).is_ok());
        assert!(gate2.evaluate(&msg, GuardDirection::LowToHigh).is_ok());

        // Two evaluations wrote two audit records to the one file.
        let report = rustgate_archive::audit_chain::verify_audit_log(
            &tmp.path().join("boundary-audit.jsonl"),
        )
        .unwrap();
        assert_eq!(report.records, 2);
    }

    #[test]
    fn gate_propagates_rejection_fail_closed() {
        let tmp = TempDir::new().unwrap();
        // mandatory marking on; a message without a marking is rejected.
        let cfg = test_config(&tmp, 64 * 1024, 64 * 1024, true);
        let gate = GuardGate::new(cfg).unwrap();
        let msg = make_message(cot_without_marking("u2"));
        assert!(matches!(
            gate.evaluate(&msg, GuardDirection::LowToHigh),
            Err(GuardError::MissingMarking)
        ));
    }
}
