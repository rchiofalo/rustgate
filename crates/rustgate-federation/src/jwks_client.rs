// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Remote JWKS (RFC 7517) URL fetching with periodic refresh and
//! fail-closed degradation. Refs #952.
//!
//! Federation operators can point at a JWKS endpoint over HTTPS and
//! have ES256 / EdDSA verifier keys hot-reload into [`JwtAuthority`]
//! without restarting the binary. The transport re-uses the federation
//! peer mTLS trust bundle (the same `rustls::ClientConfig` builder
//! `connector.rs` uses) — there is no separate JWKS-only trust path.
//!
//! ## Refresh contract
//!
//! 1. [`JwksClient::start`] spawns a background task wrapped in a
//!    [`SubsystemHandle`]. The task fetches `GET <url>` over HTTPS,
//!    parses the response as [`JsonWebKeySet`], and atomically swaps
//!    the resulting verifier map into the authority via
//!    [`JwtAuthority::install_external_verifiers`].
//! 2. The next refresh delay is taken from the response's
//!    `Cache-Control: max-age=<N>` header, clamped into
//!    `[refresh_min, refresh_max]`. Missing header → `refresh_min`.
//! 3. On HTTP 5xx or transport error, the cached keyset is preserved.
//!    No keys are rotated out (fail-closed posture). The next attempt
//!    fires after `refresh_min`.
//! 4. JWK entries are filtered by `kty`/`crv`/`alg`:
//!    - `kty=EC, crv=P-256, alg=ES256` → ES256 verifier
//!    - `kty=OKP, crv=Ed25519, alg=EdDSA` → EdDSA verifier
//!    - `kty=oct, alg=HS256` → admitted only when
//!      [`JwksConfig::allow_hs256`] is `true`. The default is `false`
//!      because a symmetric secret published over HTTP defeats the
//!      asymmetric trust boundary JWKS exists to provide.
//!
//! ## Audit events
//!
//! Each refresh emits one of:
//! - [`rustgate_core::audit::jwks_refresh_success`] (with `key_count`)
//! - [`rustgate_core::audit::jwks_refresh_failed`] (with `reason`)
//!
//! Each diff against the previous snapshot additionally emits one
//! event per added or removed kid:
//! - [`rustgate_core::audit::jwks_key_added`]
//! - [`rustgate_core::audit::jwks_key_removed`]
//!
//! ## Rotation-window state machine (closes #952)
//!
//! [`JwksClient::start`] wires a `jwks_rotation::RotationStateMachine`
//! into the live [`JwtAuthority`] so verifier installs flow through
//! the four-state `Pending → Active → Retiring → Retired` lifecycle.
//! The smoothing absorbs two edge cases the raw refresh path leaves
//! exposed:
//!
//! - **Pending → Active is gated** on a wall-time `pending_window`
//!   plus a second consecutive observation, so a typo'd JWKS push
//!   that gets rolled back within the window never registers as
//!   Active.
//! - **Active → Retiring → Retired** keeps the verifier installed
//!   for a `retiring_window` grace period after the upstream JWKS
//!   stops advertising the key, so a JWT minted just before the
//!   removal still verifies. While the kid is Retiring, every
//!   successful validation fires
//!   [`rustgate_core::audit::jwt_using_retiring_kid`] so SIEM
//!   dashboards can spot peers that have not yet rotated.
//!
//! See the module docs on `jwks_rotation` for the transition
//! table.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use rustgate_core::tasks::SubsystemHandle;
use rustgate_core::{audit, b64};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep};
use tracing::{debug, warn};

use crate::jwks_rotation::{RetainedVerifiers, RotationStateMachine, install_on_authority};
use crate::jwt::{Algorithm, ExternalVerifier, JwtAuthority};

/// Lower bound for the refresh interval. Operators MUST configure at
/// least this much delay between fetches — anything smaller would let
/// a misconfigured `Cache-Control: max-age=0` storm the upstream
/// server. Sized at 60s to match common JWKS publishers (Auth0, Okta,
/// Google) that use 1-minute negative-cache windows.
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Upper bound for the refresh interval. JWKS servers commonly return
/// 24-hour `Cache-Control` ages; a higher cap would let a stale-key
/// rotation linger longer than an attacker would tolerate.
pub const MAX_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Per-request HTTP timeout. Sized below the federation heartbeat
/// timeout (90s) so a hung JWKS server cannot wedge the federation
/// loop. Operators with intentionally slow JWKS servers can extend by
/// editing this constant — but a JWKS endpoint that takes >30s is
/// itself a misconfiguration.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default Pending → Active promotion window (closes #952). Sized to
/// match the default refresh interval so a typo'd JWKS push that is
/// rolled back within a single refresh cycle never registers as Active.
pub const DEFAULT_PENDING_WINDOW: Duration = Duration::from_secs(60);

/// Default Retiring → Retired grace window (closes #952). Five minutes
/// covers the worst case where a peer mints a JWT moments before our
/// refresh dropped its `kid` from the upstream JWKS — common token TTLs
/// are 1–5 minutes, so a 5-minute grace bridges the gap. Operators with
/// longer-TTL tokens raise this; deployments allergic to drift can
/// shorten it.
pub const DEFAULT_RETIRING_WINDOW: Duration = Duration::from_secs(300);

/// Configuration for [`JwksClient`].
///
/// Field naming follows the workspace convention of kebab-case for
/// TOML serialisation; deny-unknown-fields catches operator typos.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct JwksConfig {
    /// HTTPS URL of the JWKS endpoint, e.g.
    /// `https://idp.example.com/.well-known/jwks.json`. The URL must
    /// be HTTPS — plain HTTP refused at start-up.
    pub url: String,
    /// Floor for the refresh interval. The effective interval is
    /// `clamp(cache_control_max_age, refresh_min, refresh_max)`.
    /// Defaults to [`MIN_REFRESH_INTERVAL`] (60s).
    #[serde(default = "default_refresh_min", with = "humantime_serde_compat")]
    pub refresh_min: Duration,
    /// Ceiling for the refresh interval — see [`Self::refresh_min`].
    /// Defaults to [`MAX_REFRESH_INTERVAL`] (24h).
    #[serde(default = "default_refresh_max", with = "humantime_serde_compat")]
    pub refresh_max: Duration,
    /// When `true`, JWKS entries with `kty=oct, alg=HS256` are loaded
    /// as HMAC verifiers. Default is `false` because a JWKS over HTTP
    /// is by construction not a confidentiality boundary; symmetric
    /// secrets published this way defeat the purpose of asymmetric
    /// federation trust.
    #[serde(default)]
    pub allow_hs256: bool,
    /// Wall-time floor for the Pending → Active promotion window in
    /// the rotation-window state machine (closes #952). A newly
    /// observed `kid` must persist across at least one refresh AND
    /// remain visible for `pending_window` of wall time before the
    /// state machine flips it to Active. Defends against typo'd
    /// JWKS pushes that get rolled back within seconds. Defaults to
    /// [`DEFAULT_PENDING_WINDOW`] (60s).
    #[serde(default = "default_pending_window", with = "humantime_serde_compat")]
    pub pending_window: Duration,
    /// Grace window for the Retiring → Retired demotion (closes
    /// #952). When a `kid` drops from the upstream JWKS, the local
    /// verifier registry continues to honour it for this duration
    /// so JWTs minted just before the upstream removal still verify.
    /// Defaults to [`DEFAULT_RETIRING_WINDOW`] (300s = 5 min).
    #[serde(default = "default_retiring_window", with = "humantime_serde_compat")]
    pub retiring_window: Duration,
}

fn default_refresh_min() -> Duration {
    MIN_REFRESH_INTERVAL
}

fn default_refresh_max() -> Duration {
    MAX_REFRESH_INTERVAL
}

fn default_pending_window() -> Duration {
    DEFAULT_PENDING_WINDOW
}

fn default_retiring_window() -> Duration {
    DEFAULT_RETIRING_WINDOW
}

// Inline serde adapter for Duration → secs encoded as an integer in
// TOML. Avoids a workspace-level humantime_serde dep just for this
// config block. Deserialises any non-negative integer as seconds.
mod humantime_serde_compat {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(value.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(de)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Errors returned by [`JwksClient`].
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    /// HTTP transport, DNS, TLS, or non-2xx response.
    #[error("jwks fetch error: {0}")]
    Fetch(String),
    /// Response body did not parse as a JWKS document.
    #[error("jwks parse error: {0}")]
    Parse(String),
    /// JWKS configuration rejected at construction time.
    #[error("jwks configuration error: {0}")]
    Config(String),
    /// Failed to build the underlying `reqwest::Client` from the
    /// supplied `rustls::ClientConfig`.
    #[error("jwks http client build error: {0}")]
    ClientBuild(String),
}

/// Crate-local result alias to keep return types tidy.
pub type Result<T> = std::result::Result<T, JwksError>;

/// JSON Web Key Set wire format per RFC 7517 §5.
///
/// We intentionally accept unknown top-level fields here (no
/// `deny_unknown_fields`) because real-world JWKS publishers (Google,
/// Microsoft, AWS) frequently extend the envelope with non-standard
/// fields. We only consume `keys` and let the rest be ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonWebKeySet {
    /// Public keys advertised by the upstream issuer.
    pub keys: Vec<JsonWebKey>,
}

/// JSON Web Key wire format per RFC 7517 §4.
///
/// Field set is deliberately a superset of [`crate::jwks::Jwk`]
/// because the upstream issuer may publish additional metadata (e.g.
/// `key_ops`, `x5c`, `x5t`). We deserialise into this loose shape and
/// then validate `kty`/`crv`/`alg` ourselves before turning the entry
/// into an [`ExternalVerifier`].
#[derive(Debug, Clone, Deserialize)]
pub struct JsonWebKey {
    pub kty: String,
    pub kid: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    /// HMAC secret material, base64url-encoded. Present only on
    /// `kty=oct`. Wiped at audit boundary.
    #[serde(default)]
    pub k: Option<String>,
}

/// Background JWKS refresher. Construct with [`JwksClient::start`].
#[derive(Debug)]
pub struct JwksClient {
    /// Cached for diagnostics; the actual `reqwest::Client` lives in
    /// the spawned task.
    url: String,
}

impl JwksClient {
    /// Spawn a background JWKS refresh task and return a handle for
    /// graceful shutdown.
    ///
    /// `tls_config` is the same federation `rustls::ClientConfig`
    /// `connector.rs` builds — re-using it avoids duplicate trust
    /// management. The `authority` is the live [`JwtAuthority`]; the
    /// task atomically swaps verifier maps into it as JWKS responses
    /// arrive.
    ///
    /// # Runtime requirement
    ///
    /// **Must be called from within a tokio runtime context.** Despite
    /// the synchronous `pub fn start` signature, this function calls
    /// [`tokio::spawn`] directly. Calling it from outside a tokio
    /// runtime panics with `there is no reactor running`.
    ///
    /// The pattern is intentional: `start` is fast (it only validates
    /// the config, builds a `reqwest::Client`, and hands off to the
    /// background task), so requiring `async fn` would force every
    /// caller into an `.await` for no behavioural benefit. The cost is
    /// a runtime contract the signature does not advertise — hence
    /// this section.
    ///
    /// Returns a [`SubsystemHandle`] for graceful shutdown via
    /// [`stop_subsystem`](rustgate_core::tasks::stop_subsystem).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use std::time::Duration;
    /// use rustgate_federation::jwks_client::{
    ///     JwksClient, JwksConfig, MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL,
    ///     DEFAULT_PENDING_WINDOW, DEFAULT_RETIRING_WINDOW,
    /// };
    /// use rustgate_federation::jwt::JwtAuthority;
    ///
    /// # async fn example(
    /// #     tls_config: Arc<rustls::ClientConfig>,
    /// #     authority: Arc<JwtAuthority>,
    /// # ) {
    /// // Inside an async fn — i.e. inside a tokio runtime context.
    /// let cfg = JwksConfig {
    ///     url: "https://idp.example.com/.well-known/jwks.json".into(),
    ///     refresh_min: MIN_REFRESH_INTERVAL,
    ///     refresh_max: MAX_REFRESH_INTERVAL,
    ///     allow_hs256: false,
    ///     pending_window: DEFAULT_PENDING_WINDOW,
    ///     retiring_window: DEFAULT_RETIRING_WINDOW,
    /// };
    /// let _handle = JwksClient::start(cfg, tls_config, authority)
    ///     .expect("start jwks client");
    /// # }
    /// ```
    pub fn start(
        config: JwksConfig,
        tls_config: Arc<rustls::ClientConfig>,
        authority: Arc<JwtAuthority>,
    ) -> Result<SubsystemHandle> {
        validate_config(&config)?;
        let client = build_http_client(tls_config)?;

        let url = config.url.clone();
        let cli = JwksClient { url: url.clone() };

        // Wire the rotation-window state machine into the authority
        // so the post-validate hook fires `audit::jwt_using_retiring_kid`
        // for any kid in Retiring state. The state machine is shared
        // between the refresh task (transitions) and the verifier
        // (notify_kid_used) — both paths are lock-free in steady state.
        let rotation = Arc::new(RotationStateMachine::new(
            config.pending_window,
            config.retiring_window,
            url.clone(),
        ));
        install_on_authority(Arc::clone(&rotation), &authority);
        let retained = Arc::new(RetainedVerifiers::new());

        let shutdown = Arc::new(Notify::new());
        let shutdown_inner = Arc::clone(&shutdown);
        let task = tokio::spawn(cli.run(
            client,
            config,
            authority,
            rotation,
            retained,
            shutdown_inner,
        ));

        debug!(url = %url, "jwks client started");
        Ok(SubsystemHandle::new(shutdown, task))
    }

    /// Refresh loop body. Public-but-doc-hidden to allow targeted
    /// integration tests to drive a single iteration without going
    /// through the full timer/notify dance.
    async fn run(
        self,
        client: reqwest::Client,
        config: JwksConfig,
        authority: Arc<JwtAuthority>,
        rotation: Arc<RotationStateMachine>,
        retained: Arc<RetainedVerifiers>,
        shutdown: Arc<Notify>,
    ) {
        // Track last-installed kids so we can emit add/remove audit
        // events on each refresh. The JwtAuthority's external_verifiers
        // is the source of truth for active state — this set is kept
        // co-mutated to avoid re-loading the ArcSwap snapshot just to
        // diff.
        let mut current: HashMap<String, Algorithm> = HashMap::new();
        loop {
            let next_delay = match refresh_once_with_rotation(
                &client,
                &config,
                &authority,
                &rotation,
                &retained,
                &mut current,
            )
            .await
            {
                Ok(delay) => delay,
                Err(e) => {
                    audit::jwks_refresh_failed(&self.url, &e.to_string());
                    warn!(url = %self.url, error = %e, "jwks refresh failed; cached keyset preserved");
                    // Still advance the Retiring → Retired grace clock so a
                    // rotated-out (possibly compromised) kid is dropped from
                    // the live verifier once its window elapses, even while
                    // the JWKS endpoint is unreachable (#1627).
                    advance_grace_on_refresh_failure(
                        &authority,
                        &rotation,
                        &retained,
                        &mut current,
                        &self.url,
                        Instant::now(),
                    );
                    config.refresh_min
                }
            };
            tokio::select! {
                () = sleep(next_delay) => {}
                () = shutdown.notified() => {
                    debug!(url = %self.url, "jwks client received shutdown");
                    return;
                }
            }
        }
    }
}

/// Validate the operator-supplied configuration. Enforces:
/// - `url` is non-empty and starts with `https://` (HTTP refused).
/// - `refresh_min >= 60s` and `refresh_max <= 24h`.
/// - `refresh_min <= refresh_max`.
fn validate_config(config: &JwksConfig) -> Result<()> {
    if config.url.is_empty() {
        return Err(JwksError::Config("url is empty".into()));
    }
    if !config.url.starts_with("https://") {
        return Err(JwksError::Config(format!(
            "url must be HTTPS (got {})",
            config.url
        )));
    }
    if config.refresh_min < MIN_REFRESH_INTERVAL {
        return Err(JwksError::Config(format!(
            "refresh_min must be >= {}s (got {}s)",
            MIN_REFRESH_INTERVAL.as_secs(),
            config.refresh_min.as_secs()
        )));
    }
    if config.refresh_max > MAX_REFRESH_INTERVAL {
        return Err(JwksError::Config(format!(
            "refresh_max must be <= {}s (got {}s)",
            MAX_REFRESH_INTERVAL.as_secs(),
            config.refresh_max.as_secs()
        )));
    }
    if config.refresh_min > config.refresh_max {
        return Err(JwksError::Config(format!(
            "refresh_min ({}s) must be <= refresh_max ({}s)",
            config.refresh_min.as_secs(),
            config.refresh_max.as_secs()
        )));
    }
    Ok(())
}

/// Build a `reqwest::Client` that uses the supplied
/// `rustls::ClientConfig` for transport. Wraps with a request timeout
/// so a slow JWKS server cannot wedge the refresh loop.
fn build_http_client(tls_config: Arc<rustls::ClientConfig>) -> Result<reqwest::Client> {
    // Hand the `rustls::ClientConfig` to reqwest's preconfigured-TLS
    // builder. This bypasses reqwest's default trust store entirely
    // and re-uses whatever trust + client-cert material the federation
    // connector already loaded.
    let cfg = match Arc::try_unwrap(tls_config) {
        Ok(c) => c,
        Err(arc) => (*arc).clone(),
    };
    reqwest::Client::builder()
        .use_preconfigured_tls(cfg)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| JwksError::ClientBuild(e.to_string()))
}

/// Run one refresh cycle. Returns the duration to wait before the
/// next refresh, derived from the response's `Cache-Control: max-age`
/// header (clamped to `[refresh_min, refresh_max]`).
///
/// Visibility: `pub` rather than `pub(crate)` so integration tests
/// can drive a single iteration over a wiremock HTTP listener
/// (wiremock does not support TLS, but the HTTPS guard is enforced
/// in `validate_config` — testing the refresh body directly is
/// the only way to cover the protocol-layer invariants without an
/// in-process TLS server). The `current` map is owned by the caller
/// so the test can assert on the diff stream.
pub async fn refresh_once(
    client: &reqwest::Client,
    config: &JwksConfig,
    authority: &Arc<JwtAuthority>,
    current: &mut HashMap<String, Algorithm>,
) -> Result<Duration> {
    let response = client
        .get(&config.url)
        .send()
        .await
        .map_err(|e| JwksError::Fetch(e.to_string()))?;
    if !response.status().is_success() {
        return Err(JwksError::Fetch(format!(
            "non-success status {}",
            response.status()
        )));
    }
    let max_age_hint = parse_cache_control_max_age(&response);
    let body = response
        .bytes()
        .await
        .map_err(|e| JwksError::Fetch(e.to_string()))?;
    let parsed: JsonWebKeySet =
        serde_json::from_slice(&body).map_err(|e| JwksError::Parse(e.to_string()))?;

    let next = build_external_verifiers(&parsed, config.allow_hs256);

    // Diff: emit one add event per new kid, one remove event per kid
    // that disappeared from the upstream response. The diff drives
    // both audit emission and the kept-state map for the next tick.
    diff_and_audit(current, &next, &config.url);

    let key_count = next.len();
    authority.install_external_verifiers(next.clone());
    audit::jwks_refresh_success(&config.url, key_count);
    debug!(
        url = %config.url,
        key_count = key_count,
        "jwks refresh installed verifier set"
    );

    *current = next
        .into_iter()
        .map(|(kid, v)| (kid, v.algorithm()))
        .collect();
    Ok(clamp_refresh_delay(max_age_hint, config))
}

/// Run one refresh cycle and drive the [`RotationStateMachine`] (refs
/// #952). Identical to [`refresh_once`] except verifier installation
/// goes through [`RotationStateMachine::filter_for_install`], which
/// excludes Pending kids (not yet trusted) and Retired kids (grace
/// elapsed) and includes Retiring kids from the supplied
/// [`RetainedVerifiers`] cache.
///
/// Visibility: `pub` so `JwksClient::run` can call it without the
/// state machine leaking through the public surface, while integration
/// tests can drive a single iteration directly. The arity is wide
/// because the rotation-state-machine + retained-cache pair has to
/// flow through the call site; bundling them into a struct would push
/// the same fan-in upstream without reducing live references.
pub async fn refresh_once_with_rotation(
    client: &reqwest::Client,
    config: &JwksConfig,
    authority: &Arc<JwtAuthority>,
    rotation: &Arc<RotationStateMachine>,
    retained: &Arc<RetainedVerifiers>,
    current: &mut HashMap<String, Algorithm>,
) -> Result<Duration> {
    let response = client
        .get(&config.url)
        .send()
        .await
        .map_err(|e| JwksError::Fetch(e.to_string()))?;
    if !response.status().is_success() {
        return Err(JwksError::Fetch(format!(
            "non-success status {}",
            response.status()
        )));
    }
    let max_age_hint = parse_cache_control_max_age(&response);
    let body = response
        .bytes()
        .await
        .map_err(|e| JwksError::Fetch(e.to_string()))?;
    let parsed: JsonWebKeySet =
        serde_json::from_slice(&body).map_err(|e| JwksError::Parse(e.to_string()))?;

    let next = build_external_verifiers(&parsed, config.allow_hs256);

    // Drive the state machine: every observed kid becomes a Pending /
    // Active observation; missing kids transition Active → Retiring or
    // Retiring → Retired as appropriate.
    let observed: HashSet<String> = next.keys().cloned().collect();
    let transitions = rotation.observe_refresh(&observed, Instant::now());

    // Cache freshly-fetched verifiers so that Retiring kids that
    // dropped out of `next` keep verifying during the grace window.
    retained.upsert(&next);
    for kid in &transitions.retired {
        retained.forget(kid);
    }

    // Compute the install set: Active kids from `next` plus Retiring
    // kids from the retained cache. Pending and Retired kids are
    // filtered out by `filter_for_install`.
    let install = rotation.filter_for_install(next.clone(), &retained.snapshot());

    // Diff: emit add/remove audit events against the installed set so
    // SIEM rules see the same set the verifier path serves. The diff
    // is computed against `current` rather than `next` so a Pending
    // kid does not flap an `added` event on every refresh prior to
    // promotion.
    diff_and_audit(current, &install, &config.url);

    let key_count = install.len();
    authority.install_external_verifiers(install.clone());
    audit::jwks_refresh_success(&config.url, key_count);
    debug!(
        url = %config.url,
        key_count = key_count,
        promoted = transitions.promoted.len(),
        demoted = transitions.demoted.len(),
        retired = transitions.retired.len(),
        pending_pruned = transitions.pending_pruned.len(),
        "jwks refresh installed verifier set with rotation state machine"
    );

    *current = install
        .into_iter()
        .map(|(kid, v)| (kid, v.algorithm()))
        .collect();
    Ok(clamp_refresh_delay(max_age_hint, config))
}

/// Advance the Retiring → Retired grace clock when the JWKS refresh is failing
/// and re-install the verifier set if any kid was retired, so a rotated-out
/// (possibly compromised) kid is dropped from the live verifier once its
/// window elapses even during an upstream outage (#1627).
///
/// Without a fresh JWKS, the install set is recomputed from the retained
/// verifier cache: [`RotationStateMachine::filter_for_install`] keeps Active
/// kids and the Retiring kids still inside their grace window, and the
/// just-retired kids are first dropped from the cache so they fall out of both
/// sources. A no-op when nothing crossed its grace boundary this tick.
fn advance_grace_on_refresh_failure(
    authority: &Arc<JwtAuthority>,
    rotation: &Arc<RotationStateMachine>,
    retained: &Arc<RetainedVerifiers>,
    current: &mut HashMap<String, Algorithm>,
    url: &str,
    now: Instant,
) {
    let retired = rotation.advance_grace(now);
    if retired.is_empty() {
        return;
    }
    for kid in &retired {
        retained.forget(kid);
    }
    let snapshot = retained.snapshot();
    let install = rotation.filter_for_install(snapshot.clone(), &snapshot);
    diff_and_audit(current, &install, url);
    authority.install_external_verifiers(install.clone());
    *current = install
        .into_iter()
        .map(|(kid, v)| (kid, v.algorithm()))
        .collect();
    warn!(
        url = %url,
        retired = retired.len(),
        "jwks refresh failing; kids past their retiring grace window were retired and removed from the verifier set"
    );
}

/// Convert a parsed JWKS into a map of kid → ExternalVerifier,
/// filtering out unsupported / malformed entries. HS256 entries are
/// rejected unless `allow_hs256` is `true`.
fn build_external_verifiers(
    jwks: &JsonWebKeySet,
    allow_hs256: bool,
) -> HashMap<String, ExternalVerifier> {
    let mut map: HashMap<String, ExternalVerifier> = HashMap::new();
    // Per-entry parse failures and HS256 opt-out skips are NOT
    // security events — they are data-validation rejections inside a
    // refresh whose outcome is already captured by the surrounding
    // `audit::jwks_refresh_success` (with `key_count`) emission. The
    // `playbook-drift-ok` markers below acknowledge the rejection-
    // audit co-location rule and document why the per-entry warns
    // intentionally do not trigger an extra audit event.
    for jwk in &jwks.keys {
        if jwk.kid.is_empty() {
            warn!("jwks entry skipped: missing kid");
            continue;
        }
        let alg = jwk.alg.as_deref().unwrap_or("");
        match (jwk.kty.as_str(), jwk.crv.as_deref(), alg) {
            ("EC", Some("P-256"), "ES256") => match decode_es256(jwk) {
                Ok(v) => {
                    let _ = map.insert(jwk.kid.clone(), v);
                }
                Err(e) => warn!(kid = %jwk.kid, error = %e, "jwks ES256 entry rejected"), // playbook-drift-ok: per-entry parse skip; refresh outcome is audited via jwks_refresh_success(key_count)
            },
            ("OKP", Some("Ed25519"), "EdDSA") => match decode_ed25519(jwk) {
                Ok(v) => {
                    let _ = map.insert(jwk.kid.clone(), v);
                }
                Err(e) => warn!(kid = %jwk.kid, error = %e, "jwks EdDSA entry rejected"), // playbook-drift-ok: per-entry parse skip; refresh outcome is audited via jwks_refresh_success(key_count)
            },
            ("oct", _, "HS256") => {
                if !allow_hs256 {
                    warn!(
                        kid = %jwk.kid,
                        "jwks HS256 entry rejected: allow_hs256 is false"
                    );
                    continue;
                }
                match decode_hs256(jwk) {
                    Ok(v) => {
                        let _ = map.insert(jwk.kid.clone(), v);
                    }
                    Err(e) => warn!(kid = %jwk.kid, error = %e, "jwks HS256 entry rejected"), // playbook-drift-ok: per-entry parse skip; refresh outcome is audited via jwks_refresh_success(key_count)
                }
            }
            _ => warn!(
                kid = %jwk.kid,
                kty = %jwk.kty,
                crv = ?jwk.crv,
                alg = %alg,
                "jwks entry skipped: unsupported kty/crv/alg combination"
            ),
        }
    }
    map
}

/// Decode an ES256 entry: kty=EC, crv=P-256, alg=ES256, x+y base64url-
/// encoded 32-byte coordinates. Reconstructs SEC1 uncompressed
/// (`0x04 || x || y` = 65 bytes) which is the form
/// [`JwtAuthority::with_es256_verifier`] consumes.
fn decode_es256(jwk: &JsonWebKey) -> Result<ExternalVerifier> {
    let x_b64 = jwk
        .x
        .as_deref()
        .ok_or_else(|| JwksError::Parse(format!("ES256 jwk {} missing x", jwk.kid)))?;
    let y_b64 = jwk
        .y
        .as_deref()
        .ok_or_else(|| JwksError::Parse(format!("ES256 jwk {} missing y", jwk.kid)))?;
    let x = b64::decode_url_safe(x_b64)
        .map_err(|e| JwksError::Parse(format!("ES256 jwk {} bad x: {e}", jwk.kid)))?;
    let y = b64::decode_url_safe(y_b64)
        .map_err(|e| JwksError::Parse(format!("ES256 jwk {} bad y: {e}", jwk.kid)))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(JwksError::Parse(format!(
            "ES256 jwk {} coordinates must be 32 bytes (got x={}, y={})",
            jwk.kid,
            x.len(),
            y.len()
        )));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    Ok(ExternalVerifier::Es256(sec1))
}

/// Decode an Ed25519 entry: kty=OKP, crv=Ed25519, alg=EdDSA, x is the
/// base64url-encoded 32-byte raw public key.
fn decode_ed25519(jwk: &JsonWebKey) -> Result<ExternalVerifier> {
    let x_b64 = jwk
        .x
        .as_deref()
        .ok_or_else(|| JwksError::Parse(format!("Ed25519 jwk {} missing x", jwk.kid)))?;
    let x = b64::decode_url_safe(x_b64)
        .map_err(|e| JwksError::Parse(format!("Ed25519 jwk {} bad x: {e}", jwk.kid)))?;
    if x.len() != 32 {
        return Err(JwksError::Parse(format!(
            "Ed25519 jwk {} key must be 32 bytes (got {})",
            jwk.kid,
            x.len()
        )));
    }
    Ok(ExternalVerifier::EdDsa(x))
}

/// Decode an HS256 entry: kty=oct, alg=HS256, k is the base64url-
/// encoded HMAC secret. Caller is responsible for opting in via
/// `allow_hs256` because publishing a symmetric secret over HTTP
/// breaks the trust boundary.
fn decode_hs256(jwk: &JsonWebKey) -> Result<ExternalVerifier> {
    let k_b64 = jwk
        .k
        .as_deref()
        .ok_or_else(|| JwksError::Parse(format!("HS256 jwk {} missing k", jwk.kid)))?;
    let k = b64::decode_url_safe(k_b64)
        .map_err(|e| JwksError::Parse(format!("HS256 jwk {} bad k: {e}", jwk.kid)))?;
    if k.len() < 32 {
        return Err(JwksError::Parse(format!(
            "HS256 jwk {} secret must be >= 32 bytes (got {})",
            jwk.kid,
            k.len()
        )));
    }
    Ok(ExternalVerifier::Hs256(zeroize::Zeroizing::new(k)))
}

/// Inspect `Cache-Control: max-age=<N>` and return the parsed seconds.
/// Missing header or unparseable value → `None`. Other directives
/// (`no-store`, `private`, …) are intentionally ignored — JWKS is by
/// construction a public document and the only directive operationally
/// relevant to the refresh loop is `max-age`.
fn parse_cache_control_max_age(response: &reqwest::Response) -> Option<Duration> {
    let raw = response.headers().get(reqwest::header::CACHE_CONTROL)?;
    let s = raw.to_str().ok()?;
    for token in s.split(',') {
        let token = token.trim();
        if let Some(rest) = token.strip_prefix("max-age=")
            && let Ok(secs) = rest.parse::<u64>()
        {
            return Some(Duration::from_secs(secs));
        }
    }
    None
}

/// Clamp the upstream-suggested refresh delay into
/// `[refresh_min, refresh_max]`. Missing hint → `refresh_min`.
fn clamp_refresh_delay(hint: Option<Duration>, config: &JwksConfig) -> Duration {
    match hint {
        Some(d) => d.clamp(config.refresh_min, config.refresh_max),
        None => config.refresh_min,
    }
}

/// Compute the diff between `current` (last installed kid → alg) and
/// `next` (this refresh's kid → ExternalVerifier) and emit one
/// audit event per added / removed kid. `current` is borrowed
/// immutably here — the caller updates it after the install completes
/// so a panic in audit emission cannot leave the diff state ahead of
/// the active map.
fn diff_and_audit(
    current: &HashMap<String, Algorithm>,
    next: &HashMap<String, ExternalVerifier>,
    url: &str,
) {
    for (kid, verifier) in next {
        if !current.contains_key(kid) {
            audit::jwks_key_added(url, kid, &verifier.algorithm().to_string());
        }
    }
    for kid in current.keys() {
        if !next.contains_key(kid) {
            audit::jwks_key_removed(url, kid);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn validate_config_rejects_plain_http() {
        let cfg = JwksConfig {
            url: "http://idp.example/.well-known/jwks.json".into(),
            refresh_min: MIN_REFRESH_INTERVAL,
            refresh_max: MAX_REFRESH_INTERVAL,
            allow_hs256: false,
            pending_window: DEFAULT_PENDING_WINDOW,
            retiring_window: DEFAULT_RETIRING_WINDOW,
        };
        let err = validate_config(&cfg).expect_err("must reject http://");
        assert!(matches!(err, JwksError::Config(_)));
    }

    #[test]
    fn validate_config_rejects_min_below_floor() {
        let cfg = JwksConfig {
            url: "https://idp.example/.well-known/jwks.json".into(),
            refresh_min: Duration::from_secs(30),
            refresh_max: MAX_REFRESH_INTERVAL,
            allow_hs256: false,
            pending_window: DEFAULT_PENDING_WINDOW,
            retiring_window: DEFAULT_RETIRING_WINDOW,
        };
        let err = validate_config(&cfg).expect_err("must reject sub-floor refresh_min");
        assert!(matches!(err, JwksError::Config(_)));
    }

    #[test]
    fn validate_config_rejects_max_above_ceiling() {
        let cfg = JwksConfig {
            url: "https://idp.example/.well-known/jwks.json".into(),
            refresh_min: MIN_REFRESH_INTERVAL,
            refresh_max: Duration::from_secs(48 * 60 * 60),
            allow_hs256: false,
            pending_window: DEFAULT_PENDING_WINDOW,
            retiring_window: DEFAULT_RETIRING_WINDOW,
        };
        let err = validate_config(&cfg).expect_err("must reject above-ceiling refresh_max");
        assert!(matches!(err, JwksError::Config(_)));
    }

    #[test]
    fn validate_config_rejects_min_above_max() {
        let cfg = JwksConfig {
            url: "https://idp.example/.well-known/jwks.json".into(),
            refresh_min: Duration::from_secs(7200),
            refresh_max: Duration::from_secs(120),
            allow_hs256: false,
            pending_window: DEFAULT_PENDING_WINDOW,
            retiring_window: DEFAULT_RETIRING_WINDOW,
        };
        let err = validate_config(&cfg).expect_err("must reject inverted refresh_min/max");
        assert!(matches!(err, JwksError::Config(_)));
    }

    #[test]
    fn clamp_refresh_delay_uses_min_when_hint_missing() {
        let cfg = JwksConfig {
            url: "https://idp.example/.well-known/jwks.json".into(),
            refresh_min: Duration::from_secs(120),
            refresh_max: Duration::from_secs(3600),
            allow_hs256: false,
            pending_window: DEFAULT_PENDING_WINDOW,
            retiring_window: DEFAULT_RETIRING_WINDOW,
        };
        assert_eq!(clamp_refresh_delay(None, &cfg), Duration::from_secs(120));
    }

    #[test]
    fn clamp_refresh_delay_clamps_into_window() {
        let cfg = JwksConfig {
            url: "https://idp.example/.well-known/jwks.json".into(),
            refresh_min: Duration::from_secs(120),
            refresh_max: Duration::from_secs(3600),
            allow_hs256: false,
            pending_window: DEFAULT_PENDING_WINDOW,
            retiring_window: DEFAULT_RETIRING_WINDOW,
        };
        assert_eq!(
            clamp_refresh_delay(Some(Duration::from_secs(30)), &cfg),
            Duration::from_secs(120),
            "below floor → clamp up to refresh_min"
        );
        assert_eq!(
            clamp_refresh_delay(Some(Duration::from_secs(7200)), &cfg),
            Duration::from_secs(3600),
            "above ceiling → clamp down to refresh_max"
        );
        assert_eq!(
            clamp_refresh_delay(Some(Duration::from_secs(900)), &cfg),
            Duration::from_secs(900),
            "in window → passed through"
        );
    }

    #[test]
    fn build_external_verifiers_skips_hs256_when_disallowed() {
        let raw = serde_json::json!({
            "keys": [
                {
                    "kty": "oct",
                    "kid": "k-sym",
                    "alg": "HS256",
                    "k": "dGhpcy1pcy0zMi1ieXRlcy10ZXN0LWtleS1hYWFhYWE"
                }
            ]
        });
        let parsed: JsonWebKeySet = serde_json::from_value(raw).unwrap();
        let map = build_external_verifiers(&parsed, false);
        assert!(
            map.is_empty(),
            "HS256 must be filtered when allow_hs256=false"
        );
    }

    #[test]
    fn build_external_verifiers_admits_hs256_when_allowed() {
        let raw = serde_json::json!({
            "keys": [
                {
                    "kty": "oct",
                    "kid": "k-sym",
                    "alg": "HS256",
                    "k": "dGhpcy1pcy0zMi1ieXRlcy10ZXN0LWtleS1hYWFhYWE"
                }
            ]
        });
        let parsed: JsonWebKeySet = serde_json::from_value(raw).unwrap();
        let map = build_external_verifiers(&parsed, true);
        assert_eq!(map.len(), 1, "HS256 must load when allow_hs256=true");
        assert!(matches!(map.get("k-sym"), Some(ExternalVerifier::Hs256(_))));
    }

    #[test]
    fn build_external_verifiers_skips_entry_with_empty_kid() {
        let raw = serde_json::json!({
            "keys": [
                {
                    "kty": "EC",
                    "kid": "",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            ]
        });
        let parsed: JsonWebKeySet = serde_json::from_value(raw).unwrap();
        let map = build_external_verifiers(&parsed, false);
        assert!(map.is_empty(), "missing-kid entries must be dropped");
    }

    #[test]
    fn build_external_verifiers_skips_unsupported_alg() {
        let raw = serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "k-rsa",
                    "alg": "RS256"
                }
            ]
        });
        let parsed: JsonWebKeySet = serde_json::from_value(raw).unwrap();
        let map = build_external_verifiers(&parsed, true);
        assert!(
            map.is_empty(),
            "unsupported kty/alg combination must be skipped"
        );
    }
}
