# HTTP Egress Bridge

rustgate can forward routable messages to external HTTP endpoints — SIEM collectors, REST APIs, C2 dashboards, webhook receivers — via the `rustgate-http` crate. Each target is independently configured with its own authentication, TLS, filtering, retry, and circuit breaking.

## Quick Start

1. Build with the `http` feature:

   ```bash
   cargo build --release --features http
   ```

2. Create a config file `http-targets.toml`:

   ```toml
   [[targets]]
   name = "siem"
   url = "https://siem.internal:8443/api/v1/events"

   [targets.auth]
   type = "bearer"
   token-file = "/etc/rustgate/secrets/siem-token"
   ```

3. Start rustgate with the config:

   ```bash
   rustgate --http-config-file http-targets.toml [other flags...]
   ```

## Configuration Reference

The HTTP egress config is a standalone TOML file passed via `--http-config-file` (env `RUSTGATE_HTTP_CONFIG`).

### Top-Level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `instance-id` | string | `"rustgate-<pid>"` | Instance identifier sent in the `X-Rustgate-Instance` header |
| `targets` | array | required | One or more target endpoint configurations |
| `dlq-dir` | string | none | Directory for encrypted dead-letter queue files (requires `dlq-key-file`) |
| `dlq-key-file` | string | none | Path to JSON key file for DLQ encryption (same `KeyRing` format as `rustgate-core`) |
| `dlq-max-bytes` | integer | `268435456` | Maximum DLQ file size per target before rotation (256 MiB default) |

### Target Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique target name (used in metrics labels and logs) |
| `url` | string | required | Full URL with `http://` or `https://` scheme |
| `method` | string | `"post"` | HTTP method: `post`, `put`, or `patch` |
| `format` | string | `"json"` | Payload format: `json`, `raw_xml`, or `protobuf` (requires `proto` feature) |
| `rate-limit-per-sec` | float | unlimited | Maximum outbound requests per second to this target |
| `timeout-secs` | integer | `10` | Per-request timeout in seconds |
| `enabled` | boolean | `true` | Set `false` to disable without removing config |
| `auth` | table | none | Authentication configuration (see below) |
| `tls` | table | none | Outbound TLS configuration (see below) |
| `filter` | table | none | Message filter (see below) |
| `retry` | table | none | Retry and circuit breaker settings (see below) |
| `headers` | array | none | Custom static headers (see below) |
| `max-payload-bytes` | integer | `1048576` | Maximum payload size in bytes (1 MiB default) |

### Authentication

Secrets are always read from **files** (never inline values) to prevent exposure via debug output or config dumps.

#### Bearer Token

```toml
[targets.auth]
type = "bearer"
token-file = "/etc/rustgate/secrets/token"
```

Sends `Authorization: Bearer <contents-of-file>`.

#### Basic Auth

```toml
[targets.auth]
type = "basic"
username = "rustgate"
password-file = "/etc/rustgate/secrets/password"
```

Sends `Authorization: Basic <base64(username:password)>`.

#### HMAC-SHA256 Request Signing

```toml
[targets.auth]
type = "hmac"
secret-file = "/etc/rustgate/secrets/hmac-key"
header = "X-Signature-256"    # optional, this is the default
```

Computes `HMAC-SHA256(secret, "<timestamp>.<body>")` and sends two headers:
- `X-Signature-256: sha256=<hex>` (or whichever `header` is configured)
- `X-Rustgate-Timestamp: <unix-seconds>` — the timestamp bound into the signature

The timestamp binding prevents replay attacks: receivers should reject signatures older than an acceptable window (e.g., 5 minutes).

**Verifying on the receiver side (Python example):**

```python
import hmac, hashlib, time

def verify(body: bytes, secret: bytes, signature_header: str,
           timestamp_header: str, max_age_secs: int = 300) -> bool:
    # Reject stale signatures (replay prevention)
    ts = int(timestamp_header)
    if abs(time.time() - ts) > max_age_secs:
        return False
    # Reconstruct the signed payload: "<timestamp>.<body>"
    signed_payload = timestamp_header.encode() + b"." + body
    expected = "sha256=" + hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
```

**Secret file permissions:** on Unix, rustgate rejects secret files with group- or world-readable permissions (mode `0o077 != 0`). Ensure files are readable only by the rustgate process user:

```bash
chmod 600 /etc/rustgate/secrets/*
chown rustgate:rustgate /etc/rustgate/secrets/*
```

### Outbound TLS

Configure custom CA certificates and/or client certificates for mutual TLS with the target endpoint.

```toml
[targets.tls]
ca-cert = "/etc/rustgate/tls/custom-ca.pem"
client-cert = "/etc/rustgate/tls/client.pem"
client-key = "/etc/rustgate/tls/client-key.pem"
```

| Field | Description |
|-------|-------------|
| `ca-cert` | PEM-encoded CA certificate for server verification |
| `client-cert` | PEM-encoded client certificate for mutual TLS |
| `client-key` | PEM-encoded client private key (must pair with `client-cert`) |
| `pin-sha256` | Array of base64-encoded SHA-256 SPKI pins (RFC 7469; requires `ca-cert`) |

`client-cert` and `client-key` must both be present or both absent.

#### Certificate Pinning (RFC 7469 SPKI)

Pin the target server's public key to defend against CA compromise or mis-issuance. When configured, the SHA-256 of the leaf certificate's **SubjectPublicKeyInfo (SPKI)** is compared against the configured pins after standard WebPKI chain validation — the [RFC 7469] / HPKP convention. Pinning the SPKI rather than the full certificate DER means routine rotations that preserve the key (new serial, new validity window, new SAN list) do **not** force a pin update.

```toml
[targets.tls]
ca-cert = "/etc/rustgate/tls/target-ca.pem"
pin-sha256 = [
    "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
    "sRHdihwgkaib1P1gN7SkKPFkS5GbXEj2F4nQ5EOhNrg=",
]
```

Generate an SPKI pin from a certificate or a raw public key:

```bash
# From a leaf certificate PEM
openssl x509 -in server.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64

# From a standalone public key PEM (e.g. for a key-in-waiting)
openssl pkey -in pubkey.pem -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Multiple pins are encouraged — list at least one active pin and one backup key-in-waiting pin so operators can roll the key without a flag-day migration.

`pin-sha256` requires `ca-cert` to also be set (explicit trust anchor). Using certificate pinning with the default Mozilla root store is insecure because any public CA could issue a matching certificate.

> **Breaking change vs pre-#948 builds:** earlier rustgate versions hashed the full leaf certificate DER. Existing full-DER pins do **not** match the new SPKI semantic and must be regenerated with the OpenSSL recipe above. See [issue #948](https://github.com/rchiofalo/rustgate/issues/948).

[RFC 7469]: https://datatracker.ietf.org/doc/html/rfc7469

### Message Filtering

Filters control which messages are forwarded to each target. All dimensions are AND-combined; values within each dimension are OR-combined. Omitting a dimension means "accept all".

```toml
[targets.filter]
groups = ["team-alpha", "hq-ops"]       # only these source groups
message-types = ["position", "alert"]   # only these message types
source-cns = ["sensor-1", "sensor-2"]   # only from these clients
exclude-protocols = ["nats"]            # also exclude NATS-sourced messages
```

**Echo prevention:** messages originating from the HTTP egress bridge (source protocol `"http"`) are always excluded to prevent infinite forwarding loops, even if `exclude-protocols` is not configured. Use `exclude-protocols` to additionally block messages from other protocols (e.g., `"nats"`).

### Retry and Circuit Breaker

```toml
[targets.retry]
max-attempts = 3                       # total attempts (including initial)
backoff-base-secs = 1                  # base delay for exponential backoff
circuit-breaker-threshold = 5          # consecutive failures before circuit opens
circuit-breaker-cooldown-secs = 30     # seconds before half-open probe
half-open-max-probes = 3               # max concurrent probes in half-open state
half-open-success-threshold = 2        # successes needed to close from half-open
```

**Retry behavior:**
- Only 5xx responses, 429 (rate-limited), and network errors are retried. 4xx responses are never retried (they indicate a client/config error).
- Backoff: `base * 2^min(attempt, 5)` with 0-25% random jitter, capped at 5 minutes.
- 429 responses with a `Retry-After` header use the server-specified delay (capped at 5 minutes).

**Circuit breaker:**
- Three states: **Closed** (normal) → **Open** (after threshold consecutive failures) → **Half-Open** (after cooldown) → **Closed** (after success threshold met) or back to **Open** (on any probe failure).
- Only server errors (5xx), rate limits (429), and network failures count toward the circuit breaker. 4xx client errors do not trip the breaker.
- In Half-Open state, at most `half-open-max-probes` concurrent requests are allowed. Additional requests are rejected until probes complete.
- Recovery requires `half-open-success-threshold` consecutive successful probes (default 2) to prevent flapping on a single lucky request.

When the circuit is open, messages to that target are logged at WARN level with structured fields for forensic analysis.

### Custom Headers

Add static headers to every request:

```toml
[[targets.headers]]
name = "X-API-Version"
value = "2"

[[targets.headers]]
name = "X-Tenant"
value = "division-alpha"
```

## Payload Formats

### JSON (default)

```json
{
  "source_cn": "ALPHA-1",
  "source_groups": ["team-alpha", "hq"],
  "destination": "team-alpha",
  "message_type": "position",
  "source_protocol": "tcp",
  "received_at": "2026-04-11T14:30:00.000000000Z",
  "payload": "<base64-encoded bytes>",
  "payload_size": 1024,
  "instance_id": "rustgate-prod-01"
}
```

Content-Type: `application/json`. The `payload` field is base64-encoded because CoT XML payloads may contain non-UTF8 bytes.

### Raw XML

Sends the raw message payload bytes directly. Content-Type: `application/xml`.

### Protobuf

Requires the `proto` feature (`--features http,proto`). Converts the CoT XML payload into a protobuf-encoded binary using `rustgate-proto::xml_to_proto`. Content-Type: `application/x-protobuf`. Suitable for interop with TAK Server peers and tactical systems that consume protobuf-encoded CoT.

```toml
format = "protobuf"
```

## Request Headers

Every outbound request includes these standard headers:

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json`, `application/xml`, or `application/x-protobuf` per format |
| `Content-Digest` | RFC 9530 SHA-256 body digest (`sha-256=:<base64>:`) for end-to-end integrity |
| `X-Rustgate-Instance` | Configured `instance-id` (or auto-generated `rustgate-<pid>`) |
| `X-Rustgate-Delivery-Id` | 128-bit random hex ID, stable across retries for receiver-side deduplication |
| `X-Rustgate-Timestamp` | Unix timestamp (only on HMAC-signed requests, bound into the signature) |
| `traceparent` | W3C Trace Context header (only when the `otel` feature is enabled and a trace is active) |
| `tracestate` | W3C trace state baggage (only when the `otel` feature is enabled and trace state is non-empty) |

The `Content-Digest` header allows receivers to verify body integrity independent of TLS, detecting in-transit corruption or proxy tampering. The `X-Rustgate-Delivery-Id` is generated once per message-target pair; retries carry the same ID so receivers can deduplicate.

## Dead-Letter Queue

When `dlq-dir` and `dlq-key-file` are configured, messages that cannot be delivered because a target's circuit breaker is open are persisted as ChaCha20-Poly1305 encrypted files for later forensic recovery or replay.

```toml
dlq-dir = "/var/lib/rustgate/dlq"
dlq-key-file = "/etc/rustgate/keys/dlq.json"
dlq-max-bytes = 268435456    # 256 MiB per-target file before rotation (default)
```

Each target gets a separate file per process lifetime, named `{target}_{timestamp}.dlq.enc`. Files are rotated when they exceed `dlq-max-bytes`. The key file uses the same `KeyRing` JSON format as `rustgate-core::encrypted`:

```json
{
    "active_key_id": "key-2026",
    "keys": {
        "key-2026": "<64-char-hex-encoded-256-bit-key>"
    }
}
```

Dead-lettered messages can be recovered offline using `rustgate_core::encrypted::decrypt_file` with the same key ring. Each decrypted chunk is one JSON line containing message metadata and base64-encoded payload. DLQ writers are sealed during graceful shutdown to ensure encrypted terminators are written (readers reject unterminated files).

## Metrics

When built with `--features http,metrics`, the following Prometheus metrics are exported:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rustgate_http_publishes_total` | Counter | `target` | Successful deliveries |
| `rustgate_http_errors_total` | Counter | `target`, `reason` | Failed deliveries |
| `rustgate_http_request_duration_seconds` | Histogram | — | End-to-end request latency |
| `rustgate_http_circuit_state` | Gauge | `target` | 0=closed, 1=open, 2=half-open |
| `rustgate_http_retries_total` | Counter | `target` | Retry attempts |
| `rustgate_http_filtered_total` | Counter | `target` | Messages filtered out |
| `rustgate_http_queue_depth` | Gauge | — | Current internal channel occupancy |

Error reasons: `network`, `status_4xx`, `status_5xx`, `status_other`, `circuit_open`, `serialize`, `channel_full`, `rate_limited`, `payload_too_large`.

**Alerting suggestions:**
- Alert on `rate(rustgate_http_errors_total[5m]) > 0` with `reason="circuit_open"` to detect targets that are down.
- Alert on `rustgate_http_circuit_state > 0` to detect open circuit breakers.
- Alert on `rustgate_http_queue_depth > 200` to detect channel backpressure.

## Security Considerations

The HTTP egress bridge includes several security hardening measures:

- **SSRF protection (config-time)**: Target URLs pointing to private/reserved IP addresses (loopback `127.0.0.0/8`, RFC 1918 `10.0.0.0/8 / 172.16.0.0/12 / 192.168.0.0/16`, link-local `169.254.0.0/16` including AWS IMDS, IPv6 loopback/unique-local/link-local, multicast, and `localhost`) are rejected at config validation time. IPv4-mapped IPv6 addresses (e.g., `::ffff:127.0.0.1`) are also blocked to prevent a common SSRF bypass.
- **SSRF protection (DNS-time)**: A custom DNS resolver (`SsrfSafeResolver`) validates resolved IP addresses against the same blocklist at **connection time**, eliminating the TOCTOU gap between config validation and DNS resolution. This defends against DNS rebinding attacks where an attacker controls a domain that initially resolves to a safe IP but later resolves to a private IP.
- **Redirect following disabled**: HTTP 3xx redirects are not followed, preventing SSRF via redirect chains to internal endpoints.
- **Minimum TLS 1.2**: Outbound connections enforce TLS 1.2 or higher. Certificate pinning is available for defense-in-depth against CA compromise.
- **Auth over plaintext HTTP rejected**: Configuring authentication (Bearer, Basic, or HMAC) with an `http://` URL is rejected at validation time, preventing credentials from being sent in cleartext.
- **Connect timeout**: A 5-second connect timeout prevents slow-connect denial-of-service.
- **Non-revealing User-Agent**: The outbound `User-Agent` is `"Rustgate"` with no version number, preventing version fingerprinting by target endpoints.
- **Secret zeroization**: All secret material (tokens, passwords, HMAC keys, TLS private keys) is wrapped in `Zeroizing<T>` for automatic memory wiping on drop. Intermediate buffers (PEM text, base64, DER bytes) are explicitly zeroized before scope exit.
- **File-based secrets**: Secrets are always read from files, never inline config values. This prevents exposure via config dumps, debug output, or structured logging.
- **Secret file permission enforcement**: On Unix, secret files with group- or world-readable permissions are rejected (must be mode `0600` or `0400`).
- **Secret file limits**: Secret files larger than 8 KiB or empty after trimming are rejected.
- **Reserved header protection**: Custom headers and HMAC signature headers cannot override 13 security-relevant headers: `Host`, `Content-Type`, `Content-Length`, `Content-Digest`, `Transfer-Encoding`, `Authorization`, `Connection`, `Proxy-Authorization`, `Cookie`, `TE`, `Upgrade`, `X-Rustgate-Instance`, `X-Rustgate-Delivery-Id`, and `X-Rustgate-Timestamp`.
- **Header injection prevention**: Custom header values are validated at config time — control characters (CRLF, null bytes) are rejected to prevent header injection attacks.
- **Payload size limits**: The `max-payload-bytes` setting (default 1 MiB) prevents memory exhaustion from oversized messages.
- **Response body draining**: Error responses are drained up to 1 MiB to keep HTTP connection pools healthy, with a size cap to prevent memory exhaustion from malicious servers.
- **Per-target rate limiting**: The `rate-limit-per-sec` setting prevents overwhelming downstream endpoints with burst traffic.
- **DLQ encryption**: Dead-lettered messages are encrypted with ChaCha20-Poly1305 (AEAD) with per-chunk AAD binding, preventing tampering or reordering of archived messages.
- **Config typo detection**: All config structs use `deny_unknown_fields` to reject misspelled field names.

## Troubleshooting

### Secret file permission denied

```
WARN failed to initialize HTTP publisher: failed to read secret file `/path/to/token`: Permission denied
```

Ensure the file is readable by the rustgate process user. Check ownership and permissions with `ls -la`.

### TLS handshake failure to target

```
WARN HTTP request to `siem` failed: error sending request
```

Verify the CA certificate is correct for the target server. If the target requires client certificates, ensure both `client-cert` and `client-key` are configured.

### Circuit breaker stuck open

If a target's circuit breaker remains open, check:
1. The target endpoint is reachable from the rustgate host
2. Authentication credentials are still valid
3. The target is returning 2xx responses (not 5xx)

The circuit breaker will automatically probe after the cooldown period. Restarting rustgate resets all circuit breakers.

### Messages not forwarded

Check the filter configuration. All filter dimensions are AND-combined — a message must match all configured filters. Also verify the target is `enabled = true` (the default).

Messages with `source_protocol = "http"` are always excluded to prevent loops.
