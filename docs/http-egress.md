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

### Target Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique target name (used in metrics labels and logs) |
| `url` | string | required | Full URL with `http://` or `https://` scheme |
| `method` | string | `"post"` | HTTP method: `post`, `put`, or `patch` |
| `format` | string | `"json"` | Payload format: `json` or `raw_xml` |
| `timeout-secs` | integer | `10` | Per-request timeout in seconds |
| `enabled` | boolean | `true` | Set `false` to disable without removing config |
| `auth` | table | none | Authentication configuration (see below) |
| `tls` | table | none | Outbound TLS configuration (see below) |
| `filter` | table | none | Message filter (see below) |
| `retry` | table | none | Retry and circuit breaker settings (see below) |
| `headers` | array | none | Custom static headers (see below) |

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

Computes `HMAC-SHA256(secret, request_body)` and sends it as `X-Signature-256: sha256=<hex>`. This follows the GitHub webhook signature format.

**Verifying on the receiver side (Python example):**

```python
import hmac, hashlib

def verify(body: bytes, secret: bytes, signature_header: str) -> bool:
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
```

**Secret file permissions:** ensure files are readable only by the rustgate process user:

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

`client-cert` and `client-key` must both be present or both absent.

### Message Filtering

Filters control which messages are forwarded to each target. All dimensions are AND-combined; values within each dimension are OR-combined. Omitting a dimension means "accept all".

```toml
[targets.filter]
groups = ["team-alpha", "hq-ops"]       # only these source groups
message-types = ["position", "alert"]   # only these message types
source-cns = ["sensor-1", "sensor-2"]   # only from these clients
```

**Echo prevention:** messages originating from the HTTP egress bridge (source protocol `"http"`) are always excluded to prevent infinite forwarding loops. This is enforced even if `exclude-protocols` is not configured.

### Retry and Circuit Breaker

```toml
[targets.retry]
max-attempts = 3                    # total attempts (including initial)
backoff-base-secs = 1               # base delay for exponential backoff
circuit-breaker-threshold = 5       # consecutive failures before circuit opens
circuit-breaker-cooldown-secs = 30  # seconds before half-open probe
```

**Retry behavior:**
- Only 5xx responses and network errors are retried. 4xx responses are never retried (they indicate a client/config error).
- Backoff: `base * 2^min(attempt, 5)` with 0-25% random jitter, capped at 5 minutes.
- The circuit breaker has three states: **Closed** (normal) → **Open** (after threshold consecutive failures) → **Half-Open** (after cooldown, probes with one request) → **Closed** (on success) or back to **Open** (on failure).

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

## Metrics

When built with `--features http,metrics`, the following Prometheus metrics are exported:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rustgate_http_publishes_total` | Counter | `target` | Successful deliveries |
| `rustgate_http_errors_total` | Counter | `target`, `reason` | Failed deliveries |
| `rustgate_http_request_duration_seconds` | Histogram | `target` | End-to-end request latency |
| `rustgate_http_circuit_state` | Gauge | `target` | 0=closed, 1=open, 2=half-open |
| `rustgate_http_retries_total` | Counter | `target` | Retry attempts |
| `rustgate_http_filtered_total` | Counter | `target` | Messages filtered out |
| `rustgate_http_queue_depth` | Gauge | — | Current internal channel occupancy |

Error reasons: `network`, `status_4xx`, `status_5xx`, `circuit_open`, `serialize`, `channel_full`.

**Alerting suggestions:**
- Alert on `rate(rustgate_http_errors_total[5m]) > 0` with `reason="circuit_open"` to detect targets that are down.
- Alert on `rustgate_http_circuit_state > 0` to detect open circuit breakers.
- Alert on `rustgate_http_queue_depth > 200` to detect channel backpressure.

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
