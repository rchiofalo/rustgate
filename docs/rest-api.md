# REST API Reference

rustgate exposes several HTTP/HTTPS endpoints across different ports and feature flags. This document covers every REST endpoint, its authentication requirements, request/response formats, and usage examples.

## Overview

| Server | Default Port | Feature Flags | Auth | Protocol |
|--------|-------------|---------------|------|----------|
| Metrics / Health | 9090 | `metrics` | None | HTTP |
| Federation API | 9090 | `federation` + `metrics` | None | HTTP |
| Marti API (`/Marti/api/*`) | 9090 | `marti-compat` | Basic (signClient) / Bearer (read-only) | HTTP |
| Enrollment | Configurable | `enrollment` | Basic / None | HTTPS |
| WebSocket | Configurable | `websocket` | mTLS | WSS |

## Metrics and Health Endpoints

Served on the metrics HTTP server (default port 9090). These endpoints are always available when the `metrics` feature is enabled.

The metrics server is hardened against unauthenticated abuse: connections are bounded to 128 concurrent, with a per-connection timeout and a 5-second header read timeout.

### GET /health/live

Kubernetes **liveness** probe. Returns 200 once the metrics HTTP server is reachable; never flips back. Orchestrators interpret a non-200 here as "the process is wedged — restart the pod".

**Authentication:** None

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `ok` |
| `503 Service Unavailable` | `not live` |

```bash
curl http://localhost:9090/health/live
```

### GET /health/ready

Kubernetes **readiness** probe. Returns 200 only when the listener is bound and core subsystems (ACL, federation if enabled) have completed initial wiring. Flips back to 503 during graceful shutdown so load balancers stop sending new traffic while in-flight sessions drain.

**Authentication:** None

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `{"status":"ok","checks":{...}}` |
| `200 OK` | `{"status":"degraded","checks":{...}}` |
| `503 Service Unavailable` | `{"status":"unhealthy","checks":{...}}` |

The response body is a JSON object with per-dependency health status. Dependency checks include TLS certificate expiry (warns at 7 days), NATS connection state (feature-gated on `nats`), and federation peer connectivity (feature-gated on `federation`).

```bash
curl http://localhost:9090/health/ready
```

### GET /health/startup

Kubernetes **startup** probe. Returns 200 only after the server has entered its accept loop — i.e. one full init pass has completed. One-shot: never flipped back. Allows slow-starting pods to defer liveness/readiness checks during boot.

**Authentication:** None

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `ok` |
| `503 Service Unavailable` | `starting` |

```bash
curl http://localhost:9090/health/startup
```

### GET /healthz (deprecated alias)

Backwards-compatible alias for `/health/live`. Prefer the new path.

```bash
curl http://localhost:9090/healthz
```

### GET /health/authz

Returns the current authorization engine status, including the loaded policy ID and any compile warnings (e.g. overly broad rules). Only available when an authorization policy is loaded.

**Authentication:** None

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `{"policy_id":"...","compile_warnings":[...]}` |
| `404 Not Found` | No authorization engine loaded |

```bash
curl http://localhost:9090/health/authz
```

### GET /readyz (deprecated alias)

Backwards-compatible alias for `/health/ready`. Prefer the new path.

```bash
curl http://localhost:9090/readyz
```

### GET /metrics

Prometheus metrics in text exposition format. Includes counters for connections, messages, NATS publishes, and protocol negotiations.

**Authentication:** Optional bearer token via `--metrics-token-file` (env `RUSTGATE_METRICS_TOKEN_FILE`). When set, requests must include `Authorization: Bearer <token>`. The token is compared in constant time. When unset, the endpoint is unauthenticated. Health probe endpoints (`/health/*`, `/healthz`, `/readyz`) are never gated by the token.

**Response:**

| Status | Content-Type | Body |
|--------|-------------|------|
| `200 OK` | `text/plain; version=0.0.4; charset=utf-8` | Prometheus text format |
| `500 Internal Server Error` | — | `metrics encoding failed` |

**Available metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `rustgate_connections_accepted_total` | Counter | Total TLS connections accepted |
| `rustgate_connections_active` | Gauge | Currently active TLS connections |
| `rustgate_connections_rejected_total` | Counter | Connections rejected due to limit |
| `rustgate_accept_errors_total` | Counter | TLS accept errors |
| `rustgate_messages_received_total` | Counter | Total messages received from clients |
| `rustgate_messages_dropped_total` | Counter | Messages dropped due to per-client rate limiting |
| `rustgate_messages_replayed_total` | Counter | Messages dropped due to anti-replay detection |
| `rustgate_messages_routed_total` | Counter (label: `destination`) | Messages routed by destination type |
| `rustgate_sessions_active` | Gauge | Registered sessions in the router |
| `rustgate_nats_publishes_total` | Counter | Messages published to NATS |
| `rustgate_negotiations_total` | Counter (label: `result`) | Protocol negotiations by result |

```bash
curl http://localhost:9090/metrics
```

---

## Federation REST API

Requires features: `federation` + `metrics`. All federation endpoints are served on the metrics HTTP server (default port 9090) under the `/api/federation/` prefix.

**Authentication:** None (the metrics port is assumed to be network-protected).

**Response envelope:**

Success responses wrap data in a JSON envelope:

```json
{ "data": <T> }
```

Error responses use:

```json
{ "error": "<message>" }
```

All responses include `Content-Type: application/json`.

### Connections

#### GET /api/federation/connections

List all active peer connections with their current status.

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Array of peer status objects |

```json
{
  "data": [
    {
      "id": "peer-1",
      "address": "10.0.0.1:9001",
      "state": "connected",
      "groups": ["Alpha", "Bravo"],
      "inbound_groups": null,
      "outbound_groups": null,
      "enabled": true,
      "is_outbound": true,
      "messages_sent": 1024,
      "messages_recv": 512,
      "last_error": null,
      "connected_duration_secs": 3600,
      "reconnect_count": 0,
      "circuit_state": "closed",
      "circuit_trips": 0
    }
  ]
}
```

**Peer state values:** `disconnected`, `connecting`, `connected`, `reconnecting`

**Circuit state values:** `closed` (healthy), `open` (tripped), `half_open` (probing)

```bash
curl http://localhost:9090/api/federation/connections
```

#### GET /api/federation/connections/{id}

Get a specific peer connection by ID.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Peer identifier |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Peer status object |
| `404 Not Found` | `{"error": "connection not found"}` |

```bash
curl http://localhost:9090/api/federation/connections/peer-1
```

### Federates (Peer Management)

#### GET /api/federation/federates

List all configured federates (including disabled ones).

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Array of federate info objects |

```json
{
  "data": [
    {
      "id": "peer-1",
      "address": "10.0.0.1:9001",
      "groups": ["Alpha"],
      "inbound_groups": null,
      "outbound_groups": null,
      "enabled": true,
      "is_outbound": true,
      "trust_cert_cn": "peer-1-ca",
      "routing_mode": "matrix",
      "created_at": "2026-04-01T12:00:00Z",
      "last_seen": null,
      "messages_sent": 0,
      "messages_recv": 0
    }
  ]
}
```

```bash
curl http://localhost:9090/api/federation/federates
```

#### POST /api/federation/federates

Add a new federate peer.

**Request body (`application/json`):**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | Yes | — | Unique peer identifier |
| `address` | string | Yes | — | Network address (host:port) |
| `groups` | string[] | No | `[]` | Groups this federate participates in |
| `inbound_groups` | string[] | No | `null` | Groups accepted from this peer |
| `outbound_groups` | string[] | No | `null` | Groups sent to this peer |
| `enabled` | bool | No | `true` | Whether the federate is active |
| `is_outbound` | bool | No | `false` | Whether we initiate the connection |
| `trust_cert_cn` | string | No | `null` | CN of the trusted certificate |
| `routing_mode` | string | No | `"matrix"` | Routing mode: `"matrix"` or `"broadcast"` |

**Response:**

| Status | Description |
|--------|-------------|
| `201 Created` | Created federate info object |
| `400 Bad Request` | `{"error": "id is required"}` or `{"error": "address is required"}` or `{"error": "invalid JSON: ..."}` |

```bash
curl -X POST http://localhost:9090/api/federation/federates \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "peer-1",
    "address": "10.0.0.1:9001",
    "groups": ["Alpha", "Bravo"],
    "is_outbound": true,
    "routing_mode": "broadcast"
  }'
```

#### GET /api/federation/federates/{id}

Get details for a specific federate.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Federate identifier |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Federate info object |
| `404 Not Found` | `{"error": "federate not found"}` |

```bash
curl http://localhost:9090/api/federation/federates/peer-1
```

#### PUT /api/federation/federates/{id}

Update an existing federate. Only provided fields are modified; omitted fields remain unchanged.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Federate identifier |

**Request body (`application/json`):**

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Network address (host:port) |
| `groups` | string[] | Groups this federate participates in |
| `inbound_groups` | string[] or null | Groups accepted from this peer |
| `outbound_groups` | string[] or null | Groups sent to this peer |
| `is_outbound` | bool | Whether we initiate the connection |
| `trust_cert_cn` | string or null | CN of the trusted certificate |

All fields are optional.

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Updated federate info object |
| `400 Bad Request` | `{"error": "invalid JSON: ..."}` |
| `404 Not Found` | `{"error": "federate not found"}` |

```bash
curl -X PUT http://localhost:9090/api/federation/federates/peer-1 \
  -H 'Content-Type: application/json' \
  -d '{"address": "10.0.0.2:9001", "groups": ["Alpha", "Charlie"]}'
```

#### DELETE /api/federation/federates/{id}

Remove a federate.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Federate identifier |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | `{"data": {"deleted": "peer-1"}}` |
| `404 Not Found` | `{"error": "federate not found"}` |

```bash
curl -X DELETE http://localhost:9090/api/federation/federates/peer-1
```

#### PUT /api/federation/federates/{id}/enable

Enable a federate.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Federate identifier |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Updated federate info object (with `"enabled": true`) |
| `404 Not Found` | `{"error": "federate not found"}` |

```bash
curl -X PUT http://localhost:9090/api/federation/federates/peer-1/enable
```

#### PUT /api/federation/federates/{id}/disable

Disable a federate.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Federate identifier |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Updated federate info object (with `"enabled": false`) |
| `404 Not Found` | `{"error": "federate not found"}` |

```bash
curl -X PUT http://localhost:9090/api/federation/federates/peer-1/disable
```

#### PUT /api/federation/federates/{id}/routing-mode

Set the routing mode for a federate.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Federate identifier |

**Request body (`application/json`):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `routing_mode` | string | Yes | `"matrix"` (per-peer subscriptions) or `"broadcast"` (all peers) |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Updated federate info object |
| `400 Bad Request` | `{"error": "invalid JSON: ..."}` |
| `404 Not Found` | `{"error": "federate not found"}` |

```bash
curl -X PUT http://localhost:9090/api/federation/federates/peer-1/routing-mode \
  -H 'Content-Type: application/json' \
  -d '{"routing_mode": "broadcast"}'
```

### Certificates (Trust Store)

#### GET /api/federation/certificates

List all trusted CA certificates in the federation trust store.

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Array of certificate info objects |

```json
{
  "data": [
    {
      "common_name": "Federation CA",
      "issuer": "Federation CA",
      "not_before": "2025-01-01 00:00:00 UTC",
      "not_after": "2035-01-01 00:00:00 UTC"
    }
  ]
}
```

```bash
curl http://localhost:9090/api/federation/certificates
```

#### POST /api/federation/certificates

Upload a CA certificate to the trust store. The request body must be PEM-encoded certificate data.

**Request body:** Raw PEM-encoded certificate (`application/x-pem-file` or `text/plain`)

**Response:**

| Status | Description |
|--------|-------------|
| `201 Created` | Certificate info object for the added certificate |
| `400 Bad Request` | `{"error": "PEM body is required"}` or `{"error": "no certificates found in PEM data"}` |

```bash
curl -X POST http://localhost:9090/api/federation/certificates \
  -H 'Content-Type: application/x-pem-file' \
  --data-binary @ca-cert.pem
```

#### GET /api/federation/certificates/{cn}

Get certificate info by common name. The CN in the path is percent-decoded.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cn` | string | Certificate common name (URL-encoded if it contains special characters) |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Certificate info object |
| `404 Not Found` | `{"error": "certificate not found"}` |

```bash
curl http://localhost:9090/api/federation/certificates/Federation%20CA
```

#### DELETE /api/federation/certificates/{cn}

Remove a certificate from the trust store by common name.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cn` | string | Certificate common name (URL-encoded if it contains special characters) |

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | `{"data": {"deleted": "Federation CA"}}` |
| `404 Not Found` | `{"error": "certificate not found"}` |

```bash
curl -X DELETE http://localhost:9090/api/federation/certificates/Federation%20CA
```

### Federation Status

#### GET /api/federation/stats

Aggregated federation statistics.

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Statistics object |

```json
{
  "data": {
    "total_peers": 3,
    "connected_peers": 2,
    "running": true,
    "messages_sent": 15000,
    "messages_received": 12000,
    "certificates": 2
  }
}
```

```bash
curl http://localhost:9090/api/federation/stats
```

#### GET /api/federation/status

Full federation manager status including per-peer details.

**Response:**

| Status | Description |
|--------|-------------|
| `200 OK` | Federation status object |

```json
{
  "data": {
    "running": true,
    "v1_server_active": true,
    "v2_server_active": false,
    "total_peers": 2,
    "connected_peers": 1,
    "peers": [
      {
        "id": "peer-1",
        "address": "10.0.0.1:9001",
        "state": "connected",
        "groups": ["Alpha"],
        "enabled": true,
        "is_outbound": true,
        "messages_sent": 100,
        "messages_recv": 50,
        "last_error": null,
        "connected_duration_secs": 3600,
        "reconnect_count": 0,
        "circuit_state": "closed",
        "circuit_trips": 0
      }
    ],
    "ha_enabled": false
  }
}
```

```bash
curl http://localhost:9090/api/federation/status
```

---

## Enrollment API

Requires feature: `enrollment`. Served on a separate HTTPS port with server-only TLS (no client certificate required). Connections are bounded to 64 concurrent, with a 30-second per-connection timeout.

Responses follow the Marti v3 envelope format where noted:

```json
{
  "version": "3",
  "type": "<type>",
  "data": <T>,
  "nodeId": "rustgate"
}
```

### TLS Configuration and Signing

#### GET /Marti/api/tls/config

Returns the certificate configuration that clients use to generate their CSR. Tells clients which Organization (O) and Organizational Unit (OU) values to include.

**Authentication:** None

**Response:**

| Status | Content-Type | Body |
|--------|-------------|------|
| `200 OK` | `application/xml` | Certificate configuration XML |

```xml
<?xml version="1.0" encoding="UTF-8"?>
<certificateConfig xmlns="http://bbn.com/marti/xml/config">
  <nameEntries>
    <nameEntry name="O" value="YourOrganization"/>
    <nameEntry name="OU" value="rustgate"/>
  </nameEntries>
</certificateConfig>
```

```bash
curl https://enrollment-host:8446/Marti/api/tls/config --insecure
```

#### POST /Marti/api/tls/signClient

Sign a CSR and return a PKCS#12 (.p12) bundle containing the signed client certificate and the CA certificate. The bundle is encrypted with the standard password.

**Authentication:** HTTP Basic Auth (required)

**Rate limit:** 10 requests per IP per 60-second window

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `clientUID` or `clientUid` | string | Client unique identifier (optional, used for logging; truncated to 128 chars) |

**Request body:** PEM-encoded CSR (max 64 KB)

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/x-pkcs12` | Binary PKCS#12 bundle |
| `400 Bad Request` | `text/plain` | `CSR too large or unreadable`, `request body is not valid UTF-8`, or `failed to sign CSR` |
| `401 Unauthorized` | `text/plain` | `unauthorized` (includes `WWW-Authenticate: Basic` header) |
| `429 Too Many Requests` | `text/plain` | `rate limit exceeded` |
| `500 Internal Server Error` | `text/plain` | `failed to create PKCS#12 bundle` |

```bash
curl -X POST https://enrollment-host:8446/Marti/api/tls/signClient?clientUID=my-device \
  -u admin:password \
  --data-binary @client.csr \
  --insecure \
  -o client.p12
```

#### POST /Marti/api/tls/signClient/v2

Sign a CSR and return the signed certificate chain. Supports content negotiation: returns JSON by default, or XML if the client sends `Accept: application/xml`.

**Authentication:** HTTP Basic Auth (required)

**Rate limit:** 10 requests per IP per 60-second window

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `clientUID` or `clientUid` | string | Client unique identifier (optional, used for logging; truncated to 128 chars) |

**Request body:** PEM-encoded CSR (max 64 KB)

**Response (JSON, default):**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Signed certificate chain |

```json
{
  "signedCert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "ca0": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "ca1": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

**Response (XML, when `Accept: application/xml`):**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/xml` | Signed certificate chain |

```xml
<?xml version="1.0" encoding="UTF-8"?>
<enrollment>
  <signedCert>BASE64_CERT</signedCert>
  <ca>BASE64_CA</ca>
</enrollment>
```

**Error responses:**

| Status | Description |
|--------|-------------|
| `400 Bad Request` | `CSR too large or unreadable`, `request body is not valid UTF-8`, or `failed to sign CSR` |
| `401 Unauthorized` | `unauthorized` (includes `WWW-Authenticate: Basic` header) |
| `429 Too Many Requests` | `rate limit exceeded` |
| `500 Internal Server Error` | `failed to create PKCS#12 bundle` or internal signing error |

```bash
# JSON response (default)
curl -X POST https://enrollment-host:8446/Marti/api/tls/signClient/v2?clientUID=my-device \
  -u admin:password \
  --data-binary @client.csr \
  --insecure

# XML response
curl -X POST https://enrollment-host:8446/Marti/api/tls/signClient/v2?clientUID=my-device \
  -u admin:password \
  -H 'Accept: application/xml' \
  --data-binary @client.csr \
  --insecure
```

#### GET /Marti/api/tls/profile/enrollment

Enrollment profile endpoint. Returns an empty 204 response.

**Authentication:** None

**Response:**

| Status | Description |
|--------|-------------|
| `204 No Content` | Empty body |

```bash
curl https://enrollment-host:8446/Marti/api/tls/profile/enrollment --insecure
```

### Contacts and Groups

#### GET /Marti/api/version/config

Server version information.

**Authentication:** None

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Server configuration (Marti v3 envelope) |

```json
{
  "version": "3",
  "type": "ServerConfig",
  "data": {
    "version": "0.8.0",
    "api": "3",
    "hostname": "rustgate"
  },
  "nodeId": "rustgate"
}
```

```bash
curl https://enrollment-host:8446/Marti/api/version/config --insecure
```

#### GET /Marti/api/contacts/all

List all currently connected contacts.

**Authentication:** None

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Array of contact objects |

```json
[
  {
    "uid": "alpha-1",
    "callsign": "Alpha One",
    "groups": ["Team-A"],
    "lastStatus": "Connected"
  }
]
```

Returns an empty array `[]` when no contacts provider is configured.

```bash
curl https://enrollment-host:8446/Marti/api/contacts/all --insecure
```

#### GET /Marti/api/clientEndPoints

List client endpoints in a Marti-compatible envelope.

**Authentication:** None

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Client endpoints (Marti v3 envelope) |

```json
{
  "version": "3",
  "type": "com.bbn.marti.remote.ClientEndpoint",
  "data": [
    {
      "uid": "alpha-1",
      "callsign": "Alpha One",
      "lastStatus": "Connected"
    }
  ],
  "nodeId": "rustgate"
}
```

```bash
curl https://enrollment-host:8446/Marti/api/clientEndPoints --insecure
```

#### GET /Marti/api/groups/all

List available groups.

**Authentication:** None

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Group list (Marti v3 envelope) |

```json
{
  "version": "3",
  "type": "com.bbn.marti.remote.groups.Group",
  "data": [
    {
      "name": "__ANON__",
      "direction": "IN",
      "created": "2024-01-01T00:00:00.000Z",
      "type": "SYSTEM",
      "bitpos": 0,
      "active": true
    }
  ],
  "nodeId": "rustgate"
}
```

```bash
curl https://enrollment-host:8446/Marti/api/groups/all --insecure
```

#### GET /Marti/api/missions

List missions. Returns an empty list (mission support is not implemented).

**Authentication:** None

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Mission list (Marti v3 envelope) |

```json
{
  "version": "3",
  "type": "Mission",
  "data": [],
  "nodeId": "rustgate"
}
```

```bash
curl https://enrollment-host:8446/Marti/api/missions --insecure
```

### Data Packages

#### GET /Marti/api/device/profile/connection

Data package sync discovery. Clients call this periodically to discover packages uploaded since their last sync.

**Authentication:** None

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `syncSecago` | integer | Return packages uploaded within the last N seconds. `0` or omitted returns all packages. |

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | File list (Marti v3 envelope) |

```json
{
  "version": "3",
  "type": "com.bbn.marti.remote.sync.FileInfo",
  "data": [
    {
      "hash": "abc123def456",
      "name": "mission-package.zip",
      "size": 102400,
      "creatorUid": "admin"
    }
  ],
  "nodeId": "rustgate"
}
```

Returns an empty `data` array when no data package store is configured.

```bash
curl "https://enrollment-host:8446/Marti/api/device/profile/connection?syncSecago=3600" --insecure
```

#### POST /Marti/sync/upload

Upload a data package. Supports multipart form data (field name `assetfile`) or raw body. Maximum upload size is 50 MiB.

**Authentication:** HTTP Basic Auth (required)

**Request body:** Multipart form data with `assetfile` field, or raw binary body

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Upload result with hash, name, and size |
| `400 Bad Request` | `text/plain` | `upload too large` or `upload failed` |
| `401 Unauthorized` | `text/plain` | `unauthorized` (includes `WWW-Authenticate: Basic` header) |
| `404 Not Found` | `text/plain` | `data package storage not configured` |

```json
{
  "Hash": "abc123def456",
  "Name": "mission-package.zip",
  "Size": 102400
}
```

```bash
curl -X POST https://enrollment-host:8446/Marti/sync/upload \
  -u admin:password \
  -F "assetfile=@mission-package.zip" \
  --insecure
```

#### GET /Marti/sync/content

Download a data package by its hash.

**Authentication:** None

**Query parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hash` | string | Yes | SHA hash of the package |

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/x-zip-compressed` | Binary package data |
| `400 Bad Request` | `text/plain` | `missing hash parameter` |
| `404 Not Found` | `text/plain` | `package not found` or `data package storage not configured` |

```bash
curl "https://enrollment-host:8446/Marti/sync/content?hash=abc123def456" \
  --insecure -o package.zip
```

#### GET /Marti/sync/search

Search data packages by keyword.

**Authentication:** None

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `keyword` | string | Search keyword (empty returns all packages) |

**Response:**

| Status | Content-Type | Description |
|--------|-------------|-------------|
| `200 OK` | `application/json` | Array of package metadata objects |
| `404 Not Found` | `text/plain` | `data package storage not configured` |
| `500 Internal Server Error` | `text/plain` | `search failed` |

```json
[
  {
    "hash": "abc123def456",
    "name": "mission-package.zip",
    "creator_uid": "admin",
    "mime_type": "application/zip",
    "size": 102400,
    "upload_time": 1712300000
  }
]
```

```bash
curl "https://enrollment-host:8446/Marti/sync/search?keyword=mission" --insecure
```

---

## WebSocket

Requires feature: `websocket`. Served on a configurable port with mTLS authentication.

### WSS / (WebSocket Upgrade)

Bidirectional message streaming over WebSocket. Clients must present a valid client certificate (mTLS) to establish a connection.

**Authentication:** mTLS (client certificate required)

**Protocol:** Standard WebSocket upgrade over TLS

```bash
# Example using websocat (requires client certificate)
websocat wss://server:8444/ \
  --tls-cert client.pem \
  --tls-key client-key.pem \
  --tls-ca ca.pem
```

---

## Marti API Compatibility (`/Marti/api/*`)

Drop-in TAK Server replacement surface, mounted on the admin HTTP server (default port 9090) when the `marti-compat` feature is enabled. Every endpoint maps a TAK-compatible URL onto an existing rustgate subsystem; this is a compatibility shim, not new functionality. ATAK / WinTAK / iTAK clients connect with no reconfiguration. Closes #863.

The URL prefix `/Marti/` is **case-sensitive** with a capital `M` — ATAK builds the URL with that exact spelling and rustgate matches it byte-for-byte. Any other casing (e.g. `/marti/`) returns a 404 fall-through.

### Endpoint summary

| Marti endpoint                       | Maps to                                              | Auth                                |
| ------------------------------------ | ---------------------------------------------------- | ----------------------------------- |
| `POST /Marti/api/tls/signClient[/]`  | `rustgate-enrollment` CSR signer → PKCS#12 (`.p12`)  | HTTP Basic (TAK enrollment flow)    |
| `GET  /Marti/api/tls/config`         | CA cert + accepted ciphers + protocol versions       | Bearer token (when configured)      |
| `GET  /Marti/api/missions`           | `rustgate-missions` lightweight package store        | Bearer token (when configured)      |
| `GET  /Marti/api/contacts/all`       | Connected client list from the router                | Bearer token (when configured)      |
| `GET  /Marti/api/video`              | Video stream catalog from `rustgate-admin::video`    | Bearer token (when configured)      |

When no bearer token is configured, the GET endpoints fall through to "open" — the same disposition the existing `signClient` enrollment endpoint uses, on the assumption the admin port is fronted by mTLS.

### POST /Marti/api/tls/signClient

ATAK posts a PKCS#10 CSR (PEM) and expects a PKCS#12 (`.p12`) bundle in response containing the signed client certificate plus the CA chain.

**Authentication:** HTTP Basic. The authenticated username overrides any subject in the CSR (subject-injection-proof). Both a trailing-slash and trailing-slash-free URL are accepted because pre-2024 TAK Server ships the route both ways.

**Request:**

```bash
curl -u operator:secret \
  --data-binary @client.csr \
  https://rustgate.example.com:9090/Marti/api/tls/signClient \
  -o client.p12
```

**Response:** binary PKCS#12 bundle, `Content-Type: application/x-pkcs12`. The standard TAK ecosystem password (`atakatak`) is used for the bundle's HMAC-SHA1 integrity layer; the certificate bags themselves are unencrypted because the password is publicly known and confidentiality is provided by the mTLS-protected channel.

### GET /Marti/api/tls/config

Returns the CA cert (base64 DER) plus the static cipher / protocol-version list rustgate's TLS provider accepts. **Bearer-token gated when an admin token is configured** (open otherwise), matching the other read-only GET endpoints on this surface (#1551). This is distinct from the enrollment server's `/Marti/api/tls/config` (port 8446), which is an intentionally-unauthenticated TAK preflight.

```bash
curl -H "Authorization: Bearer <admin-token>" https://rustgate.example.com:9090/Marti/api/tls/config
```

```json
{
  "version": "3",
  "type": "TlsConfig",
  "data": {
    "organization": "rustgate-deployment",
    "caCert": "MIID...",
    "acceptedCiphers": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "..."],
    "protocolVersions": ["TLSv1.3", "TLSv1.2"]
  },
  "nodeId": "rustgate"
}
```

ATAK is tolerant about extra / missing fields in this response — rustgate ships a stable JSON shape rather than reproducing TAK Server's exact XML envelope.

### GET /Marti/api/missions

Returns the lightweight Mission Packages store (`rustgate-missions`) inventory inside the Marti `Mission` envelope. Empty when no store is wired in — silent-success rather than error so an ATAK client polling for missions does not spam the log.

```json
{
  "version": "3",
  "type": "Mission",
  "data": [
    {
      "name": "ops-overlay.zip",
      "hash": "5bf1fd927dfb...",
      "size": 4096,
      "creatorUid": "operator-1",
      "uploadTime": 1715040000
    }
  ],
  "nodeId": "rustgate"
}
```

### GET /Marti/api/contacts/all

Returns connected clients in the field-stable ATAK shape. The field names are load-bearing — every Marti consumer relies on them.

```json
[
  {
    "uid": "alpha-1",
    "callsign": "Alpha-One",
    "team": "Team-Red",
    "role": "Team Member",
    "takv": "rustgate",
    "endpoint": "*:-1:stcp",
    "lastStatus": "Connected",
    "filterGroups": ["Team-Red", "All"]
  }
]
```

### GET /Marti/api/video

Returns the in-memory CoT `b-i-v` video stream catalog (`rustgate-admin::video`) in the Marti `Feed` envelope. Each entry carries the stream URL, the per-stream `protocol` (inferred from the URL scheme), and the sensor framing block ATAK uses to drive the in-app feed list.

```json
{
  "version": "3",
  "type": "Feed",
  "data": [
    {
      "uid": "VID-A",
      "alias": "VID-A",
      "url": "rtsp://10.0.0.1/feed",
      "protocol": "rtsp",
      "address": "rtsp://10.0.0.1/feed",
      "fov": 42.5,
      "azimuth": 180.0,
      "elevation": -15.0,
      "lat": 35.0,
      "lon": -100.0
    }
  ],
  "nodeId": "rustgate"
}
```

### Out of scope (deferred)

- `Marti/api/sync/*` (mission sync — lands with the rest of #860)
- `Marti/api/cot/xml` (live CoT push — would need a WebSocket tap into the router)
- Deprecated XML response variants (we ship JSON only — ATAK is tolerant about format)

## Expanded Management API (closes #875)

Built behind the `management-api` feature flag, this surface adds operator-facing read endpoints for running configuration, connected clients, build identity, metrics summary, store-and-forward queue depth, and a verifier driver for the hash-chained audit log. It coexists alongside the legacy `/api/cert/*`, `/api/dlq/*`, `/api/reload`, and `/api/drain` endpoints (all of which remain unchanged).

The API is mounted on the same metrics HTTP server (default port 9090). Authentication uses the same `--mgmt-api-token-file` bearer token as the legacy management API — supplying the flag enables both surfaces.

| Route | Method | Purpose |
|---|---|---|
| `/api/config` | GET | Running config snapshot (secrets redacted) |
| `/api/config/reload` | POST | Trigger SIGHUP-equivalent reload (returns `202 Accepted`) |
| `/api/clients` | GET | Snapshot of connected clients |
| `/api/clients/{cn}` | GET | Detail for one client (404 when not connected) |
| `/api/metrics/summary` | GET | JSON router/federation/store-forward summary |
| `/api/store-forward` | GET | Per-CN store-and-forward queue depth + bytes |
| `/api/audit/verify` | GET | Run `verify_audit_log` over the configured audit log |
| `/api/version` | GET | Build version, git hash, feature flags, FIPS status |

**Authentication.** All endpoints require `Authorization: Bearer <token>`. The token is compared in constant time via `subtle::ConstantTimeEq`. Token length is bounded (32–256 bytes) and validated at startup. The token is wrapped in `zeroize::Zeroizing` so it is wiped from memory on drop.

**Auth model.** The MOSA OSMP calls for an "admin cert OU group" gate on write endpoints. The metrics HTTP server fronting this API uses bearer tokens, not mTLS — the bearer token itself is the admin credential. A future PR can layer mTLS in front by capturing the peer cert and checking its OU membership without changing the per-endpoint contract.

### GET /api/config

Returns the running CLI configuration as JSON, with secrets redacted via `#[serde(skip_serializing)]` and `#[serde(serialize_with = "redact_…")]` on the CLI struct (so the same redaction surface that governs `--print-config-toml` governs this endpoint — there is no separate redaction surface that can drift).

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/config
```

**Response shape:** `{"data": <cli-as-json>}` with sensitive fields elided.

### POST /api/config/reload

Fires the shared reload `Notify` instance — the same one SIGHUP and the legacy `/api/reload` endpoint observe — so the same handler in `main.rs` runs regardless of which surface triggered the reload. Returns immediately after `notify_one()`; reload completion is observable via the `rustgate_config_reload_total` counter and the audit log.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/config/reload
```

**Response:** `202 Accepted` with `{"data": {"status": "reload_initiated", "source": "api"}}`.

### GET /api/clients

Returns a snapshot of connected client sessions from the router's session registry.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/clients
```

**Response shape:** `{"data": [{"cn": ..., "fingerprint": ..., "groups": [...], "tenant": ..., ...}]}`.

Telemetry fields (`connected_at`, `bytes_rx`, `bytes_tx`, `source_protocol`) are populated when the wiring layer surfaces them through the router's session handle. The MVP scope wires the directly-available fields (cn, fingerprint, groups, tenant); the others are reported as JSON `null` so dashboards can scrape the endpoint unconditionally.

### GET /api/clients/{cn}

Returns the same shape as `/api/clients` plus a per-session `queue_depth` and `rate_limit_per_sec` snapshot. Returns `404 Not Found` when no session matches the supplied CN.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/clients/alice
```

This route does NOT shadow `POST /api/clients/{cn}/disconnect` — that endpoint is owned by the legacy `mgmt_api` handler and continues to operate unchanged.

### GET /api/metrics/summary

Returns a JSON summary of the most-relevant Prometheus counters so operators reading the HTTP API don't have to parse Prometheus text format.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/metrics/summary
```

**Response shape:** `{"data": {"router_fanout_total": N, "router_dropped_total": N, "store_forward_messages": N, "store_forward_bytes": N, "federation_peer_count": N, "federation_connected_peers": N, "connected_clients": N}}`.

### GET /api/store-forward

Returns the per-CN store-and-forward queue snapshot. Reports `enabled: false` when the server is running without a configured store-and-forward queue.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/store-forward
```

**Response shape:** `{"data": {"enabled": true, "total_bytes": N, "total_messages": N, "entries": [{"cn": "...", "messages": N, "bytes": N}]}}`.

### GET /api/audit/verify

Runs `rustgate_archive::audit_chain::verify_audit_log` over the configured `--audit-log` path and returns a typed report. A clean chain returns `verified: true`; a corrupt chain returns `verified: false` with the diagnostic on `error`. Returns `503 Service Unavailable` when no audit log was configured.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/audit/verify
```

**Response shape (clean):** `{"data": {"verified": true, "records": N, "tip": "<sha256>", "tip_seq": N, "audit_log_path": "..."}}`.

**Response shape (corrupt):** `{"data": {"verified": false, "error": "<diag>", "audit_log_path": "..."}}` (still HTTP 200 — operators distinguish via `verified`).

### GET /api/version

Returns build identity: package version, git hash baked in at build time (via the `RUSTGATE_GIT_HASH` env var if set, else `"unknown"`), the list of feature flags compiled into the running binary, and a `fips_active` flag derived from `cfg!(feature = "fips")`.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/version
```

**Response shape:** `{"data": {"version": "0.8.0", "git_hash": "abc1234", "features": ["metrics", "nats", ...], "fips_active": false}}`.

---

## Common Status Codes

| Code | Meaning | Used By |
|------|---------|---------|
| `200 OK` | Successful request | All endpoints |
| `201 Created` | Resource created | Federation: create federate, add certificate |
| `202 Accepted` | Request accepted, completion deferred | Management API: `/api/config/reload`, `/api/drain` |
| `204 No Content` | Success with no body | Enrollment: profile endpoint |
| `400 Bad Request` | Invalid input | Federation: invalid JSON; Enrollment: invalid CSR |
| `401 Unauthorized` | Missing or invalid credentials | Enrollment: signing, upload; Management API: any route |
| `404 Not Found` | Resource not found | Federation: unknown peer/cert; Enrollment: unknown path; Management API: unknown CN |
| `405 Method Not Allowed` | Wrong verb on a known endpoint | Management API |
| `429 Too Many Requests` | Rate limit exceeded | Enrollment: CSR signing (10 req/IP/min) |
| `500 Internal Server Error` | Server-side failure | All endpoints |
| `503 Service Unavailable` | Server not ready / dependency missing | Health: `/health/ready` or `/health/startup`; Federation: API not initialized; Management API: missing provider/audit log |
