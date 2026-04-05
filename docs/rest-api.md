# REST API Reference

rustgate exposes several HTTP/HTTPS endpoints across different ports and feature flags. This document covers every REST endpoint, its authentication requirements, request/response formats, and usage examples.

## Overview

| Server | Default Port | Feature Flags | Auth | Protocol |
|--------|-------------|---------------|------|----------|
| Metrics / Health | 9090 | `metrics` | None | HTTP |
| Federation API | 9090 | `federation` + `metrics` | None | HTTP |
| Enrollment | Configurable | `enrollment` | Basic / None | HTTPS |
| WebSocket | Configurable | `websocket` | mTLS | WSS |

## Metrics and Health Endpoints

Served on the metrics HTTP server (default port 9090). These endpoints are always available when the `metrics` feature is enabled.

The metrics server is hardened against unauthenticated abuse: connections are bounded to 128 concurrent, with a per-connection timeout and a 5-second header read timeout.

### GET /healthz

Liveness probe. Always returns 200 while the server process is running.

**Authentication:** None

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `ok` (plain text) |

```bash
curl http://localhost:9090/healthz
```

### GET /readyz

Readiness probe. Returns 200 when the server is ready to accept traffic, 503 during startup or graceful shutdown.

**Authentication:** None

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `ok` (plain text) |
| `503 Service Unavailable` | `not ready` (plain text) |

```bash
curl http://localhost:9090/readyz
```

### GET /metrics

Prometheus metrics in text exposition format. Includes counters for connections, messages, NATS publishes, and protocol negotiations.

**Authentication:** None

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
    "version": "0.6.0",
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

## Common Status Codes

| Code | Meaning | Used By |
|------|---------|---------|
| `200 OK` | Successful request | All endpoints |
| `201 Created` | Resource created | Federation: create federate, add certificate |
| `204 No Content` | Success with no body | Enrollment: profile endpoint |
| `400 Bad Request` | Invalid input | Federation: invalid JSON; Enrollment: invalid CSR |
| `401 Unauthorized` | Missing or invalid credentials | Enrollment: signing, upload |
| `404 Not Found` | Resource not found | Federation: unknown peer/cert; Enrollment: unknown path |
| `429 Too Many Requests` | Rate limit exceeded | Enrollment: CSR signing (10 req/IP/min) |
| `500 Internal Server Error` | Server-side failure | All endpoints |
| `503 Service Unavailable` | Server not ready | Health: readyz; Federation: API not initialized |
