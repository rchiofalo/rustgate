# rustgate-admin

HTTP management server: Prometheus exposition, health/readiness probes,
and operator REST APIs.

## Role in the workspace

`rustgate-admin` is the long-running HTTP microservice that fronts every
operator-touchable endpoint a rustgate deployment exposes — the
Prometheus `/metrics` scrape target, the Kubernetes liveness / readiness
/ startup probes, the federation peer CRUD API, the ACL hot-reload
surface, and (under feature flags) the missions / video / Marti
compatibility shims.

The Prometheus metric statics themselves still live with their owning
domain crates (federation metrics in `rustgate-federation`, transport
metrics in `rustgate-router`, …) — this crate is the **exposition and
management surface** above them, not the metric registry. Extracted
from `rustgate-server` in #895 so the HTTP surface can evolve
independently from the metric definitions.

## Public API surface

- `server::serve` — main entry point, mounts the dispatcher on the
  admin bind address
- `server::HealthState` / `server::ReadinessState` — probe types that
  hot-reload propagates into
- `acl_api::AclApiState` / `acl_api::validate_bearer_token_length` —
  REST API state + token-length checker for the runtime ACL CRUD
  endpoints mounted at `/api/acl/`
- `acl_config::{GroupAclEntry, GroupAclFile}` — JSON deserialization
  for the group ACL policy file consumed by both the file reloader and
  the API
- `acl_reloader::reload` — polling-driven hot-reload of the on-disk ACL
  file (composes with the API for SIGHUP / API-driven reloads)

## Modules and feature gates

| Module | Always-on | Feature flag |
|---|---|---|
| `server` | ✓ | — |
| `acl_api` / `acl_config` / `acl_reloader` | ✓ | — |
| `missions_api` |  | `missions` — TAK Data Packages REST API at `/api/packages/` (Feature 17 of #860). Pulls in `rustgate-missions`. |
| `video` |  | `video` — In-memory CoT `b-i-v` video stream catalog at `GET /api/video/streams` (closes #862). |
| `correlation` |  | `correlation` — Multi-sensor track correlation snapshot at `GET /api/correlation/fused-entities` backed by an in-memory `CorrelationEngine` (closes #848). |
| `management_api` |  | `management-api` — runtime introspection endpoints |
| `marti_compat` |  | `marti-compat` — Marti API compatibility shim mounting `/Marti/api/*` for drop-in TAK Server replacement (closes #863). Implies `missions` + `video`. |

Other features:

- `nats` — pulls in `rustgate-nats` so the admin server can include NATS
  bridge status in `/health/ready`
- `federation` — same for federation peer reachability
- `http` — same for HTTP egress circuit-breaker state

## Topology / deployment notes

The admin server is intentionally a separate listener from the data
plane (the mTLS routing port). Default bind is `0.0.0.0:9090`; the
`/metrics`, `/health/{live,ready,startup}` endpoints are **unauthenticated
HTTP** (Prometheus scrape model). Operators must firewall the admin
port off untrusted networks — see [docs/deployment.md § Ports
security note](../../docs/deployment.md#ports).

The REST APIs (`/api/acl/*`, `/api/packages/*`, `/Marti/api/*` if
`marti-compat` is set) authenticate with bearer tokens validated through
`acl_api::validate_bearer_token_length`. Token comparison is
constant-time (`subtle::ConstantTimeEq`).

The cert-expiry readiness gauge maintained by `server` reads from the
shared `rustgate-tls::CertReloader` so an upcoming TLS renewal lights up
both the Prometheus gauge AND the K8s readiness probe.
