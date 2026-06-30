# Audit Events Reference

This is the canonical catalogue of every audit event rustgate emits.
**87 event types across 32 domains**, all registered in
`crates/rustgate-core/src/audit.rs` and emitted via the `audit!` macro
to the `audit` tracing target at `INFO` level.

For Prometheus metrics, see [metrics-reference.md](metrics-reference.md).
For trace spans, see [observability.md](observability.md).

## How audit events work

- **Compile-time**: audit emission is always on. There is no feature
  flag; the audit log is a security-baseline guarantee.
- **Routing**: events are emitted as `tracing::info!` records with
  `target: "audit"`. Configure a separate
  `tracing_subscriber::filter::Targets` layer to route them to a
  dedicated sink (file, syslog, structured-log collector).
- **Boundary sanitization**: every user-controlled `&str` parameter is
  sanitized inside the audit module before it reaches the tracing
  macro. Control characters (newlines, CRs, ANSI CSI escapes) are
  replaced with `U+FFFD`. Callers may sanitize too (the operation is
  idempotent) but they don't have to — the trust boundary lives inside
  the audit module so a new caller that forgets cannot produce a
  forgeable audit line.
- **Hash chaining**: when audit-chain mode is enabled
  (`HashChainWriter` wraps the audit sink) each record carries a
  `sha256` field and a `prev` link to the previous record's hash.
  Tampering breaks the chain; `verify_audit_log()` walks the file and
  fails on the first discontinuity. See `rustgate-core::audit_chain`.
- **Common fields**: every event includes `event_type`, `action`, and
  (almost always) `result` — alongside event-specific structured
  fields. `result` values are conventional: `success`, `failure`,
  `rejected`, `dropped`, `triggered`, ... — pick a consistent label
  vocabulary per dashboard.

### Common fields

| Field | Type | Purpose |
|---|---|---|
| `timestamp` | RFC3339 string | Injected by the tracing subscriber; not duplicated per event. |
| `event_type` | string | The dotted identifier listed in the tables below — primary partition key. |
| `action` | string | The verb being recorded (`connect`, `disconnect`, `sign`, `reload`, `rotate`, ...). |
| `result` | string | Outcome (`success`, `failure`, `rejected`, `dropped`, `triggered`, `recovered`, ...). |
| `sha256` | hex string | Per-record SHA-256 hash. Present only when `HashChainWriter` is in use. |
| `prev` | hex string | Previous record's `sha256`. Present only with chaining; `GENESIS_PREV` for the first record. |

### Sample record

```json
{
  "timestamp": "2026-05-19T22:14:03.918273Z",
  "level": "INFO",
  "target": "audit",
  "event_type": "client.connected",
  "cn": "user-alice",
  "peer": "10.0.5.12:54231",
  "fingerprint": "sha256-…",
  "session_id": 1742,
  "action": "connect",
  "result": "success"
}
```

## Table of contents

1. [`client` — TLS client lifecycle](#client--tls-client-lifecycle) (6)
2. [`tls` — handshake failures](#tls--handshake-failures) (1)
3. [`cert` — server certificate rotation](#cert--server-certificate-rotation) (2)
4. [`crl` — CRL reload outcomes](#crl--crl-reload-outcomes) (2)
5. [`enrollment` — CSR signing / EST](#enrollment--csr-signing--est) (5)
6. [`federation` — peer connectivity](#federation--peer-connectivity) (11)
7. [`authz` — policy enforcement & reload](#authz--policy-enforcement--reload) (7)
8. [`egress` — outbound obligation actuation](#egress--outbound-obligation-actuation) (1)
9. [`classification` — CAPCO marking checks](#classification--capco-marking-checks) (2)
10. [`message` — chain-of-custody delivery & drop](#message--chain-of-custody-delivery--drop) (2)
11. [`mesh` — multi-hop routing](#mesh--multi-hop-routing) (7)
12. [`http` — egress publishers & DLQ](#http--egress-publishers--dlq) (8)
13. [`mqtt` — MQTT broker events](#mqtt--mqtt-broker-events) (1)
14. [`nats` — NATS bridge](#nats--nats-bridge) (1)
15. [`udp_multicast` — UDP multicast bridge](#udp_multicast--udp-multicast-bridge) (2)
16. [`mavlink` — MAVLink framing](#mavlink--mavlink-framing) (2)
17. [`store_forward` — offline queue](#store_forward--offline-queue) (4)
18. [`position_replay` — replay rate limits](#position_replay--replay-rate-limits) (1)
19. [`security` & `quota` — rate limits & tenant throughput](#security--quota--rate-limits--tenant-throughput) (2)
20. [`tenant` — label-cardinality protection](#tenant--label-cardinality-protection) (1)
21. [`jwks` — JWKS rotation](#jwks--jwks-rotation) (4)
22. [`jwt` — token verification](#jwt--token-verification) (1)
23. [`spiffe` — SPIFFE X.509-SVID refresh](#spiffe--spiffe-x509-svid-refresh) (2)
24. [`hw_identity` — hardware identity backends](#hw_identity--hardware-identity-backends) (3)
25. [`verifier` — TLS verifier rebuild](#verifier--tls-verifier-rebuild) (1)
26. [`archive` — encrypted archive key rotation](#archive--encrypted-archive-key-rotation) (1)
27. [`audit` — hash-chain integrity](#audit--hash-chain-integrity) (3)
28. [`admin` & `mgmt` — operator control plane](#admin--mgmt--operator-control-plane) (2)
29. [`server` — process lifecycle](#server--process-lifecycle) (1)
30. [`air_gap` — air-gap mode rejections](#air_gap--air-gap-mode-rejections) (1)

---

## `client` — TLS client lifecycle

Records every TLS client session boundary. `client.connected` /
`client.disconnected` bracket every clean session; `client.rejected`
and `client.tls_error` capture failures at the listener boundary;
`client.negotiation` reports the post-handshake protocol selection;
`client.force_disconnected` records operator-initiated kicks via the
management API.

| Event | Fields | Purpose |
|---|---|---|
| `client.connected` | `cn`, `peer`, `fingerprint`, `session_id`, `action="connect"`, `result="success"` | Successful client session admitted. |
| `client.disconnected` | `cn`, `session_id`, `action="disconnect"`, `result="success"` | Clean client disconnect. |
| `client.rejected` | `peer`, `reason`, `action="connect"`, `result="rejected"` | Connection rejected at the listener (connection-limit semaphore saturated). |
| `client.tls_error` | `peer`, `error`, `action="tls_handshake"`, `result="failure"` | TLS accept error — may carry attacker-supplied bytes (sanitized). |
| `client.negotiation` | `cn`, `protocol`, `action="negotiate"`, `result="success"\|"failure"` | Post-handshake protocol negotiation outcome (TAK proto, XML, ...). |
| `client.force_disconnected` | `cn`, `by_operator`, `sessions_closed`, `action`, `result` | Operator forced one or more sessions to close via `POST /api/v1/clients/{cn}/disconnect` (#902). |

## `tls` — handshake failures

A finer-grained companion to `client.tls_error` with a `stage` label
identifying where in the handshake the failure occurred.

| Event | Fields | Purpose |
|---|---|---|
| `tls.handshake_failed` | `peer`, `reason`, `stage`, `action`, `result` | TLS handshake failure with `stage = "accept"\|"verify"\|"identity_extract"`. |

## `cert` — server certificate rotation

Surfaces every server-certificate rotation attempt so an operator can
correlate a rotation with the downstream connection-failure rate.

| Event | Fields | Purpose |
|---|---|---|
| `cert.rotated` | `cert_path`, `new_serial`, `action`, `result` | Successful server certificate rotation. |
| `cert.rotation_failed` | `cert_path`, `error`, `action`, `result` | Failed server certificate rotation attempt. |

## `crl` — CRL reload outcomes

Every SIGHUP-driven or startup CRL reload, plus failure attribution
for stale-CRL alerting.

| Event | Fields | Purpose |
|---|---|---|
| `crl.reloaded` | `count`, `source`, `action`, `result` | Successful CRL reload. `count` is revoked-serial count. |
| `crl.reload_failed` | `source`, `error`, `action`, `result` | Failed CRL reload — investigate against the `rustgate_crl_age_seconds` gauge. |

## `enrollment` — CSR signing / EST

Records every CSR signing, certificate issuance, and revocation
through the EST (RFC 7030) / PKCS#12 enrollment endpoints.

| Event | Fields | Purpose |
|---|---|---|
| `enrollment.signed` | `username`, `client_uid`, `action`, `result` | CSR signed successfully. |
| `enrollment.sign_failed` | `username`, `client_uid`, `error`, `action`, `result` | CSR signing failed. |
| `enrollment.auth_failed` | `peer`, `action`, `result` | Enrollment endpoint authentication failed. |
| `enrollment.certificate_issued` | `username`, `client_uid`, `serial`, `action`, `result` | Certificate issued and ready for distribution. |
| `enrollment.certificate_revoked` | `serial`, `reason`, `revoked_by`, `action`, `result` | Certificate explicitly revoked via the management API. |

## `federation` — peer connectivity

Federation peer lifecycle, circuit-breaker state transitions, and
gRPC-level event handling. `federation.event_received` /
`federation.event_rejected` track every V2 unary RPC; the
`federation.group_claim_rejected` event guards against peers claiming
group memberships they should not have.

| Event | Fields | Purpose |
|---|---|---|
| `federation.connected` | `peer_id`, `peer_cn`, `direction`, `action`, `result` | Peer connection established. |
| `federation.disconnected` | `peer_id`, `reason`, `action` | Peer disconnected. |
| `federation.connect_failed` | `peer_id`, `error`, `action`, `result` | Outbound peer connection attempt failed. |
| `federation.peer_rejected` | `remote_addr`, `reason`, `action`, `result` | Peer rejected at the mTLS boundary (CN extraction failed). |
| `federation.circuit_tripped` | `peer_id`, `total_trips`, `action`, `result` | Per-peer circuit breaker opened. `total_trips` is the lifetime trip count. |
| `federation.circuit_recovered` | `peer_id`, `action`, `result` | Per-peer circuit breaker closed after probe period. |
| `federation.config_changed` | `actor`, `peer_id`, `action`, `result` | Operator modified federation config at runtime. |
| `federation.event_received` | `rpc`, `peer_cn`, `action`, `result` | Inbound V2 unary RPC accepted (`SendOneEvent`, ...). |
| `federation.event_rejected` | `rpc`, `peer_cn`, `reason`, `action`, `result` | Inbound V2 unary RPC rejected — security signal. |
| `federation.group_claim_rejected` | `peer_cn`, `origin_cn`, `claimed_count`, `claimed_groups`, `action`, `result` | Peer claimed `federate_groups` memberships it was not authorised to forward. |
| `federation.traceparent_invalid` | `peer`, `reason`, `action`, `result` | Malformed W3C `traceparent` header on an inbound gRPC RPC. |

See the [federation-reconnect runbook](runbooks/federation-reconnect.md).

## `authz` — policy enforcement & reload

The router PEP emits a `authz.denied` for every denied send/receive
decision and an `authz.classified_delivery` for every successful
delivery carrying a `TagClassified` obligation. The reload triplet
(`reload_success`, `reload_failed`, `reload_rollback`) is the canonical
"policy change happened" audit trail.

| Event | Fields | Purpose |
|---|---|---|
| `authz.denied` | `subject_cn`, `subject_fingerprint`, `action`, `resource_kind`, `resource_id`, `rule_id`, `policy_id`, `result` | PEP denied a send or receive operation. |
| `authz.classified_delivery` | `subject_cn`, `recipient_cn`, `action`, `resource_kind`, `resource_id`, `rule_id`, `policy_id`, `result` | Per-recipient delivery of a message carrying a classification obligation. |
| `authz.obligation_failed` | `subject_cn`, `obligation`, `reason`, `recovery`, `source_protocol`, `destination_kind`, `policy_id`, `action`, `result` | Obligation actuation failed (e.g. `mask_point_xml_parse_error`). |
| `authz.obligation_unknown` | `subject_cn`, `obligation`, `reason`, `source_protocol`, `destination_kind`, `policy_id`, `action`, `result` | Unknown `Obligation` variant — forward-compat signal. |
| `authz.reload_success` | `path`, `policy_id`, `rule_count`, `action`, `result` | Authz policy reloaded successfully. |
| `authz.reload_failed` | `path`, `stage`, `error`, `action`, `result` | Authz reload failed; `stage = "read"\|"parse"\|"compile"\|"startup"`. |
| `authz.reload_rollback` | `reason`, `previous_policy_id`, `action`, `result` | Failed reload rolled back to the previous policy. **Page on this.** |

See the [authz runbook](runbooks/authz.md).

## `egress` — outbound obligation actuation

Single event per obligation per sink per egress fan-out. Tracks
data-plane modifications (mask, tag, redact) that crossed the wire.

| Event | Fields | Purpose |
|---|---|---|
| `egress.obligation.applied` | `sink`, `obligation_type`, `recipient_class`, `action`, `result` | One obligation applied to the outbound envelope sent to one sink. |

## `classification` — CAPCO marking checks

Cross-domain classification enforcement. `classification.denied` fires
when a recipient's clearance does not dominate a message's marking;
`classification.missing` fires when an inbound message under
`--require-classification-marking` carried no CAPCO marking at all.

| Event | Fields | Purpose |
|---|---|---|
| `classification.denied` | `source`, `dest`, `uid`, `marking`, `group`, `action`, `result` | Egress denied — recipient clearance does not dominate the message marking. |
| `classification.missing` | `source`, `uid`, `protocol`, `action`, `result` | Inbound message rejected — no CAPCO marking under strict mode. |

## `message` — chain-of-custody delivery & drop

Per-recipient receipts (issue #854). Volume can be high — these are
the audit log's biggest contributor under load. Disable selectively
in tracing subscriber config if storage is constrained.

| Event | Fields | Purpose |
|---|---|---|
| `message.delivered` | `source`, `dest`, `uid`, `msg_type`, `group`, `entity_kind`, `trace_id`, `action`, `result` | Per-recipient delivery confirmed. |
| `message.dropped` | `source`, `dest`, `uid`, `reason`, `action`, `result` | Per-recipient delivery dropped. |

## `mesh` — multi-hop routing

DSR-style multi-hop routing in the federation mesh. Each mesh hop
emits exactly one event so the full provenance chain is reconstructable
from the audit log.

| Event | Fields | Purpose |
|---|---|---|
| `mesh.route_added` | `destination`, `next_hop`, `metric`, `action`, `result` | New mesh route learned. |
| `mesh.route_removed` | `destination`, `reason`, `action`, `result` | Route withdrawn (neighbor disappeared, peer removed, stale prune). |
| `mesh.route_updated` | `destination`, `next_hop`, `old_metric`, `new_metric`, `action`, `result` | Existing route updated to a better next hop or metric. |
| `mesh.forwarded` | `destination`, `next_hop`, `hops`, `action`, `result` | Successful mesh forward. |
| `mesh.loop_detected` | `destination`, `hops`, `action`, `result` | Message dropped — our peer ID was already in the provenance chain. |
| `mesh.ttl_expired` | `destination`, `hops`, `max_hops`, `action`, `result` | Message dropped — hop count exceeded configured maximum. |
| `mesh.no_route_to_destination` | `destination`, `action`, `result` | No mesh route to destination — message dropped. |

## `http` — egress publishers & DLQ

HTTP webhook egress: per-target circuit-breaker state machine,
rate-limit shedding, and the dead-letter queue lifecycle. The DLQ
`drain_started` / `drain_completed` pair are the audit-trail
companions to `rustgate_http_dlq_replayed_total`.

| Event | Fields | Purpose |
|---|---|---|
| `http.publish_failed` | `target`, `status`, `error`, `action`, `result` | HTTP publish failed for a target. |
| `http.circuit_tripped` | `target`, `action`, `result` | Circuit breaker opened for a target. |
| `http.circuit_recovered` | `target`, `action`, `result` | Circuit breaker closed after probe success. |
| `http.circuit_probing` | `target`, `action`, `result` | Circuit transitioned to half-open and is probing. |
| `http.rate_limited` | `target`, `source_cn`, `action`, `result` | Message shed by the per-target rate limiter. |
| `http.dlq_failed` | `target`, `error`, `action`, `result` | DLQ write failed. |
| `http.dlq_drain_started` | `target`, `segments`, `action`, `result` | Auto-drain pass began after circuit recovery. |
| `http.dlq_drain_completed` | `target`, `replayed`, `failed`, `action`, `result` | Auto-drain pass finished. |

## `mqtt` — MQTT broker events

Single audit event for the most operationally significant MQTT
event: a will message firing on ungraceful disconnect.

| Event | Fields | Purpose |
|---|---|---|
| `mqtt.will_published` | `cn`, `topic`, `group`, `retain`, `action`, `result` | LWT published on behalf of an ungracefully disconnected client. |

## `nats` — NATS bridge

The NATS subscriber's poison-message DLQ entry — fires on a
message that exceeded retry attempts and was permanently parked.

| Event | Fields | Purpose |
|---|---|---|
| `nats.poison_dlq` | `subject`, `msg_id`, `reason`, `attempts`, `action`, `result` | Message routed to the poison-message DLQ. |

## `udp_multicast` — UDP multicast bridge

Multicast ingress / egress lifecycle. `udp_multicast.publish` fires
per outbound multicast — high volume under SA broadcast workloads.

| Event | Fields | Purpose |
|---|---|---|
| `udp_multicast.joined` | `group`, `interface`, `action`, `result` | Multicast group joined on a configured interface. |
| `udp_multicast.publish` | `group`, `uid`, `action`, `result` | Per-message multicast publish (one event per outbound). |

## `mavlink` — MAVLink framing

MAVLink v2 frames. `mavlink.unsigned_rejected` is the security signal
(unsigned frames on a codec requiring signatures);
`mavlink.heartbeat_received` is the operational signal (vehicle
identity, autopilot, frame metadata).

| Event | Fields | Purpose |
|---|---|---|
| `mavlink.unsigned_rejected` | `peer`, `reason`, `action`, `result` | Unsigned MAVLink v2 frame rejected by a signature-requiring codec. |
| `mavlink.heartbeat_received` | `system_id`, `component_id`, `autopilot`, `vehicle_type`, `action`, `result` | MAVLink HEARTBEAT decoded — useful for vehicle inventory. |

## `guard` — cross-domain boundary

Cross-domain inspection guard (`rustgate-guard`). The guard writes its
own tamper-evident `boundary.evaluate` record to a **dedicated**
hash-chained log on every evaluation; these two events mirror activation
and the *deny* outcome into the main audit stream so a SIEM watching the
operational log sees boundary gating without tailing the separate guard
chain.

| Event | Fields | Purpose |
|---|---|---|
| `guard.activated` | `sink`, `direction`, `mandatory_marking`, `action="guard_activate"`, `result="active"` | A cross-domain guard was wired onto an egress leg at startup. |
| `guard.rejected` | `cn`, `sink`, `direction`, `reason`, `action="guard_evaluate"`, `result="rejected"` | A message was dropped at the boundary (`reason = rate_limit \| missing_marking \| unauthorized_classification \| audit_error`). |

## `store_forward` — offline queue

Per-CN durable offline queue lifecycle. `store_forward.drained` (issue
#729) is the dwell-time observability event — fires once per
reconnect with mean/min/max dwell statistics.

| Event | Fields | Purpose |
|---|---|---|
| `store_forward.dropped` | `cn`, `reason`, `action`, `result` | Message dropped from the queue (writer channel overflow). |
| `store_forward.key_rotated` | `path`, `depth`, `reason`, `action`, `result` | Operator-initiated wipe of the queue on startup. |
| `store_forward.drain_panic` | `session`, `error`, `action`, `result` | `spawn_blocking` drain task panicked or was cancelled. |
| `store_forward.drained` | `cn`, `count`, `dwell_seconds_mean`, `dwell_seconds_min`, `dwell_seconds_max`, `expired_count`, `tampered_count`, `action`, `result` | Successful drain on reconnect with dwell statistics. |

## `position_replay` — replay rate limits

Per-CN position-replay rate limiter (issue #724). Fires when a
reconnecting client requests more replays than its budget allows.

| Event | Fields | Purpose |
|---|---|---|
| `position_replay.rate_limited` | `session`, `attempted`, `allowed`, `action`, `result` | Replay request shed by the per-CN rate limiter. |

## `security` & `quota` — rate limits & tenant throughput

The `security.rate_limited` event is the generic per-IP rate-limit
signal; `quota.tenant_throughput_exceeded` fires when the
per-tenant aggregate-throughput token bucket is exhausted (issue #883).

| Event | Fields | Purpose |
|---|---|---|
| `security.rate_limited` | `peer`, `endpoint`, `limit`, `action`, `result` | Per-IP rate limit triggered. |
| `quota.tenant_throughput_exceeded` | `tenant`, `uid`, `requested`, `available`, `action`, `result` | Per-tenant aggregate throughput exhausted. |

## `tenant` — label-cardinality protection

Closes issue #859. Fires when the per-tenant Prometheus label-set
cardinality cap is exceeded — a strong signal of misconfiguration or
tenant-ID injection attempts.

| Event | Fields | Purpose |
|---|---|---|
| `tenant.isolation_label_overflow` | `metric`, `distinct_tenants`, `action`, `result` | Label cardinality cap exceeded for a per-tenant metric family. |

## `jwks` — JWKS rotation

JSON Web Key Set rotation lifecycle for federation JWT verification.
Every `kid` addition / removal is recorded for forensic
reconstruction of "what key signed this JWT at this time".

| Event | Fields | Purpose |
|---|---|---|
| `jwks.refresh_success` | `url`, `key_count`, `action`, `result` | Successful JWKS HTTP fetch. |
| `jwks.refresh_failed` | `url`, `reason`, `action`, `result` | JWKS HTTP fetch failed. |
| `jwks.key_added` | `url`, `kid`, `alg`, `action`, `result` | New `kid` registered with the JWT verifier. |
| `jwks.key_removed` | `url`, `kid`, `action`, `result` | Previously known `kid` no longer advertised — removed from verifier. |

## `jwt` — token verification

Single observability event: JWT verified against a `kid` currently in
the **Retiring** rotation-state, with a countdown to full retirement.

| Event | Fields | Purpose |
|---|---|---|
| `jwt.using_retiring_kid` | `kid`, `retiring_for_seconds`, `action`, `result` | JWT verified with a soon-to-retire key — schedule client rotation. |

## `spiffe` — SPIFFE X.509-SVID refresh

Workload API SVID lifecycle. Both success and failure share the same
`event_type = "spiffe.svid_refresh"`; the `result` field discriminates.

| Event | Fields | Purpose |
|---|---|---|
| `spiffe.svid_refresh` (success) | `spiffe_id`, `trust_domain`, `expiry_unix`, `action`, `result="success"` | Successful X.509-SVID refresh. |
| `spiffe.svid_refresh` (failure) | `error`, `action`, `result="failure"` | Failed X.509-SVID refresh attempt. |

## `hw_identity` — hardware identity backends

Hardware-rooted identity backends (TPM, PKCS#11 HSM, etc.).
`unavailable` fires when the backend was queried mid-handshake and
reported it could not sign right now; `sign_failed` fires when the
backend claimed availability but the signing call itself failed.

| Event | Fields | Purpose |
|---|---|---|
| `hw_identity.loaded` | `backend`, `action`, `result` | Backend initialized at startup. |
| `hw_identity.unavailable` | `backend`, `reason`, `action`, `result` | Backend reported unavailable at sign time. |
| `hw_identity.sign_failed` | `backend`, `reason`, `action`, `result` | Backend claimed availability but signing failed. |

## `verifier` — TLS verifier rebuild

The TLS root verifier is rebuilt on every CRL reload (since the
verifier holds the CRL). This event captures the rebuild failures
that would otherwise leave the listener running with stale trust.

| Event | Fields | Purpose |
|---|---|---|
| `verifier.rebuild_failed` | `error`, `action`, `result` | Verifier rebuild after trust-store change failed. |

## `archive` — encrypted archive key rotation

Closes #870. Fires at startup when the encrypted-archive `KeyRing`'s
active key is within its configured rotation window — operator
must rotate before the key expires or new archives will fail.

| Event | Fields | Purpose |
|---|---|---|
| `archive.key_rotation_due` | `kid`, `days_remaining`, `action`, `result` | Active archive key approaches rotation cliff. |
| `archive.rotation_completed` | `bytes_after`, `files_deleted`, `action`, `result` | A retention rotation pass purged ≥1 archive segment (F-69); absence is alertable if rotation stalls. |

## `audit` — hash-chain integrity

The audit subsystem audits itself. `audit.chain_discontinuity` is
emitted when startup detects that the persisted anchor tip does not
match the live tip — the strongest possible "your audit log may have
been tampered with" signal. The anchor pair tracks clean shutdowns so
operators can distinguish "tampered" from "crashed without persisting".

| Event | Fields | Purpose |
|---|---|---|
| `audit.chain_discontinuity` | `audit_path`, `anchor_tip`, `live_tip`, `reason`, `action`, `result` | **Page on this.** Audit chain head no longer matches the on-disk anchor. |
| `audit.chain_anchor_persisted` | `audit_path`, `tip`, `action`, `result` | Graceful shutdown persisted the chain anchor. |
| `audit.chain_anchor_persist_failed` | `audit_path`, `error`, `action`, `result` | Anchor persistence failed at shutdown — investigate disk / permissions. |

See the [audit-chain-corruption runbook](runbooks/audit-chain-corruption.md).

## `admin` & `mgmt` — operator control plane

Operator-driven actions go through the management API. Every read
emits `mgmt.api_accessed`; every drain emits `admin.drain_triggered`;
every force-disconnect emits `client.force_disconnected` (above).

| Event | Fields | Purpose |
|---|---|---|
| `admin.drain_triggered` | `source`, `action`, `result` | Operator triggered graceful drain (`source = "api"\|"signal"`). |
| `mgmt.api_accessed` | `endpoint`, `identity`, `action`, `result` | Read endpoint successfully served — feeds operator-action forensic trails. |

## `server` — process lifecycle

Single startup event. Pair with `audit.chain_anchor_persisted` for a
complete startup-to-shutdown audit-record envelope per process.

| Event | Fields | Purpose |
|---|---|---|
| `server.started` | `bind`, `version`, `timestamp`, `action`, `result` | Process accepted its first listener bind. |

## `air_gap` — air-gap mode rejections

Fires when an operator configuration would have caused rustgate to
contact an external endpoint while in air-gap mode (e.g. HTTP target
URL, OTEL exporter, OCSP responder, JWKS URL). The configuration is
rejected; this event tells the operator why.

| Event | Fields | Purpose |
|---|---|---|
| `air_gap.violation` | `subsystem`, `endpoint`, `reason`, `action`, `result` | Configuration rejected because air-gap mode bans an external endpoint. |

---

## Recommended audit alerts

| Alert | Expression | Severity |
|---|---|---|
| Audit chain tampered | any `audit.chain_discontinuity` | **page** |
| Authz policy reload rolled back | any `authz.reload_rollback` | **page** |
| Server certificate rotation failed | any `cert.rotation_failed` | **page** |
| Verifier rebuild failed | any `verifier.rebuild_failed` | **page** |
| HTTP circuit stuck open >5 min | `http.circuit_tripped` without matching `http.circuit_recovered` | page |
| Federation group claim rejected | any `federation.group_claim_rejected` | warn |
| MAVLink unsigned-frame rejection rate | rate of `mavlink.unsigned_rejected` > 1 / 5 min | warn |
| Classification denial spike | rate of `classification.denied` > 10 / 5 min | warn |
| Mesh loop detected (sustained) | rate of `mesh.loop_detected` > 0.1 / 1 min | warn |
| Archive key rotation overdue | `archive.key_rotation_due` with `days_remaining < 7` | warn |
| JWT relying on retiring kid | rate of `jwt.using_retiring_kid` > 0 / 1 h | warn |
| Air-gap violation attempted | any `air_gap.violation` | page |

---

## Keeping this catalogue in sync

Audit events are hand-maintained against
`crates/rustgate-core/src/audit.rs`. To regenerate the master list:

```bash
python3 - <<'PY'
import re
from pathlib import Path
src = Path("crates/rustgate-core/src/audit.rs").read_text()
events = sorted({m.group(1) for m in re.finditer(r'audit!\(\s*"([a-z_.]+)"', src)})
print(len(events))
for e in events:
    print(f"  {e}")
PY
```

— diff against the row count above (87). When you add a new
`audit::*` function in the same PR, add a row in the appropriate
domain section here.
