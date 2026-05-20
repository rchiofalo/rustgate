# Prometheus Metrics Reference

This is the canonical catalogue of every Prometheus metric rustgate exposes.
154 metrics across 10 crates, grouped here by operational domain rather than
by source crate so an operator can find "the connection counters" without
knowing which crate registers them.

For trace spans and structured logging, see [observability.md](observability.md).
For the audit-event catalogue, see [audit-events-reference.md](audit-events-reference.md).

## How metrics work

- **Compile** rustgate with `--features metrics` (enabled in the default
  release binary). Without the feature the entire instrumentation path is
  removed at compile time — zero allocations, zero cost.
- **Expose** them with `--metrics-bind <addr>` (env `RUSTGATE_METRICS_BIND`).
  Example: `--metrics-bind 0.0.0.0:9090`. The endpoint is `/metrics` in
  the Prometheus text exposition format.
- **Authenticate** scrapes with `--metrics-token-file <path>`
  (constant-time Bearer comparison) and/or `--metrics-tls-*` for mTLS.
  Without either, `/metrics` is unauthenticated — bind to a private
  interface in that case.
- **Health** is exposed at `/healthz` on the same listener.

### Naming conventions

| Suffix | Type | Convention |
|---|---|---|
| `_total` | Counter (Int or Float) | Monotonic count of events since process start |
| `_seconds` | Histogram | Latency in SI seconds (operators avoid mixed-unit dashboards) |
| `_bytes` | Gauge or Counter | Memory / queue / payload sizes in bytes |
| `_nanos` | Gauge or Histogram | Sub-millisecond latency where seconds histograms would lose resolution |
| `_size` | Gauge | Cardinality of an in-memory collection (cache, table, registry) |
| (no suffix) | Gauge | Steady-state quantity — connections active, sessions registered |

Every name carries the `rustgate_` prefix. A scrape result looks like:

```
# HELP rustgate_connections_active Currently active TLS connections
# TYPE rustgate_connections_active gauge
rustgate_connections_active 142
# HELP rustgate_messages_routed_total Messages routed by destination type and source identity
# TYPE rustgate_messages_routed_total counter
rustgate_messages_routed_total{destination="group",identity_cn="<hash>"} 38291
```

### Cardinality

Most label sets are intentionally low-cardinality. The two opt-in
exceptions are gated behind explicit flags:

- `--metrics-per-identity` enables Tier 2 per-CN counters
  (`rustgate_per_identity_*` and `rustgate_messages_dropped_total`'s
  `identity_cn` label). CNs are hashed via `rustgate_core::masking::hash_cn`
  before they reach Prometheus — what looks like a CN in the label is a
  48-bit truncation of its SHA-256.
- `--metrics-per-identity-allowlist` lets operators bound the active set
  of identities further.

Per-tenant labels (`tenant`) collapse to `_overflow` once a cap
(`MAX_TENANT_LABELS`) is hit; this protects the registry against tenant
ID explosion without losing the aggregate signal.

## Table of contents

1. [Build & process info](#build--process-info)
2. [TLS connection lifecycle](#tls-connection-lifecycle)
3. [Sessions & router](#sessions--router)
4. [Authorization (PEP)](#authorization-pep)
5. [CoT codec & delta compression](#cot-codec--delta-compression)
6. [Per-tenant quotas](#per-tenant-quotas)
7. [Per-identity (Tier 2)](#per-identity-tier-2)
8. [Per-client store-and-forward queue](#per-client-store-and-forward-queue)
9. [Federation](#federation)
10. [NATS / JetStream](#nats--jetstream)
11. [MQTT broker](#mqtt-broker)
12. [WebSocket](#websocket)
13. [HTTP egress](#http-egress)
14. [Boundary guard](#boundary-guard)
15. [Operator (Kubernetes controller)](#operator-kubernetes-controller)
16. [Enrollment & client OCSP](#enrollment--client-ocsp)
17. [CRL & archive bookkeeping](#crl--archive-bookkeeping)
18. [Admin drain](#admin-drain)

---

## Build & process info

Identity of the running binary and allocator-level memory accounting.
Use `rustgate_build_info` to confirm the rolled-out version on every node
in a federation; use the jemalloc gauges to attribute RSS growth between
allocator-internal fragmentation and application-requested allocations.

The jemalloc family is only registered when the binary was built with
`--features jemalloc`; otherwise the gauges are absent from scrape output.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_build_info` | IntGaugeVec | `version`, `rust_version`, `features` | Always 1. The label set carries the build identity. |
| `rustgate_jemalloc_resident_bytes` | IntGauge | — | jemalloc resident memory (RSS attributed to the allocator). |
| `rustgate_jemalloc_active_bytes` | IntGauge | — | jemalloc active memory (allocated pages backing application data). |
| `rustgate_jemalloc_allocated_bytes` | IntGauge | — | jemalloc allocated memory (application-requested allocations). |
| `rustgate_jemalloc_mapped_bytes` | IntGauge | — | jemalloc mapped memory (total virtual memory mapped by the allocator). |

---

## TLS connection lifecycle

From `accept(2)` through TLS handshake completion through admission into
the router. The first three metrics are the canonical "load on the
listener" signals; `handshake_failures_total` is the canonical signal for
client-side certificate problems; `admission_deferred_total` indicates
the listener intentionally backed off because the backpressure gate's
high-water mark was hit.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_connections_accepted_total` | IntCounter | — | TLS connections accepted by the listener. |
| `rustgate_connections_active` | IntGauge | — | Currently active TLS connections. |
| `rustgate_connections_rejected_total` | IntCounter | — | Connections rejected because the connection-limit semaphore was saturated. |
| `rustgate_accept_errors_total` | IntCounter | — | `accept(2)` syscall errors (file-descriptor exhaustion, listener teardown). |
| `rustgate_handshake_failures_total` | IntCounterVec | `reason` | TLS handshake failures grouped by failure mode. |
| `rustgate_tls_handshake_duration_seconds` | HistogramVec | `outcome` | TLS handshake latency, labelled `ok` / `err`. |
| `rustgate_negotiations_total` | IntCounterVec | `result` | Post-handshake protocol negotiations (e.g. TAK proto vs. XML). |
| `rustgate_queued_bytes` | IntGauge | — | Bytes the admission-control gate currently has in flight (sum across sessions). |
| `rustgate_admission_deferred_total` | IntCounter | — | Times the accept loop slept because the gate hit its high-water mark. |

---

## Sessions & router

The router is the central fan-out point. `route_for_egress` decides who
receives each message after ACL + authz + obligation + dedup filtering;
its histogram (`rustgate_router_fanout_subscribers`) is the single best
signal for "how big is a typical fan-out?". `messages_dropped_total`'s
`identity_cn` label is a Tier 2 per-identity counter and only fills with
data when `--metrics-per-identity` is set.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_sessions_active` | IntGauge | — | Sessions currently registered in the router. |
| `rustgate_messages_received_total` | IntCounter | — | Messages accepted from clients (pre-route). |
| `rustgate_messages_dropped_total` | IntCounterVec | `identity_cn` | Messages dropped by the per-client rate limiter (Tier 2 cardinality). |
| `rustgate_messages_expired_total` | IntCounter | — | Messages dropped because their TTL expired before delivery. |
| `rustgate_messages_replayed_total` | IntCounter | — | Messages dropped by anti-replay detection. |
| `rustgate_messages_routed_total` | IntCounterVec | `destination`, `identity_cn` | Successful route operations, by destination kind. |
| `rustgate_messages_routed_by_kind_total` | IntCounterVec | `kind`, `protocol` | Routes counted by canonical `EntityKind` and source protocol. Populated when an `EntityCodecRegistry` is installed. |
| `rustgate_router_fanout_total` | IntCounterVec | `destination` | Terminal `route_for_egress` calls, by destination shape (`direct`, `group`, `broadcast`, `multicast`). |
| `rustgate_router_fanout_subscribers` | Histogram | — | Distribution of recipient counts per fan-out. The 0-bucket captures fully-filtered fan-outs. |
| `rustgate_router_dropped_total` | IntCounterVec | `reason` | Recipients (or whole messages) dropped after admission, by reason (`no_subscribers`, `backpressure`, ...). |
| `rustgate_router_fanout_by_tenant_total` | IntCounterVec | `destination`, `tenant` | Per-tenant slice of `rustgate_router_fanout_total`. Tenant collapses to `_overflow` past the cap. |
| `rustgate_router_dropped_by_tenant_total` | IntCounterVec | `reason`, `tenant` | Per-tenant slice of `rustgate_router_dropped_total`. Same `_overflow` semantics. |
| `rustgate_router_interceptor_verdict_total` | IntCounterVec | `verdict` | `MessageInterceptor` verdicts (`accept`, `transformed`, `reject`). |
| `rustgate_dedup_hits_total` | IntCounter | — | Cross-path duplicate messages suppressed before dispatch. |
| `rustgate_dedup_cache_size` | IntGauge | — | Entries currently in the cross-path dedup cache. |
| `rustgate_position_cache_size` | IntGauge | — | Latest-position cache entries (one per CN). Alert on approach to `max_entries`. |
| `rustgate_multicast_oversize_dropped_total` | IntCounter | — | Multicast messages dropped because the group list exceeded `MAX_MULTICAST_GROUPS`. Amplification-DoS signal. |
| `rustgate_sa_auto_upgraded_total` | IntCounterVec | `from_version` | SA (situational-awareness) payloads whose `<event version=…>` was rewritten to the canonical form. |
| `rustgate_mavlink_heartbeats_total` | IntCounterVec | `system_id` | MAVLink `HEARTBEAT` frames received per `system_id`. |

---

## Authorization (PEP)

Two distinct evaluators feed this section. The router runs the PEP for
every send and receive operation; the underlying engine (in
`rustgate-authz`) caches decisions. Both layers emit metrics — use the
PEP family for "is the policy actually allowing/denying?" and the engine
family for "is the cache holding up under load?".

`authz_eval_nanos` is retained for backward compatibility; new
dashboards should prefer `authz_evaluation_seconds`.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_authz_decisions_total` | IntCounterVec | `action`, `decision` | PEP decisions broken out by action (send/receive) and decision (allow/deny/fail_open). |
| `rustgate_pep_send_decisions_total` | IntCounterVec | `decision` | Send-PEP decisions emitted by the router. |
| `rustgate_pep_receive_decisions_total` | IntCounterVec | `decision` | Receive-PEP decisions emitted by the router. |
| `rustgate_pep_evaluation_seconds` | HistogramVec | `direction` | PEP wall-clock evaluation latency by direction. |
| `rustgate_authz_evaluations_total` | IntCounterVec | `decision`, `subject_class` | Engine-level evaluations classified by decision + subject class. |
| `rustgate_authz_evaluation_seconds` | HistogramVec | `decision` | Engine evaluation duration (canonical SI form). |
| `rustgate_authz_eval_nanos` | Histogram | — | Engine evaluation duration in nanoseconds (legacy; use `_seconds` for new dashboards). |
| `rustgate_authz_evaluations_in_flight` | IntGauge | — | In-flight evaluations holding the engine `Arc` cloned out of the router's `ArcSwap`. Useful for tracking SIGHUP drain. |
| `rustgate_authz_cache_size` | IntGauge | — | Live entry count across all decision-cache shards. |
| `rustgate_authz_cache_hits_total` | IntCounter | — | Decision-cache lookups that returned a cached outcome. |
| `rustgate_authz_cache_misses_total` | IntCounter | — | Decision-cache lookups that ran the full scan and populated the cache. |
| `rustgate_authz_policy_rules` | IntGauge | — | Rules in the currently installed policy. |
| `rustgate_authz_reloads_total` | IntCounterVec | `result` | Policy reload outcomes (`success`, `failure`). |
| `rustgate_authz_obligations_emitted_total` | IntCounterVec | `obligation_type` | Obligations attached to allow decisions (`mask_point`, `mask_payload`, `tag_classified`, ...). |
| `rustgate_obligation_applied_total` | IntCounterVec | `kind` | Data-plane obligations actually applied to outbound messages. |
| `rustgate_obligation_failures_total` | IntCounterVec | `reason` | Obligation actuation failures (`mask_point_non_xml`, `mask_point_xml_parse_error`, ...). |
| `rustgate_authz_obligation_unknown_total` | IntCounterVec | `variant` | Unknown obligation variants encountered by the transport (issue #762 forward-compat). |
| `rustgate_reload_rollback_total` | IntCounterVec | `subsystem` | Hot-reload failures that rolled back to the previous policy (`authz`, `acl`, `crl`, ...). |

---

## CoT codec & delta compression

Cursor-on-Target parsing (`rustgate-cot`), TAK protobuf transcoding
(`rustgate-proto`), and per-UID delta compression of outbound CoT events
(`rustgate-server` integration). Delta compression trades a small CPU
cost for a large bandwidth reduction on position-update-heavy traffic;
`rustgate_cot_delta_bytes_saved_total` is the headline win metric.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_cot_parse_total` | IntCounterVec | `result` | CoT XML parse attempts, by `ok` / `err`. |
| `rustgate_cot_parse_seconds` | Histogram | — | CoT XML parse latency (every attempt, success or failure). |
| `rustgate_proto_decode_total` | IntCounterVec | `kind`, `result` | TAK protobuf ↔ CoT XML decode attempts. |
| `rustgate_proto_decode_seconds` | HistogramVec | `kind` | TAK protobuf ↔ CoT XML decode latency. |
| `rustgate_cot_delta_full_total` | IntCounter | — | Outbound CoT events emitted as full (no delta). |
| `rustgate_cot_delta_delta_total` | IntCounter | — | Outbound CoT events emitted as deltas. |
| `rustgate_cot_delta_suppressed_total` | IntCounter | — | Outbound CoT events suppressed (sub-epsilon drift, no field change). |
| `rustgate_cot_delta_bytes_saved_total` | IntCounter | — | Bytes saved by the encoder (`full_len - delta_len` summed across emissions). |
| `rustgate_cot_delta_evicted_total` | IntCounter | — | UIDs evicted from the delta cache under capacity pressure. Sustained non-zero ⇒ undersized cache. |
| `rustgate_cot_delta_oversized_total` | IntCounter | — | Payloads that exceeded the delta scan limit and were forcibly emitted as full. Sustained rate ⇒ hostile padding signal. |

---

## Per-tenant quotas

Per-tenant connection caps and aggregate-throughput token buckets. The
`tenant` label is derived from the certificate Organization (`O`) field;
when no tenant is identifiable the synthetic `DEFAULT_TENANT_KEY` is
used. To prevent registry explosion the label collapses to `_overflow`
past `MAX_TENANT_LABELS`.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_tenant_quota_rejections_total` | IntCounterVec | `tenant` | Sessions rejected because the tenant connection quota was exceeded. |
| `rustgate_tenant_throughput_rejections_total` | IntCounterVec | `tenant` | Messages dropped because the per-tenant aggregate-throughput token bucket was exhausted. |
| `rustgate_tenant_throughput_bps` | GaugeVec | `tenant` | Current token-bucket level (bytes) per tenant. Updated on every admit or reject. |

---

## Per-identity (Tier 2)

Off by default. Set `--metrics-per-identity` to enable. The
`identity_cn` label is the 48-bit hash of the client CN, not the CN
itself. Cardinality scales with the active client fleet, so combine with
`--metrics-per-identity-allowlist` if the fleet is large.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_per_identity_handshake_failures_total` | IntCounterVec | `identity_cn` | Per-identity TLS handshake failures. |
| `rustgate_per_identity_session_duration_seconds` | HistogramVec | `identity_cn` | Per-identity session duration. |
| `rustgate_per_identity_bytes_sent_total` | IntCounterVec | `identity_cn` | Per-identity bytes sent to client. |
| `rustgate_per_identity_bytes_received_total` | IntCounterVec | `identity_cn` | Per-identity bytes received from client. |

---

## Per-client store-and-forward queue

Per-CN persistent queue for clients that go offline. `client_queue_*`
gauges track the live buffer; `store_forward_dwell_seconds` is the
end-to-end "how long was that message stuck in the queue?" signal.
`client_queue_writer_drops_total` is the high-priority drop signal: it
indicates the async writer channel saturated, not a regular cap
eviction.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_client_queue_depth` | IntGaugeVec | `identity_cn` | Messages currently queued for store-and-forward per CN (bucketed). |
| `rustgate_client_queue_bytes` | IntGaugeVec | `identity_cn` | Encoded bytes currently queued per CN (bucketed). |
| `rustgate_client_queue_enqueues_total` | IntCounter | — | Messages successfully submitted to the queue writer. |
| `rustgate_client_queue_drains_total` | IntCounter | — | Successful drain operations to a reconnecting client. |
| `rustgate_client_queue_drops_total` | IntCounter | — | Messages dropped from the queue due to cap eviction. |
| `rustgate_client_queue_writer_drops_total` | IntCounter | — | Messages dropped because the async writer channel was full or closed. |
| `rustgate_client_queue_expired_total` | IntCounter | — | Queued messages skipped during drain because their TTL had elapsed. |
| `rustgate_client_queue_skipped_unsupported_total` | IntCounter | — | Queue entries skipped on reopen because destination was not direct (broadcast/group). |
| `rustgate_store_forward_dwell_seconds` | Histogram | — | Per-message dwell time in the queue (`drain_time − queued_at`). |

---

## Federation

Server-to-server federation: connection lifecycle, message accounting,
replay buffer health, V2 gRPC RPC accounting, and per-peer queue depth /
latency. The `peer` label vocabulary is the configured peer list — fixed
cardinality.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_federation_connections` | IntGauge | — | Active federation peer connections. |
| `rustgate_federation_connections_inbound` | IntGauge | — | Active inbound federation connections. |
| `rustgate_federation_connections_outbound` | IntGauge | — | Active outbound federation connections. |
| `rustgate_federation_messages_in_total` | IntCounter | — | Messages received from federation peers. |
| `rustgate_federation_messages_in_by_rpc_total` | IntCounterVec | `rpc` | Messages received, broken out by V2 RPC method. |
| `rustgate_federation_messages_out_total` | IntCounter | — | Messages sent to federation peers. |
| `rustgate_federation_messages_dropped_total` | IntCounter | — | Messages dropped due to loop detection or hop-limit exhaustion. |
| `rustgate_federation_forward_ttl_expired_total` | IntCounter | — | Messages dropped at the forward boundary because their TTL had expired. |
| `rustgate_federation_cross_region_forwards_total` | IntCounter | — | Messages forwarded to a federation peer in a different region. |
| `rustgate_federation_errors_total` | IntCounter | — | Federation errors (envelope of transport-level failures). |
| `rustgate_federation_reconnects_total` | IntCounter | — | Outbound reconnection attempts. |
| `rustgate_federation_heartbeats_total` | IntCounterVec | `direction` | Heartbeats by direction (`in`, `out`). |
| `rustgate_federation_circuit_breaker_trips_total` | IntCounter | — | Circuit-breaker trips across all peers. |
| `rustgate_federation_circuit_breaker_recoveries_total` | IntCounter | — | Circuit-breaker recoveries across all peers. |
| `rustgate_federation_replay_persisted_total` | IntCounter | — | Replay buffer entries persisted to disk. |
| `rustgate_federation_replay_restored_total` | IntCounter | — | Replay entries restored from disk on startup. |
| `rustgate_federation_replay_restored_skipped_ttl_total` | IntCounter | — | Persisted entries skipped on rehydrate because TTL had expired. |
| `rustgate_federation_replay_buffer_bytes` | IntGauge | — | On-disk size of the redb-backed replay buffer (all peers). |
| `rustgate_federation_peer_latency_nanos` | IntGaugeVec | `peer` | EWMA round-trip latency per peer. |
| `rustgate_federation_peer_queue_bytes` | IntGaugeVec | `peer` | Bytes currently queued for delivery to a peer. |
| `rustgate_federation_peer_oldest_seconds` | IntGaugeVec | `peer` | Age of the oldest message still queued for a peer. |
| `rustgate_federation_rpc_total` | IntCounterVec | `rpc`, `peer`, `result` | V2 gRPC invocation count per peer, by outcome. |
| `rustgate_federation_rpc_in_flight` | IntGaugeVec | `rpc`, `peer` | V2 gRPC in-flight count per peer. |
| `rustgate_federation_rpc_duration_seconds` | HistogramVec | `rpc`, `peer`, `result` | V2 gRPC duration per peer, per outcome. |

See the [federation-reconnect runbook](runbooks/federation-reconnect.md)
for "what does a peer flap look like in metrics?".

---

## NATS / JetStream

Bridge between rustgate and a NATS/JetStream cluster. `nats_publishes_total`
is the inbound side (rustgate → NATS); the `nats_consumer_*` family
tracks the JetStream pull-consumer rustgate runs on the outbound side.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_nats_publishes_total` | IntCounter | — | Messages published to NATS. |
| `rustgate_nats_consumer_pending` | IntGauge | — | JetStream `num_pending`. |
| `rustgate_nats_consumer_num_redelivered` | IntGauge | — | JetStream `num_redelivered`. |
| `rustgate_nats_consumer_ack_floor_stream_seq` | IntGauge | — | JetStream `ack_floor.stream_seq`. |
| `rustgate_nats_consumer_info_seconds` | Histogram | — | Latency of `consumer.info()` polls. |

See the [nats-bridge-failure runbook](runbooks/nats-bridge-failure.md).

---

## MQTT broker

The `rustgate-mqtt` crate registers a small in-broker family; the
larger session-handler family lives in `rustgate-server` (because the
session handler sits in the server, not the broker library). Counters
ending `_total` in the server family count packet-level handler
decisions; the broker family counts protocol-level handling. The pair
`active_sessions` (broker) + `mqtt_connections_total` (server) is the
canonical "connections happening vs. sessions surviving" comparison.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_mqtt_active_sessions` | IntGauge | — | Live authenticated MQTT sessions in the broker. |
| `rustgate_mqtt_publish_total` | IntCounterVec | `qos` | Broker-side PUBLISH packets handled, by QoS. |
| `rustgate_mqtt_publish_seconds` | HistogramVec | `qos` | Broker-side PUBLISH handling latency, by QoS. |
| `rustgate_mqtt_will_messages_total` | IntCounter | — | LWT registrations on CONNECT (whether or not the will fires). |
| `rustgate_mqtt_connections_total` | IntCounter | — | mTLS-authenticated MQTT sessions accepted by the listener. |
| `rustgate_mqtt_connections_rejected_total` | IntCounter | — | MQTT connections rejected because the cross-transport semaphore was saturated. |
| `rustgate_mqtt_publishes_total` | IntCounter | — | PUBLISH packets authorised and handed to the router. |
| `rustgate_mqtt_publishes_rejected_total` | IntCounter | — | PUBLISH packets rejected by the session handler (QoS2, topic invalid, authz). |
| `rustgate_mqtt_subscribes_total` | IntCounter | — | SUBSCRIBE topic filters successfully bound (per filter, not per packet). |
| `rustgate_mqtt_subscribes_rejected_total` | IntCounter | — | SUBSCRIBE filters rejected (QoS2, wildcard policy, authz). |
| `rustgate_mqtt_retain_stored_total` | IntCounter | — | PUBLISH packets that inserted or overwrote a retained message. |
| `rustgate_mqtt_retain_cleared_total` | IntCounter | — | PUBLISH packets that triggered the MQTT 5.0 §3.3.1.3 zero-byte clear. |
| `rustgate_mqtt_retain_replayed_total` | IntCounter | — | Retained messages delivered to fresh subscribers (per delivered message). |
| `rustgate_mqtt_will_published_total` | IntCounter | — | Will messages published on a client's behalf on ungraceful disconnect. |

---

## WebSocket

Connection lifecycle for the WebSocket transport. The `_total`
counters live in `rustgate-server` (session-handler boundary); the
WebSocket library itself registers the steady-state gauge and a small
set of per-handshake outcome counters.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_ws_active_connections` | IntGauge | — | Live authenticated WebSocket connections currently handled by the listener. |
| `rustgate_ws_connections_total` | IntCounter | — | WebSocket sessions successfully registered (post-mTLS, post-upgrade, post-tenant-quota). |
| `rustgate_ws_connections_rejected_total` | IntCounter | — | Sessions rejected on the session-handler boundary (per-IP rate limit, TLS, identity, upgrade, connection-limit, tenant quota). |
| `rustgate_ws_messages_total` | IntCounterVec | `direction` | Data messages handled by the listener, by `in` / `out`. |
| `rustgate_ws_compression_negotiated_total` | IntCounterVec | `result` | RFC 7692 `permessage-deflate` negotiation outcomes per session. |
| `rustgate_ws_subprotocol_selected_total` | IntCounterVec | `subprotocol` | RFC 6455 §1.9 subprotocol selections per handshake. |

See the [websocket-storms runbook](runbooks/websocket-storms.md).

---

## HTTP egress

The `rustgate-http` crate publishes messages to HTTP webhook targets
with a circuit breaker, retry loop, and persistent dead-letter queue.
The `target` label is the configured target name (fixed cardinality).

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_http_publishes_total` | IntCounterVec | `target` | Successful HTTP egress deliveries. |
| `rustgate_http_errors_total` | IntCounterVec | `target`, `reason` | Failed HTTP egress deliveries by reason. |
| `rustgate_http_request_duration_seconds` | Histogram | — | End-to-end HTTP request latency. |
| `rustgate_http_circuit_state` | IntGaugeVec | `target` | Circuit-breaker state per target: 0=closed, 1=open, 2=half-open. |
| `rustgate_http_retries_total` | IntCounterVec | `target` | Retry attempts (not initial attempts). |
| `rustgate_http_filtered_total` | IntCounterVec | `target` | Messages filtered out before HTTP dispatch. |
| `rustgate_http_queue_depth` | IntGauge | — | Current HTTP dispatch channel occupancy. |
| `rustgate_http_dropped_total` | IntCounterVec | `reason` | Messages dropped before per-target dispatch (admission-queue shed). |
| `rustgate_http_dlq_evicted_total` | IntCounterVec | `target` | Dead-letter queue files evicted by the per-target byte sweep. |
| `rustgate_http_dlq_replayed_total` | IntCounterVec | `target`, `result` | DLQ entries replayed after the target's circuit recovered. |
| `rustgate_http_response_bodies_captured_total` | IntCounterVec | `target` | 2xx response bodies captured for debug logging. |
| `rustgate_http_batches_flushed_total` | IntCounterVec | `target`, `reason` | Batched-egress flush events, by flush reason. |

---

## Boundary guard

Domain-boundary classifier in `rustgate-guard`. Decides what may cross
between security domains (north-south traffic in cross-domain
deployments). `direction` label distinguishes ingress vs. egress;
`reason` is the typed rejection cause from the guard's policy DSL.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_guard_evaluations_total` | IntCounterVec | `direction`, `decision` | Boundary evaluations by direction (`ingress`/`egress`) and decision. |
| `rustgate_guard_rejections_total` | IntCounterVec | `direction`, `reason` | Boundary rejections by direction and typed reason. |
| `rustgate_guard_throughput_bps` | IntGaugeVec | `direction` | Current token-bucket level (bps headroom) per direction. |

---

## Operator (Kubernetes controller)

The `rustgate-operator` crate is a Kubernetes controller. All six
metrics are registered into a private `Registry` (not the global
default) so the controller surfaces only its own metrics; the
`register_*!` macros are used at construction time, then the resulting
families are inserted into that registry explicitly.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_operator_reconcile_duration_seconds` | Histogram | — | Wall-clock time spent in a single reconcile pass. |
| `rustgate_operator_reconcile_total` | IntCounterVec | `result` | Reconcile attempts, partitioned by outcome. |
| `rustgate_operator_apply_total` | IntCounterVec | `kind`, `result` | Server-side-apply attempts, partitioned by object kind and outcome. |
| `rustgate_operator_clusters_total` | IntGauge | — | `RustgateCluster` resources the operator currently watches. |
| `rustgate_operator_leader` | IntGauge | — | 1 when this replica holds the leader lease; 0 otherwise. |
| `rustgate_operator_last_reconcile_timestamp_seconds` | Gauge | — | Unix time of the most recent successful reconcile across all clusters. |

---

## Enrollment & client OCSP

Certificate enrollment (EST RFC 7030 + PKCS#12) and live OCSP responder
caching for client certificates. The OCSP cache hit/miss pair is the
canonical "is the responder up?" signal — a sustained miss rate means
the cache is bypassing into background fetches.

`rustgate_enrollment_rate_limit_poison_total` is a tombstone counter
left over from pre-#798 code that used `std::sync::Mutex`; the current
implementation uses `parking_lot::Mutex` which does not poison, so the
counter is permanently zero.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_enrollment_rate_limited_total` | IntCounter | — | CSR signing requests rejected by the per-IP rate limiter. |
| `rustgate_enrollment_rate_limit_poison_total` | IntCounter | — | Pre-#798 mutex-poison counter, retained at 0 for dashboard compatibility. |
| `rustgate_client_ocsp_cache_hits_total` | IntCounter | — | Client certificate OCSP cache hits. |
| `rustgate_client_ocsp_cache_misses_total` | IntCounter | — | Client certificate OCSP cache misses (background fetch dispatched). |

---

## CRL & archive bookkeeping

CRL staleness and on-disk size of the CoT event archive. The CRL gauge
is a critical security signal: a CRL publisher that stops refreshing
silently widens the trust window for revoked certificates.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_crl_age_seconds` | IntGauge | — | Seconds since the stalest loaded CRL's `thisUpdate`. Stays at 0 when no CRL is configured. **Alert at >86 400 (24 h).** |
| `rustgate_archive_bytes` | IntGauge | — | Total bytes held in the CoT event archive directory. |

See the [crl-updates runbook](runbooks/crl-updates.md).

---

## Admin drain

Operator-initiated graceful drains via the admin API. The `source`
label distinguishes how a drain was triggered (`api`, `signal`, ...).

| Metric | Type | Labels | Description |
|---|---|---|---|
| `rustgate_admin_drain_triggered_total` | IntCounterVec | `source` | Operator-initiated graceful drain triggers by source. |

---

## Recommended alerts

A starter set. Tune thresholds to the deployment's traffic profile;
the values below are upper bounds for a typical tactical edge node.

| Alert | Expression | Severity |
|---|---|---|
| TLS handshakes failing at scale | `rate(rustgate_handshake_failures_total[5m]) > 10` | warn |
| CRL stale | `rustgate_crl_age_seconds > 86400` | page |
| Connection-limit saturation | `rate(rustgate_connections_rejected_total[5m]) > 0` | warn |
| Backpressure shedding | `rate(rustgate_admission_deferred_total[5m]) > 1` | warn |
| Federation peer down | `rustgate_federation_connections == 0 and on() rustgate_federation_reconnects_total > 0` | page |
| HTTP egress circuit stuck open | `max by (target) (rustgate_http_circuit_state) == 1` | page |
| Authz policy reload failed (any subsystem) | `increase(rustgate_reload_rollback_total[15m]) > 0` | page |
| Position cache near capacity | `rustgate_position_cache_size / 100000 > 0.9` | warn |
| Multicast amplification attempt | `rate(rustgate_multicast_oversize_dropped_total[5m]) > 0` | warn |
| Per-tenant throughput saturated | `rate(rustgate_tenant_throughput_rejections_total[5m]) > 0` | warn |
| Federation replay buffer growth | `delta(rustgate_federation_replay_buffer_bytes[1h]) > 100*1024*1024` | warn |
| MQTT will storm | `rate(rustgate_mqtt_will_published_total[5m]) > 5` | warn |

---

## Keeping this catalogue in sync

This file is hand-maintained against the metric registrations in
`crates/*/src/metrics.rs`. When you add a metric, add a row in the
appropriate section here in the same PR — there is no auto-generation
step, but `scripts/check-playbook-drift.sh` flags drift in canonical-
helper coverage rather than metric coverage. The simplest way to audit
is to regenerate the extracted list:

```bash
# from repo root
python3 - <<'PY'
import re
from pathlib import Path
pat = re.compile(r'(?:HistogramOpts|Opts)::new\(\s*"([A-Za-z0-9_]+)"')
for f in sorted(Path("crates").glob("*/src/metrics.rs")):
    for m in pat.finditer(f.read_text()):
        print(m.group(1))
PY
```

— and diff the result against the row count above (154).
