# Runbook: MQTT Broker Issues

> **Important:** rustgate's MQTT adapter authenticates every CONNECT
> via mTLS (the certificate replaces the MQTT `username`/`password`
> auth). Connection problems are nearly always TLS or
> identity-extraction failures, not MQTT-protocol-level rejections.
> QoS 2 is intentionally not implemented; QoS 0/1 are supported.

## Symptoms

- MQTT clients can complete the TLS handshake but never get a CONNACK.
- CONNACK returns a non-zero reason code (`0x80` not authorised, `0x83`
  implementation-specific error, ...).
- PUBLISH packets succeed at the protocol level but the message never
  reaches the intended subscribers.
- SUBSCRIBE returns failure return codes (`0x80` per filter) where
  success was expected.
- `rustgate_mqtt_active_sessions` gauge lower than the operator
  expected; or much lower than `rustgate_mqtt_connections_total`
  rate suggests.
- High rate of `mqtt.will_published` audit events ⇒ clients are
  dying without clean DISCONNECT.

## Detection

1. **Connection-vs-session ratio.** A persistent gap between
   `rustgate_mqtt_connections_total` and `rustgate_mqtt_active_sessions`
   indicates sessions are dying after admission:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep -E "rustgate_mqtt_(active_sessions|connections_total)"
   ```

2. **Rejection rate.** `rustgate_mqtt_connections_rejected_total` ticks
   when the shared cross-transport connection-limit semaphore is
   saturated; `rustgate_mqtt_publishes_rejected_total` ticks when
   authorisation or topic validation fails:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep -E "rustgate_mqtt_(connections_rejected|publishes_rejected|subscribes_rejected)_total"
   ```

3. **Will firing rate.** A spike on `rustgate_mqtt_will_published_total`
   correlates with ungraceful disconnects across the fleet — usually a
   keep-alive timeout, network partition, or write-loop crash:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep rustgate_mqtt_will_published_total
   ```

4. **Audit trail.** Will-firings and authorisation failures emit
   structured audit events:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=2000 \
     | grep -E '"event_type":"(mqtt\.|client\.tls_error)"' \
     | tail -50
   ```

## Diagnosis

### Connection fails before CONNACK

1. Look for TLS handshake errors first — the MQTT layer never sees
   these:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=500 \
     | grep -E "tls_handshake|client.tls_error"
   ```
   If you see them, this is a TLS-side problem; see
   [tls-handshake-failures.md](tls-handshake-failures.md).

2. Check whether the connection-limit semaphore is saturated:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep -E "rustgate_(connections_active|mqtt_connections_rejected_total)"
   ```
   A non-zero rate on `mqtt_connections_rejected_total` means the
   listener accepted the TLS session but the broker semaphore turned
   it away. Raise `--max-connections` or scale horizontally.

### CONNECT returns 0x80 (not authorised)

The MQTT session handler authorises CONNECT against the client's
certificate-derived identity. Authorisation failures emit the
canonical `client.rejected` or `authz.denied` audit event:

1. Pull the identity used:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=500 \
     | grep '"event_type":"authz.denied"' \
     | grep '"action":"connect"' | tail -20
   ```

2. Cross-reference the `subject_cn` against your authz policy.
   Common cause: the client cert was issued for a group not in any
   `allow` rule, or the policy was reloaded with a stricter set.

### PUBLISH succeeds but no subscribers receive

1. Check whether the PUBLISH was rejected by the broker first:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep -E "rustgate_mqtt_(publishes_total|publishes_rejected_total)"
   ```
   Differential rate of accepted vs. rejected tells you whether the
   issue is upstream (rejected) or downstream (delivery).

2. Confirm topic-to-group mapping. rustgate maps MQTT topics onto
   internal groups for cross-transport routing — a misconfigured
   prefix map silently routes to a non-existent group:
   ```bash
   kubectl get deploy rustgate -o yaml | grep -A5 mqtt-topic
   ```

3. Validate that subscribers are actually attached to the
   corresponding internal group:
   ```bash
   # Via management API (requires --features management-api)
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/v1/sessions | jq '.[] | .groups'
   ```

### SUBSCRIBE return codes are 0x80

The session handler rejects a filter when:
- The protocol is QoS 2 (unsupported).
- The filter is invalid under the configured wildcard policy.
- The filter has no authorised group mapping.

1. Pull recent rejection audits:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=500 \
     | grep '"event_type":"authz.denied"' \
     | grep '"action":"subscribe"' | tail -20
   ```

2. The `subscribes_rejected_total` counter and the audit events
   both increment **per filter**, not per packet — a single
   SUBSCRIBE carrying three filters can produce three rejections.

### Will messages firing more than expected

A sustained `mqtt_will_published_total` rate means clients are
disconnecting ungracefully:

1. Check for an upstream network partition or pod restart that
   would cause a fleet of clients to all hit their keep-alive
   timeout at once.

2. Verify the client keep-alive interval is short enough that the
   broker detects death within the operator's tolerance:
   ```
   Client KEEPALIVE = 60s  ⇒  broker times out at 1.5 × 60 = 90s
   ```
   For tactical workloads, KEEPALIVE in the 15–30 s range is
   typical; longer values mean longer "presence-loss invisible"
   windows.

3. Look for the matching `mqtt.will_published` audit events to
   identify which clients are dying ungracefully:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=2000 \
     | grep '"event_type":"mqtt.will_published"' \
     | tail -50
   ```

## Resolution

### Raise the broker session cap

When `mqtt_connections_rejected_total` is climbing because of
admission semaphore saturation:

1. Raise `--max-connections` (cross-transport cap, shared with
   TLS/WebSocket/MQTT):
   ```bash
   kubectl set env deploy/rustgate RUSTGATE_MAX_CONNECTIONS=8192
   kubectl rollout restart deploy/rustgate
   ```

2. If the host is CPU-bound rather than memory-bound, scale
   horizontally instead:
   ```bash
   kubectl scale deploy/rustgate --replicas=5
   ```

### Wildcard-policy mismatch

If SUBSCRIBE filters are rejected because the active wildcard policy
forbids them (e.g. operator switched from `permissive` to `strict`):

1. Reconcile the operator-set policy with the documented client
   contract. The MQTT wildcard policy is documented in
   `docs/configuration.md` under the `--mqtt-*` flags.

2. If the policy needs to be loosened, restart with a more permissive
   value — the wildcard policy is **read once at startup**, like the
   CRL:
   ```bash
   kubectl set env deploy/rustgate \
     RUSTGATE_MQTT_WILDCARD_POLICY=permissive
   kubectl rollout restart deploy/rustgate
   ```

### Retain store leaking

If `rustgate_mqtt_retain_stored_total` is climbing without a
corresponding `rustgate_mqtt_retain_cleared_total`, retained
messages are accumulating with no client clearing them:

1. Identify the producer set publishing with `retain=1` via the
   audit trail and operator dashboards.

2. Have the producer push a zero-byte payload to clear the retain
   slot on the affected topics, or accept the store growth as
   expected for the workload.

3. Restart the broker to drop the in-memory retain store if the
   accumulation has gone unbounded — note this drops all retained
   messages and clients with `retain=1` subscriptions will see no
   replay until producers re-publish:
   ```bash
   kubectl rollout restart deploy/rustgate
   ```

### Keep-alive storm

If a fleet event caused mass ungraceful disconnects and
`will_published_total` spiked:

1. Verify the wills routed correctly — they go through the same
   `route_for_egress` path as ordinary PUBLISH packets, including
   ACL + authz + obligations. A misconfigured authz policy can
   silently swallow all the wills.

2. Wait for clients to reconnect on their own backoff schedule.
   Don't restart the broker mid-storm — clients will all retry
   immediately and create a second storm.

3. If the storm originated from a single tenant exceeding their
   throughput quota, you'll see corresponding
   `quota.tenant_throughput_exceeded` audit events.

## Prevention

- Alert on `rate(rustgate_mqtt_will_published_total[5m]) > 5`. A
  sustained high will rate is the operational signal for a
  partition or keep-alive misconfiguration.
- Alert on the connection-vs-session gap:
  `rate(rustgate_mqtt_connections_total[5m]) > 0
  and rustgate_mqtt_active_sessions <
  rate(rustgate_mqtt_connections_total[5m]) * 60 * 0.8`.
  A gap means CONNECTs are succeeding but sessions are dying right
  after.
- Enforce **strict** MQTT wildcard policy in production unless a
  specific use case requires `permissive`. Mixed-wildcard subscribes
  hide topic-design mistakes.
- Document the cert-to-group mapping table for the MQTT topic
  prefix configuration so operators can answer "why did this
  subscribe fail?" without source-diving.
- Keep the per-client KEEPALIVE between 15 s and 60 s for tactical
  workloads. Long keep-alives create long invisibility windows when
  the network partitions.
- Don't enable QoS 2 — it's intentionally not implemented and a
  client that requests it will see filter-level rejections that
  look like authorisation problems but aren't.
