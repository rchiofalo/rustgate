# Troubleshooting Guide

This guide covers common operational issues, organized by subsystem. Each entry follows a **Symptom, Likely Cause, Diagnosis, Resolution** structure.

## Certificate Validation Failures

### Expired Server or Client Certificate

**Symptom:** Clients fail to connect. Logs show `tls handshake failed: certificate has expired` or `certificate is not yet valid`.

**Likely Cause:** The server certificate (`--cert`) or a connecting client's certificate has expired.

**Diagnosis:**

```bash
# Check server certificate validity
openssl x509 -in /path/to/server.pem -noout -dates

# Check a client certificate
openssl x509 -in /path/to/client.pem -noout -dates

# In Kubernetes, inspect the mounted cert
kubectl exec deploy/rustgate -- openssl x509 -in /certs/server.crt -noout -dates
```

**Resolution:**
1. Regenerate or renew the expired certificate.
2. If using `--cert-reload-interval`, replace the cert files atomically (`mv` new file into place) and the server will pick up the change on the next poll cycle.
3. If cert hot-reload is not enabled, restart the server after replacing certificates.

---

### Untrusted CA

**Symptom:** Clients receive `certificate unknown` during the TLS handshake.

**Likely Cause:** The client certificate is not signed by the CA specified in `--ca`.

**Diagnosis:**

```bash
# Verify client cert against the server's CA
openssl verify -CAfile ca.pem client.pem

# If using a certificate chain, concatenate intermediates
openssl verify -CAfile <(cat intermediate.pem root.pem) client.pem
```

**Resolution:**
1. Ensure the client certificate is signed by the CA (or a chain rooted at the CA) configured with `--ca`.
2. If the CA was recently rotated, update `--ca` to include the new CA certificate and restart.
3. For federation peers, upload the remote CA via the trust store REST API: `curl -X POST http://localhost:9090/api/federation/certificates -H "Content-Type: application/x-pem-file" --data-binary @remote-ca.pem`.

---

### CRL Revocation

**Symptom:** A specific client cannot connect, but other clients using certificates from the same CA connect successfully. Logs show the connection being rejected during the TLS handshake.

**Likely Cause:** The client's certificate serial number appears in the CRL loaded via `--crl`.

**Diagnosis:**

```bash
# View the CRL contents
openssl crl -in crl.pem -text -noout

# Check if a specific certificate is revoked
openssl crl -in crl.pem -text -noout | grep -A1 $(openssl x509 -in client.pem -noout -serial | cut -d= -f2)
```

**Resolution:**
1. If the revocation is intentional, no action needed. The CRL is working correctly.
2. If the revocation was accidental, issue a new CRL without the serial number and replace the `--crl` file.
3. Restart the server to load the updated CRL (CRL files are read at startup).

---

### CN Mismatch in Federation

**Symptom:** Federation peer connections fail with TLS errors. Logs show `federation peer handshake failed`.

**Likely Cause:** The peer's certificate CN does not match the expected value in `trust_cert_cn` in the peers JSON config.

**Diagnosis:**

```bash
# Check the remote peer's certificate CN
openssl s_client -connect <peer-host>:9000 </dev/null 2>/dev/null | openssl x509 -noout -subject

# Compare with your peers.json config
cat peers.json | grep trust_cert_cn
```

**Resolution:**
1. Update `trust_cert_cn` in the peers JSON to match the actual certificate CN.
2. As a temporary workaround, set `--federation-skip-hostname-verify` (not recommended for production).
3. Reload the peer configuration via the REST API: `curl -X POST http://localhost:9090/api/federation/federates -H "Content-Type: application/json" -d '<updated peer config>'`.

## Federation Reconnection Loops

### Wrong Peer Address

**Symptom:** Logs show repeated `federation reconnect attempt` messages for a specific peer. The `rustgate_federation_errors_total` counter increases steadily.

**Likely Cause:** The peer address in `peers.json` is incorrect or the remote peer is not listening on that address.

**Diagnosis:**

```bash
# Test network connectivity to the peer
nc -zv <peer-host> 9000

# Check federation metrics
curl -s http://localhost:9090/metrics | grep federation

# Review peer configuration
curl http://localhost:9090/api/federation/federates
```

**Resolution:**
1. Correct the peer address in `peers.json` or update via the REST API.
2. Verify the remote peer is running and listening on the expected port.
3. Check for network policies or firewalls blocking the connection.

---

### Certificate Mismatch Between Peers

**Symptom:** Reconnection attempts happen every 30 seconds to 5 minutes (exponential backoff pattern). Logs contain TLS handshake errors.

**Likely Cause:** The peers do not trust each other's CA certificates.

**Diagnosis:**

```bash
# Check federation-specific logs
kubectl logs -l app.kubernetes.io/name=rustgate --tail=200 | grep -i "federation\|tls\|handshake"

# Verify trusted CAs on this side
curl http://localhost:9090/api/federation/certificates

# Test TLS connectivity manually
openssl s_client -cert client.pem -key client-key.pem -CAfile remote-ca.pem -connect <peer-host>:9000
```

**Resolution:**
1. Upload the remote peer's CA certificate to the trust store: `curl -X POST http://localhost:9090/api/federation/certificates -H "Content-Type: application/x-pem-file" --data-binary @remote-ca.pem`.
2. Ensure the remote side also trusts your CA certificate.
3. New CAs take effect on the next TLS handshake without restart.

---

### Heartbeat Timeout

**Symptom:** Federation peers connect successfully but disconnect after approximately 90 seconds (V1) or 15 seconds (V2). The cycle repeats.

**Likely Cause:** Heartbeat messages are not reaching the remote peer due to a network issue, NAT timeout, or firewall dropping idle connections.

**Diagnosis:**

```bash
# Check for heartbeat-related logs
kubectl logs -l app.kubernetes.io/name=rustgate --tail=200 | grep -i heartbeat

# Monitor federation heartbeat metrics
curl -s http://localhost:9090/metrics | grep heartbeat

# Check for firewalls or NAT timeouts on the path
traceroute <peer-host>
```

**Resolution:**
1. Ensure firewalls allow bidirectional traffic on the federation port (default 9000 for V1, 9001 for V2).
2. If behind a NAT, configure TCP keepalive at the OS level to prevent idle connection reaping (see the Performance Tuning guide).
3. Verify both sides are running compatible protocol versions (`protocol_version` in peers JSON).
4. Check system clock skew between the servers.

## Enrollment Auth Failures

### Bad Credentials

**Symptom:** Enrollment clients receive HTTP 401 Unauthorized.

**Likely Cause:** The username or password provided by the client does not match `--enrollment-user` / `--enrollment-password`.

**Diagnosis:**

```bash
# Verify the configured credentials (careful with secrets in production)
kubectl get deploy rustgate -o yaml | grep -A2 ENROLLMENT

# Test enrollment endpoint manually
curl -v -u admin:password https://localhost:8446/Marti/api/tls/config
```

**Resolution:**
1. Verify the enrollment credentials in your deployment config.
2. Ensure the client is sending HTTP Basic Auth (not Bearer or another scheme).
3. In Kubernetes, check that the Secret referenced by `enrollment.existingSecret` contains the correct keys (`RUSTGATE_ENROLLMENT_USER`, `RUSTGATE_ENROLLMENT_PASSWORD`).

---

### Expired or Malformed CSR

**Symptom:** Enrollment returns HTTP 400 Bad Request or an error about CSR parsing.

**Likely Cause:** The client submitted a malformed PKCS#10 CSR.

**Diagnosis:**

```bash
# Check enrollment logs
kubectl logs -l app.kubernetes.io/name=rustgate --tail=100 | grep -i enrollment
```

**Resolution:**
1. Regenerate the CSR on the client side.
2. Verify the CSR is valid: `openssl req -in client.csr -noout -text`.
3. Ensure the CSR uses a supported key type (RSA 2048+ or ECDSA P-256/P-384).

## WebSocket Upgrade Failures

### Protocol Mismatch

**Symptom:** WebSocket clients fail to connect. Browser console or client logs show `WebSocket connection failed` or `unexpected response code`.

**Likely Cause:** The client is connecting to the wrong port (e.g., the TLS port instead of the WebSocket port), or the server was not built with the `websocket` feature.

**Diagnosis:**

```bash
# Verify WebSocket listener is running
curl -s http://localhost:9090/metrics | grep websocket

# Check that the websocket feature is enabled
kubectl logs -l app.kubernetes.io/name=rustgate --tail=20 | grep -i websocket
```

**Resolution:**
1. Ensure clients connect to the WebSocket bind address (default port 8443, configured via `--websocket-bind`).
2. Verify the server binary was compiled with `--features websocket`.
3. WebSocket connections require `wss://` (TLS) and a valid client certificate (mTLS).

---

### TLS Handshake Failure on WebSocket

**Symptom:** WebSocket connections fail during the TLS handshake before the HTTP upgrade.

**Likely Cause:** Same TLS certificate requirements apply as for regular mTLS connections. The client certificate may be expired, untrusted, or missing.

**Diagnosis:** Follow the same steps as the Certificate Validation Failures section above. WebSocket connections use the same CA, cert, and CRL configuration as the primary TLS listener.

**Resolution:** Ensure the WebSocket client presents a valid certificate signed by the configured CA.

---

### WebSocket Rate Limiting Disconnects

**Symptom:** WebSocket clients are disconnected after sending high volumes of messages. Logs show `rate limit exceeded` with frame or byte counts.

**Likely Cause:** The client exceeds `--ws-max-frames-per-sec` or `--ws-max-bytes-per-sec` limits. After `--ws-max-violations` (default 10) consecutive violations, the connection is terminated.

**Diagnosis:**

```bash
# Check for rate-limit logs
kubectl logs -l app.kubernetes.io/name=rustgate --tail=200 | grep -i "rate limit"
```

**Resolution:**
1. Increase rate limits if the traffic is legitimate: `--ws-max-frames-per-sec` and `--ws-max-bytes-per-sec`.
2. Increase the violation tolerance: `--ws-max-violations`.
3. Set limits to 0 to disable rate limiting entirely (not recommended for production).

## NATS Connectivity Issues

### Connection Refused

**Symptom:** Logs show `nats connection lost` or `connection refused` immediately after startup.

**Likely Cause:** The NATS server at `--nats-url` is not running or not reachable.

**Diagnosis:**

```bash
# Test NATS connectivity
nc -zv <nats-host> 4222

# In Kubernetes, check NATS pod status
kubectl get pods -l app.kubernetes.io/name=nats

# Verify the NATS URL in the deployment
kubectl get deploy rustgate -o yaml | grep NATS_URL
```

**Resolution:**
1. Ensure the NATS server is running and healthy.
2. Verify the URL in `--nats-url` or `RUSTGATE_NATS_URL`.
3. Check network policies allow egress to the NATS port (4222).

---

### NATS Auth Failures

**Symptom:** NATS connection drops immediately after connecting. Logs show authorization errors.

**Likely Cause:** Credential file referenced by `--nats-credentials` is missing, expired, or invalid.

**Diagnosis:**

```bash
# Verify the credentials file exists and is readable
kubectl exec deploy/rustgate -- ls -la /path/to/nats.creds

# Check NATS server logs for auth rejections
kubectl logs -l app.kubernetes.io/name=nats --tail=100 | grep -i auth
```

**Resolution:**
1. Regenerate NATS credentials and update the Kubernetes Secret.
2. If using NATS mTLS (`--nats-tls-cert`, `--nats-tls-key`, `--nats-tls-ca`), verify the certificates are valid and the NATS server trusts the client CA.

---

### Slow Consumer Warnings

**Symptom:** NATS logs show `slow consumer` warnings. Some messages are dropped.

**Likely Cause:** rustgate is not consuming messages from NATS fast enough, typically under high message throughput.

**Diagnosis:**

```bash
# Check NATS stream status
kubectl exec deploy/nats -- nats stream info RUSTGATE

# Check for consumer lag
kubectl exec deploy/nats -- nats consumer info RUSTGATE <consumer-name>
```

**Resolution:**
1. Scale horizontally (more rustgate replicas) to distribute the message load.
2. Check if message processing is bottlenecked by a slow federation peer (look for circuit breaker trips).
3. Ensure adequate CPU and memory resources for the rustgate pods.

## Message Routing Issues

### Group Membership Mismatch

**Symptom:** Messages from certain clients are not delivered to expected recipients.

**Likely Cause:** The sender and receiver are not in the same group. Group membership is determined by the OU fields in the client certificate.

**Diagnosis:**

```bash
# Check the sender's certificate groups
openssl x509 -in sender.pem -noout -subject
# subject=CN = ALPHA-1, OU = Team-Alpha

# Check the receiver's certificate groups
openssl x509 -in receiver.pem -noout -subject
# subject=CN = BRAVO-1, OU = Team-Bravo
```

**Resolution:**
1. Issue new certificates with matching OU fields for clients that need to communicate.
2. For federation, verify the peer's `groups` list in the peers JSON includes the relevant groups.
3. Check `routing_mode` on federation peers: `broadcast` forwards all messages, `matrix` only forwards messages matching configured groups.

---

### ACL Denials

**Symptom:** Messages are silently dropped. Logs (at debug level) show ACL denial messages.

**Likely Cause:** The `--group-acl-file` restricts which CNs may send to or receive from specific groups.

**Diagnosis:**

```bash
# Check if ACL file is configured
kubectl get deploy rustgate -o yaml | grep GROUP_ACL

# Review the ACL rules
kubectl exec deploy/rustgate -- cat /path/to/group-acl.json

# Enable debug logging to see ACL decisions
# Set RUST_LOG=debug and look for ACL-related log entries
```

**Resolution:**
1. Update the ACL file to grant the necessary send/receive permissions.
2. Groups not listed in the ACL file operate in open mode (any member can send/receive).

---

### Replay Filter Drops

**Symptom:** Legitimate messages are dropped. The `rustgate_messages_replayed_total` metric increases.

**Likely Cause:** Messages with identical `(uid, time)` pairs are being sent within the replay window (default 300 seconds).

**Diagnosis:**

```bash
# Check the replay metric
curl -s http://localhost:9090/metrics | grep replayed

# Check configured replay window
kubectl get deploy rustgate -o yaml | grep REPLAY_WINDOW
```

**Resolution:**
1. If clients intentionally retransmit, increase the window or disable it: `--replay-window 0`.
2. Ensure clients include unique timestamps on each message.
3. For multi-instance deployments, each instance maintains its own replay filter.

## High CPU / Memory

### High CPU Usage

**Symptom:** CPU usage is consistently elevated. Message latency increases.

**Likely Cause:** High connection count with concurrent TLS handshakes, high message throughput, or message parsing overhead.

**Diagnosis:**

```bash
# Check connection count
curl -s http://localhost:9090/metrics | grep connections

# Check message throughput
curl -s http://localhost:9090/metrics | grep messages

# Check TLS handshake concurrency
curl -s http://localhost:9090/metrics | grep handshake
```

**Resolution:**
1. Reduce `--max-concurrent-handshakes` (default 100) to limit CPU spent on cryptographic operations during connection storms.
2. Enable client rate limiting (`--client-message-rate`) to cap per-client message throughput.
3. Scale horizontally with NATS bridge for message distribution.
4. Enable the `jemalloc` feature for better memory allocator performance which can reduce CPU overhead from allocation.

---

### High Memory Usage

**Symptom:** Pod memory approaching limits. OOMKilled events in Kubernetes.

**Likely Cause:** Too many connections (each holds buffers), message backpressure, or a large position cache.

**Diagnosis:**

```bash
# Check memory usage
kubectl top pod -l app.kubernetes.io/name=rustgate

# Check connection count
curl -s http://localhost:9090/metrics | grep connections

# Check for message backpressure
curl -s http://localhost:9090/metrics | grep messages_dropped
```

**Resolution:**
1. Reduce `--max-connections` or scale horizontally.
2. Check for runaway clients sending excessive messages and enable rate limiting.
3. Increase memory limits in Helm values. Production recommendation: 2Gi minimum.
4. Check `--federation-max-hops` to prevent message amplification in federation mesh topologies.
5. Enable the `jemalloc` feature for reduced memory fragmentation.

## Using Structured Logs for Diagnosis

rustgate uses the `tracing` crate for structured JSON logging. Key fields to filter on:

| Field | Description |
|-------|-------------|
| `peer_id` | Federation peer identifier |
| `cn` | Client certificate Common Name |
| `addr` | Remote address (IP:port) |
| `groups` | Group memberships |
| `error` | Error message |

### Log Level Configuration

Set the `RUST_LOG` environment variable to control log verbosity:

```bash
# Default (info level)
RUST_LOG=info

# Debug for a specific crate
RUST_LOG=info,rustgate_federation=debug

# Trace for TLS debugging
RUST_LOG=info,rustgate_transport=trace

# Debug for all crates
RUST_LOG=debug
```

### Common Log Queries

```bash
# Find all federation errors
kubectl logs -l app.kubernetes.io/name=rustgate | grep '"level":"ERROR"' | grep federation

# Find TLS handshake failures
kubectl logs -l app.kubernetes.io/name=rustgate | grep "handshake failed"

# Find rate-limited clients
kubectl logs -l app.kubernetes.io/name=rustgate | grep "rate limit"

# Find circuit breaker events
kubectl logs -l app.kubernetes.io/name=rustgate | grep "circuit breaker"
```

## Using Metrics for Diagnosis

When the `metrics` feature is enabled (`--metrics-bind`), Prometheus metrics are exposed at `/metrics`. Key metrics for troubleshooting:

| Metric | Type | What It Indicates |
|--------|------|-------------------|
| `rustgate_sessions_active` | gauge | Current connected clients |
| `rustgate_connections_rejected_total` | counter | Clients rejected (limit reached) |
| `rustgate_messages_routed_total` | counter | Messages successfully routed |
| `rustgate_messages_replayed_total` | counter | Messages dropped by replay filter |
| `federation_connections` | gauge | Active federation peer connections |
| `federation_errors_total` | counter | Federation errors (connection, send) |
| `federation_messages_in_total` | counter | Messages received from peers |
| `federation_messages_out_total` | counter | Messages sent to peers |
| `rustgate_federation_circuit_breaker_trips_total` | counter | Circuit breaker activations |

### Health and Readiness Endpoints

```bash
# Liveness check (returns 200 if the server is running)
curl http://localhost:9090/healthz

# Readiness check (returns 200 when ready, 503 during shutdown)
curl http://localhost:9090/readyz
```
