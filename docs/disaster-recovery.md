# Disaster Recovery Procedures

This document covers recovery procedures for rustgate subsystem failures, including RTO/RPO expectations and step-by-step instructions for common disaster scenarios.

## RTO/RPO by Subsystem

| Subsystem | RTO (Recovery Time) | RPO (Recovery Point) | Notes |
|-----------|--------------------|-----------------------|-------|
| Client transport (TLS) | Pod restart time (~30s) | Zero (stateless) | Clients reconnect automatically |
| Federation peers | Automatic (circuit breaker timeout, default 60s) | Replay buffer depth (default 1000 messages) | Replay buffer provides catch-up on reconnection |
| NATS bridge | Automatic (library reconnect) | Pending publishes lost (fire-and-forget) | JetStream provides at-least-once for subscriptions |
| Certificate enrollment | Pod restart time (~30s) | Zero (stateless, CA key on disk/Secret) | Enrollment is stateless; fix config and restart |
| Position cache | Automatic (rebuilt from traffic) | Ephemeral (no persistence by default) | JetStream replay bootstraps on restart if configured |
| WebSocket transport | Pod restart time (~30s) | Zero (stateless) | WebSocket clients reconnect automatically |
| Metrics/health | Pod restart time (~30s) | Zero (stateless) | Monitoring gap during restart |

**Key principle:** rustgate is designed to be stateless at the application layer. Persistent state (certificates, peer config, JetStream checkpoints) lives on the filesystem or in external systems (NATS, Kubernetes Secrets). Recovery is primarily about restoring configuration and restarting.

## Certificate Disaster Recovery

### CA Key Loss

**Impact:** Cannot issue new client certificates via enrollment. Existing certificates remain valid until expiry.

**Prevention:**
- Back up the CA private key (`--ca-key`) to an offline, encrypted store (HSM, Vault, air-gapped backup).
- Use separate CA keys for different security domains.
- Store CA certificate backups in at least two geographically separate locations.

**Recovery:**
1. If a backup exists, restore the CA key file and restart the enrollment server.
2. If no backup exists:
   - Generate a new CA key and certificate.
   - Re-issue all client certificates signed by the new CA.
   - Update `--ca` on all rustgate instances to trust the new CA.
   - Distribute new certificates to all clients.
   - This is a **full re-enrollment** scenario. Plan for the time required based on client count.

### Trust Store Corruption

**Impact:** Federation peers cannot authenticate. New TLS handshakes fail.

**Prevention:**
- Back up the `--federation-trust-store-dir` contents regularly.
- Use the REST API to document which CAs are trusted: `curl http://localhost:9090/api/federation/certificates`.

**Recovery:**
1. Re-upload trusted CA certificates via the REST API:
   ```bash
   for cert in /backup/federation-cas/*.pem; do
     curl -X POST http://localhost:9090/api/federation/certificates \
       -H "Content-Type: application/x-pem-file" \
       --data-binary @"$cert"
   done
   ```
2. New CAs take effect on the next TLS handshake without restart.

### CRL File Loss

**Impact:** Revoked certificates are no longer rejected. Previously revoked clients can reconnect.

**Prevention:**
- Back up the CRL file alongside the CA certificate.
- Automate CRL generation and distribution (see the [CRL Updates runbook](runbooks/crl-updates.md)).

**Recovery:**
1. Regenerate the CRL from your CA's revocation database.
2. Replace the `--crl` file.
3. Restart rustgate to load the new CRL.

## Federation State Recovery

### Peer Reconnection

Federation peer connections recover automatically. When a peer goes down and comes back:

1. The circuit breaker detects the failure after `--federation-circuit-breaker-threshold` (default 5) consecutive failures.
2. After `--federation-circuit-breaker-timeout` (default 60 seconds), a probe is sent.
3. If the probe succeeds, the circuit closes and the replay buffer is drained (sending up to `--federation-replay-buffer-size` missed messages).
4. Normal message forwarding resumes.

**No manual intervention is required** for transient peer failures.

### Permanent Peer Loss

If a federation peer is permanently decommissioned:

1. Disable the peer via REST API: `curl -X PUT http://localhost:9090/api/federation/federates/<peer-id>/disable`.
2. Optionally remove the peer: `curl -X DELETE http://localhost:9090/api/federation/federates/<peer-id>`.
3. Update the peers JSON file (`--federation-peers-file`) to remove the entry for persistence across restarts.
4. Remove the peer's CA certificate from the trust store if it is no longer needed.

### Peer Configuration Recovery

If the peers JSON file is lost:

1. Query the current peer state from the REST API (if the server is still running):
   ```bash
   curl http://localhost:9090/api/federation/federates > peers-backup.json
   ```
2. If the server is not running, reconstruct the peers file from your infrastructure documentation or partner agreements.
3. Restore the file to the path configured in `--federation-peers-file` and restart.

### Federation HA Recovery

In multi-pod deployments using HA mode (`--federation-ha-nats-url`):

- Peer ownership claims are stored in NATS KV with a 30-second TTL.
- If a pod dies, its claims expire within 30 seconds.
- Surviving pods automatically adopt orphaned peers after a jitter delay (0-5 seconds) plus a 30-second settling period.
- **No manual intervention is required** for single-pod failures.

If NATS itself is lost, all HA coordination stops. Recovery:
1. Restore NATS service.
2. Pods will re-establish KV buckets (`federation-claims`, `federation-connections`, `federation-peers`) automatically.
3. Peer ownership will be renegotiated within 30-60 seconds.

> **HA depends on NATS today.** Multi-pod HA coordination has a hard NATS
> dependency — there is no NATS-free clustering path yet. The direction for a
> restart-safe, NATS-optional HA story (durable-store-backed ownership
> leases) is recorded in
> [ADR 0031](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0031-production-hardening-ha-and-edge.md); native leaderless
> clustering is deferred to a follow-up issue. Until it lands, keep NATS
> highly available if you rely on multi-pod HA.

## NATS JetStream Recovery

### Checkpoint Recovery

When `--nats-checkpoint-path` is configured, the server persists the last processed JetStream sequence number. On restart, replay resumes from the checkpoint.

**If the checkpoint file is lost:**
- The server replays the entire JetStream history on the next restart.
- This is safe but may cause temporary increased load and duplicate message delivery.
- To skip replay entirely, create an empty checkpoint file or set the sequence number to the stream's current last sequence.

**To manually set the checkpoint:**
```bash
# Find the current stream last sequence
kubectl exec deploy/nats -- nats stream info RUSTGATE --json | jq '.state.last_seq'

# Write that sequence number to the checkpoint file (plain text, not JSON)
echo '12345' > /data/nats-checkpoint
```

### JetStream Stream Loss

If the NATS JetStream stream is deleted or corrupted:

1. Recreate the stream:
   ```bash
   nats stream add RUSTGATE --subjects='rustgate.>' --retention=limits --max-msgs=100000
   ```
2. Restart rustgate pods (or wait for auto-reconnect).
3. Position cache data and message history from before the stream loss are not recoverable.
4. New messages will flow immediately once the stream is recreated.

## Position Cache Recovery

The position cache is **ephemeral by default**. On restart, it starts empty and rebuilds from incoming traffic.

**With JetStream replay:** If `--nats-url` is configured and a JetStream history stream exists, the position cache is bootstrapped from the stream on startup. The `--nats-checkpoint-path` controls where replay resumes from.

**Without JetStream:** The cache starts empty. Clients will see stale or missing positions until new updates arrive (typically seconds to minutes depending on update frequency).

**Cache overflow:** The position cache evicts the oldest entry (by `received_at` timestamp) when it reaches capacity (default 100,000 entries). This is automatic and requires no intervention.

## Kubernetes Pod Recovery

### Single Pod Failure

Kubernetes automatically restarts failed pods. The Helm chart configures:

| Probe | Path | Behavior |
|-------|------|----------|
| Startup | `/health/startup` | 30 retries, 2s apart. Pod is killed if startup takes > 60s. |
| Liveness | `/health/live` | Pod is restarted if unresponsive. |
| Readiness | `/health/ready` | Pod is removed from Service during shutdown/drain. |

**Recovery is automatic.** The pod restarts, loads certificates from the mounted Secret, re-establishes NATS and federation connections, and becomes ready.

### Multiple Pod Failure

If multiple pods fail simultaneously:

1. Kubernetes reschedules pods based on the Deployment's `replicas` or HPA settings.
2. Pod Disruption Budgets (PDBs) in production values prevent voluntary disruptions from draining too many pods at once.
3. Topology spread constraints distribute pods across nodes to minimize blast radius.

**Production Helm values (`values-production.yaml`):**
```yaml
replicaCount: 3
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
```

### Node Failure

1. Pods on the failed node are rescheduled to healthy nodes (subject to resource availability).
2. Federation HA claims for pods on the failed node expire after 30 seconds, and surviving pods adopt the orphaned peers.
3. Ensure your cluster has sufficient spare capacity to absorb a node failure.

### Full Cluster Recovery

For a complete cluster recovery from backup:

1. Restore the Kubernetes cluster and core services (DNS, CNI, storage).
2. Restore NATS (if running in-cluster) or verify external NATS connectivity.
3. Restore Kubernetes Secrets containing TLS certificates:
   ```bash
   kubectl create secret generic rustgate-tls \
     --from-file=server.crt --from-file=server.key --from-file=ca.crt
   ```
4. Deploy rustgate via Helm:
   ```bash
   helm install rustgate helm/ -f values-production.yaml -f my-values.yaml
   ```
5. Verify health:
   ```bash
   kubectl rollout status deploy/rustgate
   curl http://<metrics-endpoint>:9090/health/live
   ```
6. Re-upload federation trust store certificates if not persisted on a PVC.
7. Verify federation peer connectivity:
   ```bash
   curl http://<metrics-endpoint>:9090/api/federation/connections
   ```

## Enrollment Service Recovery

The enrollment service is stateless. It reads the CA key and certificate at startup and signs CSRs on demand.

**Recovery:**
1. Ensure the CA key file (`--ca-key`) and CA certificate (`--ca`) are available.
2. Ensure the enrollment credentials (`--enrollment-user`, `--enrollment-password`) are configured.
3. Restart rustgate with `--enrollment-bind` set.

**If the CA key is lost:** See the CA Key Loss section above.

## Disaster Recovery Checklist

Use this checklist to verify disaster recovery readiness:

- [ ] CA private key is backed up offline (HSM, Vault, encrypted storage)
- [ ] CA certificate is stored in at least two locations
- [ ] CRL generation process is documented and tested
- [ ] Federation peers JSON file is version-controlled or backed up
- [ ] Federation trust store CA certificates are documented
- [ ] NATS JetStream checkpoint path is on a persistent volume
- [ ] Kubernetes Secrets are backed up or managed by External Secrets Operator
- [ ] Helm values files are version-controlled
- [ ] Pod Disruption Budgets are configured for production
- [ ] Topology spread constraints distribute pods across failure domains
- [ ] Recovery procedures have been tested in a staging environment
- [ ] Monitoring and alerting are configured for all subsystems
