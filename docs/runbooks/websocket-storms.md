# Runbook: WebSocket Connection Storms

## Symptoms

- Sudden spike in CPU usage
- `rustgate_sessions_active` metric increases rapidly
- Logs show many simultaneous WebSocket handshake attempts
- TLS handshake latency increases for all clients
- Existing clients experience degraded message delivery latency

## Detection

1. Monitor the connection rate:
   ```bash
   # Watch active sessions over time
   watch -n 5 'curl -s http://localhost:9090/metrics | grep rustgate_sessions_active'
   ```

2. Check for connection rejections:
   ```bash
   curl -s http://localhost:9090/metrics | grep connections_rejected
   ```

3. Look for rapid WebSocket connection/disconnection patterns:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=500 | grep -i "websocket.*connect" | tail -50
   ```

## Diagnosis

1. Determine the source of the storm:
   ```bash
   # Check if connections come from a small number of IPs
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=1000 | grep "new connection" | \
     awk '{print $NF}' | sort | uniq -c | sort -rn | head -20
   ```

2. Check if the storm is caused by client reconnection loops (a downstream issue causing clients to disconnect and immediately retry):
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=500 | grep -i "disconnect\|close" | tail -20
   ```

3. Verify current resource usage:
   ```bash
   kubectl top pod -l app.kubernetes.io/name=rustgate
   ```

## Resolution

### Immediate: Limit Handshake Concurrency

The `--max-concurrent-handshakes` (default 100) limits the CPU cost of concurrent TLS handshakes. If a storm is overwhelming the server:

1. Reduce handshake concurrency to limit CPU impact:
   ```bash
   # Update the deployment (or Helm values)
   kubectl set env deploy/rustgate RUSTGATE_MAX_HANDSHAKES=25
   ```

2. This queues excess handshakes instead of processing them all simultaneously, protecting existing connections.

### Immediate: Reduce Max Connections

If the server is at risk of OOM from too many connections:

1. Lower `--max-connections` to a safe threshold:
   ```bash
   kubectl set env deploy/rustgate RUSTGATE_MAX_CONNECTIONS=512
   ```

2. New connections beyond this limit are rejected immediately.

### Enable WebSocket Rate Limiting

Configure per-connection rate limits to prevent abusive clients from consuming excessive resources after connecting:

```bash
kubectl set env deploy/rustgate \
  RUSTGATE_WS_MAX_FRAMES_PER_SEC=100 \
  RUSTGATE_WS_MAX_BYTES_PER_SEC=1048576 \
  RUSTGATE_WS_MAX_VIOLATIONS=10
```

This disconnects clients that sustain excessive frame or byte rates, freeing resources for legitimate clients.

### Enable Per-Client Message Rate Limiting

Limit the message throughput per connected client:

```bash
kubectl set env deploy/rustgate \
  RUSTGATE_CLIENT_MSG_RATE=10 \
  RUSTGATE_CLIENT_BURST=50
```

### Scale Horizontally

If the storm represents legitimate reconnection traffic (e.g., after a network partition heals):

1. Scale up replicas:
   ```bash
   kubectl scale deploy/rustgate --replicas=5
   ```

2. If HPA is configured, it will scale automatically based on CPU/memory thresholds.

3. Ensure NATS is configured for cross-instance message delivery.

### Block Abusive Sources

If the storm originates from a small number of sources:

1. Use Kubernetes NetworkPolicy to block specific source IPs or CIDR ranges.
2. If behind a load balancer, apply rate limiting at the load balancer level.

## Prevention

- Always configure `--max-concurrent-handshakes` below `--max-connections` to ensure handshake CPU does not overwhelm the server.
- Enable WebSocket rate limiting (`--ws-max-frames-per-sec`, `--ws-max-bytes-per-sec`) in production.
- Configure HPA with CPU-based scaling to absorb traffic spikes:
  ```yaml
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
    targetCPUUtilizationPercentage: 60
  ```
- Use the production Helm values (`values-production.yaml`) as a base, which sets 3 minimum replicas and topology spread constraints.
- Set up alerts on `rustgate_sessions_active` rate of change to detect storms early.
- Deploy a NetworkPolicy to restrict ingress to known client CIDR ranges where possible.
