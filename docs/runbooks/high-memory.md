# Runbook: High Memory Usage

## Symptoms

- Pod memory usage approaching limits (visible in Prometheus/Grafana)
- OOMKilled events in `kubectl describe pod`
- Degraded message throughput

## Diagnosis

1. Check current memory usage:
   ```bash
   kubectl top pod -l app.kubernetes.io/name=rustgate
   ```

2. Check connection count (each connection holds buffers):
   ```bash
   curl -s http://localhost:9090/metrics | grep connections
   ```

3. Check for message backpressure:
   ```bash
   curl -s http://localhost:9090/metrics | grep messages_dropped
   ```

## Resolution

1. **Too many connections**: Reduce `--max-connections` or scale horizontally.
2. **Message flood**: Check upstream clients for runaway senders. Enable rate limiting.
3. **Memory limits too low**: Increase `resources.limits.memory` in Helm values.
   Production recommendation: 2Gi minimum for high-throughput deployments.
4. **Federation message amplification**: Check `--federation-max-hops` is set low enough.
   Messages with too many hops consume memory in transit.

## Prevention

- Use `values-production.yaml` as a base (2Gi memory limit).
- Set up alerts on container memory usage at 80% of limit.
- Monitor `rustgate_federation_messages_dropped_total` for backpressure signals.
