# Runbook: NATS Bridge Failure

## Symptoms

- Messages not delivered across rustgate instances
- Logs show `nats connection lost` or `nats subscription error`
- `rustgate_federation_errors_total` counter increasing

## Diagnosis

1. Verify NATS server is healthy:
   ```bash
   kubectl exec -it deploy/nats -- nats server check connection
   ```

2. Check NATS JetStream status:
   ```bash
   kubectl exec -it deploy/nats -- nats stream ls
   ```

3. Look for NATS errors in rustgate logs:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=200 | grep -i nats
   ```

4. Verify credentials are valid:
   ```bash
   kubectl get secret <nats-secret> -o jsonpath='{.data.RUSTGATE_NATS_CREDENTIALS}' | base64 -d
   ```

## Resolution

1. **NATS server down**: Restart the NATS pod. Check NATS cluster health.
2. **JetStream stream missing**: Recreate the stream:
   ```bash
   nats stream add RUSTGATE --subjects='rustgate.>' --retention=limits --max-msgs=100000
   ```
3. **Credential rotation**: Update the K8s Secret and restart rustgate pods.
4. **Network policy blocking**: Ensure egress to NATS port 4222 is allowed.

## Consumer lag and redelivery

When `--features metrics,nats` is enabled, the pull-consumer subscriber
exports three gauges sampled every five seconds from `consumer.info()`:

- `rustgate_nats_consumer_pending` — `num_pending`. A value that grows
  unboundedly while the instance is up means messages are arriving in the
  stream faster than this consumer drains them. Investigate slow
  downstream sessions or undersized `--nats-max-ack-pending`.
- `rustgate_nats_consumer_num_redelivered` — `num_redelivered`. A
  non-zero, sustained value indicates messages are being NAK'd or
  hitting their `max_ack_pending` deadline. Look for routing errors in
  the subscriber loop.
- `rustgate_nats_consumer_ack_floor_stream_seq` — `ack_floor.stream_seq`.
  Should advance roughly in step with the stream's last sequence. If it
  flatlines while `pending` grows, the consumer is stuck — restart the
  affected pod and check downstream sessions.

Suggested alerts:

- `rate(rustgate_nats_consumer_pending[5m]) > 0` for 10m
- `rustgate_nats_consumer_num_redelivered > 0` for 5m
- `increase(rustgate_nats_consumer_ack_floor_stream_seq[5m]) == 0` while
  `rustgate_nats_consumer_pending > 0`

## Prevention

- Deploy NATS in cluster mode (3+ replicas) for HA.
- Monitor NATS connection health via `nats server check`.
- Set up alerts on `rustgate_federation_errors_total` rate.
- Alert on the JetStream consumer lag gauges above.
