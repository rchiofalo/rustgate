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

## Prevention

- Deploy NATS in cluster mode (3+ replicas) for HA.
- Monitor NATS connection health via `nats server check`.
- Set up alerts on `rustgate_federation_errors_total` rate.
