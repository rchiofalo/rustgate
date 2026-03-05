# Runbook: Federation Peer Stuck Reconnecting

## Symptoms

- Logs show repeated `federation reconnect attempt` messages for a specific peer
- Peer connection count is lower than expected in `/metrics`
- Messages are not being forwarded to the affected peer

## Diagnosis

1. Check the federation metrics endpoint:
   ```bash
   curl -s http://localhost:9090/metrics | grep federation
   ```

2. Look for reconnect errors in logs:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=100 | grep -i reconnect
   ```

3. Verify the peer is reachable:
   ```bash
   kubectl exec -it deploy/rustgate -- wget --spider -q https://<peer-address>:9000
   ```

## Resolution

1. **TLS certificate expired**: Check peer certificate validity. Regenerate and restart.
2. **Network partition**: Verify network policies allow traffic on port 9000 between namespaces.
3. **Peer is down**: Check the remote peer's pod status and logs.
4. **DNS resolution failure**: Verify the peer address resolves correctly from inside the pod.
5. **Max connections reached**: Check `rustgate_federation_connections` gauge against `--max-connections`.

## Prevention

- Set up alerts on `rustgate_federation_reconnects_total` rate.
- Use NATS HA mode for multi-replica deployments to avoid peer ownership conflicts.
