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

## Dynamic peer discovery troubleshooting

When `--federation-peer-discovery` is set (`dns-sd`, `consul`, or
`etcd`), the peer list is reconciled on a fixed interval
(`--federation-peer-discovery-interval`, default 30 s) from an external
source. If peers that should be in the mesh are missing or peers that
were removed upstream are still present, work through the checks below
before falling back to `--federation-peers-file`.

1. **Confirm the reconciler is running.** On startup the server logs
   `federation peer discovery reconciler started` with the backend and
   interval. If you don't see that line, the flag was not passed, a
   required sub-feature was not compiled in (the startup error names
   the missing feature), or federation itself is disabled.
2. **Watch the reconciler's view of the backend.** `swap_peers` logs
   each reconcile pass with the added/removed/unchanged counts via the
   structured audit event `component=federation_peers,
   event_type=config.reload`. If the counts are flat while you know the
   registry changed, the backend is either unreachable or returning an
   empty list.
3. **Backend-specific checks:**
   - **DNS-SD:** multicast between nodes is a hard requirement. On
     Kubernetes this usually means a host-network pod or a CNI that
     proxies mDNS; on a laptop cluster, verify `avahi-browse -rt
     _rustgate._tcp` sees the expected peers. Overlay networks
     typically drop multicast — prefer Consul or etcd there.
   - **Consul:** from inside the pod, curl
     `$RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_ADDR/v1/catalog/service/$RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_SERVICE`
     and confirm it returns the service instances you expect. A 200
     with an empty JSON array means the service name is wrong or no
     instance has registered yet. HTTP 5xx or timeouts are surfaced by
     the reconciler as warning logs and leave the previous peer set in
     place.
   - **etcd:** run `etcdctl --endpoints <comma-separated> get --prefix
     $RUSTGATE_FEDERATION_PEER_DISCOVERY_ETCD_PREFIX` from a pod with
     the etcd client installed, and verify each key resolves to either
     a `host:port` string or a valid serialized `PeerConfig` JSON.
     Keys that fail to decode are skipped with a warning per key.
4. **Mutual exclusion with the file reloader.** `--federation-peer-discovery`
   and `--federation-peers-file` are mutually exclusive at the CLI
   level — clap rejects both being set. If you need to migrate between
   them, restart the server with the new flag only.
5. **Fallback.** If the backend is flapping, switch to
   `--federation-peers-file` for the duration of the incident. The file
   reloader handles the same `swap_peers` path so behavior after
   failover is identical.
