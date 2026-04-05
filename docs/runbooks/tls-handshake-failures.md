# Runbook: TLS Handshake Failures

## Symptoms

- Clients cannot connect to rustgate
- Logs show `tls handshake failed` errors
- `tls_handshake` span durations (via OpenTelemetry) show failures or timeouts
- Connection count is lower than expected despite clients attempting to connect

## Detection

1. Check for handshake errors in logs:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=200 | grep -i "handshake"
   ```

2. Monitor connection metrics:
   ```bash
   curl -s http://localhost:9090/metrics | grep -E "sessions_active|connections_rejected"
   ```

3. If OpenTelemetry is enabled, check `tls_handshake` span errors in your tracing backend (Jaeger, Tempo).

## Diagnosis

### Certificate-Related Failures

1. **"certificate unknown"** — the client's certificate is not signed by the CA in `--ca`:
   ```bash
   # Verify the client cert against the server's CA
   openssl verify -CAfile ca.pem client.pem
   ```

2. **"certificate has expired"** — check expiration dates:
   ```bash
   openssl x509 -in /certs/server.crt -noout -dates
   openssl x509 -in client.pem -noout -dates
   ```

3. **"certificate revoked"** — the client's serial is in the CRL:
   ```bash
   openssl crl -in /certs/crl.pem -text -noout | grep $(openssl x509 -in client.pem -noout -serial | cut -d= -f2)
   ```

4. **Key mismatch** — the server cert and key do not match:
   ```bash
   # These two should produce the same modulus hash
   openssl x509 -in server.crt -noout -modulus | md5sum
   openssl rsa -in server.key -noout -modulus | md5sum
   ```

### Protocol-Related Failures

1. **TLS version mismatch** — the client does not support the minimum TLS version:
   ```bash
   # Check configured minimum version
   kubectl get deploy rustgate -o yaml | grep TLS_MIN_VERSION
   # Default is 1.2
   ```

2. **Cipher suite mismatch** — rare with modern clients, but possible with legacy clients:
   ```bash
   # Test which TLS versions and ciphers the server supports
   openssl s_client -connect localhost:4433 -tls1_2
   openssl s_client -connect localhost:4433 -tls1_3
   ```

3. **ALPN negotiation failure** — for V2 federation (gRPC), the client must support `h2`:
   ```bash
   openssl s_client -connect localhost:9001 -alpn h2
   ```

### Resource-Related Failures

1. **Handshake concurrency exhaustion** — all handshake slots are in use:
   ```bash
   # Check if max handshakes is the bottleneck
   # Increase logging to debug level for transport
   RUST_LOG=info,rustgate_transport=debug
   ```

2. **File descriptor exhaustion** — the process has hit its fd limit:
   ```bash
   # Check current fd usage
   kubectl exec deploy/rustgate -- ls /proc/1/fd | wc -l
   # Check fd limit
   kubectl exec deploy/rustgate -- cat /proc/1/limits | grep "open files"
   ```

3. **Handshake timeout** — the handshake does not complete within the timeout:
   ```bash
   # Test handshake timing manually
   time openssl s_client -cert client.pem -key client-key.pem -CAfile ca.pem -connect localhost:4433
   ```

### Network-Related Failures

1. **Connection reset** — firewall or network device is terminating the connection:
   ```bash
   # Test basic TCP connectivity
   nc -zv <host> 4433

   # Check for MTU issues (large certificates may fragment)
   ping -M do -s 1400 <host>
   ```

2. **Timeout** — the handshake does not complete because packets are dropped:
   ```bash
   # Check for packet loss
   traceroute <host>
   ```

## Resolution

| Cause | Action |
|-------|--------|
| Expired certificate | Renew cert, replace files, restart (or use hot-reload) |
| Untrusted CA | Update `--ca` to include the client's CA, restart |
| Revoked certificate | Remove from CRL if accidental, regenerate CRL, restart |
| Key mismatch | Regenerate cert/key pair ensuring they match |
| TLS version mismatch | Lower `--tls-min-version` to `1.2` or upgrade client |
| Handshake concurrency | Increase `--max-concurrent-handshakes` |
| File descriptor limit | Increase `ulimit -n` or container fd limits |
| Network issues | Fix firewall rules, MTU settings, or routing |

## Prevention

- Monitor certificate expiry dates and rotate before they expire (see [Certificate Rotation](certificate-rotation.md)).
- Keep `--tls-min-version` at `1.2` unless you have a specific reason to require `1.3`.
- Set `--max-concurrent-handshakes` appropriately for your expected connection rate.
- Ensure file descriptor limits are at least 2x the expected max connections.
- Use structured logging (`RUST_LOG=info,rustgate_transport=debug`) during troubleshooting to capture handshake details.
- Enable OpenTelemetry tracing for the `tls_handshake` span to track handshake latency and failure rates over time.
