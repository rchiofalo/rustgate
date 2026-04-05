# Runbook: Certificate Rotation

## Symptoms

- Certificate expiry warnings in logs or monitoring
- Upcoming certificate expiration date (check with `openssl x509 -in cert.pem -noout -enddate`)
- Scheduled rotation as part of security policy

## Detection

Monitor certificate expiry proactively:

```bash
# Check server certificate expiry
openssl x509 -in /certs/server.crt -noout -enddate

# Check days until expiry
openssl x509 -in /certs/server.crt -noout -checkend 2592000 || echo "EXPIRES WITHIN 30 DAYS"

# In Kubernetes
kubectl exec deploy/rustgate -- openssl x509 -in /certs/server.crt -noout -dates
```

Set up alerts for certificates expiring within 30 days.

## Diagnosis

1. Identify which certificate needs rotation:
   - **Server certificate** (`--cert` / `--key`) — presented to clients during TLS handshake
   - **CA certificate** (`--ca`) — used to verify client certificates
   - **CRL** (`--crl`) — certificate revocation list
   - **Federation trust store** — CA certs for federation peers

2. Check the current certificate details:
   ```bash
   openssl x509 -in /certs/server.crt -noout -subject -issuer -dates -serial
   ```

## Resolution

### Server Certificate Rotation (with hot-reload)

If `--cert-reload-interval` is configured (e.g., `3600` for hourly checks):

1. Generate the new certificate and key:
   ```bash
   openssl req -newkey rsa:4096 -keyout new-server-key.pem -out server.csr \
     -nodes -subj "/CN=rustgate-server"
   openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
     -CAcreateserial -out new-server.pem -days 365
   ```

2. Replace the files atomically (write to temp file, then rename):
   ```bash
   cp new-server.pem /certs/server.crt.tmp
   cp new-server-key.pem /certs/server.key.tmp
   mv /certs/server.key.tmp /certs/server.key
   mv /certs/server.crt.tmp /certs/server.crt
   ```

3. Wait for the next reload poll cycle. Check logs for:
   - `server certificate rotated` — rotation succeeded
   - `certificate reload failed` — check that cert and key match

4. No restart required. Existing connections continue with the old certificate; new connections use the new one.

### Server Certificate Rotation (without hot-reload)

1. Generate the new certificate (same steps as above).

2. Update the Kubernetes Secret:
   ```bash
   kubectl create secret generic rustgate-tls \
     --from-file=server.crt=new-server.pem \
     --from-file=server.key=new-server-key.pem \
     --from-file=ca.crt=ca.pem \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. Restart the pods:
   ```bash
   kubectl rollout restart deploy/rustgate
   kubectl rollout status deploy/rustgate
   ```

### CA Certificate Rotation

CA rotation affects all client and peer certificates. This is a high-impact operation.

1. Generate the new CA:
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout new-ca-key.pem -out new-ca.pem \
     -days 730 -nodes -subj "/CN=rustgate-ca-v2"
   ```

2. During the transition period, configure `--ca` with both old and new CA certificates concatenated:
   ```bash
   cat old-ca.pem new-ca.pem > combined-ca.pem
   ```

3. Re-issue client certificates signed by the new CA.

4. Once all clients have new certificates, remove the old CA from the combined file.

5. Update all rustgate instances and restart.

### Federation Trust Store Rotation

Federation CA certificates can be rotated at runtime without restart:

```bash
# Upload the new CA
curl -X POST http://localhost:9090/api/federation/certificates \
  -H "Content-Type: application/x-pem-file" \
  --data-binary @new-partner-ca.pem

# Verify it was added
curl http://localhost:9090/api/federation/certificates

# After the remote peer has rotated to certs signed by the new CA,
# remove the old CA
curl -X DELETE http://localhost:9090/api/federation/certificates/old-partner-ca
```

## Prevention

- Set up automated certificate expiry monitoring (Prometheus cert-exporter, cert-manager alerts).
- Use short-lived certificates (90-180 days) to force regular rotation practice.
- Enable `--cert-reload-interval` for zero-downtime server certificate rotation.
- Document the CA rotation procedure and test it in a staging environment annually.
- For Kubernetes, consider cert-manager for automated certificate lifecycle management.
