# Runbook: CRL Updates and Revocation Enforcement

## Symptoms

- Warning logs about stale CRL: `CRL nextUpdate is in the past`
- Revoked clients are still able to connect (CRL not loaded or outdated)
- Need to revoke a compromised client certificate

## Detection

1. Check for stale CRL warnings:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=100 | grep -i crl
   ```

2. Inspect the current CRL:
   ```bash
   openssl crl -in /certs/crl.pem -text -noout | head -20
   ```

3. Check `nextUpdate` field — if this date is in the past, the CRL is stale:
   ```bash
   openssl crl -in /certs/crl.pem -noout -nextupdate
   ```

## Diagnosis

1. Verify the CRL file is loaded:
   ```bash
   # Check if --crl is configured
   kubectl get deploy rustgate -o yaml | grep -i crl
   ```

2. Verify `--crl-warn-stale` is enabled (default `true`):
   ```bash
   kubectl get deploy rustgate -o yaml | grep CRL_WARN_STALE
   ```

3. Confirm whether the target certificate is actually in the CRL:
   ```bash
   # Get the serial number of the certificate to revoke
   openssl x509 -in compromised-client.pem -noout -serial

   # Check if it appears in the CRL
   openssl crl -in crl.pem -text -noout | grep -i <serial>
   ```

## Resolution

### Revoking a Certificate

1. Revoke the certificate using your CA's tooling:
   ```bash
   # Using OpenSSL CA
   openssl ca -config ca.cnf -revoke compromised-client.pem -crl_reason keyCompromise
   ```

2. Generate a new CRL:
   ```bash
   openssl ca -config ca.cnf -gencrl -out new-crl.pem
   ```

3. Replace the CRL file:
   ```bash
   # Atomic replacement
   cp new-crl.pem /certs/crl.pem.tmp
   mv /certs/crl.pem.tmp /certs/crl.pem
   ```

4. Restart rustgate to load the new CRL:
   ```bash
   kubectl rollout restart deploy/rustgate
   ```

5. Verify the revoked client can no longer connect:
   ```bash
   openssl s_client -cert compromised-client.pem -key compromised-client-key.pem \
     -CAfile ca.pem -connect localhost:4433
   # Should fail during handshake
   ```

### Updating a Stale CRL

1. Generate a fresh CRL with an updated `nextUpdate` field:
   ```bash
   openssl ca -config ca.cnf -gencrl -crldays 30 -out new-crl.pem
   ```

2. Verify the new CRL:
   ```bash
   openssl crl -in new-crl.pem -noout -nextupdate
   ```

3. Replace and restart (same steps as above).

### Kubernetes CRL Update

In Kubernetes, the CRL is typically stored in a Secret or ConfigMap:

```bash
# Update the Secret with the new CRL
kubectl create secret generic rustgate-tls \
  --from-file=server.crt=/certs/server.crt \
  --from-file=server.key=/certs/server.key \
  --from-file=ca.crt=/certs/ca.crt \
  --from-file=crl.pem=new-crl.pem \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart to pick up the new CRL
kubectl rollout restart deploy/rustgate
```

### Disabling CRL Checking

If CRL checking is causing issues and you need to temporarily disable it:

1. Remove the `--crl` flag or unset `RUSTGATE_CRL`.
2. Restart rustgate.
3. All certificates signed by the CA will be accepted regardless of revocation status.

This should only be used as a temporary measure.

## Prevention

- Automate CRL generation on a schedule (e.g., daily or weekly cron job).
- Set `--crl-warn-stale true` (the default) to detect stale CRLs in logs.
- Set up monitoring alerts on `CRL nextUpdate is in the past` log messages.
- Use short CRL validity periods (7-30 days) to bound the window of exposure.
- Store CRL generation scripts and CA configuration in version control.
- For high-security deployments, consider OCSP stapling or short-lived certificates as alternatives to CRL.
