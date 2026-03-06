# TLS Certificates

rustgate uses mutual TLS (mTLS) for all client and federation peer connections. Every connecting client must present a valid certificate signed by the configured CA.

## Certificate Requirements

### Server Certificate

The server certificate is presented to clients during the TLS handshake:

- **Format:** PEM-encoded X.509
- **Key type:** RSA 2048+ or ECDSA P-256/P-384
- **Usage:** Server authentication (TLS Web Server Authentication)
- **CN:** Hostname or descriptive name for the server

### Client Certificates

Client certificates authenticate connecting clients and determine their identity and group membership:

- **Format:** PEM-encoded X.509
- **Signed by:** The same CA configured with `--ca`
- **CN (Common Name):** Becomes the client's callsign/identity
- **OU (Organizational Unit):** Each OU becomes a group membership

**Example:** A certificate with CN=`ALPHA-1` and OU=`Team-Alpha`, OU=`HQ` creates an identity with callsign "ALPHA-1" belonging to groups "Team-Alpha" and "HQ".

### CA Certificate

The CA certificate is used to verify client certificates:

- **Format:** PEM-encoded X.509
- Must be the issuer of all client certificates that will connect
- Can be a chain (intermediate + root) in a single PEM file

## Generating Certificates

### Quick Test Certificates

For testing, generate a self-signed CA and certificates with OpenSSL:

```bash
# Generate CA key and certificate
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca.pem \
  -days 365 -nodes -subj "/CN=rustgate-ca"

# Generate server key and CSR
openssl req -newkey rsa:4096 -keyout server-key.pem -out server.csr \
  -nodes -subj "/CN=rustgate-server"

# Sign server certificate
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server.pem -days 365

# Generate a client certificate with group membership
openssl req -newkey rsa:4096 -keyout client-key.pem -out client.csr \
  -nodes -subj "/CN=ALPHA-1/OU=Team-Alpha/OU=HQ"

# Sign client certificate
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out client.pem -days 365
```

### Production Certificates

For production, use a proper PKI or the built-in enrollment server. Key considerations:

- Use separate CAs for different security domains
- Set appropriate certificate lifetimes (shorter is better)
- Include CRL distribution points if certificate revocation is needed
- Use ECDSA P-256 for smaller certificates and faster handshakes

## Certificate Enrollment

rustgate includes a built-in certificate enrollment server (feature-gated: `enrollment`) that implements the Marti v2 certificate signing protocol. Compatible clients can self-provision their certificates.

### Enable Enrollment

```bash
rustgate \
  --cert server.pem --key server-key.pem --ca ca.pem \
  --ca-key ca-key.pem \
  --enrollment-bind 0.0.0.0:8446 \
  --enrollment-user admin \
  --enrollment-password changeme
```

### Enrollment Flow

1. Client connects to the enrollment HTTPS endpoint (port 8446)
2. Client authenticates with HTTP Basic Auth (username/password)
3. Client submits a PKCS#10 Certificate Signing Request (CSR)
4. Server ignores the CSR subject and sets CN from the authenticated username
5. Server strips SANs and custom extensions from the CSR (anti-impersonation)
6. Server signs the certificate with the CA key
7. Server returns the signed certificate and CA cert in JSON or XML format

### Security Notes

- **Subject DN enforcement:** The certificate CN is always set from the authenticated username, not from the CSR. This prevents a client from requesting a certificate with someone else's identity.
- **SAN stripping:** Subject Alternative Names are removed from CSRs to prevent domain/IP spoofing.
- **Server-only TLS:** The enrollment endpoint uses TLS but does not require a client certificate (the client doesn't have one yet — that's why it's enrolling).

## Federation Certificates

Federation peers authenticate using the same mTLS mechanism as clients. Each federation peer needs:

1. A server certificate (for the listening side)
2. A client certificate (for the connecting side)
3. The remote peer's CA certificate in the trust store

### Cross-Organization Federation

When federating with servers from different organizations:

1. Exchange CA certificates between organizations
2. Add the remote CA to your trust store (via REST API or file)
3. Configure the peer with `trust_cert_cn` to verify the expected certificate CN

```json
{
  "id": "partner-org",
  "address": "partner.example.com:9001",
  "groups": ["Shared-Intel"],
  "enabled": true,
  "is_outbound": true,
  "trust_cert_cn": "partner-federation-server"
}
```

### Dynamic Trust Store

The federation trust store allows adding CA certificates at runtime:

```bash
# Upload a partner's CA certificate
curl -X POST http://localhost:9090/api/federation/certificates \
  -H "Content-Type: application/x-pem-file" \
  --data-binary @partner-ca.pem

# List trusted CAs
curl http://localhost:9090/api/federation/certificates

# Remove a CA by CN
curl -X DELETE http://localhost:9090/api/federation/certificates/partner-ca
```

New CAs take effect on the next TLS handshake — no restart required.

## Kubernetes TLS Setup

### Create the TLS Secret

```bash
kubectl create secret generic rustgate-tls \
  --from-file=server.crt=server.pem \
  --from-file=server.key=server-key.pem \
  --from-file=ca.crt=ca.pem
```

### Reference in Helm

The Helm chart mounts the TLS secret at `/certs/` with the paths configured in `values.yaml`:

```yaml
tls:
  secretName: rustgate-tls
  cert: /certs/server.crt
  key: /certs/server.key
  ca: /certs/ca.crt
```

### Certificate Rotation

To rotate certificates:

1. Create a new Secret with the updated certificates
2. Update the Helm release to reference the new Secret (or update the existing Secret)
3. Restart the rustgate pods: `kubectl rollout restart deploy/rustgate`

rustgate reads certificates at startup — a pod restart is required for new certificates to take effect. The dynamic trust store (for federation CAs) does not require a restart.

## Troubleshooting

### Client can't connect

```
error: tls handshake failed: certificate unknown
```

- Verify the client certificate is signed by the CA configured with `--ca`
- Check certificate expiration: `openssl x509 -in client.pem -noout -dates`
- Verify the CA chain: `openssl verify -CAfile ca.pem client.pem`

### Wrong identity extracted

Check what identity rustgate extracts from a certificate:

```bash
openssl x509 -in client.pem -noout -subject
# subject=CN = ALPHA-1, OU = Team-Alpha, OU = HQ
```

The CN becomes the callsign, and each OU becomes a group. If groups are missing, verify the certificate has OU fields in the subject DN.

### Federation TLS errors

```
error: federation peer handshake failed
```

- Verify both sides trust each other's CA certificate
- Check certificate CN matches expectations (or use `--federation-skip-hostname-verify`)
- Ensure the certificate has the correct key usage extensions
- Verify certificates aren't expired
