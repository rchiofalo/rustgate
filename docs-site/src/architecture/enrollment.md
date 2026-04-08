# Enrollment

The `rustgate-enrollment` crate is an optional PKCS#12 certificate enrollment server that lets clients bootstrap their mTLS identity from a one-time token instead of relying on an external PKI workflow. It is enabled via `--features enrollment` and exposed on its own listener.

## Flow

1. An operator (or an upstream provisioning system) issues a one-time enrollment token bound to a CN, a group set, and an expiry.
2. The client posts a CSR plus the token to the enrollment endpoint.
3. The enrollment server validates the token (constant-time compare), signs the CSR with the configured intermediate CA, and returns a PKCS#12 bundle containing the signed cert and the CA chain.
4. The client uses the returned bundle to dial the main mTLS listener.

## Hardening

- **Per-IP rate limit** on CSR signing requests (`--enrollment-rate-limit-per-ip`) prevents an attacker from grinding the signing pipeline.
- **Token single-use** — once redeemed, a token is marked spent and any subsequent presentation is rejected.
- **CSR validation** — only the requested CN must match the token; the server overrides any group SAN extensions in the CSR with the values bound to the token.
- **TLS-protected listener** — the enrollment endpoint itself runs over TLS with a server certificate distinct from the main router's certificate.

## Related

- [TLS Certificates & mTLS](../security/mtls.md) for the certificate model.
- [REST API](../reference/rest-api.md) for the wire-level enrollment endpoint reference.
- [Certificate Rotation runbook](../operations/runbooks/certificate-rotation.md) for re-enrollment procedures.
