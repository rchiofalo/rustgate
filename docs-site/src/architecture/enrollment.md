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

## EST (RFC 7030) Enrollment

When the `est` feature is enabled and `--est-enabled` is set, the enrollment server also exposes standard EST (Enrollment over Secure Transport) endpoints alongside the PKCS#12 flow:

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/est/cacerts` | GET | CA certificate distribution as a PKCS#7 certs-only bag |
| `/.well-known/est/simpleenroll` | POST | CSR-based initial enrollment (base64 DER PKCS#10) |
| `/.well-known/est/simplereenroll` | POST | Certificate re-enrollment (same flow) |
| `/.well-known/est/csrattrs` | GET | CSR attributes guidance (currently 204 No Content) |

EST responses use CMS `SignedData` certs-only bags ([RFC 5652](https://www.rfc-editor.org/rfc/rfc5652)) with base64 encoding per [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) Section 4, as clarified by [RFC 8951](https://www.rfc-editor.org/rfc/rfc8951).

**Labeled paths** are supported for multi-CA deployments: `/.well-known/est/{label}/cacerts` routes to the same handler, with the label available for future per-CA configuration.

EST reuses the same `CsrSigner`, HTTP Basic auth, and per-IP rate limiting infrastructure as the PKCS#12 flow. The only difference is the wire format: EST sends base64 DER instead of PEM, and returns PKCS#7 bags instead of JSON/PKCS#12.

### Dependencies

The `est` feature pulls in three optional crates: `cms` (CMS/PKCS#7 construction), `der` (ASN.1 DER encoding), and `x509-cert` (X.509 certificate types). These are only compiled when the feature is enabled.

## Related

- [TLS Certificates & mTLS](../security/mtls.md) for the certificate model.
- [REST API](../reference/rest-api.md) for the wire-level enrollment endpoint reference.
- [Certificate Rotation runbook](../operations/runbooks/certificate-rotation.md) for re-enrollment procedures.
