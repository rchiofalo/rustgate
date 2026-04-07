# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.7.x   | Yes                |
| 0.6.x   | Security fixes only|
| 0.5.x   | No                 |
| 0.4.x   | No                 |
| < 0.4   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in rustgate, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of the following methods:

1. **GitHub Security Advisories** (preferred): Navigate to the [Security Advisories](https://github.com/rchiofalo/rustgate/security/advisories) page and click "Report a vulnerability."

2. **Email**: Send details to the repository owner via the contact information on their GitHub profile.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, targeting 30 days for critical issues

### Scope

The following are considered security issues:

- Authentication or authorization bypass
- Certificate validation failures
- Message routing to unauthorized recipients
- Denial of service via resource exhaustion
- Information disclosure (e.g., leaking client identities or positions to unauthorized parties)
- Injection attacks (XML, command, etc.)

### At-rest encryption

The CoT archive (`--archive-dir`) and JSON audit log (`--audit-log`)
can be encrypted with ChaCha20-Poly1305 by supplying
`--archive-key-file <path>`. Each output file is sealed under a
per-file random nonce using the active key from the supplied JSON
key ring; key rotation is supported by adding new key ids without
removing old ones, so historical files remain decryptable.

Operational guidance:

- Store the key file on a tmpfs or hardware-protected mount; treat it
  with the same care as the server's TLS private key.
- Rotate keys periodically by adding a new id and updating
  `active_key_id`. Old keys must remain in the file until every file
  written under them has been migrated or expired.
- Encryption is independent of full-disk encryption (FDE) and is
  intended for environments that require application-level protection
  (classified, regulated, or multi-tenant deployments). FDE alone does
  not protect against an operator with shell access reading archive
  files.
- Use `rustgate decrypt-archive --in <enc> --out <plaintext> --key-file <path>`
  to export historical files for inspection or backup. The decrypted
  output is plaintext and should be deleted when no longer needed.

### Nonce-collision bound and key rotation cadence

Each encrypted file uses an 8-byte random base nonce concatenated with a
4-byte chunk counter to form the 96-bit ChaCha20-Poly1305 nonce. Because
the base nonce is random rather than a counter, the dominant safety
limit is the birthday bound on the **base nonce across files written
under the same key**:

- 2^32 files per key gives a ~50% chance of base-nonce collision.
- 2^16 files per key keeps the collision probability below ~2^-32.

Recommendation: rotate the active key (add a new id and update
`active_key_id`) before any single key has been used to write more than
~2^16 files (≈65k). For most deployments — one archive file per UTC day
plus one audit log per restart — this means rotating every few years is
ample, but high-rotation environments (frequent restarts, many small
files) should rotate sooner.

A future enhancement under consideration is migrating to
**XChaCha20-Poly1305**, whose 24-byte nonce makes random nonces safe for
all practical workloads and removes the birthday bound as an
operational concern. Tracking issue: see the encrypted-archive design
notes.

The following are generally **not** security issues:

- Bugs that require local access to the server
- Issues in dependencies that don't affect rustgate's usage of them
- Feature requests for additional security controls
