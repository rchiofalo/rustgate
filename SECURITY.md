# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | Yes                |
| 0.3.x   | Security fixes only|
| < 0.3   | No                 |

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

The following are generally **not** security issues:

- Bugs that require local access to the server
- Issues in dependencies that don't affect rustgate's usage of them
- Feature requests for additional security controls
