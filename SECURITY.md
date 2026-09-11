# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Educational & Research Notice

This codebase is a reference exploration and microbenchmarking implementation of the NIST FIPS 203 ML-KEM post-quantum cryptographic standard. While designed to be constant-time and adhering to FIPS 203 algorithm specifications, production mission-critical cryptographic deployments should employ formally verified, FIPS-validated hardware security modules (HSMs) or audited cryptographic libraries (such as liboqs / BoringSSL).

## Reporting a Vulnerability

If you discover a potential security flaw, timing leakage, or cryptographic implementation bug, please report it privately:

1. **Do NOT** open a public issue.
2. Submit a security disclosure through GitHub's Security Advisory tab or email the maintainer at `kanak@example.com`.
3. Include reproducible proof-of-concept steps, affected components, and potential attack vectors.

Reports will be acknowledged within 48 hours.
