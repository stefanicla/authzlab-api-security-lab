# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in AuthZLab, please report it responsibly:

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report it privately via **GitHub Security Advisories**:
open this repository on GitHub, go to **Security** -> **Advisories** ->
**Report a vulnerability**, and describe the issue there.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

## Intentionally Vulnerable Components

**AuthZLab contains intentionally vulnerable code for educational purposes.**

The `authzlab-lab` application (vulnerable variant) implements four authorization vulnerabilities:
1. **LAB-01**: BOLA/IDOR - Cross-tenant resource access
2. **LAB-02**: BFLA - Missing function-level authorization
3. **LAB-03**: Mass Assignment - Protected field modification
4. **LAB-04**: Business Logic - Self-approval violation

### Safety Controls

The vulnerable application includes multiple safety controls:
- Requires explicit `AUTHZLAB_LAB_MODE=true` environment variable to start
- Binds only to `127.0.0.1` (localhost) by default
- Separate Docker Compose profile (`lab`) that must be explicitly enabled
- Refuses startup outside approved local testing environment
- Clear warnings in logs and documentation

### Secure Variant

The `authzlab-secure` application (default) contains all remediations and is the only variant suitable for production-like use.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (MVP) | ✅ Current |

## Security Tooling

This project integrates:
- **Semgrep** - Static Application Security Testing (SAST)
- **Trivy** - Vulnerability scanning for dependencies, filesystem, containers
- **OWASP ZAP** - Dynamic Application Security Testing (DAST) - optional
- **Ruff** - Linting with security rules
- **mypy** - Static type checking

## Responsible Use

This project is designed for:
- Security engineering education
- Application security training
- Authorization vulnerability research
- Secure coding demonstrations

It is **NOT** designed for:
- Production deployment (vulnerable variant)
- Testing against systems you don't own
- Bypassing security controls in real applications

## Disclaimer

The maintainers are not responsible for misuse of the vulnerable components. Users assume all risk when running the lab variant.