# Contributing to AuthZLab

Thank you for your interest in contributing to AuthZLab!

## Development Setup

```bash
# Clone repository
git clone https://github.com/stefanicla/authzlab-api-security-lab.git
cd authzlab-api-security-lab

# Install dependencies
make install

# Destructive: recreates the shared PostgreSQL volume (secure and lab data)
make db-reset

# Seed demo data
make seed

# Run tests
# Tests drop mapped tables at setup and teardown; use a disposable DATABASE_URL.
make test
```

## Code Standards

- **Python**: 3.14+, type-annotated, PEP 8 compliant
- **Formatting**: Ruff (run `make format`)
- **Linting**: Ruff (run `make lint`)
- **Type Checking**: mypy (run `make typecheck`)
- **Testing**: pytest with an enforced coverage floor of 78% (`make test` passes
  `--cov-fail-under=78`, CI job *Coverage Floor* runs the full suite against
  PostgreSQL with the same threshold). Measured coverage is ~80.4%; the floor
  sits ~2 points below it so ordinary churn does not break the build.
  100% on authorization policies and domain models — `make test` reports per-file.

## Architecture Guidelines

1. **Keep API models separate from database models**
2. **Business logic in services, not route handlers**
3. **Centralize authorization decisions in policies**
4. **Enforce tenant isolation at data access layer**
5. **Use dependency injection for testability**
6. **Explicit database sessions and transactions**
7. **No global mutable state**
8. **Avoid circular imports**

## Security Guidelines

- Never log passwords, JWTs, or secret keys
- Handle errors consistently without information leakage
- Validate all inputs server-side
- Use secure defaults
- Keep vulnerable lab code isolated and documented

## Testing Requirements

- Unit tests for all authorization policies
- Integration tests with real PostgreSQL
- Security regression tests for all four scenarios
- Negative tests for authentication edge cases
- Coverage floor: 78% overall, enforced by `make test` and CI (measured ~80.4%),
  100% on authorization policies and domain models

## Pull Request Process

1. Run `make ci` locally before submitting
2. Ensure all tests pass
3. Update documentation for new features
4. Add security regression tests for any authorization changes
5. No vulnerable code in secure variant
6. Vulnerable variant changes must be documented with CVE/CWE references

## Commit Messages

Follow conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `security:` security-related change
- `test:` test additions/changes
- `docs:` documentation
- `refactor:` code restructuring
- `ci:` CI/CD changes

## Vulnerability Additions

To add a new vulnerability scenario:
1. Document in `docs/vulnerabilities/`
2. Add to vulnerable app with clear labeling
3. Add exploit to `scripts/exploit_scenarios.py`
4. Add regression tests in `tests/security/`
5. Map to OWASP API Top 10 and CWE
6. Update comparison table in README

## Questions?

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Open a discussion or
issue for clarification before starting significant work. For security
vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.
