# AuthZLab Agent Configuration

This file documents the project conventions for AI agents working on AuthZLab.

## Project Structure

```
src/authzlab/
├── api/
│   ├── v1/              # API routes (versioned)
│   ├── dependencies.py  # FastAPI dependencies (auth, DB)
│   └── errors.py        # Exception handlers, RFC 9457 problem details
├── application/
│   ├── services/        # Business logic services
│   └── policies/        # Authorization policies (centralized)
├── domain/
│   ├── models/          # SQLAlchemy models
│   └── exceptions.py    # Domain exceptions
├── infrastructure/
│   ├── database/        # DB engine, sessions, init
│   ├── repositories/    # Data access layer
│   └── security/        # JWT, password hashing
├── core/                # Configuration, settings
├── secure_app.py        # Secure FastAPI application
└── vulnerable_app.py    # Vulnerable FastAPI application (lab only)
```

## Key Conventions

### 1. Authorization
- All authorization decisions in `application/policies/AuthorizationPolicy`
- Never check permissions in route handlers
- Use `ensure_*` methods that raise domain exceptions
- Tenant isolation enforced at repository + policy level

### 2. Database
- Synchronous SQLAlchemy 2.x sessions
- Context manager `get_session()` for automatic commit/rollback
- Repositories receive session, don't manage transactions
- Models in `domain/models/`

### 3. Error Handling
- Domain exceptions in `domain/exceptions.py`
- RFC 9457 problem details via `api/errors.py`
- Register handlers in `register_exception_handlers(app)`
- 404 for cross-tenant (hide existence), 403 for authz, 422 for mass assignment

### 4. Security
- JWT with RS256, validate: signature, alg, iss, aud, exp, claims
- Argon2id for passwords (configurable cost factors)
- Never trust client-supplied tenant_id or role
- Validate current user's tenant membership on every request

### 5. Vulnerable vs Secure
- Secure app: `secure_app.py` (default)
- Vulnerable app: `vulnerable_app.py` (requires `AUTHZLAB_LAB_MODE=true`)
- Vulnerable behavior lives in separate service classes (`VulnerableInvoiceService`,
  `VulnerableUserService`) in `vulnerable_app.py`, not in monkey-patched secure ones
- Never mix vulnerable code into secure app
- Lab binds to different port (8001), localhost only

### 6. Testing
- Unit: `tests/unit/` - policies, services, utils
- Integration: `tests/integration/` - DB, API contracts
- Security: `tests/security/` - exploit regression tests
- Test data is built inline via pytest fixtures (no separate `tests/fixtures/` dir)
- Use real PostgreSQL for integration (no SQLite)

### 7. Code Quality
- `make format` (Ruff)
- `make lint` (Ruff)
- `make typecheck` (mypy strict)
- `make test` (pytest with coverage)
- `make security` (Semgrep + Trivy)

## Environment

- Primary: WSL Ubuntu 24.04+
- Python: 3.14 via mise
- Package manager: uv
- Database: PostgreSQL 18 via Docker Compose
- Run commands from WSL: `wsl bash -c '...'`

## Common Commands

```bash
# Development
make install          # Install deps
make db-up            # Start Postgres
make db-reset         # DESTRUCTIVE: recreate shared secure+lab PostgreSQL volume
make seed             # Seed demo data (authzlab)
make seed-lab         # Seed lab database (authzlab_lab)
make run-secure       # Run secure API (port 8000)
make run-lab          # Run vulnerable lab (port 8001)

# Quality
make format           # Ruff format
make lint             # Ruff check
make typecheck        # mypy
make test             # All tests
make test-security    # Security regression tests

# Security
make exploit-all      # Run all exploits (needs VICTIM_INVOICE, OWN_INVOICE)
make exploit-compare  # Compare vulnerable vs secure
make security         # Semgrep + Trivy scans

# Docker
make docker-build     # Build secure and lab images
make docker-up        # Start secure stack
make docker-up-lab    # Start lab stack
make docker-down      # Stop all profiles; preserve the data volume
```

## Adding New Vulnerabilities

1. Add domain exception in `domain/exceptions.py`
2. Add policy check in `application/policies/`
3. Implement vulnerable version in `vulnerable_app.py`
4. Add exploit in `scripts/exploit_scenarios.py`
5. Add regression tests in `tests/security/`
6. Document in `docs/vulnerabilities/`
7. Update README comparison table

## File Naming

- Modules: `snake_case.py`
- Classes: `PascalCase`
- Functions: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_leading_underscore`

## Imports

```python
# Standard library first
from __future__ import annotations
import uuid

# Third-party
from fastapi import Depends
from sqlalchemy.orm import Session

# Local - absolute imports
from authzlab.domain.models import User
from authzlab.application.policies import AuthorizationPolicy
```

## Type Hints

- Always use type hints
- `from __future__ import annotations` at top
- Use PEP 604 unions (`X | None`) — the project targets Python 3.14 only, so
  `Optional[X]` from `typing` is not needed
- Prefer `Sequence[X]` over `List[X]` for return types
- Annotate all public functions

## Git

- Main branch: `main`
- Feature branches: `feat/description`
- Security branches: `security/description`
- Commit with conventional messages
- No direct pushes to main (PR required)
