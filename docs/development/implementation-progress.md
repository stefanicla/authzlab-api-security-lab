# Implementation Progress

## Phase 0: Environment Audit ✅
- [x] Windows/WSL tool discovery documented
- [x] Tool inventory complete
- [x] Execution environment selected (WSL Ubuntu)
- [x] `docs/development/toolchain-audit.md` created

## Phase 1: Project Bootstrap ✅
- [x] Repository initialized with uv
- [x] `pyproject.toml` configured with all dependencies
- [x] `uv.lock` generated
- [x] Quality tooling configured (Ruff, mypy, pytest, Semgrep)
- [x] Project structure created per spec
- [x] Docker Compose with PostgreSQL configured
- [x] Application skeleton created
- [x] AGENTS.md documented
- [x] Dependencies install successfully
- [x] Basic API structure ready

## Phase 2: Secure Application Foundation
- [x] Domain models (Tenant, User, Invoice) with proper constraints
- [x] Domain exceptions
- [x] Database infrastructure (engine, sessions, init)
- [x] Repository layer (Tenant, User, Invoice)
- [x] Security infrastructure (JWT RS256, Argon2id)
- [x] Authorization policies (centralized)
- [x] Application services (Tenant, User, Invoice)
- [x] API error handling (RFC 9457)
- [x] API dependencies (auth, DB)
- [x] API v1 routes (auth, invoices, health)
- [x] Secure FastAPI application
- [x] Vulnerable FastAPI application (lab mode)
- [x] CLI with init, seed, run commands
- [x] Seed demo script
- [x] Exploit runner script
- [x] Dockerfile (multi-stage)
- [x] compose.yaml (secure, lab, dast profiles)
- [x] .env.example, .dockerignore, .gitignore
- [x] Makefile with all convenience commands
- [x] README.md with full documentation
- [x] SECURITY.md, CONTRIBUTING.md, LICENSE

## Phase 3: Vulnerability Laboratory
- [x] LAB-01 BOLA/IDOR - cross-tenant access in vulnerable app
- [x] LAB-02 BFLA - unauthorized approval in vulnerable app
- [x] LAB-03 Mass Assignment - protected field modification in vulnerable app
- [x] LAB-04 Business Logic - self-approval in vulnerable app
- [x] Vulnerable app isolated with explicit opt-in (AUTHZLAB_LAB_MODE=true)
- [x] Exploit runner with all 4 scenarios
- [x] Comparison mode (vulnerable vs secure)

## Phase 4: Security Regression Testing
- [x] Unit tests for authorization policies (25 tests)
- [x] JWT negative tests (`tests/unit/test_jwt.py`: expiry, tampered sig, wrong iss/aud, alg=none, RS->HS, missing claims)
- [x] Integration tests for secure API with real PostgreSQL (15 tests incl. H-1 member-listing regression)
- [x] Security regression tests (vulnerable vs secure, 15 tests incl. lab gate test + M-1 inner allow-list pin)
- [x] Coverage reporting configured

Current verified result: 66 passed (36 unit + 15 integration + 15 security),
80.54% coverage with the 78% floor.

## Phase 5: Security Tooling and CI
- [x] Semgrep SAST configuration
- [x] Trivy vulnerability scanning
- [x] GitHub Actions CI workflow
- [x] OWASP ZAP DAST (optional, scheduled)

## Phase 6: Portfolio Release ✅
- [x] Final README review
- [x] Diagrams and threat model documentation
- [x] Vulnerability walkthroughs
- [x] Clean setup verification from empty environment
- [x] Startup/cleanup command documentation
- [x] Interview demonstration preparation

Release: `v0.1.0`. Demo script: `docs/development/interview-demo.md`
(rehearsed live: LAB-01 200/404 contrast, 4/4 vs 4/4 sweep, 15/15 security
fallback). Docs: `docs/threat-model/`, `docs/architecture/`,
`docs/vulnerabilities/` (LAB-01…04), `docs/development/clean-setup-verification.md`.

## Verification Commands

```bash
# From WSL (mise shims on PATH via ~/.profile; `bash -lc` picks them up)
# Run from the repo root.

# Install deps (frozen to uv.lock)
uv sync --all-extras --frozen

# Start DB (wait for healthy) and initialize schema
docker compose --profile secure up -d postgres
export DATABASE_URL=postgresql+psycopg://authzlab:authzlab@localhost:5432/authzlab
uv run python -c "from authzlab.infrastructure.database import init_db; init_db()"

# Seed (needs initialized tables — init first or boot a server, whose
# lifespan inits in non-production)
uv run python scripts/seed_demo.py

# Run tests (with coverage)
uv run pytest tests/ --cov=src/authzlab --cov-report=term-missing

# Lint/Format/Typecheck
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run mypy src/

# Security scans
uv run semgrep scan --config=p/python --config=p/secrets src/
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL .
```

Notes: `make db-reset` replaces the manual compose/init steps and recreates the
shared PostgreSQL volume, deleting both secure and lab data; pytest session
fixtures `drop_db()` at setup and teardown, so use a disposable test database.
Full clean-tree evidence: `docs/development/clean-setup-verification.md`.

## Known Issues / Blockers

1. **Cross-device link warnings** during `uv sync` due to Windows/WSL filesystem boundary - fallback to copy works but slower
2. **Vulnerable app test** needs `AUTHZLAB_LAB_MODE=true` environment variable
3. **Integration tests** require running PostgreSQL (Docker Compose)

## Next Steps

1. Run full test suite to verify everything works
2. Fix any failing tests
3. Run security scans
4. Document threat model
5. Create vulnerability walkthrough documents
6. Final review and release
