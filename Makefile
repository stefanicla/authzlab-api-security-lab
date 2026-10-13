# AuthZLab Makefile
# Convenience commands for development and testing

.PHONY: help install test test-unit test-integration test-security lint lint-style format typecheck security semgrep trivy db-up db-down db-reset seed seed-lab reset-lab run-secure run-lab exploit exploit-bola exploit-bfla exploit-mass exploit-bizlogic exploit-all exploit-compare docker-build docker-up docker-up-lab docker-down docker-logs clean ci

# M-1: measured total coverage is ~80.4% (833/1036 stmts). The floor is set 2
# points below the real measurement so ordinary churn doesn't break the build;
# keep this number in sync with ci.yml and CONTRIBUTING.md.
COVERAGE_MIN = 78

# Default target
help:
	@echo "AuthZLab - Multi-tenant API Authorization Security Laboratory"
	@echo ""
	@echo "Available targets:"
	@echo "  install        Install dependencies with uv"
	@echo "  test           Run all tests"
	@echo "  test-unit      Run unit tests only"
	@echo "  test-integration Run integration tests only"
	@echo "  test-security  Run security regression tests only"
	@echo "  lint           Run ruff linting"
	@echo "  format         Run ruff formatting"
	@echo "  typecheck      Run mypy type checking"
	@echo "  security       Run security scans (semgrep, trivy)"
	@echo "  db-up          Start PostgreSQL container"
	@echo "  db-down        Stop PostgreSQL (preserve the shared data volume)"
	@echo "  db-reset       DESTRUCTIVE: recreate the shared secure+lab PostgreSQL volume"
	@echo "  seed           Seed database with demo data"
	@echo "  seed-lab       Seed lab database (authzlab_lab) with demo data"
	@echo "  reset-lab      Reset lab database to empty schema (re-seed after)"
	@echo "  run-secure     Run secure API server"
	@echo "  run-lab        Run vulnerable lab API server"
	@echo "  exploit        Run exploit scenarios against lab"
	@echo "  exploit-all    Run all exploit scenarios"
	@echo "  exploit-compare Run exploits against both vulnerable and secure"
	@echo "  docker-build   Build secure and lab Docker images"
	@echo "  docker-up      Start all Docker services (secure profile)"
	@echo "  docker-up-lab  Start all Docker services (lab profile)"
	@echo "  docker-down    Stop all profile services (preserve the data volume)"
	@echo "  clean          Clean build artifacts"

# Install dependencies
install:
	uv sync --all-extras

# Testing
test:
	uv run pytest --cov=src/authzlab --cov-report=term-missing --cov-fail-under=$(COVERAGE_MIN)

test-unit:
	uv run pytest tests/unit -v

test-integration:
	uv run pytest tests/integration -v

test-security:
	uv run pytest tests/security -v

# Code quality
lint:
	uv run ruff check src/ tests/ scripts/

# H-1: style/preview rules are informational only (non-gating).
lint-style:
	uv run ruff check src/ tests/ scripts/ --preview --select PL,TRY,ARG,PERF,FLY,PD,PGH,TID,LOG,T20,PIE,NPY,C90,TCH || true

format:
	uv run ruff format src/ tests/ scripts/

typecheck:
	uv run mypy src/

# Security scans
security: semgrep trivy

# M-C: same ruleset as CI (ci.yml) so local and CI results match.
semgrep:
	uv run semgrep scan --config=p/python --config=p/secrets src/

trivy:
	trivy fs --scanners vuln,secret,misconfig --exit-code 1 --severity HIGH,CRITICAL --skip-dirs .venv --skip-dirs .git .

# Database
db-up:
	docker compose --profile secure up -d postgres

db-down:
	docker compose --profile secure --profile lab stop postgres

db-reset:
	@echo "WARNING: this removes the shared PostgreSQL volume and all secure and lab data."
	docker compose --profile secure --profile lab down -v
	docker compose --profile secure up -d postgres
	@echo "Waiting for database to be ready..."
	@sleep 5
	uv run python -c "from authzlab.infrastructure.database import init_db; init_db()"
	@echo "Database initialized"

# Seeding
seed:
	uv run python scripts/seed_demo.py

# M-2: seed the lab database (docker compose --profile lab). Without this the
# lab stack starts against an empty authzlab_lab schema and every exploit 404s.
seed-lab:
	DATABASE_URL=postgresql+psycopg://authzlab:authzlab@localhost:5432/authzlab_lab uv run python scripts/seed_demo.py

# Reset lab database to an empty schema (re-seed afterwards with make seed-lab)
reset-lab:
	DATABASE_URL=postgresql+psycopg://authzlab:authzlab@localhost:5432/authzlab_lab uv run python scripts/reset_lab.py

# Run servers
run-secure:
	uv run authzlab-secure

run-lab:
	@echo "Starting VULNERABLE lab server - DO NOT EXPOSE PUBLICLY"
	AUTHZLAB_LAB_MODE=true uv run authzlab-lab

# Exploit scenarios
exploit:
	@echo "Usage: make exploit SCENARIO=bola ATTACKER=charlie@acme.com PASSWORD=password123 VICTIM_INVOICE=<uuid>"
	@echo "Scenarios: bola, bfla, mass_assignment, business_logic"

exploit-bola:
	@if [ -z "$(VICTIM_INVOICE)" ]; then echo "VICTIM_INVOICE required"; exit 1; fi
	uv run python scripts/exploit_scenarios.py --scenario bola --target http://127.0.0.1:8001 --attacker $(ATTACKER) --password $(PASSWORD) --victim-invoice $(VICTIM_INVOICE)

exploit-bfla:
	@if [ -z "$(VICTIM_INVOICE)" ]; then echo "VICTIM_INVOICE required"; exit 1; fi
	uv run python scripts/exploit_scenarios.py --scenario bfla --target http://127.0.0.1:8001 --attacker $(ATTACKER) --password $(PASSWORD) --victim-invoice $(VICTIM_INVOICE)

exploit-mass:
	@if [ -z "$(OWN_INVOICE)" ]; then echo "OWN_INVOICE required"; exit 1; fi
	uv run python scripts/exploit_scenarios.py --scenario mass_assignment --target http://127.0.0.1:8001 --attacker $(ATTACKER) --password $(PASSWORD) --own-invoice $(OWN_INVOICE)

exploit-bizlogic:
	@if [ -z "$(OWN_INVOICE)" ]; then echo "OWN_INVOICE required"; exit 1; fi
	uv run python scripts/exploit_scenarios.py --scenario business_logic --target http://127.0.0.1:8001 --attacker $(ATTACKER) --password $(PASSWORD) --own-invoice $(OWN_INVOICE)

exploit-all:
	@if [ -z "$(VICTIM_INVOICE)" ] || [ -z "$(OWN_INVOICE)" ]; then echo "VICTIM_INVOICE and OWN_INVOICE required"; exit 1; fi
	uv run python scripts/exploit_scenarios.py --all --target http://127.0.0.1:8001 --attacker $(ATTACKER) --password $(PASSWORD) --victim-invoice $(VICTIM_INVOICE) --own-invoice $(OWN_INVOICE)

exploit-compare:
	@if [ -z "$(VICTIM_INVOICE)" ] || [ -z "$(OWN_INVOICE)" ]; then echo "VICTIM_INVOICE and OWN_INVOICE required"; exit 1; fi
	uv run python scripts/exploit_scenarios.py --all --target http://127.0.0.1:8001 --compare --attacker $(ATTACKER) --password $(PASSWORD) --victim-invoice $(VICTIM_INVOICE) --own-invoice $(OWN_INVOICE)

# Docker
docker-build:
	docker compose --profile secure --profile lab build

docker-up:
	docker compose --profile secure up -d

docker-up-lab:
	docker compose --profile lab up -d

docker-down:
	docker compose --profile secure --profile lab --profile dast down

docker-logs:
	docker compose logs -f

# Clean
clean:
	rm -rf dist/ build/ *.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# CI simulation
ci: lint typecheck test security
	@echo "CI pipeline completed successfully"
