# Clean-Setup Verification (Phase 7, Batch 3)

Verified from a clean tree that a fresh checkout builds, passes all gates, and
reproduces the lab-vs-secure exploit contrast. Date: 2026-10-11. Commit: `bada9de`.

Current-worktree revalidation on 2026-10-13: `pytest tests/` passed **66 tests**
(36 unit, 15 integration, 15 security) with **80.54% coverage**, using a
disposable PostgreSQL Compose project.

## Procedure (fresh `git clone` into an empty dir, WSL Ubuntu + Docker)

```
uv sync --all-extras --frozen
docker compose --profile secure up -d postgres          # wait ~8s for healthy
export DATABASE_URL=postgresql+psycopg://authzlab:authzlab@localhost:5432/authzlab
uv run python -c "from authzlab.infrastructure.database import init_db; init_db()"
uv run python scripts/seed_demo.py
uv run pytest tests/                                    # 64 passed at the 2026-10-11 snapshot
uv run ruff check src/ tests/ scripts/                  # All checks passed
uv run ruff format --check src/ tests/ scripts/         # 23 files already formatted
uv run mypy src/                                        # no issues, 16 files
```

Exploit contrast (seed the lab DB too, boot both servers, fetch fresh IDs):

```
export DATABASE_URL=postgresql+psycopg://authzlab:authzlab@localhost:5432/authzlab_lab
uv run python scripts/seed_demo.py
uv run authzlab-secure &                                # :8000 (lifespan runs init_db)
AUTHZLAB_LAB_MODE=true uv run authzlab-lab &            # :8001
uv run python scripts/exploit_scenarios.py --all --compare \
  --target http://127.0.0.1:8001 --attacker charlie@acme.com --password password123 \
  --victim-invoice <EVE_ID> --own-invoice <OWN_ID>
```

## Results (clean tree)

- At the original 2026-10-11 snapshot, `pytest tests/` had **64 passed**.
- Current-worktree revalidation: **66 passed** (36 unit + 15 integration + 15 security).
- `ruff check` / `ruff format --check` / `mypy src/`: all clean.
- Exploit runner: **4/4 SUCCESS on lab** (`:8001`),
  **4/4 BLOCKED on secure** (`:8000`).
- Current Compose cleanup requires explicit profiles:
  `docker compose --profile secure --profile lab --profile dast down -v`.
  This deletes the shared PostgreSQL volume; use `make docker-down` to stop all
  profiles while preserving it.

## Gotchas (documented so nobody re-discovers them)

1. **Seed needs tables first.** `scripts/seed_demo.py` does not create schema;
   run `init_db()` (or boot a server, whose lifespan inits in non-production)
   before seeding, or seeding fails with `relation "tenants" does not exist`.
2. **Pytest drops the selected database's tables.** The integration and security
   session fixtures call `drop_db()` at setup and teardown. Point `DATABASE_URL`
   at a disposable test database; reinitialize and re-seed before demos.
3. **Per-DB UUIDs.** Each seed generates new IDs; the `--compare` run must use
   IDs from the DB it attacks (secure-side BLOCKED on unknown IDs is still a
   block, but the precise per-scenario codes are pinned by the test suite).
4. **Empty dirs are not cloned.** `migrations/versions/`, `docs/architecture/`
   etc. do not exist in a fresh clone (git tracks files, not dirs) — anything
   the setup needs must be created by code, not assumed present.

## Alembic posture decision

Findings: `migrations/` contains only an empty `versions/` dir — no `env.py`,
no `alembic.ini`, no revisions; `alembic` is declared but imported nowhere.
Schema is created solely by `init_db()` from the SQLAlchemy models
(`src/authzlab/infrastructure/database/__init__.py:90-95`), invoked by
`make db-reset` and by server lifespan in non-production.

Decision (Batch 3): **keep `init_db()`-from-models as the documented posture,
no migration generation in this release.** Rationale: single-node lab with no
production data to migrate; generating a first Alembic revision adds
regression surface (env wiring, downgrade testing) with no user-facing benefit
before portfolio release. If the project grows a production deployment, the
first step is `alembic init` + autogenerate from `Base.metadata`, with the
revision tested against an empty database. The empty `migrations/versions/`
scaffold is retained as the reserved location.
