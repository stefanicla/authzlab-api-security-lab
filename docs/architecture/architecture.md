# AuthZLab Architecture

Companion: `docs/threat-model/threat-model.md` (what is defended and why).

## 1. Layered design

All authorization decisions live in exactly one place —
`src/authzlab/application/policies/AuthorizationPolicy`. Route handlers never
check permissions; repositories never decide them.

```
Client (curl / exploit runner / tests)
  |
  v
FastAPI routes ......... src/authzlab/api/v1/__init__.py
  |  auth: get_current_user (api/dependencies.py:44-86)
  |  errors: RFC 9457 handlers (api/errors.py)
  v
Services ............... src/authzlab/application/services/__init__.py
  |  orchestration + workflow (DRAFT -> SUBMITTED -> APPROVED)
  v
Policies ............... src/authzlab/application/policies/__init__.py
  |  ensure_* methods raise domain exceptions on violation
  v
Repositories ........... src/authzlab/infrastructure/repositories/__init__.py
  |  tenant-scoped queries; fail-closed update(allowed=...)
  v
PostgreSQL 18 (SQLAlchemy 2.x synchronous sessions, get_session())
```

Supporting infrastructure: JWT RS256 + Argon2id
(`infrastructure/security/__init__.py`), settings (`core/config.py`),
domain models and exceptions (`domain/`).

## 2. Request lifecycle (example: PATCH /invoices/{id})

1. Route parses `InvoiceUpdate` — unknown fields rejected here by
   `extra="forbid"` (outer layer, `api/v1/__init__.py:54-61`).
2. `get_current_user` authenticates: Bearer format, signature, `kid`,
   iss/aud/exp, user lookup, active flag, token-tenant match; refresh tokens
   presented as access tokens become 401 (`api/dependencies.py:58-79`).
3. `InvoiceService.update_invoice` loads the invoice scoped to the caller's
   tenant (`services/__init__.py:152-156`) and enforces DRAFT-only
   (`services/__init__.py:163-167`).
4. `validate_update_fields` rejects protected fields (`tenant_id`, `owner_id`,
   `status`, `approved_by`, …) with `MassAssignmentError`
   (`policies/__init__.py:96-126`).
5. `repo.update(invoice, allowed={...})` applies only allow-listed keys;
   anything else raises `ValueError` — fail-closed by construction
   (`repositories/__init__.py:149-159`).
6. Domain exceptions map to HTTP via `register_exception_handlers`:
   401 auth, 404 cross-tenant (existence hidden), 403 authz, 422 mass
   assignment, 409 other business-rule breaches, generic 503 readiness
   (`api/errors.py:54-133`).

## 3. Authentication lifecycle

- Login (`api/v1/__init__.py:118-149`): email lookup across tenants, Argon2id
  verify, active check; identical `Invalid credentials` for every failure mode.
  Issues access token (sub/user/tenant/role/type=access) + refresh token
  (`security/__init__.py:63-117`), both carrying the `kid` header.
- Verification (`security/__init__.py:119-150`): `kid` match first, then
  signature/issuer/audience/expiry with all of iss/aud/exp/iat/sub required.
- Keys: persistent PEMs in production with fail-fast startup
  (`security/__init__.py:28-44`); ephemeral per-process keypair in development.

## 4. Secure vs lab divergence map

The lab (`src/authzlab/vulnerable_app.py`) is a separate service class
(`VulnerableInvoiceService`, line 56) that bypasses the policy layer:

| Lab | Lab bypass (vulnerable_app.py) | Secure counterpart |
|---|---|---|
| LAB-01 BOLA read | `get_invoice` fetches by id only, no tenant check (lines 59-66) | `get_by_id_and_tenant` + `ensure_can_view_invoice` + 404 |
| LAB-01b listing | `list_invoices` honors any `tenant_id` (lines 68-74) | `ensure_can_list_invoices` |
| LAB-02 BFLA | `approve_invoice` skips role check (lines 135+) | `ensure_can_approve` role requirement |
| LAB-03 mass assignment | `update_invoice` applies all fields (lines 96-134) | 3-layer allow-list (section 2) |
| LAB-04 self-approval | `approve_invoice` skips owner check (lines 135+) | `SelfApprovalError` in `ensure_can_approve` |

Safety rails: import/factory gates on `AUTHZLAB_LAB_MODE`
(`vulnerable_app.py:43-45` + factory at line 294), localhost-only bindings,
`run_lab --allow-external` requires an explicit `--host` (`cli.py:85-93`).

## 5. Invoice state machine

```
DRAFT --submit (owner only)--> SUBMITTED --approve (approver/admin, not owner)--> APPROVED
```

Enforced in `ensure_can_submit` (`policies/__init__.py:61-72`) and
`ensure_can_approve` (lines 46-58); the service layer persists transitions
(`services/__init__.py:168-195`). Rejections surface as 403 (authz) or 409
(state), never silent.

## 6. Deployment topology

- `compose.yaml`: `postgres` (5432, localhost-only), `api-secure` (8000),
  `api-lab` (8001, `AUTHZLAB_LAB_MODE=true`), optional `zap` (DAST profile).
  Both APIs bind `0.0.0.0` *inside* their containers (image default,
  `Dockerfile`) while published ports bind `127.0.0.1` on the host.
- `Dockerfile`: multi-stage build, sources copied before `uv sync` so the
  editable install resolves; runtime runs as `appuser` with a `/health/ready`
  healthcheck.
- Lifespan: non-production boots call `init_db()` (schema from models; no
  Alembic migrations — intentional, documented posture); readiness is a real
  `SELECT 1` probe returning generic 503 on failure.

## 7. Test pyramid mapping

| Layer | Suite | Pins |
|---|---|---|
| Unit (`tests/unit/`, 36) | policies, JWT negatives, OpenAPI contract | `validate_update_fields`, `kid`/alg/issuer/audience/expiry forgeries, refresh confusion, resource-specific tags |
| Integration (`tests/integration/`, 15) | secure API vs real Postgres | auth flow, member-listing scope (H-1), CRUD contracts |
| Security (`tests/security/`, 15) | lab-vs-secure + lab gate | all 4 exploits blocked on secure / reproduced on lab, M-1 inner-layer pin |

Total: 66 passed. Type safety: `mypy src/` clean (16 files). Lint: `ruff check`
clean on the enforced ruleset, style rules informational (`make lint-style`).
