# AuthZLab Threat Model

Companion: `docs/architecture/architecture.md` (how the controls are built),
`docs/vulnerabilities/` (per-lab walkthroughs, Phase 7 Batch 2).

## 1. Scope

In scope:

- Secure API (`src/authzlab/secure_app.py`, port 8000).
- Vulnerable lab API (`src/authzlab/vulnerable_app.py`, port 8001, localhost-only).
- PostgreSQL 18 data store, Docker Compose deployment, exploit runner (`scripts/exploit_scenarios.py`).

Explicitly out of scope for the MVP (accepted risks, see section 7):

- Rate limiting, CORS / trusted-host middleware, audit logging (`README.md` declares these out of scope).

## 2. Assets

| Asset | Why it matters |
|---|---|
| Invoice records (amounts, status, ownership) | Financial data; cross-tenant read/write is the primary loss |
| Tenant isolation boundary | The security property everything else rests on |
| JWT signing keys (RSA) | Forged tokens bypass all authorization |
| Password hashes | Credential theft on DB compromise; Argon2id raises the cost |
| Approval workflow integrity | Self-approval converts any approver into an unchecked spender |

## 3. Actors and roles

| Actor | Capability |
|---|---|
| Anonymous | `POST /api/v1/auth/token` only |
| MEMBER | Own invoices: create, read own, update own DRAFTs, submit own |
| APPROVER | Member + read all tenant invoices, approve others' SUBMITTED invoices |
| ADMIN | Approver + full tenant visibility |
| Cross-tenant attacker | Legitimate account in tenant A (e.g. `charlie@acme.com`, MEMBER) attacking tenant B resources |

Role enforcement lives in one place: `src/authzlab/application/policies/__init__.py`
(`ensure_role_permission`, line 29; view rules lines 75-85; approve rules lines 46-58).
Route handlers never check permissions.

## 4. Trust boundaries

1. **Client -> API**: untrusted input; JWT is the only identity. Validated in
   `src/authzlab/api/dependencies.py` (`get_current_user`, lines 42-83):
   header format, signature, `kid`, issuer/audience/expiry, user existence,
   active flag, token-tenant vs user-tenant match (lines 77-79).
2. **API -> DB**: connection string is trusted config; unreachable DB fails fast
   (5s connect timeout) and `/health/ready` returns a generic 503 with no driver
   internals (`src/authzlab/api/v1/__init__.py`, lines 251-266).
3. **Secure app <-> lab app**: separate FastAPI instances. The lab is
   localhost-only under every documented invocation (Compose binds
   `127.0.0.1`, `compose.yaml` lines 15/51-52/89-90) and refuses to build
   without `AUTHZLAB_LAB_MODE=true` (two gates:
   `src/authzlab/vulnerable_app.py` lines 41-48 and the app factory at line 300).
4. **Container boundary**: `appuser`, read-only FS, `cap_drop: ALL`,
   `no-new-privileges` (`compose.yaml` lines 35-43).

## 5. Threats per endpoint (STRIDE)

| Endpoint | Threat | Control |
|---|---|---|
| `POST /auth/token` | Credential stuffing (no rate limiting — accepted risk); user enumeration | Generic `AuthenticationError("Invalid credentials")` for unknown user, wrong password, and disabled account alike (`api/v1/__init__.py` lines 126-142) |
| `GET /invoices?tenant_id=` | Cross-tenant listing (LAB-01b) | `ensure_can_list_invoices` rejects foreign `tenant_id` (`policies/__init__.py` lines 88-93); members see only own invoices (`services/__init__.py` lines 138-142) |
| `GET /invoices/{id}` | BOLA / IDOR (LAB-01) | Tenant-scoped fetch (`repositories/__init__.py` line 118) + `ensure_can_view_invoice` (lines 75-85); cross-tenant reads return **404**, hiding existence (`api/errors.py` lines 81-89) |
| `PATCH /invoices/{id}` | Mass assignment (LAB-03) | Three layers: Pydantic `extra="forbid"` (`api/v1/__init__.py` lines 54-61), `validate_update_fields` protected-set (`policies/__init__.py` lines 96-126), fail-closed `repo.update(allowed=...)` (`repositories/__init__.py` lines 157-172) |
| `POST /invoices/{id}/approve` | BFLA by members (LAB-02); self-approval (LAB-04) | `ensure_can_approve`: same tenant + APPROVER/ADMIN + not-owner + SUBMITTED-only (`policies/__init__.py` lines 46-58); violations are 403 / 409 |
| `POST /invoices/{id}/submit` | State-machine bypass (approve a DRAFT) | Owner-only + DRAFT-only (`policies/__init__.py` lines 61-72) |

## 6. Token threats

| Threat | Control |
|---|---|
| Algorithm confusion (`alg=none`, RS->HS) | `algorithm: Literal["RS256"]` (`core/config.py` line 41); attacker key with correct `kid` still 401 (verified live, V3) |
| Key confusion / rotation without a store | `kid` written on encode (`infrastructure/security/__init__.py` lines 92/116) and enforced on decode (lines 127-131); single-key limitation documented in code |
| Refresh token presented as access token | `type` claim checked in `get_current_user` → 401, never 500 (`api/dependencies.py` lines 64-65; regression-tested) |
| Missing keys in production | `ensure_keys()` fails fast (`infrastructure/security/__init__.py` lines 42-44); development uses an ephemeral per-process keypair (tokens do not survive restarts — documented in `.env.example`) |

## 7. Accepted risks (documented limitations, not gaps)

- No rate limiting on `/auth/token` — brute-force mitigation is deployment concern.
- No CORS / trusted-host config, no audit logging — declared out of MVP scope.
- Ephemeral dev RSA keys; no key-rotation store (`kid` enforced for selection only).
- `total` in list responses is a pre-slice count (API contract, not a page count).
- Demo accounts share `password123` (including admins) with an explicit seed warning;
  safe only because every published port is localhost-bound.
- `get_current_user_optional` (`api/dependencies.py` lines 86-99) is unused
  defense surface; kept, catches `(AuthenticationError, InvalidTokenError)` explicitly.

## 8. Traceability (threat -> lab -> exploit -> fix -> test)

| Threat | Lab | Exploit scenario | Fix | Regression test |
|---|---|---|---|---|
| Cross-tenant read (BOLA) | LAB-01 (`vulnerable_app.py` lines 59-60) | `bola` | tenant-scoped repo + policy + 404 | `test_bola_blocked_in_secure` |
| Cross-tenant listing | LAB-01b (lines 68-69) | `bfla`* | `ensure_can_list_invoices` | `test_cross_tenant_listing_blocked_in_secure` |
| Member approval (BFLA) | LAB-02 (lines 135-136) | `bfla` | `ensure_can_approve` role check | `test_bfla_blocked_in_secure` |
| Protected-field write | LAB-03 (lines 96-97) | `mass_assignment` | 3-layer allow-list | `test_mass_assignment_*` (incl. M-1 inner-layer pin) |
| Self-approval | LAB-04 (lines 135-136) | `business_logic` | owner check in `ensure_can_approve` | `test_self_approval_blocked_in_secure` |

\* The runner's `bfla` scenario exercises approval; listing is covered by the
dedicated cross-tenant-listing tests. Live verification: 4/4 exploits succeed on
the lab (`:8001`), 0/4 on the secure app (`:8000`).
