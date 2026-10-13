# LAB-03: Mass Assignment — Protected Field Modification

- OWASP API Top 10: **API3:2023 Broken Object Property Level Authorization**
  (mass assignment is the canonical write-side BOPLA case)
- CWE: **CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes**
- Threat model: `docs/threat-model/threat-model.md` section 5, row `PATCH /invoices/{id}`

## Summary

The lab update endpoint applies **every** client-supplied field to the invoice,
including `status`, `tenant_id`, `owner_id`, and `approved_by`. An attacker can
approve their own invoice, reassign ownership, or move it to another tenant
with a single PATCH. The secure app defends in three independent layers, any
one of which blocks the attack alone.

## Vulnerable code

`src/authzlab/vulnerable_app.py:96-114` — `VulnerableInvoiceService.update_invoice`
deliberately bypasses the fail-closed repository with a direct assignment loop:

```python
for key, value in fields.items():
    if not hasattr(invoice, key):
        raise ValueError(f"Unknown field: {key}")
    setattr(invoice, key, value)
```

(`hasattr` is no protection — every protected field *is* an attribute.)

## Exploit

Preconditions: seeded DB, lab on `:8001`. Attacker uses their **own** invoice
(`Office supplies`) — no cross-tenant access needed, which is what makes mass
assignment nasty.

Runner (FK-safe payload: only `status`, a protected non-FK field, is flipped —
fabricated UUIDs would 500 on the FK constraint before proving anything):

```bash
uv run python scripts/exploit_scenarios.py --scenario mass_assignment \
  --target http://127.0.0.1:8001 \
  --attacker charlie@acme.com --password password123 \
  --own-invoice <OWN_INVOICE_UUID>
```

Equivalent curl:

```bash
curl -s -X PATCH http://127.0.0.1:8001/api/v1/invoices/<OWN_INVOICE_UUID> \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"amount_cents":999999,"status":"approved"}'
```

Lab response: **200** with `"status": "approved"` — persisted. The full
multi-field payload (`tenant_id`, `owner_id`, `approved_by` with real ids) is
covered by `test_mass_assignment_works_in_vulnerable`, which asserts all three
persist.

## Impact

Privilege escalation without any role: self-approval via `status`, blame
shifting via `owner_id`/`approved_by`, tenant hopping via `tenant_id`. One
request, no special permissions.

## Fix

Three layers, outer to inner (`docs/architecture/architecture.md` section 2):

1. **Pydantic** — `InvoiceUpdate` declares only `amount_cents`/`currency`/
   `description` with `extra="forbid"` (`api/v1/__init__.py:53-60`): unknown
   fields are 422 before any business logic runs.
2. **Policy** — `validate_update_fields` raises `MassAssignmentError` on any
   protected field (`id`, `tenant_id`, `owner_id`, `status`, `approved_by`,
   timestamps) (`policies/__init__.py:96-126`) → 422 via `api/errors.py:112-113`.
3. **Repository** — `update()` takes `allowed` as a *required* kw-only argument
   with no default; anything outside it raises `ValueError`
   (`repositories/__init__.py:149-159`). Fail-closed by construction: a caller
   that forgets the allow-list gets a `TypeError`, not an open update.

Secure behavior for the exploit PATCH: **422**.

## Regression tests

- `test_mass_assignment_blocked_in_secure` (multi-field → 422, outer layer)
- `test_mass_assignment_single_protected_field_blocked_in_secure`
  (`{"status": "approved"}` alone → 422)
- `test_mass_assignment_inner_layer_rejects_single_protected_field` (M-1):
  calls `InvoiceService.update_invoice` **directly**, bypassing Pydantic, and
  asserts `MassAssignmentError` — pins the inner layer independently.
  Negative control: removing validation makes this test fail (the repo raises
  `ValueError` instead), so the test genuinely distinguishes fix from bug.
- `test_mass_assignment_works_in_vulnerable` (lab persists the flip)

## Defense-in-depth notes

- The M-1 test exists because the HTTP tests alone cannot pin the inner layer:
  Pydantic rejects first, so widening the service allow-list would still pass
  them. Always test the layer beneath the one that fires.
- Unknown fields are 422 in *both* apps (lab maps them via `extra="forbid"`-style
  handling, `vulnerable_app.py:385-387`) — only *known-protected* fields
  distinguish lab from secure.
