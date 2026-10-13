# LAB-02: BFLA — Unauthorized Invoice Approval

- OWASP API Top 10: **API5:2023 Broken Function Level Authorization**
- CWE: **CWE-862 Missing Authorization**
- Threat model: `docs/threat-model/threat-model.md` section 5, row `POST /invoices/{id}/approve`

## Summary

Any authenticated user — including a MEMBER with no approval rights — can
approve any invoice, in any state. The lab approve path performs no role check,
no ownership check, and no state check. The secure app requires
APPROVER-or-ADMIN, forbids self-approval, and allows approval only from
SUBMITTED.

## Vulnerable code

`src/authzlab/vulnerable_app.py:135-147` — `VulnerableInvoiceService.approve_invoice`:

```python
invoice = repo.get_by_id(invoice_id)   # no tenant scope, no checks
invoice.status = InvoiceStatus.APPROVED
invoice.approved_by = user.id
```

No `ensure_can_approve` call anywhere on the path (this method also carries
LAB-04 — see `lab-04-self-approval.md`).

## Exploit

Preconditions: seeded DB, lab on `:8001`. Attacker `charlie@acme.com` (MEMBER);
target is Bob's SUBMITTED invoice (Acme).

Runner (uses the victim invoice id; any invoice id works in the lab):

```bash
uv run python scripts/exploit_scenarios.py --scenario bfla \
  --target http://127.0.0.1:8001 \
  --attacker charlie@acme.com --password password123 \
  --victim-invoice <BOB_SUBMITTED_UUID>
```

Equivalent curl:

```bash
curl -s -X POST http://127.0.0.1:8001/api/v1/invoices/<BOB_SUBMITTED_UUID>/approve \
  -H "Authorization: Bearer $TOKEN"
```

Lab response: **200** with `"status": "approved"` and `"approved_by": "<charlie>"`.
Note the lab also approves DRAFT invoices — there is no state machine at all.

## Impact

A MEMBER can approve arbitrary invoices — including other tenants' (combined
with LAB-01) — stamping them with their own identity as approver. Financial
workflow integrity is void: approval means nothing.

## Fix

`AuthorizationPolicy.ensure_can_approve` (`src/authzlab/application/policies/__init__.py:46-58`),
invoked by `InvoiceService.approve_invoice` (`services/__init__.py:182-195`):

1. `ensure_same_tenant` — cross-tenant approve is 404.
2. `ensure_role_permission(user, [APPROVER, ADMIN])` — members are 403.
3. Owner check — self-approval is 409 (`SelfApprovalError`).
4. `SUBMITTED`-only — approving a DRAFT is 409 (`BusinessRuleError`).

Secure behavior for Charlie's request: **403** `Insufficient role permissions`.

## Regression tests

- `test_bfla_blocked_in_secure` (403) / `test_bfla_works_in_vulnerable` (200,
  `"status": "approved"`)
- `test_legitimate_operations_work_in_secure` (Bob approving Charlie's
  SUBMITTED invoice still 200s — the fix does not break the real workflow)

## Defense-in-depth notes

- Role, ownership, and state are three *separate* checks in one policy method,
  each with a distinct status code (404 / 403 / 409). A future refactor that
  drops one check changes observable behavior the tests pin.
- `approved_by` is always the server-side caller identity
  (`services/__init__.py:192`) — clients can never nominate an approver,
  which also closes the LAB-03 variant of forging `approved_by`.
