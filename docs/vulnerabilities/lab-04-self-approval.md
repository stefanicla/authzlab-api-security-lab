# LAB-04: Business Logic — Self-Approval Violation

- OWASP API Top 10: **API4:2023** (project mapping for approval-flow abuse;
  the missing separation-of-duties constraint)
- CWE: **CWE-840 Business Logic Errors**
- Threat model: `docs/threat-model/threat-model.md` section 5, row `POST /invoices/{id}/approve`

## Summary

The lab lets an approver approve their **own** invoice — the exact conflict of
interest an approval workflow exists to prevent. Same vulnerable method as
LAB-02 (`approve_invoice` checks nothing); this walkthrough isolates the
ownership dimension. The secure app rejects self-approval with 409.

## Vulnerable code

Same method as LAB-02, `src/authzlab/vulnerable_app.py:135-147`: no role
check, no owner check, no state check. The missing line is the secure app's

```python
if invoice.owner_id == user.id:
    raise SelfApprovalError
```

(`policies/__init__.py:51-52`).

## Exploit

Preconditions: seeded DB, lab on `:8001`. Actor is `bob@acme.com` (APPROVER —
no role trickery, purely a workflow violation); target is Bob's own SUBMITTED
invoice.

Runner:

```bash
uv run python scripts/exploit_scenarios.py --scenario business_logic \
  --target http://127.0.0.1:8001 \
  --attacker bob@acme.com --password password123 \
  --own-invoice <BOB_SUBMITTED_UUID>
```

Equivalent curl:

```bash
curl -s -X POST http://127.0.0.1:8001/api/v1/invoices/<BOB_SUBMITTED_UUID>/approve \
  -H "Authorization: Bearer $TOKEN"
```

Lab response: **200** with `"status": "approved"` and `"approved_by": "<bob>"` —
the requester approved themselves, stamped in the record.

## Impact

Separation-of-duties collapse: any approver is their own auditor. Combined with
LAB-03 (flip any invoice to SUBMITTED… actually to `approved` directly) the
workflow is decorative end to end.

## Fix

`ensure_can_approve` (`policies/__init__.py:46-58`) checks, in order: same
tenant → APPROVER/ADMIN role → **not the owner** → SUBMITTED state. The
self-approval branch raises `SelfApprovalError`, mapped to **409** with a
detail mentioning "own" (`api/errors.py:108-115`;
`test_self_approval_blocked_in_secure` asserts both).

Secure behavior for Bob's request: **409** `Business Rule Violation`.

## Regression tests

- `test_self_approval_blocked_in_secure` (409 + "own" in detail) /
  `test_self_approval_works_in_vulnerable` (200, `approved_by == bob`)
- `test_legitimate_operations_work_in_secure` (Bob approving *Charlie's*
  SUBMITTED invoice → 200: the constraint blocks self-dealing, not delegation)

## Defense-in-depth notes

- The 409-vs-403 split matters: 403 = "you lack the role" (fixable by asking
  an approver), 409 = "this transition is illegal for anyone in your position"
  (fixable only by changing *who* approves). Tests pin the exact code, not
  just the 4xx family.
- `SelfApprovalError` subclasses `BusinessRuleError`
  (`domain/exceptions.py`), so any handler gap degrades to 409, never to
  success — the exception hierarchy itself is a backstop.
