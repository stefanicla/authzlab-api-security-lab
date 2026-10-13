"""Unit tests for authorization policies."""

from __future__ import annotations

from uuid import uuid4

import pytest

from authzlab.application.policies import AuthorizationPolicy
from authzlab.domain.exceptions import (
    AuthorizationError,
    BusinessRuleError,
    MassAssignmentError,
    SelfApprovalError,
    TenantIsolationError,
)
from authzlab.domain.models import Invoice, InvoiceStatus, Role, User


def make_user(tenant_id, role=Role.MEMBER, user_id=None):
    """Create a test user."""
    return User(
        id=user_id or uuid4(),
        tenant_id=tenant_id,
        email=f"user_{role.value}@test.com",
        password_hash="hash",
        role=role,
        is_active=True,
    )


def make_invoice(
    tenant_id, owner_id, status=InvoiceStatus.DRAFT, approved_by=None, invoice_id=None
):
    """Create a test invoice."""
    return Invoice(
        id=invoice_id or uuid4(),
        tenant_id=tenant_id,
        owner_id=owner_id,
        amount_cents=10000,
        currency="USD",
        description="Test",
        status=status,
        approved_by=approved_by,
    )


class TestAuthorizationPolicy:
    """Tests for AuthorizationPolicy."""

    def test_ensure_same_tenant_succeeds(self):
        """Same tenant should pass."""
        tenant_id = uuid4()
        user = make_user(tenant_id)
        AuthorizationPolicy.ensure_same_tenant(user, tenant_id)

    def test_ensure_same_tenant_fails_cross_tenant(self):
        """Cross-tenant should raise TenantIsolationError."""
        user = make_user(uuid4())
        with pytest.raises(TenantIsolationError):
            AuthorizationPolicy.ensure_same_tenant(user, uuid4())

    def test_ensure_role_permission_succeeds(self):
        """User with required role should pass."""
        user = make_user(uuid4(), Role.APPROVER)
        AuthorizationPolicy.ensure_role_permission(user, [Role.APPROVER, Role.ADMIN])

    def test_ensure_role_permission_fails(self):
        """User without required role should raise."""
        user = make_user(uuid4(), Role.MEMBER)
        with pytest.raises(AuthorizationError):
            AuthorizationPolicy.ensure_role_permission(user, [Role.APPROVER, Role.ADMIN])

    def test_ensure_invoice_owner_or_approver_owner(self):
        """Invoice owner should pass."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        invoice = make_invoice(tenant_id, owner.id)
        AuthorizationPolicy.ensure_invoice_owner_or_approver(owner, invoice)

    def test_ensure_invoice_owner_or_approver_approver(self):
        """Approver should pass for submitted invoice."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        approver = make_user(tenant_id, Role.APPROVER)
        invoice = make_invoice(tenant_id, owner.id, InvoiceStatus.SUBMITTED)
        AuthorizationPolicy.ensure_invoice_owner_or_approver(approver, invoice)

    def test_ensure_invoice_owner_or_approver_admin(self):
        """Admin should always pass."""
        tenant_id = uuid4()
        admin = make_user(tenant_id, Role.ADMIN)
        invoice = make_invoice(tenant_id, uuid4(), InvoiceStatus.APPROVED)
        AuthorizationPolicy.ensure_invoice_owner_or_approver(admin, invoice)

    def test_ensure_invoice_owner_or_approver_fails_member_other(self):
        """Member cannot access other's non-submitted invoice."""
        tenant_id = uuid4()
        member = make_user(tenant_id, Role.MEMBER)
        invoice = make_invoice(tenant_id, uuid4(), InvoiceStatus.DRAFT)
        with pytest.raises(AuthorizationError):
            AuthorizationPolicy.ensure_invoice_owner_or_approver(member, invoice)

    def test_ensure_can_approve_succeeds(self):
        """Approver can approve submitted invoice they don't own."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        approver = make_user(tenant_id, Role.APPROVER)
        invoice = make_invoice(tenant_id, owner.id, InvoiceStatus.SUBMITTED)
        AuthorizationPolicy.ensure_can_approve(approver, invoice)

    def test_ensure_can_approve_fails_self_approval(self):
        """Self-approval should raise SelfApprovalError."""
        tenant_id = uuid4()
        approver = make_user(tenant_id, Role.APPROVER)
        invoice = make_invoice(tenant_id, approver.id, InvoiceStatus.SUBMITTED)
        with pytest.raises(SelfApprovalError):
            AuthorizationPolicy.ensure_can_approve(approver, invoice)

    def test_ensure_can_approve_fails_wrong_status(self):
        """Cannot approve non-submitted invoice."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        approver = make_user(tenant_id, Role.APPROVER)
        invoice = make_invoice(tenant_id, owner.id, InvoiceStatus.DRAFT)
        with pytest.raises(BusinessRuleError):
            AuthorizationPolicy.ensure_can_approve(approver, invoice)

    def test_ensure_can_approve_fails_cross_tenant(self):
        """Cannot approve cross-tenant invoice."""
        approver = make_user(uuid4(), Role.APPROVER)
        invoice = make_invoice(uuid4(), uuid4(), InvoiceStatus.SUBMITTED)
        with pytest.raises(TenantIsolationError):
            AuthorizationPolicy.ensure_can_approve(approver, invoice)

    def test_ensure_can_submit_succeeds(self):
        """Owner can submit draft invoice."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        invoice = make_invoice(tenant_id, owner.id, InvoiceStatus.DRAFT)
        AuthorizationPolicy.ensure_can_submit(owner, invoice)

    def test_ensure_can_submit_fails_not_owner(self):
        """Non-owner cannot submit."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        other = make_user(tenant_id, Role.MEMBER)
        invoice = make_invoice(tenant_id, owner.id, InvoiceStatus.DRAFT)
        with pytest.raises(AuthorizationError):
            AuthorizationPolicy.ensure_can_submit(other, invoice)

    def test_ensure_can_submit_fails_wrong_status(self):
        """Cannot submit non-draft invoice."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        invoice = make_invoice(tenant_id, owner.id, InvoiceStatus.SUBMITTED)
        with pytest.raises(BusinessRuleError):
            AuthorizationPolicy.ensure_can_submit(owner, invoice)

    def test_ensure_can_view_invoice_admin(self):
        """Admin can view any invoice in tenant."""
        tenant_id = uuid4()
        admin = make_user(tenant_id, Role.ADMIN)
        invoice = make_invoice(tenant_id, uuid4(), InvoiceStatus.DRAFT)
        AuthorizationPolicy.ensure_can_view_invoice(admin, invoice)

    def test_ensure_can_view_invoice_approver(self):
        """Approver can view any invoice in tenant."""
        tenant_id = uuid4()
        approver = make_user(tenant_id, Role.APPROVER)
        invoice = make_invoice(tenant_id, uuid4(), InvoiceStatus.DRAFT)
        AuthorizationPolicy.ensure_can_view_invoice(approver, invoice)

    def test_ensure_can_view_invoice_owner(self):
        """Owner can view own invoice."""
        tenant_id = uuid4()
        owner = make_user(tenant_id, Role.MEMBER)
        invoice = make_invoice(tenant_id, owner.id, InvoiceStatus.DRAFT)
        AuthorizationPolicy.ensure_can_view_invoice(owner, invoice)

    def test_ensure_can_view_invoice_fails_member_other(self):
        """Member cannot view other's invoice."""
        tenant_id = uuid4()
        member = make_user(tenant_id, Role.MEMBER)
        invoice = make_invoice(tenant_id, uuid4(), InvoiceStatus.DRAFT)
        with pytest.raises(AuthorizationError):
            AuthorizationPolicy.ensure_can_view_invoice(member, invoice)

    def test_ensure_can_list_invoices_tenant_filter(self):
        """List with tenant filter validates access."""
        tenant_id = uuid4()
        user = make_user(tenant_id)
        result = AuthorizationPolicy.ensure_can_list_invoices(user, tenant_id)
        assert result == tenant_id

    def test_ensure_can_list_invoices_no_filter(self):
        """List without filter defaults to user's tenant."""
        tenant_id = uuid4()
        user = make_user(tenant_id)
        result = AuthorizationPolicy.ensure_can_list_invoices(user, None)
        assert result == tenant_id

    def test_ensure_can_list_invoices_cross_tenant_fails(self):
        """Cross-tenant list fails."""
        user = make_user(uuid4())
        with pytest.raises(TenantIsolationError):
            AuthorizationPolicy.ensure_can_list_invoices(user, uuid4())

    def test_validate_update_fields_allows_valid(self):
        """Valid fields should pass."""
        user = make_user(uuid4())
        allowed = {"amount_cents", "currency", "description"}
        result = AuthorizationPolicy.validate_update_fields(
            user, {"amount_cents", "description"}, allowed
        )
        assert result == {"amount_cents", "description"}

    def test_validate_update_fields_rejects_protected(self):
        """Protected fields should raise MassAssignmentError."""
        user = make_user(uuid4())
        with pytest.raises(MassAssignmentError) as exc:
            AuthorizationPolicy.validate_update_fields(
                user, {"amount_cents", "tenant_id", "owner_id"}, {"amount_cents"}
            )
        assert "tenant_id" in exc.value.fields
        assert "owner_id" in exc.value.fields

    def test_validate_update_fields_rejects_invalid(self):
        """Invalid fields should raise MassAssignmentError."""
        user = make_user(uuid4())
        with pytest.raises(MassAssignmentError) as exc:
            AuthorizationPolicy.validate_update_fields(
                user, {"amount_cents", "invalid_field"}, {"amount_cents"}
            )
        assert "invalid_field" in exc.value.fields
