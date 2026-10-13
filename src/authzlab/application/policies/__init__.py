"""Application policies for authorization."""

from __future__ import annotations

from uuid import UUID

from authzlab.domain.exceptions import (
    AuthorizationError,
    BusinessRuleError,
    MassAssignmentError,
    SelfApprovalError,
    TenantIsolationError,
)
from authzlab.domain.models import Invoice, InvoiceStatus, Role, User


class AuthorizationPolicy:
    """Centralized authorization decisions."""

    @staticmethod
    def ensure_same_tenant(user: User, resource_tenant_id: UUID) -> None:
        """Ensure user belongs to the same tenant as the resource."""
        if user.tenant_id != resource_tenant_id:
            raise TenantIsolationError(
                f"User {user.id} cannot access tenant {resource_tenant_id} resources"
            )

    @staticmethod
    def ensure_role_permission(user: User, required_roles: list[Role]) -> None:
        """Ensure user has one of the required roles (L-5: no role enumeration)."""
        if user.role not in required_roles:
            raise AuthorizationError("Insufficient role permissions")

    @staticmethod
    def ensure_invoice_owner_or_approver(user: User, invoice: Invoice) -> None:
        """Ensure user is the owner or an approver/admin for the invoice."""
        if user.role == Role.ADMIN:
            return
        if invoice.owner_id == user.id:
            return
        if user.role == Role.APPROVER and invoice.status == InvoiceStatus.SUBMITTED:
            return
        raise AuthorizationError("Insufficient permissions for this invoice")

    @staticmethod
    def ensure_can_approve(user: User, invoice: Invoice) -> None:
        """Ensure user can approve the given invoice."""
        AuthorizationPolicy.ensure_same_tenant(user, invoice.tenant_id)
        AuthorizationPolicy.ensure_role_permission(user, [Role.APPROVER, Role.ADMIN])

        if invoice.owner_id == user.id:
            raise SelfApprovalError

        if invoice.status != InvoiceStatus.SUBMITTED:
            raise BusinessRuleError(
                f"Cannot approve invoice in status {invoice.status.value}",
                "INVALID_STATE_FOR_APPROVAL",
            )

    @staticmethod
    def ensure_can_submit(user: User, invoice: Invoice) -> None:
        """Ensure user can submit the given invoice."""
        AuthorizationPolicy.ensure_same_tenant(user, invoice.tenant_id)

        if invoice.owner_id != user.id:
            raise AuthorizationError("Only the owner can submit this invoice")

        if invoice.status != InvoiceStatus.DRAFT:
            raise BusinessRuleError(
                f"Cannot submit invoice in status {invoice.status.value}",
                "INVALID_STATE_FOR_SUBMIT",
            )

    @staticmethod
    def ensure_can_view_invoice(user: User, invoice: Invoice) -> None:
        """Ensure user can view the given invoice."""
        AuthorizationPolicy.ensure_same_tenant(user, invoice.tenant_id)

        # Admins and approvers can view all invoices in their tenant
        if user.role in (Role.ADMIN, Role.APPROVER):
            return

        # Members can only view their own invoices
        if invoice.owner_id != user.id:
            raise AuthorizationError("Members can only view their own invoices")

    @staticmethod
    def ensure_can_list_invoices(user: User, requested_tenant_id: UUID | None = None) -> UUID:
        """Ensure user can list invoices and return the authorized tenant_id."""
        if requested_tenant_id is not None:
            AuthorizationPolicy.ensure_same_tenant(user, requested_tenant_id)
            return requested_tenant_id
        return user.tenant_id

    @staticmethod
    def validate_update_fields(
        user: User,
        provided_fields: set[str],
        allowed_fields: set[str],
    ) -> set[str]:
        """Validate that only allowed fields are being updated."""
        protected_fields = {
            "id",
            "tenant_id",
            "owner_id",
            "status",
            "approved_by",
            "created_at",
            "updated_at",
        }

        unauthorized = provided_fields & protected_fields
        if unauthorized:
            raise MassAssignmentError(
                f"Cannot modify protected fields: {', '.join(sorted(unauthorized))}",
                fields=sorted(unauthorized),
            )

        invalid = provided_fields - allowed_fields - protected_fields
        if invalid:
            raise MassAssignmentError(
                f"Invalid fields: {', '.join(sorted(invalid))}",
                fields=sorted(invalid),
            )

        return provided_fields & allowed_fields
