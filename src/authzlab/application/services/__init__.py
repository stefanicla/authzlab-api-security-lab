"""Application services for business logic."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from authzlab.application.policies import AuthorizationPolicy
from authzlab.domain.exceptions import (
    AuthenticationError,
    BusinessRuleError,
    ResourceNotFoundError,
)
from authzlab.domain.models import Invoice, InvoiceStatus, Role, Tenant, User
from authzlab.infrastructure.database import get_session
from authzlab.infrastructure.repositories import InvoiceRepository, TenantRepository, UserRepository


class TenantService:
    """Service for tenant operations."""

    def __init__(self) -> None:
        self.tenant_repo = TenantRepository
        self.user_repo = UserRepository

    def create_tenant(self, name: str) -> Tenant:
        with get_session() as session:
            repo = self.tenant_repo(session)
            return repo.create(name)

    def get_tenant(self, tenant_id: UUID) -> Tenant | None:
        with get_session() as session:
            repo = self.tenant_repo(session)
            return repo.get_by_id(tenant_id)

    def list_tenants(self) -> Sequence[Tenant]:
        with get_session() as session:
            repo = self.tenant_repo(session)
            return repo.list_all()


class UserService:
    """Service for user operations."""

    def __init__(self) -> None:
        self.user_repo = UserRepository
        self.tenant_repo = TenantRepository

    def create_user(
        self,
        tenant_id: UUID,
        email: str,
        password_hash: str,
        role: Role = Role.MEMBER,
    ) -> User:
        with get_session() as session:
            tenant_repo = self.tenant_repo(session)
            tenant = tenant_repo.get_by_id(tenant_id)
            if not tenant:
                raise ResourceNotFoundError("Tenant", str(tenant_id))

            repo = self.user_repo(session)
            return repo.create(tenant_id, email, password_hash, role)

    def get_user(self, user_id: UUID) -> User | None:
        with get_session() as session:
            repo = self.user_repo(session)
            return repo.get_by_id(user_id)

    def get_user_by_email(self, email: str, tenant_id: UUID) -> User | None:
        with get_session() as session:
            repo = self.user_repo(session)
            return repo.get_by_email_and_tenant(email, tenant_id)

    def get_user_by_email_any_tenant(self, email: str) -> User | None:
        """Find user by email across all tenants (for login).

        L-4: the same address can exist in more than one tenant because
        uniqueness is only (tenant_id, email). Login carries no tenant selector,
        so picking an arbitrary match would issue a token scoped to the wrong
        tenant. An ambiguous identity is an authentication failure instead of a
        MultipleResultsFound crash (which surfaced as a 500).
        """
        with get_session() as session:
            repo = self.user_repo(session)
            matches = repo.find_by_email_any_tenant(email)
            if len(matches) > 1:
                raise AuthenticationError("Invalid credentials")
            return matches[0] if matches else None

    def get_users_by_tenant(self, tenant_id: UUID) -> Sequence[User]:
        with get_session() as session:
            repo = self.user_repo(session)
            return repo.get_by_tenant(tenant_id)


class InvoiceService:
    """Service for invoice operations with authorization."""

    def __init__(self) -> None:
        self.invoice_repo = InvoiceRepository
        self.user_repo = UserRepository

    def create_invoice(
        self,
        user: User,
        amount_cents: int,
        currency: str = "USD",
        description: str | None = None,
    ) -> Invoice:
        with get_session() as session:
            repo = self.invoice_repo(session)
            invoice = repo.create(
                tenant_id=user.tenant_id,
                owner_id=user.id,
                amount_cents=amount_cents,
                currency=currency,
                description=description,
            )
            session.refresh(invoice)
            return invoice

    def get_invoice(self, user: User, invoice_id: UUID) -> Invoice:
        with get_session() as session:
            repo = self.invoice_repo(session)
            invoice = repo.get_by_id_and_tenant(invoice_id, user.tenant_id)
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))
            AuthorizationPolicy.ensure_can_view_invoice(user, invoice)
            session.refresh(invoice)
            return invoice

    def list_invoices(self, user: User, tenant_id: UUID | None = None) -> Sequence[Invoice]:
        authorized_tenant_id = AuthorizationPolicy.ensure_can_list_invoices(user, tenant_id)

        with get_session() as session:
            repo = self.invoice_repo(session)
            # H-1: members see only their own invoices; approvers/admins see the tenant scope.
            if user.role in (Role.ADMIN, Role.APPROVER):
                invoices = repo.get_by_tenant(authorized_tenant_id)
            else:
                invoices = repo.get_by_tenant_and_owner(authorized_tenant_id, user.id)
            for invoice in invoices:
                session.refresh(invoice)
            return invoices

    def update_invoice(
        self,
        user: User,
        invoice_id: UUID,
        **fields: Any,
    ) -> Invoice:
        with get_session() as session:
            repo = self.invoice_repo(session)
            invoice = repo.get_by_id_and_tenant(invoice_id, user.tenant_id)
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))

            AuthorizationPolicy.ensure_can_view_invoice(user, invoice)

            # Only allow updating certain fields in DRAFT status
            if invoice.status != InvoiceStatus.DRAFT:
                raise BusinessRuleError(
                    "Can only update invoices in DRAFT status",
                    "INVALID_STATE_FOR_UPDATE",
                )

            allowed_fields = {"amount_cents", "currency", "description"}
            validated_fields = AuthorizationPolicy.validate_update_fields(
                user, set(fields.keys()), allowed_fields
            )

            invoice = repo.update(
                invoice,
                allowed=allowed_fields,
                **{k: fields[k] for k in validated_fields},
            )
            session.refresh(invoice)
            return invoice

    def submit_invoice(self, user: User, invoice_id: UUID) -> Invoice:
        with get_session() as session:
            repo = self.invoice_repo(session)
            invoice = repo.get_by_id_and_tenant(invoice_id, user.tenant_id)
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))

            AuthorizationPolicy.ensure_can_submit(user, invoice)

            invoice.status = InvoiceStatus.SUBMITTED
            session.flush()
            session.refresh(invoice)
            return invoice

    def approve_invoice(self, user: User, invoice_id: UUID) -> Invoice:
        with get_session() as session:
            repo = self.invoice_repo(session)
            invoice = repo.get_by_id_and_tenant(invoice_id, user.tenant_id)
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))

            AuthorizationPolicy.ensure_can_approve(user, invoice)

            invoice.status = InvoiceStatus.APPROVED
            invoice.approved_by = user.id
            session.flush()
            session.refresh(invoice)
            return invoice


# Factory functions to create service instances
def create_tenant_service() -> TenantService:
    return TenantService()


def create_user_service() -> UserService:
    return UserService()


def create_invoice_service() -> InvoiceService:
    return InvoiceService()
