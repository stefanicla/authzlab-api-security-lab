"""Repository layer for data access."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from authzlab.domain.models import Invoice, InvoiceStatus, Role, Tenant, User


class TenantRepository:
    """Repository for tenant operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, name: str) -> Tenant:
        tenant = Tenant(name=name)
        self.session.add(tenant)
        self.session.flush()
        return tenant

    def get_by_id(self, tenant_id: UUID) -> Tenant | None:
        return self.session.get(Tenant, tenant_id)

    def get_by_name(self, name: str) -> Tenant | None:
        stmt = select(Tenant).where(Tenant.name == name)
        return self.session.execute(stmt).scalar_one_or_none()

    def list_all(self) -> Sequence[Tenant]:
        stmt = select(Tenant).order_by(Tenant.name)
        return self.session.execute(stmt).scalars().all()


class UserRepository:
    """Repository for user operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        tenant_id: UUID,
        email: str,
        password_hash: str,
        role: Role = Role.MEMBER,
    ) -> User:
        user = User(
            tenant_id=tenant_id,
            email=email,
            password_hash=password_hash,
            role=role,
        )
        self.session.add(user)
        self.session.flush()
        return user

    def get_by_id(self, user_id: UUID) -> User | None:
        return self.session.get(User, user_id)

    def get_by_email_and_tenant(self, email: str, tenant_id: UUID) -> User | None:
        stmt = select(User).where(User.email == email, User.tenant_id == tenant_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def find_by_email_any_tenant(self, email: str) -> Sequence[User]:
        """Every user with this email across all tenants.

        Login resolves identity by email alone and uniqueness is only
        (tenant_id, email), so the same address can legitimately exist in
        several tenants. Ordering by (created_at, id) keeps the result stable
        for callers that need to pick one; callers that care about the
        ambiguity must inspect the length instead of assuming a single row.
        """
        stmt = select(User).where(User.email == email).order_by(User.created_at, User.id)
        return self.session.execute(stmt).scalars().all()

    def get_by_tenant(self, tenant_id: UUID) -> Sequence[User]:
        stmt = select(User).where(User.tenant_id == tenant_id).order_by(User.email)
        return self.session.execute(stmt).scalars().all()

    def list_all(self) -> Sequence[User]:
        stmt = select(User).order_by(User.email)
        return self.session.execute(stmt).scalars().all()


class InvoiceRepository:
    """Repository for invoice operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        tenant_id: UUID,
        owner_id: UUID,
        amount_cents: int,
        currency: str = "USD",
        description: str | None = None,
    ) -> Invoice:
        invoice = Invoice(
            tenant_id=tenant_id,
            owner_id=owner_id,
            amount_cents=amount_cents,
            currency=currency,
            description=description,
        )
        self.session.add(invoice)
        self.session.flush()
        return invoice

    def get_by_id(self, invoice_id: UUID) -> Invoice | None:
        return self.session.get(Invoice, invoice_id)

    def get_by_id_and_tenant(self, invoice_id: UUID, tenant_id: UUID) -> Invoice | None:
        stmt = select(Invoice).where(Invoice.id == invoice_id, Invoice.tenant_id == tenant_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_owner(self, owner_id: UUID) -> Sequence[Invoice]:
        stmt = (
            select(Invoice).where(Invoice.owner_id == owner_id).order_by(Invoice.created_at.desc())
        )
        return self.session.execute(stmt).scalars().all()

    def get_by_tenant(self, tenant_id: UUID) -> Sequence[Invoice]:
        stmt = (
            select(Invoice)
            .where(Invoice.tenant_id == tenant_id)
            .order_by(Invoice.created_at.desc())
        )
        return self.session.execute(stmt).scalars().all()

    def get_by_tenant_and_owner(self, tenant_id: UUID, owner_id: UUID) -> Sequence[Invoice]:
        """Tenant-scoped, owner-scoped listing for least-privilege roles (H-1)."""
        stmt = (
            select(Invoice)
            .where(Invoice.tenant_id == tenant_id, Invoice.owner_id == owner_id)
            .order_by(Invoice.created_at.desc())
        )
        return self.session.execute(stmt).scalars().all()

    def get_by_tenant_and_status(self, tenant_id: UUID, status: InvoiceStatus) -> Sequence[Invoice]:
        stmt = (
            select(Invoice)
            .where(Invoice.tenant_id == tenant_id, Invoice.status == status)
            .order_by(Invoice.created_at.desc())
        )
        return self.session.execute(stmt).scalars().all()

    def list_all(self) -> Sequence[Invoice]:
        stmt = select(Invoice).order_by(Invoice.created_at.desc())
        return self.session.execute(stmt).scalars().all()

    def update(
        self,
        invoice: Invoice,
        *,
        allowed: set[str],
        **kwargs: Any,
    ) -> Invoice:
        """Apply updates; anything outside `allowed` is rejected (H-5, fail-closed)."""
        for key, value in kwargs.items():
            if key not in allowed:
                raise ValueError(f"Field not allowed: {key}")
            if not hasattr(invoice, key):
                raise ValueError(f"Unknown field: {key}")
            setattr(invoice, key, value)
        self.session.flush()
        return invoice
