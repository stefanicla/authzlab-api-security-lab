"""Domain models for AuthZLab."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all database models."""


class Role(str, enum.Enum):
    """User roles in the system."""

    MEMBER = "member"
    APPROVER = "approver"
    ADMIN = "admin"


class InvoiceStatus(str, enum.Enum):
    """Invoice workflow statuses."""

    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"


class Tenant(Base):
    """Tenant (organization) model."""

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    users: Mapped[list[User]] = relationship(back_populates="tenant", lazy="selectin")
    invoices: Mapped[list[Invoice]] = relationship(back_populates="tenant", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Tenant(id={self.id}, name={self.name})>"


class User(Base):
    """User model with tenant membership and role."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(
        Enum(Role, native_enum=False), nullable=False, default=Role.MEMBER
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    tenant: Mapped[Tenant] = relationship(back_populates="users", lazy="selectin")
    owned_invoices: Mapped[list[Invoice]] = relationship(
        back_populates="owner", foreign_keys="Invoice.owner_id", lazy="selectin"
    )
    approved_invoices: Mapped[list[Invoice]] = relationship(
        back_populates="approver", foreign_keys="Invoice.approved_by", lazy="selectin"
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        Index("ix_user_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"


class Invoice(Base):
    """Invoice model with tenant isolation and workflow."""

    __tablename__ = "invoices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[InvoiceStatus] = mapped_column(
        Enum(InvoiceStatus, native_enum=False), nullable=False, default=InvoiceStatus.DRAFT
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    tenant: Mapped[Tenant] = relationship(back_populates="invoices", lazy="selectin")
    owner: Mapped[User] = relationship(
        back_populates="owned_invoices", foreign_keys=[owner_id], lazy="selectin"
    )
    approver: Mapped[User | None] = relationship(
        back_populates="approved_invoices", foreign_keys=[approved_by], lazy="selectin"
    )

    __table_args__ = (
        Index("ix_invoice_tenant_id", "tenant_id"),
        Index("ix_invoice_owner_id", "owner_id"),
        Index("ix_invoice_status", "status"),
        Index("ix_invoice_tenant_status", "tenant_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<Invoice(id={self.id}, amount={self.amount_cents}, status={self.status})>"
