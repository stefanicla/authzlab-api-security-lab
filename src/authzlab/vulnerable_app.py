"""Intentionally vulnerable FastAPI application for AuthZLab lab mode.

This is a completely separate implementation from the secure app,
with intentionally missing authorization checks for educational purposes.

SAFETY: importing this module requires AUTHZLAB_LAB_MODE=true.
See C-3.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, Header, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from authzlab.api.errors import register_exception_handlers
from authzlab.core.config import get_settings
from authzlab.domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    BusinessRuleError,
    InvalidTokenError,
    ResourceNotFoundError,
)
from authzlab.domain.models import Invoice, InvoiceStatus, User
from authzlab.infrastructure.database import (
    get_db_session,
    get_session,
    init_db,
)
from authzlab.infrastructure.repositories import InvoiceRepository, UserRepository
from authzlab.infrastructure.security import TokenManager, get_password_manager


def _require_lab_mode() -> None:
    """Enforce explicit lab opt-in at import/factory time (C-3)."""
    if os.environ.get("AUTHZLAB_LAB_MODE") != "true":
        raise RuntimeError(
            "Refusing to build vulnerable lab app: set AUTHZLAB_LAB_MODE=true. "
            "This application contains INTENTIONAL SECURITY VULNERABILITIES "
            "and must only run on localhost."
        )


# ============================================================================
# VULNERABLE SERVICE IMPLEMENTATIONS
# ============================================================================


class VulnerableInvoiceService:
    """Vulnerable invoice service with intentionally missing authorization checks."""

    def get_invoice(self, user: User, invoice_id: UUID) -> Invoice:
        """Vulnerable: No tenant isolation check (LAB-01)."""
        with get_session() as db:
            repo = InvoiceRepository(db)
            invoice = repo.get_by_id(invoice_id)  # No tenant filter!
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))
            return invoice

    def list_invoices(self, user: User, tenant_id: UUID | None = None) -> Sequence[Invoice]:
        """Vulnerable: No tenant isolation in listing (LAB-01)."""
        with get_session() as db:
            repo = InvoiceRepository(db)
            if tenant_id:
                return repo.get_by_tenant(tenant_id)  # Allows cross-tenant listing!
            return repo.list_all()  # Returns ALL invoices from ALL tenants!

    def create_invoice(
        self,
        user: User,
        amount_cents: int,
        currency: str = "USD",
        description: str | None = None,
    ) -> Invoice:
        """Create invoice (same as secure)."""
        with get_session() as db:
            repo = InvoiceRepository(db)
            invoice = repo.create(
                tenant_id=user.tenant_id,
                owner_id=user.id,
                amount_cents=amount_cents,
                currency=currency,
                description=description,
            )
            db.refresh(invoice)
            return invoice

    def update_invoice(self, user: User, invoice_id: UUID, **fields: Any) -> Invoice:
        """Vulnerable: Mass assignment - applies all fields (LAB-03).

        Deliberately bypasses Repository.update (which is fail-closed) with a
        lab-only direct assignment loop.
        """
        with get_session() as db:
            repo = InvoiceRepository(db)
            invoice = repo.get_by_id(invoice_id)
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))
            # Applies ALL fields including protected ones!
            for key, value in fields.items():
                if not hasattr(invoice, key):
                    raise ValueError(f"Unknown field: {key}")
                setattr(invoice, key, value)
            db.flush()
            db.refresh(invoice)
            return invoice

    def submit_invoice(self, user: User, invoice_id: UUID) -> Invoice:
        """Submit invoice (same as secure - owner only)."""
        with get_session() as db:
            repo = InvoiceRepository(db)
            invoice = repo.get_by_id_and_tenant(invoice_id, user.tenant_id)
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))
            if invoice.owner_id != user.id:
                raise AuthorizationError("Only the owner can submit this invoice")
            if invoice.status != InvoiceStatus.DRAFT:
                raise BusinessRuleError(
                    f"Cannot submit invoice in status {invoice.status.value}",
                    "INVALID_STATE_FOR_SUBMIT",
                )
            invoice.status = InvoiceStatus.SUBMITTED
            db.flush()
            db.refresh(invoice)
            return invoice

    def approve_invoice(self, user: User, invoice_id: UUID) -> Invoice:
        """Vulnerable: No role check, no self-approval check (LAB-02/LAB-04)."""
        with get_session() as db:
            repo = InvoiceRepository(db)
            invoice = repo.get_by_id(invoice_id)
            if not invoice:
                raise ResourceNotFoundError("Invoice", str(invoice_id))
            # No authorization checks!
            invoice.status = InvoiceStatus.APPROVED
            invoice.approved_by = user.id
            db.flush()
            db.refresh(invoice)
            return invoice


class VulnerableUserService:
    """User service (same as secure for login)."""

    def get_user(self, user_id: UUID) -> User | None:
        with get_session() as db:
            repo = UserRepository(db)
            return repo.get_by_id(user_id)

    def get_user_by_email_any_tenant(self, email: str) -> User | None:
        """Find user by email across all tenants (for login).

        L-4: the repository no longer assumes a single row for a cross-tenant
        email. Login is not one of LAB-01..LAB-04, so the lab keeps the same
        tenant-blind behaviour it always had and simply takes the first match
        instead of crashing with MultipleResultsFound.
        """
        with get_session() as db:
            repo = UserRepository(db)
            matches = repo.find_by_email_any_tenant(email)
            return matches[0] if matches else None


# ============================================================================
# AUTHENTICATION DEPENDENCIES (single definitions)
# ============================================================================

_token_manager: TokenManager | None = None


def get_token_manager() -> TokenManager:
    """Get or create the lab token manager (separate keypair from secure app)."""
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager()
        _token_manager.ensure_keys()
    return _token_manager


def get_vulnerable_invoice_service() -> VulnerableInvoiceService:
    return VulnerableInvoiceService()


def get_vulnerable_user_service() -> VulnerableUserService:
    return VulnerableUserService()


async def get_current_user(
    request: Request,
    authorization: str | None = Header(None),
    token_manager: TokenManager = Depends(get_token_manager),
    user_service: VulnerableUserService = Depends(get_vulnerable_user_service),
) -> User:
    """Extract and validate the current user from JWT token."""
    if not authorization:
        raise AuthenticationError("Missing authorization header")
    if not authorization.startswith("Bearer "):
        raise AuthenticationError("Invalid authorization header format")
    token = authorization[7:]
    try:
        payload = token_manager.verify_token(token)
    except ValueError as e:
        raise InvalidTokenError(str(e)) from e
    user_id = UUID(payload["sub"])
    user = user_service.get_user(user_id)
    if not user:
        raise InvalidTokenError("User not found")
    if not user.is_active:
        raise AuthenticationError("User account is disabled")
    token_tenant_id = UUID(payload["tenant_id"])
    if user.tenant_id != token_tenant_id:
        raise InvalidTokenError("Token tenant mismatch")
    request.state.token_payload = payload
    return user


# ============================================================================
# SCHEMAS
# ============================================================================


class TokenRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class InvoiceCreate(BaseModel):
    amount_cents: int = Field(gt=0)
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")
    description: str | None = Field(default=None, max_length=1000)


class InvoiceResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    owner_id: UUID
    amount_cents: int
    currency: str
    description: str | None
    status: InvoiceStatus
    approved_by: UUID | None
    created_at: str
    updated_at: str

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def serialize_datetime(cls, v: Any) -> Any:
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return v

    model_config = ConfigDict(from_attributes=True)


class InvoiceListResponse(BaseModel):
    items: list[InvoiceResponse]
    total: int


def _invoice_to_dict(invoice: Invoice) -> dict:
    return {
        "id": invoice.id,
        "tenant_id": invoice.tenant_id,
        "owner_id": invoice.owner_id,
        "amount_cents": invoice.amount_cents,
        "currency": invoice.currency,
        "description": invoice.description,
        "status": invoice.status,
        "approved_by": invoice.approved_by,
        "created_at": invoice.created_at.isoformat() if invoice.created_at else None,
        "updated_at": invoice.updated_at.isoformat() if invoice.updated_at else None,
    }


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler."""
    _require_lab_mode()
    if os.environ.get("AUTHZLAB_LAB_ALLOW_EXTERNAL") == "true":
        print("WARNING: Lab application configured to allow external access!")
        print("Ensure this is only running on localhost.")
    init_db()
    yield


def create_vulnerable_app() -> FastAPI:
    """Create the vulnerable FastAPI application (single definition)."""
    _require_lab_mode()
    settings = get_settings()

    app = FastAPI(
        title=f"{settings.app_name} (LAB - VULNERABLE)",
        version=settings.app_version,
        description="AuthZLab - INTENTIONALLY VULNERABLE Multi-tenant Invoice API",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    register_exception_handlers(app)

    @app.post("/api/v1/auth/token", response_model=TokenResponse, tags=["auth"])
    async def login(
        request: TokenRequest,
        user_service: VulnerableUserService = Depends(get_vulnerable_user_service),
        token_manager: TokenManager = Depends(get_token_manager),
    ) -> TokenResponse:
        user = user_service.get_user_by_email_any_tenant(request.email)
        if not user:
            raise AuthenticationError("Invalid credentials")
        password_manager = get_password_manager()
        if not password_manager.verify_password(request.password, user.password_hash):
            raise AuthenticationError("Invalid credentials")
        if not user.is_active:
            raise AuthenticationError("Account disabled")
        access_token = token_manager.create_access_token(
            user.id, user.tenant_id, user.email, user.role.value
        )
        refresh_token = token_manager.create_refresh_token(user.id)
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    @app.get("/api/v1/invoices", response_model=InvoiceListResponse)
    async def list_invoices(
        current_user: User = Depends(get_current_user),
        tenant_id: UUID | None = Query(None),
        status_filter: InvoiceStatus | None = Query(None, alias="status"),
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
        invoice_service: VulnerableInvoiceService = Depends(get_vulnerable_invoice_service),
    ) -> InvoiceListResponse:
        invoices = invoice_service.list_invoices(current_user, tenant_id)
        if status_filter:
            invoices = [inv for inv in invoices if inv.status == status_filter]
        total = len(invoices)
        items = invoices[offset : offset + limit]
        return InvoiceListResponse(
            items=[InvoiceResponse.model_validate(_invoice_to_dict(inv)) for inv in items],
            total=total,
        )

    @app.post(
        "/api/v1/invoices", response_model=InvoiceResponse, status_code=status.HTTP_201_CREATED
    )
    async def create_invoice(
        invoice_data: InvoiceCreate,
        current_user: User = Depends(get_current_user),
        invoice_service: VulnerableInvoiceService = Depends(get_vulnerable_invoice_service),
    ) -> InvoiceResponse:
        invoice = invoice_service.create_invoice(
            current_user,
            amount_cents=invoice_data.amount_cents,
            currency=invoice_data.currency,
            description=invoice_data.description,
        )
        return InvoiceResponse.model_validate(_invoice_to_dict(invoice))

    @app.get("/api/v1/invoices/{invoice_id}", response_model=InvoiceResponse)
    async def get_invoice(
        invoice_id: UUID,
        current_user: User = Depends(get_current_user),
        invoice_service: VulnerableInvoiceService = Depends(get_vulnerable_invoice_service),
    ) -> InvoiceResponse:
        invoice = invoice_service.get_invoice(current_user, invoice_id)
        return InvoiceResponse.model_validate(_invoice_to_dict(invoice))

    @app.patch("/api/v1/invoices/{invoice_id}", response_model=InvoiceResponse)
    async def update_invoice(
        invoice_id: UUID,
        invoice_data: dict[str, Any],
        current_user: User = Depends(get_current_user),
        invoice_service: VulnerableInvoiceService = Depends(get_vulnerable_invoice_service),
    ) -> InvoiceResponse:
        """Vulnerable update endpoint - allows mass assignment (LAB-03)."""
        from authzlab.domain.exceptions import MassAssignmentError

        try:
            invoice = invoice_service.update_invoice(current_user, invoice_id, **invoice_data)
        except ValueError as e:
            # M-B: unknown fields are a clean 422, like the secure app.
            raise MassAssignmentError(str(e), fields=[]) from e
        return InvoiceResponse.model_validate(_invoice_to_dict(invoice))

    @app.post("/api/v1/invoices/{invoice_id}/submit", response_model=InvoiceResponse)
    async def submit_invoice(
        invoice_id: UUID,
        current_user: User = Depends(get_current_user),
        invoice_service: VulnerableInvoiceService = Depends(get_vulnerable_invoice_service),
    ) -> InvoiceResponse:
        invoice = invoice_service.submit_invoice(current_user, invoice_id)
        return InvoiceResponse.model_validate(_invoice_to_dict(invoice))

    @app.post("/api/v1/invoices/{invoice_id}/approve", response_model=InvoiceResponse)
    async def approve_invoice(
        invoice_id: UUID,
        current_user: User = Depends(get_current_user),
        invoice_service: VulnerableInvoiceService = Depends(get_vulnerable_invoice_service),
    ) -> InvoiceResponse:
        invoice = invoice_service.approve_invoice(current_user, invoice_id)
        return InvoiceResponse.model_validate(_invoice_to_dict(invoice))

    @app.get("/health/live")
    async def liveness_check() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready")
    async def readiness_check(db: Session = Depends(get_db_session)) -> Any:
        import logging

        from fastapi import status as http_status
        from fastapi.responses import JSONResponse
        from sqlalchemy import text

        try:
            db.execute(text("SELECT 1"))
            return {"status": "ready", "database": "connected"}
        except Exception:
            logging.getLogger(__name__).exception("readiness check failed")
            return JSONResponse(
                status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "not ready", "database": "unavailable"},
            )

    return app


_require_lab_mode()
app = create_vulnerable_app()


def main() -> None:
    """Entry point for running the vulnerable lab application."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "authzlab.vulnerable_app:app",
        host=settings.host,
        port=settings.port + 1,
        workers=1,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
