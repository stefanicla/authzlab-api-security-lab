"""API v1 routes for AuthZLab."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from authzlab.api.dependencies import (
    get_current_user,
    get_invoice_service,
    get_token_manager,
    get_user_service,
)
from authzlab.application.services import InvoiceService, UserService
from authzlab.domain.models import Invoice, InvoiceStatus, User
from authzlab.domain.models import Role as Role
from authzlab.infrastructure.database import get_db_session
from authzlab.infrastructure.security import TokenManager, get_password_manager

router = APIRouter(prefix="/api/v1")


# --- Schemas ---


class TokenRequest(BaseModel):
    """Login request."""

    email: str
    password: str


class TokenResponse(BaseModel):
    """Token response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class InvoiceCreate(BaseModel):
    """Create invoice request."""

    amount_cents: int = Field(gt=0, description="Amount in cents")
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")
    description: str | None = Field(default=None, max_length=1000)


class InvoiceUpdate(BaseModel):
    """Update invoice request - only allowed fields."""

    model_config = ConfigDict(extra="forbid")

    amount_cents: int | None = Field(default=None, gt=0)
    currency: str | None = Field(default=None, pattern="^[A-Z]{3}$")
    description: str | None = Field(default=None, max_length=1000)


class InvoiceResponse(BaseModel):
    """Invoice response."""

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

    model_config = ConfigDict(from_attributes=True)

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def serialize_datetime(cls, v: Any) -> Any:
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return v


class InvoiceListResponse(BaseModel):
    """Paginated invoice list response."""

    items: list[InvoiceResponse]
    total: int


def _invoice_to_dict(invoice: Invoice) -> dict:
    """Convert SQLAlchemy Invoice model to dict for Pydantic validation."""
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


def _invoices_to_list(invoices: Sequence[Invoice]) -> list[dict]:
    """Convert list of SQLAlchemy Invoice models to list of dicts."""
    return [_invoice_to_dict(inv) for inv in invoices]


# --- Auth Endpoints ---


@router.post("/auth/token", response_model=TokenResponse, tags=["auth"])
async def login(
    request: TokenRequest,
    db: Session = Depends(get_db_session),
    token_manager: TokenManager = Depends(get_token_manager),
    user_service: UserService = Depends(get_user_service),
) -> TokenResponse:
    """Authenticate user and return JWT tokens."""
    user = user_service.get_user_by_email_any_tenant(request.email)

    if not user:
        from authzlab.domain.exceptions import AuthenticationError

        raise AuthenticationError("Invalid credentials")

    password_manager = get_password_manager()
    if not password_manager.verify_password(request.password, user.password_hash):
        from authzlab.domain.exceptions import AuthenticationError

        raise AuthenticationError("Invalid credentials")

    if not user.is_active:
        from authzlab.domain.exceptions import AuthenticationError

        raise AuthenticationError("Account disabled")

    access_token = token_manager.create_access_token(
        user.id, user.tenant_id, user.email, user.role.value
    )
    refresh_token = token_manager.create_refresh_token(user.id)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.get("/invoices", response_model=InvoiceListResponse, tags=["invoices"])
async def list_invoices(
    current_user: User = Depends(get_current_user),
    tenant_id: UUID | None = Query(None),
    status_filter: InvoiceStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    invoice_service: InvoiceService = Depends(get_invoice_service),
) -> InvoiceListResponse:
    """List invoices for the current user's tenant."""
    invoices = invoice_service.list_invoices(current_user, tenant_id)

    if status_filter:
        invoices = [inv for inv in invoices if inv.status == status_filter]

    total = len(invoices)
    items = invoices[offset : offset + limit]

    return InvoiceListResponse(
        items=[InvoiceResponse.model_validate(_invoice_to_dict(inv)) for inv in items],
        total=total,
    )


@router.post(
    "/invoices",
    response_model=InvoiceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["invoices"],
)
async def create_invoice(
    invoice_data: InvoiceCreate,
    current_user: User = Depends(get_current_user),
    invoice_service: InvoiceService = Depends(get_invoice_service),
) -> InvoiceResponse:
    """Create a new invoice."""
    invoice = invoice_service.create_invoice(
        current_user,
        amount_cents=invoice_data.amount_cents,
        currency=invoice_data.currency,
        description=invoice_data.description,
    )
    return InvoiceResponse.model_validate(_invoice_to_dict(invoice))


@router.get("/invoices/{invoice_id}", response_model=InvoiceResponse, tags=["invoices"])
async def get_invoice(
    invoice_id: UUID,
    current_user: User = Depends(get_current_user),
    invoice_service: InvoiceService = Depends(get_invoice_service),
) -> InvoiceResponse:
    """Get a specific invoice."""
    invoice = invoice_service.get_invoice(current_user, invoice_id)
    return InvoiceResponse.model_validate(_invoice_to_dict(invoice))


@router.patch("/invoices/{invoice_id}", response_model=InvoiceResponse, tags=["invoices"])
async def update_invoice(
    invoice_id: UUID,
    invoice_data: InvoiceUpdate,
    current_user: User = Depends(get_current_user),
    invoice_service: InvoiceService = Depends(get_invoice_service),
) -> InvoiceResponse:
    """Update an invoice (only in DRAFT status)."""
    update_data = invoice_data.model_dump(exclude_unset=True)
    invoice = invoice_service.update_invoice(current_user, invoice_id, **update_data)
    return InvoiceResponse.model_validate(_invoice_to_dict(invoice))


@router.post(
    "/invoices/{invoice_id}/submit",
    response_model=InvoiceResponse,
    tags=["invoices"],
)
async def submit_invoice(
    invoice_id: UUID,
    current_user: User = Depends(get_current_user),
    invoice_service: InvoiceService = Depends(get_invoice_service),
) -> InvoiceResponse:
    """Submit an invoice for approval."""
    invoice = invoice_service.submit_invoice(current_user, invoice_id)
    return InvoiceResponse.model_validate(_invoice_to_dict(invoice))


@router.post(
    "/invoices/{invoice_id}/approve",
    response_model=InvoiceResponse,
    tags=["invoices"],
)
async def approve_invoice(
    invoice_id: UUID,
    current_user: User = Depends(get_current_user),
    invoice_service: InvoiceService = Depends(get_invoice_service),
) -> InvoiceResponse:
    """Approve a submitted invoice."""
    invoice = invoice_service.approve_invoice(current_user, invoice_id)
    return InvoiceResponse.model_validate(_invoice_to_dict(invoice))


# --- Health Endpoints ---

health_router = APIRouter(prefix="/health", tags=["health"])


@health_router.get("/live")
async def liveness_check() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "alive"}


@health_router.get("/ready")
async def readiness_check(db: Session = Depends(get_db_session)) -> Any:
    """Readiness probe (M-1: generic 503, no driver internals leaked)."""
    import logging

    from fastapi.responses import JSONResponse
    from sqlalchemy import text

    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception:
        logging.getLogger(__name__).exception("readiness check failed")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not ready", "database": "unavailable"},
        )
