"""API dependencies for authentication and authorization."""

from __future__ import annotations

from uuid import UUID

from fastapi import Depends, Header, Request

from authzlab.application.services import (
    InvoiceService,
    UserService,
    create_invoice_service,
    create_user_service,
)
from authzlab.domain.exceptions import AuthenticationError, InvalidTokenError
from authzlab.domain.models import User
from authzlab.infrastructure.security import TokenManager

# Global token manager instance
_token_manager: TokenManager | None = None


def get_token_manager() -> TokenManager:
    """Get or create the token manager (persistent keys in prod, see H-2)."""
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager()
        _token_manager.ensure_keys()
    return _token_manager


def get_user_service() -> UserService:
    """Get user service instance."""
    return create_user_service()


def get_invoice_service() -> InvoiceService:
    """Get invoice service instance."""
    return create_invoice_service()


async def get_current_user(
    request: Request,
    authorization: str | None = Header(None),
    token_manager: TokenManager = Depends(get_token_manager),
    user_service: UserService = Depends(get_user_service),
) -> User:
    """Extract and validate the current user from JWT token."""
    if not authorization:
        raise AuthenticationError("Missing authorization header")

    if not authorization.startswith("Bearer "):
        raise AuthenticationError("Invalid authorization header format")

    token = authorization[7:]  # Remove "Bearer "

    try:
        payload = token_manager.verify_token(token)
    except ValueError as e:
        raise InvalidTokenError(str(e)) from e

    # H-2: refresh tokens are valid cryptograms but carry no tenant scope;
    # presenting one as an access token is a 401, never a 500.
    if payload.get("type", "access") != "access":
        raise InvalidTokenError("Refresh token presented as access token")

    user_id = UUID(payload["sub"])
    user = user_service.get_user(user_id)

    if not user:
        raise InvalidTokenError("User not found")

    if not user.is_active:
        raise AuthenticationError("User account is disabled")

    # Attach tenant_id from token for verification
    token_tenant_id = UUID(payload["tenant_id"])
    if user.tenant_id != token_tenant_id:
        raise InvalidTokenError("Token tenant mismatch")

    # Attach payload to request state for downstream use
    request.state.token_payload = payload
    return user


async def get_current_user_optional(
    request: Request,
    authorization: str | None = Header(None),
    token_manager: TokenManager = Depends(get_token_manager),
    user_service: UserService = Depends(get_user_service),
) -> User | None:
    """Get current user if authenticated, otherwise return None."""
    if not authorization or not authorization.startswith("Bearer "):
        return None

    try:
        return await get_current_user(request, authorization, token_manager, user_service)
    except AuthenticationError, InvalidTokenError:
        return None
