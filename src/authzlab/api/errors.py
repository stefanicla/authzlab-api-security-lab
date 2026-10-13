"""API error handling and problem details."""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from authzlab.domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    BusinessRuleError,
    DomainException,
    InvalidTokenError,
    MassAssignmentError,
    ResourceNotFoundError,
    TenantIsolationError,
)


class ProblemDetail(BaseModel):
    """RFC 9457 Problem Details."""

    type: str = "about:blank"
    title: str
    status: int
    detail: str
    instance: str | None = None


def create_problem_response(
    request: Request,
    status_code: int,
    title: str,
    detail: str,
    type_uri: str = "about:blank",
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Create a standardized problem detail response."""
    problem = ProblemDetail(
        type=type_uri,
        title=title,
        status=status_code,
        detail=detail,
        instance=str(request.url),
    )
    return JSONResponse(
        status_code=status_code,
        content=problem.model_dump(),
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register exception handlers for domain exceptions."""

    @app.exception_handler(AuthenticationError)
    async def auth_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
        return create_problem_response(
            request,
            status.HTTP_401_UNAUTHORIZED,
            "Authentication Failed",
            exc.message,
            "https://authzlab.example.com/errors/authentication",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(InvalidTokenError)
    async def invalid_token_handler(request: Request, exc: InvalidTokenError) -> JSONResponse:
        return create_problem_response(
            request,
            status.HTTP_401_UNAUTHORIZED,
            "Invalid Token",
            exc.message,
            "https://authzlab.example.com/errors/invalid-token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(AuthorizationError)
    async def authz_error_handler(request: Request, exc: AuthorizationError) -> JSONResponse:
        if isinstance(exc, TenantIsolationError):
            # Return 404 to avoid disclosing resource existence across tenants
            return create_problem_response(
                request,
                status.HTTP_404_NOT_FOUND,
                "Not Found",
                "Resource not found",
                "https://authzlab.example.com/errors/not-found",
            )
        return create_problem_response(
            request,
            status.HTTP_403_FORBIDDEN,
            "Forbidden",
            exc.message,
            "https://authzlab.example.com/errors/authorization",
        )

    @app.exception_handler(ResourceNotFoundError)
    async def not_found_handler(request: Request, exc: ResourceNotFoundError) -> JSONResponse:
        return create_problem_response(
            request,
            status.HTTP_404_NOT_FOUND,
            "Not Found",
            exc.message,
            "https://authzlab.example.com/errors/not-found",
        )

    @app.exception_handler(BusinessRuleError)
    async def business_rule_handler(request: Request, exc: BusinessRuleError) -> JSONResponse:
        # L-F: MassAssignmentError is the only 422 (policy layer + lab
        # unknown-field mapping); every other business-rule breach is 409.
        if isinstance(exc, MassAssignmentError):
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        else:
            status_code = status.HTTP_409_CONFLICT

        return create_problem_response(
            request,
            status_code,
            "Business Rule Violation",
            exc.message,
            f"https://authzlab.example.com/errors/{exc.code.lower()}",
        )

    @app.exception_handler(DomainException)
    async def domain_error_handler(request: Request, exc: DomainException) -> JSONResponse:
        return create_problem_response(
            request,
            status.HTTP_400_BAD_REQUEST,
            "Bad Request",
            exc.message,
            f"https://authzlab.example.com/errors/{exc.code.lower()}",
        )
