"""Domain exceptions for AuthZLab."""

from __future__ import annotations


class DomainException(Exception):
    """Base exception for domain errors."""

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__


class AuthorizationError(DomainException):
    """Raised when authorization check fails."""

    def __init__(self, message: str = "Access denied"):
        super().__init__(message, "AUTHORIZATION_ERROR")


class TenantIsolationError(AuthorizationError):
    """Raised when cross-tenant access is attempted."""

    def __init__(self, message: str = "Cross-tenant access denied"):
        super().__init__(message)


class RolePermissionError(AuthorizationError):
    """Raised when role lacks required permission."""

    def __init__(self, message: str = "Insufficient role permissions"):
        super().__init__(message)


class BusinessRuleError(DomainException):
    """Raised when business rule is violated."""

    def __init__(self, message: str, code: str = "BUSINESS_RULE_ERROR"):
        super().__init__(message, code)


class SelfApprovalError(BusinessRuleError):
    """Raised when user attempts to approve their own invoice."""

    def __init__(self, message: str = "Users cannot approve their own invoices"):
        super().__init__(message, "SELF_APPROVAL_ERROR")


class InvalidStateTransitionError(BusinessRuleError):
    """Raised when invoice state transition is invalid."""

    def __init__(self, message: str = "Invalid invoice state transition"):
        super().__init__(message, "INVALID_STATE_TRANSITION")


class MassAssignmentError(BusinessRuleError):
    """Raised when attempt to modify protected fields."""

    def __init__(
        self,
        message: str = "Modification of protected fields not allowed",
        fields: list[str] | None = None,
    ):
        super().__init__(message, "MASS_ASSIGNMENT_ERROR")
        self.fields = fields or []


class ResourceNotFoundError(DomainException):
    """Raised when requested resource does not exist."""

    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(f"{resource_type} not found: {resource_id}", "RESOURCE_NOT_FOUND")
        self.resource_type = resource_type
        self.resource_id = resource_id


class AuthenticationError(DomainException):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "AUTHENTICATION_ERROR")


class InvalidTokenError(AuthenticationError):
    """Raised when JWT token is invalid."""

    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message)
