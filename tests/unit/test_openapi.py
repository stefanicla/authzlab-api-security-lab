"""OpenAPI contract tests for the secure API."""

from __future__ import annotations

from authzlab.secure_app import create_secure_app


def test_secure_openapi_uses_resource_specific_tags() -> None:
    schema = create_secure_app().openapi()

    auth_path = schema["paths"]["/api/v1/auth/token"]
    assert list(auth_path) == ["post"]
    assert auth_path["post"]["tags"] == ["auth"]

    invoice_operations = (
        ("/api/v1/invoices", "get"),
        ("/api/v1/invoices", "post"),
        ("/api/v1/invoices/{invoice_id}", "get"),
        ("/api/v1/invoices/{invoice_id}", "patch"),
        ("/api/v1/invoices/{invoice_id}/submit", "post"),
        ("/api/v1/invoices/{invoice_id}/approve", "post"),
    )
    for path, method in invoice_operations:
        assert schema["paths"][path][method]["tags"] == ["invoices"]
