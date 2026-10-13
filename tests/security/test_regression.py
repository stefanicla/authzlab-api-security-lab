"""Security regression tests - verify vulnerabilities are fixed in secure app."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from authzlab.infrastructure.database import drop_db, get_session, init_db
from authzlab.secure_app import app as secure_app

os.environ["AUTHZLAB_LAB_MODE"] = "true"

from authzlab.vulnerable_app import app as vulnerable_app  # noqa: E402


def test_lab_gate_requires_opt_in():
    """The lab factory must refuse to build without explicit opt-in (C-3/H-4)."""
    import importlib

    old = os.environ.pop("AUTHZLAB_LAB_MODE", None)
    try:
        import authzlab.vulnerable_app as mod

        importlib.reload(mod)
        raise AssertionError("expected RuntimeError without AUTHZLAB_LAB_MODE=true")
    except RuntimeError:
        pass
    finally:
        if old is not None:
            os.environ["AUTHZLAB_LAB_MODE"] = old
        else:
            os.environ["AUTHZLAB_LAB_MODE"] = "true"
        importlib.reload(mod)


# Test data fixtures
@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Set up test database."""
    drop_db()
    init_db()
    yield
    drop_db()


@pytest.fixture(scope="session")
def test_setup():
    """Create test tenants, users, and invoices."""
    from authzlab.domain.models import InvoiceStatus, Role
    from authzlab.infrastructure.repositories import (
        InvoiceRepository,
        TenantRepository,
        UserRepository,
    )
    from authzlab.infrastructure.security import PasswordManager

    with get_session() as db_session:
        tenant_repo = TenantRepository(db_session)
        user_repo = UserRepository(db_session)
        invoice_repo = InvoiceRepository(db_session)
        password_mgr = PasswordManager()

        # Tenant A (Acme Corp)
        tenant_a = tenant_repo.get_by_name("Acme Corp")
        if not tenant_a:
            tenant_a = tenant_repo.create("Acme Corp")

        # Tenant B (Globex Inc)
        tenant_b = tenant_repo.get_by_name("Globex Inc")
        if not tenant_b:
            tenant_b = tenant_repo.create("Globex Inc")

        # Users in Tenant A
        alice = user_repo.get_by_email_and_tenant("alice@acme.com", tenant_a.id)
        if not alice:
            alice = user_repo.create(
                tenant_a.id, "alice@acme.com", password_mgr.hash_password("password123"), Role.ADMIN
            )

        bob = user_repo.get_by_email_and_tenant("bob@acme.com", tenant_a.id)
        if not bob:
            bob = user_repo.create(
                tenant_a.id,
                "bob@acme.com",
                password_mgr.hash_password("password123"),
                Role.APPROVER,
            )

        charlie = user_repo.get_by_email_and_tenant("charlie@acme.com", tenant_a.id)
        if not charlie:
            charlie = user_repo.create(
                tenant_a.id,
                "charlie@acme.com",
                password_mgr.hash_password("password123"),
                Role.MEMBER,
            )

        # User in Tenant B
        eve = user_repo.get_by_email_and_tenant("eve@globex.com", tenant_b.id)
        if not eve:
            eve = user_repo.create(
                tenant_b.id, "eve@globex.com", password_mgr.hash_password("password123"), Role.ADMIN
            )

        # Invoices
        # Charlie's draft invoice
        charlie_draft = invoice_repo.create(
            tenant_id=tenant_a.id,
            owner_id=charlie.id,
            amount_cents=10000,
            currency="USD",
            description="Charlie's draft",
        )

        # Charlie's submitted invoice
        charlie_submitted = invoice_repo.create(
            tenant_id=tenant_a.id,
            owner_id=charlie.id,
            amount_cents=20000,
            currency="USD",
            description="Charlie's submitted",
        )
        charlie_submitted.status = InvoiceStatus.SUBMITTED

        # Bob's submitted invoice
        bob_submitted = invoice_repo.create(
            tenant_id=tenant_a.id,
            owner_id=bob.id,
            amount_cents=30000,
            currency="USD",
            description="Bob's submitted",
        )
        bob_submitted.status = InvoiceStatus.SUBMITTED

        # Eve's invoice (Tenant B)
        eve_invoice = invoice_repo.create(
            tenant_id=tenant_b.id,
            owner_id=eve.id,
            amount_cents=50000,
            currency="EUR",
            description="Eve's invoice",
        )
        # eve_invoice stays as DRAFT (default)

        db_session.commit()

        return {
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "alice": alice,
            "bob": bob,
            "charlie": charlie,
            "eve": eve,
            "charlie_draft": charlie_draft,
            "charlie_submitted": charlie_submitted,
            "bob_submitted": bob_submitted,
            "eve_invoice": eve_invoice,
        }


@pytest.fixture(scope="session")
async def secure_client():
    """Secure app test client."""
    transport = ASGITransport(app=secure_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(scope="session")
async def vulnerable_client():
    """Vulnerable app test client."""
    transport = ASGITransport(app=vulnerable_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(scope="session")
async def auth_tokens(secure_client, test_setup):
    """Get auth tokens by logging in via secure app."""
    tokens = {}
    for email in ["alice@acme.com", "bob@acme.com", "charlie@acme.com", "eve@globex.com"]:
        response = await secure_client.post(
            "/api/v1/auth/token",
            json={"email": email, "password": "password123"},
        )
        assert response.status_code == 200, f"Login failed for {email}: {response.text}"
        tokens[email] = response.json()["access_token"]
    return tokens


@pytest.fixture(scope="session")
async def lab_tokens(vulnerable_client, test_setup):
    """Get auth tokens by logging in via lab app (separate keypair, see H-2)."""
    tokens = {}
    for email in ["alice@acme.com", "bob@acme.com", "charlie@acme.com", "eve@globex.com"]:
        response = await vulnerable_client.post(
            "/api/v1/auth/token",
            json={"email": email, "password": "password123"},
        )
        assert response.status_code == 200, f"Lab login failed for {email}: {response.text}"
        tokens[email] = response.json()["access_token"]
    return tokens


class TestSecurityRegression:
    """Security regression tests - verify exploits are blocked in secure app."""

    # LAB-01: BOLA/IDOR - Cross-tenant access
    async def test_bola_blocked_in_secure(self, secure_client, auth_tokens, test_setup):
        """Secure app blocks cross-tenant invoice access."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        response = await secure_client.get(
            f"/api/v1/invoices/{test_setup['eve_invoice'].id}",
            headers=headers,
        )
        assert response.status_code == 404  # Hide existence

    async def test_bola_works_in_vulnerable(self, vulnerable_client, lab_tokens, test_setup):
        """Vulnerable app allows cross-tenant invoice access."""
        headers = {"Authorization": f"Bearer {lab_tokens['charlie@acme.com']}"}
        response = await vulnerable_client.get(
            f"/api/v1/invoices/{test_setup['eve_invoice'].id}",
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["id"] == str(test_setup["eve_invoice"].id)

    # LAB-01b: Cross-tenant listing
    async def test_cross_tenant_listing_blocked_in_secure(
        self, secure_client, auth_tokens, test_setup
    ):
        """Secure app blocks cross-tenant listing."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        response = await secure_client.get(
            "/api/v1/invoices",
            params={"tenant_id": str(test_setup["tenant_b"].id)},
            headers=headers,
        )
        assert response.status_code == 404

    async def test_cross_tenant_listing_works_in_vulnerable(
        self, vulnerable_client, lab_tokens, test_setup
    ):
        """Vulnerable app allows cross-tenant listing."""
        headers = {"Authorization": f"Bearer {lab_tokens['charlie@acme.com']}"}
        response = await vulnerable_client.get(
            "/api/v1/invoices",
            params={"tenant_id": str(test_setup["tenant_b"].id)},
            headers=headers,
        )
        assert response.status_code == 200
        data = response.json()
        # Should see Eve's invoice
        assert data["total"] >= 1

    # LAB-02: BFLA - Unauthorized function access
    async def test_bfla_blocked_in_secure(self, secure_client, auth_tokens, test_setup):
        """Secure app blocks member from approving."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        response = await secure_client.post(
            f"/api/v1/invoices/{test_setup['bob_submitted'].id}/approve",
            headers=headers,
        )
        assert response.status_code == 403

    async def test_bfla_works_in_vulnerable(self, vulnerable_client, lab_tokens, test_setup):
        """Vulnerable app allows member to approve."""
        headers = {"Authorization": f"Bearer {lab_tokens['charlie@acme.com']}"}
        response = await vulnerable_client.post(
            f"/api/v1/invoices/{test_setup['bob_submitted'].id}/approve",
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "approved"

    # LAB-03: Mass Assignment - Protected field modification
    async def test_mass_assignment_blocked_in_secure(self, secure_client, auth_tokens, test_setup):
        """Secure app blocks mass assignment (outer Pydantic layer)."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        response = await secure_client.patch(
            f"/api/v1/invoices/{test_setup['charlie_draft'].id}",
            json={
                "amount_cents": 999999,
                "tenant_id": str(uuid4()),
                "owner_id": str(uuid4()),
                "status": "approved",
                "approved_by": str(uuid4()),
            },
            headers=headers,
        )
        assert response.status_code == 422

    async def test_mass_assignment_single_protected_field_blocked_in_secure(
        self, secure_client, auth_tokens, test_setup
    ):
        """Secure app blocks a single protected field with no extras (outer layer)."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        response = await secure_client.patch(
            f"/api/v1/invoices/{test_setup['charlie_draft'].id}",
            json={"status": "approved"},
            headers=headers,
        )
        assert response.status_code == 422

    def test_mass_assignment_inner_layer_rejects_single_protected_field(self, test_setup):
        """M-1: service layer rejects a single protected field, bypassing Pydantic.

        Pins the inner allow-list independently: widening the service
        allow-list to include `status` must fail this test (the HTTP tests
        above would still pass via Pydantic `extra="forbid"`).
        """
        from authzlab.application.services import InvoiceService
        from authzlab.domain.exceptions import MassAssignmentError

        service = InvoiceService()
        charlie = test_setup["charlie"]
        invoice = service.create_invoice(
            charlie, amount_cents=1234, currency="USD", description="M-1 pin"
        )
        with pytest.raises(MassAssignmentError) as exc:
            service.update_invoice(charlie, invoice.id, status="approved")
        assert "status" in exc.value.fields

    async def test_mass_assignment_works_in_vulnerable(
        self, vulnerable_client, lab_tokens, test_setup
    ):
        """Vulnerable app allows mass assignment (uses real FK IDs to prove persistence)."""
        headers = {"Authorization": f"Bearer {lab_tokens['charlie@acme.com']}"}
        response = await vulnerable_client.patch(
            f"/api/v1/invoices/{test_setup['charlie_draft'].id}",
            json={
                "amount_cents": 999999,
                "tenant_id": str(test_setup["tenant_a"].id),
                "owner_id": str(test_setup["bob"].id),
                "status": "approved",
                "approved_by": str(test_setup["charlie"].id),
            },
            headers=headers,
        )
        assert response.status_code == 200
        data = response.json()
        # At least one protected field was modified and persisted
        assert data["status"] == "approved"
        assert data["approved_by"] == str(test_setup["charlie"].id)
        assert data["owner_id"] == str(test_setup["bob"].id)

    # LAB-04: Business Logic - Self-approval
    async def test_self_approval_blocked_in_secure(self, secure_client, auth_tokens, test_setup):
        """Secure app blocks self-approval."""
        headers = {"Authorization": f"Bearer {auth_tokens['bob@acme.com']}"}
        response = await secure_client.post(
            f"/api/v1/invoices/{test_setup['bob_submitted'].id}/approve",
            headers=headers,
        )
        assert response.status_code == 409
        assert "own" in response.json()["detail"].lower()

    async def test_self_approval_works_in_vulnerable(
        self, vulnerable_client, lab_tokens, test_setup
    ):
        """Vulnerable app allows self-approval."""
        headers = {"Authorization": f"Bearer {lab_tokens['bob@acme.com']}"}
        response = await vulnerable_client.post(
            f"/api/v1/invoices/{test_setup['bob_submitted'].id}/approve",
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "approved"
        assert response.json()["approved_by"] == str(test_setup["bob"].id)

    # Legitimate operations should work in both
    async def test_legitimate_operations_work_in_secure(
        self, secure_client, auth_tokens, test_setup
    ):
        """Legitimate operations work in secure app."""
        headers = {"Authorization": f"Bearer {auth_tokens['bob@acme.com']}"}
        response = await secure_client.post(
            f"/api/v1/invoices/{test_setup['charlie_submitted'].id}/approve",
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "approved"

    async def test_legitimate_operations_work_in_vulnerable(
        self, vulnerable_client, lab_tokens, test_setup
    ):
        """Legitimate operations work in vulnerable app."""
        headers = {"Authorization": f"Bearer {lab_tokens['bob@acme.com']}"}
        response = await vulnerable_client.post(
            f"/api/v1/invoices/{test_setup['charlie_submitted'].id}/approve",
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "approved"
