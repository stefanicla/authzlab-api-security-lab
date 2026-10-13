"""Integration tests for API with real database."""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from authzlab.domain.models import Role
from authzlab.infrastructure.database import drop_db, get_session, init_db
from authzlab.infrastructure.repositories import TenantRepository, UserRepository
from authzlab.infrastructure.security import PasswordManager
from authzlab.secure_app import app as secure_app


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Set up test database."""
    drop_db()
    init_db()
    yield
    drop_db()


@pytest.fixture(scope="session")
def db_session():
    """Get database session for test."""
    with get_session() as session:
        yield session


@pytest.fixture(scope="session")
def test_data():
    """Create test tenants and users."""
    from authzlab.infrastructure.database import get_session

    with get_session() as db_session:
        tenant_repo = TenantRepository(db_session)
        user_repo = UserRepository(db_session)
        password_mgr = PasswordManager()

        # Tenant A
        tenant_a = tenant_repo.get_by_name("Acme Corp")
        if not tenant_a:
            tenant_a = tenant_repo.create("Acme Corp")

        # Tenant B
        tenant_b = tenant_repo.get_by_name("Globex Inc")
        if not tenant_b:
            tenant_b = tenant_repo.create("Globex Inc")

        # Users
        users = {}
        for email, role, tenant in [
            ("alice@acme.com", Role.ADMIN, tenant_a),
            ("bob@acme.com", Role.APPROVER, tenant_a),
            ("charlie@acme.com", Role.MEMBER, tenant_a),
            ("eve@globex.com", Role.ADMIN, tenant_b),
            ("frank@globex.com", Role.APPROVER, tenant_b),
        ]:
            user = user_repo.get_by_email_and_tenant(email, tenant.id)
            if not user:
                user = user_repo.create(
                    tenant.id, email, password_mgr.hash_password("password123"), role
                )
            users[email] = user

        db_session.commit()
        return {"tenant_a": tenant_a, "tenant_b": tenant_b, "users": users}


@pytest.fixture(scope="session")
async def client():
    """Async test client for secure app."""
    transport = ASGITransport(app=secure_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(scope="session")
async def auth_tokens(client, setup_database, test_data):
    """Get auth tokens by logging in via API."""
    tokens = {}
    for email in [
        "alice@acme.com",
        "bob@acme.com",
        "charlie@acme.com",
        "eve@globex.com",
        "frank@globex.com",
    ]:
        response = await client.post(
            "/api/v1/auth/token",
            json={"email": email, "password": "password123"},
        )
        assert response.status_code == 200, f"Login failed for {email}: {response.text}"
        tokens[email] = response.json()["access_token"]
    return tokens


class TestSecureAPI:
    """Integration tests for secure API."""

    async def test_health_endpoints(self, client):
        """Health endpoints should work."""
        live = await client.get("/health/live")
        assert live.status_code == 200
        assert live.json()["status"] == "alive"

        ready = await client.get("/health/ready")
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"

    async def test_login_success(self, client, test_data):
        """Valid credentials should return tokens."""
        response = await client.post(
            "/api/v1/auth/token",
            json={"email": "alice@acme.com", "password": "password123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_fails_invalid_password(self, client):
        """Invalid password should return 401."""
        response = await client.post(
            "/api/v1/auth/token",
            json={"email": "alice@acme.com", "password": "wrong"},
        )
        assert response.status_code == 401

    async def test_login_fails_nonexistent_user(self, client):
        """Nonexistent user should return 401."""
        response = await client.post(
            "/api/v1/auth/token",
            json={"email": "nonexistent@test.com", "password": "password123"},
        )
        assert response.status_code == 401

    async def test_login_same_email_two_tenants_is_401_not_500(self, client, test_data):
        """L-4 regression: a cross-tenant duplicate email must not crash login.

        Uniqueness is only (tenant_id, email), so the same address can exist in
        two tenants. Login carries no tenant selector, so the identity is
        ambiguous: it must fail as 401, never as a MultipleResultsFound 500.
        """
        shared_email = "duplicate@shared.example"
        with get_session() as db_session:
            user_repo = UserRepository(db_session)
            password_mgr = PasswordManager()
            for tenant in (test_data["tenant_a"], test_data["tenant_b"]):
                if not user_repo.get_by_email_and_tenant(shared_email, tenant.id):
                    user_repo.create(
                        tenant.id,
                        shared_email,
                        password_mgr.hash_password("password123"),
                        Role.MEMBER,
                    )

        response = await client.post(
            "/api/v1/auth/token",
            json={"email": shared_email, "password": "password123"},
        )
        assert response.status_code == 401, f"expected 401, got {response.status_code}"

    async def test_refresh_token_rejected_as_access_token(self, client, test_data):
        """H-2 regression: refresh token presented as access token is 401, not 500."""
        login = await client.post(
            "/api/v1/auth/token",
            json={"email": "alice@acme.com", "password": "password123"},
        )
        assert login.status_code == 200
        refresh_token = login.json()["refresh_token"]
        response = await client.get(
            "/api/v1/invoices",
            headers={"Authorization": f"Bearer {refresh_token}"},
        )
        assert response.status_code == 401

    async def test_create_invoice(self, client, auth_tokens, test_data):
        """Member can create invoice in own tenant."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        response = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Test"},
            headers=headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["amount_cents"] == 5000
        assert data["status"] == "draft"
        assert data["owner_id"] == str(test_data["users"]["charlie@acme.com"].id)

    async def test_list_invoices_tenant_scoped(self, client, auth_tokens, test_data):
        """Users only see invoices from their tenant."""
        # Charlie creates an invoice
        headers_charlie = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Charlie's"},
            headers=headers_charlie,
        )

        # Eve (tenant B) should not see it
        headers_eve = {"Authorization": f"Bearer {auth_tokens['eve@globex.com']}"}
        response = await client.get("/api/v1/invoices", headers=headers_eve)
        assert response.status_code == 200
        data = response.json()
        # Eve's tenant has no invoices yet
        assert data["total"] == 0

        # Charlie should see his invoices (at least 2 from seed + 1 new)
        response = await client.get("/api/v1/invoices", headers=headers_charlie)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2

    async def test_get_invoice_cross_tenant_returns_404(self, client, auth_tokens, test_data):
        """Cross-tenant invoice access returns 404 (not 403)."""
        # Charlie creates invoice
        headers_charlie = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        create_resp = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Test"},
            headers=headers_charlie,
        )
        assert create_resp.status_code == 201
        invoice_id = create_resp.json()["id"]

        # Eve tries to access it
        headers_eve = {"Authorization": f"Bearer {auth_tokens['eve@globex.com']}"}
        response = await client.get(f"/api/v1/invoices/{invoice_id}", headers=headers_eve)
        assert response.status_code == 404

    async def test_update_invoice_draft_only(self, client, auth_tokens, test_data):
        """Can only update invoices in DRAFT status."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}

        # Create and submit
        create_resp = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Test"},
            headers=headers,
        )
        assert create_resp.status_code == 201
        invoice_id = create_resp.json()["id"]

        # Update while draft - should work
        response = await client.patch(
            f"/api/v1/invoices/{invoice_id}",
            json={"description": "Updated"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["description"] == "Updated"

        # Submit it
        await client.post(f"/api/v1/invoices/{invoice_id}/submit", headers=headers)

        # Update after submit - should fail
        response = await client.patch(
            f"/api/v1/invoices/{invoice_id}",
            json={"description": "Updated again"},
            headers=headers,
        )
        assert response.status_code == 409

    async def test_submit_invoice_owner_only(self, client, auth_tokens, test_data):
        """Only owner can submit invoice."""
        headers_charlie = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}

        # Create invoice as charlie
        create_resp = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Test"},
            headers=headers_charlie,
        )
        assert create_resp.status_code == 201
        invoice_id = create_resp.json()["id"]

        # Charlie can submit
        response = await client.post(
            f"/api/v1/invoices/{invoice_id}/submit", headers=headers_charlie
        )
        assert response.status_code == 200
        assert response.json()["status"] == "submitted"

    async def test_approve_invoice_approver_only(self, client, auth_tokens, test_data):
        """Only approver/admin can approve."""
        headers_charlie = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}
        headers_bob = {"Authorization": f"Bearer {auth_tokens['bob@acme.com']}"}

        # Create and submit as charlie
        create_resp = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Test"},
            headers=headers_charlie,
        )
        assert create_resp.status_code == 201
        invoice_id = create_resp.json()["id"]
        await client.post(f"/api/v1/invoices/{invoice_id}/submit", headers=headers_charlie)

        # Charlie (member) cannot approve
        response = await client.post(
            f"/api/v1/invoices/{invoice_id}/approve", headers=headers_charlie
        )
        assert response.status_code == 403

        # Bob (approver) can approve
        response = await client.post(f"/api/v1/invoices/{invoice_id}/approve", headers=headers_bob)
        assert response.status_code == 200
        assert response.json()["status"] == "approved"
        assert response.json()["approved_by"] == str(test_data["users"]["bob@acme.com"].id)

    async def test_self_approval_blocked(self, client, auth_tokens, test_data):
        """Approver cannot approve own invoice."""
        headers_bob = {"Authorization": f"Bearer {auth_tokens['bob@acme.com']}"}

        # Create and submit as bob
        create_resp = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Test"},
            headers=headers_bob,
        )
        assert create_resp.status_code == 201
        invoice_id = create_resp.json()["id"]
        await client.post(f"/api/v1/invoices/{invoice_id}/submit", headers=headers_bob)

        # Bob tries to self-approve
        response = await client.post(f"/api/v1/invoices/{invoice_id}/approve", headers=headers_bob)
        assert response.status_code == 409
        assert "own" in response.json()["detail"].lower()

    async def test_mass_assignment_blocked(self, client, auth_tokens, test_data):
        """Protected fields cannot be modified via PATCH."""
        headers = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}

        create_resp = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 5000, "currency": "USD", "description": "Test"},
            headers=headers,
        )
        assert create_resp.status_code == 201
        invoice_id = create_resp.json()["id"]

        # Try to modify protected fields
        response = await client.patch(
            f"/api/v1/invoices/{invoice_id}",
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
        data = response.json()
        # Pydantic returns validation errors as a list
        error_str = str(data.get("detail", "")).lower()
        assert "extra" in error_str or "forbid" in error_str or "unexpected" in error_str

    async def test_member_listing_excludes_other_members_invoices(
        self, client, auth_tokens, test_data
    ):
        """H-1 regression: members see only their own invoices in listings."""
        headers_bob = {"Authorization": f"Bearer {auth_tokens['bob@acme.com']}"}
        headers_charlie = {"Authorization": f"Bearer {auth_tokens['charlie@acme.com']}"}

        bob_resp = await client.post(
            "/api/v1/invoices",
            json={"amount_cents": 31337, "currency": "USD", "description": "H1_PROBE_DO_NOT_SHARE"},
            headers=headers_bob,
        )
        assert bob_resp.status_code == 201
        bob_invoice_id = bob_resp.json()["id"]

        charlie_resp = await client.get("/api/v1/invoices", headers=headers_charlie)
        assert charlie_resp.status_code == 200
        charlie_ids = {item["id"] for item in charlie_resp.json()["items"]}
        assert bob_invoice_id not in charlie_ids

        # Approver in same tenant can still see it (tenant scope preserved)
        approver_resp = await client.get("/api/v1/invoices", headers=headers_bob)
        assert approver_resp.status_code == 200
        approver_ids = {item["id"] for item in approver_resp.json()["items"]}
        assert bob_invoice_id in approver_ids
