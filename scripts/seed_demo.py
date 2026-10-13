#!/usr/bin/env python3
"""Seed demo data for AuthZLab."""

from __future__ import annotations

import sys

from authzlab.domain.models import InvoiceStatus, Role
from authzlab.infrastructure.database import get_session
from authzlab.infrastructure.repositories import InvoiceRepository, TenantRepository, UserRepository
from authzlab.infrastructure.security import PasswordManager


def seed_demo() -> int:
    """Seed the database with demo data."""
    # M-D: every demo account (including admins) shares the weak password
    # "password123". Local lab only — never seed a reachable database.
    print("WARNING: demo users (including admins) all use password 'password123'.")
    print("Local lab only — never run this against a reachable database.")
    print("Seeding demo data...")

    with get_session() as db:
        tenant_repo = TenantRepository(db)
        user_repo = UserRepository(db)
        invoice_repo = InvoiceRepository(db)
        password_manager = PasswordManager()

        # Create tenants
        tenant_a = tenant_repo.get_by_name("Acme Corp")
        if not tenant_a:
            tenant_a = tenant_repo.create("Acme Corp")
            print(f"Created tenant: {tenant_a.name} ({tenant_a.id})")

        tenant_b = tenant_repo.get_by_name("Globex Inc")
        if not tenant_b:
            tenant_b = tenant_repo.create("Globex Inc")
            print(f"Created tenant: {tenant_b.name} ({tenant_b.id})")

        # Flush to ensure tenants are visible in same transaction
        db.flush()

        # Create users for tenant A
        users_data = [
            ("alice@acme.com", "password123", Role.ADMIN, tenant_a.id),
            ("bob@acme.com", "password123", Role.APPROVER, tenant_a.id),
            ("charlie@acme.com", "password123", Role.MEMBER, tenant_a.id),
            ("diana@acme.com", "password123", Role.MEMBER, tenant_a.id),
        ]

        for email, password, role, tid in users_data:
            existing = user_repo.get_by_email_and_tenant(email, tid)
            if not existing:
                user = user_repo.create(tid, email, password_manager.hash_password(password), role)
                print(f"Created user: {user.email} ({role.value}) in {tenant_a.name}")

        # Create users for tenant B
        users_data_b = [
            ("eve@globex.com", "password123", Role.ADMIN, tenant_b.id),
            ("frank@globex.com", "password123", Role.APPROVER, tenant_b.id),
            ("grace@globex.com", "password123", Role.MEMBER, tenant_b.id),
        ]

        for email, password, role, tid in users_data_b:
            existing = user_repo.get_by_email_and_tenant(email, tid)
            if not existing:
                user = user_repo.create(tid, email, password_manager.hash_password(password), role)
                print(f"Created user: {user.email} ({role.value}) in {tenant_b.name}")

        # Flush users
        db.flush()

        # Get users for creating invoices
        bob = user_repo.get_by_email_and_tenant("bob@acme.com", tenant_a.id)
        charlie = user_repo.get_by_email_and_tenant("charlie@acme.com", tenant_a.id)
        eve = user_repo.get_by_email_and_tenant("eve@globex.com", tenant_b.id)

        # Create sample invoices directly
        sample_invoices = [
            (charlie, 15000, "USD", "Office supplies"),
            (charlie, 25000, "USD", "Software license"),
            (bob, 50000, "USD", "Consulting services"),
            (eve, 75000, "EUR", "Marketing campaign"),
        ]

        for owner, amount, currency, desc in sample_invoices:
            invoice = invoice_repo.create(
                tenant_id=owner.tenant_id,
                owner_id=owner.id,
                amount_cents=amount,
                currency=currency,
                description=desc,
            )
            print(f"Created invoice: {invoice.id} - {amount} {currency} ({desc})")

        # Flush invoices
        db.flush()

        # Submit some invoices
        charlie_invoices = invoice_repo.get_by_owner(charlie.id)
        for inv in charlie_invoices[:2]:
            try:
                inv.status = InvoiceStatus.SUBMITTED
                db.flush()
                print(f"Submitted invoice: {inv.id}")
            except Exception as e:
                print(f"Could not submit {inv.id}: {e}")

        bob_invoices = invoice_repo.get_by_owner(bob.id)
        for inv in bob_invoices[:1]:
            try:
                inv.status = InvoiceStatus.SUBMITTED
                db.flush()
                print(f"Submitted invoice: {inv.id}")
            except Exception as e:
                print(f"Could not submit {inv.id}: {e}")

        print("Demo data seeded successfully!")
        return 0


if __name__ == "__main__":
    sys.exit(seed_demo())
