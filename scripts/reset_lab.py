#!/usr/bin/env python3
"""Reset lab database for AuthZLab."""

from __future__ import annotations

import sys

from authzlab.infrastructure.database import drop_db, init_db


def reset_lab() -> int:
    """Reset the lab database."""
    print("Resetting lab database...")
    drop_db()
    init_db()
    print("Database reset complete. Run seed_demo.py to populate with demo data.")
    return 0


if __name__ == "__main__":
    sys.exit(reset_lab())
