"""CLI entry point for AuthZLab."""

from __future__ import annotations

import typer
from rich.console import Console

from authzlab.infrastructure.database import drop_db, init_db

app = typer.Typer(
    name="authzlab", help="AuthZLab - Multi-tenant API Authorization Security Laboratory"
)
console = Console()


@app.command()
def init_db_cmd(
    drop_first: bool = typer.Option(False, "--drop-first", help="Drop existing tables first"),
) -> None:
    """Initialize the database schema."""
    if drop_first:
        console.print("[yellow]Dropping existing tables...[/yellow]")
        drop_db()

    console.print("[green]Creating tables...[/green]")
    init_db()
    console.print("[green]Database initialized successfully![/green]")


@app.command()
def seed_demo() -> None:
    """Seed the database with demo data (delegates to scripts/seed_demo.py)."""
    import importlib.util
    from pathlib import Path

    # L-A: resolve relative to the repository root, not the CWD.
    script = Path(__file__).resolve().parents[2] / "scripts" / "seed_demo.py"
    spec = importlib.util.spec_from_file_location("authzlab_seed_demo", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{script} not found")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    console.print("[green]Seeding demo data...[/green]")
    module.seed_demo()


@app.command()
def reset_lab() -> None:
    """Reset the lab database (drop and recreate with seed data)."""
    console.print("[yellow]Resetting lab database...[/yellow]")
    drop_db()
    init_db()
    seed_demo()


@app.command()
def run_secure(
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
) -> None:
    """Run the secure API server."""
    import uvicorn

    console.print(f"[green]Starting secure API on {host}:{port}[/green]")
    uvicorn.run(
        "authzlab.secure_app:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def run_lab(
    host: str = "127.0.0.1",
    port: int = 8001,
    reload: bool = False,
    allow_external: bool = False,
) -> None:
    """Run the vulnerable lab API server."""
    import os

    os.environ["AUTHZLAB_LAB_MODE"] = "true"
    if allow_external:
        # L-1: --allow-external alone never changed the bind address (the flag
        # was misleading). Require an explicit --host so external exposure is
        # always a deliberate, visible choice; default stays localhost-only.
        if host == "127.0.0.1":
            raise typer.BadParameter("--host must be set explicitly with --allow-external")
        os.environ["AUTHZLAB_LAB_ALLOW_EXTERNAL"] = "true"
        console.print(f"[red]WARNING: lab exposed on {host}:{port}![/red]")

    console.print(f"[red]Starting VULNERABLE lab API on {host}:{port}[/red]")
    console.print("[red]This application contains INTENTIONAL SECURITY VULNERABILITIES![/red]")

    import uvicorn

    uvicorn.run(
        "authzlab.vulnerable_app:app",
        host=host,
        port=port,
        reload=reload,
    )


def main() -> None:
    """Console-script entry point (`authzlab`, see H-3)."""
    app()


if __name__ == "__main__":
    main()
