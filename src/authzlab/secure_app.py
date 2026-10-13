"""Secure FastAPI application for AuthZLab."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from authzlab.api.errors import register_exception_handlers
from authzlab.api.v1 import health_router
from authzlab.api.v1 import router as api_v1_router
from authzlab.core.config import get_settings
from authzlab.infrastructure.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler."""
    # Startup
    settings = get_settings()
    if settings.environment != "production":
        init_db()
    yield
    # Shutdown


def create_secure_app() -> FastAPI:
    """Create the secure FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AuthZLab - Secure Multi-tenant Invoice API",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # Register exception handlers
    register_exception_handlers(app)

    # Include routers
    app.include_router(health_router)
    app.include_router(api_v1_router)

    return app


# Global app instance
app = create_secure_app()


def main() -> None:
    """Entry point for running the secure application."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "authzlab.secure_app:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
