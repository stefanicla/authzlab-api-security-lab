"""Database infrastructure for AuthZLab."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from authzlab.core.config import get_settings


def create_database_engine() -> None:
    """Create and configure the database engine."""
    settings = get_settings()
    global _engine, _session_factory
    _engine = create_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout,
        pool_pre_ping=True,
        echo=settings.debug,
        # M-2: bound connection/setup time so unreachable DBs fail fast
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=15000"},
    )
    _session_factory = sessionmaker(
        bind=_engine,
        class_=Session,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Get the database engine."""
    global _engine
    if _engine is None:
        create_database_engine()
    assert _engine is not None
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Get the session factory."""
    global _session_factory
    if _session_factory is None:
        create_database_engine()
    assert _session_factory is not None
    return _session_factory


@contextmanager
def get_session() -> Iterator[Session]:
    """Get a database session with automatic cleanup (context manager for scripts/tests)."""
    session_factory = get_session_factory()
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_session() -> Generator[Session]:
    """Get a database session for FastAPI dependency injection (generator)."""
    session_factory = get_session_factory()
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Initialize database - create all tables."""
    from authzlab.domain.models import Base

    engine = get_engine()
    Base.metadata.create_all(bind=engine)


def drop_db() -> None:
    """Drop all tables."""
    from authzlab.domain.models import Base

    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
