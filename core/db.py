"""AI-IDS/IPS Database Engine & Session Management Module.

Configures SQLAlchemy 2.0 connection pooling, session scopes, declarative base,
and safe transactional context managers.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, scoped_session, sessionmaker

from core.config import settings
from core.logging import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    """Declarative Base class for all SQLAlchemy 2.x models."""


def get_engine(db_url: str | None = None, echo: bool = False):
    """Create and return a configured SQLAlchemy engine with connection pool hardening."""
    url = db_url or settings.get_database_url()

    # SQLite in-memory or file mode for tests
    if url.startswith("sqlite"):
        sqlite_engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            echo=echo,
        )

        @event.listens_for(sqlite_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record) -> None:  # type: ignore[no-untyped-def]
            del connection_record
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return sqlite_engine

    # PostgreSQL enterprise production pool configuration
    return create_engine(
        url,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800,
        pool_pre_ping=True,  # Test connections before checkout to prevent stale connection errors
        echo=echo,
    )


# Global Engine and Session Factory instances
engine = get_engine()
SessionFactory = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,  # Keep loaded attributes accessible after transaction commit
)
ScopedSession = scoped_session(SessionFactory)


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session scope with automatic rollback and cleanup."""
    session: Session = ScopedSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Database transaction rollback triggered")
        raise
    finally:
        session.close()
        ScopedSession.remove()
