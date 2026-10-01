"""Database connection handling.

The URL comes from the environment, never from the repository: it carries a
password, and the project's rule is that secrets live in `.env` and nowhere
else.
"""

from __future__ import annotations

import os
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def database_url() -> str:
    """Build the connection URL from the environment.

    `DATABASE_URL` wins when set, which is how tests point at a throwaway
    database. Otherwise the parts are assembled from the same variables the
    PostgreSQL container reads, so there is one place to change a password.
    """
    explicit = os.getenv("DATABASE_URL")
    if explicit:
        return explicit

    user = os.getenv("POSTGRES_USER", "honeypot")
    password = os.getenv("POSTGRES_PASSWORD", "")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    name = os.getenv("POSTGRES_DB", "honeypot")

    if not password:
        raise RuntimeError(
            "No database password configured. Set DATABASE_URL or POSTGRES_PASSWORD "
            "(see .env.example)."
        )

    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}"


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """The process-wide engine.

    `pool_pre_ping` costs one cheap round trip and avoids the classic failure
    of a long-lived worker holding a connection the database closed hours ago.
    """
    return create_engine(database_url(), pool_pre_ping=True, future=True)


def session_factory() -> sessionmaker[Session]:
    """A factory for database sessions bound to the shared engine."""
    return sessionmaker(bind=get_engine(), expire_on_commit=False)
