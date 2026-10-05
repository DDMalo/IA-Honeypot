"""Tests for the database schema.

These check the schema's shape without connecting to PostgreSQL, so CI needs no
database. The migration itself is exercised against a real server by hand (see
deploy/homelab/README.md); what matters here is that the model definitions keep
the guarantees the ingestion worker relies on.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from honeypot_ai.db import Base
from honeypot_ai.db.engine import database_url


def test_every_expected_table_is_defined() -> None:
    assert set(Base.metadata.tables) == {
        "sessions",
        "login_attempts",
        "commands",
        "file_transfers",
        "ip_intel",
    }


def test_session_id_is_the_primary_key() -> None:
    """Re-ingesting the same log must update rows, not duplicate them."""
    primary_key = Base.metadata.tables["sessions"].primary_key
    assert [column.name for column in primary_key.columns] == ["session_id"]


@pytest.mark.parametrize(
    ("table", "constraint"),
    [
        ("login_attempts", "uq_login_attempts_session_seq"),
        ("commands", "uq_commands_session_seq"),
        ("file_transfers", "uq_file_transfers_session_seq"),
    ],
)
def test_child_rows_are_unique_per_session_and_sequence(table: str, constraint: str) -> None:
    """The same command typed twice is two rows; the same log read twice is one."""
    names = {c.name for c in Base.metadata.tables[table].constraints}
    assert constraint in names


@pytest.mark.parametrize("table", ["login_attempts", "commands", "file_transfers"])
def test_child_rows_are_deleted_with_their_session(table: str) -> None:
    foreign_keys = list(Base.metadata.tables[table].foreign_keys)
    assert len(foreign_keys) == 1
    assert foreign_keys[0].ondelete == "CASCADE"


def test_source_address_is_stored_as_an_address_not_a_string() -> None:
    """`inet` is what lets queries ask about a whole subnet."""
    column = Base.metadata.tables["sessions"].columns["src_ip"]
    assert type(column.type).__name__ == "INET"


def test_hot_paths_are_indexed() -> None:
    indexes = {index.name for index in Base.metadata.tables["sessions"].indexes}
    assert {"ix_sessions_started_at", "ix_sessions_src_ip"} <= indexes


def test_database_url_prefers_an_explicit_value() -> None:
    with mock.patch.dict(os.environ, {"DATABASE_URL": "postgresql+psycopg://x@y/z"}):
        assert database_url() == "postgresql+psycopg://x@y/z"


def test_database_url_is_assembled_from_parts() -> None:
    env = {
        "POSTGRES_USER": "u",
        "POSTGRES_PASSWORD": "p",
        "POSTGRES_HOST": "h",
        "POSTGRES_PORT": "1234",
        "POSTGRES_DB": "d",
    }
    with mock.patch.dict(os.environ, env, clear=True):
        assert database_url() == "postgresql+psycopg://u:p@h:1234/d"


def test_database_url_refuses_to_guess_a_password() -> None:
    """Failing loudly beats connecting to something unintended."""
    with mock.patch.dict(os.environ, {}, clear=True), pytest.raises(RuntimeError):
        database_url()
