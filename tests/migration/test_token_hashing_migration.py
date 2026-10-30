"""Exercise the bearer-token hashing migration against PostgreSQL."""

import importlib.util
import secrets
import uuid
from pathlib import Path
from types import ModuleType

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.pool import NullPool

from autosecops.auth.crypto import hash_bearer_token
from tests.database import TEST_DB_CONFIG


def _load_migration() -> ModuleType:
    migration_path = (
        Path(__file__).parents[2]
        / "alembic/versions/3f7a9c2d5b81_hash_session_and_invitation_tokens.py"
    )
    spec = importlib.util.spec_from_file_location("token_hashing", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


def test_sql_digest_matches_python() -> None:
    """The migration's SQL hash must equal the app's, or sessions break."""
    migration = _load_migration()
    engine = sa.create_engine(TEST_DB_CONFIG.sys_url_sync, poolclass=NullPool)
    samples = [
        secrets.token_urlsafe(),
        secrets.token_urlsafe(48)[:64],
        "token-with-unicode-çğı",
        "a",
    ]
    try:
        with engine.connect() as conn:
            for raw in samples:
                digest = conn.scalar(
                    sa.text(
                        f"SELECT {migration.HASH_TOKEN_SQL} "
                        "FROM (SELECT CAST(:raw AS text) AS token) AS t"
                    ),
                    {"raw": raw},
                )
                assert digest == hash_bearer_token(raw)
    finally:
        engine.dispose()


def test_upgrade_hashes_in_place_and_downgrade_drops_hashed_sessions() -> None:
    migration = _load_migration()
    engine = sa.create_engine(TEST_DB_CONFIG.sys_url_sync, poolclass=NullPool)
    session_raw = secrets.token_urlsafe()
    invitation_raw = secrets.token_urlsafe(48)[:64]
    legacy_raw = secrets.token_urlsafe(48)[:64]
    try:
        with engine.begin() as conn:
            # Temporary tables shadow production names only on this connection.
            conn.execute(
                sa.text(
                    "CREATE TEMP TABLE access_token ("
                    " token varchar(43) PRIMARY KEY, user_id uuid NOT NULL"
                    ") ON COMMIT DROP"
                )
            )
            conn.execute(
                sa.text(
                    "CREATE TEMP TABLE invitation ("
                    " id uuid PRIMARY KEY, token varchar(64) UNIQUE NOT NULL"
                    ") ON COMMIT DROP"
                )
            )
            conn.execute(
                sa.text(
                    "CREATE TEMP TABLE organization_invitation ("
                    " id uuid PRIMARY KEY, token varchar(64) UNIQUE NOT NULL"
                    ") ON COMMIT DROP"
                )
            )
            conn.execute(
                sa.text("INSERT INTO access_token VALUES (:token, :user_id)"),
                {"token": session_raw, "user_id": uuid.uuid4()},
            )
            conn.execute(
                sa.text("INSERT INTO invitation VALUES (:id, :token)"),
                {"id": uuid.uuid4(), "token": invitation_raw},
            )
            conn.execute(
                sa.text("INSERT INTO organization_invitation VALUES (:id, :token)"),
                {"id": uuid.uuid4(), "token": legacy_raw},
            )

            with Operations.context(MigrationContext.configure(conn)):
                migration.upgrade()

            # No raw value survives; each row holds the app's digest.
            assert conn.execute(
                sa.text("SELECT token, token_hashed FROM access_token")
            ).one() == (hash_bearer_token(session_raw), True)
            assert conn.execute(
                sa.text("SELECT token, token_hashed, encrypted_token FROM invitation")
            ).one() == (hash_bearer_token(invitation_raw), True, None)
            assert conn.scalar(
                sa.text("SELECT token FROM organization_invitation")
            ) == hash_bearer_token(legacy_raw)

            # The previous app version, still running during the rollout, inserts
            # without the flag; its rows are marked raw so they keep working.
            old_app_raw = secrets.token_urlsafe()
            conn.execute(
                sa.text("INSERT INTO access_token (token, user_id) VALUES (:t, :u)"),
                {"t": old_app_raw, "u": uuid.uuid4()},
            )
            assert (
                conn.scalar(
                    sa.text("SELECT token_hashed FROM access_token WHERE token = :t"),
                    {"t": old_app_raw},
                )
                is False
            )

            with Operations.context(MigrationContext.configure(conn)):
                migration.downgrade()

            # Hashed sessions cannot be used by the previous version, so they go;
            # the raw row it wrote survives.
            assert conn.scalars(sa.text("SELECT token FROM access_token")).all() == [
                old_app_raw
            ]
            columns = set(
                conn.scalars(
                    sa.text(
                        "SELECT column_name FROM information_schema.columns"
                        " WHERE table_name IN ('access_token', 'invitation')"
                        " AND table_schema LIKE 'pg_temp%'"
                    )
                ).all()
            )
            assert "token_hashed" not in columns
            assert "encrypted_token" not in columns
    finally:
        engine.dispose()
