"""The email verification migration grandfathers existing accounts."""

import os
import subprocess
import uuid
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.pool import NullPool

from tests.database import TEST_DB_CONFIG

PREVIOUS_REVISION = "d3a7e5c1b9f2"
VERIFICATION_REVISION = "7e3c9b1d5a20"


@pytest.fixture(scope="session")
def default_org() -> None:
    """Use an isolated migration database instead of shared application fixtures."""


@pytest.fixture(scope="session")
def workflow_bucket() -> None:
    """No object storage is needed."""


@pytest.fixture
def clean_redis_db() -> None:
    """No Redis is needed."""


def _migrate(db_url: str, direction: str, revision: str) -> None:
    env = os.environ.copy()
    env["AUTOSECOPS__DB_URI"] = db_url
    result = subprocess.run(
        ["uv", "run", "alembic", direction, revision],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def migration_db_url() -> Iterator[str]:
    db_name = f"test_email_verification_{uuid.uuid4().hex}"
    admin_engine = sa.create_engine(
        TEST_DB_CONFIG.sys_url_sync,
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
    )
    db_url = TEST_DB_CONFIG.base_url.replace("+asyncpg", "+psycopg") + db_name
    with admin_engine.connect() as conn:
        conn.execute(sa.text(f'CREATE DATABASE "{db_name}"'))
    try:
        _migrate(db_url, "upgrade", PREVIOUS_REVISION)
        yield db_url
    finally:
        with admin_engine.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE "{db_name}"'))
        admin_engine.dispose()


def test_existing_accounts_are_verified_and_outbox_round_trips(
    migration_db_url: str,
) -> None:
    engine = sa.create_engine(migration_db_url, poolclass=NullPool)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text("""
                INSERT INTO "user" (
                    id, email, hashed_password, is_active, is_superuser,
                    is_verified, role
                )
                VALUES
                    (md5('unverified')::uuid, 'unverified@example.com', 'x',
                     true, false, false, 'BASIC'),
                    (md5('verified')::uuid, 'verified@example.com', 'x',
                     true, false, true, 'BASIC')
                """)
            )

        _migrate(migration_db_url, "upgrade", VERIFICATION_REVISION)

        with engine.begin() as conn:
            unverified = conn.execute(
                sa.text('SELECT count(*) FROM "user" WHERE NOT is_verified')
            ).scalar_one()
            assert unverified == 0
            conn.execute(
                sa.text(
                    "INSERT INTO email_verification_outbox (user_id) "
                    "VALUES (md5('unverified')::uuid)"
                )
            )
            attempts = conn.execute(
                sa.text("SELECT attempts FROM email_verification_outbox")
            ).scalar_one()
            assert attempts == 0
            # Deleting the account removes its pending email.
            conn.execute(
                sa.text("DELETE FROM \"user\" WHERE id = md5('unverified')::uuid")
            )
            remaining = conn.execute(
                sa.text("SELECT count(*) FROM email_verification_outbox")
            ).scalar_one()
            assert remaining == 0

        _migrate(migration_db_url, "downgrade", PREVIOUS_REVISION)

        with engine.begin() as conn:
            table = conn.execute(
                sa.text("SELECT to_regclass('public.email_verification_outbox')")
            ).scalar_one()
            assert table is None
            # The backfill is kept on downgrade by design.
            still_verified = conn.execute(
                sa.text(
                    "SELECT is_verified FROM \"user\" WHERE id = md5('verified')::uuid"
                )
            ).scalar_one()
            assert still_verified is True
    finally:
        engine.dispose()
