"""Run the bearer-token hashing expand migration against the real schema."""

import os
import secrets
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.pool import NullPool

from autosecops.auth.crypto import hash_bearer_token
from tests.database import TEST_DB_CONFIG

PREVIOUS_REVISION = "9b4d6e2f1a37"
HASHING_REVISION = "3f7a9c2d5b81"
REPO_ROOT = Path(__file__).parents[2]


@pytest.fixture(scope="session")
def default_org() -> None:
    """Use an isolated migration database instead of shared application fixtures."""


@pytest.fixture(scope="session")
def workflow_bucket() -> None:
    """No object storage is needed."""


@pytest.fixture
def clean_redis_db() -> None:
    """No Redis is needed."""


def _migrate(db_url: str, direction: str, revision: str) -> str:
    env = os.environ.copy()
    env["AUTOSECOPS__DB_URI"] = db_url
    result = subprocess.run(
        [sys.executable, "-m", "alembic", direction, revision],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout + result.stderr


@pytest.fixture
def migration_db_url() -> Iterator[str]:
    db_name = f"test_token_hashing_{uuid.uuid4().hex}"
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
            conn.execute(sa.text(f'DROP DATABASE "{db_name}" WITH (FORCE)'))
        admin_engine.dispose()


def _insert_invitation(
    conn: sa.Connection, *, org_id: uuid.UUID, token: str, status: str
) -> uuid.UUID:
    invitation_id = uuid.uuid4()
    conn.execute(
        sa.text(
            "INSERT INTO invitation"
            " (id, organization_id, email, status, token, expires_at)"
            " VALUES (:id, :org, :email, CAST(:status AS invitationstatus), :token,"
            " now() + interval '1 day')"
        ),
        {
            "id": invitation_id,
            "org": org_id,
            "email": f"{invitation_id.hex}@example.com",
            "status": status,
            "token": token,
        },
    )
    return invitation_id


def _columns(conn: sa.Connection, table: str) -> set[str]:
    return set(
        conn.scalars(
            sa.text(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_schema = 'public' AND table_name = :table"
            ),
            {"table": table},
        ).all()
    )


def test_upgrade_keeps_existing_tokens_and_downgrade_retires_hashed_rows(
    migration_db_url: str,
) -> None:
    engine = sa.create_engine(migration_db_url, poolclass=NullPool)
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    legacy_session = secrets.token_urlsafe()
    legacy_invitation = secrets.token_urlsafe(48)[:64]
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    'INSERT INTO "user" (id, email, hashed_password, is_active,'
                    " is_superuser, is_verified, role)"
                    " VALUES (:id, 'migration-user@example.com', 'x', true, false,"
                    " true, 'BASIC')"
                ),
                {"id": user_id},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO organization (id, name, slug, is_active)"
                    " VALUES (:id, 'Token hashing', 'token-hashing', true)"
                ),
                {"id": org_id},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO access_token (token, created_at, user_id, id)"
                    " VALUES (:token, now(), :user_id, :id)"
                ),
                {"token": legacy_session, "user_id": user_id, "id": uuid.uuid4()},
            )
            legacy_invitation_id = _insert_invitation(
                conn, org_id=org_id, token=legacy_invitation, status="PENDING"
            )

        _migrate(migration_db_url, "upgrade", HASHING_REVISION)

        with engine.begin() as conn:
            # Expand only: existing rows keep their raw token, so the previous
            # app version still running during the rollout reads them unchanged.
            assert conn.execute(
                sa.text("SELECT token, token_hashed FROM access_token")
            ).one() == (legacy_session, False)
            assert conn.execute(
                sa.text(
                    "SELECT token, token_hashed, encrypted_token FROM invitation"
                    " WHERE id = :id"
                ),
                {"id": legacy_invitation_id},
            ).one() == (legacy_invitation, False, None)

            # Rows the new app writes after the upgrade hold digests.
            conn.execute(
                sa.text(
                    "INSERT INTO access_token"
                    " (token, created_at, user_id, id, token_hashed)"
                    " VALUES (:token, now(), :user_id, :id, true)"
                ),
                {
                    "token": hash_bearer_token(secrets.token_urlsafe()),
                    "user_id": user_id,
                    "id": uuid.uuid4(),
                },
            )
            hashed_pending_id = _insert_invitation(
                conn,
                org_id=org_id,
                token=hash_bearer_token(secrets.token_urlsafe(48)[:64]),
                status="PENDING",
            )
            hashed_accepted_id = _insert_invitation(
                conn,
                org_id=org_id,
                token=hash_bearer_token(secrets.token_urlsafe(48)[:64]),
                status="ACCEPTED",
            )
            conn.execute(
                sa.text(
                    "UPDATE invitation SET token_hashed = true WHERE id IN (:a, :b)"
                ),
                {"a": hashed_pending_id, "b": hashed_accepted_id},
            )

        output = _migrate(migration_db_url, "downgrade", PREVIOUS_REVISION)
        assert "deleted 1 hashed sessions and revoked 1 pending invitations" in output

        with engine.begin() as conn:
            assert "token_hashed" not in _columns(conn, "access_token")
            assert {"token_hashed", "encrypted_token"}.isdisjoint(
                _columns(conn, "invitation")
            )
            # The previous version cannot use a digest, so hashed sessions go;
            # the session written before the upgrade survives.
            assert conn.scalars(sa.text("SELECT token FROM access_token")).all() == [
                legacy_session
            ]
            statuses = dict(
                conn.execute(sa.text("SELECT id, status::text FROM invitation"))
                .tuples()
                .all()
            )
            # A pending row holding a digest would accept that digest as its
            # link token under the previous version, so it is revoked.
            assert statuses == {
                legacy_invitation_id: "PENDING",
                hashed_pending_id: "REVOKED",
                hashed_accepted_id: "ACCEPTED",
            }
            assert (
                conn.scalar(
                    sa.text("SELECT token FROM invitation WHERE id = :id"),
                    {"id": legacy_invitation_id},
                )
                == legacy_invitation
            )
    finally:
        engine.dispose()
