"""Session and invitation bearer tokens are stored only as digests.

Read access to the database (a backup, a replica, a DBA account, or SQL
injection) must not yield a cookie or invitation link that works.
"""

from __future__ import annotations

import contextlib
import re
import secrets
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie

import pytest
from fastapi import Response
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.crypto import hash_bearer_token
from autosecops.auth.schemas import UserRole
from autosecops.auth.session_tokens import HashedAccessTokenDatabase
from autosecops.auth.users import (
    SessionMetadataDatabaseStrategy,
    UserManager,
    auth_backend,
    cookie_transport,
)
from autosecops.db.models import (
    AccessToken,
    Invitation,
    InvitationGrant,
    Organization,
    User,
)
from autosecops.db.models import Role as DBRole
from autosecops.email.transport import OutboundEmail, SMTPTransport
from autosecops.invitations.consumer import run_invitation_email_tick
from autosecops.invitations.enums import InvitationStatus
from autosecops.invitations.router import get_invitation_by_token
from autosecops.invitations.schemas import InvitationCreate
from autosecops.invitations.schemas import InvitationGrant as InvitationGrantSchema
from autosecops.invitations.service import (
    create_invitation_row,
    find_invitation_by_token,
    reveal_invitation_token,
)

# --- Fixtures


@pytest.fixture
async def user(session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"hashing-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="unused",
        role=UserRole.BASIC,
        is_active=True,
        is_superuser=False,
        is_verified=True,
    )
    session.add(user)
    await session.commit()
    return user


@pytest.fixture
async def org(session: AsyncSession) -> Organization:
    org = Organization(
        id=uuid.uuid4(),
        name="Hashing Org",
        slug=f"hashing-org-{uuid.uuid4().hex[:8]}",
        is_active=True,
    )
    session.add(org)
    await session.commit()
    return org


@pytest.fixture
async def org_role(session: AsyncSession, org: Organization) -> DBRole:
    role = DBRole(
        id=uuid.uuid4(),
        name="Organization Member",
        slug=f"organization-member-{uuid.uuid4().hex[:8]}",
        description="Member role",
        organization_id=org.id,
    )
    session.add(role)
    await session.commit()
    return role


def _strategy(session: AsyncSession) -> SessionMetadataDatabaseStrategy:
    return SessionMetadataDatabaseStrategy(
        HashedAccessTokenDatabase(session, AccessToken),
        lifetime_seconds=config.SESSION_EXPIRE_TIME_SECONDS,
    )


def _user_manager(session: AsyncSession) -> UserManager:
    return UserManager(SQLAlchemyUserDatabase(session, User))


def _cookie_value(response: Response) -> str:
    cookie = SimpleCookie()
    cookie.load(response.headers["set-cookie"])
    return cookie[cookie_transport.cookie_name].value


async def _stored_session_rows(
    session: AsyncSession, user_id: uuid.UUID
) -> list[tuple[str, bool]]:
    table = AccessToken.__table__
    result = await session.execute(
        select(table.c.token, table.c.token_hashed).where(table.c.user_id == user_id)
    )
    return [(token, hashed) for token, hashed in result.tuples()]


# --- Digest


def test_hash_bearer_token_is_fixed_length_and_url_safe() -> None:
    digests = {hash_bearer_token(secrets.token_urlsafe()) for _ in range(50)}
    assert len(digests) == 50
    for digest in digests:
        assert len(digest) == 43
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", digest)
    assert hash_bearer_token("same") == hash_bearer_token("same")


# --- Sessions


@pytest.mark.anyio
async def test_login_stores_only_the_digest_and_logout_deletes_it(
    session: AsyncSession, user: User
) -> None:
    strategy = _strategy(session)

    response = await auth_backend.login(strategy, user)
    raw = _cookie_value(response)

    rows = await _stored_session_rows(session, user.id)
    assert rows == [(hash_bearer_token(raw), True)]
    assert raw not in {token for token, _ in rows}

    authenticated = await strategy.read_token(raw, _user_manager(session))
    assert authenticated is not None and authenticated.id == user.id

    await auth_backend.logout(strategy, user, raw)
    assert await _stored_session_rows(session, user.id) == []
    assert await strategy.read_token(raw, _user_manager(session)) is None


@pytest.mark.anyio
async def test_digest_read_from_database_is_not_a_valid_cookie(
    session: AsyncSession, user: User
) -> None:
    strategy = _strategy(session)
    raw = await strategy.write_token(user)
    [(digest, _)] = await _stored_session_rows(session, user.id)

    assert await strategy.read_token(digest, _user_manager(session)) is None
    # Logging out with the stolen digest must not touch the real session.
    await strategy.destroy_token(digest, user)
    assert await _stored_session_rows(session, user.id) == [(digest, True)]
    assert await strategy.read_token(raw, _user_manager(session)) is not None


@pytest.mark.anyio
async def test_session_written_by_previous_version_still_authenticates(
    session: AsyncSession, user: User
) -> None:
    """A row inserted raw during a rolling upgrade works until the contract step."""
    raw = secrets.token_urlsafe()
    session.add(AccessToken(token=raw, token_hashed=False, user_id=user.id))
    await session.commit()
    strategy = _strategy(session)

    authenticated = await strategy.read_token(raw, _user_manager(session))
    assert authenticated is not None and authenticated.id == user.id
    # A raw value matches only rows flagged raw, never a hashed row's digest.
    assert (
        await strategy.read_token(hash_bearer_token(raw), _user_manager(session))
        is None
    )

    await strategy.destroy_token(raw, user)
    assert await _stored_session_rows(session, user.id) == []


@pytest.mark.anyio
async def test_expired_hashed_session_is_rejected(
    session: AsyncSession, user: User
) -> None:
    strategy = _strategy(session)
    raw = await strategy.write_token(user)
    table = AccessToken.__table__
    await session.execute(
        update(AccessToken)
        .where(table.c.user_id == user.id)
        .values(
            created_at=datetime.now(UTC)
            - timedelta(seconds=config.SESSION_EXPIRE_TIME_SECONDS + 60)
        )
    )
    await session.commit()

    assert await strategy.read_token(raw, _user_manager(session)) is None


# --- Invitations


async def _create_invitation(
    session: AsyncSession, org: Organization, role: DBRole
) -> Invitation:
    invitation = await create_invitation_row(
        session,
        organization_id=org.id,
        params=InvitationCreate(
            email=f"invitee-{uuid.uuid4().hex[:8]}@example.com",
            grants=[InvitationGrantSchema(role_id=role.id)],
        ),
        invited_by=None,
        created_by_platform_admin=False,
    )
    await session.commit()
    return invitation


async def _stored_invitation(
    session: AsyncSession, invitation_id: uuid.UUID
) -> tuple[str, bool, bytes | None]:
    row = (
        await session.execute(
            select(
                Invitation.token, Invitation.token_hashed, Invitation.encrypted_token
            ).where(Invitation.id == invitation_id)
        )
    ).one()
    return row.token, row.token_hashed, row.encrypted_token


@pytest.mark.anyio
async def test_invitation_row_never_contains_the_raw_token(
    session: AsyncSession, org: Organization, org_role: DBRole
) -> None:
    invitation = await _create_invitation(session, org, org_role)
    raw = await reveal_invitation_token(session, invitation)

    token, hashed, ciphertext = await _stored_invitation(session, invitation.id)
    assert token == hash_bearer_token(raw)
    assert hashed is True
    assert ciphertext is not None
    assert raw.encode() not in ciphertext

    found = await find_invitation_by_token(session, raw)
    assert found is not None and found.id == invitation.id
    assert await find_invitation_by_token(session, token) is None

    page = await get_invitation_by_token(session=session, token=raw)
    assert page.organization_id == org.id
    assert page.status == InvitationStatus.PENDING


@pytest.mark.anyio
async def test_invitation_hashed_by_migration_keeps_link_until_rotated(
    session: AsyncSession, org: Organization, org_role: DBRole
) -> None:
    """A pre-upgrade link works; revealing the token issues a new one."""
    emailed_raw = secrets.token_urlsafe(48)[:64]
    invitation = Invitation(
        id=uuid.uuid4(),
        organization_id=org.id,
        email=f"legacy-{uuid.uuid4().hex[:8]}@example.com",
        status=InvitationStatus.PENDING,
        token=hash_bearer_token(emailed_raw),
        token_hashed=True,
        encrypted_token=None,
        expires_at=datetime.now(UTC) + timedelta(days=7),
        grants=[InvitationGrant(organization_id=org.id, role_id=org_role.id)],
    )
    session.add(invitation)
    await session.commit()

    found = await find_invitation_by_token(session, emailed_raw)
    assert found is not None and found.id == invitation.id

    new_raw = await reveal_invitation_token(session, invitation)
    await session.commit()
    assert new_raw != emailed_raw
    assert await find_invitation_by_token(session, emailed_raw) is None
    found = await find_invitation_by_token(session, new_raw)
    assert found is not None and found.id == invitation.id

    token, _, ciphertext = await _stored_invitation(session, invitation.id)
    assert token == hash_bearer_token(new_raw)
    assert ciphertext is not None
    # Later reveals decrypt instead of rotating again.
    assert await reveal_invitation_token(session, invitation) == new_raw


@pytest.mark.anyio
async def test_invitation_written_by_previous_version_still_resolves(
    session: AsyncSession, org: Organization, org_role: DBRole
) -> None:
    raw = secrets.token_urlsafe(48)[:64]
    invitation = Invitation(
        id=uuid.uuid4(),
        organization_id=org.id,
        email=f"rollout-{uuid.uuid4().hex[:8]}@example.com",
        status=InvitationStatus.PENDING,
        token=raw,
        token_hashed=False,
        expires_at=datetime.now(UTC) + timedelta(days=7),
        grants=[InvitationGrant(organization_id=org.id, role_id=org_role.id)],
    )
    session.add(invitation)
    await session.commit()

    found = await find_invitation_by_token(session, raw)
    assert found is not None and found.id == invitation.id
    assert await reveal_invitation_token(session, invitation) == raw


class _RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[OutboundEmail] = []

    async def send(self, message: OutboundEmail) -> None:
        self.sent.append(message)


@pytest.mark.anyio
async def test_outbox_emails_the_raw_token_not_the_digest(
    session: AsyncSession,
    org: Organization,
    org_role: DBRole,
    smtp_configured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextlib.asynccontextmanager
    async def fake_session_context() -> AsyncGenerator[AsyncSession, None]:
        yield session

    monkeypatch.setattr(
        "autosecops.invitations.consumer.get_async_session_bypass_rls_context_manager",
        fake_session_context,
    )
    transport = _RecordingTransport()
    monkeypatch.setattr(
        "autosecops.invitations.consumer.SMTPTransport.from_config",
        staticmethod(lambda: transport),
    )
    assert SMTPTransport.from_config() is transport

    invitation = await _create_invitation(session, org, org_role)
    raw = await reveal_invitation_token(session, invitation)
    digest = hash_bearer_token(raw)

    assert await run_invitation_email_tick() == 1
    [message] = transport.sent
    assert f"token={raw}" in message.text
    assert digest not in message.text
    assert digest not in message.html
