"""End-to-end password registration with email verification over the real app."""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import status
from sqlalchemy import delete, select

from autosecops import config
from autosecops.api.app import app as api_app
from autosecops.auth import email_verification as ev
from autosecops.auth.crypto import hash_bearer_token
from autosecops.auth.email_verification import run_verification_email_tick
from autosecops.authz.scopes import ORG_MEMBER_ROLE_SLUG
from autosecops.authz.seeding import seed_system_roles_for_org
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import Invitation, InvitationGrant, Organization, Role, User
from autosecops.email.transport import OutboundEmail
from autosecops.invitations.enums import InvitationStatus

PASSWORD = "a-long-enough-password"
NEW_PASSWORD = "the-mailbox-owner-password"
PUBLIC_CLIENT = ("203.0.113.20", 4321)


class FakeTransport:
    def __init__(self) -> None:
        self.sent: list[OutboundEmail] = []

    async def send(self, message: OutboundEmail) -> None:
        self.sent.append(message)


@pytest.fixture
async def created_emails(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[list[str]]:
    """Open registration to any domain and delete the accounts afterwards."""
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_ALLOWED_DOMAINS", [])
    emails: list[str] = []
    # Registration past the first user needs at least one account to exist.
    anchor = f"anchor-{uuid.uuid4().hex[:8]}@example.com"
    async with get_async_session_bypass_rls_context_manager() as session:
        session.add(User(email=anchor, hashed_password="x", is_verified=True))
        await session.commit()
    emails.append(anchor)
    yield emails
    async with get_async_session_bypass_rls_context_manager() as session:
        await session.execute(delete(User).where(User.email.in_(emails)))  # pyright: ignore[reportAttributeAccessIssue]
        await session.commit()


def _client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=api_app, client=PUBLIC_CLIENT)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def _login(
    client: httpx.AsyncClient, email: str, *, password: str = PASSWORD
) -> httpx.Response:
    return await client.post(
        "/auth/login", data={"username": email, "password": password}
    )


@pytest.mark.anyio
async def test_self_registration_signs_in_only_after_verification(
    created_emails: list[str],
    smtp_configured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeTransport()
    monkeypatch.setattr(
        ev.SMTPTransport, "from_config", staticmethod(lambda: transport)
    )
    email = f"self-{uuid.uuid4().hex[:8]}@example.com"
    created_emails.append(email)

    async with _client() as client:
        registered = await client.post(
            "/auth/register",
            json={"email": email, "password": PASSWORD, "is_verified": True},
        )
        assert registered.status_code == status.HTTP_201_CREATED
        assert registered.json()["is_verified"] is False

        refused = await _login(client, email)
        assert refused.status_code == status.HTTP_400_BAD_REQUEST
        assert refused.json()["detail"] == "LOGIN_USER_NOT_VERIFIED"

        await run_verification_email_tick()
        [message] = [m for m in transport.sent if m.to == (email,)]
        link = next(w for w in message.text.split() if w.startswith("http"))
        token = parse_qs(urlsplit(link).query)["token"][0]

        # The link alone is not enough: it must also set the password.
        token_only = await client.post("/auth/verify", json={"token": token})
        assert token_only.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        weak = await client.post(
            "/auth/verify", json={"token": token, "password": "short"}
        )
        assert weak.status_code == status.HTTP_400_BAD_REQUEST
        assert weak.json()["detail"]["code"] == "VERIFY_USER_INVALID_PASSWORD"

        verified = await client.post(
            "/auth/verify", json={"token": token, "password": NEW_PASSWORD}
        )
        assert verified.status_code == status.HTTP_200_OK
        assert verified.json()["is_verified"] is True

        reused = await client.post(
            "/auth/verify", json={"token": token, "password": NEW_PASSWORD}
        )
        assert reused.status_code == status.HTTP_400_BAD_REQUEST
        assert reused.json()["detail"] == "VERIFY_USER_ALREADY_VERIFIED"

        # The password chosen at registration no longer works.
        old_password = await _login(client, email)
        assert old_password.status_code == status.HTTP_400_BAD_REQUEST
        assert old_password.json()["detail"] == "LOGIN_BAD_CREDENTIALS"
        signed_in = await _login(client, email, password=NEW_PASSWORD)
        assert signed_in.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.anyio
async def test_invitation_registration_without_smtp_signs_in(
    created_emails: list[str], smtp_unconfigured: None
) -> None:
    """Invitation tokens are stored hashed; the raw link token must still admit."""
    email = f"invited-{uuid.uuid4().hex[:8]}@example.com"
    created_emails.append(email)
    raw = secrets.token_urlsafe(32)
    org_id = uuid.uuid4()
    async with get_async_session_bypass_rls_context_manager() as session:
        session.add(
            Organization(id=org_id, name="Invite org", slug=f"invite-{org_id.hex[:8]}")
        )
        await session.flush()
        await seed_system_roles_for_org(session, org_id)
        member_role_id = await session.scalar(
            select(Role.id).where(
                Role.organization_id == org_id, Role.slug == ORG_MEMBER_ROLE_SLUG
            )
        )
        assert member_role_id is not None
        invitation = Invitation(
            organization_id=org_id,
            email=email,
            token=hash_bearer_token(raw),
            token_hashed=True,
            expires_at=datetime.now(UTC) + timedelta(days=7),
            status=InvitationStatus.PENDING,
        )
        session.add(invitation)
        await session.flush()
        session.add(
            InvitationGrant(
                organization_id=org_id,
                invitation_id=invitation.id,
                role_id=member_role_id,
            )
        )
        await session.commit()

    try:
        async with _client() as client:
            bogus = await client.post(
                "/auth/register",
                json={
                    "email": email,
                    "password": PASSWORD,
                    "invitation_token": hash_bearer_token(raw),
                },
            )
            assert bogus.status_code == status.HTTP_403_FORBIDDEN

            registered = await client.post(
                "/auth/register",
                json={"email": email, "password": PASSWORD, "invitation_token": raw},
            )
            assert registered.status_code == status.HTTP_201_CREATED
            assert registered.json()["is_verified"] is True

            signed_in = await _login(client, email)
            assert signed_in.status_code == status.HTTP_204_NO_CONTENT
    finally:
        async with get_async_session_bypass_rls_context_manager() as session:
            await session.execute(delete(User).where(User.email == email))  # pyright: ignore[reportArgumentType]
            await session.execute(delete(Organization).where(Organization.id == org_id))  # pyright: ignore[reportArgumentType]
            await session.commit()


@pytest.mark.anyio
async def test_self_registration_is_refused_without_smtp(
    created_emails: list[str], smtp_unconfigured: None
) -> None:
    email = f"nosmtp-{uuid.uuid4().hex[:8]}@example.com"
    created_emails.append(email)

    async with _client() as client:
        response = await client.post(
            "/auth/register", json={"email": email, "password": PASSWORD}
        )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"]["code"] == "self_registration_unavailable"
    async with get_async_session_bypass_rls_context_manager() as session:
        found = await session.execute(select(User).where(User.email == email))  # pyright: ignore[reportArgumentType]
        assert found.scalars().first() is None


@pytest.mark.anyio
async def test_request_verify_token_answers_the_same_for_unknown_email(
    created_emails: list[str], smtp_configured: None
) -> None:
    async with _client() as client:
        response = await client.post(
            "/auth/request-verify-token",
            json={"email": f"nobody-{uuid.uuid4().hex[:8]}@example.com"},
        )

    assert response.status_code == status.HTTP_202_ACCEPTED
