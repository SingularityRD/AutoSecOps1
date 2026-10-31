"""End-to-end password registration with email verification over the real app."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import status
from sqlalchemy import delete, select

from autosecops import config
from autosecops.api.app import app as api_app
from autosecops.auth import email_verification as ev
from autosecops.auth.email_verification import run_verification_email_tick
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import User
from autosecops.email.transport import OutboundEmail

PASSWORD = "a-long-enough-password"
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


async def _login(client: httpx.AsyncClient, email: str) -> httpx.Response:
    return await client.post(
        "/auth/login", data={"username": email, "password": PASSWORD}
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

        verified = await client.post("/auth/verify", json={"token": token})
        assert verified.status_code == status.HTTP_200_OK
        assert verified.json()["is_verified"] is True

        reused = await client.post("/auth/verify", json={"token": token})
        assert reused.status_code == status.HTTP_400_BAD_REQUEST
        assert reused.json()["detail"] == "VERIFY_USER_ALREADY_VERIFIED"

        signed_in = await _login(client, email)
        assert signed_in.status_code == status.HTTP_204_NO_CONTENT


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
