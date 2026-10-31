"""Email verification for password accounts: tokens, outbox, and policy."""

from __future__ import annotations

import contextlib
import secrets
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import HTTPException
from fastapi_users import InvalidPasswordException
from fastapi_users.exceptions import (
    InvalidVerifyToken,
    UserAlreadyVerified,
    UserInactive,
)
from fastapi_users.password import PasswordHelper
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth import email_verification as ev
from autosecops.auth import users as users_module
from autosecops.auth.crypto import hash_bearer_token
from autosecops.auth.email_verification import (
    MAX_EMAIL_ATTEMPTS,
    create_verification_token,
    enqueue_verification_email,
    run_verification_email_tick,
    verification_email,
)
from autosecops.auth.enums import AuthErrorCode, EmailVerificationMethod
from autosecops.auth.schemas import UserCreate
from autosecops.auth.users import (
    LicensedUserDatabase,
    SessionMetadataDatabaseStrategy,
    UserManager,
)
from autosecops.db.models import (
    AccessToken,
    EmailVerificationOutbox,
    Invitation,
    OAuthAccount,
    Organization,
    User,
)
from autosecops.email.transport import EmailDeliveryError, OutboundEmail, SMTPTransport
from autosecops.invitations.enums import InvitationStatus

PASSWORD = "registrant-password-1234"
NEW_PASSWORD = "mailbox-owner-password-5678"
SUPERADMIN_EMAIL = "superadmin@example.com"


class FakeTransport:
    """Records sends, optionally failing with a chosen error."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.sent: list[OutboundEmail] = []

    async def send(self, message: OutboundEmail) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append(message)


@pytest.fixture(autouse=True)
def isolate_side_effects(session: AsyncSession, monkeypatch: pytest.MonkeyPatch):
    """Keep every write in the test transaction and stub tenant defaults."""

    @contextlib.asynccontextmanager
    async def fake_session_context() -> AsyncGenerator[AsyncSession, None]:
        yield session

    monkeypatch.setattr(
        ev, "get_async_session_bypass_rls_context_manager", fake_session_context
    )
    monkeypatch.setattr(
        users_module,
        "get_async_session_bypass_rls_context_manager",
        fake_session_context,
    )
    defaults = AsyncMock(return_value=None)
    monkeypatch.setattr(users_module, "ensure_single_tenant_user_defaults", defaults)
    return defaults


def _patch_transport(monkeypatch: pytest.MonkeyPatch, transport: FakeTransport) -> None:
    real_from_config = SMTPTransport.from_config

    def fake_from_config() -> FakeTransport | None:
        return transport if real_from_config() is not None else None

    monkeypatch.setattr(ev.SMTPTransport, "from_config", staticmethod(fake_from_config))


@pytest.fixture
def manager(session: AsyncSession) -> UserManager:
    manager = UserManager(LicensedUserDatabase(session, User, OAuthAccount))
    # Domain policy and audit sinks open their own sessions; neither is under
    # test here.
    manager.validate_email = AsyncMock()  # pyright: ignore[reportAttributeAccessIssue]
    manager._emit_user_verify_audit = AsyncMock()  # pyright: ignore[reportAttributeAccessIssue]
    manager._emit_user_create_audit = AsyncMock()  # pyright: ignore[reportAttributeAccessIssue]
    return manager


async def _add_user(
    session: AsyncSession,
    *,
    verified: bool = False,
    active: bool = True,
    email: str | None = None,
    verified_via: EmailVerificationMethod | None = None,
) -> User:
    user = User(
        email=email or f"user-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=PasswordHelper().hash(PASSWORD),
        is_active=active,
        is_verified=verified,
        email_verified_via=verified_via.value if verified_via else None,
    )
    session.add(user)
    await session.commit()
    return user


async def _outbox(session: AsyncSession, user_id: uuid.UUID) -> EmailVerificationOutbox:
    row = await session.get(EmailVerificationOutbox, user_id)
    assert row is not None
    await session.refresh(row)
    return row


# === Tokens === #


@pytest.mark.anyio
async def test_minted_token_verifies_the_account_exactly_once(
    session: AsyncSession, manager: UserManager
) -> None:
    user = await _add_user(session)
    token = create_verification_token(user_id=user.id, email=user.email)

    verified = await manager.verify_with_password(token, NEW_PASSWORD)

    assert verified.is_verified is True
    assert verified.email_verified_via == EmailVerificationMethod.EMAIL
    with pytest.raises(UserAlreadyVerified):
        await manager.verify_with_password(token, NEW_PASSWORD)


@pytest.mark.anyio
async def test_verification_hands_the_account_to_the_mailbox_owner(
    session: AsyncSession, manager: UserManager
) -> None:
    """Whoever registered someone else's address loses it once the owner verifies."""
    user = await _add_user(session)
    session.add(AccessToken(token=uuid.uuid4().hex, user_id=user.id))
    await session.commit()
    token = create_verification_token(user_id=user.id, email=user.email)

    verified = await manager.verify_with_password(token, NEW_PASSWORD)

    helper = PasswordHelper()
    assert helper.verify_and_update(NEW_PASSWORD, verified.hashed_password)[0]
    assert not helper.verify_and_update(PASSWORD, verified.hashed_password)[0]
    tokens = await session.execute(
        select(AccessToken).where(AccessToken.user_id == user.id)  # pyright: ignore[reportArgumentType]
    )
    assert tokens.scalars().all() == []


@pytest.mark.anyio
async def test_verification_with_a_weak_password_changes_nothing(
    session: AsyncSession, manager: UserManager
) -> None:
    user = await _add_user(session)
    token = create_verification_token(user_id=user.id, email=user.email)

    with pytest.raises(InvalidPasswordException):
        await manager.verify_with_password(token, "short")

    await session.refresh(user)
    assert user.is_verified is False
    assert PasswordHelper().verify_and_update(PASSWORD, user.hashed_password)[0]


@pytest.mark.anyio
async def test_token_only_verification_is_refused(
    session: AsyncSession, manager: UserManager
) -> None:
    user = await _add_user(session)
    token = create_verification_token(user_id=user.id, email=user.email)

    with pytest.raises(NotImplementedError):
        await manager.verify(token)

    await session.refresh(user)
    assert user.is_verified is False


@pytest.mark.anyio
async def test_token_for_a_deactivated_account_is_rejected(
    session: AsyncSession, manager: UserManager
) -> None:
    user = await _add_user(session, active=False)
    token = create_verification_token(user_id=user.id, email=user.email)

    with pytest.raises(InvalidVerifyToken):
        await manager.verify_with_password(token, NEW_PASSWORD)


@pytest.mark.anyio
async def test_token_is_void_after_an_email_change(
    session: AsyncSession, manager: UserManager
) -> None:
    user = await _add_user(session)
    token = create_verification_token(user_id=user.id, email=user.email)
    user.email = f"changed-{uuid.uuid4().hex[:8]}@example.com"
    await session.commit()

    with pytest.raises(InvalidVerifyToken):
        await manager.verify_with_password(token, NEW_PASSWORD)


@pytest.mark.anyio
async def test_expired_token_is_rejected(
    session: AsyncSession, manager: UserManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _add_user(session)
    monkeypatch.setattr(
        config, "AUTOSECOPS__AUTH_EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS", -1
    )
    token = create_verification_token(user_id=user.id, email=user.email)

    with pytest.raises(InvalidVerifyToken):
        await manager.verify_with_password(token, NEW_PASSWORD)


@pytest.mark.anyio
async def test_token_for_another_account_is_rejected(
    session: AsyncSession, manager: UserManager
) -> None:
    victim = await _add_user(session)
    attacker = await _add_user(session)
    token = create_verification_token(user_id=attacker.id, email=victim.email)

    with pytest.raises(InvalidVerifyToken):
        await manager.verify_with_password(token, NEW_PASSWORD)


@pytest.mark.anyio
async def test_verification_email_links_to_the_app_and_escapes() -> None:
    message = verification_email(to="member@example.com", token="a.b+c/d")

    assert message.to == ("member@example.com",)
    link = next(word for word in message.text.split() if word.startswith("http"))
    parsed = urlsplit(link)
    assert parsed.path == "/verify-email"
    assert parse_qs(parsed.query)["token"] == ["a.b+c/d"]
    assert "a.b%2Bc%2Fd" in message.html
    assert "ignore this email" in message.text


# === Outbox === #


@pytest.mark.anyio
async def test_enqueue_honours_the_resend_cooldown(session: AsyncSession) -> None:
    user = await _add_user(session)

    assert await enqueue_verification_email(session, user.id) is True
    # A waiting row is refreshed, not duplicated.
    assert await enqueue_verification_email(session, user.id) is True

    row = await _outbox(session, user.id)
    row.claimed_at = datetime.now(UTC)
    row.sent_at = datetime.now(UTC)
    await session.commit()
    assert await enqueue_verification_email(session, user.id) is False

    row = await _outbox(session, user.id)
    row.claimed_at = datetime.now(UTC) - timedelta(minutes=10)
    row.sent_at = datetime.now(UTC) - timedelta(minutes=10)
    row.attempts = MAX_EMAIL_ATTEMPTS
    await session.commit()
    assert await enqueue_verification_email(session, user.id) is True
    row = await _outbox(session, user.id)
    assert row.claimed_at is None
    assert row.attempts == 0


@pytest.mark.anyio
async def test_enqueue_leaves_an_in_flight_send_alone(session: AsyncSession) -> None:
    user = await _add_user(session)
    await enqueue_verification_email(session, user.id)
    row = await _outbox(session, user.id)
    row.claimed_at = datetime.now(UTC)
    await session.commit()

    assert await enqueue_verification_email(session, user.id) is False


@pytest.mark.anyio
async def test_tick_sends_a_working_link_and_stores_no_token(
    session: AsyncSession,
    manager: UserManager,
    smtp_configured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await _add_user(session)
    await enqueue_verification_email(session, user.id)
    await session.commit()
    transport = FakeTransport()
    _patch_transport(monkeypatch, transport)

    assert await run_verification_email_tick() == 1

    assert len(transport.sent) == 1
    message = transport.sent[0]
    assert message.to == (user.email,)
    row = await _outbox(session, user.id)
    assert row.sent_at is not None
    assert row.attempts == 1
    link = next(word for word in message.text.split() if word.startswith("http"))
    token = parse_qs(urlsplit(link).query)["token"][0]
    verified = await manager.verify_with_password(token, NEW_PASSWORD)
    assert verified.is_verified is True


@pytest.mark.anyio
async def test_tick_skips_verified_and_inactive_accounts(
    session: AsyncSession, smtp_configured: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    verified = await _add_user(session, verified=True)
    inactive = await _add_user(session, active=False)
    for user in (verified, inactive):
        await enqueue_verification_email(session, user.id)
    await session.commit()
    transport = FakeTransport()
    _patch_transport(monkeypatch, transport)

    assert await run_verification_email_tick() == 0
    assert transport.sent == []


@pytest.mark.anyio
async def test_tick_releases_the_claim_on_a_retryable_failure(
    session: AsyncSession, smtp_configured: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _add_user(session)
    await enqueue_verification_email(session, user.id)
    await session.commit()
    _patch_transport(
        monkeypatch, FakeTransport(EmailDeliveryError("down", retryable=True))
    )

    assert await run_verification_email_tick() == 0

    row = await _outbox(session, user.id)
    assert row.claimed_at is None
    assert row.attempts == 1
    assert row.sent_at is None


@pytest.mark.anyio
async def test_tick_does_nothing_without_smtp(
    session: AsyncSession, smtp_unconfigured: None
) -> None:
    user = await _add_user(session)
    await enqueue_verification_email(session, user.id)
    await session.commit()

    assert await run_verification_email_tick() == 0
    row = await _outbox(session, user.id)
    assert row.claimed_at is None


# === UserManager policy === #


@pytest.mark.anyio
async def test_request_verify_queues_without_minting_a_token(
    session: AsyncSession, manager: UserManager, smtp_configured: None
) -> None:
    user = await _add_user(session)
    manager.on_after_request_verify = AsyncMock()  # pyright: ignore[reportAttributeAccessIssue]

    await manager.request_verify(user)

    manager.on_after_request_verify.assert_not_awaited()
    assert (await _outbox(session, user.id)).claimed_at is None


@pytest.mark.anyio
async def test_request_verify_refuses_verified_and_inactive(
    session: AsyncSession, manager: UserManager, smtp_configured: None
) -> None:
    with pytest.raises(UserAlreadyVerified):
        await manager.request_verify(await _add_user(session, verified=True))
    with pytest.raises(UserInactive):
        await manager.request_verify(await _add_user(session, active=False))


@pytest.mark.anyio
async def test_request_verify_without_smtp_queues_nothing(
    session: AsyncSession, manager: UserManager, smtp_unconfigured: None
) -> None:
    user = await _add_user(session)

    await manager.request_verify(user)

    assert await session.get(EmailVerificationOutbox, user.id) is None


@pytest.mark.anyio
async def test_verify_clears_the_outbox_and_applies_defaults(
    session: AsyncSession,
    manager: UserManager,
    smtp_configured: None,
    isolate_side_effects: AsyncMock,
) -> None:
    user = await _add_user(session)
    await enqueue_verification_email(session, user.id)
    await session.commit()

    await manager.verify_with_password(
        create_verification_token(user_id=user.id, email=user.email), NEW_PASSWORD
    )

    result = await session.execute(
        select(EmailVerificationOutbox).where(
            EmailVerificationOutbox.user_id == user.id
        )
    )
    assert result.scalar_one_or_none() is None
    isolate_side_effects.assert_awaited_once()


@pytest.mark.anyio
async def test_identity_provider_adopts_unverified_account(
    session: AsyncSession, manager: UserManager
) -> None:
    """A squatter's password and sessions do not survive SSO proving the email."""
    user = await _add_user(session)
    session.add(AccessToken(token=uuid.uuid4().hex, user_id=user.id))
    await session.commit()

    adopted = await manager.provision_user_by_email(
        email=user.email, is_verified_by_default=True, provider="saml"
    )

    assert adopted.id == user.id
    assert adopted.is_verified is True
    verified, _ = PasswordHelper().verify_and_update(PASSWORD, adopted.hashed_password)
    assert verified is False
    tokens = await session.execute(
        select(AccessToken).where(AccessToken.user_id == user.id)  # pyright: ignore[reportArgumentType]
    )
    assert tokens.scalars().all() == []


@pytest.mark.anyio
async def test_identity_provider_adopts_an_invitation_sign_up(
    session: AsyncSession, manager: UserManager
) -> None:
    """An invitation link proves no mailbox control: its reader may have used it."""
    user = await _add_user(
        session, verified=True, verified_via=EmailVerificationMethod.INVITATION
    )

    adopted = await manager.provision_user_by_email(
        email=user.email, is_verified_by_default=True, provider="scim"
    )

    assert adopted.email_verified_via == EmailVerificationMethod.SCIM
    verified, _ = PasswordHelper().verify_and_update(PASSWORD, adopted.hashed_password)
    assert verified is False


@pytest.mark.anyio
async def test_oidc_sign_in_adopts_unverified_account(
    session: AsyncSession, manager: UserManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The OIDC callback links by email only after replacing the squatter's password."""
    user = await _add_user(session)
    session.add(AccessToken(token=uuid.uuid4().hex, user_id=user.id))
    await session.commit()
    monkeypatch.setattr(manager, "_enforce_login_ip_allowlist", AsyncMock())

    linked = await manager.oauth_callback(
        "oidc",
        "provider-access-token",
        "provider-account-id",
        user.email,
        associate_by_email=True,
        is_verified_by_default=True,
    )

    assert linked.id == user.id
    assert linked.is_verified is True
    assert linked.email_verified_via == EmailVerificationMethod.OIDC
    verified, _ = PasswordHelper().verify_and_update(PASSWORD, linked.hashed_password)
    assert verified is False
    tokens = await session.execute(
        select(AccessToken).where(AccessToken.user_id == user.id)  # pyright: ignore[reportArgumentType]
    )
    assert tokens.scalars().all() == []


@pytest.mark.anyio
async def test_identity_provider_leaves_verified_account_password(
    session: AsyncSession, manager: UserManager
) -> None:
    user = await _add_user(session, verified=True)
    original_hash = user.hashed_password

    linked = await manager.provision_user_by_email(email=user.email)

    assert linked.hashed_password == original_hash


@pytest.mark.anyio
async def test_new_sso_account_starts_verified(
    session: AsyncSession, manager: UserManager
) -> None:
    created = await manager.provision_user_by_email(
        email=f"sso-{uuid.uuid4().hex[:8]}@example.com"
    )

    assert created.is_verified is True


# === Self-registration gate === #


def _gate_manager(
    monkeypatch: pytest.MonkeyPatch, *, users: bool, invitation: bool
) -> UserManager:
    @contextlib.asynccontextmanager
    async def fake_session() -> AsyncGenerator[MagicMock, None]:
        yield MagicMock()

    monkeypatch.setattr(
        users_module, "get_async_session_auth_context_manager", fake_session
    )
    monkeypatch.setattr(users_module, "users_exist", AsyncMock(return_value=users))
    monkeypatch.setattr(
        users_module, "_has_matching_invitation", AsyncMock(return_value=invitation)
    )
    return UserManager(cast(Any, MagicMock()))


@pytest.mark.anyio
async def test_self_registration_is_refused_without_smtp(
    monkeypatch: pytest.MonkeyPatch, smtp_unconfigured: None
) -> None:
    manager = _gate_manager(monkeypatch, users=True, invitation=False)

    with pytest.raises(HTTPException) as exc_info:
        await manager._check_self_registration("member@example.com", None)

    assert exc_info.value.status_code == 403
    detail = cast(dict[str, str], exc_info.value.detail)
    assert detail["code"] == AuthErrorCode.SELF_REGISTRATION_UNAVAILABLE


@pytest.mark.anyio
async def test_self_registration_is_allowed_with_smtp(
    monkeypatch: pytest.MonkeyPatch, smtp_configured: None
) -> None:
    manager = _gate_manager(monkeypatch, users=True, invitation=False)

    await manager._check_self_registration("member@example.com", None)

    assert manager._pending_bootstrap_registration is False


@pytest.mark.anyio
async def test_invited_registration_needs_no_smtp(
    monkeypatch: pytest.MonkeyPatch, smtp_unconfigured: None
) -> None:
    manager = _gate_manager(monkeypatch, users=True, invitation=True)

    await manager._check_self_registration("member@example.com", "invite-token")


@pytest.mark.anyio
async def test_bogus_invitation_token_does_not_bypass_the_gate(
    monkeypatch: pytest.MonkeyPatch, smtp_unconfigured: None
) -> None:
    manager = _gate_manager(monkeypatch, users=True, invitation=False)

    with pytest.raises(HTTPException):
        await manager._check_self_registration("member@example.com", "bogus")


async def _add_invitation(
    session: AsyncSession, organization: Organization, *, email: str
) -> str:
    raw = secrets.token_urlsafe(32)
    session.add(
        Invitation(
            organization_id=organization.id,
            email=email,
            token=hash_bearer_token(raw),
            token_hashed=True,
            expires_at=datetime.now(UTC) + timedelta(days=7),
            status=InvitationStatus.PENDING,
        )
    )
    await session.commit()
    return raw


@pytest.fixture
def gate_on_test_session(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> UserManager:
    """A manager whose registration gate queries the test database."""

    @contextlib.asynccontextmanager
    async def fake_session() -> AsyncGenerator[AsyncSession, None]:
        yield session

    monkeypatch.setattr(
        users_module, "get_async_session_auth_context_manager", fake_session
    )
    monkeypatch.setattr(users_module, "users_exist", AsyncMock(return_value=True))
    return UserManager(cast(Any, MagicMock()))


@pytest.mark.anyio
async def test_hashed_invitation_admits_registration_without_smtp(
    session: AsyncSession,
    svc_organization: Organization,
    gate_on_test_session: UserManager,
    smtp_unconfigured: None,
) -> None:
    raw = await _add_invitation(session, svc_organization, email="Invited@Example.com")

    await gate_on_test_session._check_self_registration("invited@example.com", raw)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "token_for",
    ["bogus", "digest", "other-email"],
)
async def test_unmatched_invitation_does_not_bypass_the_gate(
    session: AsyncSession,
    svc_organization: Organization,
    gate_on_test_session: UserManager,
    smtp_unconfigured: None,
    token_for: str,
) -> None:
    raw = await _add_invitation(session, svc_organization, email="invited@example.com")
    token = {
        "bogus": secrets.token_urlsafe(32),
        # The stored digest must never work as a link token.
        "digest": hash_bearer_token(raw),
        "other-email": raw,
    }[token_for]
    email = "other@example.com" if token_for == "other-email" else "invited@example.com"

    with pytest.raises(HTTPException) as exc_info:
        await gate_on_test_session._check_self_registration(email, token)

    assert exc_info.value.status_code == 403


@pytest.mark.anyio
async def test_first_user_bootstrap_is_marked_for_verification(
    monkeypatch: pytest.MonkeyPatch, smtp_unconfigured: None
) -> None:
    manager = _gate_manager(monkeypatch, users=False, invitation=False)

    await manager._check_self_registration("admin@example.com", None)

    assert manager._pending_bootstrap_registration is True


@pytest.mark.anyio
async def test_unverified_registration_queues_email_and_skips_defaults(
    session: AsyncSession,
    manager: UserManager,
    smtp_configured: None,
    isolate_side_effects: AsyncMock,
) -> None:
    user = await _add_user(session)

    await manager.on_after_register(user)

    isolate_side_effects.assert_not_awaited()
    assert (await _outbox(session, user.id)).claimed_at is None
    await session.refresh(user)
    assert user.is_verified is False


@pytest.mark.anyio
async def test_bootstrap_registration_is_verified(
    session: AsyncSession,
    manager: UserManager,
    smtp_unconfigured: None,
    isolate_side_effects: AsyncMock,
) -> None:
    user = await _add_user(session)
    manager._pending_bootstrap_registration = True

    await manager.on_after_register(user)

    await session.refresh(user)
    assert user.is_verified is True
    isolate_side_effects.assert_awaited_once()
    manager._emit_user_verify_audit.assert_awaited_once()  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.anyio
async def test_accepted_invitation_verifies_registration(
    session: AsyncSession,
    manager: UserManager,
    smtp_unconfigured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await _add_user(session)
    manager._pending_invitation_token = "invite-token"
    monkeypatch.setattr(
        manager,
        "_accept_invitation_atomically",
        AsyncMock(return_value=uuid.uuid4()),
    )

    await manager.on_after_register(user)

    await session.refresh(user)
    assert user.is_verified is True
    assert user.email_verified_via == EmailVerificationMethod.INVITATION


@pytest.mark.anyio
async def test_invitation_sign_up_at_the_superadmin_email_is_not_promoted(
    session: AsyncSession,
    manager: UserManager,
    smtp_unconfigured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_SUPERADMIN_EMAIL", SUPERADMIN_EMAIL)
    user = await _add_user(session, email=SUPERADMIN_EMAIL)
    manager._pending_invitation_token = "invite-token"
    monkeypatch.setattr(
        manager,
        "_accept_invitation_atomically",
        AsyncMock(return_value=uuid.uuid4()),
    )

    await manager.on_after_register(user)

    await session.refresh(user)
    assert user.is_superuser is False


@pytest.mark.anyio
async def test_superadmin_email_is_promoted_only_once_the_mailbox_is_proven(
    session: AsyncSession,
    manager: UserManager,
    smtp_configured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_SUPERADMIN_EMAIL", SUPERADMIN_EMAIL)
    user = await _add_user(session, email=SUPERADMIN_EMAIL)

    await manager.on_after_register(user)

    await session.refresh(user)
    assert user.is_superuser is False

    verified = await manager.verify_with_password(
        create_verification_token(user_id=user.id, email=user.email), NEW_PASSWORD
    )

    await session.refresh(verified)
    assert verified.is_superuser is True


@pytest.mark.anyio
async def test_bootstrap_registration_is_promoted(
    session: AsyncSession,
    manager: UserManager,
    smtp_unconfigured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_SUPERADMIN_EMAIL", SUPERADMIN_EMAIL)
    user = await _add_user(session, email=SUPERADMIN_EMAIL)
    manager._pending_bootstrap_registration = True

    await manager.on_after_register(user)

    await session.refresh(user)
    assert user.is_superuser is True
    assert user.email_verified_via == EmailVerificationMethod.BOOTSTRAP


@pytest.mark.anyio
async def test_failed_invitation_leaves_registration_unverified(
    session: AsyncSession,
    manager: UserManager,
    smtp_configured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await _add_user(session)
    manager._pending_invitation_token = "invite-token"
    monkeypatch.setattr(
        manager, "_accept_invitation_atomically", AsyncMock(return_value=None)
    )

    await manager.on_after_register(user)

    await session.refresh(user)
    assert user.is_verified is False


@pytest.mark.anyio
async def test_public_registration_cannot_self_verify(
    session: AsyncSession,
    manager: UserManager,
    smtp_configured: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``is_verified`` in the request body is dropped on the public route."""
    monkeypatch.setattr(manager, "_check_self_registration", AsyncMock())

    user = await manager.create(
        UserCreate(
            email=f"self-{uuid.uuid4().hex[:8]}@example.com",
            password=PASSWORD,
            is_verified=True,
        ),
        safe=True,
    )

    assert user.is_verified is False


# === Sessions === #


@pytest.mark.anyio
async def test_session_of_unverified_account_reads_as_signed_out() -> None:
    database = MagicMock()
    database.get_by_token = AsyncMock(return_value=SimpleNamespace(user_id="id"))
    strategy = SessionMetadataDatabaseStrategy(database, lifetime_seconds=3600)
    user_manager = MagicMock()
    user_manager.parse_id = MagicMock(side_effect=lambda value: value)
    user_manager.get = AsyncMock(return_value=SimpleNamespace(is_verified=False))

    assert await strategy.read_token("token", user_manager) is None
