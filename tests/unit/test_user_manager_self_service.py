"""Security regressions for self-service account updates and token hooks."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from fastapi import HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.exceptions import (
    InvalidPasswordException,
    InvalidResetPasswordToken,
)
from fastapi_users.password import PasswordHelper
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.audit.enums import AuditEventStatus
from autosecops.auth import users as users_module
from autosecops.auth.audit import drain_auth_audit_tasks
from autosecops.auth.schemas import UserUpdate
from autosecops.auth.types import CredentialRevocation, Role
from autosecops.auth.users import PermissionsException, UserManager, cookie_transport
from autosecops.contexts import ctx_role
from autosecops.db.models import (
    AccessToken,
    MCPPersonalAccessToken,
    MCPRefreshToken,
    Organization,
    User,
)

OLD_PASSWORD = "old-password-123456"
NEW_PASSWORD = "new-password-654321"


def _role(*, superuser: bool = False, user_id: uuid.UUID | None = None) -> Role:
    return Role(
        type="user",
        user_id=user_id or uuid.uuid4(),
        service_id="autosecops-api",
        is_platform_superuser=superuser,
        scopes=frozenset({"*"}) if superuser else frozenset(),
    )


@pytest.fixture(autouse=True)
def audit_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture auth audit events instead of resolving a real sink."""
    events: list[dict[str, Any]] = []

    async def fake_user_event(**kwargs: Any) -> None:
        events.append({"kind": "user", **kwargs})

    async def fake_anonymous_event(**kwargs: Any) -> None:
        events.append({"kind": "anonymous", **kwargs})

    monkeypatch.setattr(users_module, "emit_user_auth_event", fake_user_event)
    monkeypatch.setattr(users_module, "emit_anonymous_auth_event", fake_anonymous_event)
    monkeypatch.setattr(
        users_module, "single_organization_for_audit", AsyncMock(return_value=None)
    )
    return events


@pytest.fixture
def user_db() -> AsyncMock:
    db = AsyncMock()
    db.get_by_email.return_value = None
    db.update.side_effect = lambda user, update_dict: user
    db.session.execute.return_value = MagicMock()
    return db


@pytest.fixture
def manager(user_db: AsyncMock) -> UserManager:
    return UserManager(cast(Any, user_db))


@pytest.fixture
def user() -> User:
    return cast(
        User,
        SimpleNamespace(
            id=uuid.uuid4(),
            email="member@example.com",
            hashed_password=PasswordHelper().hash(OLD_PASSWORD),
            is_active=True,
            is_superuser=False,
        ),
    )


def _request_with_session(token: str | None) -> Request:
    headers = (
        [(b"cookie", f"{cookie_transport.cookie_name}={token}".encode())]
        if token
        else []
    )
    return Request({"type": "http", "method": "PATCH", "headers": headers})


@pytest.mark.anyio
@pytest.mark.parametrize("current_password", [None, "", "wrong-password-000"])
async def test_self_service_password_change_requires_current_password(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    current_password: str | None,
) -> None:
    """A stolen session cookie must not be enough to take the account over."""
    ctx_role.set(_role(user_id=user.id))

    with pytest.raises(InvalidPasswordException):
        await manager.update(
            UserUpdate(password=NEW_PASSWORD, current_password=current_password),
            user,
            safe=True,
        )

    user_db.update.assert_not_awaited()
    user_db.session.execute.assert_not_awaited()


@pytest.mark.anyio
async def test_self_service_password_change_with_current_password(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    ctx_role.set(_role(user_id=user.id))

    await manager.update(
        UserUpdate(password=NEW_PASSWORD, current_password=OLD_PASSWORD),
        user,
        safe=True,
        request=_request_with_session("current-session"),
    )

    update_dict = user_db.update.await_args.args[1]
    assert "current_password" not in update_dict
    assert "password" not in update_dict
    verified, _ = PasswordHelper().verify_and_update(
        NEW_PASSWORD, update_dict["hashed_password"]
    )
    assert verified
    user_db.session.execute.assert_awaited_once()
    user_db.session.commit.assert_awaited_once()


@pytest.mark.anyio
async def test_profile_update_does_not_need_current_password(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    ctx_role.set(_role(user_id=user.id))

    await manager.update(UserUpdate(first_name="Ada"), user, safe=True)

    user_db.update.assert_awaited_once()
    user_db.session.execute.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("current_password", [None, "wrong-password-000"])
async def test_superuser_own_password_on_users_id_requires_current_password(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    current_password: str | None,
) -> None:
    """A stolen superuser cookie cannot take the account over via `/users/{id}`.

    That route passes safe=False; for the caller's own account it would
    otherwise set the password, keep the attacker's session, and end every
    legitimate one.
    """
    ctx_role.set(_role(superuser=True, user_id=user.id))

    with pytest.raises(InvalidPasswordException):
        await manager.update(
            UserUpdate(password=NEW_PASSWORD, current_password=current_password),
            user,
            safe=False,
            request=_request_with_session("current-session"),
        )

    user_db.update.assert_not_awaited()
    user_db.session.execute.assert_not_awaited()


@pytest.mark.anyio
async def test_superuser_patch_own_user_with_current_password(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    audit_events: list[dict[str, Any]],
) -> None:
    """`PATCH /users/{id}` is superuser-only and passes safe=False."""
    ctx_role.set(_role(superuser=True, user_id=user.id))

    await manager.update(
        UserUpdate(password=NEW_PASSWORD, current_password=OLD_PASSWORD),
        user,
        safe=False,
        request=_request_with_session("current-session"),
    )

    assert "hashed_password" in user_db.update.await_args.args[1]
    # Their own account: the other sessions end, the requesting one stays.
    user_db.session.execute.assert_awaited_once()
    user_db.session.commit.assert_awaited_once()
    [event] = audit_events
    assert event["data"]["operation"] == "password_change"
    assert event["actor_user_id"] == user.id


@pytest.mark.anyio
async def test_platform_superuser_sets_member_password_without_current_password(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    audit_events: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The org member route updates another account with safe=True."""
    admin = _role(superuser=True)
    ctx_role.set(admin)
    revoke_all = AsyncMock(
        return_value=CredentialRevocation(
            sessions=2, mcp_personal_access_tokens=1, mcp_refresh_tokens=3
        )
    )
    monkeypatch.setattr(users_module, "revoke_all_user_credentials", revoke_all)

    await manager.update(UserUpdate(password=NEW_PASSWORD), user, safe=True)

    assert "hashed_password" in user_db.update.await_args.args[1]
    revoke_all.assert_awaited_once_with(user.id, revoked_by=admin.user_id)
    [event] = audit_events
    assert event["user_id"] == user.id
    assert event["actor_user_id"] == admin.user_id
    assert event["resource_type"] == "user"
    assert event["action"] == "update"
    assert event["organization_id"] is None
    assert event["data"] == {
        "operation": "admin_password_set",
        "changed_fields": ["password"],
        "revoked_session_count": 2,
        "revoked_mcp_personal_access_token_count": 1,
        "revoked_mcp_refresh_token_count": 3,
    }


@pytest.mark.anyio
async def test_password_change_revokes_other_sessions_only(
    session: AsyncSession,
) -> None:
    user = User(
        id=uuid.uuid4(),
        email=f"pw-change-{uuid.uuid4().hex}@example.com",
        hashed_password=PasswordHelper().hash(OLD_PASSWORD),
    )
    other_user_id = uuid.uuid4()
    session.add(user)
    session.add(
        User(
            id=other_user_id,
            email=f"bystander-{uuid.uuid4().hex}@example.com",
            hashed_password="unused",
        )
    )
    await session.flush()
    current, stolen, bystander = (uuid.uuid4().hex for _ in range(3))
    session.add_all(
        [
            AccessToken(token=current, user_id=user.id),
            AccessToken(token=stolen, user_id=user.id),
            AccessToken(token=bystander, user_id=other_user_id),
        ]
    )
    await session.commit()
    ctx_role.set(_role(user_id=user.id))
    manager = UserManager(SQLAlchemyUserDatabase(session, User))

    await manager.update(
        UserUpdate(password=NEW_PASSWORD, current_password=OLD_PASSWORD),
        user,
        safe=True,
        request=_request_with_session(current),
    )

    tokens = (
        await session.execute(
            select(AccessToken).where(
                AccessToken.token.in_([current, stolen, bystander])  # pyright: ignore[reportAttributeAccessIssue]
            )
        )
    ).scalars()
    remaining = {token.token for token in tokens}
    assert remaining == {current, bystander}


@pytest.mark.anyio
async def test_self_service_update_cannot_change_email(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    """An unverified new address would claim invitations and SSO links."""
    # Each anyio test runs in its own task context, so this does not leak.
    ctx_role.set(_role())

    with pytest.raises(PermissionsException):
        await manager.update(
            UserUpdate(email="invitee@victim.example"), user, safe=True
        )

    user_db.update.assert_not_awaited()


@pytest.mark.anyio
async def test_self_service_update_still_changes_profile_fields(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    # Each anyio test runs in its own task context, so this does not leak.
    ctx_role.set(_role())

    await manager.update(
        UserUpdate(first_name="Ada", email="member@example.com"), user, safe=True
    )

    user_db.update.assert_awaited_once()
    update_dict = user_db.update.await_args.args[1]
    assert update_dict["first_name"] == "Ada"
    assert "is_verified" not in update_dict


@pytest.mark.anyio
async def test_superuser_admin_update_can_change_email(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    """`PATCH /users/{id}` is superuser-only and passes safe=False."""
    # Each anyio test runs in its own task context, so this does not leak.
    ctx_role.set(_role())

    await manager.update(UserUpdate(email="renamed@example.com"), user, safe=False)

    update_dict = user_db.update.await_args.args[1]
    assert update_dict["email"] == "renamed@example.com"


@pytest.mark.anyio
async def test_platform_superuser_role_can_change_email(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    # Each anyio test runs in its own task context, so this does not leak.
    ctx_role.set(_role(superuser=True))

    await manager.update(UserUpdate(email="renamed@example.com"), user, safe=True)

    update_dict = user_db.update.await_args.args[1]
    assert update_dict["email"] == "renamed@example.com"


@pytest.mark.anyio
async def test_auth_token_hooks_never_log_the_token(
    manager: UserManager, user: User
) -> None:
    """Reset and verification tokens are bearer credentials for the account."""
    reset_token = "reset-token-" + uuid.uuid4().hex
    verify_token = "verify-token-" + uuid.uuid4().hex
    manager.logger = Mock()

    await manager.on_after_forgot_password(user, reset_token)
    await manager.on_after_request_verify(user, verify_token)

    logged = repr(manager.logger.mock_calls)
    assert len(manager.logger.mock_calls) == 2
    assert reset_token not in logged
    assert verify_token not in logged


async def _seed_user_with_sessions(
    session: AsyncSession, *, token_count: int
) -> tuple[User, list[str], str]:
    user = User(
        id=uuid.uuid4(),
        email=f"sessions-{uuid.uuid4().hex}@example.com",
        hashed_password=PasswordHelper().hash(OLD_PASSWORD),
    )
    bystander_user = User(
        id=uuid.uuid4(),
        email=f"bystander-{uuid.uuid4().hex}@example.com",
        hashed_password="unused",
    )
    session.add_all([user, bystander_user])
    await session.flush()
    tokens = [uuid.uuid4().hex for _ in range(token_count)]
    bystander = uuid.uuid4().hex
    session.add_all(
        [AccessToken(token=token, user_id=user.id) for token in tokens]
        + [AccessToken(token=bystander, user_id=bystander_user.id)]
    )
    await session.commit()
    return user, tokens, bystander


@pytest.fixture
def system_session(session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the RLS-bypass credential revocation on the test's session."""

    @contextlib.asynccontextmanager
    async def _bypass_session() -> AsyncIterator[AsyncSession]:
        yield session

    monkeypatch.setattr(
        users_module, "get_async_session_bypass_rls_context_manager", _bypass_session
    )


async def _seed_mcp_credentials(
    session: AsyncSession, user_id: uuid.UUID
) -> tuple[uuid.UUID, uuid.UUID]:
    """Give a user one live MCP personal access token and refresh token."""
    suffix = uuid.uuid4().hex
    organization = Organization(
        id=uuid.uuid4(), name=f"Org {suffix}", slug=f"org-{suffix}", is_active=True
    )
    session.add(organization)
    await session.flush()
    pat = MCPPersonalAccessToken(
        id=uuid.uuid4(),
        user_id=user_id,
        organization_id=organization.id,
        name="mcp",
        key_id=uuid.uuid4().hex,
        hashed="unused",
        salt="unused",
        preview="unused",
    )
    refresh_token = MCPRefreshToken(
        id=uuid.uuid4(),
        token_hash=uuid.uuid4().hex,
        family_id=uuid.uuid4(),
        user_id=user_id,
        organization_id=organization.id,
        client_id="client",
        encrypted_metadata=b"\x00",
        status="active",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    session.add_all([pat, refresh_token])
    await session.commit()
    return pat.id, refresh_token.id


async def _mcp_credential_state(
    session: AsyncSession, pat_id: uuid.UUID, refresh_token_id: uuid.UUID
) -> tuple[bool, str]:
    """Whether the PAT is revoked, and the refresh token's status."""
    revoked_at = (
        await session.execute(
            select(MCPPersonalAccessToken.revoked_at).where(
                MCPPersonalAccessToken.id == pat_id  # pyright: ignore[reportArgumentType]
            )
        )
    ).scalar_one()
    status = (
        await session.execute(
            select(MCPRefreshToken.status).where(
                MCPRefreshToken.id == refresh_token_id  # pyright: ignore[reportArgumentType]
            )
        )
    ).scalar_one()
    return revoked_at is not None, status


async def _remaining_tokens(session: AsyncSession, tokens: list[str]) -> set[str]:
    result = await session.execute(
        select(AccessToken).where(
            AccessToken.token.in_(tokens)  # pyright: ignore[reportAttributeAccessIssue]
        )
    )
    return {access_token.token for access_token in result.scalars().all()}


@pytest.mark.anyio
async def test_revoke_user_sessions_keeps_only_the_named_token(
    session: AsyncSession,
) -> None:
    """The helper the admin CLI's break-glass reset also uses."""
    user, tokens, bystander = await _seed_user_with_sessions(session, token_count=3)

    revoked = await users_module.revoke_user_sessions(
        session, user.id, keep_token=tokens[0]
    )
    await session.commit()

    assert revoked == 2
    assert await _remaining_tokens(session, [*tokens, bystander]) == {
        tokens[0],
        bystander,
    }
    assert await users_module.revoke_user_sessions(session, user.id) == 1


@pytest.mark.anyio
@pytest.mark.usefixtures("system_session")
async def test_admin_password_set_revokes_every_session(
    session: AsyncSession, audit_events: list[dict[str, Any]]
) -> None:
    """A password an admin sets locks out whoever holds the old sessions."""
    user, tokens, bystander = await _seed_user_with_sessions(session, token_count=2)
    pat_id, refresh_id = await _seed_mcp_credentials(session, user.id)
    admin = User(
        id=uuid.uuid4(),
        email=f"admin-{uuid.uuid4().hex}@example.com",
        hashed_password="unused",
    )
    session.add(admin)
    await session.commit()
    ctx_role.set(_role(superuser=True, user_id=admin.id))
    manager = UserManager(SQLAlchemyUserDatabase(session, User))

    await manager.update(
        UserUpdate(password=NEW_PASSWORD),
        user,
        safe=True,
        # A cookie on the admin's request must not shield a member session.
        request=_request_with_session(tokens[0]),
    )

    assert await _remaining_tokens(session, [*tokens, bystander]) == {bystander}
    # MCP credentials minted by whoever held the account end with it.
    assert await _mcp_credential_state(session, pat_id, refresh_id) == (
        True,
        "revoked",
    )
    revoked_by = (
        await session.execute(
            select(MCPPersonalAccessToken.revoked_by).where(
                MCPPersonalAccessToken.id == pat_id  # pyright: ignore[reportArgumentType]
            )
        )
    ).scalar_one()
    assert revoked_by == admin.id
    data = audit_events[-1]["data"]
    assert data["revoked_session_count"] == 2
    assert data["revoked_mcp_personal_access_token_count"] == 1
    assert data["revoked_mcp_refresh_token_count"] == 1


@pytest.mark.anyio
@pytest.mark.usefixtures("system_session")
async def test_password_reset_revokes_every_session(
    session: AsyncSession, audit_events: list[dict[str, Any]]
) -> None:
    """A reset recovers the account from whoever holds it, MCP access included."""
    user, tokens, bystander = await _seed_user_with_sessions(session, token_count=3)
    pat_id, refresh_id = await _seed_mcp_credentials(session, user.id)
    other = User(
        id=uuid.uuid4(),
        email=f"other-{uuid.uuid4().hex}@example.com",
        hashed_password="unused",
    )
    session.add(other)
    await session.commit()
    other_pat_id, other_refresh_id = await _seed_mcp_credentials(session, other.id)
    manager = UserManager(SQLAlchemyUserDatabase(session, User))

    await manager.on_after_reset_password(
        user, request=_request_with_session(tokens[0])
    )

    assert await _remaining_tokens(session, [*tokens, bystander]) == {bystander}
    assert await _mcp_credential_state(session, pat_id, refresh_id) == (
        True,
        "revoked",
    )
    assert await _mcp_credential_state(session, other_pat_id, other_refresh_id) == (
        False,
        "active",
    )
    [event] = audit_events
    assert event["kind"] == "user"
    assert event["resource_type"] == "user"
    assert event["action"] == "reset"
    assert event["user_id"] == user.id
    assert event["data"] == {
        "operation": "password_reset",
        "revoked_session_count": 3,
        "revoked_mcp_personal_access_token_count": 1,
        "revoked_mcp_refresh_token_count": 1,
    }


@pytest.mark.anyio
async def test_reset_with_invalid_token_is_audited_and_refused(
    manager: UserManager, audit_events: list[dict[str, Any]]
) -> None:
    with pytest.raises(InvalidResetPasswordToken):
        await manager.reset_password("not-a-token", NEW_PASSWORD)

    [event] = audit_events
    assert event["kind"] == "anonymous"
    assert event["identifier"] is None
    assert event["action"] == "reset"
    assert event["data"]["failure_reason"] == "invalid_token"


@pytest.mark.anyio
async def test_forgot_password_request_is_audited_without_the_token(
    manager: UserManager, user: User, audit_events: list[dict[str, Any]]
) -> None:
    token = "reset-token-" + uuid.uuid4().hex

    await manager.on_after_forgot_password(user, token)
    await drain_auth_audit_tasks()

    [event] = audit_events
    assert event["action"] == "request"
    assert event["data"] == {"operation": "password_reset_requested"}
    assert token not in repr(audit_events)


@pytest.mark.anyio
async def test_forgot_password_audit_runs_off_the_request_path(
    manager: UserManager, user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A registered email must not answer slower than an unknown one."""
    release = asyncio.Event()
    finished: list[uuid.UUID] = []

    async def slow_audit(**kwargs: Any) -> None:
        await release.wait()
        finished.append(kwargs["user_id"])

    monkeypatch.setattr(users_module, "emit_user_auth_event", slow_audit)

    await asyncio.wait_for(
        manager.on_after_forgot_password(user, "reset-token"), timeout=1
    )
    assert finished == []

    release.set()
    await drain_auth_audit_tasks()
    assert finished == [user.id]


def _login_form(email: str, password: str) -> OAuth2PasswordRequestForm:
    return OAuth2PasswordRequestForm(username=email, password=password)


@pytest.mark.anyio
async def test_login_with_unknown_email_is_audited_anonymously(
    manager: UserManager,
    user_db: AsyncMock,
    audit_events: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "nobody@example.com"
    password = "guessed-password-123"
    user_db.get_by_email.return_value = None
    lookup = AsyncMock(return_value=None)
    monkeypatch.setattr(users_module, "_lookup_user_for_audit", lookup)

    assert await manager.authenticate(_login_form(email, password)) is None
    await drain_auth_audit_tasks()

    lookup.assert_awaited_once_with(email)

    [event] = audit_events
    assert event["kind"] == "anonymous"
    assert event["identifier"] == email
    assert event["action"] == "sign_in"
    assert event["data"] == {
        "auth_method": "basic",
        "failure_reason": "unknown_account",
    }
    assert password not in repr(audit_events)


@pytest.mark.anyio
async def test_login_with_wrong_password_is_audited_for_the_account(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    audit_events: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_db.get_by_email.return_value = user
    monkeypatch.setattr(
        users_module, "_lookup_user_for_audit", AsyncMock(return_value=user)
    )

    assert (
        await manager.authenticate(_login_form(user.email, "wrong-password-000"))
        is None
    )
    await drain_auth_audit_tasks()

    [event] = audit_events
    assert event["kind"] == "user"
    assert event["user_id"] == user.id
    assert event["resource_type"] == "auth"
    assert event["status"] == AuditEventStatus.FAILURE
    assert event["data"] == {
        "auth_method": "basic",
        "failure_reason": "invalid_credentials",
    }
    assert "wrong-password-000" not in repr(audit_events)


@pytest.mark.anyio
async def test_login_to_inactive_account_is_refused_and_audited(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    audit_events: list[dict[str, Any]],
) -> None:
    cast(Any, user).is_active = False
    user_db.get_by_email.return_value = user

    assert await manager.authenticate(_login_form(user.email, OLD_PASSWORD)) is None

    [event] = audit_events
    assert event["data"]["failure_reason"] == "inactive_account"


@pytest.mark.anyio
async def test_login_audit_failure_does_not_change_the_outcome(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing org lookup for the audit event must not change a login."""
    monkeypatch.setattr(
        users_module,
        "single_organization_for_audit",
        AsyncMock(side_effect=RuntimeError("database unavailable")),
    )
    monkeypatch.setattr(
        UserManager, "_is_local_password_login_allowed", AsyncMock(return_value=True)
    )
    monkeypatch.setattr(UserManager, "_enforce_login_ip_allowlist", AsyncMock())
    monkeypatch.setattr(
        users_module,
        "_lookup_user_for_audit",
        AsyncMock(side_effect=RuntimeError("database unavailable")),
    )
    user_db.get_by_email.return_value = user

    assert await manager.authenticate(_login_form(user.email, OLD_PASSWORD)) is user
    assert (
        await manager.authenticate(_login_form(user.email, "wrong-password-000"))
        is None
    )
    await drain_auth_audit_tasks()


@pytest.mark.anyio
@pytest.mark.parametrize("org_count", [1, 2])
async def test_login_refused_by_ip_allowlist_is_audited(
    manager: UserManager,
    user: User,
    audit_events: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    org_count: int,
) -> None:
    """One denying organization owns the event; several leave it to the platform."""
    org_ids = {uuid.uuid4() for _ in range(org_count)}
    monkeypatch.setattr(manager, "_list_user_org_ids", AsyncMock(return_value=org_ids))
    monkeypatch.setattr(
        users_module, "is_ip_allowed_for_org", AsyncMock(return_value=False)
    )
    monkeypatch.setattr(users_module, "current_client_ip", lambda: None)

    with pytest.raises(HTTPException) as exc_info:
        await manager._enforce_login_ip_allowlist(user, auth_method="oidc")

    assert exc_info.value.status_code == 403
    [event] = audit_events
    assert event["user_id"] == user.id
    assert event["resource_type"] == "auth"
    assert event["action"] == "sign_in"
    assert event["status"] == AuditEventStatus.FAILURE
    assert event["data"] == {"auth_method": "oidc", "failure_reason": "ip_not_allowed"}
    expected_org = next(iter(org_ids)) if org_count == 1 else None
    assert event["organization_id"] == expected_org


@pytest.mark.anyio
async def test_sign_out_ends_the_session_and_is_audited(
    user: User,
    audit_events: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = uuid.uuid4()
    monkeypatch.setattr(
        users_module, "single_organization_for_audit", AsyncMock(return_value=org_id)
    )
    access_token = MagicMock()
    database = AsyncMock()
    database.get_by_token.return_value = access_token
    strategy = users_module.SessionMetadataDatabaseStrategy(
        cast(Any, database), lifetime_seconds=3600
    )

    await strategy.destroy_token("session-token", user)

    database.delete.assert_awaited_once_with(access_token)
    [event] = audit_events
    assert event["user_id"] == user.id
    assert event["resource_type"] == "auth"
    assert event["action"] == "sign_out"
    assert event["data"] == {"auth_method": "session"}
    assert event["organization_id"] == org_id
    assert "session-token" not in repr(audit_events)


@pytest.mark.anyio
async def test_password_login_refused_by_auth_policy_is_audited(
    manager: UserManager,
    user_db: AsyncMock,
    user: User,
    audit_events: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Correct credentials that policy refuses read as a refusal, not a success."""
    monkeypatch.setattr(
        UserManager, "_is_local_password_login_allowed", AsyncMock(return_value=False)
    )
    ip_check = AsyncMock()
    monkeypatch.setattr(UserManager, "_enforce_login_ip_allowlist", ip_check)
    user_db.get_by_email.return_value = user

    assert await manager.authenticate(_login_form(user.email, OLD_PASSWORD)) is None

    ip_check.assert_not_awaited()
    [event] = audit_events
    assert event["user_id"] == user.id
    assert event["status"] == AuditEventStatus.FAILURE
    assert event["data"] == {"auth_method": "basic", "failure_reason": "auth_policy"}
    assert OLD_PASSWORD not in repr(audit_events)
