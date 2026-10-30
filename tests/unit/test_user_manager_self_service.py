"""Security regressions for self-service account updates and token hooks."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from fastapi import Request
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.exceptions import InvalidPasswordException
from fastapi_users.password import PasswordHelper
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.crypto import hash_bearer_token
from autosecops.auth.schemas import UserUpdate
from autosecops.auth.types import Role
from autosecops.auth.users import PermissionsException, UserManager, cookie_transport
from autosecops.contexts import ctx_role
from autosecops.db.models import AccessToken, User

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
async def test_superuser_patch_user_sets_password_without_current_password(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    """`PATCH /users/{id}` is superuser-only and passes safe=False."""
    ctx_role.set(_role(superuser=True, user_id=user.id))

    await manager.update(UserUpdate(password=NEW_PASSWORD), user, safe=False)

    assert "hashed_password" in user_db.update.await_args.args[1]
    user_db.session.execute.assert_not_awaited()


@pytest.mark.anyio
async def test_platform_superuser_sets_member_password_without_current_password(
    manager: UserManager, user_db: AsyncMock, user: User
) -> None:
    """The org member route updates another account with safe=True."""
    ctx_role.set(_role(superuser=True))

    await manager.update(UserUpdate(password=NEW_PASSWORD), user, safe=True)

    assert "hashed_password" in user_db.update.await_args.args[1]
    user_db.session.execute.assert_not_awaited()


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
            AccessToken(token=hash_bearer_token(current), user_id=user.id),
            AccessToken(token=hash_bearer_token(stolen), user_id=user.id),
            AccessToken(token=hash_bearer_token(bystander), user_id=other_user_id),
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

    digests = {hash_bearer_token(t): t for t in (current, stolen, bystander)}
    tokens = (
        await session.execute(
            select(AccessToken.__table__.c.token).where(
                AccessToken.__table__.c.token.in_(digests)
            )
        )
    ).scalars()
    remaining = {digests[digest] for digest in tokens}
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
