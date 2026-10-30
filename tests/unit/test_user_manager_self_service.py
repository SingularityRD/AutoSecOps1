"""Security regressions for self-service account updates and token hooks."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from autosecops.auth.schemas import UserUpdate
from autosecops.auth.types import Role
from autosecops.auth.users import PermissionsException, UserManager
from autosecops.contexts import ctx_role
from autosecops.db.models import User


def _role(*, superuser: bool = False) -> Role:
    return Role(
        type="user",
        user_id=uuid.uuid4(),
        service_id="autosecops-api",
        is_platform_superuser=superuser,
        scopes=frozenset({"*"}) if superuser else frozenset(),
    )


@pytest.fixture
def user_db() -> AsyncMock:
    db = AsyncMock()
    db.get_by_email.return_value = None
    db.update.side_effect = lambda user, update_dict: user
    return db


@pytest.fixture
def manager(user_db: AsyncMock) -> UserManager:
    return UserManager(cast(Any, user_db))


@pytest.fixture
def user() -> User:
    return cast(User, SimpleNamespace(id=uuid.uuid4(), email="member@example.com"))


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
