"""The organization key lifetime limit, stored through the router and enforced in the DB.

The settings and service account services run against the test database, so a
change in how the setting is serialized or read back fails here even though
the mocked unit tests still pass.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES, ORG_ADMIN_SCOPES
from autosecops.contexts import ctx_role
from autosecops.db.models import OrganizationSetting, User, Workspace
from autosecops.exceptions import AutoSecOpsValidationError
from autosecops.service_accounts.constants import (
    SERVICE_ACCOUNT_API_KEY_MAX_TTL_DAYS_KEY,
)
from autosecops.service_accounts.service import (
    OrganizationServiceAccountService,
    WorkspaceServiceAccountService,
)
from autosecops.settings import router as settings_router
from autosecops.settings.schemas import SecuritySettingsUpdate
from autosecops.settings.service import SettingsService
from autosecops.tiers import defaults as tier_defaults
from tests.support.membership import (
    grant_org_membership,
    grant_workspace_membership,
)

MAX_TTL_DAYS = 30
# Issuance takes a moment; allow for it when comparing against "now + limit".
SLACK = timedelta(minutes=5)


@pytest.fixture(autouse=True)
def enable_service_accounts_entitlement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.DEFAULT_ENTITLEMENTS.model_copy(
            update={"service_accounts": True}
        ),
    )


@pytest.fixture
async def admin_user(session: AsyncSession, svc_workspace: Workspace) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"sa-admin-{uuid.uuid4().hex}@example.com",
        hashed_password="unused",
    )
    session.add(user)
    await session.flush()
    await grant_org_membership(
        session, user_id=user.id, organization_id=svc_workspace.organization_id
    )
    await grant_workspace_membership(
        session,
        user_id=user.id,
        organization_id=svc_workspace.organization_id,
        workspace_id=svc_workspace.id,
    )
    await session.commit()
    return user


@pytest.fixture
def org_role(svc_workspace: Workspace, admin_user: User) -> Iterator[Role]:
    role = Role(
        type="user",
        user_id=admin_user.id,
        organization_id=svc_workspace.organization_id,
        service_id="autosecops-api",
        scopes=ORG_ADMIN_SCOPES | ADMIN_SCOPES,
    )
    token = ctx_role.set(role)
    yield role
    ctx_role.reset(token)


@pytest.fixture
def workspace_role(svc_workspace: Workspace, admin_user: User) -> Role:
    """A role scoped to one workspace, as a workspace route resolves it."""
    return Role(
        type="user",
        user_id=admin_user.id,
        organization_id=svc_workspace.organization_id,
        workspace_id=svc_workspace.id,
        service_id="autosecops-api",
        scopes=ORG_ADMIN_SCOPES | ADMIN_SCOPES,
    )


async def _set_max_ttl_through_router(
    session: AsyncSession, role: Role, days: int | None
) -> None:
    await settings_router.update_security_settings(
        role=role,
        session=session,
        params=SecuritySettingsUpdate(service_account_api_key_max_ttl_days=days),
    )


def _assert_bounded(expires_at: datetime | None, *, days: int) -> None:
    assert expires_at is not None
    limit = datetime.now(UTC) + timedelta(days=days)
    assert limit - SLACK <= expires_at <= limit


@pytest.mark.anyio
async def test_limit_set_through_router_is_stored_as_an_integer(
    session: AsyncSession, org_role: Role
) -> None:
    await _set_max_ttl_through_router(session, org_role, MAX_TTL_DAYS)

    stored = (
        await session.execute(
            select(OrganizationSetting).where(
                OrganizationSetting.organization_id == org_role.organization_id,
                OrganizationSetting.key == SERVICE_ACCOUNT_API_KEY_MAX_TTL_DAYS_KEY,
            )
        )
    ).scalar_one()
    service = SettingsService(session, org_role)
    assert service.get_value(stored) == MAX_TTL_DAYS
    read_back = await settings_router._load_security_settings(service)
    assert read_back.service_account_api_key_max_ttl_days == MAX_TTL_DAYS


@pytest.mark.anyio
async def test_limit_bounds_org_service_account_keys(
    session: AsyncSession, org_role: Role
) -> None:
    await _set_max_ttl_through_router(session, org_role, MAX_TTL_DAYS)
    service = OrganizationServiceAccountService(session, role=org_role)

    created = await service.create_service_account(
        name=f"org-bot-{uuid.uuid4().hex[:8]}",
        description=None,
        scope_ids=[],
        initial_key_name="Primary",
    )
    _assert_bounded(created.api_key.expires_at, days=MAX_TTL_DAYS)

    with pytest.raises(AutoSecOpsValidationError):
        await service.issue_api_key(
            created.service_account.id,
            name="Too long",
            expires_at=datetime.now(UTC) + timedelta(days=MAX_TTL_DAYS + 1),
        )

    rotated = await service.issue_api_key(
        created.service_account.id, name="Rotated", expires_at=None
    )
    _assert_bounded(rotated.api_key.expires_at, days=MAX_TTL_DAYS)


@pytest.mark.anyio
async def test_limit_bounds_workspace_service_account_keys(
    session: AsyncSession, org_role: Role, workspace_role: Role
) -> None:
    """A workspace-scoped role still reads the organization's limit."""
    await _set_max_ttl_through_router(session, org_role, MAX_TTL_DAYS)
    ctx_role.set(workspace_role)
    service = WorkspaceServiceAccountService(session, role=workspace_role)

    created = await service.create_service_account(
        name=f"ws-bot-{uuid.uuid4().hex[:8]}",
        description=None,
        scope_ids=[],
        initial_key_name="Primary",
    )
    _assert_bounded(created.api_key.expires_at, days=MAX_TTL_DAYS)

    with pytest.raises(AutoSecOpsValidationError):
        await service.issue_api_key(
            created.service_account.id,
            name="Too long",
            expires_at=datetime.now(UTC) + timedelta(days=MAX_TTL_DAYS + 1),
        )


@pytest.mark.anyio
async def test_clearing_the_limit_issues_keys_without_expiry(
    session: AsyncSession, org_role: Role
) -> None:
    await _set_max_ttl_through_router(session, org_role, MAX_TTL_DAYS)
    await _set_max_ttl_through_router(session, org_role, None)
    service = OrganizationServiceAccountService(session, role=org_role)

    created = await service.create_service_account(
        name=f"org-bot-{uuid.uuid4().hex[:8]}",
        description=None,
        scope_ids=[],
        initial_key_name="Primary",
    )

    assert created.api_key.expires_at is None
