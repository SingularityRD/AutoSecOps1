from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth import credentials
from autosecops.auth.api_keys import generate_managed_api_key
from autosecops.auth.audit import AuthAuditFailureReason
from autosecops.auth.credentials import _authenticate_api_key
from autosecops.authz.seeding import seed_system_scopes
from autosecops.contexts import ctx_service_account_api_key_id
from autosecops.db import engine as engine_module
from autosecops.db.models import (
    Organization,
    Scope,
    ServiceAccount,
    ServiceAccountApiKey,
    Workspace,
)
from autosecops.tiers import defaults as tier_defaults


@pytest.fixture(autouse=True)
def enable_service_accounts_entitlement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.DEFAULT_ENTITLEMENTS.model_copy(
            update={"service_accounts": True}
        ),
    )


async def _org(session: AsyncSession) -> Organization:
    organization = Organization(
        name="Auth test org", slug=f"auth-org-{uuid.uuid4().hex[:8]}", is_active=True
    )
    session.add(organization)
    await session.flush()
    return organization


async def _workspace(session: AsyncSession, organization_id: uuid.UUID) -> Workspace:
    workspace = Workspace(
        name=f"Auth test workspace {uuid.uuid4().hex[:8]}",
        organization_id=organization_id,
    )
    session.add(workspace)
    await session.flush()
    return workspace


async def _service_account_key(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    workspace_id: uuid.UUID | None,
    scope_names: tuple[str, ...],
    expires_at: datetime | None = None,
) -> tuple[ServiceAccount, str]:
    """Persist a service account with one API key and return the raw key."""
    await seed_system_scopes(session)
    result = await session.execute(select(Scope).where(Scope.name.in_(scope_names)))
    generated = generate_managed_api_key(
        prefix="tc_ws_sk_" if workspace_id else "tc_org_sk_"
    )
    service_account = ServiceAccount(
        organization_id=organization_id,
        workspace_id=workspace_id,
        name="Automation",
        scopes=list(result.scalars().all()),
    )
    session.add(service_account)
    await session.flush()
    session.add(
        ServiceAccountApiKey(
            service_account_id=service_account.id,
            name="Primary",
            key_id=generated.key_id,
            hashed=generated.hashed,
            salt=generated.salt_b64,
            preview=generated.preview(),
            expires_at=expires_at,
        )
    )
    await session.commit()
    return service_account, generated.raw


def _use_auth_session(monkeypatch: pytest.MonkeyPatch, session: AsyncSession) -> None:
    @asynccontextmanager
    async def _session_cm():
        yield session

    monkeypatch.setattr(
        "autosecops.auth.credentials.get_async_session_auth_context_manager",
        _session_cm,
    )


@pytest.mark.anyio
async def test_authenticate_org_service_account_key_for_workspace_route(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    workspace = await _workspace(session, organization.id)
    service_account, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=None,
        scope_names=("org:read", "workflow:read"),
    )
    _use_auth_session(monkeypatch, session)
    monkeypatch.setattr(
        "autosecops.auth.credentials._get_workspace_org_id",
        AsyncMock(return_value=organization.id),
    )

    role = await _authenticate_api_key(api_key=api_key, workspace_id=workspace.id)

    assert role is not None
    assert role.type == "service_account"
    assert role.service_account_id == service_account.id
    assert role.organization_id == organization.id
    assert role.workspace_id == workspace.id
    assert role.bound_workspace_id is None
    assert role.scopes == frozenset({"org:read", "workflow:read"})


@pytest.mark.anyio
async def test_authenticate_api_key_cold_workspace_cache_uses_one_auth_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid.uuid4()
    workspace_id = uuid.uuid4()
    service_account_id = uuid.uuid4()
    generated = generate_managed_api_key(prefix="tc_org_sk_")

    service_account = SimpleNamespace(
        id=service_account_id,
        organization_id=organization_id,
        workspace_id=None,
        disabled_at=None,
        scopes=[SimpleNamespace(name="workflow:read")],
    )
    record = SimpleNamespace(
        id=uuid.uuid4(),
        revoked_at=None,
        expires_at=None,
        salt=generated.salt_b64,
        hashed=generated.hashed,
        service_account=service_account,
        last_used_at=None,
    )

    api_key_result = MagicMock()
    api_key_result.scalar_one_or_none.return_value = record
    workspace_result = MagicMock()
    workspace_result.scalar_one_or_none.return_value = organization_id
    auth_session = AsyncMock()
    auth_session.add = MagicMock()
    auth_session.execute.side_effect = [api_key_result, workspace_result]

    checkout_count = 0
    active_checkouts = 0
    max_active_checkouts = 0

    @asynccontextmanager
    async def _counted_auth_session_cm():
        nonlocal active_checkouts, checkout_count, max_active_checkouts
        checkout_count += 1
        active_checkouts += 1
        max_active_checkouts = max(max_active_checkouts, active_checkouts)
        try:
            yield auth_session
        finally:
            active_checkouts -= 1

    credentials._get_workspace_org_id_cached.cache_clear()
    monkeypatch.setattr(
        credentials,
        "get_async_session_auth_context_manager",
        _counted_auth_session_cm,
    )
    monkeypatch.setattr(
        credentials,
        "is_org_entitled",
        AsyncMock(return_value=True),
    )

    role = await _authenticate_api_key(
        api_key=generated.raw,
        workspace_id=workspace_id,
    )

    assert role is not None
    assert role.workspace_id == workspace_id
    assert role.service_account_id == service_account_id
    assert ctx_service_account_api_key_id.get() == record.id
    assert checkout_count == 1
    assert max_active_checkouts == 1
    assert active_checkouts == 0
    assert auth_session.execute.await_count == 2


@pytest.mark.anyio
async def test_authenticate_org_service_account_key_rejects_workspace_outside_org(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    other_organization = await _org(session)
    workspace = await _workspace(session, other_organization.id)
    _, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=None,
        scope_names=("workflow:read",),
    )
    _use_auth_session(monkeypatch, session)
    monkeypatch.setattr(
        "autosecops.auth.credentials._get_workspace_org_id",
        AsyncMock(return_value=other_organization.id),
    )

    with pytest.raises(HTTPException, match="Forbidden") as exc_info:
        await _authenticate_api_key(api_key=api_key, workspace_id=workspace.id)

    assert exc_info.value.status_code == 403


@pytest.mark.anyio
async def test_authenticate_api_key_checks_entitlement_before_workspace_resolution(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    workspace = await _workspace(session, organization.id)
    _, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=None,
        scope_names=("workflow:read",),
    )
    _use_auth_session(monkeypatch, session)
    get_workspace_org_id = AsyncMock(return_value=organization.id)
    monkeypatch.setattr(
        "autosecops.auth.credentials.is_org_entitled",
        AsyncMock(return_value=False),
    )
    monkeypatch.setattr(
        "autosecops.auth.credentials._get_workspace_org_id",
        get_workspace_org_id,
    )

    with pytest.raises(HTTPException) as exc_info:
        await _authenticate_api_key(api_key=api_key, workspace_id=workspace.id)

    assert exc_info.value.status_code == 401
    get_workspace_org_id.assert_not_awaited()


@pytest.mark.anyio
async def test_workspace_service_account_key_resolves_bound_workspace_for_org_route(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    workspace = await _workspace(session, organization.id)
    service_account, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=workspace.id,
        scope_names=("workspace:read",),
    )
    _use_auth_session(monkeypatch, session)

    role = await _authenticate_api_key(api_key=api_key, workspace_id=None)

    assert role is not None
    assert role.type == "service_account"
    assert role.service_account_id == service_account.id
    assert role.organization_id == organization.id
    assert role.workspace_id == workspace.id
    assert role.bound_workspace_id == workspace.id
    assert role.scopes == frozenset({"workspace:read"})


@pytest.mark.anyio
async def test_workspace_service_account_key_for_workspace_route_tracks_target_and_bound(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    workspace = await _workspace(session, organization.id)
    _, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=workspace.id,
        scope_names=("workflow:read",),
    )
    _use_auth_session(monkeypatch, session)

    role = await _authenticate_api_key(api_key=api_key, workspace_id=workspace.id)

    assert role is not None
    assert role.workspace_id == workspace.id
    assert role.bound_workspace_id == workspace.id


@pytest.mark.anyio
async def test_workspace_service_account_key_rejects_mismatched_workspace_target(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    bound_workspace = await _workspace(session, organization.id)
    other_workspace = await _workspace(session, organization.id)
    _, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=bound_workspace.id,
        scope_names=("workflow:read",),
    )
    _use_auth_session(monkeypatch, session)

    with pytest.raises(HTTPException, match="Forbidden") as exc_info:
        await _authenticate_api_key(api_key=api_key, workspace_id=other_workspace.id)

    assert exc_info.value.status_code == 403


@pytest.mark.anyio
async def test_workspace_service_account_key_rejects_bound_workspace_outside_org(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    other_organization = await _org(session)
    bound_workspace = await _workspace(session, other_organization.id)
    _, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=bound_workspace.id,
        scope_names=("workspace:read",),
    )
    _use_auth_session(monkeypatch, session)

    with pytest.raises(HTTPException, match="Forbidden") as exc_info:
        await _authenticate_api_key(api_key=api_key, workspace_id=None)

    assert exc_info.value.status_code == 403


@pytest.mark.anyio
async def test_workspace_service_account_key_can_bind_workspace_for_actor_org_route(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    workspace = await _workspace(session, organization.id)
    _, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=workspace.id,
        scope_names=("workspace:read",),
    )
    _use_auth_session(monkeypatch, session)

    role = await _authenticate_api_key(api_key=api_key, workspace_id=None)

    assert role is not None
    assert role.type == "service_account"
    assert role.organization_id == organization.id
    assert role.workspace_id == workspace.id
    assert role.scopes == frozenset({"workspace:read"})


@pytest.mark.anyio
async def test_expired_api_key_is_refused_and_audited(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    service_account, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=None,
        scope_names=("org:read",),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    @asynccontextmanager
    async def _auth_pool_session():
        # Mark the auth pool held, as the real accessor does.
        token = engine_module._ctx_auth_pool_session.set(session)
        try:
            yield session
        finally:
            engine_module._ctx_auth_pool_session.reset(token)

    monkeypatch.setattr(
        credentials, "get_async_session_auth_context_manager", _auth_pool_session
    )
    events: list[dict[str, Any]] = []

    async def fake_emit(**kwargs: Any) -> None:
        # The audit writer takes a main-pool session, which the engine refuses
        # while the auth pool is held, so it must run after its release.
        assert engine_module._ctx_auth_pool_session.get() is None
        events.append(kwargs)

    monkeypatch.setattr(credentials, "emit_api_key_rejected_event", fake_emit)
    first_in_window = AsyncMock(side_effect=[True, False])
    monkeypatch.setattr(
        credentials, "first_expired_api_key_refusal_in_window", first_in_window
    )

    with pytest.raises(HTTPException) as exc_info:
        await _authenticate_api_key(api_key=api_key, workspace_id=None)
    assert exc_info.value.status_code == 401
    # A client that keeps polling is refused every time, audited once.
    with pytest.raises(HTTPException) as exc_info:
        await _authenticate_api_key(api_key=api_key, workspace_id=None)
    assert exc_info.value.status_code == 401
    assert isinstance(exc_info.value, credentials.ExpiredApiKeyError)
    record = (
        await session.execute(
            select(ServiceAccountApiKey).where(
                ServiceAccountApiKey.service_account_id == service_account.id
            )
        )
    ).scalar_one()
    assert record.last_used_at is None
    assert events == [
        {
            "organization_id": organization.id,
            "workspace_id": None,
            "service_account_id": service_account.id,
            "api_key_id": record.id,
            "failure_reason": AuthAuditFailureReason.EXPIRED,
        }
    ]
    first_in_window.assert_awaited_with(record.id)


@pytest.mark.anyio
async def test_unexpired_api_key_authenticates(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _org(session)
    service_account, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=None,
        scope_names=("org:read",),
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    _use_auth_session(monkeypatch, session)

    role = await _authenticate_api_key(api_key=api_key, workspace_id=None)

    assert role is not None
    assert role.service_account_id == service_account.id


@pytest.mark.anyio
async def test_wrong_secret_for_expired_key_is_not_audited(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a caller holding the secret can make an expiry event."""
    organization = await _org(session)
    _, api_key = await _service_account_key(
        session,
        organization_id=organization.id,
        workspace_id=None,
        scope_names=("org:read",),
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    _use_auth_session(monkeypatch, session)
    emit = AsyncMock()
    monkeypatch.setattr(credentials, "emit_api_key_rejected_event", emit)

    with pytest.raises(HTTPException):
        await _authenticate_api_key(api_key=api_key[:-4] + "XXXX", workspace_id=None)

    emit.assert_not_awaited()
