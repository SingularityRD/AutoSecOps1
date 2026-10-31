"""Service account routes and token lifecycle against the test database."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import autosecops.service_accounts.service as service_accounts_service
from autosecops.auth.api_keys import ORG_API_KEY_PREFIX, WORKSPACE_API_KEY_PREFIX
from autosecops.auth.types import Role
from autosecops.authz.seeding import seed_system_scopes
from autosecops.db.models import (
    Organization,
    OrganizationMembership,
    Scope,
    ServiceAccountApiKey,
    User,
    Workspace,
)
from autosecops.service_accounts.router import org_router, workspace_router
from autosecops.tiers import defaults as tier_defaults
from tests._db_api_client import RoleSwitch, db_api_client

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]

WORKSPACE_SCOPES = frozenset(
    {
        "workspace:service_account:read",
        "workspace:service_account:create",
        "workspace:service_account:update",
        "workspace:service_account:disable",
        "workflow:read",
    }
)
ORG_SCOPES = frozenset(
    {
        "org:service_account:read",
        "org:service_account:create",
        "org:service_account:update",
        "org:service_account:disable",
    }
)


@pytest.fixture(autouse=True)
def enable_service_accounts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.DEFAULT_ENTITLEMENTS.model_copy(
            update={"service_accounts": True}
        ),
    )

    # Scope escalation checks resolve the caller's RBAC scopes from committed
    # assignments; use the scopes on the test role instead.
    async def _role_scopes(role: Role) -> frozenset[str]:
        return role.scopes or frozenset()

    monkeypatch.setattr(
        service_accounts_service, "compute_effective_scopes", _role_scopes
    )


@pytest.fixture(autouse=True)
async def platform_scopes(session: AsyncSession) -> None:
    await seed_system_scopes(session)
    await session.commit()


async def _org_member(session: AsyncSession, organization_id: uuid.UUID) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"sa-owner-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="unused",
        is_active=True,
        is_verified=True,
    )
    session.add(user)
    await session.flush()
    session.add(
        OrganizationMembership(user_id=user.id, organization_id=organization_id)
    )
    await session.commit()
    return user


@pytest.fixture
async def owner(session: AsyncSession, svc_organization: Organization) -> User:
    return await _org_member(session, svc_organization.id)


@pytest.fixture
async def other_workspace(
    session: AsyncSession, svc_organization: Organization
) -> Workspace:
    workspace = Workspace(
        name="sa-other-workspace", organization_id=svc_organization.id
    )
    session.add(workspace)
    await session.commit()
    return workspace


@pytest.fixture
def caller(owner: User, svc_workspace: Workspace) -> RoleSwitch:
    return RoleSwitch(
        Role(
            type="user",
            user_id=owner.id,
            organization_id=svc_workspace.organization_id,
            workspace_id=svc_workspace.id,
            service_id="autosecops-api",
            scopes=WORKSPACE_SCOPES | ORG_SCOPES,
        )
    )


@pytest.fixture
async def client(
    session: AsyncSession, caller: RoleSwitch
) -> AsyncIterator[httpx.AsyncClient]:
    async with db_api_client(
        org_router, workspace_router, session=session, caller=caller
    ) as c:
        yield c


async def _scope_id(session: AsyncSession, name: str) -> uuid.UUID:
    scope_id = await session.scalar(
        select(Scope.id).where(Scope.name == name, Scope.organization_id.is_(None))
    )
    assert scope_id is not None, f"platform scope {name} is not seeded"
    return scope_id


def _ws(workspace: Workspace, path: str = "") -> str:
    return f"/workspaces/{workspace.id}/service-accounts{path}"


async def _create_ws_account(
    client: httpx.AsyncClient, workspace: Workspace, **body: object
) -> dict:
    response = await client.post(_ws(workspace), json={"name": "automation", **body})
    assert response.status_code == 201, response.text
    return response.json()


async def test_workspace_key_rotation_revokes_the_previous_key(
    client: httpx.AsyncClient, session: AsyncSession, svc_workspace: Workspace
) -> None:
    created = await _create_ws_account(client, svc_workspace)
    account_id = created["service_account"]["id"]
    first_key = created["issued_api_key"]
    assert first_key["raw_key"].startswith(WORKSPACE_API_KEY_PREFIX)
    # The raw key is shown once and never persisted in clear text.
    stored = await session.scalar(
        select(ServiceAccountApiKey).where(
            ServiceAccountApiKey.id == uuid.UUID(first_key["api_key"]["id"])
        )
    )
    assert stored is not None
    assert first_key["raw_key"] not in (stored.hashed, stored.salt, stored.preview)

    rotated = await client.post(
        _ws(svc_workspace, f"/{account_id}/api-keys"), json={"name": "Rotated"}
    )
    assert rotated.status_code == 201, rotated.text
    body = rotated.json()
    assert body["issued_api_key"]["raw_key"] != first_key["raw_key"]
    assert (
        body["service_account"]["active_api_key"]["id"]
        == (body["issued_api_key"]["api_key"]["id"])
    )
    assert body["service_account"]["api_key_counts"] == {
        "total": 2,
        "active": 1,
        "expired": 0,
        "revoked": 1,
    }

    keys = await client.get(_ws(svc_workspace, f"/{account_id}/api-keys"))
    assert keys.status_code == 200
    by_id = {key["id"]: key for key in keys.json()["items"]}
    old = by_id[first_key["api_key"]["id"]]
    assert old["revoked_at"] is not None
    assert old["revoked_by"] == str(created["service_account"]["owner_user_id"])
    assert old["revoked_by_user"]["id"] == old["revoked_by"]


async def test_revoking_a_key_is_idempotent_and_keeps_first_revocation(
    client: httpx.AsyncClient, session: AsyncSession, svc_workspace: Workspace
) -> None:
    created = await _create_ws_account(client, svc_workspace)
    account_id = created["service_account"]["id"]
    key_id = created["issued_api_key"]["api_key"]["id"]
    revoke = _ws(svc_workspace, f"/{account_id}/api-keys/{key_id}/revoke")

    assert (await client.post(revoke)).status_code == 204
    stored = await session.scalar(
        select(ServiceAccountApiKey).where(ServiceAccountApiKey.id == uuid.UUID(key_id))
    )
    assert stored is not None and stored.revoked_at is not None
    first_revoked_at = stored.revoked_at

    assert (await client.post(revoke)).status_code == 204
    await session.refresh(stored)
    assert stored.revoked_at == first_revoked_at

    account = await client.get(_ws(svc_workspace, f"/{account_id}"))
    assert account.json()["active_api_key"] is None


async def test_disabled_account_cannot_issue_keys_until_enabled(
    client: httpx.AsyncClient, svc_workspace: Workspace
) -> None:
    created = await _create_ws_account(client, svc_workspace)
    account_id = created["service_account"]["id"]

    assert (
        await client.post(_ws(svc_workspace, f"/{account_id}/disable"))
    ).status_code == 204
    denied = await client.post(
        _ws(svc_workspace, f"/{account_id}/api-keys"), json={"name": "blocked"}
    )
    assert denied.status_code == 403
    assert "Disabled" in denied.json()["detail"]
    # The active key is left alone; disabling blocks authentication elsewhere.
    account = (await client.get(_ws(svc_workspace, f"/{account_id}"))).json()
    assert account["disabled_at"] is not None
    assert account["api_key_counts"]["total"] == 1

    assert (
        await client.post(_ws(svc_workspace, f"/{account_id}/enable"))
    ).status_code == 204
    issued = await client.post(
        _ws(svc_workspace, f"/{account_id}/api-keys"), json={"name": "after"}
    )
    assert issued.status_code == 201, issued.text
    assert issued.json()["service_account"]["disabled_at"] is None


async def test_workspace_routes_hide_accounts_of_other_workspaces(
    client: httpx.AsyncClient,
    caller: RoleSwitch,
    svc_workspace: Workspace,
    other_workspace: Workspace,
) -> None:
    created = await _create_ws_account(client, svc_workspace)
    account_id = created["service_account"]["id"]
    key_id = created["issued_api_key"]["api_key"]["id"]

    caller.role = caller.role.model_copy(update={"workspace_id": other_workspace.id})
    for method, path in [
        ("GET", f"/{account_id}"),
        ("PATCH", f"/{account_id}"),
        ("GET", f"/{account_id}/api-keys"),
        ("POST", f"/{account_id}/disable"),
        ("POST", f"/{account_id}/api-keys"),
        ("POST", f"/{account_id}/api-keys/{key_id}/revoke"),
    ]:
        response = await client.request(
            method,
            _ws(other_workspace, path),
            json={"name": "x"} if method != "GET" else None,
        )
        assert response.status_code == 404, (method, path, response.text)

    listed = await client.get(_ws(other_workspace))
    assert listed.status_code == 200
    assert listed.json()["items"] == []
    assert listed.json()["total_estimate"] == 0


async def test_org_routes_do_not_expose_workspace_accounts(
    client: httpx.AsyncClient, svc_workspace: Workspace
) -> None:
    created = await _create_ws_account(client, svc_workspace)
    account_id = created["service_account"]["id"]

    assert (
        await client.get(f"/organization/service-accounts/{account_id}")
    ).status_code == 404
    listed = await client.get("/organization/service-accounts")
    assert account_id not in {item["id"] for item in listed.json()["items"]}

    org_created = await client.post(
        "/organization/service-accounts", json={"name": "org automation"}
    )
    assert org_created.status_code == 201, org_created.text
    org_body = org_created.json()
    assert org_body["service_account"]["workspace_id"] is None
    assert org_body["issued_api_key"]["raw_key"].startswith(ORG_API_KEY_PREFIX)
    org_account_id = org_body["service_account"]["id"]
    assert (
        await client.get(_ws(svc_workspace, f"/{org_account_id}"))
    ).status_code == 404


async def test_api_key_from_another_account_cannot_be_revoked_through_this_one(
    client: httpx.AsyncClient, session: AsyncSession, svc_workspace: Workspace
) -> None:
    first = await _create_ws_account(client, svc_workspace, name="first")
    second = await _create_ws_account(client, svc_workspace, name="second")
    foreign_key_id = second["issued_api_key"]["api_key"]["id"]

    response = await client.post(
        _ws(
            svc_workspace,
            f"/{first['service_account']['id']}/api-keys/{foreign_key_id}/revoke",
        )
    )

    assert response.status_code == 404
    stored = await session.scalar(
        select(ServiceAccountApiKey).where(
            ServiceAccountApiKey.id == uuid.UUID(foreign_key_id)
        )
    )
    assert stored is not None and stored.revoked_at is None


async def test_scope_assignment_is_limited_to_held_and_assignable_scopes(
    client: httpx.AsyncClient,
    session: AsyncSession,
    caller: RoleSwitch,
    svc_workspace: Workspace,
) -> None:
    held = await _scope_id(session, "workflow:read")
    not_held = await _scope_id(session, "workflow:delete")
    org_only = await _scope_id(session, "org:member:read")

    escalation = await client.post(
        _ws(svc_workspace), json={"name": "escalate", "scope_ids": [str(not_held)]}
    )
    assert escalation.status_code == 403
    assert "workflow:delete" in escalation.json()["detail"]

    # Org scopes cannot be granted to a workspace account, even by an owner.
    assert caller.role.scopes is not None
    caller.role = caller.role.model_copy(
        update={"scopes": caller.role.scopes | {"org:member:read"}}
    )
    unsupported = await client.post(
        _ws(svc_workspace), json={"name": "org", "scope_ids": [str(org_only)]}
    )
    assert unsupported.status_code == 400
    assert "org:member:read" in unsupported.json()["detail"]

    missing = await client.post(
        _ws(svc_workspace), json={"name": "missing", "scope_ids": [str(uuid.uuid4())]}
    )
    assert missing.status_code == 400

    created = await _create_ws_account(client, svc_workspace, scope_ids=[str(held)])
    assert [s["name"] for s in created["service_account"]["scopes"]] == [
        "workflow:read"
    ]

    account_id = created["service_account"]["id"]
    widened = await client.patch(
        _ws(svc_workspace, f"/{account_id}"), json={"scope_ids": [str(not_held)]}
    )
    assert widened.status_code == 403
    cleared = await client.patch(
        _ws(svc_workspace, f"/{account_id}"),
        json={"scope_ids": [], "description": "no scopes"},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["scopes"] == []
    assert cleared.json()["description"] == "no scopes"


async def test_assignable_scope_listing_matches_account_kind(
    client: httpx.AsyncClient, svc_workspace: Workspace
) -> None:
    workspace_scopes = {
        item["name"]
        for item in (await client.get(_ws(svc_workspace, "/scopes"))).json()["items"]
    }
    org_scopes = {
        item["name"]
        for item in (await client.get("/organization/service-accounts/scopes")).json()[
            "items"
        ]
    }

    assert "workflow:read" in workspace_scopes
    assert not any(name.startswith("org:") for name in workspace_scopes)
    assert "org:member:read" in org_scopes
    assert workspace_scopes < org_scopes
    # Accounts can never mint further service accounts.
    assert not any("service_account" in name for name in org_scopes)


async def test_missing_scope_is_denied_before_any_write(
    client: httpx.AsyncClient,
    session: AsyncSession,
    caller: RoleSwitch,
    svc_workspace: Workspace,
) -> None:
    created = await _create_ws_account(client, svc_workspace)
    account_id = created["service_account"]["id"]
    caller.role = caller.role.model_copy(
        update={"scopes": frozenset({"workspace:service_account:read"})}
    )

    for method, path in [
        ("POST", ""),
        ("PATCH", f"/{account_id}"),
        ("POST", f"/{account_id}/disable"),
        ("POST", f"/{account_id}/enable"),
        ("POST", f"/{account_id}/api-keys"),
    ]:
        response = await client.request(
            method, _ws(svc_workspace, path), json={"name": "denied"}
        )
        assert response.status_code == 403, (method, path, response.text)

    keys = await session.scalars(
        select(ServiceAccountApiKey).where(
            ServiceAccountApiKey.service_account_id == uuid.UUID(account_id)
        )
    )
    assert len(keys.all()) == 1


async def test_list_pagination_walks_every_account_once(
    client: httpx.AsyncClient, svc_workspace: Workspace
) -> None:
    created_ids = {
        (await _create_ws_account(client, svc_workspace, name=f"sa-{i}"))[
            "service_account"
        ]["id"]
        for i in range(3)
    }

    first = (await client.get(_ws(svc_workspace), params={"limit": 2})).json()
    assert first["has_more"] is True and first["has_previous"] is False
    second = (
        await client.get(
            _ws(svc_workspace), params={"limit": 2, "cursor": first["next_cursor"]}
        )
    ).json()
    assert second["has_more"] is False and second["has_previous"] is True
    seen = [item["id"] for item in first["items"] + second["items"]]
    assert set(seen) == created_ids and len(seen) == 3

    back = (
        await client.get(
            _ws(svc_workspace),
            params={"limit": 2, "cursor": second["prev_cursor"], "reverse": True},
        )
    ).json()
    # Paging backwards from the second page returns to the first page.
    assert [item["id"] for item in back["items"]] == [
        item["id"] for item in first["items"]
    ]

    bad = await client.get(_ws(svc_workspace), params={"cursor": "not-a-cursor"})
    assert bad.status_code == 400
