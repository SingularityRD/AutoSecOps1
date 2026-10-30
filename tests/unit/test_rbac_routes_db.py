"""RBAC routes against the test database: tenant isolation and grant ceilings."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from unittest.mock import AsyncMock

import httpx
import pytest
from autosecops_ee.rbac import router as ee_rbac_router
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.types import Role
from autosecops.authz.membership import ensure_member
from autosecops.authz.rbac.router import (
    roles_router,
    user_assignments_router,
    user_scopes_router,
)
from autosecops.authz.scopes import ORG_ADMIN_SCOPES, ORG_MEMBER_ROLE_SLUG
from autosecops.authz.seeding import seed_system_roles_for_org, seed_system_scopes
from autosecops.db.models import (
    Organization,
    Scope,
    User,
    UserRoleAssignment,
    Workspace,
)
from autosecops.db.models import Role as DBRole
from tests._db_api_client import RoleSwitch, db_api_client

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]


@dataclass
class Tenant:
    org: Organization
    workspace: Workspace
    roles: dict[str, DBRole]


@pytest.fixture(autouse=True)
def rbac_entitled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ee_rbac_router, "check_entitlement", AsyncMock())
    monkeypatch.setattr(
        "autosecops.service.is_org_entitled", AsyncMock(return_value=True)
    )


async def _tenant(session: AsyncSession, label: str) -> Tenant:
    org = Organization(
        id=uuid.uuid4(),
        name=f"RBAC {label}",
        slug=f"rbac-{label}-{uuid.uuid4().hex[:8]}",
        is_active=True,
    )
    session.add(org)
    await session.flush()
    await seed_system_scopes(session)
    await seed_system_roles_for_org(session, org.id)
    workspace = Workspace(name=f"{label}-ws", organization_id=org.id)
    session.add(workspace)
    await session.commit()
    roles = (
        await session.scalars(select(DBRole).where(DBRole.organization_id == org.id))
    ).all()
    return Tenant(
        org=org,
        workspace=workspace,
        roles={r.slug: r for r in roles if r.slug is not None},
    )


async def _member(
    session: AsyncSession, tenant: Tenant, role_slug: str | None = None
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"rbac-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="unused",
        is_active=True,
        is_verified=True,
    )
    session.add(user)
    await session.flush()
    await ensure_member(session, tenant.org.id, user.id)
    if role_slug is not None:
        session.add(
            UserRoleAssignment(
                organization_id=tenant.org.id,
                user_id=user.id,
                workspace_id=None,
                role_id=tenant.roles[role_slug].id,
            )
        )
    await session.commit()
    return user


@pytest.fixture
async def tenant(session: AsyncSession) -> Tenant:
    return await _tenant(session, "home")


@pytest.fixture
async def foreign(session: AsyncSession) -> Tenant:
    return await _tenant(session, "foreign")


@pytest.fixture
async def admin(session: AsyncSession, tenant: Tenant) -> User:
    return await _member(session, tenant, "organization-admin")


@pytest.fixture
def caller(admin: User, tenant: Tenant) -> RoleSwitch:
    return RoleSwitch(
        Role(
            type="user",
            user_id=admin.id,
            organization_id=tenant.org.id,
            service_id="autosecops-api",
            scopes=ORG_ADMIN_SCOPES,
        )
    )


@pytest.fixture
async def client(
    session: AsyncSession, caller: RoleSwitch
) -> AsyncIterator[httpx.AsyncClient]:
    async with db_api_client(
        user_scopes_router,
        roles_router,
        user_assignments_router,
        ee_rbac_router.roles_router,
        ee_rbac_router.scopes_router,
        ee_rbac_router.groups_router,
        session=session,
        caller=caller,
    ) as c:
        yield c


async def _assign(
    client: httpx.AsyncClient,
    user: User,
    role: DBRole,
    workspace: Workspace | None = None,
) -> httpx.Response:
    return await client.post(
        "/rbac/user-assignments",
        json={
            "user_id": str(user.id),
            "role_id": str(role.id),
            "workspace_id": str(workspace.id) if workspace else None,
        },
    )


async def test_my_scopes_are_sorted_and_role_listing_hides_member_role(
    client: httpx.AsyncClient, tenant: Tenant, foreign: Tenant
) -> None:
    scopes = (await client.get("/users/me/scopes")).json()["scopes"]
    assert scopes == sorted(ORG_ADMIN_SCOPES)

    listed = (await client.get("/rbac/roles")).json()
    slugs = {item["slug"] for item in listed["items"]}
    assert ORG_MEMBER_ROLE_SLUG not in slugs
    assert "organization-owner" in slugs
    assert {item["organization_id"] for item in listed["items"]} == {str(tenant.org.id)}
    names = [item["name"] for item in listed["items"]]
    assert names == sorted(names)
    assert listed["total"] == len(listed["items"])


async def test_assignment_validation_maps_to_precise_statuses(
    client: httpx.AsyncClient, session: AsyncSession, tenant: Tenant, foreign: Tenant
) -> None:
    target = await _member(session, tenant)
    outsider = await _member(session, foreign)
    editor = tenant.roles["workspace-editor"]

    created = await _assign(client, target, editor, tenant.workspace)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["user_email"] == target.email
    assert body["workspace_name"] == tenant.workspace.name
    assert body["role_name"] == editor.name

    # Organization roles are org-wide only.
    org_role = await _assign(
        client, target, tenant.roles["organization-admin"], tenant.workspace
    )
    assert org_role.status_code == 400
    # Another tenant's workspace, role or user is indistinguishable from missing.
    assert (await _assign(client, target, editor, foreign.workspace)).status_code == 404
    assert (
        await _assign(
            client, target, foreign.roles["workspace-editor"], tenant.workspace
        )
    ).status_code == 404
    assert (
        await _assign(client, outsider, editor, tenant.workspace)
    ).status_code == 404
    # The implicit member role is never granted explicitly.
    member_role = await _assign(client, target, tenant.roles[ORG_MEMBER_ROLE_SLUG])
    assert member_role.status_code == 400

    assignments = (
        await client.get(
            "/rbac/user-assignments",
            params={
                "user_id": str(target.id),
                "workspace_id": str(tenant.workspace.id),
            },
        )
    ).json()
    assert [a["id"] for a in assignments["items"]] == [body["id"]]

    duplicate = await _assign(
        client, target, tenant.roles["workspace-viewer"], tenant.workspace
    )
    assert duplicate.status_code == 409


async def test_admin_cannot_grant_or_revoke_above_their_own_scopes(
    client: httpx.AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    owner = await _member(session, tenant, "organization-owner")
    target = await _member(session, tenant)

    escalate = await _assign(client, target, tenant.roles["organization-owner"])
    assert escalate.status_code == 403

    owner_assignment = await session.scalar(
        select(UserRoleAssignment.id).where(UserRoleAssignment.user_id == owner.id)
    )
    demote = await client.patch(
        f"/rbac/user-assignments/{owner_assignment}",
        json={"role_id": str(tenant.roles["workspace-viewer"].id)},
    )
    assert demote.status_code == 403
    remove = await client.delete(f"/rbac/user-assignments/{owner_assignment}")
    assert remove.status_code == 403

    still_owner = await session.scalar(
        select(UserRoleAssignment.role_id).where(
            UserRoleAssignment.id == owner_assignment
        )
    )
    assert still_owner == tenant.roles["organization-owner"].id


async def test_assignments_of_another_org_are_not_found(
    client: httpx.AsyncClient, session: AsyncSession, foreign: Tenant
) -> None:
    foreign_user = await _member(session, foreign, "workspace-viewer")
    foreign_assignment = await session.scalar(
        select(UserRoleAssignment.id).where(
            UserRoleAssignment.user_id == foreign_user.id
        )
    )
    path = f"/rbac/user-assignments/{foreign_assignment}"

    assert (await client.get(path)).status_code == 404
    assert (
        await client.patch(
            path, json={"role_id": str(foreign.roles["workspace-editor"].id)}
        )
    ).status_code == 404
    assert (await client.delete(path)).status_code == 404
    assert (
        await session.scalar(
            select(func.count()).where(UserRoleAssignment.id == foreign_assignment)
        )
    ) == 1


async def test_replace_assignments_rejects_stale_edits_and_missing_scopes(
    client: httpx.AsyncClient,
    session: AsyncSession,
    caller: RoleSwitch,
    tenant: Tenant,
) -> None:
    # A failed replace rolls back and expires loaded rows, so keep plain IDs.
    target_id = (await _member(session, tenant)).id
    viewer_id = tenant.roles["workspace-viewer"].id
    body = {
        "user_id": str(target_id),
        "assignments": [{"role_id": str(viewer_id), "workspace_id": None}],
        "expected_assignments": [],
    }

    stale = await client.put(
        "/rbac/user-assignments",
        json={
            **body,
            "expected_assignments": [
                {
                    "id": str(uuid.uuid4()),
                    "role_id": str(viewer_id),
                    "workspace_id": None,
                }
            ],
        },
    )
    assert stale.status_code == 409

    # The route only requires read; each write is checked against its own scope.
    caller.role = caller.role.model_copy(
        update={"scopes": frozenset({"org:rbac:read"})}
    )
    denied = await client.put("/rbac/user-assignments", json=body)
    assert denied.status_code == 403
    assert (
        await session.scalar(
            select(func.count()).where(UserRoleAssignment.user_id == target_id)
        )
    ) == 0

    caller.role = caller.role.model_copy(update={"scopes": ORG_ADMIN_SCOPES})
    saved = await client.put("/rbac/user-assignments", json=body)
    assert saved.status_code == 204, saved.text
    current = (
        await client.get("/rbac/user-assignments", params={"user_id": str(target_id)})
    ).json()["items"]
    assert [(a["role_id"], a["workspace_id"]) for a in current] == [
        (str(viewer_id), None)
    ]

    removal_without_delete = caller.role.scopes - {"org:rbac:delete"}
    caller.role = caller.role.model_copy(update={"scopes": removal_without_delete})
    remove = await client.put(
        "/rbac/user-assignments",
        json={
            "user_id": str(target_id),
            "assignments": [],
            "expected_assignments": [
                {
                    "id": current[0]["id"],
                    "role_id": str(viewer_id),
                    "workspace_id": None,
                }
            ],
        },
    )
    assert remove.status_code == 403


async def test_custom_roles_respect_preset_and_tenant_boundaries(
    client: httpx.AsyncClient, session: AsyncSession, tenant: Tenant, foreign: Tenant
) -> None:
    preset = tenant.roles["workspace-viewer"]
    assert (await client.delete(f"/rbac/roles/{preset.id}")).status_code == 403
    locked = await client.patch(f"/rbac/roles/{preset.id}", json={"scope_ids": []})
    assert locked.status_code == 403
    assert (
        await client.get(f"/rbac/roles/{foreign.roles['workspace-viewer'].id}")
    ).status_code == 404

    # Any platform org scope outside the admin preset is above the ceiling.
    owner_only = await session.scalar(
        select(Scope.id)
        .where(
            Scope.name.not_in(sorted(ORG_ADMIN_SCOPES)),
            Scope.organization_id.is_(None),
            Scope.name.like("org:%"),
        )
        .limit(1)
    )
    assert owner_only is not None
    above_ceiling = await client.post(
        "/rbac/roles", json={"name": "too strong", "scope_ids": [str(owner_only)]}
    )
    assert above_ceiling.status_code == 403
    missing_scope = await client.post(
        "/rbac/roles", json={"name": "ghost", "scope_ids": [str(uuid.uuid4())]}
    )
    assert missing_scope.status_code == 404

    read_scope = await session.scalar(
        select(Scope.id).where(
            Scope.name == "workflow:read", Scope.organization_id.is_(None)
        )
    )
    created = await client.post(
        "/rbac/roles", json={"name": "Analyst", "scope_ids": [str(read_scope)]}
    )
    assert created.status_code == 201, created.text
    role_id = created.json()["id"]
    assert [s["name"] for s in created.json()["scopes"]] == ["workflow:read"]

    in_use = await _member(session, tenant)
    assigned = await client.post(
        "/rbac/user-assignments",
        json={"user_id": str(in_use.id), "role_id": role_id, "workspace_id": None},
    )
    assert assigned.status_code == 201, assigned.text
    blocked = await client.delete(f"/rbac/roles/{role_id}")
    assert blocked.status_code == 400
    assert "assigned to users" in blocked.json()["detail"]


async def test_custom_scopes_cannot_shadow_platform_scopes(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    reserved = await client.post("/rbac/scopes", json={"name": "org:takeover"})
    assert reserved.status_code == 400

    created = await client.post("/rbac/scopes", json={"name": "custom.reports:read"})
    assert created.status_code == 201, created.text
    scope_id = created.json()["id"]
    assert (await client.get(f"/rbac/scopes/{scope_id}")).status_code == 200

    platform = await session.scalar(
        select(Scope.id).where(
            Scope.name == "workflow:read", Scope.organization_id.is_(None)
        )
    )
    assert (await client.delete(f"/rbac/scopes/{platform}")).status_code == 403
    assert (await client.delete(f"/rbac/scopes/{scope_id}")).status_code == 204
    assert (await client.get(f"/rbac/scopes/{scope_id}")).status_code == 404


async def test_group_membership_is_limited_to_org_members(
    client: httpx.AsyncClient, session: AsyncSession, tenant: Tenant, foreign: Tenant
) -> None:
    group = await client.post("/rbac/groups", json={"name": "responders"})
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    member = await _member(session, tenant)
    outsider = await _member(session, foreign)

    members_path = f"/rbac/groups/{group_id}/members"
    assert (
        await client.post(members_path, json={"user_id": str(outsider.id)})
    ).status_code == 404
    assert (
        await client.post(members_path, json={"user_id": str(member.id)})
    ).status_code == 201
    again = await client.post(members_path, json={"user_id": str(member.id)})
    assert again.status_code == 400

    detail = (await client.get(f"/rbac/groups/{group_id}")).json()
    assert [m["user_id"] for m in detail["members"]] == [str(member.id)]

    assert (await client.delete(f"{members_path}/{outsider.id}")).status_code == 404
    assert (await client.delete(f"{members_path}/{member.id}")).status_code == 204
    assert (await client.get(f"/rbac/groups/{uuid.uuid4()}")).status_code == 404
