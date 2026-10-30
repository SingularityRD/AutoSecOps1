"""Workspace and organization secret routes against the test database."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from autosecops_ee.secrets.stores import router as stores_router_module
from autosecops_ee.secrets.stores.router import router as stores_router
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES, ORG_ADMIN_SCOPES
from autosecops.db.models import Organization, OrganizationSecret, Secret, Workspace
from autosecops.secrets import router as secrets_router_module
from autosecops.secrets.router import org_router, router
from tests._db_api_client import RoleSwitch, db_api_client

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]

VALUE = "plaintext-api-token-value"
ROLE_ARN = "arn:aws:iam::123456789012:role/autosecops-secrets-reader"


@pytest.fixture
async def other_workspace(
    session: AsyncSession, svc_organization: Organization
) -> Workspace:
    workspace = Workspace(name="secrets-other", organization_id=svc_organization.id)
    session.add(workspace)
    await session.commit()
    return workspace


@pytest.fixture
async def foreign_org(session: AsyncSession) -> Organization:
    org = Organization(
        id=uuid.uuid4(), name="Foreign", slug=f"foreign-{uuid.uuid4().hex[:8]}"
    )
    session.add(org)
    await session.commit()
    return org


@pytest.fixture
def caller(svc_role: Role) -> RoleSwitch:
    return RoleSwitch(
        svc_role.model_copy(update={"scopes": ADMIN_SCOPES | ORG_ADMIN_SCOPES})
    )


@pytest.fixture
async def client(
    session: AsyncSession, caller: RoleSwitch, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    async def _entitled(*_args: object) -> None:
        return None

    monkeypatch.setattr(stores_router_module, "check_entitlement", _entitled)
    async with db_api_client(
        router, org_router, stores_router, session=session, caller=caller
    ) as c:
        yield c


async def _by_id(
    session: AsyncSession,
    model: type[Secret] | type[OrganizationSecret],
    secret_id: str,
) -> Secret | OrganizationSecret | None:
    """Load a secret by its public ID; the mapped primary key is a surrogate."""
    session.expire_all()
    return await session.scalar(select(model).where(model.id == uuid.UUID(secret_id)))


def _secret(
    name: str = "api", value: str = VALUE, environment: str = "default"
) -> dict:
    return {
        "name": name,
        "type": "custom",
        "keys": [{"key": "TOKEN", "value": value}],
        "environment": environment,
    }


async def test_workspace_secret_values_never_leave_the_api(
    client: httpx.AsyncClient,
) -> None:
    created = await client.post("/secrets", json=_secret())
    assert created.status_code == 201, created.text
    assert VALUE not in created.text
    assert created.json()["keys"] == ["TOKEN"]

    for response in (
        await client.get("/secrets"),
        await client.get("/secrets/api"),
        await client.get("/secrets/search", params={"environment": "default"}),
    ):
        assert response.status_code == 200, response.text
        assert VALUE not in response.text

    duplicate = await client.post("/secrets", json=_secret(value="other-value"))
    assert duplicate.status_code == 409
    # The conflict message must not echo the encrypted INSERT parameters.
    assert "other-value" not in duplicate.text
    assert "encrypted" not in duplicate.text.lower()


async def test_workspace_secrets_are_invisible_to_other_workspaces(
    client: httpx.AsyncClient,
    session: AsyncSession,
    caller: RoleSwitch,
    other_workspace: Workspace,
) -> None:
    created = (await client.post("/secrets", json=_secret())).json()
    secret_id = created["id"]

    caller.role = caller.role.model_copy(update={"workspace_id": other_workspace.id})
    assert (await client.get("/secrets/api")).status_code == 404
    assert (await client.get("/secrets")).json() == []
    assert (
        await client.post(f"/secrets/{secret_id}", json={"description": "hijack"})
    ).status_code == 404
    assert (await client.delete(f"/secrets/{secret_id}")).status_code == 404

    stored = await _by_id(session, Secret, secret_id)
    assert stored is not None and stored.description is None


async def test_update_and_delete_by_id_and_short_id(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    first = (await client.post("/secrets", json=_secret("first"))).json()
    (await client.post("/secrets", json=_secret("second"))).json()

    invalid = await client.post("/secrets/not-a-secret-id", json={"description": "x"})
    assert invalid.status_code == 422

    updated = await client.post(
        f"/secrets/{first['id']}",
        json={"keys": [{"key": "ROTATED", "value": "new-value"}]},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["keys"] == ["ROTATED"]
    assert "new-value" not in updated.text

    assert (await client.delete(f"/secrets/{first['id']}")).status_code == 204
    assert (await client.delete(f"/secrets/{first['id']}")).status_code == 404
    assert await _by_id(session, Secret, first["id"]) is None

    # Renaming onto a taken name conflicts and leaves the secret unchanged.
    third = (await client.post("/secrets", json=_secret("third"))).json()
    renamed = await client.post(f"/secrets/{third['id']}", json={"name": "second"})
    assert renamed.status_code == 409
    assert (await client.get("/secrets/third")).status_code == 200


async def test_corrupted_secret_is_listed_without_keys(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    created = (await client.post("/secrets", json=_secret("broken"))).json()
    stored = await _by_id(session, Secret, created["id"])
    assert stored is not None
    stored.encrypted_keys = b"not-a-fernet-token"
    await session.commit()

    listed = (await client.get("/secrets")).json()

    [entry] = [item for item in listed if item["name"] == "broken"]
    assert entry["is_corrupted"] is True
    assert entry["keys"] == []


async def test_missing_scope_blocks_secret_reads_and_writes(
    client: httpx.AsyncClient, caller: RoleSwitch
) -> None:
    caller.role = caller.role.model_copy(
        update={"scopes": frozenset({"workflow:read"})}
    )

    assert (await client.get("/secrets")).status_code == 403
    assert (await client.post("/secrets", json=_secret())).status_code == 403
    assert (await client.get("/organization/secrets")).status_code == 403
    assert (
        await client.post("/organization/secrets", json=_secret())
    ).status_code == 403


async def test_aws_assume_role_details_require_configuration(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _unconfigured() -> str:
        raise ValueError("AUTOSECOPS__AWS_ASSUME_ROLE_ACCOUNT_ID is not set")

    monkeypatch.setattr(
        secrets_router_module, "get_autosecops_aws_account_id", _unconfigured
    )
    unavailable = await client.get("/secrets/aws-assume-role")
    assert unavailable.status_code == 503
    assert "ACCOUNT_ID" not in unavailable.text

    monkeypatch.setattr(
        secrets_router_module, "get_autosecops_aws_account_id", lambda: "123456789012"
    )
    monkeypatch.setattr(
        secrets_router_module,
        "get_autosecops_aws_principal_arn",
        lambda: "arn:aws:iam::123456789012:role/autosecops",
    )
    available = await client.get("/secrets/aws-assume-role")
    assert available.status_code == 200, available.text
    first_external_id = available.json()["external_id"]
    assert first_external_id
    # The external ID is stable per workspace.
    again = await client.get("/secrets/aws-assume-role")
    assert again.json()["external_id"] == first_external_id


async def test_org_secrets_are_scoped_to_the_organization(
    client: httpx.AsyncClient,
    session: AsyncSession,
    caller: RoleSwitch,
    foreign_org: Organization,
) -> None:
    created = await client.post("/organization/secrets", json=_secret("shared"))
    assert created.status_code == 201, created.text
    secret_id = created.json()["id"]
    assert VALUE not in created.text

    fetched = await client.get("/organization/secrets/shared")
    assert fetched.status_code == 200
    assert VALUE not in fetched.text
    assert (
        await client.get("/organization/secrets/shared", params={"environment": "prod"})
    ).status_code == 404
    caller.role = caller.role.model_copy(
        update={"organization_id": foreign_org.id, "workspace_id": None}
    )
    assert (await client.get("/organization/secrets/shared")).status_code == 404
    assert (await client.get("/organization/secrets")).json() == []
    assert (
        await client.post(
            f"/organization/secrets/{secret_id}", json={"description": "x"}
        )
    ).status_code == 404
    assert (
        await client.delete(f"/organization/secrets/{secret_id}")
    ).status_code == 404
    stored = await _by_id(session, OrganizationSecret, secret_id)
    assert isinstance(stored, OrganizationSecret)

    caller.role = caller.role.model_copy(
        update={"organization_id": stored.organization_id}
    )
    duplicate = await client.post("/organization/secrets", json=_secret("shared"))
    assert duplicate.status_code == 409
    # The conflict rolls back cleanly: the original secret is still served.
    assert (await client.get("/organization/secrets/shared")).status_code == 200


async def test_org_secret_update_and_delete(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    secret_id = (
        await client.post("/organization/secrets", json=_secret("rotating"))
    ).json()["id"]
    await client.post("/organization/secrets", json=_secret("taken"))

    updated = await client.post(
        f"/organization/secrets/{secret_id}", json={"description": "rotated"}
    )
    assert updated.status_code == 200, updated.text
    assert (
        await client.delete(f"/organization/secrets/{secret_id}")
    ).status_code == 204
    assert (
        await client.delete(f"/organization/secrets/{secret_id}")
    ).status_code == 404
    remaining = await session.scalar(
        select(OrganizationSecret.id).where(
            OrganizationSecret.id == uuid.UUID(secret_id)
        )
    )
    assert remaining is None

    # Renaming onto a taken name conflicts and leaves both secrets in place.
    clash_id = (
        await client.post("/organization/secrets", json=_secret("clashing"))
    ).json()["id"]
    clash = await client.post(
        f"/organization/secrets/{clash_id}", json={"name": "taken"}
    )
    assert clash.status_code == 409
    assert (await client.get("/organization/secrets/clashing")).status_code == 200
    assert (await client.get("/organization/secrets/taken")).status_code == 200


async def _store(client: httpx.AsyncClient, name: str = "prod") -> dict:
    response = await client.post(
        "/organization/secret-stores",
        json={
            "name": name,
            "config": {
                "provider": "aws_secrets_manager",
                "role_arn": ROLE_ARN,
                "region": "us-east-1",
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def test_secret_store_lifecycle_and_tenant_isolation(
    client: httpx.AsyncClient,
    caller: RoleSwitch,
    svc_workspace: Workspace,
    foreign_org: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        config, "AUTOSECOPS__AWS_ASSUME_ROLE_ACCOUNT_ID", "210987654321"
    )
    store = await _store(client)
    store_id = store["id"]
    assert store["autosecops_aws_account_id"] == "210987654321"

    granted = await client.post(
        f"/organization/secret-stores/{store_id}/authorizations",
        json={"workspace_id": str(svc_workspace.id)},
    )
    assert granted.status_code == 201, granted.text
    fetched = (await client.get(f"/organization/secret-stores/{store_id}")).json()
    assert fetched["authorized_workspace_ids"] == [str(svc_workspace.id)]
    listed = (await client.get("/organization/secret-stores")).json()
    assert [item["id"] for item in listed["items"]] == [store_id]
    assert (
        await client.get("/organization/secret-stores", params={"cursor": "%%%"})
    ).status_code == 400

    renamed = await client.patch(
        f"/organization/secret-stores/{store_id}", json={"description": "primary"}
    )
    assert renamed.status_code == 204, renamed.text

    caller.role = caller.role.model_copy(
        update={"organization_id": foreign_org.id, "workspace_id": None}
    )
    path = f"/organization/secret-stores/{store_id}"
    assert (await client.get(path)).status_code == 404
    assert (
        await client.patch(path, json={"description": "takeover"})
    ).status_code == 404
    assert (await client.delete(path)).status_code == 404
    assert (
        await client.post(
            f"{path}/authorizations", json={"workspace_id": str(uuid.uuid4())}
        )
    ).status_code == 404
    assert (
        await client.delete(f"{path}/authorizations/{svc_workspace.id}")
    ).status_code == 404
    assert (await client.get("/organization/secret-stores")).json()["items"] == []


async def test_secret_store_grants_only_reach_own_workspaces(
    client: httpx.AsyncClient,
    session: AsyncSession,
    svc_workspace: Workspace,
    foreign_org: Organization,
) -> None:
    foreign_workspace = Workspace(name="foreign-ws", organization_id=foreign_org.id)
    session.add(foreign_workspace)
    await session.commit()
    store_id = (await _store(client))["id"]

    cross_tenant = await client.post(
        f"/organization/secret-stores/{store_id}/authorizations",
        json={"workspace_id": str(foreign_workspace.id)},
    )
    assert cross_tenant.status_code == 404
    # Revoking a grant that was never made is reported, not silently accepted.
    assert (
        await client.delete(
            f"/organization/secret-stores/{store_id}/authorizations/{svc_workspace.id}"
        )
    ).status_code == 404
    assert (
        await client.get(f"/organization/secret-stores/{uuid.uuid4()}")
    ).status_code == 404
    assert (
        await client.delete(f"/organization/secret-stores/{store_id}")
    ).status_code == 204

    invalid = await client.post(
        "/organization/secret-stores",
        json={
            "name": "wrong-partition",
            "config": {
                "provider": "aws_secrets_manager",
                "role_arn": "arn:aws-cn:iam::123456789012:role/reader",
                "region": "us-east-1",
            },
        },
    )
    assert invalid.status_code == 422
