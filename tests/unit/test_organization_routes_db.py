"""Organization routes against the test database: membership and tenant isolation."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.types import Role
from autosecops.authz.membership import ensure_member
from autosecops.authz.scopes import ORG_ADMIN_SCOPES
from autosecops.db.models import AccessToken, Organization, OrganizationDomain, User
from autosecops.organization.router import router
from tests._db_api_client import RoleSwitch, db_api_client

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]


async def _org(
    session: AsyncSession, name: str, *, active: bool = True
) -> Organization:
    org = Organization(
        id=uuid.uuid4(),
        name=name,
        slug=f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}",
        is_active=active,
    )
    session.add(org)
    await session.commit()
    return org


async def _user(
    session: AsyncSession, *orgs: Organization, superuser: bool = False
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"org-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="unused",
        is_active=True,
        is_verified=True,
        is_superuser=superuser,
        first_name="Original",
    )
    session.add(user)
    await session.flush()
    for org in orgs:
        await ensure_member(session, org.id, user.id)
    await session.commit()
    return user


@pytest.fixture
async def home(session: AsyncSession) -> Organization:
    return await _org(session, "Home Org")


@pytest.fixture
async def foreign(session: AsyncSession) -> Organization:
    return await _org(session, "Foreign Org")


@pytest.fixture
async def admin(session: AsyncSession, home: Organization) -> User:
    return await _user(session, home)


@pytest.fixture
def caller(admin: User, home: Organization) -> RoleSwitch:
    return RoleSwitch(
        Role(
            type="user",
            user_id=admin.id,
            organization_id=home.id,
            service_id="autosecops-api",
            scopes=ORG_ADMIN_SCOPES,
        )
    )


@pytest.fixture
async def client(
    session: AsyncSession, caller: RoleSwitch
) -> AsyncIterator[httpx.AsyncClient]:
    async with db_api_client(router, session=session, caller=caller) as c:
        yield c


async def test_current_org_and_membership_listing_are_caller_scoped(
    client: httpx.AsyncClient,
    session: AsyncSession,
    caller: RoleSwitch,
    admin: User,
    home: Organization,
    foreign: Organization,
) -> None:
    current = await client.get("/organization")
    assert current.json() == {"id": str(home.id), "name": home.name}

    second = await _org(session, "Another Org")
    retired = await _org(session, "Archived Org", active=False)
    for org in (second, retired):
        await ensure_member(session, org.id, admin.id)
    await session.commit()
    # Someone else's membership in the foreign org must not leak.
    await _user(session, foreign)

    memberships = (await client.get("/organization/memberships")).json()
    assert [m["name"] for m in memberships] == ["Another Org", "Home Org"]

    caller.role = caller.role.model_copy(update={"organization_id": uuid.uuid4()})
    assert (await client.get("/organization")).status_code == 404


async def test_domains_list_primary_first_and_only_for_this_org(
    client: httpx.AsyncClient,
    session: AsyncSession,
    home: Organization,
    foreign: Organization,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    session.add_all(
        [
            OrganizationDomain(
                organization_id=home.id,
                domain=f"secondary-{suffix}.example",
                normalized_domain=f"secondary-{suffix}.example",
                is_primary=False,
                is_active=True,
            ),
            OrganizationDomain(
                organization_id=home.id,
                domain=f"primary-{suffix}.example",
                normalized_domain=f"primary-{suffix}.example",
                is_primary=True,
                is_active=True,
            ),
            OrganizationDomain(
                organization_id=foreign.id,
                domain=f"foreign-{suffix}.example",
                normalized_domain=f"foreign-{suffix}.example",
                is_primary=True,
                is_active=True,
            ),
        ]
    )
    await session.commit()

    domains = (await client.get("/organization/domains")).json()

    assert [d["domain"] for d in domains] == [
        f"primary-{suffix}.example",
        f"secondary-{suffix}.example",
    ]


async def test_members_of_other_orgs_cannot_be_read_changed_or_removed(
    client: httpx.AsyncClient,
    session: AsyncSession,
    foreign: Organization,
) -> None:
    outsider = await _user(session, foreign)
    outsider_id = outsider.id

    assert (
        await client.patch(
            f"/organization/members/{outsider_id}", json={"first_name": "Pwned"}
        )
    ).status_code == 404
    assert (
        await client.delete(f"/organization/members/{outsider_id}")
    ).status_code == 404
    assert (
        await client.get(f"/organization/members/{outsider_id}/access")
    ).status_code == 404

    session.expire_all()
    stored = await session.get(User, outsider_id)
    assert stored is not None and stored.first_name == "Original"


async def test_org_admin_cannot_change_member_credentials_or_superusers(
    client: httpx.AsyncClient,
    session: AsyncSession,
    home: Organization,
) -> None:
    member = await _user(session, home)
    superuser = await _user(session, home, superuser=True)

    for field, value in (("email", "attacker@example.com"), ("password", "hunter2!")):
        response = await client.patch(
            f"/organization/members/{member.id}", json={field: value}
        )
        assert response.status_code == 403, field
    assert (
        await client.patch(
            f"/organization/members/{superuser.id}", json={"first_name": "x"}
        )
    ).status_code == 403

    member_id = member.id
    session.expire_all()
    stored = await session.get(User, member_id)
    assert stored is not None and stored.email != "attacker@example.com"


async def test_sessions_of_other_orgs_are_hidden_and_not_revocable(
    client: httpx.AsyncClient,
    session: AsyncSession,
    home: Organization,
    foreign: Organization,
) -> None:
    member = await _user(session, home)
    outsider = await _user(session, foreign)
    own = AccessToken(token=f"own-{uuid.uuid4().hex}", user_id=member.id)
    other = AccessToken(token=f"other-{uuid.uuid4().hex}", user_id=outsider.id)
    session.add_all([own, other])
    await session.commit()
    own_id, other_id = own.id, other.id

    listed = {s["id"] for s in (await client.get("/organization/sessions")).json()}
    assert str(own_id) in listed
    assert str(other_id) not in listed

    assert (
        await client.delete(f"/organization/sessions/{other_id}")
    ).status_code == 404
    assert (await client.delete(f"/organization/sessions/{own_id}")).status_code == 204
    assert (
        await session.scalar(select(AccessToken.id).where(AccessToken.id == other_id))
    ) == other_id


async def test_member_routes_require_their_scopes(
    client: httpx.AsyncClient,
    caller: RoleSwitch,
    session: AsyncSession,
    home: Organization,
) -> None:
    member = await _user(session, home)
    caller.role = caller.role.model_copy(update={"scopes": frozenset({"org:read"})})

    assert (await client.get("/organization")).status_code == 200
    assert (await client.get("/organization/members")).status_code == 403
    assert (
        await client.delete(f"/organization/members/{member.id}")
    ).status_code == 403
    assert (
        await client.patch(
            f"/organization/members/{member.id}", json={"first_name": "x"}
        )
    ).status_code == 403
    assert (
        await client.delete("/organization", params={"confirm": home.name})
    ).status_code == 403
