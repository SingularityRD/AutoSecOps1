"""The DB-backed router harness must behave like a production request."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Annotated

import httpx
import pytest
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.dependencies import OrgUserRole
from autosecops.auth.types import Role
from autosecops.contexts import ctx_role
from autosecops.db.engine import get_async_session
from autosecops.db.models import Organization
from tests._db_api_client import RoleSwitch, db_api_client

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]

SessionDep = Annotated[AsyncSession, Depends(get_async_session)]

router = APIRouter()


def _org(slug: str) -> Organization:
    return Organization(id=uuid.uuid4(), name=slug, slug=slug, is_active=True)


@router.get("/whoami")
async def whoami(role: OrgUserRole) -> dict[str, str | None]:
    current = ctx_role.get()
    return {
        "argument": str(role.user_id),
        "context": str(current.user_id) if current is not None else None,
    }


@router.post("/orgs/{slug}")
async def create_org(
    slug: str, role: OrgUserRole, session: SessionDep, commit: bool = True
) -> None:
    session.add(_org(slug))
    await session.flush()
    if commit:
        await session.commit()


@router.post("/orgs/{slug}/fail")
async def create_org_then_fail(
    slug: str, role: OrgUserRole, session: SessionDep
) -> None:
    session.add(_org(slug))
    await session.flush()
    raise HTTPException(status_code=409, detail="rejected after a flush")


@pytest.fixture
def caller(svc_role: Role) -> RoleSwitch:
    return RoleSwitch(svc_role)


@pytest.fixture
async def client(
    session: AsyncSession, caller: RoleSwitch
) -> AsyncIterator[httpx.AsyncClient]:
    async with db_api_client(router, session=session, caller=caller) as client:
        yield client


async def _org_count(session: AsyncSession, slug: str) -> int | None:
    return await session.scalar(
        select(func.count()).select_from(Organization).where(Organization.slug == slug)
    )


async def test_switched_role_reaches_ctx_role(
    client: httpx.AsyncClient, caller: RoleSwitch
) -> None:
    for user_id in (uuid.uuid4(), uuid.uuid4()):
        caller.role = caller.role.model_copy(update={"user_id": user_id})
        body = (await client.get("/whoami")).json()
        assert body == {"argument": str(user_id), "context": str(user_id)}


async def test_committed_write_is_kept(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    slug = f"kept-{uuid.uuid4().hex[:8]}"
    assert (await client.post(f"/orgs/{slug}")).status_code == 200
    assert await _org_count(session, slug) == 1


async def test_uncommitted_write_is_discarded(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    slug = f"lost-{uuid.uuid4().hex[:8]}"
    response = await client.post(f"/orgs/{slug}", params={"commit": False})
    assert response.status_code == 200
    # Production closes the session without a commit, so the write is lost.
    assert await _org_count(session, slug) == 0


async def test_write_before_an_http_error_is_discarded(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    slug = f"failed-{uuid.uuid4().hex[:8]}"
    assert (await client.post(f"/orgs/{slug}/fail")).status_code == 409
    assert await _org_count(session, slug) == 0
    # The session stays usable for the next request.
    assert (await client.post(f"/orgs/{slug}")).status_code == 200
    assert await _org_count(session, slug) == 1


async def test_test_seed_data_survives_a_request(
    client: httpx.AsyncClient, session: AsyncSession
) -> None:
    slug = f"seed-{uuid.uuid4().hex[:8]}"
    seeded = _org(slug)
    session.add(seeded)
    await session.flush()
    response = await client.post(f"/orgs/other-{slug}", params={"commit": False})
    assert response.status_code == 200
    assert await _org_count(session, slug) == 1
