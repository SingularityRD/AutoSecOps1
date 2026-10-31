"""The DB-backed router harness must behave like a production request."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.dependencies import OrgUserRole
from autosecops.auth.types import Role
from autosecops.contexts import ctx_role
from tests._db_api_client import RoleSwitch, db_api_client

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]

router = APIRouter()


@router.get("/whoami")
async def whoami(role: OrgUserRole) -> dict[str, str | None]:
    current = ctx_role.get()
    return {
        "argument": str(role.user_id),
        "context": str(current.user_id) if current is not None else None,
    }


@pytest.fixture
def caller(svc_role: Role) -> RoleSwitch:
    return RoleSwitch(svc_role)


@pytest.fixture
async def client(
    session: AsyncSession, caller: RoleSwitch
) -> AsyncIterator[httpx.AsyncClient]:
    async with db_api_client(router, session=session, caller=caller) as client:
        yield client


async def test_switched_role_reaches_ctx_role(
    client: httpx.AsyncClient, caller: RoleSwitch
) -> None:
    for user_id in (uuid.uuid4(), uuid.uuid4()):
        caller.role = caller.role.model_copy(update={"user_id": user_id})
        body = (await client.get("/whoami")).json()
        assert body == {"argument": str(user_id), "context": str(user_id)}
