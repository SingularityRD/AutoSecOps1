"""Pre-auth organization resolution against a real database.

Login, SSO and invitation flows run before a user is known, so the target
organization comes from ``?org=<slug>``. In multi-tenant mode an inactive or
unknown organization must never be selectable.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.api.common import get_default_organization_id
from autosecops.auth.org_context import resolve_auth_organization_id
from autosecops.db.models import Organization


def _request(query: str = "") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/auth/login",
            "query_string": query.encode(),
            "headers": [],
        }
    )


async def _org(session: AsyncSession, *, active: bool = True) -> Organization:
    org_id = uuid.uuid4()
    org = Organization(
        id=org_id,
        name="Pre-auth org",
        slug=f"preauth-{org_id.hex[:12]}",
        is_active=active,
    )
    session.add(org)
    await session.flush()
    return org


@pytest.fixture
def multi_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)


@pytest.mark.anyio
@pytest.mark.usefixtures("db", "multi_tenant")
async def test_multi_tenant_resolves_active_org_by_trimmed_slug(
    session: AsyncSession,
) -> None:
    org = await _org(session)
    resolved = await resolve_auth_organization_id(
        _request(f"org=%20{org.slug}%20"), session=session
    )
    assert resolved == org.id


@pytest.mark.anyio
@pytest.mark.usefixtures("db", "multi_tenant")
async def test_multi_tenant_rejects_inactive_org(session: AsyncSession) -> None:
    org = await _org(session, active=False)
    with pytest.raises(HTTPException) as exc_info:
        await resolve_auth_organization_id(_request(f"org={org.slug}"), session=session)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid organization"


@pytest.mark.anyio
@pytest.mark.usefixtures("db", "multi_tenant")
async def test_multi_tenant_rejects_unknown_slug(session: AsyncSession) -> None:
    with pytest.raises(HTTPException) as exc_info:
        await resolve_auth_organization_id(
            _request(f"org=missing-{uuid.uuid4().hex}"), session=session
        )
    assert exc_info.value.status_code == 400


@pytest.mark.anyio
@pytest.mark.usefixtures("db", "multi_tenant")
@pytest.mark.parametrize("query", ["", "org="], ids=["absent", "empty"])
async def test_multi_tenant_requires_explicit_org_selection(
    session: AsyncSession, query: str
) -> None:
    """Without a selection there is no fallback to the default organization."""
    await _org(session)
    with pytest.raises(HTTPException) as exc_info:
        await resolve_auth_organization_id(_request(query), session=session)
    assert exc_info.value.status_code == 428


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_single_tenant_ignores_org_parameter(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single-tenant install always signs in to its default organization."""
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    other = await _org(session)
    default_org_id = await get_default_organization_id(session)
    assert default_org_id != other.id

    resolved = await resolve_auth_organization_id(
        _request(f"org={other.slug}"), session=session
    )
    assert resolved == default_org_id
