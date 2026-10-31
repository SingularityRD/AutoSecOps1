"""Watchtower admin controls and tool-call blocking against the test database."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from autosecops_ee.watchtower import service as watchtower
from autosecops_ee.watchtower.service import WatchtowerService
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.types import Role
from autosecops.db.models import (
    Organization,
    User,
    WatchtowerAgent,
    WatchtowerAgentSession,
    WatchtowerAgentToolCall,
)
from autosecops.exceptions import AutoSecOpsNotFoundError

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]

DISABLED = "This local agent has been disabled by your organization admin."
REVOKED = "This local agent session has been revoked by your organization admin."


@dataclass
class Tracked:
    org: Organization
    agent: WatchtowerAgent
    session: WatchtowerAgentSession


async def _org(session: AsyncSession, label: str) -> Organization:
    org = Organization(
        id=uuid.uuid4(), name=f"WT {label}", slug=f"wt-{label}-{uuid.uuid4().hex[:8]}"
    )
    session.add(org)
    await session.commit()
    return org


async def _track(
    session: AsyncSession,
    org: Organization,
    mcp_session_id: str,
    *,
    last_seen: datetime | None = None,
) -> Tracked:
    seen = last_seen or datetime.now(UTC)
    agent = WatchtowerAgent(
        id=uuid.uuid4(),
        organization_id=org.id,
        fingerprint_hash=uuid.uuid4().hex,
        agent_type="claude_code",
        agent_source="client_info",
        first_seen_at=seen,
        last_seen_at=seen,
    )
    session.add(agent)
    await session.flush()
    tracked = WatchtowerAgentSession(
        id=uuid.uuid4(),
        organization_id=org.id,
        agent_id=agent.id,
        session_state="connected",
        agent_session_id=mcp_session_id,
        first_seen_at=seen,
        last_seen_at=seen,
    )
    session.add(tracked)
    await session.commit()
    return Tracked(org=org, agent=agent, session=tracked)


@pytest.fixture
async def admin(session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"wt-admin-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="unused",
        is_active=True,
        is_verified=True,
    )
    session.add(user)
    await session.commit()
    return user


@pytest.fixture
async def org(session: AsyncSession) -> Organization:
    return await _org(session, "home")


@pytest.fixture
async def foreign_org(session: AsyncSession) -> Organization:
    return await _org(session, "foreign")


@pytest.fixture
def admin_service(
    session: AsyncSession, admin: User, org: Organization
) -> WatchtowerService:
    return WatchtowerService(
        session,
        role=Role(
            type="user",
            user_id=admin.id,
            organization_id=org.id,
            service_id="autosecops-api",
        ),
    )


@pytest.fixture
def entitled(monkeypatch: pytest.MonkeyPatch) -> set[uuid.UUID]:
    """Organizations entitled to Watchtower; tests add to it."""
    orgs: set[uuid.UUID] = set()

    async def _is_entitled(
        _session: object, org_id: uuid.UUID, _entitlement: object
    ) -> bool:
        return org_id in orgs

    monkeypatch.setattr(watchtower, "is_org_entitled", _is_entitled)
    return orgs


@pytest.fixture
def shared_session(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> AsyncSession:
    """Route the module's own sessions to the test transaction."""

    @asynccontextmanager
    async def _session_cm() -> AsyncIterator[AsyncSession]:
        yield session

    monkeypatch.setattr(watchtower, "get_async_session_context_manager", _session_cm)
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    return session


async def _context(
    session: AsyncSession, org: Organization, mcp_session_id: str
) -> tuple[watchtower.WatchtowerAgentCallContext | None, str | None]:
    return await watchtower._get_tool_call_context_for_org(
        session, organization_id=org.id, mcp_session_id=mcp_session_id
    )


async def test_disabling_an_agent_blocks_its_calls_until_re_enabled(
    session: AsyncSession,
    org: Organization,
    admin: User,
    admin_service: WatchtowerService,
    entitled: set[uuid.UUID],
) -> None:
    entitled.add(org.id)
    tracked = await _track(session, org, "mcp-disable")

    ctx, reason = await _context(session, org, "mcp-disable")
    assert reason is None
    assert ctx is not None and ctx.session_row_id == tracked.session.id

    await admin_service.disable_agent(tracked.agent.id, "lost laptop")
    await session.refresh(tracked.agent)
    assert tracked.agent.blocked_reason == "lost laptop"
    assert tracked.agent.blocked_by_user_id == admin.id
    ctx, reason = await _context(session, org, "mcp-disable")
    assert reason == DISABLED
    assert ctx is not None and ctx.agent_id == tracked.agent.id

    await admin_service.enable_agent(tracked.agent.id)
    assert (await _context(session, org, "mcp-disable"))[1] is None


async def test_revoking_a_session_blocks_only_that_session(
    session: AsyncSession,
    org: Organization,
    admin_service: WatchtowerService,
    entitled: set[uuid.UUID],
) -> None:
    entitled.add(org.id)
    revoked = await _track(session, org, "mcp-revoked")
    await _track(session, org, "mcp-other")

    await admin_service.revoke_session(revoked.session.id, "suspicious")

    assert (await _context(session, org, "mcp-revoked"))[1] == REVOKED
    assert (await _context(session, org, "mcp-other"))[1] is None
    await session.refresh(revoked.session)
    assert revoked.session.session_state == "revoked"
    assert revoked.session.revoked_reason == "suspicious"


async def test_admins_cannot_act_on_another_orgs_agents(
    session: AsyncSession,
    foreign_org: Organization,
    admin_service: WatchtowerService,
    entitled: set[uuid.UUID],
) -> None:
    entitled.add(foreign_org.id)
    foreign = await _track(session, foreign_org, "mcp-foreign")

    with pytest.raises(AutoSecOpsNotFoundError):
        await admin_service.disable_agent(foreign.agent.id, "nope")
    with pytest.raises(AutoSecOpsNotFoundError):
        await admin_service.enable_agent(foreign.agent.id)
    with pytest.raises(AutoSecOpsNotFoundError):
        await admin_service.revoke_session(foreign.session.id, "nope")
    with pytest.raises(AutoSecOpsNotFoundError):
        await admin_service._assert_agent_exists(foreign.agent.id)
    with pytest.raises(AutoSecOpsNotFoundError):
        await admin_service._assert_session_exists(foreign.session.id)

    await session.refresh(foreign.agent)
    await session.refresh(foreign.session)
    assert foreign.agent.blocked_at is None
    assert foreign.session.revoked_at is None
    assert (await _context(session, foreign_org, "mcp-foreign"))[1] is None


async def test_context_is_untracked_when_unentitled_unknown_or_expired(
    session: AsyncSession,
    org: Organization,
    foreign_org: Organization,
    entitled: set[uuid.UUID],
) -> None:
    await _track(session, org, "mcp-live")
    await _track(
        session,
        org,
        "mcp-stale",
        last_seen=datetime.now(UTC)
        - timedelta(days=watchtower.WATCHTOWER_RETENTION_DAYS + 1),
    )

    assert await _context(session, org, "mcp-live") == (None, None)
    entitled.add(org.id)
    assert (await _context(session, org, "mcp-live"))[0] is not None
    assert await _context(session, org, "mcp-stale") == (None, None)
    assert await _context(session, org, "mcp-unknown") == (None, None)
    # Session IDs are only meaningful inside their own organization.
    entitled.add(foreign_org.id)
    assert await _context(session, foreign_org, "mcp-live") == (None, None)


async def test_multi_org_call_is_blocked_if_any_targeted_org_blocks(
    session: AsyncSession,
    shared_session: AsyncSession,
    org: Organization,
    foreign_org: Organization,
    admin: User,
    entitled: set[uuid.UUID],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entitled.update({org.id, foreign_org.id})
    allowed = await _track(session, org, "mcp-shared")
    blocked = await _track(session, foreign_org, "mcp-shared")
    blocked.agent.blocked_at = datetime.now(UTC)
    await session.commit()

    async def _candidates(*_args: object, **_kwargs: object) -> list[uuid.UUID]:
        return [org.id, foreign_org.id]

    monkeypatch.setattr(watchtower, "_resolve_candidate_orgs", _candidates)

    ctx, reason = await watchtower.get_watchtower_tool_call_context(
        email=admin.email,
        mcp_session_id="mcp-shared",
        claimed_org_ids=None,
        claimed_workspace_ids=None,
    )
    assert reason == DISABLED
    assert ctx is not None and ctx.organization_id == foreign_org.id

    blocked.agent.blocked_at = None
    await session.commit()
    ctx, reason = await watchtower.get_watchtower_tool_call_context(
        email=admin.email,
        mcp_session_id="mcp-shared",
        claimed_org_ids=None,
        claimed_workspace_ids=None,
    )
    assert reason is None
    assert ctx is not None and ctx.session_row_id == allowed.session.id

    assert await watchtower.get_watchtower_tool_call_context(
        email="nobody@example.com",
        mcp_session_id="mcp-shared",
        claimed_org_ids=None,
        claimed_workspace_ids=None,
    ) == (None, None)


async def test_tool_calls_are_recorded_without_raw_argument_values(
    session: AsyncSession,
    shared_session: AsyncSession,
    org: Organization,
    admin: User,
) -> None:
    tracked = await _track(
        session, org, "mcp-record", last_seen=datetime.now(UTC) - timedelta(hours=1)
    )
    context = watchtower.WatchtowerAgentCallContext(
        organization_id=org.id,
        agent_id=tracked.agent.id,
        session_row_id=tracked.session.id,
    )

    await watchtower.record_watchtower_tool_call(
        call_context=context,
        tool_name="run_workflow",
        call_status="error",
        latency_ms=12,
        workspace_id=None,
        tool_args={"api_key": "sk-live-not-for-storage", "count": 3},
        error_redacted="x" * 5000,
        email=admin.email,
    )

    calls = (
        await session.scalars(
            select(WatchtowerAgentToolCall).where(
                WatchtowerAgentToolCall.agent_session_id == tracked.session.id
            )
        )
    ).all()
    assert len(calls) == 1
    call = calls[0]
    assert "sk-live-not-for-storage" not in str(call.args_redacted)
    assert call.args_redacted["args"]["api_key"] == {"type": "str", "length": 23}
    assert call.error_redacted is not None and len(call.error_redacted) < 5000
    await session.refresh(tracked.session)
    await session.refresh(tracked.agent)
    assert tracked.session.user_id == admin.id
    assert tracked.agent.last_user_email == admin.email
    assert tracked.session.last_seen_at > datetime.now(UTC) - timedelta(minutes=1)

    # A session pruned or moved between lookup and recording is ignored.
    await watchtower.record_watchtower_tool_call(
        call_context=watchtower.WatchtowerAgentCallContext(
            organization_id=org.id,
            agent_id=tracked.agent.id,
            session_row_id=uuid.uuid4(),
        ),
        tool_name="run_workflow",
        call_status="ok",
        latency_ms=1,
        workspace_id=None,
        tool_args=None,
        error_redacted=None,
        email=None,
    )
    assert (
        len(
            (
                await session.scalars(
                    select(WatchtowerAgentToolCall).where(
                        WatchtowerAgentToolCall.agent_id == tracked.agent.id
                    )
                )
            ).all()
        )
        == 1
    )


async def test_single_tenant_deployments_skip_watchtower(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)

    assert await watchtower.get_watchtower_tool_call_context(
        email="a@example.com",
        mcp_session_id="x",
        claimed_org_ids=None,
        claimed_workspace_ids=None,
    ) == (None, None)
    assert (
        await watchtower.ingest_watchtower_initialize_event(
            email="a@example.com",
            auth_client_id=None,
            mcp_session_id="x",
            user_agent=None,
            client_info=None,
            claimed_org_ids=None,
            claimed_workspace_ids=None,
        )
        is None
    )
