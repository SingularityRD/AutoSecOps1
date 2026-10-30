"""Approval inbox routes and session lookups against the test database."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from autosecops_ee.agent.approvals import service as approvals_service_module
from autosecops_ee.agent.approvals.router import _to_approval_decisions, router
from autosecops_ee.agent.approvals.schemas import ApprovalCreate
from autosecops_ee.agent.approvals.service import ApprovalService
from sqlalchemy import select
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.agent.approvals.enums import ApprovalStatus
from autosecops.agent.session.service import AgentSessionService
from autosecops.agent.types import ToolApproved, ToolDenied
from autosecops.auth.types import Role
from autosecops.chat.schemas import ContinueRunRequest
from autosecops.db.models import AgentSession, Approval, Organization, Workspace
from autosecops.exceptions import AutoSecOpsConflictError, AutoSecOpsNotFoundError
from tests._db_api_client import RoleSwitch, db_api_client

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]


@pytest.fixture
async def other_workspace(
    session: AsyncSession, svc_organization: Organization
) -> Workspace:
    workspace = Workspace(name="approvals-other", organization_id=svc_organization.id)
    session.add(workspace)
    await session.commit()
    return workspace


async def _agent_session(
    session: AsyncSession, workspace_id: uuid.UUID, *, backend_id: str = "oss"
) -> AgentSession:
    agent_session = AgentSession(
        id=uuid.uuid4(),
        title="Approval test",
        workspace_id=workspace_id,
        entity_type="workflow",
        entity_id=uuid.uuid4(),
        backend_id=backend_id,
    )
    session.add(agent_session)
    await session.commit()
    return agent_session


@pytest.fixture
async def agent_session(session: AsyncSession, svc_role: Role) -> AgentSession:
    assert svc_role.workspace_id is not None
    return await _agent_session(session, svc_role.workspace_id)


@pytest.fixture
def caller(svc_role: Role) -> RoleSwitch:
    return RoleSwitch(svc_role)


@pytest.fixture
def run_turn(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mock = AsyncMock()
    monkeypatch.setattr(AgentSessionService, "run_turn", mock)
    return mock


@pytest.fixture
async def client(
    session: AsyncSession, caller: RoleSwitch, run_turn: AsyncMock
) -> AsyncIterator[httpx.AsyncClient]:
    async with db_api_client(router, session=session, caller=caller) as c:
        yield c


async def _pending(
    session: AsyncSession, role: Role, agent_session: AgentSession, *tool_call_ids: str
) -> list[Approval]:
    service = ApprovalService(session=session, role=role)
    return await service.create_approvals(
        [
            ApprovalCreate(
                session_id=agent_session.id,
                tool_call_id=tool_call_id,
                tool_name="core.http_request",
            )
            for tool_call_id in tool_call_ids
        ]
    )


def test_decision_mapping_covers_every_payload_shape() -> None:
    decisions = _to_approval_decisions(
        {
            "approve": True,
            "deny": False,
            "override": ToolApproved(override_args={"url": "https://safe.example"}),
            "plain": ToolApproved(),
            "denied": ToolDenied(message="not on weekends"),
            "denied-empty": ToolDenied(message=""),
        }
    )

    by_id = {d.tool_call_id: d for d in decisions}
    assert by_id["approve"].action == "approve"
    assert (by_id["deny"].action, by_id["deny"].reason) == (
        "deny",
        "Tool denied by user",
    )
    assert by_id["override"].action == "override"
    assert by_id["override"].override_args == {"url": "https://safe.example"}
    assert by_id["plain"].action == "approve"
    assert by_id["denied"].reason == "not on weekends"
    assert by_id["denied-empty"].reason == "Tool denied by user"

    with pytest.raises(ValueError, match="expected bool, ToolApproved, or ToolDenied"):
        _to_approval_decisions({"bad": "yes"})  # pyright: ignore[reportArgumentType]


async def test_submit_forwards_decisions_from_the_inbox(
    client: httpx.AsyncClient, agent_session: AgentSession, run_turn: AsyncMock
) -> None:
    response = await client.post(
        f"/approvals/{agent_session.id}",
        json={
            "approvals": {
                "call-1": True,
                "call-2": {"kind": "tool-denied", "message": "too risky"},
                "call-3": {"kind": "tool-approved", "override_args": {"limit": 1}},
            }
        },
    )

    assert response.status_code == 204, response.text
    session_id, continuation = run_turn.await_args.args
    assert session_id == agent_session.id
    assert isinstance(continuation, ContinueRunRequest)
    assert continuation.source == "inbox"
    assert [(d.tool_call_id, d.action) for d in continuation.decisions] == [
        ("call-1", "approve"),
        ("call-2", "deny"),
        ("call-3", "override"),
    ]


async def test_sessions_of_other_workspaces_are_not_found(
    client: httpx.AsyncClient,
    session: AsyncSession,
    other_workspace: Workspace,
    run_turn: AsyncMock,
) -> None:
    foreign = await _agent_session(session, other_workspace.id)

    submit = await client.post(
        f"/approvals/{foreign.id}", json={"approvals": {"call-1": True}}
    )
    dismiss = await client.delete(f"/approvals/{foreign.id}")

    assert submit.status_code == 404
    assert dismiss.status_code == 404
    run_turn.assert_not_awaited()


async def test_submit_requires_agent_update_scope(
    client: httpx.AsyncClient,
    caller: RoleSwitch,
    agent_session: AgentSession,
    run_turn: AsyncMock,
) -> None:
    caller.role = caller.role.model_copy(update={"scopes": frozenset({"agent:read"})})

    submit = await client.post(
        f"/approvals/{agent_session.id}", json={"approvals": {"call-1": True}}
    )
    dismiss = await client.delete(f"/approvals/{agent_session.id}")

    assert submit.status_code == 403
    assert dismiss.status_code == 403
    run_turn.assert_not_awaited()


@pytest.mark.parametrize(
    ("error", "status_code", "detail"),
    [
        (AutoSecOpsNotFoundError("workflow is gone"), 404, "workflow is gone"),
        (
            AutoSecOpsConflictError("x", detail="call-1 was already denied"),
            409,
            "call-1 was already denied",
        ),
        (ValueError("no pending approvals"), 400, "no pending approvals"),
        (RuntimeError("temporal internals"), 500, "Failed to submit approvals"),
    ],
)
async def test_submit_maps_workflow_errors(
    client: httpx.AsyncClient,
    agent_session: AgentSession,
    run_turn: AsyncMock,
    error: Exception,
    status_code: int,
    detail: str,
) -> None:
    run_turn.side_effect = error

    response = await client.post(
        f"/approvals/{agent_session.id}", json={"approvals": {"call-1": True}}
    )

    assert response.status_code == status_code
    assert response.json()["detail"] == detail


async def test_dismiss_denies_only_pending_approvals_through_the_workflow(
    client: httpx.AsyncClient,
    session: AsyncSession,
    svc_role: Role,
    agent_session: AgentSession,
    run_turn: AsyncMock,
) -> None:
    _, decided = await _pending(session, svc_role, agent_session, "p-1", "d-1")
    decided.status = ApprovalStatus.APPROVED
    await session.commit()

    response = await client.delete(f"/approvals/{agent_session.id}")

    assert response.status_code == 204
    continuation = run_turn.await_args.args[1]
    assert [(d.tool_call_id, d.action) for d in continuation.decisions] == [
        ("p-1", "deny")
    ]
    # The workflow owns the records while it is alive.
    remaining = (
        await session.scalars(
            select(Approval.tool_call_id).where(Approval.session_id == agent_session.id)
        )
    ).all()
    assert sorted(remaining) == ["d-1", "p-1"]


async def test_dismiss_deletes_pending_records_when_the_workflow_is_gone(
    client: httpx.AsyncClient,
    session: AsyncSession,
    svc_role: Role,
    agent_session: AgentSession,
    run_turn: AsyncMock,
) -> None:
    _, decided = await _pending(session, svc_role, agent_session, "p-1", "d-1")
    decided.status = ApprovalStatus.REJECTED
    await session.commit()
    run_turn.side_effect = RuntimeError("workflow not found")

    response = await client.delete(f"/approvals/{agent_session.id}")

    assert response.status_code == 204
    remaining = (
        await session.scalars(
            select(Approval.tool_call_id).where(Approval.session_id == agent_session.id)
        )
    ).all()
    assert remaining == ["d-1"]


async def test_dismiss_without_pending_approvals_is_a_no_op(
    client: httpx.AsyncClient, agent_session: AgentSession, run_turn: AsyncMock
) -> None:
    assert (await client.delete(f"/approvals/{agent_session.id}")).status_code == 204
    run_turn.assert_not_awaited()


async def test_approval_reads_are_scoped_to_the_workspace(
    session: AsyncSession,
    svc_role: Role,
    agent_session: AgentSession,
    other_workspace: Workspace,
) -> None:
    [approval] = await _pending(session, svc_role, agent_session, "call-1")
    other = ApprovalService(
        session=session,
        role=svc_role.model_copy(update={"workspace_id": other_workspace.id}),
    )

    with pytest.raises(NoResultFound):
        await other.get_approval(approval.id)
    assert (
        await other.get_approval_by_session_and_tool(
            session_id=agent_session.id, tool_call_id="call-1"
        )
        is None
    )
    assert await other.list_approvals_for_session(agent_session.id) == []
    assert await other.update_approvals({}) == []
    assert await other.create_approvals([]) == []


class _Description:
    def __init__(self, parent_id: str | None, root_id: str | None) -> None:
        self.start_time = datetime(2026, 1, 1, tzinfo=UTC)
        self.parent_id = parent_id
        self.root_id = root_id

    async def memo(self) -> dict[str, str]:
        return {"action_ref": "triage", "action_title": "Triage alert"}


async def test_legacy_session_view_skips_other_backends_and_bad_parent_ids(
    session: AsyncSession,
    svc_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert svc_role.workspace_id is not None
    service = ApprovalService(session=session, role=svc_role)
    handle = SimpleNamespace(
        describe=AsyncMock(return_value=_Description("not-an-exec-id", None))
    )
    monkeypatch.setattr(service, "handle", AsyncMock(return_value=handle))

    remote = await _agent_session(session, svc_role.workspace_id, backend_id="ee")
    assert await service.get_session(remote.id) is None
    service.handle.assert_not_awaited()

    oss = await _agent_session(session, svc_role.workspace_id)
    description = await service.get_session(oss.id)
    assert description is not None
    assert description.parent_workflow_id is None
    assert description.root_workflow_id is None
    assert (description.action_ref, description.action_title) == (
        "triage",
        "Triage alert",
    )

    # Without a parent workflow the history query cannot be built.
    assert await service.list_session_history(oss.id) == []
    assert await service.list_session_history(oss.id, limit=0) == []
    client = AsyncMock()
    monkeypatch.setattr(
        approvals_service_module, "get_temporal_client", AsyncMock(return_value=client)
    )
    assert await service.list_session_history(remote.id) == []
    client.list_workflows.assert_not_called()
