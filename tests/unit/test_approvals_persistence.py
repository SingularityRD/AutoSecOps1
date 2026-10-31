"""Approval persistence through independent, committed database sessions.

These tests mirror how the Temporal worker runs the approval activities: every
activity opens its own connection via ``ApprovalService.with_session`` and must
commit for the API (or a poller on another connection) to observe the rows.
Unlike ``test_approvals_manager.py`` they do not patch ``with_session`` onto
the SAVEPOINT-isolated test session, so lost writes and uncommitted state are
caught here.
"""

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from unittest.mock import patch

import pytest
from autosecops_ee.agent.activities import (
    ApplyApprovalResultsActivityInputs,
    ApprovalDecisionPayload,
    PersistApprovalsActivityInputs,
    ToolApprovalPayload,
)
from autosecops_ee.agent.approvals.service import ApprovalManager, ApprovalService
from autosecops_ee.agent.context import AgentContext
from sqlalchemy import delete, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from temporalio.exceptions import ApplicationError

from autosecops.agent.approvals.enums import ApprovalStatus
from autosecops.agent.common.stream_types import ToolCallContent
from autosecops.agent.types import ToolApproved, ToolDenied
from autosecops.auth.types import Role
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import AgentSession, Approval, User
from autosecops.runtime.errors import RuntimeErrorKind

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]


@pytest.fixture
async def committed_user(svc_role: Role) -> AsyncIterator[User]:
    """A reviewer committed globally so independent sessions satisfy the FK."""
    assert svc_role.user_id is not None
    user = User(
        id=svc_role.user_id,
        email=f"reviewer-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="not-a-real-hash",
        is_active=True,
        is_verified=True,
        is_superuser=False,
        last_login_at=None,
    )
    async with get_async_session_bypass_rls_context_manager() as setup:
        setup.add(user)
        await setup.commit()
    try:
        yield user
    finally:
        async with get_async_session_bypass_rls_context_manager() as cleanup:
            await cleanup.execute(
                delete(Approval).where(Approval.approved_by == svc_role.user_id)
            )
            await cleanup.execute(
                delete(User).where(User.__table__.c.id == svc_role.user_id)
            )
            await cleanup.commit()


@pytest.fixture
async def committed_session_id(svc_role: Role) -> AsyncIterator[uuid.UUID]:
    """An agent session committed globally, as create_session_activity does."""
    session_id = uuid.uuid4()
    async with get_async_session_bypass_rls_context_manager() as setup:
        setup.add(
            AgentSession(
                id=session_id,
                title="Approval Persistence Session",
                workspace_id=svc_role.workspace_id,
                entity_type="workflow",
                entity_id=uuid.uuid4(),
            )
        )
        await setup.commit()
    try:
        yield session_id
    finally:
        async with get_async_session_bypass_rls_context_manager() as cleanup:
            await cleanup.execute(
                delete(Approval).where(Approval.session_id == session_id)
            )
            await cleanup.execute(
                delete(AgentSession).where(AgentSession.id == session_id)
            )
            await cleanup.commit()


async def _rows_by_tool_call(role: Role, session_id: uuid.UUID) -> dict[str, Approval]:
    """Read approvals on a fresh connection, as the API or a poller would."""
    async with ApprovalService.with_session(role=role) as service:
        approvals = await service.list_approvals_for_session(session_id)
        return {approval.tool_call_id: approval for approval in approvals}


def _record_input(
    role: Role, session_id: uuid.UUID, *payloads: ToolApprovalPayload
) -> PersistApprovalsActivityInputs:
    return PersistApprovalsActivityInputs(
        role=role, session_id=session_id, approvals=list(payloads)
    )


def _assert_permanent_failure(error: ApplicationError) -> None:
    assert error.non_retryable is True
    assert error.type == RuntimeErrorKind.AGENT_APPROVAL_PERSISTENCE_FAILED.value
    # The session sees an approval error, not a session-initialization error.
    assert "session" not in error.message
    # The database error echoes bound parameters (tool arguments may hold
    # sensitive values); it must not travel into Temporal history.
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "secret-value" not in str(error)
    assert all("secret-value" not in str(detail) for detail in error.details)


class TestRecordApprovalRequestsCommitted:
    async def test_batch_is_visible_to_other_connections(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        await ApprovalManager.record_approval_requests(
            _record_input(
                svc_role,
                committed_session_id,
                ToolApprovalPayload(
                    tool_call_id="call_a",
                    tool_name="core__http_request",
                    args={"url": "https://a.example.com"},
                ),
                ToolApprovalPayload(
                    tool_call_id="call_b",
                    tool_name="core__http_request",
                    args='{"url": "https://b.example.com"}',
                    metadata={"approval_key": "core.http_request"},
                ),
            )
        )

        rows = await _rows_by_tool_call(svc_role, committed_session_id)
        assert set(rows) == {"call_a", "call_b"}
        assert all(row.status == ApprovalStatus.PENDING for row in rows.values())
        assert rows["call_a"].tool_call_args == {"url": "https://a.example.com"}
        assert rows["call_b"].tool_call_args == {
            "url": "https://b.example.com",
            "_autosecops": {"approval_key": "core.http_request"},
        }

    async def test_absent_args_are_stored_as_sql_null(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        await ApprovalManager.record_approval_requests(
            _record_input(
                svc_role,
                committed_session_id,
                ToolApprovalPayload(tool_call_id="call_none", tool_name="tool"),
            )
        )

        async with get_async_session_bypass_rls_context_manager() as verify:
            is_sql_null = await verify.scalar(
                select(Approval.tool_call_args.is_(None)).where(
                    Approval.session_id == committed_session_id
                )
            )
        assert is_sql_null is True

    async def test_rerequest_keeps_decided_row_and_fails_closed(
        self,
        svc_role: Role,
        committed_session_id: uuid.UUID,
        committed_user: User,
    ) -> None:
        """A reused tool call ID must never erase a recorded decision.

        The approval row is the record of who authorized a tool action. A
        provider that reuses tool call IDs across turns fails the run closed,
        and the earlier reviewer, time, reason, and decision stay intact.
        """
        await ApprovalManager.record_approval_requests(
            _record_input(
                svc_role,
                committed_session_id,
                ToolApprovalPayload(
                    tool_call_id="call_again", tool_name="old_tool", args={"v": 1}
                ),
                ToolApprovalPayload(tool_call_id="call_other", tool_name="tool"),
            )
        )
        await ApprovalManager.apply_approval_decisions(
            ApplyApprovalResultsActivityInputs(
                role=svc_role,
                session_id=committed_session_id,
                decisions=[
                    ApprovalDecisionPayload(
                        tool_call_id="call_again",
                        approved=False,
                        reason="no",
                        decision={"kind": "tool-denied", "message": "no"},
                        approved_by=committed_user.id,
                    )
                ],
            )
        )
        before = await _rows_by_tool_call(svc_role, committed_session_id)
        decided = before["call_again"]
        assert decided.status == ApprovalStatus.REJECTED
        assert decided.approved_at is not None

        with pytest.raises(ApplicationError) as exc_info:
            await ApprovalManager.record_approval_requests(
                _record_input(
                    svc_role,
                    committed_session_id,
                    ToolApprovalPayload(
                        tool_call_id="call_again", tool_name="new_tool", args={"v": 2}
                    ),
                    # A batch is all-or-nothing: the undecided row and the new
                    # row are not written either.
                    ToolApprovalPayload(
                        tool_call_id="call_other", tool_name="renamed_tool"
                    ),
                    ToolApprovalPayload(tool_call_id="call_new", tool_name="tool"),
                ),
            )

        error = exc_info.value
        assert error.non_retryable is True
        assert error.type == RuntimeErrorKind.AGENT_APPROVAL_PERSISTENCE_FAILED.value
        assert "tool call ID" in error.message

        after = await _rows_by_tool_call(svc_role, committed_session_id)
        assert set(after) == {"call_again", "call_other"}
        row = after["call_again"]
        assert row.id == decided.id
        assert row.status == ApprovalStatus.REJECTED
        assert row.tool_name == "old_tool"
        assert row.tool_call_args == {"v": 1}
        assert row.reason == "no"
        assert row.approved_by == committed_user.id
        assert row.approved_at == decided.approved_at
        assert row.decision == {"kind": "tool-denied", "message": "no"}
        assert after["call_other"].tool_name == "tool"

    async def test_rerequest_refreshes_undecided_row(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        await ApprovalManager.record_approval_requests(
            _record_input(
                svc_role,
                committed_session_id,
                ToolApprovalPayload(
                    tool_call_id="call_pending", tool_name="old_tool", args={"v": 1}
                ),
            )
        )
        first = (await _rows_by_tool_call(svc_role, committed_session_id))[
            "call_pending"
        ]

        await ApprovalManager.record_approval_requests(
            _record_input(
                svc_role,
                committed_session_id,
                ToolApprovalPayload(
                    tool_call_id="call_pending", tool_name="new_tool", args={"v": 2}
                ),
            )
        )

        row = (await _rows_by_tool_call(svc_role, committed_session_id))["call_pending"]
        assert row.id == first.id
        assert row.status == ApprovalStatus.PENDING
        assert row.tool_name == "new_tool"
        assert row.tool_call_args == {"v": 2}
        assert row.updated_at >= first.updated_at

    async def test_nul_byte_in_args_fails_fast_with_diagnostics(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        """JSONB rejects NUL; the failure is permanent and diagnosable."""
        with (
            patch("autosecops_ee.agent.approvals.service.logger") as mock_logger,
            pytest.raises(ApplicationError) as exc_info,
        ):
            await ApprovalManager.record_approval_requests(
                _record_input(
                    svc_role,
                    committed_session_id,
                    ToolApprovalPayload(
                        tool_call_id="call_nul",
                        tool_name="tool",
                        args={"token": "secret-value\u0000"},
                    ),
                )
            )

        _assert_permanent_failure(exc_info.value)
        assert await _rows_by_tool_call(svc_role, committed_session_id) == {}
        log_kwargs = mock_logger.error.call_args.kwargs
        # 22P05 untranslatable_character. The asyncpg dialect raises a bare
        # DBAPIError for it, so classification must rely on the SQLSTATE.
        assert log_kwargs["sqlstate"] == "22P05"
        assert "secret-value" not in repr(mock_logger.error.call_args)

    async def test_retry_is_idempotent(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        activity_input = _record_input(
            svc_role,
            committed_session_id,
            ToolApprovalPayload(tool_call_id="call_retry", tool_name="tool"),
        )
        await ApprovalManager.record_approval_requests(activity_input)
        await ApprovalManager.record_approval_requests(activity_input)

        rows = await _rows_by_tool_call(svc_role, committed_session_id)
        assert list(rows) == ["call_retry"]

    async def test_duplicate_tool_call_ids_keep_last_request(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        await ApprovalManager.record_approval_requests(
            _record_input(
                svc_role,
                committed_session_id,
                ToolApprovalPayload(tool_call_id="dup", tool_name="first"),
                ToolApprovalPayload(tool_call_id="dup", tool_name="second"),
            )
        )

        rows = await _rows_by_tool_call(svc_role, committed_session_id)
        assert list(rows) == ["dup"]
        assert rows["dup"].tool_name == "second"

    async def test_missing_agent_session_fails_fast(self, svc_role: Role) -> None:
        """A missing session row is permanent; retrying would hang the run."""
        missing_session_id = uuid.uuid4()

        with pytest.raises(ApplicationError) as exc_info:
            await ApprovalManager.record_approval_requests(
                _record_input(
                    svc_role,
                    missing_session_id,
                    ToolApprovalPayload(
                        tool_call_id="call_orphan",
                        tool_name="tool",
                        args={"token": "secret-value"},
                    ),
                )
            )

        _assert_permanent_failure(exc_info.value)
        assert await _rows_by_tool_call(svc_role, missing_session_id) == {}


class TestApplyApprovalDecisionsCommitted:
    async def test_missing_agent_session_fails_fast(self, svc_role: Role) -> None:
        with pytest.raises(ApplicationError) as exc_info:
            await ApprovalManager.apply_approval_decisions(
                ApplyApprovalResultsActivityInputs(
                    role=svc_role,
                    session_id=uuid.uuid4(),
                    decisions=[
                        ApprovalDecisionPayload(
                            tool_call_id="call_orphan",
                            approved=True,
                            decision={
                                "kind": "tool-approved",
                                "override_args": {"token": "secret-value"},
                            },
                        )
                    ],
                )
            )

        _assert_permanent_failure(exc_info.value)

    async def test_deleted_reviewer_fails_fast_with_constraint_name(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        """A reviewer deleted during the wait violates the approved_by FK."""
        await ApprovalManager.record_approval_requests(
            _record_input(
                svc_role,
                committed_session_id,
                ToolApprovalPayload(tool_call_id="call_fk", tool_name="tool"),
            )
        )

        with (
            patch("autosecops_ee.agent.approvals.service.logger") as mock_logger,
            pytest.raises(ApplicationError) as exc_info,
        ):
            await ApprovalManager.apply_approval_decisions(
                ApplyApprovalResultsActivityInputs(
                    role=svc_role,
                    session_id=committed_session_id,
                    decisions=[
                        ApprovalDecisionPayload(
                            tool_call_id="call_fk",
                            approved=True,
                            decision=True,
                            approved_by=uuid.uuid4(),
                        )
                    ],
                )
            )

        _assert_permanent_failure(exc_info.value)
        log_kwargs = mock_logger.error.call_args.kwargs
        assert log_kwargs["error_type"] == "IntegrityError"
        assert log_kwargs["sqlstate"] == "23503"
        assert log_kwargs["constraint_name"]
        assert log_kwargs["table_name"] == "approval"
        row = (await _rows_by_tool_call(svc_role, committed_session_id))["call_fk"]
        assert row.status == ApprovalStatus.PENDING

    async def test_transient_errors_stay_retryable(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        """Only deterministic database errors are converted to non-retryable."""

        async def boom(*_args: Any, **_kwargs: Any) -> None:
            raise ConnectionResetError("connection lost")

        with (
            patch.object(AsyncSession, "execute", boom),
            pytest.raises(ConnectionResetError),
        ):
            await ApprovalManager.apply_approval_decisions(
                ApplyApprovalResultsActivityInputs(
                    role=svc_role,
                    session_id=committed_session_id,
                    decisions=[
                        ApprovalDecisionPayload(
                            tool_call_id="call_x", approved=True, decision=True
                        )
                    ],
                )
            )

    async def test_unclassified_driver_errors_stay_retryable(
        self, svc_role: Role, committed_session_id: uuid.UUID
    ) -> None:
        """A driver error outside SQLSTATE classes 22/23 is retried."""
        driver_error = DBAPIError("INSERT ...", None, ConnectionError("reset"))

        async def boom(*_args: Any, **_kwargs: Any) -> None:
            raise driver_error

        with (
            patch.object(AsyncSession, "execute", boom),
            pytest.raises(DBAPIError) as exc_info,
        ):
            await ApprovalManager.record_approval_requests(
                _record_input(
                    svc_role,
                    committed_session_id,
                    ToolApprovalPayload(tool_call_id="call_x", tool_name="tool"),
                )
            )
        assert exc_info.value is driver_error


async def _run_activity_inline(
    activity_fn: Callable[[Any], Awaitable[None]], *, arg: Any, **_: Any
) -> None:
    """Stand-in for ``workflow.execute_activity`` that runs the activity body."""
    await activity_fn(arg)


class TestApprovalManagerRoundTrip:
    """Drive ApprovalManager the way DurableAgentWorkflow does.

    ``workflow.execute_activity`` is replaced with an inline call so the real
    activities run against committed sessions, covering the same persistence
    path as the Temporal approval tests in
    ``tests/temporal/test_durable_agent_workflow.py``.
    """

    async def test_mixed_decisions_round_trip(
        self,
        svc_role: Role,
        committed_session_id: uuid.UUID,
        committed_user: User,
    ) -> None:
        AgentContext.set(session_id=committed_session_id)
        manager = ApprovalManager(role=svc_role)
        tool_calls = [
            ToolCallContent(
                id="call_plain",
                name="core__http_request",
                input={"url": "https://plain.example.com", "method": "GET"},
            ),
            ToolCallContent(
                id="call_override",
                name="core__http_request",
                input={"url": "https://original.example.com", "method": "GET"},
            ),
            ToolCallContent(
                id="call_denied",
                name="core__http_request",
                input={"url": "https://risky.example.com", "method": "DELETE"},
            ),
        ]

        with patch(
            "autosecops_ee.agent.approvals.service.workflow.execute_activity",
            _run_activity_inline,
        ):
            await manager.prepare(tool_calls)

            pending = await _rows_by_tool_call(svc_role, committed_session_id)
            assert set(pending) == {"call_plain", "call_override", "call_denied"}
            assert all(row.status == ApprovalStatus.PENDING for row in pending.values())

            # Parallel cards are decided one by one.
            manager.set({"call_plain": True}, approved_by=committed_user.id)
            assert not manager.is_ready()
            manager.set(
                {
                    "call_override": ToolApproved(
                        override_args={"url": "https://modified.example.com"}
                    ),
                    "call_denied": ToolDenied(message="Too risky"),
                },
                approved_by=committed_user.id,
            )
            assert manager.is_ready()
            await manager.handle_decisions()

        rows = await _rows_by_tool_call(svc_role, committed_session_id)
        assert {k: v.status for k, v in rows.items()} == {
            "call_plain": ApprovalStatus.APPROVED,
            "call_override": ApprovalStatus.APPROVED,
            "call_denied": ApprovalStatus.REJECTED,
        }
        assert all(row.approved_by == committed_user.id for row in rows.values())
        assert all(row.approved_at is not None for row in rows.values())
        # Decisions preserve the request-time tool name and arguments.
        assert rows["call_plain"].tool_name == "core__http_request"
        assert rows["call_plain"].tool_call_args == {
            "url": "https://plain.example.com",
            "method": "GET",
        }
        assert rows["call_plain"].decision is True
        assert rows["call_override"].decision == {
            "kind": "tool-approved",
            "override_args": {"url": "https://modified.example.com"},
        }
        assert rows["call_denied"].decision == {
            "kind": "tool-denied",
            "message": "Too risky",
        }
        assert rows["call_denied"].reason == "Too risky"
