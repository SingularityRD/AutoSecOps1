from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import Executable, func, null, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DataError, IntegrityError
from temporalio import activity, workflow
from temporalio.client import WorkflowExecution, WorkflowExecutionStatus, WorkflowHandle

from autosecops.agent.aliases import build_agent_alias
from autosecops.agent.approvals.enums import ApprovalStatus
from autosecops.agent.common.stream_types import ToolCallContent
from autosecops.agent.error_policy import agent_session_initialization_failed
from autosecops.agent.mcp.metadata import strip_proxy_tool_metadata
from autosecops.agent.schemas import AgentOutput
from autosecops.agent.types import (
    DeferredToolApprovalResult,
    DeferredToolResults,
    ToolApproved,
    ToolDenied,
)
from autosecops.auth.types import Role
from autosecops.common import all_activities
from autosecops.db.models import AgentSession, Approval, User, Workflow
from autosecops.dsl.client import get_temporal_client
from autosecops.dsl.common import AgentActionMemo
from autosecops.identifiers import WorkflowID
from autosecops.identifiers.workflow import exec_id_to_parts
from autosecops.logger import logger
from autosecops.service import BaseWorkspaceService
from autosecops.temporal.errors import raise_application_error_from_classification
from autosecops.workflow.executions.enums import TemporalSearchAttr
from autosecops_ee.agent.activities import (
    ApplyApprovalResultsActivityInputs,
    ApprovalDecisionPayload,
    PersistApprovalsActivityInputs,
    ToolApprovalPayload,
)
from autosecops_ee.agent.approvals.schemas import (
    ApprovalCreate,
    ApprovalUpdate,
)
from autosecops_ee.agent.context import AgentContext
from autosecops_ee.agent.types import AgentWorkflowID

if TYPE_CHECKING:
    from autosecops_ee.agent.workflows.durable import DurableAgentWorkflow


@dataclass(slots=True)
class EnrichedApproval:
    approval: Approval
    approved_by: User | None = None


@dataclass(slots=True, kw_only=True)
class SessionDescription:
    start_time: datetime
    parent_workflow_id: WorkflowID | None
    root_workflow_id: WorkflowID | None
    action_ref: str | None
    action_title: str | None


@dataclass(slots=True, kw_only=True)
class EnrichedSession:
    id: uuid.UUID
    approvals: list[EnrichedApproval] = field(default_factory=list)
    parent_workflow: Workflow | None = None
    root_workflow: Workflow | None = None
    start_time: datetime
    action_ref: str | None = None
    action_title: str | None = None


@dataclass(slots=True, kw_only=True)
class SessionInfo:
    session_id: uuid.UUID
    start_time: datetime
    parent_workflow_id: uuid.UUID | None = None
    root_workflow_id: uuid.UUID | None = None
    action_ref: str | None = None
    action_title: str | None = None


@dataclass(slots=True, kw_only=True)
class SessionHistoryItem:
    """Represents a single execution in the session history."""

    execution: WorkflowExecution
    """The workflow execution metadata."""
    result: AgentOutput
    """The execution result, if available and successful."""


class ApprovalService(BaseWorkspaceService):
    """Service for managing agent approval records.

    Provides simple CRUD operations for approval records.
    Business logic (upsert, placeholder creation, etc.) should be handled
    at the orchestration layer (ApprovalManager or Temporal activities).
    """

    service_name = "approvals"

    # CREATE operations

    async def create_approval(self, params: ApprovalCreate) -> Approval:
        """Create a single approval record."""
        approval = Approval(
            workspace_id=self.workspace_id,
            session_id=params.session_id,
            tool_call_id=params.tool_call_id,
            tool_name=params.tool_name,
            status=ApprovalStatus.PENDING,
            tool_call_args=params.tool_call_args,
        )
        self.session.add(approval)
        await self.session.commit()
        await self.session.refresh(approval)
        return approval

    async def create_approvals(
        self, approvals: Sequence[ApprovalCreate]
    ) -> list[Approval]:
        """Batch create multiple approval records."""
        if not approvals:
            return []

        records: list[Approval] = []
        for params in approvals:
            approval = Approval(
                workspace_id=self.workspace_id,
                session_id=params.session_id,
                tool_call_id=params.tool_call_id,
                tool_name=params.tool_name,
                status=ApprovalStatus.PENDING,
                tool_call_args=params.tool_call_args,
            )
            self.session.add(approval)
            records.append(approval)

        await self.session.commit()
        for record in records:
            await self.session.refresh(record)
        return records

    # READ operations

    async def get_approval(self, approval_id: uuid.UUID) -> Approval:
        """Get a single approval by ID."""
        statement = select(Approval).where(
            Approval.workspace_id == self.workspace_id,
            Approval.id == approval_id,
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def get_approval_by_session_and_tool(
        self,
        *,
        session_id: uuid.UUID,
        tool_call_id: str,
    ) -> Approval | None:
        """Get approval by session ID and tool call ID."""
        statement = select(Approval).where(
            Approval.workspace_id == self.workspace_id,
            Approval.session_id == session_id,
            Approval.tool_call_id == tool_call_id,
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def list_approvals_for_session(
        self, session_id: uuid.UUID
    ) -> Sequence[Approval]:
        """List all approvals for a given session."""
        statement = select(Approval).where(
            Approval.workspace_id == self.workspace_id,
            Approval.session_id == session_id,
        )
        result = await self.session.execute(statement)
        return result.scalars().all()

    async def list_sessions_enriched(
        self, sessions: Sequence[SessionInfo]
    ) -> list[EnrichedSession]:
        """List all enriched sessions for a given list of session IDs."""
        session_ids = [s.session_id for s in sessions]

        # Get unique workflow IDs to fetch
        workflow_ids = set()
        for session in sessions:
            if session.parent_workflow_id:
                workflow_ids.add(session.parent_workflow_id)
            if session.root_workflow_id:
                workflow_ids.add(session.root_workflow_id)

        # Fetch workflows if any exist
        workflows_by_id = {}
        if workflow_ids:
            workflow_statement = select(Workflow).where(
                Workflow.id.in_(list(workflow_ids))
            )
            workflow_result = await self.session.execute(workflow_statement)
            workflows = workflow_result.scalars().all()
            workflows_by_id = {w.id: w for w in workflows}

        statement = (
            select(Approval, User)
            .outerjoin(User, Approval.approved_by == User.id)
            .where(
                Approval.workspace_id == self.workspace_id,
                Approval.session_id.in_(session_ids),
            )
        )
        result = await self.session.execute(statement)

        # Group approvals by session_id
        approvals_by_session: dict[uuid.UUID, list[tuple[Approval, User | None]]] = {}
        for approval, user in result.tuples().all():
            if approval.session_id is None:
                continue
            if approval.session_id not in approvals_by_session:
                approvals_by_session[approval.session_id] = []
            approvals_by_session[approval.session_id].append((approval, user))

        # Create one EnrichedSession per session with all its approvals
        res: list[EnrichedSession] = []
        for session in sessions:
            id = session.session_id
            parent_wf_id = session.parent_workflow_id
            root_wf_id = session.root_workflow_id
            session_approvals = approvals_by_session.get(id, [])

            # Create enriched approval objects
            enriched_approvals = [
                EnrichedApproval(approval=approval, approved_by=user)
                for approval, user in session_approvals
            ]

            # Create the enriched session
            enriched_session = EnrichedSession(
                id=id,
                approvals=enriched_approvals,
                parent_workflow=workflows_by_id.get(parent_wf_id)
                if parent_wf_id
                else None,
                root_workflow=workflows_by_id.get(root_wf_id) if root_wf_id else None,
                start_time=session.start_time,
                action_ref=session.action_ref,
                action_title=session.action_title,
            )
            res.append(enriched_session)

        return res

    async def handle(
        self,
        agent_wf_id: AgentWorkflowID,
        run_id: str | None = None,
    ) -> WorkflowHandle[DurableAgentWorkflow, AgentOutput]:
        """Get a workflow handle for an agent workflow.

        Args:
            agent_wf_id: The agent workflow ID
            run_id: Optional run ID for a specific execution. If not provided,
                    gets the handle for the latest/current workflow execution.

        Returns:
            A workflow handle for the specified workflow/execution
        """
        from autosecops_ee.agent.workflows.durable import DurableAgentWorkflow

        client = await get_temporal_client()
        return client.get_workflow_handle_for(
            DurableAgentWorkflow.run, agent_wf_id, run_id=run_id
        )

    async def get_session(self, session_id: uuid.UUID) -> SessionDescription | None:
        """Get a session by ID."""

        # This legacy view parses durable-workflow metadata. Other backends use
        # the shared session approval API and must never be looked up as oss.
        backend_id = await self.session.scalar(
            select(AgentSession.backend_id).where(
                AgentSession.id == session_id,
                AgentSession.workspace_id == self.workspace_id,
            )
        )
        if backend_id is not None and backend_id != "oss":
            return None

        # Query workflow executions using the agent session key
        agent_wf_id = AgentWorkflowID(session_id)

        handle = await self.handle(agent_wf_id)
        description = await handle.describe()
        memo = await description.memo()
        validated_memo = AgentActionMemo.model_validate(memo)
        parent_id, root_id = None, None
        try:
            if description.parent_id:
                parent_id, _ = exec_id_to_parts(description.parent_id)
        except Exception as e:
            logger.warning("Error parsing parent ID", error=e)
        try:
            if description.root_id:
                root_id, _ = exec_id_to_parts(description.root_id)
        except Exception as e:
            logger.warning("Error parsing root ID", error=e)
        return SessionDescription(
            start_time=description.start_time,
            parent_workflow_id=parent_id,
            root_workflow_id=root_id,
            action_ref=validated_memo.action_ref,
            action_title=validated_memo.action_title,
        )

    async def list_session_history(
        self,
        session_id: uuid.UUID,
        limit: int = 5,
    ) -> list[SessionHistoryItem]:
        """Query DurableAgentWorkflow executions sharing the same alias and fetch their results."""
        if limit <= 0:
            return []
        # get the alias for the session
        session = await self.get_session(session_id)
        if session is None:
            return []
        if session.parent_workflow_id is None or session.action_ref is None:
            logger.warning(
                "Session parent workflow ID or action ref is missing",
                session_id=session_id,
            )
            return []
        alias = build_agent_alias(session.parent_workflow_id, session.action_ref)

        query = " AND ".join(
            [
                "WorkflowType = 'DurableAgentWorkflow'",
                f"{TemporalSearchAttr.WORKSPACE_ID.value} = '{str(self.workspace_id)}'",
                f"{TemporalSearchAttr.ALIAS.value} = '{alias}'",
            ]
        )

        page_size = max(1, min(limit, 50))
        history_items: list[SessionHistoryItem] = []
        client = await get_temporal_client()
        async for execution in client.list_workflows(
            query=query,
            page_size=page_size,
        ):
            if len(history_items) >= limit:
                break
            # Get workflow handle for specific execution run
            agent_wf_id = AgentWorkflowID.from_workflow_id(execution.id)
            handle = await self.handle(agent_wf_id, run_id=execution.run_id)

            # Try to fetch the result
            if execution.status != WorkflowExecutionStatus.COMPLETED:
                logger.warning(
                    "Workflow is not completed",
                    workflow_id=execution.id,
                    run_id=execution.run_id,
                )
                continue

            result = await handle.result()
            history_items.append(
                SessionHistoryItem(
                    execution=execution,
                    result=result,
                )
            )

        logger.info(
            "Session history fetched",
            session_id=session_id,
            n_items=len(history_items),
            n_with_results=sum(1 for item in history_items if item.result is not None),
        )
        # These are the last n=limit DurableAgentWorkflow executions related to the session
        return history_items

    # UPDATE operations

    async def update_approval(
        self, approval: Approval, params: ApprovalUpdate
    ) -> Approval:
        """Update a single approval record."""
        for key, value in params.model_dump(exclude_unset=True).items():
            setattr(approval, key, value)

        await self.session.commit()
        await self.session.refresh(approval)
        return approval

    async def update_approvals(
        self, updates: dict[uuid.UUID, ApprovalUpdate]
    ) -> list[Approval]:
        """Batch update multiple approval records by IDs."""
        if not updates:
            return []

        records: list[Approval] = []
        for approval_id, params in updates.items():
            approval = await self.get_approval(approval_id)
            for key, value in params.model_dump(exclude_unset=True).items():
                setattr(approval, key, value)
            records.append(approval)

        await self.session.commit()
        for record in records:
            await self.session.refresh(record)
        return records

    # DELETE operations

    async def delete_approval(self, approval: Approval) -> None:
        """Delete an approval record."""
        await self.session.delete(approval)
        await self.session.commit()


type ApprovalResult = bool | DeferredToolApprovalResult
type ApprovalMap = dict[str, ApprovalResult]


class ApprovalManagerStatus(StrEnum):
    """Possible states for a deferred tool approval."""

    IDLE = "idle"
    PENDING = "pending"
    READY = "ready"


class ApprovalManager:
    def __init__(self, role: Role) -> None:
        self._approvals: ApprovalMap = {}
        self._decision_metadata_by_tool_call_id: dict[str, dict[str, Any]] = {}
        self._approved_by_by_tool_call_id: dict[str, uuid.UUID] = {}
        self._status: ApprovalManagerStatus = ApprovalManagerStatus.IDLE
        self.role = role
        agent_ctx = AgentContext.get()
        if agent_ctx is None:
            raise RuntimeError("Agent context is not set")
        self.session_id = agent_ctx.session_id
        self._expected_tool_calls: dict[str, ToolCallContent] = {}

    @classmethod
    def get_activities(cls) -> list[Callable[..., Any]]:
        return all_activities(cls)

    @property
    def status(self) -> ApprovalManagerStatus:
        return self._status

    def is_ready(self) -> bool:
        return self._status == ApprovalManagerStatus.READY

    def set(
        self,
        approvals: ApprovalMap,
        *,
        approved_by: uuid.UUID | None = None,
        decision_metadata: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Record approval decisions, accepting partial submissions.

        Parallel tool calls surface as individual approval cards that are
        decided one by one, so decisions are merged across submissions. The
        manager only becomes READY (resuming the run) once every expected
        tool call has a decision.
        """
        self._approvals.update(approvals)
        if approved_by is not None:
            for tool_call_id in approvals:
                self._approved_by_by_tool_call_id[tool_call_id] = approved_by
        if decision_metadata:
            self._decision_metadata_by_tool_call_id.update(decision_metadata)

        expected_ids = set(self._expected_tool_calls.keys())
        if expected_ids.issubset(self._approvals.keys()):
            self._status = ApprovalManagerStatus.READY
        else:
            self._status = ApprovalManagerStatus.PENDING
            logger.info(
                "Partial approval decisions recorded",
                decided=sorted(self._approvals.keys()),
                awaiting=sorted(expected_ids - set(self._approvals.keys())),
            )

    async def wait(self) -> None:
        await workflow.wait_condition(lambda: self.is_ready())

    async def prepare(
        self,
        approvals: list[ToolCallContent],
        *,
        request_metadata: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._approvals.clear()
        self._decision_metadata_by_tool_call_id.clear()
        self._status = ApprovalManagerStatus.IDLE
        self._expected_tool_calls = {approval.id: approval for approval in approvals}
        self._approved_by_by_tool_call_id.clear()

        # Preserve per-tool proxy metadata on approval rows for display and
        # decision reconciliation.
        approval_payloads = [
            ToolApprovalPayload(
                tool_call_id=approval.id,
                tool_name=approval.name,
                args=approval.input,
                metadata=(request_metadata or {}).get(approval.id),
            )
            for approval in approvals
        ]
        # Persist the approval state (and chat messages atomically for chat namespace)
        await workflow.execute_activity(
            ApprovalManager.record_approval_requests,
            arg=PersistApprovalsActivityInputs(
                role=self.role,
                session_id=self.session_id,
                approvals=approval_payloads,
            ),
            start_to_close_timeout=timedelta(seconds=30),
        )

    def get(self) -> DeferredToolResults | None:
        if not self._approvals:
            return None
        return DeferredToolResults(approvals=self._approvals)

    def get_decision(
        self, tool_call_id: str
    ) -> bool | DeferredToolApprovalResult | None:
        """Get the approval decision for a specific tool call ID."""
        return self._approvals.get(tool_call_id)

    def validate_responses(self, approvals: ApprovalMap) -> None:
        """Validate approval responses against the expected tool calls.

        Partial submissions are valid: parallel tool calls are decided one
        card at a time, and ``set`` accumulates decisions until every expected
        tool call is covered. Responses for unknown tool calls or with missing
        decisions are rejected.
        """
        if not self._expected_tool_calls:
            raise ValueError("No pending approvals to validate")
        if not approvals:
            raise ValueError("Approval responses cannot be empty")

        expected_ids = set(self._expected_tool_calls.keys())
        provided_ids = set(approvals.keys())

        unexpected = provided_ids - expected_ids
        if unexpected:
            logger.warning(
                "Unexpected approval responses",
                unexpected_count=len(unexpected),
                unexpected_ids=sorted(unexpected),
                expected_ids=sorted(expected_ids),
            )
            raise ValueError(
                f"Received {len(unexpected)} unexpected approval response(s) for tool call IDs: "
                f"{', '.join(sorted(unexpected))}. "
                f"Expected only: {', '.join(sorted(expected_ids))}"
            )

        for tool_call_id in provided_ids:
            if approvals[tool_call_id] is None:
                tool_name = self._expected_tool_calls[tool_call_id].name
                logger.warning(
                    "Approval response is None",
                    tool_call_id=tool_call_id,
                    tool_name=tool_name,
                )
                raise ValueError(
                    f"Approval response for tool call '{tool_name}' (ID: {tool_call_id}) "
                    f"cannot be None. Please provide a valid approval decision."
                )

    async def handle_decisions(self) -> None:
        decisions: list[ApprovalDecisionPayload] = []

        for tool_call_id, result in self._approvals.items():
            approved = False
            reason: str | None = None
            decision: bool | dict[str, Any] | None = None

            match result:
                case bool(value):
                    approved = value
                    decision = value
                case ToolApproved(override_args=override_args):
                    approved = True
                    decision_payload: dict[str, Any] = {"kind": "tool-approved"}
                    if override_args is not None:
                        decision_payload["override_args"] = override_args
                    decision = decision_payload
                case ToolDenied(message=message):
                    approved = False
                    reason = message
                    decision_payload = {"kind": "tool-denied"}
                    if message:
                        decision_payload["message"] = message
                    decision = decision_payload
                case _:
                    raise RuntimeError(
                        "Invalid approval result", approval_result=result
                    )
            decisions.append(
                ApprovalDecisionPayload(
                    tool_call_id=tool_call_id,
                    approved=approved,
                    reason=reason,
                    decision=decision,
                    decision_metadata=self._decision_metadata_by_tool_call_id.get(
                        tool_call_id
                    ),
                    approved_by=self._approved_by_by_tool_call_id.get(tool_call_id),
                )
            )
        if decisions:
            await workflow.execute_activity(
                ApprovalManager.apply_approval_decisions,
                arg=ApplyApprovalResultsActivityInputs(
                    role=self.role,
                    session_id=self.session_id,
                    decisions=decisions,
                ),
                start_to_close_timeout=timedelta(seconds=30),
            )
        self._approved_by_by_tool_call_id.clear()
        self._decision_metadata_by_tool_call_id.clear()

    @staticmethod
    @activity.defn
    async def apply_approval_decisions(
        input: ApplyApprovalResultsActivityInputs,
    ) -> None:
        """Apply approval decisions once responses are received.

        Handles business logic:
        - Creates placeholder records if they don't exist
        - Automatically sets approved_at timestamp based on status
        """

        if not input.decisions:
            return

        async with ApprovalService.with_session(role=input.role) as service:
            now = datetime.now(tz=UTC)
            # Untyped: these are SQLAlchemy insert values keyed by column name,
            # where each value may be a Python scalar or a SQL element (null()).
            rows: list[dict[str, Any]] = []
            for decision in input.decisions:
                status = (
                    ApprovalStatus.APPROVED
                    if decision.approved
                    else ApprovalStatus.REJECTED
                )
                resolved_decision = decision.decision
                if decision.decision_metadata:
                    if isinstance(resolved_decision, dict):
                        resolved_decision = {
                            **resolved_decision,
                            "metadata": decision.decision_metadata,
                        }
                    elif isinstance(resolved_decision, bool):
                        resolved_decision = {
                            "value": resolved_decision,
                            "metadata": decision.decision_metadata,
                        }
                    elif resolved_decision is None:
                        resolved_decision = {"metadata": decision.decision_metadata}
                rows.append(
                    {
                        "workspace_id": service.workspace_id,
                        "session_id": input.session_id,
                        "tool_call_id": decision.tool_call_id,
                        "tool_name": "unknown",
                        "tool_call_args": None,
                        "status": status,
                        "reason": decision.reason,
                        "approved_by": decision.approved_by,
                        "approved_at": now,
                        # SQL NULL (not Python None) so COALESCE preserves a stored
                        # decision instead of overwriting it with JSON null.
                        "decision": resolved_decision
                        if resolved_decision is not None
                        else null(),
                    }
                )

            stmt = pg_insert(Approval).values(rows)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_approval_workspace_session_tool",
                set_={
                    "status": stmt.excluded.status,
                    "reason": stmt.excluded.reason,
                    "approved_by": stmt.excluded.approved_by,
                    "approved_at": stmt.excluded.approved_at,
                    "decision": func.coalesce(
                        stmt.excluded.decision, Approval.decision
                    ),
                    # onupdate does not fire for ON CONFLICT DO UPDATE.
                    "updated_at": func.now(),
                },
            )
            await _execute_approval_write(
                service,
                stmt,
                session_id=input.session_id,
                tool_call_ids=[decision.tool_call_id for decision in input.decisions],
                operation="apply_approval_decisions",
            )

    @staticmethod
    @activity.defn
    async def record_approval_requests(
        input: PersistApprovalsActivityInputs,
    ) -> None:
        """Persist pending approval records for deferred tool calls.

        All rows are written with a single ``INSERT ... ON CONFLICT DO UPDATE``
        in one transaction, so a batch of parallel tool calls becomes visible
        atomically and the activity is idempotent under Temporal retries.

        The conflict path is required, not legacy: an activity retry after a
        committed-but-unacknowledged attempt, or the executor re-requesting the
        same tool call ID in a later turn, must reset the existing row to a
        clean PENDING state (clearing any prior decision, reviewer, and
        ``approved_at``) instead of failing on the unique constraint.
        """

        if not input.approvals:
            return

        # Parallel tool calls with a repeated ID would make ON CONFLICT touch
        # the same row twice in one statement, which PostgreSQL rejects. Keep
        # the last request for each ID, matching sequential upsert semantics.
        payloads = {payload.tool_call_id: payload for payload in input.approvals}

        async with ApprovalService.with_session(role=input.role) as service:
            # Untyped: these are SQLAlchemy insert values keyed by column name,
            # where each value may be a Python scalar or a SQL element (null()).
            rows: list[dict[str, Any]] = []
            for payload in payloads.values():
                approval_args = _normalize_approval_args(payload)
                rows.append(
                    {
                        "workspace_id": service.workspace_id,
                        "session_id": input.session_id,
                        "tool_call_id": payload.tool_call_id,
                        "tool_name": payload.tool_name,
                        "status": ApprovalStatus.PENDING,
                        # SQL NULL rather than JSON null for absent arguments.
                        "tool_call_args": approval_args
                        if approval_args is not None
                        else null(),
                    }
                )

            stmt = pg_insert(Approval).values(rows)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_approval_workspace_session_tool",
                set_={
                    "tool_name": stmt.excluded.tool_name,
                    "tool_call_args": stmt.excluded.tool_call_args,
                    "status": ApprovalStatus.PENDING,
                    "reason": null(),
                    "approved_by": null(),
                    "approved_at": null(),
                    "decision": null(),
                    # onupdate does not fire for ON CONFLICT DO UPDATE.
                    "updated_at": func.now(),
                },
            )
            await _execute_approval_write(
                service,
                stmt,
                session_id=input.session_id,
                tool_call_ids=list(payloads),
                operation="record_approval_requests",
            )


def _normalize_approval_args(payload: ToolApprovalPayload) -> dict[str, Any] | None:
    """Normalize deferred tool arguments into the stored approval args shape.

    Internal proxy metadata is stripped from the model-supplied arguments, and
    per-tool request metadata is stored under the reserved ``_autosecops`` key
    for display and decision reconciliation.
    """
    approval_args: dict[str, Any] | None = None
    match payload.args:
        case dict() as args:
            approval_args = strip_proxy_tool_metadata(args)
        case str() as raw_args:
            try:
                loaded_args = json.loads(raw_args)
            except (json.JSONDecodeError, ValueError):
                # Store as-is if not valid JSON
                loaded_args = None
            if isinstance(loaded_args, dict):
                approval_args = strip_proxy_tool_metadata(loaded_args)
            else:
                approval_args = {"raw_args": raw_args}
        case None:
            approval_args = None
    if payload.metadata:
        approval_args = approval_args or {}
        approval_args["_autosecops"] = payload.metadata
    return approval_args


async def _execute_approval_write(
    service: ApprovalService,
    stmt: Executable,
    *,
    session_id: uuid.UUID,
    tool_call_ids: list[str],
    operation: str,
) -> None:
    """Execute and commit an approval write, failing fast on permanent errors.

    Approval activities run with Temporal's default (unbounded) retry policy.
    Integrity and data errors are deterministic for a given input, for example
    when the agent session row was deleted while the run waited, so retrying
    them would hang the run indefinitely with no signal to the user. They are
    raised as a non-retryable classified error instead, which fails the turn
    and surfaces the session error. Transient errors (connection loss,
    timeouts) still propagate unchanged and are retried.

    The replacement error is raised after the ``except`` block exits so the
    original database error, whose message can echo bound parameters such as
    tool arguments, is never chained into Temporal workflow history.
    """
    permanent_error_type: str | None = None
    try:
        await service.session.execute(stmt)
        await service.session.commit()
    except (IntegrityError, DataError) as exc:
        await service.session.rollback()
        permanent_error_type = type(exc).__name__
    if permanent_error_type is None:
        return
    logger.error(
        "Approval persistence failed with a non-retryable database error",
        operation=operation,
        session_id=str(session_id),
        tool_call_ids=tool_call_ids,
        error_type=permanent_error_type,
    )
    raise_application_error_from_classification(
        agent_session_initialization_failed(retryable=False)
    )
