"""Audit robot action requests and reverts (`tools.robodr.request_action`/`revert_action`).

The registry actions run inside a workflow or agent run and talk to the robot
directly; the platform sees them only through this audit route. Each call is
written before the request is signed (``attempt``, fail closed: the registry
action sends nothing to the robot unless it is written) and again when the
robot answered or the call failed.

The attempt is checked against the platform's own records. The sign-off form
submissions named in the request, read here in the caller's workspace, must
all come from one form, be submitted by platform users within the last 24
hours, and carry exactly this request id, digest and robot id (and, for a
request, the catalog action) with the requester's ``request`` decision and an
``approve`` decision from each other approver. The people in the event are
the submitters. A body that names other people, another request, robot or
action, an old or mixed-form sign-off, or another workspace's submissions is
refused, so the event cannot credit a sign-off nobody gave.

The attempt is stored (:class:`~autosecops.db.models.RobotActionAudit`). An
``answered`` or ``failed`` event names it and must match it field for field,
from the same run, and closes it: an outcome is accepted once, and only for
an attempt that was audited. A revert's ``robot_action`` (the action the
robot says it undoes) is not on the sign-off: it is bound to the attempt only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select, update

from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.types import AuditMetadataValue
from autosecops.contexts import ExecutorProvenance, ctx_executor_provenance
from autosecops.db.models import FormSubmission, RobotActionAudit
from autosecops.exceptions import AutoSecOpsValidationError
from autosecops.robot_edr.audit import write_robot_edr_audit
from autosecops.robot_edr.schemas import (
    RobotActionAuditRequest,
    RobotActionAuditResponse,
)
from autosecops.service import BaseWorkspaceService
from autosecops.tiers.enums import Entitlement

SIGNOFF_REQUEST_ID: Final = "robodr_request_id"
SIGNOFF_DIGEST: Final = "robodr_request_digest"
SIGNOFF_DECISION: Final = "robodr_decision"
SIGNOFF_ROBOT_ID: Final = "robodr_robot_id"
SIGNOFF_ACTION: Final = "robodr_action"
MAX_SIGNOFF_AGE: Final = timedelta(hours=24)
"""How old a sign-off submission may be (the registry action's limit)."""

_STATUS: Final = {
    "attempt": AuditEventStatus.ATTEMPT,
    "answered": AuditEventStatus.SUCCESS,
    "failed": AuditEventStatus.FAILURE,
}


@dataclass(frozen=True, slots=True)
class SignoffPeople:
    """The platform users who signed off a robot action, from their submissions."""

    requested_by_user_id: uuid.UUID
    approved_by_user_ids: tuple[uuid.UUID, ...]


class RobotActionAuditService(BaseWorkspaceService):
    """Write audit events for robot action requests and reverts."""

    service_name = "robot_edr_action_audit"

    def _expected_answers(self, params: RobotActionAuditRequest) -> dict[str, str]:
        """The sign-off answers every submission for this call must carry."""
        expected = {
            SIGNOFF_REQUEST_ID: params.request_id,
            SIGNOFF_DIGEST: params.request_digest,
            SIGNOFF_ROBOT_ID: params.robot_id,
        }
        if params.operation == "request_action":
            expected[SIGNOFF_ACTION] = params.robot_action
        return expected

    async def _signoff_people(self, params: RobotActionAuditRequest) -> SignoffPeople:
        """Read the sign-off submissions and check they sign off this request.

        Raises:
            AutoSecOpsValidationError: A submission is unknown here, reused,
                not a platform user's, too old, from another form, or not
                for this request, robot or action.
        """
        ids = [params.request_submission_id, *params.approval_submission_ids]
        if len(set(ids)) != len(ids):
            raise AutoSecOpsValidationError("a sign-off submission is named twice")
        stmt = select(
            FormSubmission.id,
            FormSubmission.form_id,
            FormSubmission.created_at,
            FormSubmission.submitted_by_user_id,
            FormSubmission.answers,
        ).where(
            FormSubmission.workspace_id == self.workspace_id,
            FormSubmission.id.in_(ids),
        )
        rows = {row[0]: row[1:] for row in (await self.session.execute(stmt)).tuples()}
        expected = self._expected_answers(params)
        oldest_allowed = datetime.now(UTC) - MAX_SIGNOFF_AGE
        form_ids: set[uuid.UUID] = set()
        people: list[uuid.UUID] = []
        for sid, decision in [(params.request_submission_id, "request")] + [
            (sid, "approve") for sid in params.approval_submission_ids
        ]:
            if (row := rows.get(sid)) is None:
                raise AutoSecOpsValidationError(
                    f"sign-off submission {sid} is not in this workspace"
                )
            form_id, created_at, user_id, answers = row
            if user_id is None:
                raise AutoSecOpsValidationError(
                    f"sign-off submission {sid} was not submitted by a platform user"
                )
            if created_at < oldest_allowed:
                raise AutoSecOpsValidationError(
                    f"sign-off submission {sid} is older than 24 hours"
                )
            got = {key: answers.get(key) for key in expected} | {
                SIGNOFF_DECISION: answers.get(SIGNOFF_DECISION)
            }
            if got != expected | {SIGNOFF_DECISION: decision}:
                mismatched = sorted(
                    key
                    for key, value in (expected | {SIGNOFF_DECISION: decision}).items()
                    if got.get(key) != value
                )
                raise AutoSecOpsValidationError(
                    f"sign-off submission {sid} does not sign off this "
                    f"{params.operation} with {SIGNOFF_DECISION}={decision!r} "
                    f"(differs in {', '.join(mismatched)})"
                )
            form_ids.add(form_id)
            people.append(user_id)
        if len(form_ids) != 1:
            raise AutoSecOpsValidationError(
                "all sign-off submissions must come from the same form"
            )
        requester, *approvers = people
        if requester in approvers or len(set(approvers)) != len(approvers):
            raise AutoSecOpsValidationError(
                "the requester and each approver must be different platform users"
            )
        return SignoffPeople(requester, tuple(approvers))

    @staticmethod
    def _run() -> ExecutorProvenance:
        """The run the executor token names (this route admits executors only)."""
        if (provenance := ctx_executor_provenance.get()) is None:
            raise AutoSecOpsValidationError(
                "a robot action is audit-logged only from a workflow or agent run"
            )
        return provenance

    async def _store_attempt(
        self, params: RobotActionAuditRequest, people: SignoffPeople
    ) -> uuid.UUID:
        run = self._run()
        attempt = RobotActionAudit(
            id=uuid.uuid4(),
            workspace_id=self.workspace_id,
            request_id=params.request_id,
            operation=params.operation,
            robot_id=params.robot_id,
            robot_action=params.robot_action,
            request_digest=params.request_digest,
            request_submission_id=params.request_submission_id,
            approval_submission_ids=[str(s) for s in params.approval_submission_ids],
            requested_by_user_id=people.requested_by_user_id,
            approved_by_user_ids=[str(u) for u in people.approved_by_user_ids],
            workflow_id=run.workflow_id,
            run_id=run.run_id,
            agent_session_id=run.agent_session_id,
        )
        self.session.add(attempt)
        await self.session.flush()
        return attempt.id

    async def _close_attempt(self, params: RobotActionAuditRequest) -> SignoffPeople:
        """Close the open attempt this outcome belongs to.

        Raises:
            AutoSecOpsValidationError: No open attempt from this run matches
                (unknown, already closed, another run's, or other fields).
        """
        run = self._run()
        table = RobotActionAudit
        stmt = (
            update(table)
            .where(
                table.workspace_id == self.workspace_id,
                table.id == params.attempt_id,
                table.closed_at.is_(None),
                table.request_id == params.request_id,
                table.operation == params.operation,
                table.robot_id == params.robot_id,
                table.robot_action == params.robot_action,
                table.request_digest == params.request_digest,
                table.request_submission_id == params.request_submission_id,
                table.approval_submission_ids
                == [str(s) for s in params.approval_submission_ids],
                table.workflow_id == run.workflow_id,
                table.run_id == run.run_id,
                (
                    table.agent_session_id.is_(None)
                    if run.agent_session_id is None
                    else table.agent_session_id == run.agent_session_id
                ),
            )
            .values(closed_phase=params.phase, closed_at=datetime.now(UTC))
            .returning(table.requested_by_user_id, table.approved_by_user_ids)
        )
        row = (await self.session.execute(stmt)).tuples().one_or_none()
        if row is None:
            raise AutoSecOpsValidationError(
                f"no open audited attempt of this {params.operation} from this run "
                f"matches attempt_id {params.attempt_id}"
            )
        requester, approvers = row
        return SignoffPeople(requester, tuple(uuid.UUID(u) for u in approvers))

    async def record(self, params: RobotActionAuditRequest) -> RobotActionAuditResponse:
        """Write the audit event for one phase of a robot action call.

        Raises:
            AutoSecOpsValidationError: The sign-off submissions do not sign
                off this request, or an outcome matches no open attempt.
            AuditWriteError: The event could not be written (fail closed);
                nothing is stored or closed.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        if params.phase == "attempt":
            people = await self._signoff_people(params)
            attempt_id = await self._store_attempt(params, people)
        else:
            people = await self._close_attempt(params)
            attempt_id = params.attempt_id
            if attempt_id is None:  # the schema requires it; narrows the type
                raise AutoSecOpsValidationError("an outcome needs the attempt_id")
        data: dict[str, AuditMetadataValue] = {
            "robot_id": params.robot_id,
            "request_id": params.request_id,
            "operation": params.operation,
            "robot_action": params.robot_action,
            "request_digest": params.request_digest,
            "requested_by_user_id": str(people.requested_by_user_id),
            "approved_by_user_ids": [str(u) for u in people.approved_by_user_ids],
            "request_submission_id": str(params.request_submission_id),
            "approval_submission_ids": [str(s) for s in params.approval_submission_ids],
            "action_audit_id": str(attempt_id),
        }
        if params.phase == "answered":
            data["outcome"] = params.outcome
            if params.applied is not None:
                data["is_applied"] = params.applied
        elif params.phase == "failed":
            data["failure_reason"] = params.failure_reason
        try:
            result = await write_robot_edr_audit(
                self.session,
                self.role,
                resource_type="robot_action",
                action="request" if params.operation == "request_action" else "revert",
                status=_STATUS[params.phase],
                data=data,
                strict=True,
            )
        except BaseException:
            await self.session.rollback()
            raise
        await self.session.commit()
        return RobotActionAuditResponse(attempt_id=attempt_id, audit_log=result.value)
