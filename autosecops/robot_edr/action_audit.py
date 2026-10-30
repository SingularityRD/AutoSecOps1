"""Audit robot action requests and reverts (`tools.robodr.request_action`/`revert_action`).

The registry actions run inside a workflow or agent run and talk to the robot
directly; the platform sees them only through this audit route. Each call is
written before the request is signed (``attempt``, fail closed: the registry
action sends nothing to the robot unless it is written) and again when the
robot answered or the call failed.

The people in the event come from the platform's own records: the sign-off
form submissions named in the request, read here in the caller's workspace,
must be submitted by platform users for exactly this request id and digest,
with the requester's ``request`` decision and an ``approve`` decision from
each approver. A body that names other people, another request or another
workspace's submissions is refused, so the event cannot credit a sign-off
nobody gave.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Final

from sqlalchemy import select

from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.types import AuditMetadataValue
from autosecops.db.models import FormSubmission
from autosecops.exceptions import AutoSecOpsValidationError
from autosecops.robot_edr.audit import write_robot_edr_audit
from autosecops.robot_edr.schemas import RobotActionAuditRequest
from autosecops.service import BaseWorkspaceService
from autosecops.tiers.enums import Entitlement

SIGNOFF_REQUEST_ID: Final = "robodr_request_id"
SIGNOFF_DIGEST: Final = "robodr_request_digest"
SIGNOFF_DECISION: Final = "robodr_decision"

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

    async def _signoff_people(self, params: RobotActionAuditRequest) -> SignoffPeople:
        """Read the sign-off submissions and check they sign off this request.

        Raises:
            AutoSecOpsValidationError: A submission is unknown here, reused,
                not a platform user's, or not for this request.
        """
        ids = [params.request_submission_id, *params.approval_submission_ids]
        if len(set(ids)) != len(ids):
            raise AutoSecOpsValidationError("a sign-off submission is named twice")
        stmt = select(
            FormSubmission.id,
            FormSubmission.submitted_by_user_id,
            FormSubmission.answers[SIGNOFF_REQUEST_ID].astext,
            FormSubmission.answers[SIGNOFF_DIGEST].astext,
            FormSubmission.answers[SIGNOFF_DECISION].astext,
        ).where(
            FormSubmission.workspace_id == self.workspace_id,
            FormSubmission.id.in_(ids),
        )
        rows = {row[0]: row[1:] for row in (await self.session.execute(stmt)).tuples()}
        people: list[uuid.UUID] = []
        for sid, decision in [(params.request_submission_id, "request")] + [
            (sid, "approve") for sid in params.approval_submission_ids
        ]:
            if (row := rows.get(sid)) is None:
                raise AutoSecOpsValidationError(
                    f"sign-off submission {sid} is not in this workspace"
                )
            user_id, request_id, digest, answered = row
            if user_id is None:
                raise AutoSecOpsValidationError(
                    f"sign-off submission {sid} was not submitted by a platform user"
                )
            if (request_id, digest, answered) != (
                params.request_id,
                params.request_digest,
                decision,
            ):
                raise AutoSecOpsValidationError(
                    f"sign-off submission {sid} does not sign off this request "
                    f"with {SIGNOFF_DECISION}={decision!r}"
                )
            people.append(user_id)
        requester, *approvers = people
        if requester in approvers or len(set(approvers)) != len(approvers):
            raise AutoSecOpsValidationError(
                "the requester and each approver must be different platform users"
            )
        return SignoffPeople(requester, tuple(approvers))

    async def record(self, params: RobotActionAuditRequest) -> None:
        """Write the audit event for one phase of a robot action call.

        Raises:
            AutoSecOpsValidationError: The sign-off submissions do not sign
                off this request.
            AuditWriteError: The event could not be written (fail closed).
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        people = await self._signoff_people(params)
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
        }
        if params.phase == "answered":
            data["outcome"] = params.outcome
            if params.applied is not None:
                data["is_applied"] = params.applied
        elif params.phase == "failed":
            data["failure_reason"] = params.failure_reason
        await write_robot_edr_audit(
            self.session,
            self.role,
            resource_type="robot_action",
            action="request" if params.operation == "request_action" else "revert",
            status=_STATUS[params.phase],
            data=data,
            strict=True,
        )
