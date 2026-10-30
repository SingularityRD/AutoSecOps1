"""Audit events for RoboDR actions, attributed to whoever acted.

The platform's role-based attribution names a person or a service account. A
workflow run, schedule, webhook, subflow or agent acting through the executor
carries no such actor: its role is an internal service role whose
``actor_id`` is the attributed user at best and ``None`` for an unattended
run, so a role-attributed event is either dropped or credited to a person as
if they had acted interactively. RoboDR events therefore resolve the actor
here:

* a verified executor token (``ctx_executor_provenance``): the agent session
  (``AGENT``) or the workflow (``WORKFLOW``) is the actor, and the event data
  names the run (``workflow_id``, ``run_id``, ``execution_id``,
  ``trigger_type``, ``execution_origin``, ``root_action``,
  ``agent_session_id``) and, when a person started it,
  ``initiated_by_user_id``;
* a service account: the account is the actor and ``api_key_id`` names the
  key it authenticated with;
* a user: the user.

Anything else has no auditable actor. A strict write (privileged actions)
then refuses the operation, as does a configured sink that cannot take the
event (:class:`~autosecops.audit.service.AuditWriteError`).
"""

from __future__ import annotations

import uuid
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.audit.enums import AuditEventActor, AuditEventStatus
from autosecops.audit.service import AuditService, AuditWriteError
from autosecops.audit.types import (
    AuditAction,
    AuditActor,
    AuditMetadata,
    AuditMetadataValue,
    AuditResourceType,
)
from autosecops.auth.types import Role
from autosecops.contexts import (
    ExecutorProvenance,
    ctx_executor_provenance,
    ctx_service_account_api_key_id,
)
from autosecops.identifiers.workflow import WorkflowUUID
from autosecops.logger import logger

_WORKFLOW_ACTOR_NAMESPACE: Final = uuid.UUID("5b1f8a52-6f0e-4a59-9a43-52b0a7d3c0e1")
"""Derives a stable actor id from a workflow id that is not a workflow UUID."""


def _workflow_actor_id(workflow_id: str) -> uuid.UUID:
    try:
        return WorkflowUUID.new(workflow_id)
    except (TypeError, ValueError):
        return uuid.uuid5(_WORKFLOW_ACTOR_NAMESPACE, workflow_id)


def _executor_actor(
    role: Role, provenance: ExecutorProvenance
) -> tuple[AuditActor, dict[str, AuditMetadataValue]]:
    data: dict[str, AuditMetadataValue] = {
        "workflow_id": provenance.workflow_id,
        "run_id": provenance.run_id,
        "execution_id": provenance.execution_id,
        "trigger_type": provenance.trigger_type,
        "execution_origin": provenance.execution_origin,
        "root_action": provenance.root_action,
        "agent_session_id": (
            str(provenance.agent_session_id)
            if provenance.agent_session_id is not None
            else None
        ),
        "initiated_by_user_id": str(role.user_id) if role.user_id else None,
        "executor_service_id": role.service_id,
    }
    data = {key: value for key, value in data.items() if value is not None}
    if provenance.agent_session_id is not None:
        actor = AuditActor(AuditEventActor.AGENT, provenance.agent_session_id)
    else:
        actor = AuditActor(
            AuditEventActor.WORKFLOW, _workflow_actor_id(provenance.workflow_id)
        )
    return actor, data


def resolve_actor(
    role: Role,
) -> tuple[AuditActor, dict[str, AuditMetadataValue]] | None:
    """The actor of a RoboDR operation and the data that identifies it.

    Returns:
        The actor and its identifying event data, or ``None`` when the role
        names no auditable actor.
    """
    if role.type == "service" and (provenance := ctx_executor_provenance.get()):
        return _executor_actor(role, provenance)
    if role.type == "service_account" and role.service_account_id is not None:
        account: dict[str, AuditMetadataValue] = {
            "service_account_id": str(role.service_account_id)
        }
        if (api_key_id := ctx_service_account_api_key_id.get()) is not None:
            account["api_key_id"] = str(api_key_id)
        actor = AuditActor(AuditEventActor.SERVICE_ACCOUNT, role.service_account_id)
        return actor, account
    if role.type == "user" and role.user_id is not None:
        return AuditActor(AuditEventActor.USER, role.user_id), {}
    return None


async def write_robot_edr_audit(
    session: AsyncSession,
    role: Role,
    *,
    resource_type: AuditResourceType,
    action: AuditAction,
    status: AuditEventStatus,
    data: AuditMetadata,
    strict: bool,
) -> bool:
    """Write a RoboDR audit event attributed by :func:`resolve_actor`.

    The event is also logged (actor and data, never content). A strict
    write raises instead of returning ``False``.

    Args:
        session: The caller's database session (settings lookups only).
        role: The authenticated role.
        resource_type: The RoboDR resource.
        action: The operation.
        status: Attempt or outcome.
        data: Operation identifiers; actor identifiers are added.
        strict: Fail closed (privileged actions).

    Returns:
        Whether the event was written (or no sink is configured).

    Raises:
        AuditWriteError: ``strict`` and the event could not be written.
    """
    resolved = resolve_actor(role)
    if resolved is None:
        logger.warning(
            "RoboDR audit event has no auditable actor",
            resource_type=resource_type,
            action=action,
            role_type=role.type,
        )
        if strict:
            raise AuditWriteError(
                "Refusing the RoboDR operation: the caller is not an auditable "
                "actor, so it cannot be audit-logged"
            )
        return False
    actor, actor_data = resolved
    event_data = {**actor_data, **data}
    logger.info(
        "RoboDR audit event",
        resource_type=resource_type,
        action=action,
        status=status.value,
        actor_type=actor.actor_type.value,
        actor_id=str(actor.actor_id),
        **{k: v for k, v in event_data.items() if v is not None},
    )
    try:
        await AuditService(session, role=role).create_actor_event(
            actor=actor,
            resource_type=resource_type,
            action=action,
            status=status,
            data=event_data,
            strict=strict,
        )
    except AuditWriteError:
        raise
    except Exception as exc:
        if strict:
            raise AuditWriteError(
                "Refusing the RoboDR operation: its audit event could not be "
                f"written ({type(exc).__name__})"
            ) from exc
        logger.warning(
            "RoboDR audit event failed",
            resource_type=resource_type,
            error_type=type(exc).__name__,
        )
        return False
    return True
