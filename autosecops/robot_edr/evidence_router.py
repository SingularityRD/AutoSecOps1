"""Action-gateway routes for RoboDR evidence (`tools.robodr` evidence actions).

Authorization: these routes admit only a verified executor token
(`ExecutorWorkspaceRole`), i.e. the run of a workflow or agent action.
Reading a robot's evidence needs `robot:read`, which the internal service
principals' operational scopes deliberately lack: adding it there would grant
robot reads to every internal service on every route. These routes grant it
to the executor themselves (`_require_executor_robot_read`), never beyond the
person the run acts for.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Path, Query, status

from autosecops.auth.credentials import compute_attributed_user_scopes
from autosecops.auth.dependencies import ExecutorWorkspaceRole
from autosecops.auth.types import Role
from autosecops.authz.controls import has_scope, require_scope
from autosecops.cases.dependencies import ExecutorCaseIDPath
from autosecops.db.dependencies import AsyncDBSession
from autosecops.exceptions import (
    ScopeDeniedError,
    TracecatNotFoundError,
    TracecatValidationError,
)
from autosecops.robot_edr.evidence import RobotEvidenceService
from autosecops.robot_edr.schemas import (
    ROBOT_ID_PATTERN,
    EvidenceAccessRequest,
    EvidenceStoreRequest,
    EvidenceStoreResponse,
)
from autosecops.storage.exceptions import FileValidationError

_MAX_MS = 253_402_300_799_999
"""9999-12-31T23:59:59.999Z, the last instant a datetime holds."""

ROBOT_READ = "robot:read"


async def _require_executor_robot_read(role: Role) -> None:
    """Grant `robot:read` on these routes to the run's executor only.

    `role` comes from `ExecutorWorkspaceRole`: a verified executor token for
    this workspace, whose service principal scopes hold no `robot:read`.
    When the token attributes a user (a run a person started), that user's
    own scopes must hold `robot:read`; an unattributed run (schedule,
    webhook, subflow) acts for the workspace.

    Raises:
        ScopeDeniedError: The role is not an executor of a workspace, or the
            user the run acts for may not read robots.
    """
    if role.type != "service" or role.workspace_id is None:
        raise ScopeDeniedError(
            required_scopes=[ROBOT_READ], missing_scopes=[ROBOT_READ]
        )
    user_scopes = await compute_attributed_user_scopes(role)
    if user_scopes is not None and not has_scope(user_scopes, ROBOT_READ):
        raise ScopeDeniedError(
            required_scopes=[ROBOT_READ],
            missing_scopes=[ROBOT_READ],
            message="The user this run acts for may not read robots.",
        )


router = APIRouter(
    tags=["internal-robot-edr"],
    prefix="/internal/robot-edr",
    include_in_schema=False,
)


@router.post("/cases/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
@require_scope("case:update")
async def store_evidence(
    *,
    role: ExecutorWorkspaceRole,
    session: AsyncDBSession,
    case_id: ExecutorCaseIDPath,
    params: EvidenceStoreRequest,
) -> EvidenceStoreResponse:
    """Store a verified evidence export and attach its report to the case."""
    await _require_executor_robot_read(role)
    service = RobotEvidenceService(session, role=role)
    try:
        return await service.store_verified_export(case_id, params)
    except TracecatNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (TracecatValidationError, FileValidationError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/evidence/access", status_code=status.HTTP_204_NO_CONTENT)
async def record_evidence_access(
    *,
    role: ExecutorWorkspaceRole,
    session: AsyncDBSession,
    params: EvidenceAccessRequest,
) -> None:
    """Audit-log a workflow's read of a robot's evidence."""
    await _require_executor_robot_read(role)
    await RobotEvidenceService(session, role=role).record_access(params)


@router.get("/robots/{robot_id}/blackbox-keys")
async def list_blackbox_keys(
    *,
    role: ExecutorWorkspaceRole,
    session: AsyncDBSession,
    robot_id: str = Path(..., pattern=ROBOT_ID_PATTERN),
    from_ms: int | None = Query(default=None, ge=0, le=_MAX_MS),
    to_ms: int | None = Query(default=None, ge=0, le=_MAX_MS),
) -> list[str]:
    """The robot's enrolled black-box public key files valid in the time range.

    Newest first, the current key always included; more keys than a keyring
    holds is a `409`, never a silent cut.
    """
    await _require_executor_robot_read(role)
    try:
        return await RobotEvidenceService(session, role=role).blackbox_key_files(
            robot_id, from_ms=from_ms, to_ms=to_ms
        )
    except TracecatNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except TracecatValidationError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
