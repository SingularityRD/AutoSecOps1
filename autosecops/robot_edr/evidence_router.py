"""Action-gateway routes for RoboDR evidence (`tools.robodr` evidence actions)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Path, Query, status

from autosecops.auth.dependencies import ExecutorWorkspaceRole
from autosecops.authz.controls import require_scope
from autosecops.cases.dependencies import ExecutorCaseIDPath
from autosecops.db.dependencies import AsyncDBSession
from autosecops.exceptions import TracecatNotFoundError, TracecatValidationError
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

router = APIRouter(
    tags=["internal-robot-edr"],
    prefix="/internal/robot-edr",
    include_in_schema=False,
)


@router.post("/cases/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
@require_scope("case:update", "robot:read")
async def store_evidence(
    *,
    role: ExecutorWorkspaceRole,
    session: AsyncDBSession,
    case_id: ExecutorCaseIDPath,
    params: EvidenceStoreRequest,
) -> EvidenceStoreResponse:
    """Store a verified evidence export and attach its report to the case."""
    service = RobotEvidenceService(session, role=role)
    try:
        return await service.store_verified_export(case_id, params)
    except TracecatNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (TracecatValidationError, FileValidationError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/evidence/access", status_code=status.HTTP_204_NO_CONTENT)
@require_scope("robot:read")
async def record_evidence_access(
    *,
    role: ExecutorWorkspaceRole,
    session: AsyncDBSession,
    params: EvidenceAccessRequest,
) -> None:
    """Audit-log a workflow's read of a robot's evidence."""
    await RobotEvidenceService(session, role=role).record_access(params)


@router.get("/robots/{robot_id}/blackbox-keys")
@require_scope("robot:read")
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
    try:
        return await RobotEvidenceService(session, role=role).blackbox_key_files(
            robot_id, from_ms=from_ms, to_ms=to_ms
        )
    except TracecatNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except TracecatValidationError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
