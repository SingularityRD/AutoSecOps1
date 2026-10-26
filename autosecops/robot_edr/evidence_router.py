"""Action-gateway routes for RoboDR evidence (`tools.robodr` evidence actions)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from autosecops.auth.dependencies import ExecutorWorkspaceRole
from autosecops.authz.controls import require_scope
from autosecops.cases.dependencies import ExecutorCaseIDPath
from autosecops.db.dependencies import AsyncDBSession
from autosecops.exceptions import TracecatNotFoundError, TracecatValidationError
from autosecops.robot_edr.evidence import RobotEvidenceService
from autosecops.robot_edr.schemas import (
    EvidenceAccessRequest,
    EvidenceStoreRequest,
    EvidenceStoreResponse,
)
from autosecops.storage.exceptions import FileValidationError

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
