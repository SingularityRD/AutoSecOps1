from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.authz.controls import require_scope
from autosecops.db.dependencies import AsyncDBSession
from autosecops.db.models import Schedule
from autosecops.exceptions import (
    AutoSecOpsConflictError,
    AutoSecOpsNotFoundError,
    AutoSecOpsServiceError,
)
from autosecops.identifiers.workflow import OptionalAnyWorkflowIDQuery
from autosecops.logger import logger
from autosecops.workflow.schedules.dependencies import AnyScheduleIDPath
from autosecops.workflow.schedules.schemas import (
    ScheduleCreate,
    ScheduleRead,
    ScheduleSearch,
    ScheduleUpdate,
)
from autosecops.workflow.schedules.service import WorkflowSchedulesService

router = APIRouter(prefix="/schedules", tags=["schedules"])


@router.get("", response_model=list[ScheduleRead])
@require_scope("schedule:read")
async def list_schedules(
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    workflow_id: OptionalAnyWorkflowIDQuery,
) -> list[ScheduleRead]:
    service = WorkflowSchedulesService(session, role=role)
    schedules = await service.list_schedules(workflow_id=workflow_id)
    return ScheduleRead.list_adapter().validate_python(schedules)


@router.post("", response_model=ScheduleRead)
@require_scope("schedule:create")
async def create_schedule(
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: ScheduleCreate,
) -> ScheduleRead:
    """Create a schedule for a workflow."""
    service = WorkflowSchedulesService(session, role=role)
    try:
        schedule = await service.create_schedule(params)
        return ScheduleRead.model_validate(schedule)
    except AutoSecOpsNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except AutoSecOpsConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        ) from e
    except AutoSecOpsServiceError as e:
        logger.error("Error creating schedule", error=e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating schedule: {e}. Please try again or contact support.",
        ) from e


@router.get("/{schedule_id}", response_model=ScheduleRead)
@require_scope("schedule:read")
async def get_schedule(
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    schedule_id: AnyScheduleIDPath,
) -> ScheduleRead:
    """Get a schedule from a workflow."""
    service = WorkflowSchedulesService(session, role=role)
    try:
        schedule = await service.get_schedule(schedule_id)
        return ScheduleRead.model_validate(schedule)
    except AutoSecOpsNotFoundError as e:
        logger.error("Error getting schedule", error=e)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found. Please check whether this schedule exists and try again.",
        ) from e


@router.post("/{schedule_id}", response_model=ScheduleRead)
@require_scope("schedule:update")
async def update_schedule(
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    schedule_id: AnyScheduleIDPath,
    params: ScheduleUpdate,
) -> ScheduleRead:
    """Update a schedule from a workflow. You cannot update the Workflow Definition, but you can update other fields."""
    service = WorkflowSchedulesService(session, role=role)
    try:
        schedule = await service.update_schedule(schedule_id, params)
        return ScheduleRead.model_validate(schedule)
    except AutoSecOpsNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found. Please check whether this schedule exists and try again.",
        ) from e
    except AutoSecOpsServiceError as e:
        logger.error("Error updating schedule", error=e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update schedule: {e}. Please try again or contact support.",
        ) from e


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_scope("schedule:delete")
async def delete_schedule(
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    schedule_id: AnyScheduleIDPath,
) -> None:
    """Delete a schedule from a workflow."""
    service = WorkflowSchedulesService(session, role=role)
    try:
        await service.delete_schedule(schedule_id)
    except AutoSecOpsNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found. Please check whether this schedule exists and try again.",
        ) from e
    except AutoSecOpsServiceError as e:
        logger.error("Error deleting schedule", error=e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete schedule: {e}. Please try again or contact support.",
        ) from e


@router.get("/search", response_model=list[ScheduleRead])
@require_scope("schedule:read")
async def search_schedules(
    role: WorkspaceActorRouteRole, session: AsyncDBSession, params: ScheduleSearch
) -> list[ScheduleRead]:
    """**[WORK IN PROGRESS]** Search for schedules."""
    statement = select(Schedule).where(Schedule.workspace_id == role.workspace_id)
    results = await session.execute(statement)
    schedules = results.scalars().all()
    return ScheduleRead.list_adapter().validate_python(schedules)
