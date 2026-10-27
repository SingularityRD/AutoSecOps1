"""HTTP routes for agent tag definition CRUD."""

from fastapi import APIRouter, HTTPException, Query, status

from autosecops import config
from autosecops.agent.tags.schemas import AgentTagRead
from autosecops.agent.tags.service import AgentTagsService
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.authz.controls import require_scope
from autosecops.db.dependencies import AsyncDBSession
from autosecops.exceptions import (
    AutoSecOpsConflictError,
    AutoSecOpsNotFoundError,
    AutoSecOpsValidationError,
)
from autosecops.identifiers import AgentTagID
from autosecops.pagination import CursorPaginatedResponse, CursorPaginationParams
from autosecops.tags.schemas import TagCreate, TagUpdate

router = APIRouter(prefix="/agent-tags", tags=["agent-tags"])


@router.get("", response_model=CursorPaginatedResponse[AgentTagRead])
@require_scope("agent:read")
async def list_agent_tags(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    limit: int = Query(
        default=config.AUTOSECOPS__LIMIT_DEFAULT,
        ge=config.AUTOSECOPS__LIMIT_MIN,
        le=config.AUTOSECOPS__LIMIT_CURSOR_MAX,
    ),
    cursor: str | None = Query(default=None),
    reverse: bool = Query(default=False),
) -> CursorPaginatedResponse[AgentTagRead]:
    """List all agent tags in the workspace."""
    service = AgentTagsService(session=session, role=role)
    try:
        page = await service.list_tags_paginated(
            CursorPaginationParams(limit=limit, cursor=cursor, reverse=reverse)
        )
    except AutoSecOpsValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err
    return CursorPaginatedResponse(
        items=[
            AgentTagRead.model_validate(tag, from_attributes=True) for tag in page.items
        ],
        next_cursor=page.next_cursor,
        prev_cursor=page.prev_cursor,
        has_more=page.has_more,
        has_previous=page.has_previous,
        total_estimate=page.total_estimate,
    )


@router.get("/{tag_id}", response_model=AgentTagRead)
@require_scope("agent:read")
async def get_agent_tag(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    tag_id: AgentTagID,
) -> AgentTagRead:
    """Get an agent tag by ID."""
    service = AgentTagsService(session=session, role=role)
    try:
        tag = await service.get_tag(tag_id)
    except AutoSecOpsNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    return AgentTagRead.model_validate(tag, from_attributes=True)


@router.post("", response_model=AgentTagRead, status_code=status.HTTP_201_CREATED)
@require_scope("agent:create")
async def create_agent_tag(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: TagCreate,
) -> AgentTagRead:
    """Create a new agent tag definition."""
    service = AgentTagsService(session=session, role=role)
    try:
        tag = await service.create_tag(params)
    except AutoSecOpsConflictError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(err),
        ) from err
    return AgentTagRead.model_validate(tag, from_attributes=True)


@router.patch("/{tag_id}", response_model=AgentTagRead)
@require_scope("agent:update")
async def update_agent_tag(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    tag_id: AgentTagID,
    params: TagUpdate,
) -> AgentTagRead:
    """Update an agent tag definition."""
    service = AgentTagsService(session=session, role=role)
    try:
        tag = await service.get_tag(tag_id)
    except AutoSecOpsNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    try:
        updated = await service.update_tag(tag, params)
    except AutoSecOpsConflictError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(err),
        ) from err
    return AgentTagRead.model_validate(updated, from_attributes=True)


@router.delete("/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_scope("agent:delete")
async def delete_agent_tag(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    tag_id: AgentTagID,
) -> None:
    """Delete an agent tag definition."""
    service = AgentTagsService(session=session, role=role)
    try:
        await service.delete_tag_by_id(tag_id)
    except AutoSecOpsNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
