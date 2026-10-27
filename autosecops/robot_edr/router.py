"""Workspace API for registering robots and their Ed25519 keys."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from autosecops import config
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.authz.controls import require_scope
from autosecops.db.dependencies import AsyncDBSession
from autosecops.exceptions import AutoSecOpsValidationError
from autosecops.pagination import Page, PageParams, PaginationError
from autosecops.robot_edr.schemas import (
    RobotCreate,
    RobotKeyCreate,
    RobotKeyRead,
    RobotRead,
    RobotUpdate,
)
from autosecops.robot_edr.service import RobotConflictError, RobotsService
from autosecops.tiers.entitlements import check_entitlement
from autosecops.tiers.enums import Entitlement


async def _require_entitlement(
    role: WorkspaceActorRouteRole, session: AsyncDBSession
) -> None:
    await check_entitlement(session, role, Entitlement.ROBOT_EDR)


router = APIRouter(
    prefix="/robot-edr",
    tags=["robot-edr"],
    dependencies=[Depends(_require_entitlement)],
)

_LIMIT = Query(
    config.AUTOSECOPS__LIMIT_DEFAULT,
    ge=config.AUTOSECOPS__LIMIT_MIN,
    le=config.AUTOSECOPS__LIMIT_CURSOR_MAX,
)
_CURSOR = Query(None, max_length=8192)


def _conflict(exc: RobotConflictError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


def _page_params(limit: int, cursor: str | None) -> PageParams:
    return PageParams(limit=limit, cursor=cursor)


@router.get("/robots")
@require_scope("robot:read")
async def list_robots(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    limit: int = _LIMIT,
    cursor: str | None = _CURSOR,
) -> Page[RobotRead]:
    """List the robots registered in the workspace."""
    service = RobotsService(session, role=role)
    try:
        robots = await service.list_robots(_page_params(limit, cursor))
    except PaginationError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    return Page(
        items=[RobotRead.model_validate(robot) for robot in robots.items],
        next_cursor=robots.next_cursor,
        prev_cursor=robots.prev_cursor,
    )


@router.post("/robots", status_code=status.HTTP_201_CREATED)
@require_scope("robot:update")
async def create_robot(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: RobotCreate,
) -> RobotRead:
    """Register a robot."""
    service = RobotsService(session, role=role)
    try:
        robot = await service.create_robot(params)
    except RobotConflictError as exc:
        raise _conflict(exc) from exc
    return RobotRead.model_validate(robot)


@router.get("/robots/{robot_id}")
@require_scope("robot:read")
async def get_robot(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
) -> RobotRead:
    """Get a robot."""
    service = RobotsService(session, role=role)
    return RobotRead.model_validate(await service.get_robot(robot_id))


@router.patch("/robots/{robot_id}")
@require_scope("robot:update")
async def update_robot(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    params: RobotUpdate,
) -> RobotRead:
    """Update a robot."""
    service = RobotsService(session, role=role)
    robot = await service.get_robot(robot_id)
    return RobotRead.model_validate(await service.update_robot(robot, params))


@router.delete("/robots/{robot_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_scope("robot:update")
async def delete_robot(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
) -> None:
    """Delete a robot and its keys. Findings and cases are kept."""
    service = RobotsService(session, role=role)
    await service.delete_robot(await service.get_robot(robot_id))


@router.get("/keys")
@require_scope("robot:read")
async def list_robot_keys(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID | None = Query(None, description="Only this robot's keys"),
    limit: int = _LIMIT,
    cursor: str | None = _CURSOR,
) -> Page[RobotKeyRead]:
    """List registered keys."""
    service = RobotsService(session, role=role)
    robot = await service.get_robot(robot_id) if robot_id is not None else None
    try:
        return await service.list_keys(_page_params(limit, cursor), robot=robot)
    except PaginationError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc


@router.post("/keys", status_code=status.HTTP_201_CREATED)
@require_scope("robot:update")
async def create_robot_key(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: RobotKeyCreate,
) -> RobotKeyRead:
    """Register an Ed25519 public key for a robot (uplink, finding) or the workspace (relay)."""
    service = RobotsService(session, role=role)
    try:
        key = await service.create_key(params)
    except RobotConflictError as exc:
        raise _conflict(exc) from exc
    except AutoSecOpsValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return RobotsService.to_read(key, params.robot_id)


@router.get("/keys/{key_id}")
@require_scope("robot:read")
async def get_robot_key(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    key_id: uuid.UUID,
) -> RobotKeyRead:
    """Get a key."""
    service = RobotsService(session, role=role)
    key, robodr_robot_id = await service.get_key(key_id)
    return RobotsService.to_read(key, robodr_robot_id)


@router.post("/keys/{key_id}/revoke")
@require_scope("robot:update")
async def revoke_robot_key(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    key_id: uuid.UUID,
) -> RobotKeyRead:
    """Revoke a key; it authenticates nothing from now on."""
    service = RobotsService(session, role=role)
    key, robodr_robot_id = await service.get_key(key_id)
    return RobotsService.to_read(await service.revoke_key(key), robodr_robot_id)


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_scope("robot:update")
async def delete_robot_key(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    key_id: uuid.UUID,
) -> None:
    """Delete a key."""
    service = RobotsService(session, role=role)
    key, _ = await service.get_key(key_id)
    await service.delete_key(key)
