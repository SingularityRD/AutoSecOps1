"""Robot and key registry (workspace-scoped management API)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from autosecops.audit.logger import audit_log
from autosecops.authz.controls import require_scope
from autosecops.db.models import Robot, RobotKey
from autosecops.exceptions import TracecatNotFoundError, TracecatValidationError
from autosecops.pagination import Page, PageParams, paginate
from autosecops.robot_edr.crypto import derive_key_id, is_strict_public_key
from autosecops.robot_edr.schemas import (
    RobotCreate,
    RobotKeyCreate,
    RobotKeyRead,
    RobotUpdate,
)
from autosecops.robot_edr.types import SENDER_KEY_ROLES, RobotKeyRole
from autosecops.service import BaseWorkspaceService
from autosecops.tiers.enums import Entitlement


class RobotConflictError(Exception):
    """A robot or key with the same identity is already registered."""


def _key_row(row: tuple[object, ...]) -> RobotKeyRead:
    key, robodr_robot_id = row
    if not isinstance(key, RobotKey) or not (
        robodr_robot_id is None or isinstance(robodr_robot_id, str)
    ):
        raise TypeError("unexpected robot key row")
    return RobotsService.to_read(key, robodr_robot_id)


class RobotsService(BaseWorkspaceService):
    """Manage the robots and Ed25519 keys of a workspace."""

    service_name = "robot_edr"

    # --- robots ---------------------------------------------------------------

    @require_scope("robot:read")
    async def list_robots(self, page: PageParams) -> Page[Robot]:
        """List robots in stable creation order."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        stmt = select(Robot).where(Robot.workspace_id == self.workspace_id)
        return await paginate(
            self.session,
            stmt,
            page=page,
            order_by=(Robot.created_at.asc(), Robot.id.asc()),
        )

    @require_scope("robot:read")
    async def get_robot(self, robot_id: uuid.UUID) -> Robot:
        """Return one robot by its UUID."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self.session.scalar(
            select(Robot).where(
                Robot.workspace_id == self.workspace_id, Robot.id == robot_id
            )
        )
        if robot is None:
            raise TracecatNotFoundError("Robot not found")
        return robot

    async def _robot_by_robodr_id(self, robodr_id: str) -> Robot:
        robot = await self.session.scalar(
            select(Robot).where(
                Robot.workspace_id == self.workspace_id, Robot.robot_id == robodr_id
            )
        )
        if robot is None:
            raise TracecatNotFoundError("Robot not found")
        return robot

    @require_scope("robot:update")
    @audit_log(resource_type="robot", action="create")
    async def create_robot(self, params: RobotCreate) -> Robot:
        """Register a robot.

        Raises:
            RobotConflictError: The robot id is already registered here.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = Robot(workspace_id=self.workspace_id, **params.model_dump())
        self.session.add(robot)
        await self._commit_or_conflict("A robot with this id is already registered")
        await self.session.refresh(robot)
        return robot

    @require_scope("robot:update")
    @audit_log(resource_type="robot", action="update")
    async def update_robot(self, robot: Robot, params: RobotUpdate) -> Robot:
        """Update a robot's descriptive fields or signature policy."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        for key, value in params.model_dump(exclude_unset=True).items():
            if key == "require_finding_signature" and value is None:
                continue
            setattr(robot, key, value)
        await self.session.commit()
        await self.session.refresh(robot)
        return robot

    @require_scope("robot:update")
    @audit_log(resource_type="robot", action="delete")
    async def delete_robot(self, robot: Robot) -> None:
        """Delete a robot and its keys; its findings and cases are kept."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        await self.session.delete(robot)
        await self.session.commit()

    # --- keys -----------------------------------------------------------------

    @require_scope("robot:read")
    async def list_keys(
        self, page: PageParams, *, robot: Robot | None = None
    ) -> Page[RobotKeyRead]:
        """List keys, optionally only those of one robot."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        stmt = (
            select(RobotKey, Robot.robot_id)
            .outerjoin(Robot, Robot.id == RobotKey.robot_fk)
            .where(RobotKey.workspace_id == self.workspace_id)
        )
        if robot is not None:
            stmt = stmt.where(RobotKey.robot_fk == robot.id)
        return await paginate(
            self.session,
            stmt,
            page=page,
            order_by=(RobotKey.created_at.asc(), RobotKey.id.asc()),
            row_factory=_key_row,
        )

    @require_scope("robot:read")
    async def get_key(self, key_id: uuid.UUID) -> tuple[RobotKey, str | None]:
        """Return a key and its robot's RoboDR id."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        row = (
            await self.session.execute(
                select(RobotKey, Robot.robot_id)
                .outerjoin(Robot, Robot.id == RobotKey.robot_fk)
                .where(
                    RobotKey.workspace_id == self.workspace_id, RobotKey.id == key_id
                )
            )
        ).first()
        if row is None:
            raise TracecatNotFoundError("Robot key not found")
        return row[0], row[1]

    @require_scope("robot:update")
    @audit_log(resource_type="robot_key", action="create")
    async def create_key(self, params: RobotKeyCreate) -> RobotKey:
        """Register a public key.

        Raises:
            TracecatValidationError: The key is not a canonical, large-order
                Ed25519 key, or the role/robot/key id combination is invalid.
            TracecatNotFoundError: The named robot is not registered.
            RobotConflictError: The key id is already registered in this
                workspace, or is an active sender key anywhere.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        public_key = bytes.fromhex(params.public_key)
        if not is_strict_public_key(public_key):
            raise TracecatValidationError(
                "public_key is not a canonical, large-order Ed25519 public key"
            )
        derived = derive_key_id(public_key)
        if params.role in SENDER_KEY_ROLES or params.role is RobotKeyRole.BLACKBOX:
            if params.key_id is not None and params.key_id != derived:
                raise TracecatValidationError(
                    f"A {params.role} key's id is derived from its public key: {derived}"
                )
            key_id = derived
        else:
            key_id = params.key_id or derived

        robot_fk: uuid.UUID | None = None
        if params.role is RobotKeyRole.RELAY:
            if params.robot_id is not None:
                raise TracecatValidationError("A relay key is not bound to a robot")
        else:
            if params.site is not None or params.vouches_origin:
                raise TracecatValidationError(
                    "site and vouches_origin apply to relay keys only"
                )
            if params.robot_id is None:
                raise TracecatValidationError(f"A {params.role} key needs a robot_id")
            robot_fk = (await self._robot_by_robodr_id(params.robot_id)).id

        key = RobotKey(
            workspace_id=self.workspace_id,
            key_id=key_id,
            role=params.role.value,
            robot_fk=robot_fk,
            public_key=public_key,
            site=params.site,
            vouches_origin=params.vouches_origin,
            expires_at=params.expires_at,
            created_by=self.role.user_id,
        )
        self.session.add(key)
        await self._commit_or_conflict("This key is already registered")
        await self.session.refresh(key)
        return key

    @require_scope("robot:update")
    @audit_log(resource_type="robot_key", action="revoke")
    async def revoke_key(self, key: RobotKey) -> RobotKey:
        """Revoke a key; it authenticates nothing from now on. Idempotent."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        if key.revoked_at is None:
            key.revoked_at = datetime.now(UTC)
            await self.session.commit()
            await self.session.refresh(key)
        return key

    @require_scope("robot:update")
    @audit_log(resource_type="robot_key", action="delete")
    async def delete_key(self, key: RobotKey) -> None:
        """Delete a key and the replay records of the batches it signed."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        await self.session.delete(key)
        await self.session.commit()

    @staticmethod
    def to_read(key: RobotKey, robodr_robot_id: str | None) -> RobotKeyRead:
        """Serialize a key with its robot's RoboDR id."""
        return RobotKeyRead(
            id=key.id,
            key_id=key.key_id,
            role=RobotKeyRole(key.role),
            robot_id=robodr_robot_id,
            public_key=key.public_key.hex(),
            site=key.site,
            vouches_origin=key.vouches_origin,
            revoked_at=key.revoked_at,
            expires_at=key.expires_at,
            created_by=key.created_by,
            created_at=key.created_at,
            updated_at=key.updated_at,
        )

    async def _commit_or_conflict(self, message: str) -> None:
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise RobotConflictError(message) from exc
