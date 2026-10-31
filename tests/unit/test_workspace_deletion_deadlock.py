"""Regression tests for lock ordering between case writes and workspace deletion.

Every workspace owns a ``custom_fields_<ws>.case_fields`` table with an
``ON DELETE CASCADE`` foreign key to the shared ``"case"`` table. Deleting a
case anywhere fires that cascade into every workspace's table, so case writers
lock ``"case"`` and then each ``case_fields`` table. Dropping a workspace schema
must lock the tables in the same order, or it deadlocks with them.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.types import Role
from autosecops.cases.enums import CasePriority, CaseSeverity, CaseStatus
from autosecops.cases.schemas import CaseCreate
from autosecops.cases.service import CaseFieldsService, CasesService
from autosecops.db.engine import (
    get_async_session_bypass_rls_context_manager,
)
from autosecops.db.models import Organization, Ownership, Workspace
from autosecops.identifiers.workflow import WorkspaceUUID
from autosecops.workspaces.service import WorkspaceService

pytestmark = pytest.mark.usefixtures("db")

_LOCK_WAIT_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class LockWait:
    """A lock a backend is waiting for, and the relations it already holds."""

    waiting_relation: str
    waiting_mode: str
    held_relations: frozenset[str]


def _org_role(organization_id: uuid.UUID) -> Role:
    return Role(
        type="service",
        service_id="autosecops-service",
        organization_id=organization_id,
        scopes=frozenset({"*"}),
    )


def _workspace_role(organization_id: uuid.UUID, workspace_id: uuid.UUID) -> Role:
    return Role(
        type="service",
        service_id="autosecops-service",
        organization_id=organization_id,
        workspace_id=workspace_id,
        scopes=frozenset({"*"}),
    )


async def _bound_waits(session: AsyncSession) -> None:
    """Fail instead of hanging if a lock wait never resolves."""
    await session.execute(text("SET LOCAL lock_timeout = '30s'"))
    await session.execute(text("SET LOCAL statement_timeout = '60s'"))


async def _wait_for_lock_wait(pid: int, task: asyncio.Task[None]) -> LockWait:
    """Poll until ``pid`` is blocked on a relation lock and describe it."""
    deadline = asyncio.get_running_loop().time() + _LOCK_WAIT_SECONDS
    async with get_async_session_bypass_rls_context_manager() as observer:
        while True:
            rows = (
                await observer.execute(
                    text(
                        "SELECT l.relation::regclass::text, l.mode, l.granted"
                        " FROM pg_locks l"
                        " WHERE l.pid = :pid AND l.locktype = 'relation'"
                    ),
                    {"pid": pid},
                )
            ).tuples()
            waiting: tuple[str, str] | None = None
            held: set[str] = set()
            for relation, mode, granted in rows.all():
                if granted:
                    held.add(relation)
                else:
                    waiting = (relation, mode)
            await observer.rollback()
            if waiting is not None:
                return LockWait(
                    waiting_relation=waiting[0],
                    waiting_mode=waiting[1],
                    held_relations=frozenset(held),
                )
            if task.done():
                # Surface the task's own error instead of a polling timeout.
                await task
                raise AssertionError(f"Backend {pid} finished without waiting")
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError(f"Backend {pid} never waited on a lock")
            await asyncio.sleep(0.05)


@dataclass(frozen=True, slots=True)
class DeadlockFixture:
    """Committed organization with three workspaces and a case in the first."""

    organization_id: uuid.UUID
    case_workspace_id: uuid.UUID
    deleted_workspace_id: uuid.UUID
    case_id: uuid.UUID


@pytest.fixture
async def deadlock_fixture() -> AsyncGenerator[DeadlockFixture, None]:
    organization_id = uuid.uuid4()
    async with get_async_session_bypass_rls_context_manager() as session:
        session.add(
            Organization(
                id=organization_id,
                name=f"Deadlock org {organization_id.hex[:8]}",
                slug=f"deadlock-{organization_id.hex}",
                is_active=True,
            )
        )
        await session.commit()

    workspace_ids: list[uuid.UUID] = []
    for index in range(3):
        async with WorkspaceService.with_session(
            role=_org_role(organization_id)
        ) as svc:
            workspace = await svc.create_workspace(
                f"deadlock-{index}-{uuid.uuid4().hex[:8]}"
            )
            workspace_ids.append(workspace.id)

    case_workspace_id, deleted_workspace_id, _ = workspace_ids
    async with get_async_session_bypass_rls_context_manager() as session:
        case = await CasesService(
            session, role=_workspace_role(organization_id, case_workspace_id)
        ).create_case(
            CaseCreate(
                summary="Lock order",
                description="synthetic",
                status=CaseStatus.NEW,
                priority=CasePriority.LOW,
                severity=CaseSeverity.LOW,
            )
        )

    try:
        yield DeadlockFixture(
            organization_id=organization_id,
            case_workspace_id=case_workspace_id,
            deleted_workspace_id=deleted_workspace_id,
            case_id=case.id,
        )
    finally:
        async with get_async_session_bypass_rls_context_manager() as session:
            await _bound_waits(session)
            for workspace_id in workspace_ids:
                await CaseFieldsService(
                    session, role=_workspace_role(organization_id, workspace_id)
                ).drop_workspace_schema()
            await session.execute(
                delete(Workspace).where(Workspace.organization_id == organization_id)
            )
            await session.execute(
                delete(Ownership).where(Ownership.owner_id == organization_id)
            )
            await session.execute(
                delete(Organization).where(Organization.id == organization_id)
            )
            await session.commit()


@pytest.mark.anyio
async def test_workspace_deletion_does_not_deadlock_with_cascading_case_delete(
    deadlock_fixture: DeadlockFixture,
) -> None:
    """A workspace drop must wait on "case" before locking its own tables.

    The case writer holds ``"case"`` first. Deleting its workspace then
    cascades through ``"case"`` into every ``case_fields`` table, including the
    one the concurrent workspace deletion is about to drop. If the drop already
    holds that table while waiting for ``"case"``, PostgreSQL reports a
    deadlock.
    """
    fx = deadlock_fixture
    deleted_schema = (
        f"custom_fields_{WorkspaceUUID.new(fx.deleted_workspace_id).short()}"
    )
    async with get_async_session_bypass_rls_context_manager() as case_writer:
        await _bound_waits(case_writer)
        # Render the name the way pg_locks reports it (quoted when needed).
        deleted_case_fields = await case_writer.scalar(
            text(
                "SELECT format('%I.case_fields', CAST(:schema AS text))::regclass::text"
            ),
            {"schema": deleted_schema},
        )
        assert deleted_case_fields is not None
        # Hold "case" the way any transaction that has already written a case
        # does, then start the concurrent workspace deletion.
        await case_writer.execute(
            text('UPDATE "case" SET summary = summary WHERE id = :id'),
            {"id": fx.case_id},
        )

        deleter_pid: asyncio.Future[int] = asyncio.get_running_loop().create_future()

        async def delete_other_workspace() -> None:
            # with_session sets the request role, so enforce mode scopes RLS.
            async with WorkspaceService.with_session(
                role=_org_role(fx.organization_id)
            ) as svc:
                await _bound_waits(svc.session)
                pid = await svc.session.scalar(select(text("pg_backend_pid()")))
                assert isinstance(pid, int)
                deleter_pid.set_result(pid)
                await svc.delete_workspace(fx.deleted_workspace_id)

        deleter = asyncio.create_task(delete_other_workspace())
        try:
            lock_wait = await _wait_for_lock_wait(
                await asyncio.wait_for(deleter_pid, _LOCK_WAIT_SECONDS), deleter
            )

            # The deleter queues behind the case writer on "case" and has not
            # locked the table it is about to drop.
            assert lock_wait.waiting_relation == '"case"'
            assert deleted_case_fields not in lock_wait.held_relations

            # Cascades through "case" into every workspace's case_fields table.
            await case_writer.execute(
                delete(Workspace).where(Workspace.id == fx.case_workspace_id)
            )
            await case_writer.commit()
        finally:
            # Release "case" if an assertion failed before the commit.
            if case_writer.in_transaction():
                await case_writer.rollback()
            await asyncio.wait_for(deleter, timeout=_LOCK_WAIT_SECONDS)

    async with get_async_session_bypass_rls_context_manager() as session:
        remaining = (
            await session.scalars(
                select(Workspace.id).where(
                    Workspace.id.in_([fx.case_workspace_id, fx.deleted_workspace_id])
                )
            )
        ).all()
        schema_exists = await session.scalar(
            text("SELECT to_regnamespace(:name) IS NOT NULL"),
            {"name": deleted_schema},
        )
    assert remaining == []
    assert schema_exists is False
