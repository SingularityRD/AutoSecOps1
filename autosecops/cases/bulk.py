"""Set-based case creation for high-volume producers (RoboDR ingest).

:meth:`BulkCasesService.create_cases` writes what
:meth:`CasesService.create_case` writes for each case, with a constant number
of statements per call instead of a dozen round trips (and an ORM refresh)
per case. Side effects of ``create_case`` and how the bulk path matches them:

* ``case:create`` scope check: the same ``require_scope`` decorator.
* Workspace custom-fields schema: ``_ensure_schema_ready`` once per call.
* ``case`` row: one multi-row ``INSERT`` with the same columns, a per-case
  ``created_at`` from the Python clock and ``updated_at`` at the transaction
  time (where ``create_case``'s case-number flush leaves it). The ``case``
  insert triggers, search indexes (expression GIN indexes on the case table)
  and RLS policies apply to set-based inserts exactly as to single-row ones.
* Initial ``case_version`` rows (summary and description, version 1, the
  actor if it is a persisted user): one multi-row ``INSERT``.
* Custom-fields row: always created; values normalised as
  ``upsert_field_values`` does (``normalize_field_values``) and written with
  ``updated_at = statement_timestamp()`` when there are values, as
  ``TableEditorService.update_row`` does; columns without a value keep their
  database defaults.
* ``case_created`` event (with the workflow execution id from ``ctx_run``),
  its after-commit case-trigger publish (Redis streams) and duration sync:
  ``CaseEventsService.create_events``, which shares ``create_event``'s
  after-commit code.
* Agent-session interaction (``CREATE``) when the request carries one.
* Case number: one block of gapless numbers from the workspace counter (one
  ``UPDATE ... RETURNING``), assigned in creation order and inserted with the
  cases. ``create_case`` inserts a sentinel and sets the number last; setting
  it after the insert would re-index every new case in the search indexes
  (``case_number`` is indexed, so the update is not HOT). The counter row
  stays locked from the insert to the end of the transaction, as it does
  from the first ``create_case`` of a transaction.
* Audit log: for a role with an auditable actor, an ``attempt`` and a
  ``success`` event per case, as ``audit_log`` records for ``create_case``;
  actor-less service roles (such as ingest) are not audited, as there.

Not supported in bulk (``ValueError``): sub-cases (``parent_id``) and
dropdown values; create those with ``create_case``. The caller owns the
transaction: nothing is committed or rolled back here.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.service import AuditService
from autosecops.auth.types import Role
from autosecops.authz.controls import require_scope
from autosecops.cases.agent_sessions.service import (
    CaseAgentSessionInteractionService,
)
from autosecops.cases.enums import (
    CaseAgentSessionInteractionOperation,
    CaseVersionField,
)
from autosecops.cases.event_schemas import CreatedEvent
from autosecops.cases.events import CaseEventItem, CaseEventsService
from autosecops.cases.schemas import CaseCreate
from autosecops.cases.service import CaseFieldsService
from autosecops.cases.types import CreatedCase
from autosecops.cases.versions.service import CaseVersionsService
from autosecops.contexts import ctx_run
from autosecops.db.models import Base, Case, CaseVersion, Workspace
from autosecops.exceptions import TracecatNotFoundError
from autosecops.service import BaseWorkspaceService
from autosecops.tables.common import coerce_to_date, coerce_to_utc_datetime


class BulkCasesService(BaseWorkspaceService):
    """Create many cases in the caller's transaction (see the module notes)."""

    service_name = "cases_bulk"

    def __init__(self, session: AsyncSession, role: Role | None = None):
        super().__init__(session, role)
        self.fields = CaseFieldsService(session=self.session, role=self.role)
        self.events = CaseEventsService(session=self.session, role=self.role)
        self.versions = CaseVersionsService(session=self.session, role=self.role)
        self.agent_session_interactions = CaseAgentSessionInteractionService(
            session=self.session, role=self.role
        )

    @require_scope("case:create")
    async def create_cases(self, params: Sequence[CaseCreate]) -> list[CreatedCase]:
        """Create cases with their numbers, fields, versions and created events.

        Args:
            params: The cases to create, in creation (and numbering) order.

        Returns:
            The new cases, in ``params`` order.

        Raises:
            ValueError: A case names a parent or dropdown values, or a custom
                field that is reserved, does not exist, or has an invalid
                value.
        """
        if not params:
            return []
        for case_params in params:
            if case_params.parent_id is not None:
                raise ValueError("Bulk case creation does not create sub-cases")
            if case_params.dropdown_values is not None:
                raise ValueError("Bulk case creation does not set dropdown values")
            for field_name in case_params.fields or {}:
                self.fields._assert_user_field_name_allowed(field_name)
        await self._audit(AuditEventStatus.ATTEMPT, [None] * len(params))

        # As in create_case: initialise the workspace fields schema before any
        # case-table lock is taken.
        await self.fields._ensure_schema_ready()
        field_values = await self.fields.normalize_field_values_many(
            [case_params.fields or {} for case_params in params]
        )
        case_ids = [uuid.uuid4() for _ in params]
        numbers = await self._allocate_case_numbers(len(params))
        await self._insert_cases(case_ids, numbers, params)
        await self._insert_versions(case_ids, params)
        await self._insert_field_rows(case_ids, field_values)

        run_ctx = ctx_run.get()
        wf_exec_id = run_ctx.wf_exec_id if run_ctx else None
        await self.events.create_events(
            [
                CaseEventItem(
                    case_id=case_id, event=CreatedEvent(wf_exec_id=wf_exec_id)
                )
                for case_id in case_ids
            ]
        )
        for case_id in case_ids:
            await self.agent_session_interactions.record_from_context(
                case_id=case_id,
                operation=CaseAgentSessionInteractionOperation.CREATE,
            )
        await self._audit(AuditEventStatus.SUCCESS, case_ids)
        return [
            CreatedCase(id=case_id, case_number=number)
            for case_id, number in zip(case_ids, numbers, strict=True)
        ]

    async def _allocate_case_numbers(self, count: int) -> list[int]:
        """Take the next ``count`` gapless numbers from the workspace counter."""
        last = await self.session.scalar(
            sa.update(Workspace)
            .where(Workspace.id == self.workspace_id)
            .values(last_case_number=Workspace.last_case_number + count)
            .returning(Workspace.last_case_number)
        )
        if last is None:
            raise TracecatNotFoundError("Workspace not found")
        return list(range(last - count + 1, last + 1))

    async def _insert_cases(
        self,
        case_ids: Sequence[uuid.UUID],
        numbers: Sequence[int],
        params: Sequence[CaseCreate],
    ) -> None:
        rows: list[dict[str, Any]] = []
        for case_id, number, case_params in zip(case_ids, numbers, params, strict=True):
            rows.append(
                {
                    "id": case_id,
                    "workspace_id": self.workspace_id,
                    "case_number": number,
                    "summary": case_params.summary,
                    "description": case_params.description,
                    "priority": case_params.priority,
                    "severity": case_params.severity,
                    "status": case_params.status,
                    "assignee_id": case_params.assignee_id,
                    "payload": case_params.payload,
                    "parent_id": None,
                    "created_at": datetime.now(UTC),
                }
            )
        await self.session.execute(
            sa.insert(_table_of(Case)).values(updated_at=sa.func.now()), rows
        )

    async def _insert_versions(
        self, case_ids: Sequence[uuid.UUID], params: Sequence[CaseCreate]
    ) -> None:
        user_id = await self.versions._resolve_user_id()
        rows: list[dict[str, Any]] = []
        for case_id, case_params in zip(case_ids, params, strict=True):
            for field, content in (
                (CaseVersionField.SUMMARY, case_params.summary),
                (CaseVersionField.DESCRIPTION, case_params.description),
            ):
                rows.append(
                    {
                        "id": uuid.uuid4(),
                        "workspace_id": self.workspace_id,
                        "case_id": case_id,
                        "field": field,
                        "version": 1,
                        "content": content,
                        "user_id": user_id,
                    }
                )
        await self.session.execute(sa.insert(_table_of(CaseVersion)), rows)

    async def _insert_field_rows(
        self, case_ids: Sequence[uuid.UUID], field_values: Sequence[dict[str, Any]]
    ) -> None:
        """Insert each case's custom-fields row, grouped by the columns set."""
        columns: dict[str, Any] = {}
        if any(field_values):
            columns = {
                column["name"]: column["type"]
                for column in await self.fields.editor.get_columns()
            }
        groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for case_id, values in zip(case_ids, field_values, strict=True):
            row: dict[str, Any] = {"id": uuid.uuid4(), "case_id": case_id}
            for name, value in values.items():
                if name not in columns:
                    raise ValueError(
                        f"Column '{name}' does not exist in table "
                        f"{self.fields.sanitized_table_name}"
                    )
                row[name] = _coerce(columns[name], value)
            groups.setdefault(tuple(values), []).append(row)
        for names, rows in groups.items():
            table = sa.table(
                self.fields.sanitized_table_name,
                sa.column("id"),
                sa.column("case_id"),
                sa.column("updated_at"),
                *(sa.column(name, columns[name]) for name in names),
                schema=self.fields.schema_name,
            )
            statement = sa.insert(table)
            if names:
                statement = statement.values(updated_at=sa.func.statement_timestamp())
            await self.session.execute(statement, rows)

    async def _audit(
        self, status: AuditEventStatus, case_ids: Sequence[uuid.UUID | None]
    ) -> None:
        """Record ``create_case``'s audit events, one per case (best effort)."""
        if self.role.actor_id is None:
            return
        try:
            async with AuditService.with_session(
                self.role, session=self.session
            ) as audit:
                for case_id in case_ids:
                    await audit.create_event(
                        resource_type="case",
                        action="create",
                        resource_id=case_id,
                        status=status,
                        data=None,
                    )
        except Exception as exc:
            self.logger.warning(
                "Bulk case audit log failed", error_type=type(exc).__name__
            )


def _coerce(column_type: Any, value: Any) -> Any:
    """Coerce a value as ``TableEditorService.update_row`` does."""
    if value is None:
        return None
    if isinstance(column_type, sa.Date):
        return coerce_to_date(value)
    if isinstance(column_type, sa.DateTime) and column_type.timezone:
        return coerce_to_utc_datetime(value)
    return value


def _table_of(model: type[Base]) -> sa.Table:
    """The mapped table of a model (typed for Core statements)."""
    table = model.__table__
    if not isinstance(table, sa.Table):
        raise TypeError(f"{model.__name__} is not mapped to a single table")
    return table
