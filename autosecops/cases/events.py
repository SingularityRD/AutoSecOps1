"""Case event persistence service."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

from redis.typing import EncodableT, FieldT
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.types import Role
from autosecops.cases.agent_sessions.service import (
    CaseAgentSessionInteractionService,
)
from autosecops.cases.durations.materialization import sync_case_duration
from autosecops.cases.durations.sync_queue import (
    case_duration_sync_fields,
    deliver_case_duration_sync,
    enqueue_case_duration_sync_after_commit,
)
from autosecops.cases.enums import (
    CaseAgentSessionInteractionOperation,
    CaseEventType,
)
from autosecops.cases.event_schemas import (
    CaseEventVariant,
    CaseViewedEvent,
)
from autosecops.cases.triggers.publisher import (
    case_event_fields,
    publish_case_event_payload,
)
from autosecops.db.models import Case, CaseEvent
from autosecops.db.session_events import AfterCommitQueue
from autosecops.logger import logger
from autosecops.redis.client import get_redis_client
from autosecops.service import BaseWorkspaceService

CASE_VIEW_EVENT_DEDUP_WINDOW = timedelta(minutes=5)
_CHILD_MUTATION_EVENTS = frozenset(
    {
        CaseEventType.ATTACHMENT_CREATED,
        CaseEventType.ATTACHMENT_DELETED,
        CaseEventType.COMMENT_DELETED,
        CaseEventType.COMMENT_REPLY_DELETED,
        CaseEventType.DROPDOWN_VALUE_CHANGED,
        CaseEventType.TABLE_ROW_LINKED,
        CaseEventType.TABLE_ROW_UNLINKED,
        CaseEventType.TAG_ADDED,
        CaseEventType.TAG_REMOVED,
    }
)


@dataclass(frozen=True, slots=True)
class CaseEventItem:
    """One activity record to create for a case (see ``create_events``)."""

    case_id: uuid.UUID
    event: CaseEventVariant


@dataclass(frozen=True, slots=True)
class _RecordedEvent:
    """A created event's identity for its after-commit side effects."""

    event_id: uuid.UUID
    case_id: uuid.UUID
    event_type: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class _StreamEntry:
    """One Redis stream entry and the per-event path that redelivers it."""

    stream: str
    fields: dict[str, str]
    maxlen: int | None
    redeliver: Callable[[], Awaitable[None]]


class CaseEventsService(BaseWorkspaceService):
    """Service for managing case events."""

    service_name = "case_events"

    def __init__(self, session: AsyncSession, role: Role | None = None):
        super().__init__(session, role)
        self.agent_session_interactions = CaseAgentSessionInteractionService(
            session=self.session,
            role=self.role,
        )

    async def list_events(self, case: Case) -> Sequence[CaseEvent]:
        """List all events for a case."""
        statement = (
            select(CaseEvent)
            .where(CaseEvent.case_id == case.id)
            .order_by(CaseEvent.created_at.desc(), CaseEvent.surrogate_id.desc())
        )
        result = await self.session.execute(statement)
        return result.scalars().all()

    async def create_event(
        self,
        case: Case,
        event: CaseEventVariant,
        *,
        publish_case_trigger: bool = True,
        sync_durations: bool = True,
        system_generated: bool = False,
        record_agent_interaction: bool = True,
    ) -> CaseEvent:
        """Create a non-committing activity record for a case."""
        db_event = CaseEvent(
            workspace_id=self.workspace_id,
            case_id=case.id,
            type=event.type,
            data=event.model_dump(exclude={"type"}, mode="json"),
            user_id=None if system_generated else self.role.user_id,
        )
        self.session.add(db_event)
        await self.session.flush()

        if (
            record_agent_interaction
            and not system_generated
            and event.type in _CHILD_MUTATION_EVENTS
        ):
            await self.agent_session_interactions.record_from_context(
                case_id=case.id,
                operation=CaseAgentSessionInteractionOperation.UPDATE,
            )

        event_type = (
            db_event.type.value if hasattr(db_event.type, "value") else db_event.type
        )
        self._register_after_commit(
            event_id=db_event.id,
            case_id=case.id,
            workspace_id=case.workspace_id,
            event_type=event_type,
            created_at=db_event.created_at or datetime.now(UTC),
            publish_case_trigger=publish_case_trigger,
            sync_durations=sync_durations,
        )

        return db_event

    def _register_after_commit(
        self,
        *,
        event_id: uuid.UUID,
        case_id: uuid.UUID,
        workspace_id: uuid.UUID,
        event_type: str,
        created_at: datetime,
        publish_case_trigger: bool,
        sync_durations: bool,
    ) -> None:
        """Queue an event's case-trigger publish and duration sync for commit."""
        if publish_case_trigger:
            payload_event_id = str(event_id)
            payload_case_id = str(case_id)
            payload_workspace_id = str(workspace_id)

            async def _publish_case_event() -> None:
                await publish_case_event_payload(
                    event_id=payload_event_id,
                    case_id=payload_case_id,
                    workspace_id=payload_workspace_id,
                    event_type=event_type,
                    created_at=created_at,
                )

            AfterCommitQueue.of(self.session).add(_publish_case_event)

        if sync_durations:
            enqueue_case_duration_sync_after_commit(
                self.session,
                workspace_id=workspace_id,
                case_id=case_id,
                event_type=event_type,
                reason="case_event",
                inline_fallback=partial(
                    sync_case_duration,
                    workspace_id,
                    case_id,
                    event_types={event_type},
                ),
            )

    async def create_events(self, items: Sequence[CaseEventItem]) -> list[uuid.UUID]:
        """Create activity records for many cases of this workspace at once.

        Equivalent to calling :meth:`create_event` with its default options for
        each item, in order: the same rows (inserted in item order, so each
        case's events keep their relative order), the same agent-session
        interactions, and after commit the same case-trigger and duration-sync
        stream entries. The rows go in one multi-row ``INSERT ... RETURNING``
        instead of one flush per event, and the stream entries in one Redis
        pipeline, in item order (each event's trigger entry, then its duration
        sync entry), instead of two concurrent publishes per event; an entry
        the pipeline cannot add is delivered through ``create_event``'s
        per-event path (with its retries and inline duration-sync fallback).

        Args:
            items: The events to record, each with the case it belongs to.

        Returns:
            The new event ids, in item order.
        """
        if not items:
            return []
        rows = [
            {
                "id": uuid.uuid4(),
                "workspace_id": self.workspace_id,
                "case_id": item.case_id,
                "type": item.event.type,
                "data": item.event.model_dump(exclude={"type"}, mode="json"),
                "user_id": self.role.user_id,
            }
            for item in items
        ]
        result = await self.session.execute(
            insert(CaseEvent).returning(
                CaseEvent.id, CaseEvent.created_at, sort_by_parameter_order=True
            ),
            rows,
        )
        inserted = result.tuples().all()
        records: list[_RecordedEvent] = []
        for item, (event_id, created_at) in zip(items, inserted, strict=True):
            if item.event.type in _CHILD_MUTATION_EVENTS:
                await self.agent_session_interactions.record_from_context(
                    case_id=item.case_id,
                    operation=CaseAgentSessionInteractionOperation.UPDATE,
                )
            records.append(
                _RecordedEvent(
                    event_id=event_id,
                    case_id=item.case_id,
                    event_type=CaseEventType(item.event.type).value,
                    created_at=created_at or datetime.now(UTC),
                )
            )
        workspace_id = self.workspace_id

        async def _deliver() -> None:
            await _deliver_after_commit(workspace_id, records)

        AfterCommitQueue.of(self.session).add(_deliver)
        return [event_id for event_id, _ in inserted]

    async def create_case_viewed_event(
        self,
        case: Case,
        *,
        dedupe_window: timedelta = CASE_VIEW_EVENT_DEDUP_WINDOW,
    ) -> CaseEvent | None:
        """Record a case viewed event if the current user has not viewed recently."""
        if not self.role.user_id:
            return None

        now_utc = datetime.now(UTC)
        statement = (
            select(CaseEvent)
            .where(
                CaseEvent.workspace_id == self.workspace_id,
                CaseEvent.case_id == case.id,
                CaseEvent.type == CaseEventType.CASE_VIEWED,
                CaseEvent.user_id == self.role.user_id,
            )
            .order_by(CaseEvent.created_at.desc())
            .limit(1)
        )
        last_event = (await self.session.execute(statement)).scalars().first()
        if last_event:
            last_created_at = last_event.created_at
            if last_created_at.tzinfo is None:
                if datetime.now() - last_created_at < dedupe_window:
                    return None
            elif now_utc - last_created_at < dedupe_window:
                return None

        return await self.create_event(case=case, event=CaseViewedEvent())


def _stream_entries(
    workspace_id: uuid.UUID, records: Sequence[_RecordedEvent]
) -> list[_StreamEntry]:
    """What ``create_event`` publishes after commit, for each record in order."""
    entries: list[_StreamEntry] = []
    for record in records:
        if config.AUTOSECOPS__CASE_TRIGGERS_ENABLED:
            entries.append(
                _StreamEntry(
                    stream=config.AUTOSECOPS__CASE_TRIGGERS_STREAM_KEY,
                    fields=case_event_fields(
                        event_id=str(record.event_id),
                        case_id=str(record.case_id),
                        workspace_id=str(workspace_id),
                        event_type=record.event_type,
                        created_at=record.created_at,
                    ),
                    maxlen=config.AUTOSECOPS__CASE_TRIGGERS_MAXLEN,
                    redeliver=partial(
                        publish_case_event_payload,
                        event_id=str(record.event_id),
                        case_id=str(record.case_id),
                        workspace_id=str(workspace_id),
                        event_type=record.event_type,
                        created_at=record.created_at,
                    ),
                )
            )
        entries.append(
            _StreamEntry(
                stream=config.AUTOSECOPS__CASE_DURATION_SYNC_STREAM_KEY,
                fields=case_duration_sync_fields(
                    workspace_id=workspace_id,
                    reason="case_event",
                    case_id=record.case_id,
                    event_type=record.event_type,
                ),
                maxlen=None,
                redeliver=partial(
                    deliver_case_duration_sync,
                    workspace_id=workspace_id,
                    reason="case_event",
                    case_id=record.case_id,
                    event_type=record.event_type,
                    inline_fallback=partial(
                        sync_case_duration,
                        workspace_id,
                        record.case_id,
                        event_types={record.event_type},
                    ),
                ),
            )
        )
    return entries


async def _deliver_after_commit(
    workspace_id: uuid.UUID, records: Sequence[_RecordedEvent]
) -> None:
    """Add the records' stream entries in one pipeline; redeliver failures."""
    entries = _stream_entries(workspace_id, records)
    if not entries:
        return
    results: list[Any]
    try:
        client = await (await get_redis_client())._get_client()
        async with client.pipeline(transaction=False) as pipe:
            for entry in entries:
                fields: dict[FieldT, EncodableT] = {}
                fields.update(entry.fields.items())
                if entry.maxlen is None:
                    pipe.xadd(entry.stream, fields)
                else:
                    pipe.xadd(
                        entry.stream,
                        fields,
                        maxlen=entry.maxlen,
                        approximate=True,
                    )
            results = await pipe.execute(raise_on_error=False)
    except Exception as exc:
        logger.warning(
            "Pipelined case event delivery failed; delivering one by one",
            error_type=type(exc).__name__,
            entries=len(entries),
        )
        results = [exc] * len(entries)
    for entry, result in zip(entries, results, strict=True):
        if not isinstance(result, Exception):
            continue
        try:
            await entry.redeliver()
        except Exception as exc:
            logger.warning(
                "Case event side effect delivery failed",
                stream=entry.stream,
                error_type=type(exc).__name__,
            )
