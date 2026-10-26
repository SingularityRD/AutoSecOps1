"""Side-effect parity of ``BulkCasesService.create_cases`` with ``create_case``.

A case created through ``CasesService.create_case`` (then tagged with
``CaseEventsService.create_event``, as RoboDR ingest used to) and one created
through the bulk path (tagged with ``create_events``) are compared field by
field: the case row, case number and short id, the initial versions, the
custom-field row, the tag link, the activity events, the audit events and the
Redis stream entries (case triggers and duration syncs) published after
commit.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.audit.service import AuditService
from autosecops.auth.types import Role
from autosecops.cases.bulk import BulkCasesService
from autosecops.cases.enums import CasePriority, CaseSeverity, CaseStatus
from autosecops.cases.event_schemas import TagAddedEvent
from autosecops.cases.events import CaseEventItem, CaseEventsService
from autosecops.cases.schemas import CaseCreate, CaseFieldCreate
from autosecops.cases.service import CaseFieldsService, CasesService
from autosecops.db.models import (
    Case,
    CaseEvent,
    CaseTag,
    CaseTagLink,
    CaseVersion,
    Workspace,
)
from autosecops.redis.client import get_redis_client
from autosecops.tables.enums import SqlType

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]


@dataclass
class AuditCapture:
    events: list[dict[str, Any]] = field(default_factory=list)


@pytest.fixture
def audit_capture(monkeypatch: pytest.MonkeyPatch) -> AuditCapture:
    capture = AuditCapture()

    async def _create_event(self: AuditService, **kwargs: Any) -> None:
        capture.events.append(kwargs)

    monkeypatch.setattr(AuditService, "create_event", _create_event)
    return capture


@pytest.fixture
def streams(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str]]:
    triggers = f"test-case-events-{uuid.uuid4().hex}"
    durations = f"test-case-durations-{uuid.uuid4().hex}"
    monkeypatch.setattr(config, "TRACECAT__CASE_TRIGGERS_ENABLED", True)
    monkeypatch.setattr(config, "TRACECAT__CASE_TRIGGERS_STREAM_KEY", triggers)
    monkeypatch.setattr(config, "TRACECAT__CASE_DURATION_SYNC_STREAM_KEY", durations)
    yield triggers, durations


async def _stream(key: str, expected: int) -> list[dict[str, str]]:
    """The stream's entries once ``expected`` arrived (after-commit tasks)."""
    client = await get_redis_client()
    entries: list[tuple[str, dict[str, str]]] = []
    for _ in range(200):
        entries = await client.xrange(key, min_id="-", max_id="+")
        if len(entries) >= expected:
            break
        await asyncio.sleep(0.05)
    return [fields for _, fields in entries]


def _case_params() -> CaseCreate:
    return CaseCreate(
        summary="Robot ugv-001: unexpected writer on rt/cmd_vel",
        description="A participant outside the locked profile wrote a topic.",
        status=CaseStatus.NEW,
        priority=CasePriority.HIGH,
        severity=CaseSeverity.HIGH,
        payload={"robodr": {"rule_id": "R1", "occurrence_count": 1}},
        fields={"robot_id": "ugv-001", "occurrence_count": 1},
    )


async def _snapshot(session: AsyncSession, case_id: uuid.UUID) -> dict[str, Any]:
    case = await session.scalar(sa.select(Case).where(Case.id == case_id))
    assert case is not None
    versions = (
        await session.execute(
            sa.select(
                CaseVersion.field,
                CaseVersion.version,
                CaseVersion.content,
                CaseVersion.user_id,
            )
            .where(CaseVersion.case_id == case_id)
            .order_by(CaseVersion.field)
        )
    ).all()
    events = (
        await session.execute(
            sa.select(CaseEvent.type, CaseEvent.data, CaseEvent.user_id)
            .where(CaseEvent.case_id == case_id)
            .order_by(CaseEvent.surrogate_id)
        )
    ).all()
    tags = (
        await session.scalars(
            sa.select(CaseTagLink.tag_id).where(CaseTagLink.case_id == case_id)
        )
    ).all()
    return {
        "summary": case.summary,
        "description": case.description,
        "priority": case.priority,
        "severity": case.severity,
        "status": case.status,
        "payload": case.payload,
        "assignee_id": case.assignee_id,
        "parent_id": case.parent_id,
        "workspace_id": case.workspace_id,
        "updated_after_created": case.updated_at is not None,
        "versions": [tuple(v) for v in versions],
        "events": [tuple(e) for e in events],
        "tags": list(tags),
    }


async def test_bulk_creation_matches_create_case(
    session: AsyncSession,
    svc_role: Role,
    svc_workspace: Workspace,
    audit_capture: AuditCapture,
    streams: tuple[str, str],
) -> None:
    fields = CaseFieldsService(session, role=svc_role)
    await fields.create_field(CaseFieldCreate(name="robot_id", type=SqlType.TEXT))
    await fields.create_field(
        CaseFieldCreate(name="occurrence_count", type=SqlType.INTEGER)
    )
    await fields.create_field(
        CaseFieldCreate(name="untouched", type=SqlType.TEXT, default="preset")
    )
    tag = CaseTag(workspace_id=svc_workspace.id, name="robodr", ref="robodr")
    session.add(tag)
    await session.commit()
    tag_added = TagAddedEvent(tag_id=tag.id, tag_ref=tag.ref, tag_name=tag.name)

    # Reference: create_case, then tag it with create_event.
    single = await CasesService(session, role=svc_role).create_case(
        _case_params(), commit=False
    )
    session.add(CaseTagLink(case_id=single.id, tag_id=tag.id))
    await CaseEventsService(session, role=svc_role).create_event(
        case=single, event=tag_added
    )
    await session.commit()
    single_audit = list(audit_capture.events)
    audit_capture.events.clear()

    # Bulk: create_cases, then tag with create_events.
    bulk = BulkCasesService(session, role=svc_role)
    created = await bulk.create_cases([_case_params(), _case_params()])
    bulk_id, second_id = (case.id for case in created)
    await session.execute(
        sa.insert(CaseTagLink),
        [
            {"case_id": bulk_id, "tag_id": tag.id},
            {"case_id": second_id, "tag_id": tag.id},
        ],
    )
    await bulk.events.create_events(
        [
            CaseEventItem(case_id=bulk_id, event=tag_added),
            CaseEventItem(case_id=second_id, event=tag_added),
        ]
    )
    await session.commit()

    # Gapless numbers after create_case's, in creation order.
    assert [case.case_number for case in created] == [
        single.case_number + 1,
        single.case_number + 2,
    ]
    bulk_case = await session.scalar(sa.select(Case).where(Case.id == bulk_id))
    assert bulk_case is not None
    assert bulk_case.case_number == single.case_number + 1
    assert bulk_case.short_id == created[0].short_id
    assert created[0].short_id == f"CASE-{single.case_number + 1:04d}"

    assert await _snapshot(session, bulk_id) == await _snapshot(session, single.id)
    single_fields = await fields.get_fields(single)
    bulk_fields = await fields.get_fields(bulk_case)
    assert single_fields is not None and bulk_fields is not None
    row_identity = {"id", "case_id", "created_at", "updated_at"}
    assert set(single_fields) == set(bulk_fields)
    single_values = {k: v for k, v in single_fields.items() if k not in row_identity}
    bulk_values = {k: v for k, v in bulk_fields.items() if k not in row_identity}
    assert single_values == bulk_values
    assert bulk_fields["case_id"] == bulk_id
    assert bulk_values == {
        "robot_id": "ugv-001",
        "occurrence_count": 1,
        "untouched": "preset",
    }

    # Audit: an attempt and a success per case, as audit_log records.
    def _audit_shape(events: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
        return [
            (e["resource_type"], e["action"], e["status"], e["resource_id"] is None)
            for e in events
        ]

    bulk_audit = audit_capture.events
    assert len(single_audit) == 2
    assert sorted(_audit_shape(bulk_audit), key=str) == sorted(
        _audit_shape(single_audit) * 2, key=str
    )
    assert {e["resource_id"] for e in bulk_audit if e["resource_id"]} == {
        bulk_id,
        second_id,
    }

    # Case triggers and duration syncs: the same entries per event, in order.
    triggers, durations = streams
    trigger_entries = await _stream(triggers, 6)
    duration_entries = await _stream(durations, 6)
    event_rows = (
        await session.execute(
            sa.select(CaseEvent.id, CaseEvent.case_id, CaseEvent.type)
            .where(CaseEvent.case_id.in_([single.id, bulk_id, second_id]))
            .order_by(CaseEvent.surrogate_id)
        )
    ).all()
    expected_triggers = {
        (str(event_id), str(case_id), str(event_type.value))
        for event_id, case_id, event_type in event_rows
    }
    assert {
        (e["event_id"], e["case_id"], e["event_type"]) for e in trigger_entries
    } == expected_triggers
    assert all(e["workspace_id"] == str(svc_workspace.id) for e in trigger_entries)
    assert sorted(
        (e["case_id"], e["event_type"], e["reason"], e["workspace_id"])
        for e in duration_entries
    ) == sorted(
        (str(case_id), str(event_type.value), "case_event", str(svc_workspace.id))
        for _, case_id, event_type in event_rows
    )
    # The bulk entries keep event order: each case's created, then tag_added.
    bulk_triggers = [
        (e["case_id"], e["event_type"])
        for e in trigger_entries
        if e["case_id"] != str(single.id)
    ]
    assert bulk_triggers == [
        (str(bulk_id), "case_created"),
        (str(second_id), "case_created"),
        (str(bulk_id), "tag_added"),
        (str(second_id), "tag_added"),
    ]


async def test_bulk_creation_refuses_what_it_cannot_batch(
    session: AsyncSession, svc_role: Role
) -> None:
    bulk = BulkCasesService(session, role=svc_role)
    with pytest.raises(ValueError):
        await bulk.create_cases(
            [_case_params().model_copy(update={"parent_id": uuid.uuid4()})]
        )
    with pytest.raises(ValueError):
        await bulk.create_cases(
            [_case_params().model_copy(update={"fields": {"no_such_field": "x"}})]
        )
