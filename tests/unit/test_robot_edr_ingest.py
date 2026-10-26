"""End-to-end tests of `POST /robot-edr/v2/ingest` and the robot registry API.

The ingest route runs against the live test database and Redis exactly as in
production (its own sessions, no dependency overrides); only the audit
webhook delivery is captured.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from collections.abc import AsyncGenerator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, get_args

import httpx
import psycopg
import pytest
from autosecops_registry.integrations.robodr import finding_to_case_fields
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg import sql
from sqlalchemy import delete, func, select

from autosecops import config
from autosecops.audit.service import AuditService
from autosecops.audit.types import AuditEvent
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES, VIEWER_SCOPES
from autosecops.cases.enums import CaseEventType, CasePriority, CaseSeverity
from autosecops.cases.service import CaseFieldsService
from autosecops.db.engine import get_async_session_context_manager
from autosecops.db.models import (
    Case,
    CaseEvent,
    CaseTag,
    CaseTagLink,
    Organization,
    RobotFinding,
    RobotFindingEvent,
    RobotIngestBatch,
    RobotKey,
    Workspace,
)
from autosecops.db.tenant_rls import enable_workspace_table_rls
from autosecops.exceptions import (
    EntitlementRequired,
    ScopeDeniedError,
    TracecatNotFoundError,
)
from autosecops.robot_edr import ingest as ingest_module
from autosecops.robot_edr import rate_limit
from autosecops.robot_edr.ingest_router import arrived_over_tls
from autosecops.robot_edr.ingest_router import router as ingest_router
from autosecops.robot_edr.router import router as management_router
from autosecops.robot_edr.schemas import RobotCreate, RobotKeyCreate
from autosecops.robot_edr.service import RobotsService
from autosecops.robot_edr.types import RobotKeyRole
from autosecops.tiers import defaults as tier_defaults
from tests._robot_edr_utils import (
    RoboKey,
    body_of,
    finding_sig,
    key,
    line,
    producer_entries,
    producer_values,
    signed_headers,
    synth_finding,
)
from tests.database import TEST_DB_CONFIG

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]

INGEST = "/robot-edr/v2/ingest"


# --- fixtures -------------------------------------------------------------------


@pytest.fixture(autouse=True)
def robot_edr_entitled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(update={"robot_edr": True}),
    )


@pytest.fixture(autouse=True)
def fresh_rate_limits() -> Iterator[None]:
    rate_limit._local_buckets.clear()
    yield
    rate_limit._local_buckets.clear()


@dataclass
class AuditCapture:
    events: list[AuditEvent] = field(default_factory=list)


@pytest.fixture(autouse=True)
def audit_capture(monkeypatch: pytest.MonkeyPatch) -> AuditCapture:
    capture = AuditCapture()

    async def _webhook(self: AuditService) -> str:
        return "https://audit.invalid/hook"

    async def _post(
        self: AuditService, *, webhook_url: str, payload: AuditEvent
    ) -> None:
        capture.events.append(payload)

    monkeypatch.setattr(AuditService, "_get_webhook_url", _webhook)
    monkeypatch.setattr(AuditService, "_post_event", _post)
    return capture


async def _new_workspace(org_id: uuid.UUID) -> Workspace:
    workspace = Workspace(
        id=uuid.uuid4(),
        name=f"robot-edr-{uuid.uuid4().hex[:8]}",
        organization_id=org_id,
    )
    async with get_async_session_context_manager() as session:
        session.add(workspace)
        await session.commit()
    return workspace


async def _drop_workspace(workspace_id: uuid.UUID) -> None:
    async with get_async_session_context_manager() as session:
        await session.execute(delete(Workspace).where(Workspace.id == workspace_id))
        await session.commit()


@pytest.fixture
async def workspace(svc_organization: Organization) -> AsyncGenerator[Workspace, None]:
    ws = await _new_workspace(svc_organization.id)
    yield ws
    await _drop_workspace(ws.id)


@pytest.fixture
async def other_workspace(
    svc_organization: Organization,
) -> AsyncGenerator[Workspace, None]:
    ws = await _new_workspace(svc_organization.id)
    yield ws
    await _drop_workspace(ws.id)


def admin_role(ws: Workspace, scopes: frozenset[str] = ADMIN_SCOPES) -> Role:
    return Role(
        type="service",
        service_id="tracecat-api",
        workspace_id=ws.id,
        organization_id=ws.organization_id,
        scopes=scopes,
    )


async def register_robot(
    ws: Workspace, robot_id: str, *, require_sig: bool = False
) -> None:
    async with get_async_session_context_manager() as session:
        await RobotsService(session, role=admin_role(ws)).create_robot(
            RobotCreate(
                robot_id=robot_id,
                site="range-north",
                require_finding_signature=require_sig,
            )
        )


async def register_key(
    ws: Workspace,
    signer: RoboKey,
    role: RobotKeyRole,
    robot_id: str | None = None,
    *,
    key_id: str | None = None,
    expires_at: datetime | None = None,
) -> uuid.UUID:
    async with get_async_session_context_manager() as session:
        created = await RobotsService(session, role=admin_role(ws)).create_key(
            RobotKeyCreate(
                role=role,
                robot_id=robot_id,
                public_key=signer.public.hex(),
                key_id=key_id,
                expires_at=expires_at,
            )
        )
        return created.id


@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    app = FastAPI()
    app.include_router(ingest_router)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def post_batch(
    client: httpx.AsyncClient,
    signer: RoboKey,
    lines: list[bytes],
    *,
    batch_id: str | None = None,
    **kwargs: Any,
) -> httpx.Response:
    body = body_of(lines)
    batch = batch_id or f"b-{uuid.uuid4().hex}"
    headers = signed_headers(signer, batch, body, **kwargs)
    return await client.post(INGEST, content=body, headers=headers)


@pytest.fixture
async def uplink(workspace: Workspace) -> RoboKey:
    signer = key(f"uplink-{workspace.id}")
    await register_robot(workspace, "ugv-001")
    await register_key(workspace, signer, RobotKeyRole.UPLINK, "ugv-001")
    return signer


async def _findings(ws: Workspace) -> list[RobotFinding]:
    async with get_async_session_context_manager() as session:
        return list(
            (
                await session.scalars(
                    select(RobotFinding).where(RobotFinding.workspace_id == ws.id)
                )
            ).all()
        )


async def _case(case_id: uuid.UUID | None) -> Case:
    assert case_id is not None
    async with get_async_session_context_manager() as session:
        case = await session.scalar(select(Case).where(Case.id == case_id))
        assert case is not None
        return case


async def _case_event_types(case_id: uuid.UUID) -> list[CaseEventType]:
    async with get_async_session_context_manager() as session:
        rows = await session.scalars(
            select(CaseEvent.type).where(CaseEvent.case_id == case_id)
        )
        return [CaseEventType(t) for t in rows.all()]


# --- dedup, cases, replay ---------------------------------------------------------


async def test_created_updated_duplicate_and_replay(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    values = producer_values()
    first = await post_batch(
        client, uplink, [line(values["r1_critical_c1"])], batch_id="batch-1"
    )
    assert first.status_code == 200, first.text
    assert first.json() == {
        "batch_id": "batch-1",
        "replayed": False,
        "accepted": 1,
        "created": 1,
        "updated": 0,
        "duplicates": 0,
        "rejected": [],
    }

    # A retry (same batch id, re-signed with a new timestamp) is replayed.
    replay = await post_batch(
        client, uplink, [line(values["r1_critical_c1"])], batch_id="batch-1"
    )
    assert replay.status_code == 200
    assert replay.json() == {**first.json(), "replayed": True}

    second = await post_batch(client, uplink, [line(values["r1_critical_c2"])])
    assert second.json()["updated"] == 1

    third = await post_batch(
        client,
        uplink,
        [line(values["r1_critical_c2"]), line(values["r1_critical_c1"])],
    )
    assert third.json() == {
        **third.json(),
        "accepted": 2,
        "created": 0,
        "updated": 0,
        "duplicates": 2,
    }

    [finding] = await _findings(workspace)
    assert finding.occurrence_count == 2
    assert finding.raw_value == values["r1_critical_c2"]
    assert finding.adversary_controlled_fields
    case = await _case(finding.case_id)
    assert case.severity == CaseSeverity.CRITICAL
    assert case.priority == CasePriority.CRITICAL
    assert case.payload is not None
    assert case.payload["robodr"]["occurrence_count"] == 2
    events = await _case_event_types(case.id)
    assert CaseEventType.CASE_CREATED in events
    assert CaseEventType.FIELDS_CHANGED in events

    async with get_async_session_context_manager() as session:
        fields = await CaseFieldsService(
            session, role=admin_role(workspace)
        ).get_fields(case)
    assert fields is not None
    assert fields["robot_id"] == "ugv-001"
    assert fields["occurrence_count"] == 2
    assert fields["profile_mode"] == "enforce"
    assert fields["mitre_ics"] == "T0855"
    assert fields["external_id"] == finding.external_id


async def test_severity_only_rises(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    values = producer_values()
    for name in ("sev_low_c1", "sev_critical_c2", "sev_medium_c3"):
        response = await post_batch(client, uplink, [line(values[name])])
        assert response.status_code == 200, response.text
        assert response.json()["rejected"] == []
    [finding] = await _findings(workspace)
    assert finding.occurrence_count == 3
    assert finding.severity_id == 5
    case = await _case(finding.case_id)
    assert case.severity == CaseSeverity.CRITICAL
    assert case.priority == CasePriority.CRITICAL
    assert CaseEventType.SEVERITY_CHANGED in await _case_event_types(case.id)


async def test_custom_fields_are_created_once(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    for label in ("a", "b"):
        response = await post_batch(client, uplink, [line(synth_finding(label=label))])
        assert response.json()["created"] == 1
    async with get_async_session_context_manager() as session:
        schema = await CaseFieldsService(
            session, role=admin_role(workspace)
        ).get_field_schema()
    for name in (
        "robot_id",
        "site",
        "rule_id",
        "mitre_ics",
        "profile_mode",
        "safety_state",
        "external_id",
        "data_source",
        "contract_version",
        "occurrence_count",
    ):
        assert name in schema
    assert schema["occurrence_count"]["type"] == "INTEGER"


# --- per-line errors -----------------------------------------------------------------


async def test_every_line_error_code(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    await register_robot(workspace, "ugv-sig", require_sig=True)
    good = synth_finding(label="good")
    contract_1 = json.loads(good)
    contract_1["contract_version"] = "1.3.0"
    lines = [
        line(good),  # 1 created
        b"",  # 2 empty line
        b'{"value":"x","sig":null}\r',  # 3 CR
        b"not json",  # 4
        b'{"value":"x","sig":null,"extra":1}',  # 5 extra key
        b'{"value":1,"sig":null}',  # 6 value not a string
        b'{"value":"x","value":"y","sig":null}',  # 7 duplicate key
        line("{}"),  # 8 invalid finding
        line(json.dumps(contract_1)),  # 9 unsupported contract
        line(" " * (256 * 1024 + 1)),  # 10 too large
        line(synth_finding(robot_id="ugv-002", label="other")),  # 11 robot mismatch
        line(good.replace('"title":', '"title":"x","title":', 1)),  # 12 dup in value
        b'{"value":"x","sig":"nope"}',  # 13 sig not an object
    ]
    response = await post_batch(client, uplink, lines)
    assert response.status_code == 200, response.text
    body = response.json()
    codes = {r["line"]: r["code"] for r in body["rejected"]}
    assert body["created"] == 1 and body["accepted"] == 1
    assert codes == {
        2: "invalid_line",
        3: "invalid_line",
        4: "invalid_line",
        5: "invalid_line",
        6: "invalid_line",
        7: "invalid_line",
        8: "invalid_finding",
        9: "unsupported_contract",
        10: "too_large",
        11: "robot_mismatch",
        12: "invalid_finding",
        13: "invalid_line",
    }
    assert all(r["detail"] for r in body["rejected"])


async def test_relay_binding_and_finding_signatures(
    client: httpx.AsyncClient, workspace: Workspace
) -> None:
    relay = key(f"relay-{workspace.id}")
    finding_key = key(f"finding-{workspace.id}")
    other_finding_key = key(f"finding-other-{workspace.id}")
    await register_robot(workspace, "ugv-001")
    await register_robot(workspace, "ugv-sig", require_sig=True)
    await register_key(workspace, relay, RobotKeyRole.RELAY)
    await register_key(
        workspace,
        finding_key,
        RobotKeyRole.FINDING,
        "ugv-sig",
        key_id="finding:ugv-sig:1",
    )
    await register_key(workspace, other_finding_key, RobotKeyRole.FINDING, "ugv-001")

    signed = synth_finding(robot_id="ugv-sig", label="signed")
    unsigned = synth_finding(robot_id="ugv-sig", label="unsigned")
    lines = [
        line(synth_finding(robot_id="ugv-001", label="relay-ok")),  # 1 relay, any robot
        line(synth_finding(robot_id="ugv-404", label="nobody")),  # 2 unknown robot
        line(signed, finding_sig(finding_key, signed, "finding:ugv-sig:1")),  # 3 ok
        line(unsigned),  # 4 missing signature
        # 5: a finding key of another robot never vouches for this one.
        line(unsigned, finding_sig(other_finding_key, unsigned)),
        # 6: signature over different bytes.
        line(unsigned, finding_sig(finding_key, signed, "finding:ugv-sig:1")),
        line(unsigned, {"alg": "hmac-sha256", "key_id": "k", "sig": "00" * 64}),  # 7
        line(unsigned, {"alg": "ed25519", "key_id": "k"}),  # 8 malformed
    ]
    response = await post_batch(client, relay, lines)
    body = response.json()
    assert body["created"] == 2
    assert {r["line"]: r["code"] for r in body["rejected"]} == {
        2: "unknown_robot",
        4: "missing_finding_signature",
        5: "bad_finding_signature",
        6: "bad_finding_signature",
        7: "invalid_line",
        8: "invalid_line",
    }
    stored = {f.robot_id: f.signature_key_id for f in await _findings(workspace)}
    assert stored == {"ugv-001": None, "ugv-sig": "finding:ugv-sig:1"}


async def test_site_scoped_and_origin_vouching_relays(
    client: httpx.AsyncClient, workspace: Workspace
) -> None:
    await register_robot(workspace, "ugv-001")  # site range-north
    await register_robot(workspace, "ugv-sig", require_sig=True)
    async with get_async_session_context_manager() as session:
        service = RobotsService(session, role=admin_role(workspace))
        await service.create_robot(RobotCreate(robot_id="ugv-far", site="range-south"))
    site_relay = key(f"site-relay-{workspace.id}")
    diode = key(f"diode-{workspace.id}")
    async with get_async_session_context_manager() as session:
        service = RobotsService(session, role=admin_role(workspace))
        await service.create_key(
            RobotKeyCreate(
                role=RobotKeyRole.RELAY,
                public_key=site_relay.public.hex(),
                site="range-north",
            )
        )
        await service.create_key(
            RobotKeyCreate(
                role=RobotKeyRole.RELAY,
                public_key=diode.public.hex(),
                vouches_origin=True,
            )
        )
    near = line(synth_finding(robot_id="ugv-001", label="near"))
    far = line(synth_finding(robot_id="ugv-far", label="far"))
    unsigned = line(synth_finding(robot_id="ugv-sig", label="unsigned"))
    body = (await post_batch(client, site_relay, [near, far, unsigned])).json()
    assert {r["line"]: r["code"] for r in body["rejected"]} == {
        2: "site_mismatch",
        3: "missing_finding_signature",
    }
    vouched = (await post_batch(client, diode, [unsigned, far])).json()
    assert vouched["created"] == 2 and vouched["rejected"] == []


async def test_rotation_keeps_both_keys_active(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    second = key(f"uplink-2-{workspace.id}")
    await register_key(workspace, second, RobotKeyRole.UPLINK, "ugv-001")
    assert (
        await post_batch(client, uplink, [line(synth_finding(label="k1"))])
    ).status_code == 200
    assert (
        await post_batch(client, second, [line(synth_finding(label="k2"))])
    ).status_code == 200


async def test_out_of_order_events(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    newest = synth_finding(label="ooo", count=3, severity="low")
    older = synth_finding(label="ooo", count=2, severity="critical")
    first = (await post_batch(client, uplink, [line(newest)])).json()
    assert first["created"] == 1
    late = (await post_batch(client, uplink, [line(older), line(older)])).json()
    assert (late["updated"], late["duplicates"]) == (1, 1)
    [finding] = await _findings(workspace)
    # last_seen and count stay at the newest emission; the payload too.
    assert finding.occurrence_count == 3
    assert finding.raw_value == newest
    assert finding.severity_id == 5  # severity still rises
    case = await _case(finding.case_id)
    assert case.severity == CaseSeverity.CRITICAL
    assert case.payload is not None
    assert case.payload["robodr"]["occurrence_count"] == 3
    async with get_async_session_context_manager() as session:
        events = (
            await session.scalars(
                select(RobotFindingEvent.event_uid).where(
                    RobotFindingEvent.finding_fk == finding.id
                )
            )
        ).all()
    assert len(events) == 2
    # A late emission that changes nothing on the case still leaves an event.
    even_older = synth_finding(label="ooo", count=2, severity="low")
    even_older = even_older.replace(
        json.loads(older)["ocsf"]["metadata"]["uid"], "re1-" + "e" * 32
    )
    before = await _case_event_types(case.id)
    assert (await post_batch(client, uplink, [line(even_older)])).json()["updated"] == 1
    assert len(await _case_event_types(case.id)) == len(before) + 1


# --- set-based upsert: per-line semantics, concurrency ----------------------------


def _mixed_lines() -> list[bytes]:
    """Creates, updates, duplicates, older emissions and a bad line, interleaved."""
    a1 = synth_finding(label="mix-a", count=1, severity="low")
    a3 = synth_finding(label="mix-a", count=3, severity="medium")
    a2 = synth_finding(label="mix-a", count=2, severity="critical")
    b1 = synth_finding(label="mix-b", count=1)
    b2 = synth_finding(label="mix-b", count=2)
    c1 = synth_finding(label="mix-c", count=1, severity="high")
    return [
        line(a1),
        line(b1),
        line(a3),
        b"{not json",
        line(a3),
        line(a2),
        line(c1),
        line(b2),
        line(b1),
        line(a1),
    ]


async def _case_state(ws: Workspace) -> dict[str, Any]:
    """Every finding of ``ws`` with its case, case fields and case events."""
    state: dict[str, Any] = {}
    async with get_async_session_context_manager() as session:
        fields_service = CaseFieldsService(session, role=admin_role(ws))
        for finding in await _findings(ws):
            case = await _case(finding.case_id)
            fields = await fields_service.get_fields(case)
            assert fields is not None
            events = (
                await session.execute(
                    select(CaseEvent.type, CaseEvent.data)
                    .where(CaseEvent.case_id == case.id)
                    .order_by(CaseEvent.surrogate_id)
                )
            ).all()
            emissions = (
                await session.scalars(
                    select(RobotFindingEvent.event_uid)
                    .where(RobotFindingEvent.finding_fk == finding.id)
                    .order_by(RobotFindingEvent.surrogate_id)
                )
            ).all()
            state[finding.external_id] = {
                "finding": {
                    name: getattr(finding, name)
                    for name in (
                        "occurrence_count",
                        "severity_id",
                        "first_seen",
                        "last_seen",
                        "last_event_uid",
                        "raw_value",
                        "rule_id",
                        "signature_key_id",
                    )
                },
                "emissions": list(emissions),
                "case": (
                    case.summary,
                    case.description,
                    case.severity,
                    case.priority,
                    case.status,
                    case.payload,
                ),
                "fields": {
                    k: v
                    for k, v in fields.items()
                    if k not in {"id", "case_id", "created_at", "updated_at"}
                },
                # The tag id is per workspace; everything else must match.
                "events": [
                    (t, {k: v for k, v in d.items() if k != "tag_id"})
                    for t, d in events
                ],
            }
    return state


async def test_one_batch_equals_its_lines_one_by_one(
    client: httpx.AsyncClient,
    workspace: Workspace,
    other_workspace: Workspace,
    uplink: RoboKey,
) -> None:
    """The set-based upsert yields exactly the per-line outcomes and effects."""
    relay = key(f"relay-{other_workspace.id}")
    await register_robot(other_workspace, "ugv-001")
    await register_key(other_workspace, relay, RobotKeyRole.RELAY)
    lines = _mixed_lines()

    batched = (await post_batch(client, uplink, lines)).json()
    singles = [(await post_batch(client, relay, [raw])).json() for raw in lines]

    for key_name in ("accepted", "created", "updated", "duplicates"):
        assert batched[key_name] == sum(s[key_name] for s in singles), key_name
    assert (batched["created"], batched["updated"], batched["duplicates"]) == (3, 3, 3)
    assert [r["line"] for r in batched["rejected"]] == [4]
    assert batched["rejected"][0]["code"] == singles[3]["rejected"][0]["code"]

    assert await _case_state(workspace) == await _case_state(other_workspace)
    async with get_async_session_context_manager() as session:
        numbers = (
            await session.scalars(
                select(Case.case_number)
                .where(Case.workspace_id == workspace.id)
                .order_by(Case.case_number)
            )
        ).all()
    assert list(numbers) == [1, 2, 3]


async def test_concurrent_batches_on_the_same_findings(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    """Overlapping batches in opposite orders neither deadlock nor duplicate."""
    for round_ in range(3):
        a1, a2 = (synth_finding(label=f"race-a-{round_}", count=c) for c in (1, 2))
        b1, b2 = (synth_finding(label=f"race-b-{round_}", count=c) for c in (1, 2))
        first, second = await asyncio.gather(
            post_batch(client, uplink, [line(a1), line(b1), line(a2)]),
            post_batch(client, uplink, [line(b2), line(a2), line(b1)]),
        )
        assert first.status_code == second.status_code == 200, (
            first.text,
            second.text,
        )
        results = [first.json(), second.json()]
        assert sum(r["created"] for r in results) == 2
        assert sum(r["accepted"] for r in results) == 6
        # Every emission is recorded once: 4 distinct events, 2 duplicates.
        assert sum(r["created"] + r["updated"] for r in results) == 4
    findings = await _findings(workspace)
    assert len(findings) == 6
    assert len({f.case_id for f in findings}) == 6
    assert all(f.occurrence_count == 2 for f in findings)


async def test_a_deleted_case_is_reopened(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    first = synth_finding(label="reopen", count=1)
    again = synth_finding(label="reopen", count=2)
    assert (await post_batch(client, uplink, [line(first)])).json()["created"] == 1
    [finding] = await _findings(workspace)
    async with get_async_session_context_manager() as session:
        await session.execute(delete(Case).where(Case.id == finding.case_id))
        await session.commit()
    response = (await post_batch(client, uplink, [line(again), line(again)])).json()
    assert (response["updated"], response["duplicates"]) == (1, 1)
    [finding] = await _findings(workspace)
    case = await _case(finding.case_id)
    assert case.case_number == 2
    assert await _case_event_types(case.id) == [
        CaseEventType.CASE_CREATED,
        CaseEventType.TAG_ADDED,
    ]


# --- 401 / audit -----------------------------------------------------------------------


async def test_authentication_failures_are_401_and_audited(
    client: httpx.AsyncClient,
    workspace: Workspace,
    uplink: RoboKey,
    audit_capture: AuditCapture,
) -> None:
    value = line(synth_finding(label="auth"))
    stranger = key("never-registered")
    revoked = key(f"revoked-{workspace.id}")
    expired = key(f"expired-{workspace.id}")
    finding_only = key(f"finding-only-{workspace.id}")
    revoked_id = await register_key(workspace, revoked, RobotKeyRole.UPLINK, "ugv-001")
    async with get_async_session_context_manager() as session:
        service = RobotsService(session, role=admin_role(workspace))
        revoked_key, _ = await service.get_key(revoked_id)
        await service.revoke_key(revoked_key)
    await register_key(
        workspace,
        expired,
        RobotKeyRole.UPLINK,
        "ugv-001",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    await register_key(workspace, finding_only, RobotKeyRole.FINDING, "ugv-001")

    now_ms = int(time.time() * 1000)
    cases: list[tuple[httpx.Response, str, str]] = [
        (await post_batch(client, stranger, [value]), "unknown_key", "unknown_key"),
        (await post_batch(client, revoked, [value]), "unknown_key", "revoked_key"),
        (await post_batch(client, expired, [value]), "unknown_key", "expired_key"),
        (await post_batch(client, finding_only, [value]), "unknown_key", "wrong_role"),
        (
            await post_batch(client, uplink, [value], timestamp_ms=now_ms - 301_000),
            "stale_timestamp",
            "stale_timestamp",
        ),
        (
            await post_batch(client, uplink, [value], timestamp_ms=now_ms + 301_000),
            "stale_timestamp",
            "stale_timestamp",
        ),
    ]
    # Tampered body: signed over different bytes.
    body = body_of([value])
    headers = signed_headers(uplink, "tampered", body)
    tampered = await client.post(INGEST, content=body + b"\n", headers=headers)
    cases.append((tampered, "bad_signature", "bad_signature"))

    for response, code, _ in cases:
        assert response.status_code == 401, response.text
        assert response.json()["code"] == code
    reasons = [
        e.data.get("failure_reason") if e.data else None for e in audit_capture.events
    ]
    assert reasons == [reason for _, _, reason in cases]
    assert all(
        e.status == "FAILURE" and e.actor_type == "ROBOT" for e in audit_capture.events
    )
    assert all(e.ip_address == "127.0.0.1" for e in audit_capture.events)
    # Known keys are audited in their workspace; unknown ones on the platform sink.
    assert audit_capture.events[0].workspace_id is None
    assert audit_capture.events[1].workspace_id == workspace.id
    assert await _findings(workspace) == []


async def test_successful_batch_is_audited(
    client: httpx.AsyncClient,
    workspace: Workspace,
    uplink: RoboKey,
    audit_capture: AuditCapture,
) -> None:
    await post_batch(client, uplink, [line(synth_finding(label="audited"))])
    [event] = [e for e in audit_capture.events if e.resource_type == "robot_ingest"]
    assert event.status == "SUCCESS"
    assert event.data == {
        "sender_key_id": uplink.key_id,
        "batch_id": event.data["batch_id"] if event.data else None,
        "created_count": 1,
        "updated_count": 0,
        "duplicate_count": 0,
        "rejected_count": 0,
    }


# --- request-level limits ------------------------------------------------------------


async def test_content_type_and_size_limits(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    body = body_of([line(synth_finding(label="limits"))])
    headers = signed_headers(uplink, "ct", body)
    for content_type in ("application/x-ndjson; charset=utf-8", "application/json"):
        response = await client.post(
            INGEST, content=body, headers={**headers, "Content-Type": content_type}
        )
        assert response.status_code == 415
        assert response.json()["code"] == "unsupported_media_type"

    big = b"x" * (4 * 1024 * 1024 + 1)
    response = await client.post(
        INGEST, content=big, headers=signed_headers(uplink, "big", big)
    )
    assert response.status_code == 413
    assert response.json()["code"] == "body_too_large"

    async def _stream() -> AsyncGenerator[bytes, None]:
        for _ in range(5):
            yield b"y" * (1024 * 1024)

    response = await client.post(
        INGEST, content=_stream(), headers=signed_headers(uplink, "streamed", b"")
    )
    assert response.status_code == 413

    many = body_of([b"{}"] * 1001)
    response = await client.post(
        INGEST, content=many, headers=signed_headers(uplink, "many", many)
    )
    assert response.status_code == 413
    assert response.json()["code"] == "too_many_lines"

    bad_headers: list[dict[str, str]] = [
        signed_headers(uplink, "bad batch id!", body),
        {**headers, "X-RoboDR-Key-Id": "ed25519:XYZ"},
        {**headers, "X-RoboDR-Timestamp": "0" + headers["X-RoboDR-Timestamp"]},
        {k: v for k, v in headers.items() if k != "X-RoboDR-Signature"},
    ]
    for bad in bad_headers:
        response = await client.post(INGEST, content=body, headers=bad)
        assert response.status_code == 400
        assert response.json()["code"] == "bad_header"
    # A repeated header is refused too.
    repeated = list(headers.items()) + [("X-RoboDR-Batch-Id", "ct")]
    response = await client.post(INGEST, content=body, headers=repeated)
    assert response.status_code == 400
    assert response.json()["code"] == "bad_header"
    response = await client.post(
        INGEST, content=b"", headers=signed_headers(uplink, "e", b"")
    )
    assert response.status_code == 400
    assert response.json()["code"] == "empty_batch"
    upper = {**headers, "Content-Type": "Application/X-NDJSON"}
    assert (await client.post(INGEST, content=body, headers=upper)).status_code == 200


async def test_rate_limit_returns_429_with_retry_after(
    client: httpx.AsyncClient,
    workspace: Workspace,
    uplink: RoboKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rate_limit, "BURST", 2)
    monkeypatch.setattr(rate_limit, "_RATE_PER_SECOND", 0.01)
    one = [line(synth_finding(label="rate"))]
    statuses = [(await post_batch(client, uplink, one)).status_code for _ in range(3)]
    assert statuses == [200, 200, 429]
    limited = await post_batch(client, uplink, one)
    assert limited.json()["code"] == "rate_limited"
    assert int(limited.headers["Retry-After"]) >= 1


async def test_rate_limit_falls_back_in_process_without_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _broken() -> Any:
        raise ConnectionError("redis down")

    monkeypatch.setattr(rate_limit, "get_redis_client", _broken)
    monkeypatch.setattr(rate_limit, "BURST", 1)
    sender = uuid.uuid4()
    assert (await rate_limit.take_batch_token(sender)).allowed
    decision = await rate_limit.take_batch_token(sender)
    assert not decision.allowed and decision.retry_after_seconds >= 1


async def test_entitlement_is_required(
    client: httpx.AsyncClient,
    workspace: Workspace,
    uplink: RoboKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tier_defaults, "DEFAULT_ENTITLEMENTS", tier_defaults.BASELINE_ENTITLEMENTS
    )
    response = await post_batch(client, uplink, [line(synth_finding(label="ent"))])
    assert response.status_code == 403
    assert response.json() == {
        "code": "not_entitled",
        "detail": "Robot EDR is not enabled for this workspace",
    }


async def test_batch_id_reuse_with_another_body_is_409(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    first = await post_batch(
        client, uplink, [line(synth_finding(label="one"))], batch_id="reuse"
    )
    assert first.status_code == 200
    second = await post_batch(
        client, uplink, [line(synth_finding(label="two"))], batch_id="reuse"
    )
    assert second.status_code == 409
    assert second.json()["code"] == "batch_id_reuse"
    assert len(await _findings(workspace)) == 1


async def test_failed_batch_leaves_nothing_behind(
    client: httpx.AsyncClient,
    workspace: Workspace,
    uplink: RoboKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ingest_module._BatchUpsert._write

    async def _fail_after_writes(self: Any, *args: Any) -> None:
        # Every effect of the batch is written, then the transaction fails.
        await original(self, *args)
        raise RuntimeError("database went away")

    monkeypatch.setattr(ingest_module._BatchUpsert, "_write", _fail_after_writes)
    lines = [line(synth_finding(label="tx-a")), line(synth_finding(label="tx-b"))]
    with pytest.raises(RuntimeError):
        await post_batch(client, uplink, lines, batch_id="atomic")
    assert await _findings(workspace) == []
    async with get_async_session_context_manager() as session:
        cases = await session.scalar(
            select(func.count())
            .select_from(Case)
            .where(Case.workspace_id == workspace.id)
        )
    assert cases == 0
    monkeypatch.setattr(ingest_module._BatchUpsert, "_write", original)
    retried = await post_batch(client, uplink, lines, batch_id="atomic")
    assert retried.json()["created"] == 2 and retried.json()["replayed"] is False


async def test_old_batches_are_purged(workspace: Workspace, uplink: RoboKey) -> None:
    async with get_async_session_context_manager() as session:
        key_row = await session.scalar(
            select(RobotKey).where(RobotKey.key_id == uplink.key_id)
        )
        assert key_row is not None
        session.add(
            RobotIngestBatch(
                workspace_id=workspace.id,
                sender_key_fk=key_row.id,
                batch_id="ancient",
                body_sha256="0" * 64,
                response={"batch_id": "ancient"},
                created_at=datetime.now(UTC) - timedelta(days=8),
            )
        )
        await session.commit()
    assert await ingest_module.purge_expired_batches() >= 1
    async with get_async_session_context_manager() as session:
        assert (
            await session.scalar(
                select(RobotIngestBatch).where(RobotIngestBatch.batch_id == "ancient")
            )
        ) is None


# --- taint in case text --------------------------------------------------------------


async def test_injection_corpus_never_reaches_case_text_unescaped(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    entries = [e for e in producer_entries() if e["name"].startswith("injection_")]
    response = await post_batch(client, uplink, [line(e["value"]) for e in entries])
    assert response.json()["created"] == len(entries)
    findings = {f.external_id: f for f in await _findings(workspace)}
    for entry in entries:
        external_id = json.loads(entry["value"])["external_id"]
        case = await _case(findings[external_id].case_id)
        raw: str = entry["raw"]
        for text in (case.summary, case.description, json.dumps(case.payload)):
            assert raw not in text
            assert "\r" not in text and "\x1b" not in text and "\u202e" not in text
        prose = re.sub(r"`[^`\n]*`", "", case.description)
        for needle in ("SYSTEM:", "</", "<", "assistant:", "benign"):
            assert needle not in prose
        # The stored case is exactly the registry's mapping of the value.
        mapped = finding_to_case_fields(entry["value"])
        assert case.payload == mapped["payload"]
        assert case.description == mapped["description"]
        assert case.summary == mapped["summary"]


async def test_cases_are_tagged_robodr(
    client: httpx.AsyncClient, workspace: Workspace, uplink: RoboKey
) -> None:
    for label in ("tag-a", "tag-b"):
        await post_batch(client, uplink, [line(synth_finding(label=label))])
    async with get_async_session_context_manager() as session:
        tags = (
            await session.execute(
                select(CaseTag.ref, func.count(CaseTagLink.case_id))
                .join(CaseTagLink, CaseTagLink.tag_id == CaseTag.id)
                .where(CaseTag.workspace_id == workspace.id)
                .group_by(CaseTag.ref)
            )
        ).all()
    assert [tuple(t) for t in tags] == [("robodr", 2)]
    [finding, *_] = await _findings(workspace)
    assert finding.case_id is not None
    assert CaseEventType.TAG_ADDED in await _case_event_types(finding.case_id)


# --- isolation -------------------------------------------------------------------------


async def test_workspaces_are_isolated(
    client: httpx.AsyncClient,
    workspace: Workspace,
    other_workspace: Workspace,
    uplink: RoboKey,
) -> None:
    other_relay = key(f"relay-{other_workspace.id}")
    await register_robot(other_workspace, "ugv-001")
    await register_key(other_workspace, other_relay, RobotKeyRole.RELAY)

    value = synth_finding(label="shared-id")
    assert (await post_batch(client, uplink, [line(value)])).json()["created"] == 1
    # The same external id in another workspace is another finding and case.
    assert (await post_batch(client, other_relay, [line(value)])).json()["created"] == 1
    [mine] = await _findings(workspace)
    [theirs] = await _findings(other_workspace)
    assert mine.case_id != theirs.case_id
    assert (await _case(theirs.case_id)).workspace_id == other_workspace.id

    # A sender key is registered in one workspace only.
    with pytest.raises(Exception, match="already registered"):
        await register_key(other_workspace, uplink, RobotKeyRole.RELAY)


@pytest.mark.usefixtures("db")
async def test_row_level_security_policies_isolate_workspaces() -> None:
    schema_role = f"robot_rls_{uuid.uuid4().hex}"
    ws_a, ws_b, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    url = TEST_DB_CONFIG.test_url_sync.replace("+psycopg", "")
    with psycopg.connect(url) as conn:
        try:
            conn.execute("SET LOCAL session_replication_role = replica")
            for table in ("robot", "robot_key", "robot_finding", "robot_ingest_batch"):
                conn.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
                conn.execute(f'DROP POLICY IF EXISTS rls_policy_{table} ON "{table}"')
                conn.execute(enable_workspace_table_rls(table).encode())
            for ws in (ws_a, ws_b):
                conn.execute(
                    "INSERT INTO robot (id, workspace_id, robot_id, require_finding_signature)"
                    " VALUES (%s, %s, 'ugv-001', false)",
                    (uuid.uuid4(), ws),
                )
            conn.execute(
                sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(schema_role))
            )
            conn.execute(
                sql.SQL("GRANT ALL ON robot, robot_key, robot_finding TO {}").format(
                    sql.Identifier(schema_role)
                )
            )
            conn.execute(
                sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(schema_role))
            )
            conn.execute("SELECT set_config('app.rls_bypass', 'off', true)")
            conn.execute(
                "SELECT set_config('app.current_workspace_id', %s, true)", (str(ws_a),)
            )
            rows = conn.execute("SELECT workspace_id FROM robot").fetchall()
            assert rows == [(ws_a,)]
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(
                        "INSERT INTO robot (id, workspace_id, robot_id, require_finding_signature)"
                        " VALUES (%s, %s, 'ugv-x', false)",
                        (uuid.uuid4(), ws_b),
                    )
            assert (
                conn.execute(
                    "UPDATE robot SET site = 'x' WHERE workspace_id = %s", (ws_b,)
                ).rowcount
                == 0
            )
            assert org  # org id unused: workspace policies need no org context
        finally:
            conn.rollback()


# --- management API ---------------------------------------------------------------------


class _RoleHolder:
    def __init__(self, role: Role) -> None:
        self.role = role


@pytest.fixture
async def mgmt(
    workspace: Workspace,
) -> AsyncGenerator[tuple[httpx.AsyncClient, _RoleHolder], None]:
    holder = _RoleHolder(admin_role(workspace))
    app = FastAPI()
    app.include_router(management_router)
    role_dependency = get_args(WorkspaceActorRouteRole)[1].dependency
    app.dependency_overrides[role_dependency] = lambda: holder.role

    async def _denied(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    async def _entitlement(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, EntitlementRequired)
        return JSONResponse(status_code=403, content={"entitlement": exc.entitlement})

    async def _not_found(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    app.add_exception_handler(TracecatNotFoundError, _not_found)
    app.add_exception_handler(ScopeDeniedError, _denied)
    app.add_exception_handler(EntitlementRequired, _entitlement)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c, holder


async def test_management_crud_and_revoke(
    mgmt: tuple[httpx.AsyncClient, _RoleHolder],
    workspace: Workspace,
    client: httpx.AsyncClient,
) -> None:
    api, _ = mgmt
    created = await api.post(
        "/robot-edr/robots", json={"robot_id": "ugv-001", "model": "ugv-tracked-v1"}
    )
    assert created.status_code == 201, created.text
    robot = created.json()
    assert (
        await api.post("/robot-edr/robots", json={"robot_id": "ugv-001"})
    ).status_code == 409
    patched = await api.patch(
        f"/robot-edr/robots/{robot['id']}", json={"require_finding_signature": True}
    )
    assert patched.json()["require_finding_signature"] is True
    listed = await api.get("/robot-edr/robots")
    assert [r["robot_id"] for r in listed.json()["items"]] == ["ugv-001"]

    signer = key(f"mgmt-{workspace.id}")
    created_key = await api.post(
        "/robot-edr/keys",
        json={
            "role": "uplink",
            "robot_id": "ugv-001",
            "public_key": signer.public.hex(),
        },
    )
    assert created_key.status_code == 201, created_key.text
    key_body = created_key.json()
    assert key_body["key_id"] == signer.key_id
    assert key_body["robot_id"] == "ugv-001"

    for bad in (
        {"role": "relay", "robot_id": "ugv-001", "public_key": key("x").public.hex()},
        {"role": "uplink", "public_key": key("y").public.hex()},
        {"role": "uplink", "robot_id": "ugv-001", "public_key": "01" + "00" * 31},
        {
            "role": "uplink",
            "robot_id": "ugv-001",
            "public_key": key("z").public.hex(),
            "key_id": "ed25519:0000000000000000",
        },
    ):
        response = await api.post("/robot-edr/keys", json=bad)
        assert response.status_code in (400, 422), response.text

    keys = await api.get("/robot-edr/keys", params={"robot_id": robot["id"]})
    assert [k["id"] for k in keys.json()["items"]] == [key_body["id"]]

    revoked = await api.post(f"/robot-edr/keys/{key_body['id']}/revoke")
    assert revoked.json()["revoked_at"] is not None
    response = await post_batch(client, signer, [line(synth_finding(label="r"))])
    assert response.status_code == 401

    assert (await api.delete(f"/robot-edr/keys/{key_body['id']}")).status_code == 204
    assert (await api.delete(f"/robot-edr/robots/{robot['id']}")).status_code == 204
    assert (await api.get(f"/robot-edr/robots/{robot['id']}")).status_code == 404


async def test_management_scopes_and_entitlement(
    mgmt: tuple[httpx.AsyncClient, _RoleHolder],
    workspace: Workspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, holder = mgmt
    holder.role = admin_role(workspace, VIEWER_SCOPES)
    assert (await api.get("/robot-edr/robots")).status_code == 200
    denied = await api.post("/robot-edr/robots", json={"robot_id": "ugv-001"})
    assert denied.status_code == 403

    monkeypatch.setattr(
        tier_defaults, "DEFAULT_ENTITLEMENTS", tier_defaults.BASELINE_ENTITLEMENTS
    )
    response = await api.get("/robot-edr/robots")
    assert response.status_code == 403
    assert response.json() == {"entitlement": "robot_edr"}


# --- transport ---------------------------------------------------------------------------


def _request(scheme: str, peer: str, headers: dict[str, str] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "scheme": scheme,
            "method": "POST",
            "path": INGEST,
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
            ],
            "client": (peer, 1234),
            "server": ("api", 8000),
        }
    )


@pytest.mark.parametrize(
    ("scheme", "peer", "headers", "expected"),
    [
        ("https", "203.0.113.7", {}, True),
        ("http", "127.0.0.1", {}, True),
        ("http", "203.0.113.7", {}, False),
        (
            "http",
            "172.18.0.5",
            {"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"},
            True,
        ),
        (
            "http",
            "172.18.0.5",
            {"X-Forwarded-Proto": "http", "X-Forwarded-For": "203.0.113.7"},
            False,
        ),
        ("http", "203.0.113.9", {"X-Forwarded-Proto": "https"}, False),
    ],
)
def test_tls_requirement(
    scheme: str, peer: str, headers: dict[str, str], expected: bool
) -> None:
    assert arrived_over_tls(_request(scheme, peer, headers)) is expected


async def test_route_is_public_in_the_full_app() -> None:
    from autosecops.api.app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        signer = key("full-app")
        body = body_of([line("{}")])
        response = await c.post(
            INGEST, content=body, headers=signed_headers(signer, "full-app", body)
        )
    # Reached the ingest pipeline: no session, cookie or API key was asked for.
    assert response.status_code == 401
    assert response.json()["code"] == "unknown_key"
