"""Opt-in latency benchmark for `POST /robot-edr/v2/ingest`.

For each batch size, ingests 10 000 new findings as signed batches (every line
a new finding and a new case: the worst case), then the same findings again
as new emissions (every line an update), and reports per-batch latency. The
default sizes are 50 lines and the contract maximum of 1000 lines; findings
are compact (about 3.7 KiB, the optional ROS names dropped) so that 1000 of
them fit the 4 MiB body cap.

Acceptance (Gate 1): p95 below 2 s per batch at 10 000 findings per hour, for
both sizes. Set AUTOSECOPS_ROBOT_EDR_BENCHMARK_ASSERT=1 to fail when a phase's
p95 exceeds that budget; by default the benchmark only reports.

Run with:

    AUTOSECOPS_RUN_ROBOT_EDR_BENCHMARK=1 \
    uv run pytest tests/integration/test_robot_edr_ingest_benchmark.py -s

Tune with AUTOSECOPS_ROBOT_EDR_BENCHMARK_BATCH_SIZES (comma-separated, default
``50,1000``) and AUTOSECOPS_ROBOT_EDR_BENCHMARK_FINDINGS (findings per size,
default 10 000). The benchmark calls ``freeze_startup_heap()`` first, as the
API lifespan does after start-up, so full collections skip the start-up
objects; AUTOSECOPS_ROBOT_EDR_BENCHMARK_GC_FREEZE=0 measures without it (full
collections then cost about 0.45 s each, every few 1000-line batches).
"""

from __future__ import annotations

import os
import statistics
import time
import uuid
from collections.abc import AsyncGenerator, Iterator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete

from autosecops import config
from autosecops.api.lifespan import freeze_startup_heap, unfreeze_startup_heap
from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES
from autosecops.db.engine import get_async_session_context_manager
from autosecops.db.models import Organization, Workspace
from autosecops.robot_edr import rate_limit
from autosecops.robot_edr.ingest import MAX_BODY_BYTES
from autosecops.robot_edr.ingest_router import router as ingest_router
from autosecops.robot_edr.schemas import RobotCreate, RobotKeyCreate
from autosecops.robot_edr.service import RobotsService
from autosecops.robot_edr.types import RobotKeyRole
from autosecops.tiers import defaults as tier_defaults
from tests._robot_edr_utils import body_of, key, line, signed_headers, synth_finding

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.slow,
    pytest.mark.usefixtures("db"),
    pytest.mark.skipif(
        os.environ.get("AUTOSECOPS_RUN_ROBOT_EDR_BENCHMARK") != "1",
        reason="set AUTOSECOPS_RUN_ROBOT_EDR_BENCHMARK=1 to run",
    ),
]

BATCH_SIZES = [
    int(size)
    for size in (
        os.environ.get("AUTOSECOPS_ROBOT_EDR_BENCHMARK_BATCH_SIZES") or "50,1000"
    ).split(",")
]
FINDINGS = int(os.environ.get("AUTOSECOPS_ROBOT_EDR_BENCHMARK_FINDINGS") or 10_000)
P95_BUDGET_SECONDS = 2.0
ROBOTS = [f"ugv-{i:03d}" for i in range(10)]


@pytest.fixture
async def workspace(svc_organization: Organization) -> AsyncGenerator[Workspace, None]:
    ws = Workspace(
        id=uuid.uuid4(),
        name=f"bench-{uuid.uuid4().hex[:8]}",
        organization_id=svc_organization.id,
    )
    async with get_async_session_context_manager() as session:
        session.add(ws)
        await session.commit()
    try:
        yield ws
    finally:
        async with get_async_session_context_manager() as session:
            await session.execute(delete(Workspace).where(Workspace.id == ws.id))
            await session.commit()


@pytest.fixture
def gc_frozen() -> Iterator[None]:
    """``gc.freeze()`` as the API lifespan does after start-up.

    Set AUTOSECOPS_ROBOT_EDR_BENCHMARK_GC_FREEZE=0 to measure without it.
    """
    if os.environ.get("AUTOSECOPS_ROBOT_EDR_BENCHMARK_GC_FREEZE") == "0":
        yield
        return
    freeze_startup_heap()
    try:
        yield
    finally:
        unfreeze_startup_heap()


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, int(round(0.95 * len(ordered))) - 1)]


def _batch_body(size: int, batch: int, count: int) -> bytes:
    lines = [
        line(
            synth_finding(
                robot_id=ROBOTS[n % len(ROBOTS)],
                label=f"bench-{size}-{batch}-{n}",
                count=count,
                compact=True,
            )
        )
        for n in range(size)
    ]
    body = body_of(lines)
    assert len(body) <= MAX_BODY_BYTES
    return body


@pytest.mark.usefixtures("gc_frozen")
async def test_ingest_latency(
    workspace: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(update={"robot_edr": True}),
    )
    # Batches go back to back, far above 10 000 findings per hour; lift the
    # burst so the limiter (still consulted) does not refuse them.
    monkeypatch.setattr(rate_limit, "BURST", 100_000)
    rate_limit._local_buckets.clear()
    signer = key(f"bench-relay-{workspace.id}")
    role = Role(
        type="service",
        service_id="autosecops-api",
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        scopes=ADMIN_SCOPES,
    )
    async with get_async_session_context_manager() as session:
        service = RobotsService(session, role=role)
        for robot in ROBOTS:
            await service.create_robot(RobotCreate(robot_id=robot))
        await service.create_key(
            RobotKeyCreate(role=RobotKeyRole.RELAY, public_key=signer.public.hex())
        )

    app = FastAPI()
    app.include_router(ingest_router)
    transport = httpx.ASGITransport(app=app)
    results: dict[tuple[int, str], list[float]] = {}
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", timeout=120
    ) as client:
        for size in BATCH_SIZES:
            batches = max(1, FINDINGS // size)
            for phase, count in (("create", 1), ("update", 2)):
                latencies = results.setdefault((size, phase), [])
                for batch in range(batches):
                    body = _batch_body(size, batch, count)
                    headers = signed_headers(signer, f"{size}-{phase}-{batch}", body)
                    started = time.perf_counter()
                    response = await client.post(
                        "/robot-edr/v2/ingest", content=body, headers=headers
                    )
                    latencies.append(time.perf_counter() - started)
                    assert response.status_code == 200, response.text
                    payload = response.json()
                    assert payload["rejected"] == []
                    assert payload[f"{phase}d"] == size

    for (size, phase), latencies in results.items():
        print(
            f"robot-edr ingest {phase}: {len(latencies)} x {size} findings; "
            f"p50 {statistics.median(latencies):.3f}s "
            f"p95 {_p95(latencies):.3f}s max {max(latencies):.3f}s "
            f"({size / statistics.median(latencies):.0f} findings/s)"
        )
    if os.environ.get("AUTOSECOPS_ROBOT_EDR_BENCHMARK_ASSERT") == "1":
        for (size, phase), latencies in results.items():
            assert _p95(latencies) < P95_BUDGET_SECONDS, (size, phase)
