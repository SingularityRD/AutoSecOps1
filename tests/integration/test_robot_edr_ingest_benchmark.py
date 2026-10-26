"""Opt-in latency benchmark for `POST /robot-edr/v2/ingest`.

Ingests 10 000 new findings as 100 signed batches of 100 lines (every line a
new finding and a new case: the worst case), then the same findings again as
new emissions (every line an update), and reports per-batch latency.
Acceptance (Gate 1): p95 below 2 s per batch at 10 000 findings per hour.
Set TRACECAT_ROBOT_EDR_BENCHMARK_ASSERT=1 to fail when a phase's p95 exceeds
that budget; by default the benchmark reports only, because the latency of a
batch grows with its number of lines (about 30 ms per new finding and 20 ms
per update on a developer machine) and the producer sends whatever is queued.

Run with:

    TRACECAT_RUN_ROBOT_EDR_BENCHMARK=1 \
    uv run pytest tests/integration/test_robot_edr_ingest_benchmark.py -s

Tune with TRACECAT_ROBOT_EDR_BENCHMARK_BATCHES and
TRACECAT_ROBOT_EDR_BENCHMARK_BATCH_SIZE.
"""

from __future__ import annotations

import os
import statistics
import time
import uuid
from collections.abc import AsyncGenerator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete

from autosecops import config
from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES
from autosecops.db.engine import get_async_session_context_manager
from autosecops.db.models import Organization, Workspace
from autosecops.robot_edr import rate_limit
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
        os.environ.get("TRACECAT_RUN_ROBOT_EDR_BENCHMARK") != "1",
        reason="set TRACECAT_RUN_ROBOT_EDR_BENCHMARK=1 to run",
    ),
]

BATCHES = int(os.environ.get("TRACECAT_ROBOT_EDR_BENCHMARK_BATCHES") or 100)
BATCH_SIZE = int(os.environ.get("TRACECAT_ROBOT_EDR_BENCHMARK_BATCH_SIZE") or 100)
P95_BUDGET_SECONDS = 2.0


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


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, int(round(0.95 * len(ordered))) - 1)]


async def test_ingest_latency(
    workspace: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(update={"robot_edr": True}),
    )
    rate_limit._local_buckets.clear()
    signer = key(f"bench-relay-{workspace.id}")
    robots = [f"ugv-{i:03d}" for i in range(10)]
    role = Role(
        type="service",
        service_id="tracecat-api",
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        scopes=ADMIN_SCOPES,
    )
    async with get_async_session_context_manager() as session:
        service = RobotsService(session, role=role)
        for robot in robots:
            await service.create_robot(RobotCreate(robot_id=robot))
        await service.create_key(
            RobotKeyCreate(role=RobotKeyRole.RELAY, public_key=signer.public.hex())
        )

    app = FastAPI()
    app.include_router(ingest_router)
    transport = httpx.ASGITransport(app=app)
    results: dict[str, list[float]] = {"create": [], "update": []}
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", timeout=120
    ) as client:
        for phase, count in (("create", 1), ("update", 2)):
            for batch in range(BATCHES):
                lines = [
                    line(
                        synth_finding(
                            robot_id=robots[n % len(robots)],
                            label=f"bench-{batch}-{n}",
                            count=count,
                        )
                    )
                    for n in range(BATCH_SIZE)
                ]
                body = body_of(lines)
                headers = signed_headers(signer, f"{phase}-{batch}", body)
                started = time.perf_counter()
                response = await client.post(
                    "/robot-edr/v2/ingest", content=body, headers=headers
                )
                results[phase].append(time.perf_counter() - started)
                assert response.status_code == 200, response.text
                payload = response.json()
                assert payload["rejected"] == []
                assert payload[f"{phase}d"] == BATCH_SIZE

    for phase, latencies in results.items():
        print(
            f"robot-edr ingest {phase}: {BATCHES} x {BATCH_SIZE} findings; "
            f"p50 {statistics.median(latencies):.3f}s "
            f"p95 {_p95(latencies):.3f}s max {max(latencies):.3f}s "
            f"({BATCH_SIZE / statistics.median(latencies):.0f} findings/s)"
        )
    if os.environ.get("TRACECAT_ROBOT_EDR_BENCHMARK_ASSERT") == "1":
        assert _p95(results["create"]) < P95_BUDGET_SECONDS
        assert _p95(results["update"]) < P95_BUDGET_SECONDS
