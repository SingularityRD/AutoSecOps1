"""Run the shared `robodr.ingest` contract vectors against the ingest route.

`tests/data/robot_edr/ingest_vectors/` is a copy of the RoboDR repository's
`docs/contracts/fixtures/ingest/` (`manifest.json` and `cases/`), generated
by `cargo run -p robodr-export --example ingest_vectors`. The test keys'
secret files are not copied: registering a key needs only its public half,
which the manifest carries.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete

from autosecops import config
from autosecops.audit.service import AuditService
from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES
from autosecops.db.engine import get_async_session_context_manager
from autosecops.db.models import Organization, Workspace
from autosecops.robot_edr import ingest as ingest_module
from autosecops.robot_edr import rate_limit
from autosecops.robot_edr.ingest_router import router as ingest_router
from autosecops.robot_edr.schemas import RobotCreate, RobotKeyCreate
from autosecops.robot_edr.service import RobotsService
from autosecops.robot_edr.types import RobotKeyRole
from autosecops.tiers import defaults as tier_defaults

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]

VECTORS = Path(__file__).parents[1] / "data" / "robot_edr" / "ingest_vectors"
MANIFEST: dict[str, Any] = json.loads((VECTORS / "manifest.json").read_text())


@pytest.fixture(autouse=True)
def robot_edr_entitled(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(update={"robot_edr": True}),
    )

    async def _no_webhook(self: AuditService) -> None:
        return None

    monkeypatch.setattr(AuditService, "_get_webhook_url", _no_webhook)
    rate_limit._local_buckets.clear()
    yield


async def _new_workspace(org_id: uuid.UUID) -> Workspace:
    ws = Workspace(
        id=uuid.uuid4(), name=f"vectors-{uuid.uuid4().hex[:8]}", organization_id=org_id
    )
    async with get_async_session_context_manager() as session:
        session.add(ws)
        await session.commit()
    return ws


async def _drop_workspace(ws: Workspace) -> None:
    async with get_async_session_context_manager() as session:
        await session.execute(delete(Workspace).where(Workspace.id == ws.id))
        await session.commit()


async def _register_manifest_workspace(ws: Workspace) -> None:
    role = Role(
        type="service",
        service_id="tracecat-api",
        workspace_id=ws.id,
        organization_id=ws.organization_id,
        scopes=ADMIN_SCOPES,
    )
    async with get_async_session_context_manager() as session:
        service = RobotsService(session, role=role)
        for robot in MANIFEST["workspace"]["robots"]:
            await service.create_robot(
                RobotCreate(
                    robot_id=robot["id"],
                    site=robot.get("site"),
                    require_finding_signature=robot["require_finding_signature"],
                )
            )
        for entry in MANIFEST["keys"]:
            if entry["role"] not in {r.value for r in RobotKeyRole}:
                continue
            created = await service.create_key(
                RobotKeyCreate(
                    role=RobotKeyRole(entry["role"]),
                    robot_id=entry["robot"] if entry["role"] != "relay" else None,
                    public_key=entry["public_key_hex"],
                    key_id=entry["key_id"],
                    site=entry.get("site"),
                    vouches_origin=bool(entry.get("vouches_origin", False)),
                )
            )
            assert created.key_id == entry["key_id"]


def _compare(expected: dict[str, Any], response: httpx.Response, where: str) -> None:
    assert response.status_code == expected["status"], (where, response.text)
    body = response.json()
    want = expected["body"]
    if expected["status"] != 200:
        assert body["code"] == want["code"], where
        return
    got_rejected = [{"line": r["line"], "code": r["code"]} for r in body["rejected"]]
    assert got_rejected == want["rejected"], where
    for key, value in want.items():
        if key != "rejected":
            assert body[key] == value, (where, key)


async def test_every_contract_vector(
    svc_organization: Organization, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each case runs in a fresh workspace holding the manifest's robots and keys.

    One test runs every case in turn: the manifest's sender keys may be
    registered in one workspace at a time (contract §3, AutoSecOps keeps
    active sender keys unique across workspaces).
    """
    app = FastAPI()
    app.include_router(ingest_router)
    transport = httpx.ASGITransport(app=app)
    for case in MANIFEST["cases"]:
        rate_limit._local_buckets.clear()
        workspace = await _new_workspace(svc_organization.id)
        try:
            await _register_manifest_workspace(workspace)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                for request_path in case["requests"]:
                    await _run_request(client, request_path, monkeypatch)
        finally:
            await _drop_workspace(workspace)


async def _run_request(
    client: httpx.AsyncClient, request_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = VECTORS / request_path
    request = json.loads(base.with_name(base.name + ".request.json").read_text())
    expected = json.loads(base.with_name(base.name + ".response.json").read_text())
    body = (base.parent / request["body_file"]).read_bytes()
    assert hashlib.sha256(body).hexdigest() == request["body_sha256"]
    server_time = request["server_time_ms"]
    monkeypatch.setattr(ingest_module, "now_ms", lambda: server_time)
    response = await client.request(
        request["method"],
        request["path"],
        content=body,
        headers=[(name, value) for name, value in request["headers"]],
    )
    _compare(expected, response, request_path)
