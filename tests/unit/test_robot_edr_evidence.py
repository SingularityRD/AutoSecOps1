"""Storing verified RoboDR evidence exports for cases (robodr.control-plane §11).

Uses the shared contract vector export (`tests/data/robodr_control_plane_v2/`):
its manifest is signed by the vector finding key, registered here as the
robot's finding key.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, update

from autosecops import config
from autosecops.audit.enums import AuditEventActor, AuditEventStatus
from autosecops.audit.service import AuditService, AuditWriteError
from autosecops.audit.types import AuditEvent
from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES
from autosecops.cases.attachments.schemas import CaseAttachmentCreate
from autosecops.cases.attachments.service import CaseAttachmentService
from autosecops.cases.enums import CasePriority, CaseSeverity, CaseStatus
from autosecops.cases.schemas import CaseCreate
from autosecops.cases.service import CasesService
from autosecops.db.engine import get_async_session_context_manager
from autosecops.db.models import Case, Organization, RobotKey, Workspace
from autosecops.exceptions import AutoSecOpsNotFoundError, AutoSecOpsValidationError
from autosecops.executor.action_gateway.app import create_app as create_gateway_app
from autosecops.robot_edr.evidence import RobotEvidenceService
from autosecops.robot_edr.schemas import (
    EvidenceAccessRequest,
    EvidenceStoreRequest,
    RobotCreate,
    RobotKeyCreate,
)
from autosecops.robot_edr.service import RobotsService
from autosecops.robot_edr.types import RobotKeyRole
from autosecops.storage import blob
from autosecops.storage.exceptions import FileNameError
from autosecops.tiers import defaults as tier_defaults
from tests._route_utils import iter_effective_api_routes
from tests.support.robot_keys import exclusive_vector_keys

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]

VECTORS = Path(__file__).parents[1] / "data" / "robodr_control_plane_v2"
ROBOT_ID = "ugv-007"
EXPORT_ID = "case-42:ev-1"
MANIFEST = (VECTORS / "evidence" / "manifest.json").read_bytes()
MANIFEST_SIG = (VECTORS / "evidence" / "manifest.sig").read_text()
BUNDLE = (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
FINDING_KEY = json.loads((VECTORS / "keys" / "finding.key.pub").read_text())
SERVICE_ACCOUNT_ID = uuid.UUID("5a5a5a5a-0000-4000-8000-000000000001")


@pytest.fixture(autouse=True)
def robot_edr_entitled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(update={"robot_edr": True}),
    )


@dataclass
class AuditCapture:
    events: list[AuditEvent] = field(default_factory=list)
    refuse: bool = False
    """Simulate a configured sink that does not accept the event."""
    no_sink: bool = False
    """Simulate a deployment with no audit sink configured."""


@pytest.fixture(autouse=True)
def audit_capture(monkeypatch: pytest.MonkeyPatch) -> AuditCapture:
    capture = AuditCapture()

    async def _webhook(self: AuditService) -> str | None:
        return None if capture.no_sink else "https://audit.invalid/hook"

    async def _post(
        self: AuditService, *, webhook_url: str, payload: AuditEvent
    ) -> bool:
        """Best-effort (background) delivery."""
        if capture.refuse:
            return False
        capture.events.append(payload)
        return True

    async def _write(
        self: AuditService, *, webhook_url: str, payload: AuditEvent
    ) -> None:
        """Strict delivery: the sink confirms the event, or it is refused."""
        if capture.refuse:
            raise AuditWriteError(
                "the audit sink did not accept it: HTTPStatusError 500"
            )
        capture.events.append(payload)

    monkeypatch.setattr(AuditService, "_get_webhook_url", _webhook)
    monkeypatch.setattr(AuditService, "_post_event", _post)
    monkeypatch.setattr(AuditService, "_write_event", _write)
    return capture


@pytest.fixture
async def storage(minio_bucket: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(
        config,
        "AUTOSECOPS__BLOB_STORAGE_BUCKET_ATTACHMENTS",
        minio_bucket,
        raising=False,
    )
    await blob.ensure_bucket_exists(minio_bucket)
    return minio_bucket


def _role(ws: Workspace, user_id: uuid.UUID | None = None) -> Role:
    """A person, or else a service account (an auditable non-person actor)."""
    if user_id is None:
        return Role(
            type="service_account",
            service_id="autosecops-api",
            workspace_id=ws.id,
            organization_id=ws.organization_id,
            service_account_id=SERVICE_ACCOUNT_ID,
            scopes=ADMIN_SCOPES,
        )
    return Role(
        type="user",
        service_id="autosecops-api",
        workspace_id=ws.id,
        organization_id=ws.organization_id,
        user_id=user_id,
        scopes=ADMIN_SCOPES,
    )


@pytest.fixture
async def workspace(svc_organization: Organization) -> AsyncGenerator[Workspace, None]:
    ws = Workspace(
        id=uuid.uuid4(),
        name=f"evidence-{uuid.uuid4().hex[:8]}",
        organization_id=svc_organization.id,
    )
    # The fixed vector keys are unique SOC-wide and the service database is
    # shared by every xdist worker: hold them until the workspace is gone.
    async with exclusive_vector_keys(
        [bytes.fromhex(FINDING_KEY["public_hex"]), TEST_FINDING_PUBLIC]
    ):
        async with get_async_session_context_manager() as session:
            session.add(ws)
            await session.commit()
            robots = RobotsService(session, role=_role(ws))
            await robots.create_robot(RobotCreate(robot_id=ROBOT_ID))
            await robots.create_key(
                RobotKeyCreate(
                    role=RobotKeyRole.FINDING,
                    robot_id=ROBOT_ID,
                    public_key=FINDING_KEY["public_hex"],
                    key_id=FINDING_KEY["key_id"],
                )
            )
        try:
            yield ws
        finally:
            async with get_async_session_context_manager() as session:
                await session.execute(delete(Workspace).where(Workspace.id == ws.id))
                await session.commit()


@pytest.fixture
async def case(workspace: Workspace) -> Case:
    async with get_async_session_context_manager() as session:
        return await CasesService(session, role=_role(workspace)).create_case(
            CaseCreate(
                summary="Robot finding",
                description="evidence",
                status=CaseStatus.NEW,
                priority=CasePriority.HIGH,
                severity=CaseSeverity.HIGH,
            )
        )


def _request(**overrides: Any) -> EvidenceStoreRequest:
    values: dict[str, Any] = {
        "robot_id": ROBOT_ID,
        "export_id": EXPORT_ID,
        "manifest_base64": base64.b64encode(MANIFEST).decode(),
        "manifest_signature": MANIFEST_SIG,
        "bundle_base64": base64.b64encode(BUNDLE).decode(),
        "verification": {"verified": True, "intact": True},
    }
    return EvidenceStoreRequest(**(values | overrides))


async def _store(
    ws: Workspace,
    case: Case,
    request: EvidenceStoreRequest,
    user_id: uuid.UUID | None = None,
) -> Any:
    async with get_async_session_context_manager() as session:
        service = RobotEvidenceService(session, role=_role(ws, user_id))
        return await service.store_verified_export(case.id, request)


async def test_verified_export_is_stored_and_reported(
    workspace: Workspace,
    case: Case,
    storage: str,
) -> None:
    stored = await _store(workspace, case, _request())
    bundle_sha256 = hashlib.sha256(BUNDLE).hexdigest()
    assert stored.bundle_sha256 == bundle_sha256
    assert stored.manifest_key_id == FINDING_KEY["key_id"]
    assert stored.attachment_name == f"robodr-evidence-{bundle_sha256[:16]}.txt"
    manifest_sha256 = hashlib.sha256(MANIFEST).hexdigest()
    assert stored.storage_key.startswith(
        f"robot-edr/evidence/{workspace.id}/{manifest_sha256}/"
    )
    assert stored.storage_key.endswith("/bundle.rbbx")
    assert await blob.download_file(stored.storage_key, storage) == BUNDLE
    prefix = stored.storage_key.removesuffix("/bundle.rbbx")
    assert await blob.download_file(f"{prefix}/manifest.json", storage) == MANIFEST
    assert (
        await blob.download_file(f"{prefix}/manifest.sig", storage)
    ).decode() == MANIFEST_SIG

    async with get_async_session_context_manager() as session:
        service = CaseAttachmentService(session, role=_role(workspace))
        attachment = await service.get_attachment(case, stored.attachment_id)
        assert attachment is not None
        assert attachment.file.name == stored.attachment_name
        assert attachment.file.content_type == "text/plain"
        # Created by the run, not a person.
        assert attachment.file.creator_id is None
        # The server-side mark the UI trusts.
        assert attachment.file.robodr_evidence is True
        content, _, _ = await service.download_attachment(case, stored.attachment_id)
    text = content.decode()
    assert "RoboDR evidence export: verified" in text
    assert "records: 7..15 (9 records)" in text
    assert f"bundle_sha256: {bundle_sha256}" in text


@pytest.mark.parametrize(
    ("overrides", "error", "match"),
    [
        (
            {"bundle_base64": base64.b64encode(BUNDLE[:-1] + b"\x00").decode()},
            AutoSecOpsValidationError,
            "does not match its manifest",
        ),
        (
            {"manifest_base64": base64.b64encode(MANIFEST + b" ").decode()},
            AutoSecOpsValidationError,
            "does not verify",
        ),
        ({"export_id": "case-42:ev-2"}, AutoSecOpsValidationError, "export_id"),
        (
            {
                "manifest_signature": MANIFEST_SIG.replace(
                    "finding:ugv-007:1", "other:1"
                )
            },
            AutoSecOpsNotFoundError,
            "finding key",
        ),
        (
            {"manifest_signature": "ed25519;sig=00"},
            AutoSecOpsValidationError,
            "malformed",
        ),
        ({"verification": {"verified": False}}, AutoSecOpsValidationError, "verified"),
        ({"verification": {"verified": True}}, AutoSecOpsValidationError, "intact"),
        (
            {"verification": {"verified": True, "intact": False}},
            AutoSecOpsValidationError,
            "intact",
        ),
        (
            {"verification": {"verified": True, "intact": True, "x": "y" * 70_000}},
            AutoSecOpsValidationError,
            "too large",
        ),
        ({"bundle_base64": "not base64!"}, AutoSecOpsValidationError, "base64"),
    ],
)
async def test_unverifiable_exports_are_refused(
    workspace: Workspace,
    case: Case,
    storage: str,
    overrides: dict[str, Any],
    error: type[Exception],
    match: str,
) -> None:
    with pytest.raises(error, match=match):
        await _store(workspace, case, _request(**overrides))
    async with get_async_session_context_manager() as session:
        attachments = await CaseAttachmentService(
            session, role=_role(workspace)
        ).list_attachments(case)
    assert attachments == []


async def test_a_revoked_finding_key_does_not_verify(
    workspace: Workspace, case: Case, storage: str
) -> None:
    async with get_async_session_context_manager() as session:
        await session.execute(
            update(RobotKey)
            .where(RobotKey.workspace_id == workspace.id)
            .values(revoked_at=datetime.now(UTC))
        )
        await session.commit()
    with pytest.raises(AutoSecOpsNotFoundError, match="finding key"):
        await _store(workspace, case, _request())


async def test_the_report_prefix_is_reserved(
    workspace: Workspace, case: Case, storage: str
) -> None:
    content = b"RoboDR evidence export: verified\n"
    params = CaseAttachmentCreate(
        file_name="Robodr-Evidence-0000.txt",
        content_type="text/plain",
        size=len(content),
        content=content,
    )
    for role in (_role(workspace), _role(workspace, uuid.uuid4())):
        async with get_async_session_context_manager() as session:
            with pytest.raises(FileNameError, match="reserved"):
                await CaseAttachmentService(session, role=role).create_attachment(
                    case, params
                )


async def test_evidence_reads_are_audit_logged(
    workspace: Workspace, audit_capture: AuditCapture
) -> None:
    async with get_async_session_context_manager() as session:
        await RobotEvidenceService(
            session, role=_role(workspace, uuid.uuid4())
        ).record_access(
            EvidenceAccessRequest(
                robot_id=ROBOT_ID, operation="download_export", export_id=EXPORT_ID
            )
        )
    [event] = [e for e in audit_capture.events if e.resource_type == "robot_evidence"]
    assert event.action == "read"
    assert event.data == {
        "robot_id": ROBOT_ID,
        "export_id": EXPORT_ID,
        "operation": "download_export",
    }


def test_the_action_gateway_serves_the_evidence_routes() -> None:
    routes = {
        (method, route.path)
        for route in iter_effective_api_routes(create_gateway_app())
        for method in route.methods
    }
    assert ("POST", "/internal/robot-edr/cases/{case_id}/evidence") in routes
    assert ("POST", "/internal/robot-edr/evidence/access") in routes


# --------------------------------------------------------------------------- #
# The evidence routes with a real executor token (e2e defect D1)
# --------------------------------------------------------------------------- #

from httpx import ASGITransport, AsyncClient  # noqa: E402

from autosecops.auth.executor_tokens import mint_executor_token  # noqa: E402
from autosecops.authz.scopes import (  # noqa: E402
    PRESET_ROLE_SCOPES,
    SERVICE_PRINCIPAL_SCOPES,
    WORKSPACE_OPERATIONAL_SCOPES,
)
from autosecops.identifiers.workflow import WorkflowUUID  # noqa: E402
from autosecops.robot_edr import evidence_router  # noqa: E402
from autosecops.workflow.executions.enums import TriggerType  # noqa: E402

WORKFLOW_ID = uuid.UUID("0f0f0f0f-1111-4222-8333-444444444444")
RUN_ID = "7d7d7d7d-5555-4666-8777-888888888888"
EXECUTION_ID = f"{WorkflowUUID.from_uuid(WORKFLOW_ID).short()}/exec-synthetic1"


def _executor_token(
    ws: Workspace,
    *,
    user_id: uuid.UUID | None = None,
    service_id: Any = "autosecops-executor",
    trigger_type: TriggerType | None = TriggerType.SCHEDULED,
    root_action: str = "tools.robodr.download_evidence_export",
    agent_session_id: uuid.UUID | None = None,
    run_id: str | None = None,
) -> str:
    """The token a workflow run's action gets, minted as the executor does."""
    return mint_executor_token(
        workspace_id=ws.id,
        user_id=user_id,
        service_id=service_id,
        execution_origin="agent" if agent_session_id else "workflow",
        root_action=root_action,
        agent_session_id=agent_session_id,
        wf_id=str(WORKFLOW_ID),
        wf_exec_id=run_id or RUN_ID,
        execution_id=EXECUTION_ID,
        trigger_type=trigger_type,
    )


def _run_data(
    *,
    trigger_type: str | None = "scheduled",
    service_id: str = "autosecops-executor",
    root_action: str = "tools.robodr.download_evidence_export",
) -> dict[str, Any]:
    """The run identity an executor-attributed event carries."""
    return {
        "workflow_id": str(WORKFLOW_ID),
        "run_id": RUN_ID,
        "execution_id": EXECUTION_ID,
        "trigger_type": trigger_type,
        "execution_origin": "workflow",
        "root_action": root_action,
        "executor_service_id": service_id,
    }


@pytest.fixture
async def gateway() -> AsyncGenerator[AsyncClient, None]:
    """The action gateway app the registry SDK calls, served in process."""
    transport = ASGITransport(app=create_gateway_app())
    async with AsyncClient(transport=transport, base_url="http://gateway") as client:
        yield client


@pytest.mark.parametrize(
    "service_id", ["autosecops-executor", "autosecops-runner", "autosecops-mcp"]
)
async def test_the_executor_reaches_every_evidence_route(
    workspace: Workspace,
    case: Case,
    storage: str,
    gateway: AsyncClient,
    service_id: str,
) -> None:
    headers = {
        "Authorization": f"Bearer {_executor_token(workspace, service_id=service_id)}"
    }
    access = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers=headers,
        json={
            "robot_id": ROBOT_ID,
            "operation": "download_export",
            "export_id": EXPORT_ID,
        },
    )
    # Accepted and audited: this unattributed (scheduled) run is the actor.
    assert access.status_code == 200, access.text

    keys = await gateway.get(
        f"/internal/robot-edr/robots/{ROBOT_ID}/blackbox-keys", headers=headers
    )
    # Authorized: the robot simply has no black-box key enrolled yet.
    assert keys.status_code == 404, keys.text
    assert "enroll" in keys.text

    stored = await gateway.post(
        f"/internal/robot-edr/cases/{case.id}/evidence",
        headers=headers,
        json=_request().model_dump(mode="json"),
    )
    assert stored.status_code == 201, stored.text
    assert stored.json()["bundle_sha256"] == hashlib.sha256(BUNDLE).hexdigest()


async def test_the_evidence_routes_refuse_a_token_of_another_workspace(
    workspace: Workspace, gateway: AsyncClient, svc_organization: Organization
) -> None:
    other = Workspace(
        id=uuid.uuid4(),
        name=f"evidence-other-{uuid.uuid4().hex[:8]}",
        organization_id=svc_organization.id,
    )
    async with get_async_session_context_manager() as session:
        session.add(other)
        await session.commit()
    try:
        headers = {"Authorization": f"Bearer {_executor_token(other)}"}
        keys = await gateway.get(
            f"/internal/robot-edr/robots/{ROBOT_ID}/blackbox-keys", headers=headers
        )
        # The token's workspace scopes the lookup: the robot of another
        # workspace is not found from it.
        assert keys.status_code == 404, keys.text
    finally:
        async with get_async_session_context_manager() as session:
            await session.execute(delete(Workspace).where(Workspace.id == other.id))
            await session.commit()


async def test_the_evidence_routes_refuse_a_missing_or_forged_token(
    workspace: Workspace, gateway: AsyncClient
) -> None:
    body = {"robot_id": ROBOT_ID, "operation": "list"}
    missing = await gateway.post("/internal/robot-edr/evidence/access", json=body)
    assert missing.status_code == 401
    forged = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={"Authorization": f"Bearer {_executor_token(workspace)}x"},
        json=body,
    )
    assert forged.status_code == 401


async def test_an_attributed_user_without_robot_read_is_refused(
    workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    # A run started by a person reads evidence only if that person may read
    # robots: the executor's grant never exceeds its attributed user's.
    token = _executor_token(workspace, user_id=uuid.uuid4())
    response = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={"Authorization": f"Bearer {token}"},
        json={"robot_id": ROBOT_ID, "operation": "list"},
    )
    assert response.status_code == 403, response.text
    assert "robot:read" in response.text
    assert not [e for e in audit_capture.events if e.resource_type == "robot_evidence"]


async def test_an_attributed_viewer_reads_evidence_audited(
    workspace: Workspace,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The run acts for a workspace viewer (who holds robot:read). Only the
    # membership lookup is stubbed; the token and the route are real.
    user_id = uuid.uuid4()
    looked_up: list[uuid.UUID | None] = []

    async def viewer_scopes(role: Role) -> frozenset[str]:
        looked_up.append(role.user_id)
        return PRESET_ROLE_SCOPES["workspace-viewer"]

    monkeypatch.setattr(
        evidence_router, "compute_attributed_user_scopes", viewer_scopes
    )
    response = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={
            "Authorization": f"Bearer {_executor_token(workspace, user_id=user_id)}"
        },
        json={"robot_id": ROBOT_ID, "operation": "list"},
    )
    assert response.status_code == 200, response.text
    assert looked_up == [user_id]
    [event] = [e for e in audit_capture.events if e.resource_type == "robot_evidence"]
    # The run acted; the person who started it is named, not credited.
    assert event.actor_type == AuditEventActor.WORKFLOW
    assert event.actor_id == WORKFLOW_ID
    assert event.data == _run_data() | {
        "initiated_by_user_id": str(user_id),
        "robot_id": ROBOT_ID,
        "export_id": None,
        "operation": "list",
    }


def test_robot_read_is_not_an_operational_scope_of_every_service() -> None:
    # Least privilege: the evidence routes grant robot reads to the executor
    # themselves; no internal service gets robot:read for every robot route.
    assert "robot:read" not in WORKSPACE_OPERATIONAL_SCOPES
    assert all("robot:read" not in s for s in SERVICE_PRINCIPAL_SCOPES.values())


# --------------------------------------------------------------------------- #
# Hardening: server-side mark, storage keys, quota, cleanup, re-verification
# --------------------------------------------------------------------------- #

from autosecops_registry.integrations import robodr_evidence as ev  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from pydantic import ValidationError  # noqa: E402

from autosecops.robot_edr.evidence import report_text  # noqa: E402
from autosecops.robot_edr.evidence_storage import EVIDENCE_OBJECTS  # noqa: E402
from autosecops.storage.exceptions import FileContentMismatchError  # noqa: E402

TEST_FINDING_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TEST_FINDING_PUBLIC = TEST_FINDING_KEY.public_key().public_bytes_raw()
TEST_FINDING_KEY_ID = "finding:ugv-007:test"


async def _objects(storage: str, prefix: str) -> dict[str, bool]:
    return {
        name: await blob.file_exists(f"{prefix}/{name}", storage)
        for name in EVIDENCE_OBJECTS
    }


async def _list_attachments(ws: Workspace, case: Case) -> list[Any]:
    async with get_async_session_context_manager() as session:
        return list(
            await CaseAttachmentService(session, role=_role(ws)).list_attachments(case)
        )


@pytest.fixture
async def other_case(workspace: Workspace) -> Case:
    async with get_async_session_context_manager() as session:
        return await CasesService(session, role=_role(workspace)).create_case(
            CaseCreate(
                summary="Another case",
                description="copy target",
                status=CaseStatus.NEW,
                priority=CasePriority.LOW,
                severity=CaseSeverity.LOW,
            )
        )


async def test_a_copied_report_is_not_evidence_in_another_case(
    workspace: Workspace, case: Case, other_case: Case, storage: str
) -> None:
    stored = await _store(workspace, case, _request())
    async with get_async_session_context_manager() as session:
        service = CaseAttachmentService(session, role=_role(workspace))
        content, name, _ = await service.download_attachment(case, stored.attachment_id)
    # Same bytes, any name, another case: the dedup path must not hand the
    # evidence File (and its mark) to an ordinary upload.
    for file_name in ("copy.txt", name.upper().replace("ROBODR-", "robodr_")):
        async with get_async_session_context_manager() as session:
            with pytest.raises(FileContentMismatchError, match="evidence report"):
                await CaseAttachmentService(
                    session, role=_role(workspace, uuid.uuid4())
                ).create_attachment(
                    other_case,
                    CaseAttachmentCreate(
                        file_name=file_name,
                        content_type="text/plain",
                        size=len(content),
                        content=content,
                    ),
                )
    assert await _list_attachments(workspace, other_case) == []
    [original] = await _list_attachments(workspace, case)
    assert original.file.robodr_evidence is True


async def test_an_ordinary_upload_is_never_marked_as_evidence(
    workspace: Workspace, case: Case, storage: str
) -> None:
    content = b"RoboDR evidence export: verified\nrobot_id: ugv-007\n"
    async with get_async_session_context_manager() as session:
        attachment = await CaseAttachmentService(
            session, role=_role(workspace, uuid.uuid4())
        ).create_attachment(
            case,
            CaseAttachmentCreate(
                file_name="evidence.txt",
                content_type="text/plain",
                size=len(content),
                content=content,
            ),
        )
    assert attachment.file.robodr_evidence is False


async def test_a_second_store_never_overwrites_the_first(
    workspace: Workspace, case: Case, other_case: Case, storage: str
) -> None:
    first = await _store(workspace, case, _request())
    second = await _store(workspace, other_case, _request())
    assert first.storage_key != second.storage_key
    for stored in (first, second):
        prefix = stored.storage_key.removesuffix("/bundle.rbbx")
        assert await blob.download_file(f"{prefix}/manifest.json", storage) == MANIFEST
        assert await blob.download_file(stored.storage_key, storage) == BUNDLE


async def test_the_workspace_quota_is_enforced(
    workspace: Workspace,
    case: Case,
    other_case: Case,
    storage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        config, "AUTOSECOPS__ROBOT_EDR_EVIDENCE_QUOTA_BYTES", len(BUNDLE) * 3 // 2
    )
    await _store(workspace, case, _request())
    with pytest.raises(AutoSecOpsValidationError, match="quota"):
        await _store(workspace, other_case, _request())
    assert await _list_attachments(workspace, other_case) == []


async def test_objects_are_removed_when_the_report_cannot_be_attached(
    workspace: Workspace,
    case: Case,
    storage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uploaded: list[str] = []
    real_upload = blob.upload_file

    async def upload(data: bytes, key: str, *args: Any, **kwargs: Any) -> None:
        uploaded.append(key)
        await real_upload(data, key, *args, **kwargs)

    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise AutoSecOpsValidationError("attachment refused")

    monkeypatch.setattr(blob, "upload_file", upload)
    monkeypatch.setattr(CaseAttachmentService, "create_attachment", fail)
    with pytest.raises(AutoSecOpsValidationError, match="attachment refused"):
        await _store(workspace, case, _request())
    assert len(uploaded) == 3
    for key in uploaded:
        assert not await blob.file_exists(key, storage)


@pytest.mark.parametrize("batch", [False, True])
async def test_case_deletion_deletes_the_stored_objects(
    workspace: Workspace, case: Case, storage: str, batch: bool
) -> None:
    stored = await _store(workspace, case, _request())
    prefix = stored.storage_key.removesuffix("/bundle.rbbx")
    assert all((await _objects(storage, prefix)).values())
    async with get_async_session_context_manager() as session:
        cases = CasesService(session, role=_role(workspace))
        if batch:
            await cases.batch_delete_cases([case.id])
        else:
            loaded = await cases.get_case(case.id)
            assert loaded is not None
            await cases.delete_case(loaded)
    for _ in range(50):  # deletion runs after the commit
        if not any((await _objects(storage, prefix)).values()):
            break
        await asyncio.sleep(0.05)
    assert not any((await _objects(storage, prefix)).values())


def _signed(manifest: dict[str, Any]) -> tuple[str, str]:
    raw = json.dumps(manifest).encode()
    sig = TEST_FINDING_KEY.sign(ev.manifest_message(raw)).hex()
    return (
        base64.b64encode(raw).decode(),
        f"ed25519;key_id={TEST_FINDING_KEY_ID};sig={sig}",
    )


@pytest.fixture
async def test_finding_key(workspace: Workspace) -> None:
    # Forgotten by `workspace`, which holds the vector-key lock meanwhile.
    public = TEST_FINDING_PUBLIC.hex()
    async with get_async_session_context_manager() as session:
        await RobotsService(session, role=_role(workspace)).create_key(
            RobotKeyCreate(
                role=RobotKeyRole.FINDING,
                robot_id=ROBOT_ID,
                public_key=public,
                key_id=TEST_FINDING_KEY_ID,
            )
        )


def _manifest_for(bundle: bytes, **records: Any) -> dict[str, Any]:
    manifest = json.loads(MANIFEST)
    digest = hashlib.sha256(bundle).hexdigest()
    manifest["bundle"].update(
        bytes=len(bundle),
        sha256=digest,
        chunk_bytes=len(bundle),
        chunks=[{"index": 0, "offset": 0, "bytes": len(bundle), "sha256": digest}],
    )
    manifest["records"].update(records)
    return manifest


@pytest.mark.usefixtures("test_finding_key")
async def test_the_platform_rechecks_the_records_against_the_manifest(
    workspace: Workspace, case: Case, storage: str
) -> None:
    # A correctly signed manifest that misstates the bundle's records.
    manifest_b64, signature = _signed(_manifest_for(BUNDLE, count=8))
    with pytest.raises(AutoSecOpsValidationError, match="count differs"):
        await _store(
            workspace,
            case,
            _request(manifest_base64=manifest_b64, manifest_signature=signature),
        )
    assert await _list_attachments(workspace, case) == []


@pytest.mark.usefixtures("test_finding_key")
async def test_the_platform_rechecks_the_bundle_structure(
    workspace: Workspace, case: Case, storage: str
) -> None:
    # Flip a payload byte of the last record: the bundle matches its (signed)
    # manifest, but the record no longer hashes to its stored hash.
    tampered = BUNDLE[:-200] + bytes([BUNDLE[-200] ^ 1]) + BUNDLE[-199:]
    manifest_b64, signature = _signed(_manifest_for(tampered))
    with pytest.raises(AutoSecOpsValidationError, match="does not verify"):
        await _store(
            workspace,
            case,
            _request(
                manifest_base64=manifest_b64,
                manifest_signature=signature,
                bundle_base64=base64.b64encode(tampered).decode(),
            ),
        )
    assert await _list_attachments(workspace, case) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m["referenced"][0].update(segment="0\nchecked_by_platform: all"),
        lambda m: m["records"].update(last_sha256="00\r\n" + "0" * 60),
        lambda m: m["anchor"].update(seq=True),
        lambda m: m.update(referenced=[{"segment": 0, "seq": -1, "sha256": "0"}]),
    ],
)
def test_report_values_are_checked_before_they_are_written(mutate: Any) -> None:
    raw = json.loads(MANIFEST)
    mutate(raw)
    manifest = ev.parse_manifest(
        json.dumps(raw).encode(), robot_id=ROBOT_ID, export_id=EXPORT_ID
    )
    with pytest.raises(ValueError):
        report_text(
            manifest,
            manifest_sha256="0" * 64,
            manifest_key_id="finding:ugv-007:1",
            storage_key="k",
            evidence_id=uuid.uuid4(),
        )


def test_bundle_base64_is_capped_before_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    field = EvidenceStoreRequest.model_fields["bundle_base64"]
    cap = next(m.max_length for m in field.metadata if hasattr(m, "max_length"))
    assert cap == 4 * -(-config.AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES // 3)
    with pytest.raises(ValidationError):
        _request(bundle_base64="A" * (cap + 4))


# --------------------------------------------------------------------------- #
# Runs without a person are audited, and named (audit gap: non-human actors)
# --------------------------------------------------------------------------- #


@pytest.fixture
async def bare_workspace(
    svc_organization: Organization,
) -> AsyncGenerator[Workspace, None]:
    """A workspace without the fixed vector key (safe to run in parallel)."""
    ws = Workspace(
        id=uuid.uuid4(),
        name=f"evidence-bare-{uuid.uuid4().hex[:8]}",
        organization_id=svc_organization.id,
    )
    async with get_async_session_context_manager() as session:
        session.add(ws)
        await session.commit()
    yield ws
    async with get_async_session_context_manager() as session:
        await session.execute(delete(Workspace).where(Workspace.id == ws.id))
        await session.commit()


from sqlalchemy import func, select  # noqa: E402

from autosecops.contexts import ctx_service_account_api_key_id  # noqa: E402
from autosecops.db.models import (  # noqa: E402
    FormSubmission,
    Robot,
    RobotActionAudit,
    RobotEvidenceExport,
    User,
)
from autosecops.robot_edr.schemas import RobotActionAuditRequest  # noqa: E402
from autosecops.robot_edr.schemas import RobotCreate as _RobotCreate  # noqa: E402
from tests import _forms_utils  # noqa: E402

AGENT_SESSION_ID = uuid.UUID("9a9a9a9a-aaaa-4bbb-8ccc-dddddddddddd")


def _evidence_events(capture: AuditCapture) -> list[AuditEvent]:
    return [e for e in capture.events if e.resource_type == "robot_evidence"]


@pytest.mark.parametrize(
    "trigger_type", [TriggerType.SCHEDULED, TriggerType.WEBHOOK, None]
)
async def test_an_unattended_run_is_the_audited_actor_of_an_evidence_read(
    bare_workspace: Workspace,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
    trigger_type: TriggerType | None,
) -> None:
    # A schedule, webhook or subflow run has no person: the event names the
    # workflow, its run and execution and how it was triggered, all from the
    # signed executor token. It used to be dropped (no auditable actor).
    token = _executor_token(bare_workspace, trigger_type=trigger_type)
    response = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "robot_id": ROBOT_ID,
            "operation": "download_export",
            "export_id": EXPORT_ID,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"audit_log": "written"}
    [event] = _evidence_events(audit_capture)
    assert event.status == AuditEventStatus.ATTEMPT
    assert event.actor_type == AuditEventActor.WORKFLOW
    assert event.actor_id == WORKFLOW_ID
    assert event.workspace_id == bare_workspace.id
    assert event.action == "read"
    expected = _run_data(trigger_type=trigger_type.value if trigger_type else None)
    assert event.data == {k: v for k, v in expected.items() if v is not None} | {
        "robot_id": ROBOT_ID,
        "export_id": EXPORT_ID,
        "operation": "download_export",
    }


async def test_an_agent_session_is_the_audited_actor_of_an_evidence_read(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    token = _executor_token(
        bare_workspace,
        service_id="autosecops-mcp",
        trigger_type=None,
        root_action="tools.robodr.list_evidence",
        agent_session_id=AGENT_SESSION_ID,
    )
    response = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={"Authorization": f"Bearer {token}"},
        json={"robot_id": ROBOT_ID, "operation": "list"},
    )
    assert response.status_code == 200, response.text
    [event] = _evidence_events(audit_capture)
    assert event.actor_type == AuditEventActor.AGENT
    assert event.actor_id == AGENT_SESSION_ID
    assert event.data is not None
    assert event.data["agent_session_id"] == str(AGENT_SESSION_ID)
    assert event.data["execution_origin"] == "agent"
    assert event.data["executor_service_id"] == "autosecops-mcp"
    # An agent's tool call runs in a one-off tool workflow whose ids are
    # generated per call: they name nothing, so they are not recorded.
    assert not {"workflow_id", "run_id", "execution_id"} & event.data.keys()


async def test_an_evidence_read_the_sink_does_not_take_is_refused(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    # Fail closed: the route answers an error, so the registry action reads
    # nothing from the robot (it was a 204 with the event silently lost).
    audit_capture.refuse = True
    response = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json={"robot_id": ROBOT_ID, "operation": "list"},
    )
    assert response.status_code == 500, response.text
    assert response.json()["type"] == "AuditWriteError"


async def test_an_unattended_store_is_audited_before_and_after(
    workspace: Workspace,
    case: Case,
    storage: str,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
) -> None:
    response = await gateway.post(
        f"/internal/robot-edr/cases/{case.id}/evidence",
        headers={"Authorization": f"Bearer {_executor_token(workspace)}"},
        json=_request().model_dump(mode="json"),
    )
    assert response.status_code == 201, response.text
    attempt, success = _evidence_events(audit_capture)
    assert (attempt.status, success.status) == (
        AuditEventStatus.ATTEMPT,
        AuditEventStatus.SUCCESS,
    )
    for event in (attempt, success):
        assert event.action == "create"
        assert event.actor_type == AuditEventActor.WORKFLOW
        assert event.actor_id == WORKFLOW_ID
        assert event.data is not None
        assert event.data["trigger_type"] == "scheduled"
        assert event.data["case_id"] == str(case.id)
    assert success.data is not None and "evidence_id" in success.data


async def _stored_exports(ws: Workspace) -> int:
    async with get_async_session_context_manager() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(RobotEvidenceExport)
            .where(RobotEvidenceExport.workspace_id == ws.id)
        )
    return int(count or 0)


async def test_a_store_the_sink_does_not_take_stores_nothing(
    workspace: Workspace,
    case: Case,
    storage: str,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
) -> None:
    audit_capture.refuse = True
    response = await gateway.post(
        f"/internal/robot-edr/cases/{case.id}/evidence",
        headers={"Authorization": f"Bearer {_executor_token(workspace)}"},
        json=_request().model_dump(mode="json"),
    )
    assert response.status_code == 500, response.text
    assert await _stored_exports(workspace) == 0
    assert await _list_attachments(workspace, case) == []


async def test_a_caller_with_no_auditable_actor_cannot_read_evidence(
    bare_workspace: Workspace, audit_capture: AuditCapture
) -> None:
    # An internal service role that names no one (and is no executor run).
    role = Role(
        type="service",
        service_id="autosecops-api",
        workspace_id=bare_workspace.id,
        organization_id=bare_workspace.organization_id,
        scopes=ADMIN_SCOPES,
    )
    async with get_async_session_context_manager() as session:
        with pytest.raises(AuditWriteError, match="auditable actor"):
            await RobotEvidenceService(session, role=role).record_access(
                EvidenceAccessRequest(robot_id=ROBOT_ID, operation="list")
            )
    assert _evidence_events(audit_capture) == []


async def test_a_service_account_store_names_its_api_key(
    workspace: Workspace, case: Case, storage: str, audit_capture: AuditCapture
) -> None:
    api_key_id = uuid.uuid4()
    token = ctx_service_account_api_key_id.set(api_key_id)
    try:
        await _store(workspace, case, _request())
    finally:
        ctx_service_account_api_key_id.reset(token)
    attempt, _ = _evidence_events(audit_capture)
    assert attempt.actor_type == AuditEventActor.SERVICE_ACCOUNT
    assert attempt.actor_id == SERVICE_ACCOUNT_ID
    assert attempt.data is not None
    assert attempt.data["api_key_id"] == str(api_key_id)
    assert attempt.data["service_account_id"] == str(SERVICE_ACCOUNT_ID)


# --- robot registry changes fail closed, and name the API key ---------------------


async def test_a_robot_change_the_sink_does_not_take_is_refused(
    bare_workspace: Workspace, audit_capture: AuditCapture
) -> None:
    audit_capture.refuse = True
    async with get_async_session_context_manager() as session:
        with pytest.raises(AuditWriteError):
            await RobotsService(session, role=_role(bare_workspace)).create_robot(
                _RobotCreate(robot_id="ugv-unaudited")
            )
        robot = await session.scalar(
            select(Robot).where(
                Robot.workspace_id == bare_workspace.id,
                Robot.robot_id == "ugv-unaudited",
            )
        )
    assert robot is None


async def test_a_robot_change_by_an_unnamed_service_is_refused(
    bare_workspace: Workspace, audit_capture: AuditCapture
) -> None:
    role = Role(
        type="service",
        service_id="autosecops-api",
        workspace_id=bare_workspace.id,
        organization_id=bare_workspace.organization_id,
        scopes=ADMIN_SCOPES,
    )
    async with get_async_session_context_manager() as session:
        with pytest.raises(AuditWriteError, match="auditable actor"):
            await RobotsService(session, role=role).create_robot(
                _RobotCreate(robot_id="ugv-unnamed")
            )


async def test_a_service_account_robot_change_names_its_api_key(
    bare_workspace: Workspace, audit_capture: AuditCapture
) -> None:
    api_key_id = uuid.uuid4()
    token = ctx_service_account_api_key_id.set(api_key_id)
    try:
        async with get_async_session_context_manager() as session:
            await RobotsService(session, role=_role(bare_workspace)).create_robot(
                _RobotCreate(robot_id="ugv-keyed")
            )
    finally:
        ctx_service_account_api_key_id.reset(token)
    events = [e for e in audit_capture.events if e.resource_type == "robot"]
    assert [e.status for e in events] == [
        AuditEventStatus.ATTEMPT,
        AuditEventStatus.SUCCESS,
    ]
    for event in events:
        assert event.actor_type == AuditEventActor.SERVICE_ACCOUNT
        assert event.data is not None
        assert event.data["api_key_id"] == str(api_key_id)


# --- robot action requests and reverts (tools.robodr.request/revert_action) -------

DIGEST = hashlib.sha256(b"synthetic signed-off request").hexdigest()
REQUEST_ID = "robot_restrict_motion:ugv-007:00112233aabbccdd"


@dataclass
class Signoff:
    request_submission_id: uuid.UUID
    approval_submission_ids: list[uuid.UUID]
    requester: uuid.UUID
    approvers: list[uuid.UUID]


async def _platform_user() -> uuid.UUID:
    user = User(
        email=f"signoff-{uuid.uuid4().hex[:12]}@example.com",
        hashed_password="hashed_password_for_testing",
        is_active=True,
        is_verified=True,
        is_superuser=False,
    )
    async with get_async_session_context_manager() as session:
        session.add(user)
        await session.commit()
        return user.id


async def _signoff(
    ws: Workspace,
    *,
    approvers: int = 1,
    request_id: str = REQUEST_ID,
    digest: str = DIGEST,
    robot_id: str = ROBOT_ID,
    action: str | None = "robot_restrict_motion",
    approvals_on_another_form: bool = False,
    approver_is_requester: bool = False,
) -> Signoff:
    """A sign-off form's submissions, as the platform recorded them.

    ``action=None`` is a revert's sign-off (the action it undoes is the
    robot's word, not on the form).
    """
    requester = await _platform_user()
    leads = [
        requester if approver_is_requester else await _platform_user()
        for _ in range(approvers)
    ]
    answers: dict[str, str] = {
        "robodr_request_id": request_id,
        "robodr_request_digest": digest,
        "robodr_robot_id": robot_id,
    }
    if action is not None:
        answers["robodr_action"] = action
    async with get_async_session_context_manager() as session:
        workflow = await _forms_utils.create_workflow(session, ws.id)
        form = await _forms_utils.create_form(session, workflow)
        approval_form = form
        if approvals_on_another_form:
            other = await _forms_utils.create_workflow(session, ws.id)
            approval_form = await _forms_utils.create_form(session, other)

        async def submit(on: Any, user_id: uuid.UUID, decision: str) -> uuid.UUID:
            submission = await _forms_utils.create_submission(
                session,
                on,
                user_id=user_id,
                answers=answers | {"robodr_decision": decision},
            )
            return submission.id

        request_sid = await submit(form, requester, "request")
        approval_sids = [await submit(approval_form, lead, "approve") for lead in leads]
    return Signoff(request_sid, approval_sids, requester, leads)


def _action_body(signoff: Signoff, **overrides: Any) -> dict[str, Any]:
    return {
        "robot_id": ROBOT_ID,
        "request_id": REQUEST_ID,
        "operation": "request_action",
        "robot_action": "robot_restrict_motion",
        "request_digest": DIGEST,
        "request_submission_id": str(signoff.request_submission_id),
        "approval_submission_ids": [str(s) for s in signoff.approval_submission_ids],
        "phase": "attempt",
    } | overrides


def _action_events(capture: AuditCapture) -> list[AuditEvent]:
    return [e for e in capture.events if e.resource_type == "robot_action"]


async def _attempt(
    gateway: AsyncClient, ws: Workspace, signoff: Signoff, **overrides: Any
) -> str:
    """Write the attempt of a robot action call; its stored attempt id."""
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(ws)}"},
        json=_action_body(signoff, **overrides),
    )
    assert response.status_code == 200, response.text
    return response.json()["attempt_id"]


async def test_an_unattended_robot_action_names_the_run_and_the_signoff(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace, approvers=2)
    token = _executor_token(bare_workspace, root_action="tools.robodr.request_action")
    headers = {"Authorization": f"Bearer {token}"}
    attempt = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers=headers,
        json=_action_body(signoff),
    )
    assert attempt.status_code == 200, attempt.text
    assert attempt.json()["audit_log"] == "written"
    attempt_id = attempt.json()["attempt_id"]
    answered = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers=headers,
        json=_action_body(
            signoff,
            phase="answered",
            outcome="recorded_not_executed",
            applied=False,
            attempt_id=attempt_id,
        ),
    )
    assert answered.status_code == 200, answered.text
    assert answered.json() == {"attempt_id": attempt_id, "audit_log": "written"}

    first, second = _action_events(audit_capture)
    assert (first.status, second.status) == (
        AuditEventStatus.ATTEMPT,
        AuditEventStatus.SUCCESS,
    )
    assert first.action == second.action == "request"
    assert first.actor_type == AuditEventActor.WORKFLOW
    assert first.actor_id == WORKFLOW_ID
    assert first.workspace_id == bare_workspace.id
    assert first.data == _run_data(root_action="tools.robodr.request_action") | {
        "robot_id": ROBOT_ID,
        "request_id": REQUEST_ID,
        "operation": "request_action",
        "robot_action": "robot_restrict_motion",
        "request_digest": DIGEST,
        "requested_by_user_id": str(signoff.requester),
        "approved_by_user_ids": [str(u) for u in signoff.approvers],
        "request_submission_id": str(signoff.request_submission_id),
        "approval_submission_ids": [str(s) for s in signoff.approval_submission_ids],
        "action_audit_id": attempt_id,
    }
    assert second.data is not None
    assert second.data["outcome"] == "recorded_not_executed"
    assert second.data["is_applied"] is False
    assert second.data["action_audit_id"] == attempt_id
    assert second.data["requested_by_user_id"] == str(signoff.requester)


async def test_a_failed_robot_revert_is_audited_as_a_failure(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace, action=None)
    attempt_id = await _attempt(
        gateway, bare_workspace, signoff, operation="revert_action"
    )
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(
            signoff,
            operation="revert_action",
            phase="failed",
            failure_reason="ControlPlaneError",
            attempt_id=attempt_id,
        ),
    )
    assert response.status_code == 200, response.text
    _, event = _action_events(audit_capture)
    assert event.action == "revert"
    assert event.status == AuditEventStatus.FAILURE
    assert event.data is not None
    assert event.data["failure_reason"] == "ControlPlaneError"


async def _email_of(user_id: uuid.UUID) -> str:
    async with get_async_session_context_manager() as session:
        users = User.__table__
        email = await session.scalar(select(users.c.email).where(users.c.id == user_id))
    assert email is not None
    return email


async def test_a_robot_action_records_the_names_sent_to_the_robot(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    # The registry action reports the requested_by and approved_by it sends;
    # the platform recomputes them from the submitters' user records.
    signoff = await _signoff(bare_workspace, approvers=2)
    requested = await _email_of(signoff.requester)
    approved = [f"user-{u}" for u in signoff.approvers]
    attempt_id = await _attempt(
        gateway,
        bare_workspace,
        signoff,
        requested_by_name=requested,
        approved_by_names=approved,
    )
    async with get_async_session_context_manager() as session:
        row = (
            await session.execute(
                select(
                    RobotActionAudit.requested_by_name,
                    RobotActionAudit.approved_by_names,
                ).where(RobotActionAudit.id == uuid.UUID(attempt_id))
            )
        ).one()
    assert tuple(row) == (requested, approved)
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(
            signoff,
            phase="answered",
            outcome="verified",
            applied=True,
            attempt_id=attempt_id,
        ),
    )
    assert response.status_code == 200, response.text
    # Events carry flags only: the audit policy keeps emails out of them.
    for event in _action_events(audit_capture):
        assert event.data is not None
        assert event.data["has_approved_by"] is True
        assert event.data["is_requested_by_email"] is True
        assert requested not in json.dumps(event.data)


async def test_a_robot_action_that_sends_no_approvers_records_none(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace, approvers=2)
    await _attempt(
        gateway,
        bare_workspace,
        signoff,
        requested_by_name=await _email_of(signoff.requester),
        approved_by_names=[],
    )
    (event,) = _action_events(audit_capture)
    assert event.data is not None
    assert event.data["has_approved_by"] is False


@pytest.mark.parametrize(
    "change",
    ["other_requester", "email_approvers", "swapped", "one_short", "requester"],
)
async def test_robot_action_names_that_differ_from_the_signoff_are_refused(
    bare_workspace: Workspace,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
    change: str,
) -> None:
    signoff = await _signoff(bare_workspace, approvers=2)
    requested = await _email_of(signoff.requester)
    approved = [f"user-{u}" for u in signoff.approvers]
    match change:
        case "other_requester":
            requested = "someone.else@example.com"
        case "email_approvers":
            approved = [await _email_of(u) for u in signoff.approvers]
        case "swapped":
            approved = approved[::-1]
        case "one_short":
            approved = approved[:1]
        case "requester":
            approved = [f"user-{signoff.requester}", approved[1]]
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(
            signoff, requested_by_name=requested, approved_by_names=approved
        ),
    )
    assert response.status_code == 400, response.text
    assert _action_events(audit_capture) == []


async def test_a_requester_whose_email_changed_is_refused(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    # The registry read the requester's email from the submission; if the
    # user changed it before the attempt, the names no longer match and the
    # attempt (so the robot action) is refused.
    signoff = await _signoff(bare_workspace)
    old_email = await _email_of(signoff.requester)
    async with get_async_session_context_manager() as session:
        user = await session.get(User, signoff.requester)
        assert user is not None
        user.email = f"renamed-{uuid.uuid4().hex[:8]}@example.com"
        await session.commit()
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff, requested_by_name=old_email, approved_by_names=[]),
    )
    assert response.status_code == 400, response.text
    assert "requested_by_name" in response.text
    assert _action_events(audit_capture) == []


def test_the_names_sent_belong_to_the_attempt_only() -> None:
    signoff = Signoff(uuid.uuid4(), [uuid.uuid4()], uuid.uuid4(), [uuid.uuid4()])
    with pytest.raises(ValidationError, match="belong to the attempt"):
        RobotActionAuditRequest.model_validate(
            _action_body(
                signoff,
                phase="answered",
                outcome="verified",
                attempt_id=str(uuid.uuid4()),
                approved_by_names=["user-x"],
            )
        )
    with pytest.raises(ValidationError):
        RobotActionAuditRequest.model_validate(
            _action_body(signoff, approved_by_names=["bob smith"])
        )


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"request_digest": "0" * 64}, "differs in robodr_request_digest"),
        ({"request_id": "robot_restrict_motion:ugv-007:ffff"}, "robodr_request_id"),
        ({"robot_id": "ugv-008"}, "differs in robodr_robot_id"),
        ({"robot_action": "robot_quarantine_node"}, "differs in robodr_action"),
        ({"approval_submission_ids": "request"}, "named twice"),
        ({"approval_submission_ids": "unknown"}, "not in this workspace"),
    ],
)
async def test_a_robot_action_audit_that_misstates_the_signoff_is_refused(
    bare_workspace: Workspace,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
    change: dict[str, Any],
    match: str,
) -> None:
    # The people come from the platform's records, never from the body: a
    # body that names another request, digest or submission is refused (and
    # the registry action then sends nothing).
    signoff = await _signoff(bare_workspace)
    match change.get("approval_submission_ids"):
        case "request":
            change = {"approval_submission_ids": [str(signoff.request_submission_id)]}
        case "unknown":
            change = {"approval_submission_ids": [str(uuid.uuid4())]}
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff, **change),
    )
    assert response.status_code == 400, response.text
    assert match in response.text
    assert _action_events(audit_capture) == []


async def test_a_robot_action_signoff_from_another_workspace_is_refused(
    bare_workspace: Workspace,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
    svc_organization: Organization,
) -> None:
    other = Workspace(
        id=uuid.uuid4(),
        name=f"evidence-other-{uuid.uuid4().hex[:8]}",
        organization_id=svc_organization.id,
    )
    async with get_async_session_context_manager() as session:
        session.add(other)
        await session.commit()
    try:
        foreign = await _signoff(other)
        response = await gateway.post(
            "/internal/robot-edr/actions/audit",
            headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
            json=_action_body(foreign),
        )
        assert response.status_code == 400, response.text
        assert "not in this workspace" in response.text
        assert _action_events(audit_capture) == []
    finally:
        async with get_async_session_context_manager() as session:
            await session.execute(delete(Workspace).where(Workspace.id == other.id))
            await session.commit()


async def test_a_robot_action_signed_off_by_a_service_account_is_refused(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace)
    async with get_async_session_context_manager() as session:
        await session.execute(
            update(FormSubmission)
            .where(FormSubmission.id == signoff.approval_submission_ids[0])
            .values(submitted_by_user_id=None)
        )
        await session.commit()
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff),
    )
    assert response.status_code == 400, response.text
    assert "not submitted by a platform user" in response.text


async def test_a_robot_action_the_sink_does_not_take_is_refused(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace)
    audit_capture.refuse = True
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff),
    )
    assert response.status_code == 500, response.text
    assert response.json()["type"] == "AuditWriteError"


async def test_the_robot_action_audit_route_needs_an_executor_token(
    bare_workspace: Workspace, gateway: AsyncClient
) -> None:
    signoff = await _signoff(bare_workspace)
    response = await gateway.post(
        "/internal/robot-edr/actions/audit", json=_action_body(signoff)
    )
    assert response.status_code == 401


def test_the_action_gateway_serves_the_robot_action_audit_route() -> None:
    routes = {
        (method, route.path)
        for route in iter_effective_api_routes(create_gateway_app())
        for method in route.methods
    }
    assert ("POST", "/internal/robot-edr/actions/audit") in routes


# --- the attempt is checked like the registry checks it (review F3) -----------


async def test_a_robot_action_signoff_older_than_24_hours_is_refused(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace)
    async with get_async_session_context_manager() as session:
        await session.execute(
            update(FormSubmission)
            .where(FormSubmission.id == signoff.approval_submission_ids[0])
            .values(created_at=datetime.now(UTC) - timedelta(hours=24, minutes=1))
        )
        await session.commit()
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff),
    )
    assert response.status_code == 400, response.text
    assert "older than 24 hours" in response.text
    assert _action_events(audit_capture) == []


async def test_a_robot_action_signoff_from_two_forms_is_refused(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace, approvals_on_another_form=True)
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff),
    )
    assert response.status_code == 400, response.text
    assert "same form" in response.text
    assert _action_events(audit_capture) == []


async def test_a_requester_approving_through_another_submission_is_refused(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    # Two distinct submissions, one person: not a second person's approval.
    signoff = await _signoff(bare_workspace, approver_is_requester=True)
    assert signoff.request_submission_id not in signoff.approval_submission_ids
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff),
    )
    assert response.status_code == 400, response.text
    assert "different platform users" in response.text
    assert _action_events(audit_capture) == []


async def test_an_attempt_cannot_cite_an_attempt_id(
    bare_workspace: Workspace, gateway: AsyncClient
) -> None:
    signoff = await _signoff(bare_workspace)
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff, attempt_id=str(uuid.uuid4())),
    )
    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "change",
    [
        {"attempt_id": "unknown"},
        {"robot_id": "ugv-008"},
        {"robot_action": "robot_quarantine_node"},
        {"request_digest": "0" * 64},
        {"approval_submission_ids": "reordered"},
        {"run_id": "another-run"},
    ],
)
async def test_an_outcome_must_match_its_audited_attempt(
    bare_workspace: Workspace,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
    change: dict[str, Any],
) -> None:
    # An outcome with no audited attempt behind it, for another robot or
    # action than was attempted, or from another run, is not recorded.
    signoff = await _signoff(bare_workspace, approvers=2)
    attempt_id = await _attempt(gateway, bare_workspace, signoff)
    body = _action_body(
        signoff,
        phase="answered",
        outcome="applied",
        applied=True,
        attempt_id=attempt_id,
    )
    token = _executor_token(bare_workspace)
    match change:
        case {"attempt_id": "unknown"}:
            body["attempt_id"] = str(uuid.uuid4())
        case {"approval_submission_ids": "reordered"}:
            body["approval_submission_ids"].reverse()
        case {"run_id": run_id}:
            token = _executor_token(bare_workspace, run_id=run_id)
        case _:
            body |= change
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )
    assert response.status_code == 400, response.text
    assert "no open audited attempt" in response.text
    assert [e.status for e in _action_events(audit_capture)] == [
        AuditEventStatus.ATTEMPT
    ]


async def test_an_outcome_is_recorded_once(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace)
    attempt_id = await _attempt(gateway, bare_workspace, signoff)
    headers = {"Authorization": f"Bearer {_executor_token(bare_workspace)}"}
    answered = _action_body(
        signoff,
        phase="answered",
        outcome="applied",
        applied=True,
        attempt_id=attempt_id,
    )
    failed = _action_body(
        signoff, phase="failed", failure_reason="TimeoutError", attempt_id=attempt_id
    )
    first = await gateway.post(
        "/internal/robot-edr/actions/audit", headers=headers, json=answered
    )
    assert first.status_code == 200, first.text
    for again in (answered, failed):
        response = await gateway.post(
            "/internal/robot-edr/actions/audit", headers=headers, json=again
        )
        assert response.status_code == 400, response.text
    assert len(_action_events(audit_capture)) == 2


async def test_an_attempt_the_sink_refuses_is_not_stored(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    signoff = await _signoff(bare_workspace)
    audit_capture.refuse = True
    response = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=_action_body(signoff),
    )
    assert response.status_code == 500, response.text
    async with get_async_session_context_manager() as session:
        stored = await session.scalar(
            select(func.count())
            .select_from(RobotActionAudit)
            .where(RobotActionAudit.workspace_id == bare_workspace.id)
        )
    assert stored == 0


# --- no sink, identifier fields, evidence phases (review F2, F4, F8) ----------


async def test_an_audit_with_no_sink_is_reported_as_such(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    # Not refused (no sink is a deployment choice), never reported as written.
    audit_capture.no_sink = True
    headers = {"Authorization": f"Bearer {_executor_token(bare_workspace)}"}
    access = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers=headers,
        json={"robot_id": ROBOT_ID, "operation": "list"},
    )
    assert access.status_code == 200, access.text
    assert access.json() == {"audit_log": "no_sink"}
    signoff = await _signoff(bare_workspace)
    action = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers=headers,
        json=_action_body(signoff),
    )
    assert action.status_code == 200, action.text
    assert action.json()["audit_log"] == "no_sink"


async def test_schema_valid_ids_are_written_as_given(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    # `token:`/`secret:` prefixes match the free-text credential patterns;
    # the event used to drop them and still report success.
    request_id = "token:rq-0001"
    signoff = await _signoff(bare_workspace, request_id=request_id)
    headers = {"Authorization": f"Bearer {_executor_token(bare_workspace)}"}
    action = await gateway.post(
        "/internal/robot-edr/actions/audit",
        headers=headers,
        json=_action_body(signoff, request_id=request_id),
    )
    assert action.status_code == 200, action.text
    access = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers=headers,
        json={
            "robot_id": ROBOT_ID,
            "operation": "download_export",
            "export_id": "secret:e1",
        },
    )
    assert access.status_code == 200, access.text
    [action_event] = _action_events(audit_capture)
    [access_event] = _evidence_events(audit_capture)
    assert action_event.data is not None and access_event.data is not None
    assert action_event.data["request_id"] == request_id
    assert access_event.data["export_id"] == "secret:e1"


@pytest.mark.parametrize(
    ("operation", "phase", "action", "status"),
    [
        ("download_export", "succeeded", "read", AuditEventStatus.SUCCESS),
        ("list", "failed", "read", AuditEventStatus.FAILURE),
        ("delete_export", "attempt", "delete", AuditEventStatus.ATTEMPT),
        ("delete_export", "succeeded", "delete", AuditEventStatus.SUCCESS),
    ],
)
async def test_evidence_access_is_audited_before_and_after(
    bare_workspace: Workspace,
    gateway: AsyncClient,
    audit_capture: AuditCapture,
    operation: str,
    phase: str,
    action: str,
    status: AuditEventStatus,
) -> None:
    body: dict[str, Any] = {
        "robot_id": ROBOT_ID,
        "operation": operation,
        "export_id": None if operation == "list" else EXPORT_ID,
        "phase": phase,
    }
    if phase == "failed":
        body["failure_reason"] = "EvidenceError"
    response = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json=body,
    )
    assert response.status_code == 200, response.text
    # Closing events are best effort: handed to background delivery.
    assert response.json()["audit_log"] == (
        "written" if phase == "attempt" else "queued"
    )
    [event] = _evidence_events(audit_capture)
    assert (event.action, event.status) == (action, status)
    assert event.data is not None
    assert event.data["operation"] == operation
    if phase == "failed":
        assert event.data["failure_reason"] == "EvidenceError"


async def test_a_closing_evidence_event_the_sink_refuses_is_not_an_error(
    bare_workspace: Workspace, gateway: AsyncClient, audit_capture: AuditCapture
) -> None:
    audit_capture.refuse = True
    response = await gateway.post(
        "/internal/robot-edr/evidence/access",
        headers={"Authorization": f"Bearer {_executor_token(bare_workspace)}"},
        json={"robot_id": ROBOT_ID, "operation": "list", "phase": "succeeded"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"audit_log": "failed"}
