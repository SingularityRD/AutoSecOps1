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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, update

from autosecops import config
from autosecops.audit.service import AuditService
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
from autosecops.exceptions import TracecatNotFoundError, TracecatValidationError
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

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]

VECTORS = Path(__file__).parents[1] / "data" / "robodr_control_plane_v2"
ROBOT_ID = "ugv-007"
EXPORT_ID = "case-42:ev-1"
MANIFEST = (VECTORS / "evidence" / "manifest.json").read_bytes()
MANIFEST_SIG = (VECTORS / "evidence" / "manifest.sig").read_text()
BUNDLE = (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
FINDING_KEY = json.loads((VECTORS / "keys" / "finding.key.pub").read_text())


@pytest.fixture(autouse=True)
def robot_edr_entitled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(update={"robot_edr": True}),
    )


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


@pytest.fixture
async def storage(minio_bucket: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(
        config, "TRACECAT__BLOB_STORAGE_BUCKET_ATTACHMENTS", minio_bucket, raising=False
    )
    await blob.ensure_bucket_exists(minio_bucket)
    return minio_bucket


def _role(ws: Workspace, user_id: uuid.UUID | None = None) -> Role:
    return Role(
        type="user" if user_id else "service",
        service_id="tracecat-api",
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
    yield ws
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
            TracecatValidationError,
            "does not match its manifest",
        ),
        (
            {"manifest_base64": base64.b64encode(MANIFEST + b" ").decode()},
            TracecatValidationError,
            "does not verify",
        ),
        ({"export_id": "case-42:ev-2"}, TracecatValidationError, "export_id"),
        (
            {
                "manifest_signature": MANIFEST_SIG.replace(
                    "finding:ugv-007:1", "other:1"
                )
            },
            TracecatNotFoundError,
            "finding key",
        ),
        (
            {"manifest_signature": "ed25519;sig=00"},
            TracecatValidationError,
            "malformed",
        ),
        ({"verification": {"verified": False}}, TracecatValidationError, "verified"),
        ({"verification": {"verified": True}}, TracecatValidationError, "intact"),
        (
            {"verification": {"verified": True, "intact": False}},
            TracecatValidationError,
            "intact",
        ),
        (
            {"verification": {"verified": True, "intact": True, "x": "y" * 70_000}},
            TracecatValidationError,
            "too large",
        ),
        ({"bundle_base64": "not base64!"}, TracecatValidationError, "base64"),
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
    with pytest.raises(TracecatNotFoundError, match="finding key"):
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
        config, "TRACECAT__ROBOT_EDR_EVIDENCE_QUOTA_BYTES", len(BUNDLE) * 3 // 2
    )
    await _store(workspace, case, _request())
    with pytest.raises(TracecatValidationError, match="quota"):
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
        raise TracecatValidationError("attachment refused")

    monkeypatch.setattr(blob, "upload_file", upload)
    monkeypatch.setattr(CaseAttachmentService, "create_attachment", fail)
    with pytest.raises(TracecatValidationError, match="attachment refused"):
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
    public = TEST_FINDING_KEY.public_key().public_bytes_raw().hex()
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
    with pytest.raises(TracecatValidationError, match="count differs"):
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
    with pytest.raises(TracecatValidationError, match="does not verify"):
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
    assert cap == 4 * -(-config.TRACECAT__ROBOT_EDR_MAX_EVIDENCE_BYTES // 3)
    with pytest.raises(ValidationError):
        _request(bundle_base64="A" * (cap + 4))
