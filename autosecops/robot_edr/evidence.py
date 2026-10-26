"""Verified RoboDR evidence exports for cases (robodr.control-plane §11).

`tools.robodr.download_evidence_export` downloads an export, verifies it as
§11.6 requires and hands the result to `store_verified_export`, which does not
take the workflow's word for the parts it can check itself:

* the manifest signature, against a finding key registered for that robot in
  this workspace (the key the robot's answers are signed with);
* the manifest's robot, export and bundle layout, and the bundle's length and
  SHA-256 against it.

The black-box record check (§11.6 steps 4-5) needs the robot's black-box
keyring, which the platform does not hold; the workflow's report of it is
stored as-is. The bundle, manifest and signature go to the attachments bucket
under `robot-edr/evidence/<workspace>/<bundle sha256>/`, outside the per-case
attachment limits and allowlist (an `RBBXBND1` bundle is no allowed type), and
the case gets a plain-text report attachment named `robodr-evidence-...`, a
prefix no other upload path may use.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import uuid
from datetime import UTC, datetime
from typing import Final, Literal

from autosecops_registry.integrations.robodr_evidence import (
    Manifest,
    parse_manifest,
    parse_signature_header,
    verify_manifest_signature,
)
from sqlalchemy import or_, select

from autosecops import config
from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.service import AuditService
from autosecops.cases.attachments.schemas import CaseAttachmentCreate
from autosecops.cases.attachments.service import ROBODR_EVIDENCE_PREFIX
from autosecops.cases.service import CasesService
from autosecops.db.models import Robot, RobotKey
from autosecops.exceptions import TracecatNotFoundError, TracecatValidationError
from autosecops.robot_edr.schemas import (
    EvidenceAccessRequest,
    EvidenceStoreRequest,
    EvidenceStoreResponse,
)
from autosecops.robot_edr.types import RobotKeyRole
from autosecops.service import BaseWorkspaceService
from autosecops.storage import blob
from autosecops.tiers.enums import Entitlement

EVIDENCE_KEY_PREFIX: Final = "robot-edr/evidence"


def _decode(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TracecatValidationError(f"{what} is not valid base64") from exc


def evidence_storage_prefix(workspace_id: object, bundle_sha256: str) -> str:
    """Object-storage prefix of one stored bundle (with manifest and signature)."""
    return f"{EVIDENCE_KEY_PREFIX}/{workspace_id}/{bundle_sha256}"


def report_text(
    manifest: Manifest,
    *,
    manifest_sha256: str,
    manifest_key_id: str,
    storage_key: str,
    verification: dict[str, object],
) -> str:
    """The plain-text verification report attached to the case.

    Every value comes from the signature-checked manifest or is a fixed
    word; nothing is copied from free text.
    """
    records = manifest.raw.get("records")
    records = records if isinstance(records, dict) else {}
    anchor = manifest.raw.get("anchor")
    referenced = manifest.raw.get("referenced")
    lines = [
        "RoboDR evidence export: verified (robodr.control-plane section 11.6)",
        f"robot_id: {manifest.robot_id}",
        f"export_id: {manifest.export_id}",
        f"manifest_sha256: {manifest_sha256}",
        f"manifest_signed_by: {manifest_key_id}",
        f"chain_id: {manifest.chain_id}",
        f"blackbox_signing_key: {manifest.signing_key_id}",
        f"records: {records.get('first_seq')}..{records.get('last_seq')} "
        f"({records.get('count')} records)",
        f"last_record_sha256: {records.get('last_sha256')}",
    ]
    if isinstance(anchor, dict):
        lines.append(
            f"anchor: seq {anchor.get('seq')} sha256 {anchor.get('sha256')} "
            "(unverified: first contact)"
        )
    if isinstance(referenced, list):
        for item in referenced:
            if isinstance(item, dict):
                lines.append(
                    f"referenced: segment {item.get('segment')} seq {item.get('seq')} "
                    f"sha256 {item.get('sha256')}"
                )
    lines += [
        f"bundle_sha256: {manifest.bundle_sha256}",
        f"bundle_bytes: {manifest.bundle_bytes}",
        f"bundle_storage_key: {storage_key}",
        "checked_by_platform: manifest signature (registered finding key), "
        "bundle length and SHA-256",
        "checked_by_workflow: answer signatures, chunk hashes, black-box "
        f"records ({'intact' if verification.get('intact') is True else 'NOT intact'})",
        f"stored_at: {datetime.now(UTC).isoformat()}",
    ]
    return "\n".join(str(line) for line in lines) + "\n"


class RobotEvidenceService(BaseWorkspaceService):
    """Store verified evidence exports and audit evidence reads."""

    service_name = "robot_edr_evidence"

    async def _finding_keys(self, robot_id: str) -> dict[str, bytes]:
        now = datetime.now(UTC)
        stmt = (
            select(RobotKey.key_id, RobotKey.public_key)
            .join(Robot, Robot.id == RobotKey.robot_fk)
            .where(
                Robot.workspace_id == self.workspace_id,
                Robot.robot_id == robot_id,
                RobotKey.workspace_id == self.workspace_id,
                RobotKey.role == RobotKeyRole.FINDING.value,
                RobotKey.revoked_at.is_(None),
                or_(RobotKey.expires_at.is_(None), RobotKey.expires_at > now),
            )
        )
        rows = (await self.session.execute(stmt)).tuples().all()
        return {key_id: bytes(public_key) for key_id, public_key in rows}

    async def store_verified_export(
        self, case_id: uuid.UUID, params: EvidenceStoreRequest
    ) -> EvidenceStoreResponse:
        """Check and store a verified export; attach its report to the case.

        Raises:
            TracecatNotFoundError: The case or the robot's finding key is unknown.
            TracecatValidationError: The export does not check out.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        cases = CasesService(self.session, role=self.role)
        case = await cases.get_case(case_id)
        if case is None:
            raise TracecatNotFoundError("Case not found")

        manifest_bytes = _decode(params.manifest_base64, "manifest_base64")
        if len(params.bundle_base64) > 4 * (
            config.TRACECAT__ROBOT_EDR_MAX_EVIDENCE_BYTES // 3 + 1
        ):
            raise TracecatValidationError("the evidence bundle is too large")
        bundle = _decode(params.bundle_base64, "bundle_base64")
        if len(bundle) > config.TRACECAT__ROBOT_EDR_MAX_EVIDENCE_BYTES:
            raise TracecatValidationError("the evidence bundle is too large")

        parsed = parse_signature_header(params.manifest_signature)
        if parsed is None:
            raise TracecatValidationError("manifest_signature is malformed")
        key_id = parsed[0]
        keys = await self._finding_keys(params.robot_id)
        if key_id not in keys:
            raise TracecatNotFoundError(
                "No active finding key with the manifest's key id is registered "
                "for this robot"
            )
        try:
            verify_manifest_signature(
                manifest_bytes, params.manifest_signature, keys[key_id], key_id
            )
            manifest = parse_manifest(
                manifest_bytes, robot_id=params.robot_id, export_id=params.export_id
            )
        # EvidenceError is a ValueError; catching the base keeps this correct
        # when the registry package is reloaded (registry sync re-imports it).
        except ValueError as exc:
            raise TracecatValidationError(str(exc)) from exc
        bundle_sha256 = hashlib.sha256(bundle).hexdigest()
        if len(bundle) != manifest.bundle_bytes or bundle_sha256 != (
            manifest.bundle_sha256
        ):
            raise TracecatValidationError("the bundle does not match its manifest")
        if params.verification.get("verified") is not True:
            raise TracecatValidationError("only verified evidence is stored")

        prefix = evidence_storage_prefix(self.workspace_id, bundle_sha256)
        bucket = config.TRACECAT__BLOB_STORAGE_BUCKET_ATTACHMENTS
        storage_key = f"{prefix}/bundle.rbbx"
        await blob.upload_file(bundle, storage_key, bucket, "application/octet-stream")
        await blob.upload_file(
            manifest_bytes, f"{prefix}/manifest.json", bucket, "application/json"
        )
        await blob.upload_file(
            params.manifest_signature.encode("ascii"),
            f"{prefix}/manifest.sig",
            bucket,
            "text/plain",
        )

        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        name = f"{ROBODR_EVIDENCE_PREFIX}{bundle_sha256[:16]}.txt"
        content = report_text(
            manifest,
            manifest_sha256=manifest_sha256,
            manifest_key_id=key_id,
            storage_key=storage_key,
            verification=params.verification,
        ).encode("ascii", errors="replace")
        attachment = await cases.attachments.create_attachment(
            case,
            CaseAttachmentCreate(
                file_name=name,
                content_type="text/plain",
                size=len(content),
                content=content,
            ),
            allow_reserved_name=True,
        )
        await self._audit(
            "create",
            {
                "robot_id": params.robot_id,
                "export_id": params.export_id,
                "case_id": str(case.id),
                "operation": "store_evidence",
            },
        )
        return EvidenceStoreResponse(
            attachment_id=attachment.id,
            attachment_name=name,
            storage_key=storage_key,
            bundle_sha256=bundle_sha256,
            bundle_bytes=len(bundle),
            manifest_sha256=manifest_sha256,
            manifest_key_id=key_id,
        )

    async def record_access(self, params: EvidenceAccessRequest) -> None:
        """Write the audit event for an evidence read by a workflow."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        await self._audit(
            "read",
            {
                "robot_id": params.robot_id,
                "export_id": params.export_id,
                "operation": params.operation,
            },
        )

    async def _audit(
        self, action: Literal["create", "read"], data: dict[str, str | None]
    ) -> None:
        self.logger.info("RoboDR evidence access", action=action, **data)
        try:
            await AuditService(self.session, role=self.role).create_event(
                resource_type="robot_evidence",
                action=action,
                status=AuditEventStatus.SUCCESS,
                data=dict(data),
            )
        except Exception as exc:  # audit delivery is best-effort, like ingest's
            self.logger.warning(
                "RoboDR evidence audit event failed", error_type=type(exc).__name__
            )
