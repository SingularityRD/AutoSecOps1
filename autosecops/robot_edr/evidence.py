"""Verified RoboDR evidence exports for cases (robodr.control-plane §11).

`tools.robodr.download_evidence_export` downloads an export, verifies it as
§11.6 requires and hands the result to `store_verified_export`, which does not
take the workflow's word for the parts it can check itself:

* the manifest signature, against a finding key registered for that robot in
  this workspace (the key the robot's answers are signed with);
* the manifest's robot, export and bundle layout, and the bundle's length and
  SHA-256 against it.

* the workflow's report says verified and intact;
* the bundle itself (§11.6 steps 4-5 without the record signatures): every
  record's hash, the chain, sequence and anchor, the control records, and
  the result against the manifest (`check_report_against_manifest`). The
  record signatures need the black-box keyring the workflow verified with.

The bundle, manifest and signature go to the attachments bucket under a
prefix of their own (`evidence_storage`), outside the per-case attachment
limits and allowlist (an `RBBXBND1` bundle is no allowed type) but within a
per-workspace quota (`AUTOSECOPS__ROBOT_EDR_EVIDENCE_QUOTA_BYTES`); they are
deleted with the case. The case gets a plain-text report attachment on a
File marked `robodr_evidence`, which is what the UI trusts.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Final, Literal

from autosecops_registry.integrations.robodr_evidence import (
    Manifest,
    check_report_against_manifest,
    parse_manifest,
    parse_signature_header,
    verify_bundle,
    verify_manifest_signature,
)
from sqlalchemy import func, or_, select

from autosecops import config
from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.service import AuditService
from autosecops.cases.attachments.schemas import CaseAttachmentCreate
from autosecops.cases.attachments.service import ROBODR_EVIDENCE_PREFIX
from autosecops.cases.service import CasesService
from autosecops.db.models import Robot, RobotEvidenceExport, RobotKey
from autosecops.exceptions import AutoSecOpsNotFoundError, AutoSecOpsValidationError
from autosecops.robot_edr.evidence_storage import (
    BUNDLE_OBJECT,
    MANIFEST_OBJECT,
    SIGNATURE_OBJECT,
    delete_evidence_objects,
    evidence_storage_prefix,
)
from autosecops.robot_edr.fleet_wire import public_key_file
from autosecops.robot_edr.schemas import (
    EvidenceAccessRequest,
    EvidenceStoreRequest,
    EvidenceStoreResponse,
)
from autosecops.robot_edr.types import RobotKeyProvenance, RobotKeyRole
from autosecops.service import BaseWorkspaceService
from autosecops.storage import blob
from autosecops.tiers.enums import Entitlement

MAX_VERIFICATION_JSON_BYTES: Final = 64 * 1024
MAX_KEYRING_KEYS: Final = 16
"""Keys a black-box keyring takes (``parse_blackbox_keyring``)."""
_SKEW: Final = timedelta(milliseconds=300_000)
_EVIDENCE_LOCK_NAMESPACE: Final = 0x524F424F44520001  # "ROBODR" + 1
_REPORT_TEXT_RE: Final = re.compile(r"[!-~]{1,128}")
_HEX64_RE: Final = re.compile(r"[0-9a-f]{64}")


def _decode(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AutoSecOpsValidationError(f"{what} is not valid base64") from exc


def _uint(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"manifest {what} is not a non-negative integer")
    return value


def _hex64(value: object, what: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise ValueError(f"manifest {what} is not a lower-case SHA-256")
    return value


def _token(value: object, what: str) -> str:
    """Printable ASCII without spaces: no newline or control character."""
    if not isinstance(value, str) or _REPORT_TEXT_RE.fullmatch(value) is None:
        raise ValueError(f"manifest {what} is not printable ASCII")
    return value


def report_text(
    manifest: Manifest,
    *,
    manifest_sha256: str,
    manifest_key_id: str,
    storage_key: str,
    evidence_id: uuid.UUID,
) -> str:
    """The plain-text verification report attached to the case.

    Every value comes from the signature-checked manifest or is a fixed
    word, and is checked to be a number, a SHA-256 or a printable ASCII
    token before it is written: nothing can add a line or a control
    character to the report.

    Raises:
        ValueError: A manifest value is not of its documented form.
    """
    records = manifest.raw.get("records")
    records = records if isinstance(records, dict) else {}
    anchor = manifest.raw.get("anchor")
    referenced = manifest.raw.get("referenced", [])
    if not isinstance(referenced, list):
        raise ValueError("manifest referenced is not a list")
    lines = [
        "RoboDR evidence export: verified (robodr.control-plane section 11.6)",
        f"evidence_id: {evidence_id}",
        f"robot_id: {_token(manifest.robot_id, 'robot_id')}",
        f"export_id: {_token(manifest.export_id, 'export_id')}",
        f"manifest_sha256: {_hex64(manifest_sha256, 'sha256')}",
        f"manifest_signed_by: {_token(manifest_key_id, 'signature key id')}",
        f"chain_id: {_hex64(manifest.chain_id, 'chain_id')}",
        f"blackbox_signing_key: {_token(manifest.signing_key_id, 'signing_key')}",
        f"records: {_uint(records.get('first_seq'), 'first_seq')}.."
        f"{_uint(records.get('last_seq'), 'last_seq')} "
        f"({_uint(records.get('count'), 'count')} records)",
        f"last_record_sha256: {_hex64(records.get('last_sha256'), 'last_sha256')}",
    ]
    if anchor is not None:
        if not isinstance(anchor, dict):
            raise ValueError("manifest anchor is not an object")
        lines.append(
            f"anchor: seq {_uint(anchor.get('seq'), 'anchor.seq')} sha256 "
            f"{_hex64(anchor.get('sha256'), 'anchor.sha256')} "
            "(unverified: first contact)"
        )
    for item in referenced:
        if not isinstance(item, dict):
            raise ValueError("manifest referenced[] is not an object")
        lines.append(
            f"referenced: segment {_uint(item.get('segment'), 'referenced.segment')} "
            f"seq {_uint(item.get('seq'), 'referenced.seq')} "
            f"sha256 {_hex64(item.get('sha256'), 'referenced.sha256')}"
        )
    lines += [
        f"bundle_sha256: {_hex64(manifest.bundle_sha256, 'bundle.sha256')}",
        f"bundle_bytes: {_uint(manifest.bundle_bytes, 'bundle.bytes')}",
        f"bundle_storage_key: {storage_key}",
        "checked_by_platform: manifest signature (registered finding key), "
        "bundle length and SHA-256, black-box record hashes, chain, sequence "
        "and control records, records against the manifest",
        "checked_by_workflow: answer signatures, chunk hashes, black-box "
        "record signatures (intact)",
        f"stored_at: {datetime.now(UTC).isoformat()}",
    ]
    return "\n".join(lines) + "\n"


def _check_verification(verification: dict[str, object]) -> None:
    """The workflow's report must say verified and intact (and be small)."""
    try:
        size = len(json.dumps(verification, default=str))
    except (TypeError, ValueError) as exc:
        raise AutoSecOpsValidationError("verification is not JSON") from exc
    if size > MAX_VERIFICATION_JSON_BYTES:
        raise AutoSecOpsValidationError("verification is too large")
    if verification.get("verified") is not True:
        raise AutoSecOpsValidationError("only verified evidence is stored")
    if verification.get("intact") is not True:
        raise AutoSecOpsValidationError("only intact evidence is stored")


def _overlaps(
    *,
    valid_from: datetime | None,
    valid_to: datetime,
    from_ms: int | None,
    to_ms: int | None,
) -> bool:
    """Whether a key's validity (with clock skew) meets ``[from_ms, to_ms]``."""
    if from_ms is not None and valid_to + _SKEW < _ms(from_ms):
        return False
    if to_ms is not None and valid_from is not None and valid_from - _SKEW > _ms(to_ms):
        return False
    return True


def _ms(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1000, tz=UTC)


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

    async def blackbox_key_files(
        self,
        robot_id: str,
        *,
        from_ms: int | None = None,
        to_ms: int | None = None,
    ) -> list[str]:
        """The robot's black-box public key files (``robodr-blackbox-key/v2``).

        Only keys registered by fleet enrollment (the robot proved it holds
        them; black-box keys are not rotated by the fleet API), newest first,
        and only those valid for records between ``from_ms`` and ``to_ms``
        (Unix ms, either open): a key is valid from its enrollment (its first
        enrollment: since ever, as ``--reuse-existing-keys`` may register
        agentd's existing key) until the next enrollment retired it, with the
        contract's 300 s clock skew on both ends. The current key is always
        included. Nothing is cut off silently: more than
        :data:`MAX_KEYRING_KEYS` keys is an error.

        Raises:
            AutoSecOpsNotFoundError: The robot has no enrolled black-box key.
            AutoSecOpsValidationError: More keys match than a keyring holds.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        stmt = (
            select(RobotKey.public_key, RobotKey.created_at, RobotKey.revoked_at)
            .join(Robot, Robot.id == RobotKey.robot_fk)
            .where(
                Robot.workspace_id == self.workspace_id,
                Robot.robot_id == robot_id,
                RobotKey.workspace_id == self.workspace_id,
                RobotKey.role == RobotKeyRole.BLACKBOX.value,
                RobotKey.provenance == RobotKeyProvenance.ENROLLMENT.value,
            )
            .order_by(RobotKey.created_at.desc(), RobotKey.surrogate_id.desc())
        )
        rows = (await self.session.execute(stmt)).tuples().all()
        if not rows:
            raise AutoSecOpsNotFoundError(
                "The robot has no black-box key registered by enrollment "
                "(enroll it with robodr-enroll)"
            )
        oldest = len(rows) - 1
        selected = [
            bytes(public_key)
            for index, (public_key, created_at, revoked_at) in enumerate(rows)
            if revoked_at is None
            or _overlaps(
                valid_from=None if index == oldest else created_at,
                valid_to=revoked_at,
                from_ms=from_ms,
                to_ms=to_ms,
            )
        ]
        if len(selected) > MAX_KEYRING_KEYS:
            raise AutoSecOpsValidationError(
                f"{len(selected)} black-box keys are valid for this time range, "
                f"more than a keyring holds ({MAX_KEYRING_KEYS}): narrow "
                "from_ms/to_ms or pass the keys explicitly"
            )
        return [public_key_file(key) for key in selected]

    async def store_verified_export(
        self, case_id: uuid.UUID, params: EvidenceStoreRequest
    ) -> EvidenceStoreResponse:
        """Check and store a verified export; attach its report to the case.

        Raises:
            AutoSecOpsNotFoundError: The case or the robot's finding key is unknown.
            AutoSecOpsValidationError: The export does not check out.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        cases = CasesService(self.session, role=self.role)
        case = await cases.get_case(case_id)
        if case is None:
            raise AutoSecOpsNotFoundError("Case not found")

        manifest_bytes = _decode(params.manifest_base64, "manifest_base64")
        if len(params.bundle_base64) > 4 * (
            config.AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES // 3 + 1
        ):
            raise AutoSecOpsValidationError("the evidence bundle is too large")
        bundle = _decode(params.bundle_base64, "bundle_base64")
        if len(bundle) > config.AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES:
            raise AutoSecOpsValidationError("the evidence bundle is too large")

        parsed = parse_signature_header(params.manifest_signature)
        if parsed is None:
            raise AutoSecOpsValidationError("manifest_signature is malformed")
        key_id = parsed[0]
        keys = await self._finding_keys(params.robot_id)
        if key_id not in keys:
            raise AutoSecOpsNotFoundError(
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
            raise AutoSecOpsValidationError(str(exc)) from exc
        bundle_sha256 = hashlib.sha256(bundle).hexdigest()
        if len(bundle) != manifest.bundle_bytes or bundle_sha256 != (
            manifest.bundle_sha256
        ):
            raise AutoSecOpsValidationError("the bundle does not match its manifest")
        _check_verification(params.verification)
        # §11.6 steps 4-5 again, here: everything but the record signatures.
        report = verify_bundle(
            bundle,
            None,
            robot_id=params.robot_id,
            signing_key_id=manifest.signing_key_id,
        )
        problems = report.problems or check_report_against_manifest(report, manifest)
        if problems:
            raise AutoSecOpsValidationError(
                "the bundle does not verify: " + "; ".join(problems[:5])
            )

        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        evidence_id = uuid.uuid4()
        prefix = evidence_storage_prefix(
            self.workspace_id, manifest_sha256, evidence_id
        )
        storage_key = f"{prefix}/{BUNDLE_OBJECT}"
        try:
            content = report_text(
                manifest,
                manifest_sha256=manifest_sha256,
                manifest_key_id=key_id,
                storage_key=storage_key,
                evidence_id=evidence_id,
            ).encode("ascii")
        except (ValueError, UnicodeEncodeError) as exc:
            raise AutoSecOpsValidationError(str(exc)) from exc
        await self._reserve_quota(len(bundle))

        # Objects first (each under a fresh, never-reused key), then the rows
        # and the report in one commit; on any failure the objects go.
        await self._upload_new(
            prefix,
            (
                (BUNDLE_OBJECT, bundle, "application/octet-stream"),
                (MANIFEST_OBJECT, manifest_bytes, "application/json"),
                (
                    SIGNATURE_OBJECT,
                    params.manifest_signature.encode("ascii"),
                    "text/plain",
                ),
            ),
        )
        name = f"{ROBODR_EVIDENCE_PREFIX}{bundle_sha256[:16]}.txt"
        try:
            self.session.add(
                RobotEvidenceExport(
                    id=evidence_id,
                    workspace_id=self.workspace_id,
                    case_id=case.id,
                    robot_id=params.robot_id,
                    export_id=params.export_id,
                    manifest_sha256=manifest_sha256,
                    bundle_sha256=bundle_sha256,
                    bundle_bytes=len(bundle),
                    storage_prefix=prefix,
                )
            )
            attachment = await cases.attachments.create_attachment(
                case,
                CaseAttachmentCreate(
                    file_name=name,
                    content_type="text/plain",
                    size=len(content),
                    content=content,
                ),
                robodr_evidence=True,
            )
        except BaseException:
            await self.session.rollback()
            await delete_evidence_objects([prefix])
            raise
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

    async def _reserve_quota(self, size: int) -> None:
        """Refuse a bundle over the workspace's evidence quota.

        A transaction-scoped advisory lock per workspace serializes stores
        until the storing transaction commits, so two concurrent stores
        cannot both fit under the quota.
        """
        lock = (self.workspace_id.int ^ _EVIDENCE_LOCK_NAMESPACE) & (2**63 - 1)
        await self.session.execute(select(func.pg_advisory_xact_lock(lock)))
        used = await self.session.scalar(
            select(func.coalesce(func.sum(RobotEvidenceExport.bundle_bytes), 0)).where(
                RobotEvidenceExport.workspace_id == self.workspace_id
            )
        )
        quota = config.AUTOSECOPS__ROBOT_EDR_EVIDENCE_QUOTA_BYTES
        if int(used or 0) + size > quota:
            raise AutoSecOpsValidationError(
                f"the workspace's RoboDR evidence quota ({quota} bytes) is "
                "exhausted; delete cases with stored evidence or raise "
                "AUTOSECOPS__ROBOT_EDR_EVIDENCE_QUOTA_BYTES"
            )

    async def _upload_new(
        self, prefix: str, objects: tuple[tuple[str, bytes, str], ...]
    ) -> None:
        """Upload objects under keys that must not exist yet (never overwrite)."""
        bucket = config.AUTOSECOPS__BLOB_STORAGE_BUCKET_ATTACHMENTS
        uploaded: list[str] = []
        try:
            for name, data, content_type in objects:
                key = f"{prefix}/{name}"
                if await blob.file_exists(key, bucket):
                    raise AutoSecOpsValidationError(
                        "the evidence storage key is already in use"
                    )
                await blob.upload_file(data, key, bucket, content_type)
                uploaded.append(name)
        except BaseException:
            if uploaded:
                await delete_evidence_objects([prefix])
            raise

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
