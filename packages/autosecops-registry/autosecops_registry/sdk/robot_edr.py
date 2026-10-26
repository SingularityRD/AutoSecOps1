"""RoboDR (Robot EDR) SDK client for AutoSecOps API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote

if TYPE_CHECKING:
    from autosecops_registry.sdk.client import TracecatClient

type EvidenceOperation = Literal["list", "create_export", "download_export"]


class RobotEdrClient:
    """Client for the RoboDR evidence endpoints of the action gateway."""

    def __init__(self, client: TracecatClient) -> None:
        self._client = client

    async def store_evidence(
        self,
        case_id: str,
        *,
        robot_id: str,
        export_id: str,
        manifest_base64: str,
        manifest_signature: str,
        bundle_base64: str,
        verification: dict[str, Any],
    ) -> dict[str, Any]:
        """Store a verified evidence export for a case.

        The API checks the manifest signature against the robot's registered
        finding key and the bundle against the manifest, stores the bundle,
        manifest and signature in object storage, and attaches a plain-text
        verification report to the case.

        Args:
            case_id: The case UUID or short ID.
            robot_id: The robot the export comes from.
            export_id: The export id.
            manifest_base64: The manifest bytes exactly as received, base64.
            manifest_signature: The `X-RoboDR-Manifest-Signature` value.
            bundle_base64: The verified `RBBXBND1` bundle, base64.
            verification: The client-side verification report.

        Returns:
            The stored evidence: attachment id, storage key and digests.
        """
        return await self._client.post(
            f"/robot-edr/cases/{quote(case_id, safe='')}/evidence",
            json={
                "robot_id": robot_id,
                "export_id": export_id,
                "manifest_base64": manifest_base64,
                "manifest_signature": manifest_signature,
                "bundle_base64": bundle_base64,
                "verification": verification,
            },
        )

    async def record_evidence_access(
        self,
        *,
        robot_id: str,
        operation: EvidenceOperation,
        export_id: str | None = None,
    ) -> None:
        """Write an audit event for reading a robot's evidence."""
        await self._client.post(
            "/robot-edr/evidence/access",
            json={
                "robot_id": robot_id,
                "operation": operation,
                "export_id": export_id,
            },
        )

    async def blackbox_public_keys(self, robot_id: str) -> list[str]:
        """The robot's registered black-box public key files.

        Registered at fleet enrollment (``robodr.fleet`` §3, role
        ``blackbox``); retired keys included, so a chain that spans a
        re-enrollment still verifies.

        Args:
            robot_id: The robot whose keys to read.

        Returns:
            ``robodr-blackbox-key/v2`` public key files (JSON text).
        """
        return await self._client.get(
            f"/robot-edr/robots/{quote(robot_id, safe='')}/blackbox-keys"
        )
