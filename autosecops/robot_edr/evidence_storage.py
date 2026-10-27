"""Object storage of verified RoboDR evidence exports (bundle, manifest, signature).

Every stored export gets its own prefix,
``robot-edr/evidence/<workspace>/<manifest sha256>/<export row id>/``, so a
second export of the same evidence never overwrites the first one's objects.
A `RobotEvidenceExport` row records each prefix: the rows count against the
workspace's evidence quota, and deleting a case deletes its objects once the
deletion commits.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.db.models import RobotEvidenceExport
from autosecops.db.session_events import AfterCommitQueue
from autosecops.logger import logger
from autosecops.storage import blob

EVIDENCE_KEY_PREFIX: Final = "robot-edr/evidence"
BUNDLE_OBJECT: Final = "bundle.rbbx"
MANIFEST_OBJECT: Final = "manifest.json"
SIGNATURE_OBJECT: Final = "manifest.sig"
EVIDENCE_OBJECTS: Final = (BUNDLE_OBJECT, MANIFEST_OBJECT, SIGNATURE_OBJECT)


def evidence_storage_prefix(
    workspace_id: object, manifest_sha256: str, export_row_id: uuid.UUID
) -> str:
    """Object-storage prefix of one stored export (unique per stored export)."""
    return f"{EVIDENCE_KEY_PREFIX}/{workspace_id}/{manifest_sha256}/{export_row_id}"


async def delete_evidence_objects(prefixes: Iterable[str]) -> None:
    """Delete stored evidence objects; best effort (logged, never raised)."""
    bucket = config.AUTOSECOPS__BLOB_STORAGE_BUCKET_ATTACHMENTS
    for prefix in prefixes:
        for name in EVIDENCE_OBJECTS:
            try:
                await blob.delete_file(f"{prefix}/{name}", bucket)
            except Exception as exc:
                logger.warning(
                    "Failed to delete RoboDR evidence object",
                    key=f"{prefix}/{name}",
                    error_type=type(exc).__name__,
                )


async def case_evidence_prefixes(
    session: AsyncSession, workspace_id: uuid.UUID, case_ids: Iterable[uuid.UUID]
) -> list[str]:
    """Storage prefixes of the evidence stored for these cases."""
    ids = list(case_ids)
    if not ids:
        return []
    stmt = select(RobotEvidenceExport.storage_prefix).where(
        RobotEvidenceExport.workspace_id == workspace_id,
        RobotEvidenceExport.case_id.in_(ids),
    )
    return list((await session.scalars(stmt)).all())


def delete_evidence_objects_after_commit(
    session: AsyncSession, prefixes: list[str]
) -> None:
    """Delete these evidence objects once the session commits (not on rollback).

    Case deletion reads the prefixes first (the rows cascade with the case),
    deletes the case, then calls this.
    """
    if prefixes:
        AfterCommitQueue.of(session).add(lambda: delete_evidence_objects(prefixes))
