"""Domain types for RoboDR ingest."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

from autosecops.identifiers import OrganizationID, WorkspaceID


class RobotKeyRole(StrEnum):
    """What a registered Ed25519 key may authenticate (ingest contract §3)."""

    UPLINK = "uplink"
    """Signs batches for its one robot."""
    RELAY = "relay"
    """Signs batches for any robot registered in the workspace."""
    FINDING = "finding"
    """Verifies per-finding signatures of its robot; never signs a batch."""


SENDER_KEY_ROLES: frozenset[RobotKeyRole] = frozenset(
    {RobotKeyRole.UPLINK, RobotKeyRole.RELAY}
)


class IngestErrorCode(StrEnum):
    """Whole-request error codes of `POST /robot-edr/v2/ingest`."""

    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    BODY_TOO_LARGE = "body_too_large"
    TOO_MANY_LINES = "too_many_lines"
    BAD_HEADER = "bad_header"
    EMPTY_BATCH = "empty_batch"
    UNKNOWN_KEY = "unknown_key"
    STALE_TIMESTAMP = "stale_timestamp"
    BAD_SIGNATURE = "bad_signature"
    BATCH_ID_REUSE = "batch_id_reuse"
    RATE_LIMITED = "rate_limited"
    # AutoSecOps extensions (contract §6.2 allows new codes):
    TLS_REQUIRED = "tls_required"
    """`403`: plain HTTP from a non-loopback client (contract §1)."""
    NOT_ENTITLED = "not_entitled"
    """`403`: the key's workspace lacks the `robot_edr` entitlement."""


class LineErrorCode(StrEnum):
    """Per-line rejection codes (ingest contract §4 step 5)."""

    INVALID_LINE = "invalid_line"
    INVALID_FINDING = "invalid_finding"
    UNSUPPORTED_CONTRACT = "unsupported_contract"
    TOO_LARGE = "too_large"
    ROBOT_MISMATCH = "robot_mismatch"
    UNKNOWN_ROBOT = "unknown_robot"
    SITE_MISMATCH = "site_mismatch"
    BAD_FINDING_SIGNATURE = "bad_finding_signature"
    MISSING_FINDING_SIGNATURE = "missing_finding_signature"


class AuthFailureReason(StrEnum):
    """Why a batch failed authentication; recorded in the audit log."""

    UNKNOWN_KEY = "unknown_key"
    REVOKED_KEY = "revoked_key"
    EXPIRED_KEY = "expired_key"
    WRONG_ROLE = "wrong_role"
    STALE_TIMESTAMP = "stale_timestamp"
    BAD_SIGNATURE = "bad_signature"


class UpsertOutcome(StrEnum):
    """Result of deduplicating one accepted finding (contract §5)."""

    CREATED = "created"
    UPDATED = "updated"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class SenderKey:
    """A batch-authenticating key resolved from `X-RoboDR-Key-Id`."""

    id: uuid.UUID
    key_id: str
    role: RobotKeyRole
    public_key: bytes
    workspace_id: WorkspaceID
    organization_id: OrganizationID
    robot_fk: uuid.UUID | None
    robot_id: str | None
    site: str | None = None
    """Relay keys: only robots registered with this site."""
    vouches_origin: bool = False
    """Relay keys: findings satisfy ``require_finding_signature`` unsigned."""


@dataclass(frozen=True, slots=True)
class LineRejection:
    """A rejected line as reported in the response."""

    line: int
    code: LineErrorCode
    detail: str
