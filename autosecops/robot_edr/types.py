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
    BLACKBOX = "blackbox"
    """Verifies its robot's black-box records and evidence bundles; registered
    at fleet enrollment and never authenticates a batch or a fleet request."""


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


class FleetErrorCode(StrEnum):
    """Error codes of the `robodr.fleet` API (contract §2.6)."""

    BAD_REQUEST = "bad_request"
    BAD_HEADER = "bad_header"
    INVALID_PROFILE = "invalid_profile"
    BAD_TOKEN = "bad_token"
    BAD_SIGNATURE = "bad_signature"
    UNKNOWN_KEY = "unknown_key"
    STALE_TIMESTAMP = "stale_timestamp"
    WRONG_KEY = "wrong_key"
    REPLAYED_REQUEST = "replayed_request"
    WORKSPACE_MISMATCH = "workspace_mismatch"
    ROBOT_MISMATCH = "robot_mismatch"
    NO_LIST = "no_list"
    NO_PROFILE = "no_profile"
    NO_APPROVAL = "no_approval"
    NO_RING = "no_ring"
    UNKNOWN_ROTATION = "unknown_rotation"
    NOT_FOUND = "not_found"
    TOKEN_USED = "token_used"
    KEY_CONFLICT = "key_conflict"
    ROTATION_IN_PROGRESS = "rotation_in_progress"
    ROTATION_ID_REUSE = "rotation_id_reuse"
    STALE_KEY = "stale_key"
    ALREADY_RETIRED = "already_retired"
    ROTATION_CANCELLED = "rotation_cancelled"
    ALREADY_CANCELLED = "already_cancelled"
    TOKEN_EXPIRED = "token_expired"
    TOO_LARGE = "too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    # AutoSecOps extensions (contract §2.6 allows new codes):
    NOT_ENTITLED = "not_entitled"
    """`403`: the workspace lacks the `robot_edr` entitlement."""
    TLS_REQUIRED = "tls_required"
    """`403`: plain HTTP from a non-loopback client (contract §1)."""
    NO_FLEET_KEY = "no_fleet_key"
    """`503`: the workspace has no active SOC fleet key to sign the answer."""


class FleetSocKeyKind(StrEnum):
    """The two kinds of SOC Ed25519 keys (contract §2.7)."""

    FLEET = "fleet"
    """Online: tokens, enroll/rotate/retire/cancel answers, ring information."""
    APPROVAL = "approval"
    """Profile approvals only, used after the two-person sign-off."""


class FleetSocKeyCustody(StrEnum):
    """Where a SOC key's secret lives (contract §2.7)."""

    ONLINE = "online"
    """Generated on the server; the seed is stored encrypted and the API signs."""
    OFFLINE = "offline"
    """Approval keys only: the operator holds the secret (offline or in an
    HSM) and uploads detached signatures; the SOC stores the public key only."""


class RobotKeyProvenance(StrEnum):
    """How a robot key was registered."""

    MANUAL = "manual"
    """Registered by an operator through the key API."""
    ENROLLMENT = "enrollment"
    """Registered by fleet enrollment (proof of possession, contract §3)."""
    ROTATION = "rotation"
    """Registered by a fleet key rotation (contract §5)."""


class FleetSocKeyStatus(StrEnum):
    """Lifecycle of a SOC key (contract §2.7 rotation)."""

    PENDING = "pending"
    """Generated or imported; robots must install it before it signs."""
    ACTIVE = "active"
    """The key the SOC signs with (one per kind and workspace)."""
    RETIRED = "retired"
    """No longer used to sign."""


class FleetRotationStatus(StrEnum):
    """State of a key rotation (contract §5)."""

    OPEN = "open"
    RETIRED = "retired"
    CANCELLED = "cancelled"


class FleetApprovalStatus(StrEnum):
    """State of a profile approval (contract §6.3)."""

    PENDING = "pending"
    """Requested by one operator; waits for a second, distinct operator."""
    PREPARED = "prepared"
    """Two people signed it off and the payload is fixed; it waits for the
    detached signature of the offline approval key."""
    SIGNED = "signed"
    """Signed by the approval key; served to the robot."""
    CANCELLED = "cancelled"


class FleetFailureReason(StrEnum):
    """Why a fleet request failed authentication; recorded in the audit log."""

    BAD_HEADER = "bad_header"
    UNKNOWN_KEY = "unknown_key"
    STALE_TIMESTAMP = "stale_timestamp"
    BAD_SIGNATURE = "bad_signature"
    WRONG_KEY = "wrong_key"
    REPLAYED_REQUEST = "replayed_request"
    BAD_TOKEN = "bad_token"


@dataclass(frozen=True, slots=True)
class FleetRobot:
    """The robot an authenticated fleet request acts for."""

    robot_fk: uuid.UUID
    robot_id: str
    workspace_id: WorkspaceID
    organization_id: OrganizationID
    fleet_workspace: str
    """The workspace label of the robot's enrollment (the contract's `workspace`)."""
    key_fk: uuid.UUID
    key_id: str
    """The uplink key that authenticated the request."""
