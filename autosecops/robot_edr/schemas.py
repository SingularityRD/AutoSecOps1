"""API schemas for robot management and RoboDR ingest."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from autosecops import config
from autosecops.core.schemas import Schema
from autosecops.robot_edr.types import (
    FleetApprovalStatus,
    FleetRotationStatus,
    FleetSocKeyCustody,
    FleetSocKeyKind,
    FleetSocKeyStatus,
    LineErrorCode,
    RobotKeyProvenance,
    RobotKeyRole,
)

ROBOT_ID_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"
LABEL_PATTERN = r"^[ -;=?-_a-~]*$"
PUBLIC_KEY_HEX_PATTERN = r"^[0-9a-f]{64}$"
KEY_ID_PATTERN = r"^[!-~]{1,128}$"


class RobotCreate(Schema):
    """Register a robot in the workspace."""

    model_config = ConfigDict(extra="forbid")

    robot_id: str = Field(
        ...,
        pattern=ROBOT_ID_PATTERN,
        description="RoboDR robot id (`entity_context.robot.id`)",
    )
    site: str | None = Field(default=None, max_length=128, pattern=LABEL_PATTERN)
    model: str | None = Field(default=None, max_length=128, pattern=LABEL_PATTERN)
    morphology: str | None = Field(default=None, max_length=64, pattern=LABEL_PATTERN)
    require_finding_signature: bool = Field(
        default=False,
        description="Refuse findings for this robot that carry no per-finding signature",
    )


class RobotUpdate(Schema):
    """Update a robot's descriptive fields or signature policy."""

    model_config = ConfigDict(extra="forbid")

    site: str | None = Field(default=None, max_length=128, pattern=LABEL_PATTERN)
    model: str | None = Field(default=None, max_length=128, pattern=LABEL_PATTERN)
    morphology: str | None = Field(default=None, max_length=64, pattern=LABEL_PATTERN)
    require_finding_signature: bool | None = Field(default=None)


class RobotRead(Schema):
    """A registered robot."""

    id: uuid.UUID
    robot_id: str
    site: str | None
    model: str | None
    morphology: str | None
    require_finding_signature: bool
    fleet_enrolled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RobotKeyCreate(Schema):
    """Register an Ed25519 public key.

    ``uplink`` and ``finding`` keys name a robot; ``relay`` keys do not. A
    sender key's id is always derived from its public key
    (``ed25519:<16 hex>``); a ``finding`` key may carry the producer's own key
    id (printable ASCII, 1-128 characters) and defaults to the derived id.
    """

    model_config = ConfigDict(extra="forbid")

    role: RobotKeyRole
    robot_id: str | None = Field(default=None, pattern=ROBOT_ID_PATTERN)
    public_key: str = Field(
        ...,
        pattern=PUBLIC_KEY_HEX_PATTERN,
        description="Ed25519 public key, 64 lower-case hex digits",
    )
    key_id: str | None = Field(default=None, pattern=KEY_ID_PATTERN)
    site: str | None = Field(
        default=None,
        max_length=128,
        pattern=LABEL_PATTERN,
        description="Relay keys only: report only robots registered with this site",
    )
    vouches_origin: bool = Field(
        default=False,
        description=(
            "Relay keys only, for the SOC-side diode importer: findings it relays "
            "satisfy require_finding_signature without a per-finding signature"
        ),
    )
    expires_at: datetime | None = Field(default=None)


class RobotKeyRead(Schema):
    """A registered key (public material only)."""

    id: uuid.UUID
    key_id: str
    role: RobotKeyRole
    robot_id: str | None
    public_key: str
    site: str | None
    vouches_origin: bool
    revoked_at: datetime | None
    expires_at: datetime | None
    provenance: RobotKeyProvenance | None = Field(
        default=None,
        description="How the key was registered (null: before this was recorded)",
    )
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class IngestLineRejection(BaseModel):
    """One rejected NDJSON line."""

    line: int = Field(..., ge=1, description="1-based line number")
    code: LineErrorCode
    detail: str


class IngestResponse(BaseModel):
    """`200` body of `POST /robot-edr/v2/ingest` (ingest contract §6)."""

    batch_id: str
    replayed: bool
    accepted: int
    created: int
    updated: int
    duplicates: int
    rejected: list[IngestLineRejection]


class IngestErrorResponse(BaseModel):
    """Error body of `POST /robot-edr/v2/ingest`."""

    code: str
    detail: str


# --- evidence (robodr.control-plane §11) ------------------------------------------

EXPORT_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"


class EvidenceStoreRequest(BaseModel):
    """A verified evidence export to store for a case (internal API)."""

    model_config = ConfigDict(extra="forbid")

    robot_id: str = Field(..., pattern=ROBOT_ID_PATTERN)
    export_id: str = Field(..., pattern=EXPORT_ID_PATTERN)
    manifest_base64: str = Field(..., min_length=1, max_length=2 * 1024 * 1024)
    manifest_signature: str = Field(..., min_length=1, max_length=512)
    bundle_base64: str = Field(
        ...,
        min_length=1,
        # Base64 of at most AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES, refused
        # before it is decoded (or parsed as a bundle).
        max_length=4 * -(-config.AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES // 3),
    )
    verification: dict[str, object] = Field(
        ...,
        max_length=64,
        description=(
            "The workflow's §11.6 verification report; it must say verified "
            "and intact, and the platform re-checks the bundle against the "
            "manifest itself"
        ),
    )


class EvidenceStoreResponse(BaseModel):
    """Where a verified evidence export was stored."""

    attachment_id: uuid.UUID
    attachment_name: str
    storage_key: str
    bundle_sha256: str
    bundle_bytes: int
    manifest_sha256: str
    manifest_key_id: str


class EvidenceAccessRequest(BaseModel):
    """An evidence read to write to the audit log (internal API)."""

    model_config = ConfigDict(extra="forbid")

    robot_id: str = Field(..., pattern=ROBOT_ID_PATTERN)
    operation: Literal["list", "create_export", "download_export"]
    export_id: str | None = Field(default=None, pattern=EXPORT_ID_PATTERN)


REQUEST_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
ROBOT_ACTION_PATTERN = r"^robot_[a-z_]{1,64}$"
ROBOT_OUTCOME_PATTERN = r"^[a-z_]{1,64}$"
REQUEST_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
FAILURE_REASON_PATTERN = r"^[A-Za-z0-9_.]{1,64}$"
MAX_ACTION_APPROVALS = 4
"""Approval submissions a robot action request reads (registry limit)."""


class RobotActionAuditRequest(BaseModel):
    """A robot action request or revert to write to the audit log (internal API).

    The registry action sends one ``attempt`` before it signs the request
    (nothing is sent to the robot unless it is written), then ``answered``
    or ``failed``. The people are not taken from this body: the platform
    reads them from the sign-off submissions it names.
    """

    model_config = ConfigDict(extra="forbid")

    robot_id: str = Field(..., pattern=ROBOT_ID_PATTERN)
    request_id: str = Field(..., pattern=REQUEST_ID_PATTERN)
    operation: Literal["request_action", "revert_action"]
    robot_action: str = Field(..., pattern=ROBOT_ACTION_PATTERN)
    request_digest: str = Field(..., pattern=REQUEST_DIGEST_PATTERN)
    request_submission_id: uuid.UUID
    approval_submission_ids: list[uuid.UUID] = Field(
        ..., min_length=1, max_length=MAX_ACTION_APPROVALS
    )
    phase: Literal["attempt", "answered", "failed"]
    outcome: str | None = Field(default=None, pattern=ROBOT_OUTCOME_PATTERN)
    """``answered``: the robot's status (e.g. ``recorded_not_executed``)."""
    applied: bool | None = Field(default=None)
    """``answered``: whether the robot reports the action applied."""
    failure_reason: str | None = Field(default=None, pattern=FAILURE_REASON_PATTERN)
    """``failed``: the error type that stopped the call."""


# --- fleet (robodr.fleet API v1) --------------------------------------------------

FLEET_LABEL_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"
FLEET_VERSION_PATTERN = r"^[0-9][0-9A-Za-z.+~-]{0,63}$"
FLEET_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
MAX_TOKEN_VALIDITY_HOURS = 168
MAX_APPROVAL_VALIDITY_HOURS = 168


class FleetErrorResponse(BaseModel):
    """Error body of the robot-facing fleet endpoints (contract §2.6)."""

    code: str
    detail: str


class FleetDraftReceipt(BaseModel):
    """`200` body of `POST /robot-edr/v2/fleet/profiles/drafts`."""

    digest: str
    status: Literal["received"]


class FleetSocKeyCreate(Schema):
    """Create a SOC key.

    Fleet keys are online: generated on the server, or imported from a secret
    key file. Approval keys are ``offline`` (recommended: only the public key
    file is registered and approvals are signed by the operator who holds the
    secret) or ``online`` (generated on the server; lower assurance). An
    approval key's secret is never imported.
    """

    model_config = ConfigDict(extra="forbid")

    kind: FleetSocKeyKind
    custody: FleetSocKeyCustody = Field(
        default=FleetSocKeyCustody.ONLINE,
        description=(
            "online: the server holds the secret and signs; offline (approval "
            "keys only): register public_key_file and upload detached signatures"
        ),
    )
    secret_key_file: str | None = Field(
        default=None,
        max_length=4096,
        description=(
            "Fleet keys only: a robodr-blackbox-key/v2 secret key file to import "
            "instead of generating a key on the server"
        ),
    )
    public_key_file: str | None = Field(
        default=None,
        max_length=4096,
        description=(
            "Offline approval keys: the robodr-blackbox-key/v2 public key file "
            "(or 64 hex digits) of the operator-held approval key"
        ),
    )


class FleetSocKeyRead(Schema):
    """A SOC key (public material only)."""

    id: uuid.UUID
    kind: FleetSocKeyKind
    key_id: str
    fingerprint: str
    custody: FleetSocKeyCustody
    status: FleetSocKeyStatus
    public_key_file: str = Field(
        ..., description="The robodr-blackbox-key/v2 public file robots install"
    )
    created_by: uuid.UUID | None
    activated_by: uuid.UUID | None
    created_at: datetime
    activated_at: datetime | None
    retired_at: datetime | None


class FleetTokenCreate(Schema):
    """Issue a single-use enrollment token for a robot."""

    model_config = ConfigDict(extra="forbid")

    validity_hours: int = Field(default=24, ge=1, le=MAX_TOKEN_VALIDITY_HOURS)


class FleetTokenRead(Schema):
    """An enrollment token (never the token itself)."""

    id: uuid.UUID
    token_id: str
    robot_id: str
    site: str | None
    workspace: str
    soc_key_id: str
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    revoked_at: datetime | None
    status: Literal["active", "consumed", "expired", "revoked"]


class FleetTokenIssued(FleetTokenRead):
    """A newly issued token: the only response that carries the token."""

    token: str = Field(
        ...,
        description=(
            "The compact token (rdet1.…). A bearer credential until consumed: it is "
            "shown once and never stored"
        ),
    )


class FleetRotationRead(Schema):
    """A key rotation of the robot (contract §5)."""

    rotation_id: str
    role: RobotKeyRole
    old_key_id: str
    new_key_id: str
    status: FleetRotationStatus
    received: bool = Field(
        ..., description="False for a cancel of a rotation the SOC never received"
    )
    created_at: datetime
    closed_at: datetime | None


class FleetDraftRead(Schema):
    """A draft profile the robot published for review."""

    id: uuid.UUID
    digest: str
    size: int
    received_at: datetime


class FleetDraftContent(FleetDraftRead):
    """A draft profile with its file text."""

    profile: str


class FleetOfferUpdate(Schema):
    """Offer a locked, signed profile to the robot (contract §6.2)."""

    model_config = ConfigDict(extra="forbid")

    profile: str = Field(
        ...,
        min_length=1,
        max_length=1024 * 1024,
        description="The locked profile file, exactly as robodr-commission wrote it",
    )
    signature: str = Field(
        ...,
        min_length=1,
        max_length=64 * 1024,
        description="The profile's .sig file, exactly as written",
    )


class FleetOfferRead(Schema):
    """The profile currently offered to the robot."""

    digest: str
    profile_version: int
    platform: str
    updated_at: datetime


class FleetApprovalCreate(Schema):
    """Request an observe -> enforce approval of the offered profile."""

    model_config = ConfigDict(extra="forbid")

    profile_digest: str = Field(..., pattern=FLEET_DIGEST_PATTERN)
    validity_hours: int = Field(default=24, ge=1, le=MAX_APPROVAL_VALIDITY_HOURS)


class FleetApprovalRead(Schema):
    """An approval request and, once two people signed it off, its signature."""

    id: uuid.UUID
    approval_id: str
    profile_digest: str
    profile_version: int
    platform: str
    status: FleetApprovalStatus
    requested_by: uuid.UUID | None
    approved_by: uuid.UUID | None
    validity_hours: int
    issued_at: datetime | None
    expires_at: datetime | None
    signer_key_id: str | None
    signing_payload: str | None = Field(
        default=None,
        description=(
            "Prepared approvals: the profile-approval payload (base64url, no "
            "padding) the offline approval key signs"
        ),
    )
    signing_message_hex: str | None = Field(
        default=None,
        description=(
            "Prepared approvals: the exact bytes to sign with Ed25519 (contract "
            "§2.3 message for type profile-approval and signer_key_id), as hex"
        ),
    )
    created_at: datetime


class FleetApprovalSignature(Schema):
    """The offline approval key's detached signature of a prepared approval."""

    model_config = ConfigDict(extra="forbid")

    signature: str = Field(
        ...,
        pattern=r"^[0-9a-f]{128}$",
        description="Ed25519 signature of signing_message_hex, 128 lower-case hex",
    )


class FleetRingUpdate(Schema):
    """Publish update-ring information for the robot (contract §7)."""

    model_config = ConfigDict(extra="forbid")

    ring: int = Field(..., ge=0, le=2, description="0 canary, 1 early, 2 broad")
    target_version: str | None = Field(default=None, pattern=FLEET_VERSION_PATTERN)
    bundle_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    min_version: str | None = Field(
        default=None,
        pattern=FLEET_VERSION_PATTERN,
        description="Security floor: the lowest release the robot may run",
    )
    validity_hours: int = Field(default=24 * 7, ge=1, le=24 * 90)


class FleetRingRead(Schema):
    """The latest update-ring document of the robot."""

    serial: int
    ring: int
    target_version: str | None
    bundle_sha256: str | None
    min_version: str | None
    issued_at: datetime
    expires_at: datetime


class FleetRevocationCreate(Schema):
    """Publish a root-signed revocation list for a platform (contract §4.1)."""

    model_config = ConfigDict(extra="forbid")

    revocation_list: str = Field(
        ...,
        min_length=1,
        max_length=1024 * 1024,
        description=(
            "The list, signed by one of the workspace's trust roots (it is "
            "refused otherwise)"
        ),
    )


class FleetRevocationRead(Schema):
    """A published revocation list."""

    id: uuid.UUID
    platform: str
    serial: int
    list_digest: str
    signer_key_id: str
    signature_checked: bool
    trust_root_key_id: str | None
    withdrawal_reason: str | None
    withdrawal_requested_by: uuid.UUID | None
    withdrawal_requested_at: datetime | None
    withdrawn_by: uuid.UUID | None
    withdrawn_at: datetime | None
    created_at: datetime


class FleetRevocationWithdraw(Schema):
    """Request the withdrawal of a published revocation list."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=512, pattern=LABEL_PATTERN)


class FleetTrustRootCreate(Schema):
    """Trust a robodr-commission trust root for revocation lists (§4.1)."""

    model_config = ConfigDict(extra="forbid")

    public_key: str = Field(
        ...,
        min_length=64,
        max_length=4096,
        description="robodr-blackbox-key/v2 public key file, or 64 hex digits",
    )
    label: str | None = Field(default=None, max_length=128, pattern=LABEL_PATTERN)


class FleetTrustRootRead(Schema):
    """A trust root of the workspace."""

    id: uuid.UUID
    key_id: str
    fingerprint: str
    label: str | None
    created_by: uuid.UUID | None
    created_at: datetime
    revoked_at: datetime | None


class RobotFleetStatus(Schema):
    """The fleet lifecycle of one robot (latest 20 items of each kind)."""

    enrolled: bool
    workspace: str | None
    enrolled_at: datetime | None
    agentd_version: str | None
    profile_digest: str | None
    tokens: list[FleetTokenRead]
    rotations: list[FleetRotationRead]
    drafts: list[FleetDraftRead]
    offer: FleetOfferRead | None
    approvals: list[FleetApprovalRead]
    ring: FleetRingRead | None
