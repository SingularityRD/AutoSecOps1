"""API schemas for robot management and RoboDR ingest."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from autosecops.core.schemas import Schema
from autosecops.robot_edr.types import LineErrorCode, RobotKeyRole

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
