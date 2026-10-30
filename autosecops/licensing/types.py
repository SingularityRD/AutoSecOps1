"""Domain types for license keys."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
    field_validator,
    model_validator,
)

from autosecops.tiers.enums import Entitlement


class LicenseStatus(StrEnum):
    """Lifecycle state of the configured license key."""

    MISSING = "missing"
    """No license key is configured."""
    VALID = "valid"
    """The signature verifies and the license has not expired."""
    GRACE = "grace"
    """The license expired but is inside the grace period; entitlements still apply."""
    EXPIRED = "expired"
    """The license expired and the grace period ended; entitlements no longer apply."""
    INVALID = "invalid"
    """The key is malformed, its signature fails, or its claims are invalid."""


class LicenseErrorCode(StrEnum):
    """Why a license key failed verification."""

    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    INVALID_CLAIMS = "invalid_claims"
    NOT_YET_VALID = "not_yet_valid"
    """``issued_at`` is in the future beyond the allowed clock skew."""
    DEPLOYMENT_MISMATCH = "deployment_mismatch"
    """The license is bound to a different installation's deployment ID."""


class LicenseGrant(StrEnum):
    """Deployment-wide capabilities a license can grant.

    These are not organization entitlements: they never appear in tiers or in
    ``EffectiveEntitlements``. A license lists them in ``entitlements`` next to
    organization entitlement keys.
    """

    MULTI_TENANT = "multi_tenant"
    """Lets ``AUTOSECOPS__EE_MULTI_TENANT=true`` take effect."""


class LicenseNoticeLevel(StrEnum):
    """Why administrators should be warned about the license."""

    EXPIRING = "expiring"
    """The license is valid but expires within the warning window."""
    GRACE = "grace"
    """The license expired and is inside the grace period."""
    EXPIRED = "expired"
    """The license and its grace period expired."""
    INVALID = "invalid"
    """The configured key does not verify on this installation."""


class LicensePlan(StrEnum):
    """Commercial plan label carried by a license.

    Display only: entitlements and limits in the license decide what applies.
    """

    COMMUNITY = "community"
    TEAM = "team"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    MSSP = "mssp"
    PILOT = "pilot"


class LicenseLimitName(StrEnum):
    """Quantitative limit a license can set."""

    MAX_USERS = "max_users"
    MAX_WORKSPACES = "max_workspaces"
    MAX_ORGANIZATIONS = "max_organizations"
    MAX_CONCURRENT_WORKFLOWS = "max_concurrent_workflows"
    MAX_CONCURRENT_ACTIONS = "max_concurrent_actions"
    MAX_ACTION_EXECUTIONS_PER_WORKFLOW = "max_action_executions_per_workflow"


class LicenseLimits(BaseModel):
    """Quantitative limits a license sets. ``None`` means unlimited."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    max_users: PositiveInt | None = Field(
        default=None,
        description="Active user accounts on a single-tenant install;"
        " service accounts do not count",
    )
    max_workspaces: PositiveInt | None = Field(
        default=None, description="Workspaces on a single-tenant install"
    )
    max_organizations: PositiveInt | None = Field(
        default=None, description="Organizations on a multi-tenant install"
    )
    max_concurrent_workflows: PositiveInt | None = Field(
        default=None, description="Concurrent workflow executions"
    )
    max_concurrent_actions: PositiveInt | None = Field(
        default=None, description="Concurrent action executions"
    )
    max_action_executions_per_workflow: PositiveInt | None = Field(
        default=None, description="Action executions per workflow run"
    )


MAX_LICENSE_EXPIRY = datetime(9000, 1, 1, tzinfo=UTC)
"""Latest accepted ``expires_at``.

Keeps grace-period arithmetic far away from ``datetime.max``. Issue a license
with a long but finite expiry instead of a "perpetual" one.
"""


class LicenseClaims(BaseModel):
    """Signed payload of a license key.

    Unknown fields are ignored so newer issuers stay readable by older
    releases; the signature still covers every byte of the payload.
    ``limits``, ``deployment_id``, and ``plan`` are optional additions to
    payload version 1: releases that predate them ignore them.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    version: Literal[1] = Field(default=1, description="Payload format version")
    license_id: str = Field(min_length=1, max_length=128)
    customer: str = Field(min_length=1, max_length=256)
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    entitlements: list[str] = Field(
        default_factory=list,
        description="Entitlement keys granted on top of the free baseline",
    )
    limits: LicenseLimits | None = Field(
        default=None,
        description="Quantitative limits; absent or null means unlimited",
    )
    deployment_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="If set, the license only verifies on the installation"
        " with this deployment ID",
    )
    plan: LicensePlan | None = Field(
        default=None, description="Commercial plan label, for display only"
    )

    @field_validator("plan", mode="before")
    @classmethod
    def _ignore_unknown_plan(cls, value: object) -> object:
        """Treat a plan label this release does not know as absent."""
        if isinstance(value, str) and value not in LicensePlan:
            return None
        return value

    @model_validator(mode="after")
    def _check_validity_window(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.expires_at >= MAX_LICENSE_EXPIRY:
            raise ValueError(
                f"expires_at must be before {MAX_LICENSE_EXPIRY.date().isoformat()}"
            )
        return self


@dataclass(frozen=True, slots=True)
class LicenseState:
    """Evaluated license at a point in time."""

    status: LicenseStatus
    claims: LicenseClaims | None = None
    granted: frozenset[Entitlement] = frozenset()
    """Entitlements that apply now; empty unless the status is VALID or GRACE."""
    grants: frozenset[LicenseGrant] = frozenset()
    """Deployment grants that apply now; empty unless the status is VALID or GRACE."""
    limits: LicenseLimits = LicenseLimits()
    """Limits that apply now; unlimited unless the status is VALID or GRACE."""
    unknown_entitlements: tuple[str, ...] = ()
    """Entitlement keys in the license that this release does not recognize."""
    grace_ends_at: datetime | None = None
    error: LicenseErrorCode | None = None
