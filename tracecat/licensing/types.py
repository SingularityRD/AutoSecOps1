"""Domain types for license keys."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from tracecat.tiers.enums import Entitlement


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


class LicenseClaims(BaseModel):
    """Signed payload of a license key.

    Unknown fields are ignored so newer issuers stay readable by older
    releases; the signature still covers every byte of the payload.
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

    @model_validator(mode="after")
    def _check_validity_window(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self


@dataclass(frozen=True, slots=True)
class LicenseState:
    """Evaluated license at a point in time."""

    status: LicenseStatus
    claims: LicenseClaims | None = None
    granted: frozenset[Entitlement] = frozenset()
    """Entitlements that apply now; empty unless the status is VALID or GRACE."""
    unknown_entitlements: tuple[str, ...] = ()
    """Entitlement keys in the license that this release does not recognize."""
    grace_ends_at: datetime | None = None
    error: LicenseErrorCode | None = None
