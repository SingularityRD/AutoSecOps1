"""Schemas for the platform license status endpoint."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from tracecat.licensing.types import LicenseErrorCode, LicenseStatus
from tracecat.tiers.enums import Entitlement


class LicenseRead(BaseModel):
    """License status for the platform admin."""

    status: LicenseStatus
    enforced: bool = Field(
        description="Whether the license controls entitlements."
        " False in multi-tenant mode, where database tiers apply."
    )
    license_id: str | None = Field(default=None)
    customer: str | None = Field(default=None)
    issued_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    grace_ends_at: datetime | None = Field(default=None)
    entitlements: list[Entitlement] = Field(
        default_factory=list,
        description="Paid entitlements the license grants right now",
    )
    included_entitlements: list[Entitlement] = Field(
        default_factory=list,
        description="Free entitlements every single-tenant install gets"
        " without a license",
    )
    licensed_entitlements: list[str] = Field(
        default_factory=list,
        description="Every entitlement key listed in the license",
    )
    error: LicenseErrorCode | None = Field(default=None)
