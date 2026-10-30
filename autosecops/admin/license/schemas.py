"""Schemas for the platform license status endpoint."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from autosecops.licensing.schemas import LicenseUsageRead
from autosecops.licensing.types import (
    LicenseErrorCode,
    LicenseGrant,
    LicenseLimits,
    LicenseNoticeLevel,
    LicensePlan,
    LicenseStatus,
)
from autosecops.tiers.enums import Entitlement


class LicenseRead(BaseModel):
    """License status for the platform admin."""

    status: LicenseStatus
    enforced: bool = Field(
        description="Whether the license controls entitlements."
        " False in multi-tenant mode, where database tiers apply."
    )
    license_id: str | None = Field(default=None)
    customer: str | None = Field(default=None)
    plan: LicensePlan | None = Field(default=None)
    issued_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    grace_ends_at: datetime | None = Field(default=None)
    days_remaining: int | None = Field(
        default=None,
        description="Whole days until the license expires; negative once expired",
    )
    notice: LicenseNoticeLevel | None = Field(
        default=None,
        description="Why administrators are warned about the license, if at all",
    )
    entitlements: list[Entitlement] = Field(
        default_factory=list,
        description="Paid entitlements the license grants right now",
    )
    grants: list[LicenseGrant] = Field(
        default_factory=list,
        description="Deployment-wide grants the license applies right now,"
        " such as multi_tenant",
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
    limits: LicenseLimits = Field(
        default_factory=LicenseLimits,
        description="Limits that apply right now; null fields are unlimited",
    )
    licensed_limits: LicenseLimits | None = Field(
        default=None,
        description="Limits listed in the license, whether or not they apply",
    )
    usage: LicenseUsageRead
    deployment_id: str = Field(
        description="This installation's deployment ID. Send it to the vendor"
        " to receive a license bound to this installation."
    )
    license_deployment_id: str | None = Field(
        default=None,
        description="Deployment ID the license is bound to, if any",
    )
    error: LicenseErrorCode | None = Field(default=None)
