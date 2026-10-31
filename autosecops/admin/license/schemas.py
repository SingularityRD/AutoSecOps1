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
    MultiTenantMode,
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
    multi_tenant_requested: bool = Field(
        default=False,
        description="Whether AUTOSECOPS__EE_MULTI_TENANT=true is set",
    )
    multi_tenant_mode: MultiTenantMode = Field(
        default=MultiTenantMode.OFF,
        description="Whether this deployment runs multi-tenant. 'lapsed' means"
        " the license that grants multi_tenant expired past its grace period:"
        " existing organizations keep working, while creating organizations and"
        " changing tiers are blocked until a renewed license is installed",
    )
    clock_high_water: datetime | None = Field(
        default=None,
        description="Latest trusted time this deployment has recorded. License"
        " expiry is evaluated against the later of this and the system clock",
    )
    clock_rollback_detected_at: datetime | None = Field(
        default=None,
        description="When an AutoSecOps process first saw the system clock"
        " behind the high-water mark by more than the tolerance. Null once the"
        " clock has caught up",
    )
    clock_rollback_seconds: int | None = Field(
        default=None,
        description="How many seconds the system clock of the answering API"
        " replica is behind the high-water mark now. Null when it is not",
    )
    clock_last_reset_at: datetime | None = Field(
        default=None,
        description="When a superuser last reset the high-water mark through"
        " POST /admin/license/clock/reset",
    )


class LicenseClockResetRead(BaseModel):
    """Result of resetting the license clock high-water mark."""

    clock_high_water: datetime = Field(
        description="The new high-water mark: this API replica's current time",
    )
