"""API schemas shared by the license status endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from autosecops.licensing.types import (
    LicenseNoticeLevel,
    LicensePlan,
    LicenseStatus,
)


class LicenseUsageRead(BaseModel):
    """Current usage counted against license limits."""

    users: int = Field(description="Active user accounts; service accounts excluded")
    workspaces: int = Field(description="Workspaces on this installation")
    organizations: int = Field(description="Organizations on this installation")


class LicenseNoticeRead(BaseModel):
    """License expiry notice for organization administrators.

    ``level`` is null when no warning is needed, including on unlicensed
    Community installs and in multi-tenant mode.
    """

    level: LicenseNoticeLevel | None = Field(default=None)
    status: LicenseStatus | None = Field(default=None)
    plan: LicensePlan | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    grace_ends_at: datetime | None = Field(default=None)
    days_remaining: int | None = Field(
        default=None,
        description="Whole days until the license expires; negative once expired",
    )
