"""Audited superuser actions on the platform license."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.audit.logger import AuditEventDetails, audit_log
from autosecops.auth.types import PlatformRole
from autosecops.licensing.clock import reset_high_water


def _clock_reset_details(
    *, role: PlatformRole, session: AsyncSession
) -> AuditEventDetails:
    del role, session
    return AuditEventDetails(data={"operation": "license_clock_reset"})


@audit_log(
    resource_type="platform_setting",
    action="update",
    attempt_metadata=_clock_reset_details,
    fail_closed=True,
)
async def reset_license_clock_high_water(
    *, role: PlatformRole, session: AsyncSession
) -> datetime:
    """Reset the license clock high-water mark to the current trusted time.

    Refused unless the attempt is written to the platform audit log first.

    Args:
        role: The superuser performing the reset; the audit log attributes it.
        session: A session that bypasses RLS.

    Returns:
        The new high-water mark.

    Raises:
        LicenseClockResetError: If the mark cannot be reset now.
        AuditWriteError: If the audit event cannot be written.
    """
    del role
    return await reset_high_water(session)
