"""Enforce license seat and resource limits when resources are created.

Limits only block new resources. Existing users, workspaces, and
organizations are never deactivated or deleted, even after a license with a
lower limit is installed.

``max_users`` and ``max_workspaces`` apply to single-tenant installs, where
the license controls the product. ``max_organizations`` applies to
multi-tenant installs. Each check takes a transaction-scoped advisory lock
before counting, so concurrent creations cannot both pass the last free slot;
the lock is released when the caller's transaction ends.
"""

from __future__ import annotations

import zlib
from collections.abc import Awaitable, Callable
from typing import cast

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped

from autosecops import config
from autosecops.db.engine import SupportsExecute
from autosecops.db.locks import pg_advisory_xact_lock
from autosecops.db.models import Organization, User, Workspace
from autosecops.exceptions import LicenseLimitExceeded
from autosecops.licensing.service import (
    LICENSE_CONTACT,
    ensure_license_deployment_loaded,
    get_license_state,
)
from autosecops.licensing.types import LicenseLimitName

type _Counter = Callable[[SupportsExecute], Awaitable[int]]


async def count_active_users(session: SupportsExecute) -> int:
    """Count active user accounts. Service accounts live in their own table."""
    # fastapi-users declares ``is_active`` as a plain bool; cast to the column.
    is_active = cast(Mapped[bool], User.is_active)
    stmt = select(func.count()).select_from(User).where(is_active.is_(True))
    return int((await session.execute(stmt)).scalar_one())


async def count_workspaces(session: SupportsExecute) -> int:
    """Count workspaces visible to ``session``."""
    stmt = select(func.count()).select_from(Workspace)
    return int((await session.execute(stmt)).scalar_one())


async def count_organizations(session: SupportsExecute) -> int:
    """Count organizations visible to ``session``."""
    stmt = select(func.count()).select_from(Organization)
    return int((await session.execute(stmt)).scalar_one())


def _advisory_lock_key(limit: LicenseLimitName) -> int:
    """Stable signed 32-bit key so each limit serializes independently."""
    return zlib.crc32(f"autosecops.license.{limit.value}".encode()) - 2**31


async def _lock_limit(session: AsyncSession, limit: LicenseLimitName) -> None:
    await pg_advisory_xact_lock(session, _advisory_lock_key(limit))


async def _licensed_maximum(limit: LicenseLimitName) -> int | None:
    await ensure_license_deployment_loaded()
    limits = get_license_state(log=False).limits
    match limit:
        case LicenseLimitName.MAX_USERS:
            return limits.max_users
        case LicenseLimitName.MAX_WORKSPACES:
            return limits.max_workspaces
        case LicenseLimitName.MAX_ORGANIZATIONS:
            return limits.max_organizations
        case _:
            raise ValueError(f"{limit.value} is not a creation limit")


async def _enforce(
    session: AsyncSession,
    limit: LicenseLimitName,
    *,
    count_current: _Counter,
) -> None:
    maximum = await _licensed_maximum(limit)
    if maximum is None:
        return
    await _lock_limit(session, limit)
    current = await count_current(session)
    if current >= maximum:
        raise LicenseLimitExceeded(
            limit, current=current, maximum=maximum, contact=LICENSE_CONTACT
        )


async def enforce_user_limit(session: AsyncSession) -> None:
    """Block a new active user beyond the license's ``max_users``.

    Call before inserting the user, in the transaction that inserts it.
    Single-tenant only; multi-tenant installs size users through tiers.

    Raises:
        LicenseLimitExceeded: If the install already has ``max_users`` active
            users.
    """
    if config.AUTOSECOPS__EE_MULTI_TENANT:
        return
    await _enforce(
        session, LicenseLimitName.MAX_USERS, count_current=count_active_users
    )


async def enforce_workspace_limit(session: AsyncSession) -> None:
    """Block a new workspace beyond the license's ``max_workspaces``.

    Single-tenant only.

    Raises:
        LicenseLimitExceeded: If the install already has ``max_workspaces``
            workspaces.
    """
    if config.AUTOSECOPS__EE_MULTI_TENANT:
        return
    await _enforce(
        session, LicenseLimitName.MAX_WORKSPACES, count_current=count_workspaces
    )


async def enforce_organization_limit(session: AsyncSession) -> None:
    """Block a new organization beyond the license's ``max_organizations``.

    Multi-tenant only; a single-tenant install has one organization.

    Raises:
        LicenseLimitExceeded: If the install already has ``max_organizations``
            organizations.
    """
    if not config.AUTOSECOPS__EE_MULTI_TENANT:
        return
    await _enforce(
        session,
        LicenseLimitName.MAX_ORGANIZATIONS,
        count_current=count_organizations,
    )
