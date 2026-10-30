"""Stable per-installation deployment ID.

The deployment ID is generated once, on first use, and stored in the
``platform_settings`` table. A license can name it in its ``deployment_id``
claim to bind itself to one installation. The ID survives restarts, upgrades,
and database restores, because it lives in the database.

Each process reads the ID from the database at most once and caches it, so
license evaluation (which is synchronous) never queries the database.
"""

from __future__ import annotations

import uuid

import orjson
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import PlatformSetting

DEPLOYMENT_ID_SETTING_KEY = "deployment_id"
"""``platform_settings.key`` that stores the deployment ID."""

DEPLOYMENT_ID_PREFIX = "dep_"

_cached_deployment_id: str | None = None


def generate_deployment_id() -> str:
    """Return a new random deployment ID such as ``dep_<32 hex chars>``."""
    return f"{DEPLOYMENT_ID_PREFIX}{uuid.uuid4().hex}"


def get_cached_deployment_id() -> str | None:
    """Return this process's cached deployment ID, or ``None`` if not loaded."""
    return _cached_deployment_id


def set_cached_deployment_id(deployment_id: str | None) -> None:
    """Set or clear the cached deployment ID.

    Startup code sets it after loading it; tests use it to stay deterministic.
    """
    global _cached_deployment_id
    _cached_deployment_id = deployment_id


def _decode_setting_value(value: bytes) -> str | None:
    try:
        decoded = orjson.loads(value)
    except orjson.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, str) and decoded else None


async def _read_deployment_id(session: AsyncSession) -> str | None:
    stmt = select(PlatformSetting.value).where(
        PlatformSetting.key == DEPLOYMENT_ID_SETTING_KEY
    )
    value = (await session.execute(stmt)).scalar_one_or_none()
    return _decode_setting_value(value) if value is not None else None


async def load_or_create_deployment_id(session: AsyncSession) -> str:
    """Read the deployment ID, creating it on first use.

    Concurrent first starts race on the unique ``key`` column; the insert does
    nothing when another process won, and both read the winner's ID back.

    Raises:
        RuntimeError: If the stored value is unreadable. The row is never
            overwritten, because that would unbind every license issued for it.
    """
    if (existing := await _read_deployment_id(session)) is not None:
        return existing
    stmt = (
        insert(PlatformSetting)
        .values(
            id=uuid.uuid4(),
            key=DEPLOYMENT_ID_SETTING_KEY,
            value=orjson.dumps(generate_deployment_id()),
            value_type="json",
            is_encrypted=False,
        )
        .on_conflict_do_nothing(index_elements=[PlatformSetting.key])
    )
    await session.execute(stmt)
    await session.commit()
    if (stored := await _read_deployment_id(session)) is None:
        raise RuntimeError("The stored deployment ID is unreadable")
    return stored


async def ensure_deployment_id() -> str:
    """Return the deployment ID, loading (or creating) it once per process."""
    if (cached := get_cached_deployment_id()) is not None:
        return cached
    async with get_async_session_bypass_rls_context_manager() as session:
        deployment_id = await load_or_create_deployment_id(session)
    set_cached_deployment_id(deployment_id)
    return deployment_id
