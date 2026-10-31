"""Clock-rollback resistance for license expiry.

A license is evaluated against wall-clock time. Turning the system clock back
would otherwise keep an expired license valid. To resist that, AutoSecOps keeps
a high-water mark of the latest time it has observed and evaluates expiry
against ``max(now, high_water)``.

The high-water mark lives in two places:

- In each process, ``effective_now()`` advances it on every call, so a clock
  that moves backwards while a process runs never moves license time back.
- In the database (``platform_settings`` key ``license_clock_high_water``),
  ``refresh_license_clock()`` persists it at most once per
  ``CLOCK_PERSIST_INTERVAL``, so a restart with a rolled-back clock still
  evaluates against the last persisted time. Concurrent writers take a row
  lock and only ever raise the stored value.

When the observed time is more than ``CLOCK_ROLLBACK_TOLERANCE`` behind the
high-water mark, AutoSecOps logs an error and reports the rollback to platform
administrators in the license status API.

A clock that was set into the future and then corrected also looks like a
rollback: license time stays at the future high-water mark until real time
catches up. The license self-hosting docs describe how to recover.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import orjson
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import PlatformSetting
from autosecops.logger import logger

LICENSE_CLOCK_SETTING_KEY = "license_clock_high_water"
"""``platform_settings.key`` that stores the persisted high-water mark."""

CLOCK_PERSIST_INTERVAL = timedelta(hours=1)
"""Write the high-water mark to the database at most this often."""

CLOCK_REFRESH_RETRY_SECONDS = 300.0
"""After a failed refresh, wait this long before a process tries again."""

CLOCK_ROLLBACK_TOLERANCE = timedelta(minutes=15)
"""How far the clock may lag the high-water mark before it counts as a
rollback. Covers ordinary skew between hosts of one deployment."""


@dataclass(frozen=True, slots=True)
class ClockRollback:
    """A backwards clock jump that exceeded the tolerance."""

    observed_at: datetime
    """The wall-clock time read when the rollback was detected."""
    high_water: datetime
    """The high-water mark the clock fell behind."""

    @property
    def behind(self) -> timedelta:
        """How far the wall clock was behind the high-water mark."""
        return self.high_water - self.observed_at


@dataclass(frozen=True, slots=True)
class LicenseClockStatus:
    """What this process knows about license time."""

    high_water: datetime | None
    """Latest time observed by this process or loaded from the database."""
    rollback: ClockRollback | None
    """The most recent rollback this process detected, if any."""


_high_water: datetime | None = None
_rollback: ClockRollback | None = None
_next_refresh_monotonic: float | None = None


def _record_rollback(observed: datetime, high_water: datetime) -> None:
    global _rollback
    _rollback = ClockRollback(observed_at=observed, high_water=high_water)
    logger.error(
        "System clock moved backwards; license expiry is evaluated against the"
        " latest time AutoSecOps observed. Fix the host clock (NTP)",
        observed_at=observed.isoformat(),
        high_water=high_water.isoformat(),
        behind_seconds=int((high_water - observed).total_seconds()),
    )


def effective_now(now: datetime | None = None) -> datetime:
    """Return ``max(now, high_water)`` and advance the in-process high-water mark.

    Args:
        now: The wall-clock time; defaults to ``datetime.now(UTC)``.
    """
    global _high_water
    observed = now or datetime.now(UTC)
    high_water = _high_water
    if high_water is None or observed >= high_water:
        _high_water = observed
        return observed
    if high_water - observed > CLOCK_ROLLBACK_TOLERANCE and (
        _rollback is None or _rollback.high_water != high_water
    ):
        # Log once per high-water mark, not on every evaluation.
        _record_rollback(observed, high_water)
    return high_water


def get_license_clock_status() -> LicenseClockStatus:
    """Return this process's high-water mark and last detected rollback."""
    return LicenseClockStatus(high_water=_high_water, rollback=_rollback)


def reset_license_clock(
    *,
    high_water: datetime | None = None,
    next_refresh_monotonic: float | None = None,
) -> None:
    """Reset in-process clock state. Tests use it to stay deterministic."""
    global _high_water, _rollback, _next_refresh_monotonic
    _high_water = high_water
    _rollback = None
    _next_refresh_monotonic = next_refresh_monotonic


def _decode(value: bytes) -> datetime | None:
    try:
        decoded = orjson.loads(value)
    except orjson.JSONDecodeError:
        return None
    if not isinstance(decoded, str):
        return None
    try:
        parsed = datetime.fromisoformat(decoded)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _encode(value: datetime) -> bytes:
    return orjson.dumps(value.astimezone(UTC).isoformat())


async def persist_high_water(session: AsyncSession, now: datetime) -> datetime:
    """Merge ``now`` into the stored high-water mark and return the result.

    Creates the row on first use. Takes a row lock so concurrent processes
    serialize, and writes only when the stored value is missing, unreadable,
    or at least ``CLOCK_PERSIST_INTERVAL`` older than ``now``. The stored value
    never decreases. Commits the session.

    Returns:
        ``max(stored, now)``: the deployment's high-water mark.
    """
    await session.execute(
        insert(PlatformSetting)
        .values(
            id=uuid.uuid4(),
            key=LICENSE_CLOCK_SETTING_KEY,
            value=_encode(now),
            value_type="json",
            is_encrypted=False,
        )
        .on_conflict_do_nothing(index_elements=[PlatformSetting.key])
    )
    setting = (
        await session.execute(
            select(PlatformSetting)
            .where(PlatformSetting.key == LICENSE_CLOCK_SETTING_KEY)
            .with_for_update()
        )
    ).scalar_one()
    stored = _decode(setting.value)
    if stored is None:
        logger.error(
            "The stored license clock high-water mark is unreadable; resetting"
            " it to the current time",
        )
        setting.value = _encode(now)
        stored = now
    elif now - stored >= CLOCK_PERSIST_INTERVAL:
        setting.value = _encode(now)
        stored = now
    await session.commit()
    return max(stored, now)


async def refresh_license_clock(*, now: datetime | None = None) -> LicenseClockStatus:
    """Load and persist the high-water mark, then fold it into this process.

    Never raises: a database failure is logged and the process keeps its
    in-process high-water mark, retrying after ``CLOCK_REFRESH_RETRY_SECONDS``.
    """
    global _high_water, _next_refresh_monotonic
    observed = now or datetime.now(UTC)
    try:
        async with get_async_session_bypass_rls_context_manager() as session:
            stored = await persist_high_water(session, observed)
    except Exception as exc:
        _next_refresh_monotonic = time.monotonic() + CLOCK_REFRESH_RETRY_SECONDS
        logger.error(
            "Could not persist the license clock high-water mark; license"
            " expiry falls back to this process's clock",
            error=type(exc).__name__,
        )
        return get_license_clock_status()
    _next_refresh_monotonic = time.monotonic() + CLOCK_PERSIST_INTERVAL.total_seconds()
    if stored - observed > CLOCK_ROLLBACK_TOLERANCE:
        _record_rollback(observed, stored)
    if _high_water is None or stored > _high_water:
        _high_water = stored
    return get_license_clock_status()


async def ensure_license_clock_fresh() -> None:
    """Refresh the high-water mark if this process has not done so recently."""
    if (
        _next_refresh_monotonic is not None
        and time.monotonic() < _next_refresh_monotonic
    ):
        return
    await refresh_license_clock()
