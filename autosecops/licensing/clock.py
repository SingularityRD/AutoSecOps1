"""Clock-rollback resistance for license expiry.

A license is evaluated against wall-clock time. Turning the system clock back
would otherwise keep an expired license valid. To resist that, AutoSecOps keeps
a high-water mark of the latest time it trusts and evaluates expiry against
``max(now, high_water)``.

The mark only ever rises, so it must never rise on a bad reading. A host whose
real-time clock reads years ahead for a few seconds before NTP corrects it
would otherwise push license time into the future for the whole deployment.
A wall-clock reading is therefore *trusted* only once it has agreed with the
process's monotonic clock for ``CLOCK_SETTLE_TIME``; a step of more than
``CLOCK_STEP_TOLERANCE`` in either direction starts the wait again.

- In each process, the mark is a ``(wall, monotonic)`` anchor projected
  forward with the monotonic clock, so a wall clock that moves backwards while
  a process runs never moves license time back. Readings that tick along
  within ``CLOCK_STEP_TOLERANCE`` of the projected mark raise it at once; a
  reading that jumps further ahead raises it only once it is trusted.
- In the database (``platform_settings`` key ``license_clock_high_water``),
  ``refresh_license_clock()`` persists a trusted reading at most once per
  ``CLOCK_PERSIST_INTERVAL``, so a restart with a rolled-back clock still
  evaluates against the last persisted time. A reading more than
  ``CLOCK_FORWARD_JUMP_LIMIT`` ahead of the stored mark is persisted only once
  it has been steady for ``CLOCK_FORWARD_JUMP_SETTLE_TIME``. Concurrent writers
  take a row lock and only ever raise the stored value.

When the observed time is more than ``CLOCK_ROLLBACK_TOLERANCE`` behind the
mark, AutoSecOps logs an error and records the rollback in ``platform_settings``
(key ``license_clock_rollback``) so every API replica reports the same state.
The record is cleared once the clock catches up again.

If a bad time still reaches the stored mark, a superuser resets it to the
current trusted time through ``POST /api/admin/license/clock/reset``, which is
audited and recorded (key ``license_clock_reset``). Every other process drops
its own mark to the reset value on its next refresh.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import orjson
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import PlatformSetting
from autosecops.logger import logger

LICENSE_CLOCK_SETTING_KEY = "license_clock_high_water"
"""``platform_settings.key`` that stores the persisted high-water mark."""

LICENSE_CLOCK_ROLLBACK_SETTING_KEY = "license_clock_rollback"
"""``platform_settings.key`` that stores the rollback in effect, if any."""

LICENSE_CLOCK_RESET_SETTING_KEY = "license_clock_reset"
"""``platform_settings.key`` that stores the last superuser reset of the mark."""

CLOCK_PERSIST_INTERVAL = timedelta(hours=1)
"""Write the high-water mark to the database at most this often."""

CLOCK_REFRESH_RETRY_SECONDS = 300.0
"""After a failed refresh, wait this long before a process tries again."""

CLOCK_ROLLBACK_TOLERANCE = timedelta(minutes=15)
"""How far the clock may lag the high-water mark before it counts as a
rollback. Covers ordinary skew between hosts of one deployment."""

CLOCK_STEP_TOLERANCE = timedelta(minutes=1)
"""How far the wall clock may drift from the monotonic clock between two
readings before it counts as a step. NTP slews far slower than this."""

CLOCK_SETTLE_TIME = timedelta(minutes=5)
"""How long the wall clock must agree with the monotonic clock before a
reading is trusted."""

CLOCK_FORWARD_JUMP_LIMIT = timedelta(days=1)
"""A trusted reading this far ahead of the stored mark needs
``CLOCK_FORWARD_JUMP_SETTLE_TIME`` before it is persisted."""

CLOCK_FORWARD_JUMP_SETTLE_TIME = timedelta(hours=1)
"""How long a reading far ahead of the stored mark must stay steady before it
is persisted. A restart after a long outage persists within about an hour; a
host clock that is wrong only until NTP syncs never does."""

_monotonic = time.monotonic
"""Monotonic clock source, at module level so tests can drive it."""


@dataclass(frozen=True, slots=True)
class _Anchor:
    """A wall-clock reading tied to the monotonic time it was read at."""

    wall: datetime
    monotonic: float

    def at(self, monotonic: float) -> datetime:
        """Project the reading forward to ``monotonic``."""
        return self.wall + timedelta(seconds=monotonic - self.monotonic)


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
    """Latest trusted time of this process, or loaded from the database."""
    rollback: ClockRollback | None
    """The rollback in effect in this process, if any."""


@dataclass(frozen=True, slots=True)
class DeploymentClockStatus:
    """License time as the whole deployment sees it, read from the database."""

    high_water: datetime | None
    """The persisted high-water mark."""
    rollback: ClockRollback | None
    """The rollback in effect now, if the clock is behind the persisted mark."""
    rollback_first_detected_at: datetime | None
    """When a process first detected the rollback in effect."""
    last_reset_at: datetime | None
    """When a superuser last reset the mark."""


@dataclass(frozen=True, slots=True)
class _ResetRecord:
    reset_id: str
    reset_at: datetime


_floor: _Anchor | None = None
_candidate: _Anchor | None = None
_rollback: ClockRollback | None = None
_next_refresh_monotonic: float | None = None
_seen_reset_id: str | None = None


def _floor_at(monotonic: float) -> datetime | None:
    return _floor.at(monotonic) if _floor is not None else None


def _raise_floor(value: datetime, monotonic: float) -> None:
    global _floor
    current = _floor_at(monotonic)
    if current is None or value > current:
        _floor = _Anchor(value, monotonic)


def _trusted_for(monotonic: float) -> timedelta:
    """How long the current reading has agreed with the monotonic clock."""
    if _candidate is None:
        return timedelta(0)
    return timedelta(seconds=monotonic - _candidate.monotonic)


def _track(observed: datetime, monotonic: float) -> None:
    """Fold one wall-clock reading into the in-process mark."""
    global _candidate
    candidate = _candidate
    stepped = (
        candidate is None
        or abs(observed - candidate.at(monotonic)) > CLOCK_STEP_TOLERANCE
    )
    if stepped:
        # The wall clock stepped, or this is the first reading: start over.
        _candidate = _Anchor(observed, monotonic)
    floor = _floor_at(monotonic)
    ticking = floor is not None and observed - floor <= CLOCK_STEP_TOLERANCE
    if ticking or _trusted_for(monotonic) >= CLOCK_SETTLE_TIME:
        _raise_floor(observed, monotonic)


def _note_rollback(observed: datetime, high_water: datetime) -> ClockRollback | None:
    """Record, or clear once the clock caught up, the in-process rollback."""
    global _rollback
    if high_water - observed <= CLOCK_ROLLBACK_TOLERANCE:
        if _rollback is not None:
            logger.info(
                "System clock caught up with the license clock high-water mark",
                high_water=high_water.isoformat(),
            )
            _rollback = None
        return None
    if _rollback is None:
        # Log once per rollback, not on every evaluation.
        logger.error(
            "System clock moved backwards; license expiry is evaluated against"
            " the latest time AutoSecOps observed. Fix the host clock (NTP)",
            observed_at=observed.isoformat(),
            high_water=high_water.isoformat(),
            behind_seconds=int((high_water - observed).total_seconds()),
        )
        _rollback = ClockRollback(observed_at=observed, high_water=high_water)
    return _rollback


def effective_now(now: datetime | None = None) -> datetime:
    """Return ``max(now, high_water)`` and fold ``now`` into the in-process mark.

    A reading that jumps ahead of the mark is returned as is, but it raises the
    mark only once it is trusted, so a transient future reading never sticks.

    Args:
        now: The wall-clock time; defaults to ``datetime.now(UTC)``.
    """
    observed = now or datetime.now(UTC)
    monotonic = _monotonic()
    _track(observed, monotonic)
    floor = _floor_at(monotonic)
    if floor is None:
        return observed
    _note_rollback(observed, floor)
    return max(observed, floor)


def get_license_clock_status() -> LicenseClockStatus:
    """Return this process's high-water mark and current rollback."""
    return LicenseClockStatus(high_water=_floor_at(_monotonic()), rollback=_rollback)


def reset_license_clock(
    *,
    high_water: datetime | None = None,
    next_refresh_monotonic: float | None = None,
) -> None:
    """Reset in-process clock state. Tests use it to stay deterministic."""
    global _floor, _candidate, _rollback, _next_refresh_monotonic, _seen_reset_id
    _floor = _Anchor(high_water, _monotonic()) if high_water is not None else None
    _candidate = None
    _rollback = None
    _next_refresh_monotonic = next_refresh_monotonic
    _seen_reset_id = None


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _decode(value: bytes) -> datetime | None:
    try:
        decoded = orjson.loads(value)
    except orjson.JSONDecodeError:
        return None
    return _parse_datetime(decoded)


def _decode_record(value: bytes) -> dict[str, object] | None:
    """Decode a JSON object record; callers match the keys they need."""
    try:
        decoded = orjson.loads(value)
    except orjson.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _encode(value: datetime) -> bytes:
    return orjson.dumps(value.astimezone(UTC).isoformat())


async def _read_setting(session: AsyncSession, key: str) -> bytes | None:
    stmt = select(PlatformSetting.value).where(PlatformSetting.key == key)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _upsert_setting(session: AsyncSession, key: str, value: bytes) -> None:
    await session.execute(
        insert(PlatformSetting)
        .values(
            id=uuid.uuid4(),
            key=key,
            value=value,
            value_type="json",
            is_encrypted=False,
        )
        .on_conflict_do_update(
            index_elements=[PlatformSetting.key], set_={"value": value}
        )
    )


async def persist_high_water(
    session: AsyncSession,
    now: datetime | None,
    *,
    allow_forward_jump: bool = False,
) -> datetime | None:
    """Merge a trusted reading into the stored high-water mark.

    Creates the row on first use. Takes a row lock so concurrent processes
    serialize, and writes only when the stored value is missing, unreadable,
    or at least ``CLOCK_PERSIST_INTERVAL`` older than ``now``. A reading more
    than ``CLOCK_FORWARD_JUMP_LIMIT`` ahead of the stored value is written only
    with ``allow_forward_jump``. The stored value never decreases. Commits the
    session.

    Args:
        session: A session that bypasses RLS.
        now: A trusted wall-clock reading, or ``None`` to only read the mark.
        allow_forward_jump: Whether ``now`` has been steady for
            ``CLOCK_FORWARD_JUMP_SETTLE_TIME``.

    Returns:
        The deployment's high-water mark after the merge, or ``None`` when
        ``now`` is ``None`` and no readable mark is stored.
    """
    if now is None:
        raw = await _read_setting(session, LICENSE_CLOCK_SETTING_KEY)
        return _decode(raw) if raw is not None else None
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
    result = now
    if stored is None:
        logger.error(
            "The stored license clock high-water mark is unreadable; resetting"
            " it to the current time",
        )
        setting.value = _encode(now)
    elif now - stored > CLOCK_FORWARD_JUMP_LIMIT and not allow_forward_jump:
        logger.warning(
            "The system clock is far ahead of the license clock high-water"
            " mark; it is recorded once the clock has stayed steady for an hour",
            high_water=stored.isoformat(),
            observed_at=now.isoformat(),
        )
        result = stored
    elif now - stored >= CLOCK_PERSIST_INTERVAL:
        setting.value = _encode(now)
    else:
        result = max(stored, now)
    await session.commit()
    return result


async def _sync_rollback_record(
    session: AsyncSession, rollback: ClockRollback | None
) -> None:
    """Store the rollback in effect for every replica, or clear it once fixed."""
    raw = await _read_setting(session, LICENSE_CLOCK_ROLLBACK_SETTING_KEY)
    if rollback is None:
        if raw is not None:
            await session.execute(
                delete(PlatformSetting).where(
                    PlatformSetting.key == LICENSE_CLOCK_ROLLBACK_SETTING_KEY
                )
            )
            await session.commit()
        return
    if raw is not None and _decode_record(raw) is not None:
        # Keep the first detection time of the rollback in effect.
        return
    record = {
        "detected_at": rollback.observed_at.astimezone(UTC).isoformat(),
        "high_water": rollback.high_water.astimezone(UTC).isoformat(),
    }
    await _upsert_setting(
        session, LICENSE_CLOCK_ROLLBACK_SETTING_KEY, orjson.dumps(record)
    )
    await session.commit()


async def _read_reset_record(session: AsyncSession) -> _ResetRecord | None:
    raw = await _read_setting(session, LICENSE_CLOCK_RESET_SETTING_KEY)
    if raw is None:
        return None
    match _decode_record(raw):
        case {"reset_id": str(reset_id), "reset_at": reset_at} if (
            parsed := _parse_datetime(reset_at)
        ) is not None:
            return _ResetRecord(reset_id=reset_id, reset_at=parsed)
        case _:
            return None


def _apply_reset(record: _ResetRecord | None, stored: datetime | None) -> None:
    """Drop the in-process mark to the stored one after a superuser reset."""
    global _floor, _candidate, _rollback, _seen_reset_id
    if record is None or record.reset_id == _seen_reset_id:
        return
    first_refresh = _seen_reset_id is None
    _seen_reset_id = record.reset_id
    if first_refresh and _floor is None:
        # Nothing was loaded before the reset; the stored mark is current.
        return
    logger.warning(
        "The license clock high-water mark was reset by a superuser; this"
        " process now evaluates license time from the reset value",
        reset_at=record.reset_at.isoformat(),
    )
    _floor = _Anchor(stored, _monotonic()) if stored is not None else None
    _candidate = None
    _rollback = None


async def refresh_license_clock(*, now: datetime | None = None) -> LicenseClockStatus:
    """Load and persist the high-water mark, then fold it into this process.

    Only a trusted reading (see the module docstring) is persisted; until then
    the stored mark is only read. Never raises: a database failure is logged
    and the process keeps its in-process mark, retrying after
    ``CLOCK_REFRESH_RETRY_SECONDS``.
    """
    global _next_refresh_monotonic
    observed = now or datetime.now(UTC)
    monotonic = _monotonic()
    _track(observed, monotonic)
    trusted_for = _trusted_for(monotonic)
    trusted = observed if trusted_for >= CLOCK_SETTLE_TIME else None
    try:
        async with get_async_session_bypass_rls_context_manager() as session:
            stored = await persist_high_water(
                session,
                trusted,
                allow_forward_jump=trusted_for >= CLOCK_FORWARD_JUMP_SETTLE_TIME,
            )
            _apply_reset(await _read_reset_record(session), stored)
            if stored is not None:
                _raise_floor(stored, monotonic)
            floor = _floor_at(monotonic)
            rollback = _note_rollback(observed, floor) if floor is not None else None
            await _sync_rollback_record(session, rollback)
    except Exception as exc:
        _next_refresh_monotonic = _monotonic() + CLOCK_REFRESH_RETRY_SECONDS
        logger.error(
            "Could not persist the license clock high-water mark; license"
            " expiry falls back to this process's clock",
            error=type(exc).__name__,
        )
        return get_license_clock_status()
    _next_refresh_monotonic = _monotonic() + CLOCK_PERSIST_INTERVAL.total_seconds()
    return get_license_clock_status()


async def ensure_license_clock_fresh() -> None:
    """Refresh the high-water mark if this process has not done so recently.

    Single-flight: the first caller claims the refresh before it awaits, so
    concurrent callers in a process return at once instead of each opening
    another database connection and queueing on the same row lock.
    """
    global _next_refresh_monotonic
    if _next_refresh_monotonic is not None and _monotonic() < _next_refresh_monotonic:
        return
    # refresh_license_clock replaces this claim with the real deadline.
    _next_refresh_monotonic = _monotonic() + CLOCK_REFRESH_RETRY_SECONDS
    await refresh_license_clock()


async def read_deployment_clock_status(
    session: AsyncSession, *, now: datetime | None = None
) -> DeploymentClockStatus:
    """Read license time as every replica sees it, for the admin status API.

    The rollback is evaluated against the persisted mark on each call, so it
    clears as soon as the clock is fixed, whichever replica answers.
    """
    observed = now or datetime.now(UTC)
    raw_mark = await _read_setting(session, LICENSE_CLOCK_SETTING_KEY)
    high_water = _decode(raw_mark) if raw_mark is not None else None
    reset = await _read_reset_record(session)
    rollback: ClockRollback | None = None
    first_detected: datetime | None = None
    if high_water is not None and high_water - observed > CLOCK_ROLLBACK_TOLERANCE:
        rollback = ClockRollback(observed_at=observed, high_water=high_water)
        raw = await _read_setting(session, LICENSE_CLOCK_ROLLBACK_SETTING_KEY)
        match _decode_record(raw) if raw is not None else None:
            case {"detected_at": detected_at}:
                first_detected = _parse_datetime(detected_at)
            case _:
                pass
        first_detected = first_detected or observed
    return DeploymentClockStatus(
        high_water=high_water,
        rollback=rollback,
        rollback_first_detected_at=first_detected,
        last_reset_at=reset.reset_at if reset else None,
    )


class LicenseClockResetError(Exception):
    """The high-water mark cannot be reset now."""


async def reset_high_water(
    session: AsyncSession, *, now: datetime | None = None
) -> datetime:
    """Reset the stored mark to this process's current trusted time.

    Recovery for a bad host clock that pushed the mark into the future. The
    caller audits the reset. It is recorded in ``platform_settings`` so every
    other process drops its own mark on its next refresh. Commits the session.

    Args:
        session: A session that bypasses RLS.
        now: The wall-clock time; defaults to ``datetime.now(UTC)``.

    Raises:
        LicenseClockResetError: If this process has not seen a steady clock for
            ``CLOCK_SETTLE_TIME``, or the stored mark is not ahead of the clock
            by more than ``CLOCK_ROLLBACK_TOLERANCE``.

    Returns:
        The new high-water mark.
    """
    global _floor, _rollback, _seen_reset_id
    observed = now or datetime.now(UTC)
    monotonic = _monotonic()
    _track(observed, monotonic)
    if _trusted_for(monotonic) < CLOCK_SETTLE_TIME:
        raise LicenseClockResetError(
            "This API process has not seen a steady system clock for"
            f" {int(CLOCK_SETTLE_TIME.total_seconds() // 60)} minutes yet. Fix"
            " the host clock (NTP) and try again"
        )
    setting = (
        await session.execute(
            select(PlatformSetting)
            .where(PlatformSetting.key == LICENSE_CLOCK_SETTING_KEY)
            .with_for_update()
        )
    ).scalar_one_or_none()
    stored = _decode(setting.value) if setting is not None else None
    if setting is None or stored is None:
        raise LicenseClockResetError("No license clock high-water mark is stored")
    if stored - observed <= CLOCK_ROLLBACK_TOLERANCE:
        raise LicenseClockResetError(
            "The license clock high-water mark is not ahead of the system"
            " clock; there is nothing to reset"
        )
    reset_id = uuid.uuid4().hex
    setting.value = _encode(observed)
    record = {
        "reset_id": reset_id,
        "reset_at": observed.astimezone(UTC).isoformat(),
        "previous_high_water": stored.astimezone(UTC).isoformat(),
    }
    await _upsert_setting(
        session, LICENSE_CLOCK_RESET_SETTING_KEY, orjson.dumps(record)
    )
    await session.execute(
        delete(PlatformSetting).where(
            PlatformSetting.key == LICENSE_CLOCK_ROLLBACK_SETTING_KEY
        )
    )
    await session.commit()
    logger.warning(
        "License clock high-water mark reset by a superuser",
        previous_high_water=stored.isoformat(),
        high_water=observed.isoformat(),
    )
    _floor = _Anchor(observed, monotonic)
    _rollback = None
    _seen_reset_id = reset_id
    return observed
