"""Test helpers for the SOC-wide robot key registry.

The registry keeps every registered key forever (``key_registry``), while
several suites register the same fixed contract-vector keys in a fresh
workspace per test. Those suites forget their fixed keys right before they
register them; suites that test uniqueness use fresh random keys.

Because the registry is shared, two pytest-xdist workers cannot hold the same
fixed key at once. Tests that register fixed keys run under
``fixed_robot_keys_lock`` so they take turns across workers.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager

from sqlalchemy import delete, text

from autosecops.db.engine import get_async_session_context_manager
from autosecops.db.models import RobotKeyRegistry


async def forget_registered_keys(public_keys: Iterable[bytes]) -> None:
    """Remove fixed test keys from the SOC-wide key registry."""
    keys = list(public_keys)
    if not keys:
        return
    async with get_async_session_context_manager() as session:
        await session.execute(
            delete(RobotKeyRegistry).where(RobotKeyRegistry.public_key.in_(keys))
        )
        await session.commit()


_FIXED_ROBOT_KEYS_LOCK_ID = 0x524F424F544B4559
"""Postgres advisory lock key ("ROBOTKEY") for tests that use fixed keys."""


@asynccontextmanager
async def fixed_robot_keys_lock() -> AsyncIterator[None]:
    """Hold a cross-process lock while a test uses fixed contract-vector keys.

    The lock is a session-level advisory lock on its own connection, so it
    serializes these tests across pytest-xdist workers sharing one database.
    """
    async with get_async_session_context_manager() as session:
        await session.execute(
            text("SELECT pg_advisory_lock(:key)"), {"key": _FIXED_ROBOT_KEYS_LOCK_ID}
        )
        try:
            yield
        finally:
            await session.execute(
                text("SELECT pg_advisory_unlock(:key)"),
                {"key": _FIXED_ROBOT_KEYS_LOCK_ID},
            )
