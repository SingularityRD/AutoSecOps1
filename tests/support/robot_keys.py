"""Test helpers for the SOC-wide robot key registry.

The registry keeps every registered key forever (``key_registry``), while
several suites register the same fixed contract-vector keys in a fresh
workspace per test. Those suites forget their fixed keys right before they
register them; suites that test uniqueness use fresh random keys.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import delete

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
