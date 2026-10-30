"""Test helpers for the SOC-wide robot key registry.

The registry keeps every registered key forever (``key_registry``), while
several suites register the same fixed contract-vector keys in a fresh
workspace per test. Those suites hold :func:`exclusive_vector_keys` while a
fixed key is registered: it forgets the keys right before they are
registered and serializes every such test across pytest-xdist workers (and
concurrent test runs), which share the service database. Suites that test
uniqueness use fresh random keys and need no lock.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Iterable
from typing import Final

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from autosecops.db.engine import get_async_engine, get_async_session_context_manager
from autosecops.db.models import RobotKeyRegistry

VECTOR_KEY_LOCK: Final = "autosecops-tests:robot-vector-keys"
"""Advisory lock name held while a test has fixed vector keys registered."""


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


@contextlib.asynccontextmanager
async def exclusive_vector_keys(public_keys: Iterable[bytes]) -> AsyncIterator[None]:
    """Own the fixed vector keys for the duration of the block.

    Takes a PostgreSQL session advisory lock on a dedicated connection (not
    the service pool), so tests on other xdist workers that register the
    same fixed keys wait, then forgets the keys. Register the keys and
    remove the workspaces holding them inside the block: the lock is
    released only after that. A crashed worker's connection closes, which
    releases its lock.
    """
    keys = list(public_keys)
    lock_id = func.hashtext(VECTOR_KEY_LOCK)
    engine = create_async_engine(get_async_engine().url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(select(func.pg_advisory_lock(lock_id)))
            await conn.commit()
            try:
                await forget_registered_keys(keys)
                yield
            finally:
                await conn.execute(select(func.pg_advisory_unlock(lock_id)))
                await conn.commit()
    finally:
        await engine.dispose()
