"""Replay cache of authenticated fleet requests (contract §2.5).

A captured request authenticates again within the 300 s skew window; every
fleet ``GET`` is read-only and every ``POST`` is idempotent, so a replay
changes nothing. The SOC still remembers each accepted
(``X-RoboDR-Key-Id``, ``X-RoboDR-Signature``) pair for twice the skew
window and answers a repeat with ``401 replayed_request`` (a robot signs
every send anew). The cache lives in Redis so every API replica shares it.

If Redis is unreachable the cache falls back to a bounded per-process cache
(fail-open across replicas: with several API replicas a replay that reaches
another replica is not detected). The answer stays correct, since a replay
changes nothing, but the detection degrades: every fallback is logged at
error level and counted (:func:`fallback_count`), so monitor that log line.
"""

from __future__ import annotations

import asyncio
import time
import uuid

from redis.exceptions import RedisError
from tenacity import RetryError

from autosecops.logger import logger
from autosecops.redis.client import get_redis_client

WINDOW_SECONDS = 600
_KEY_PREFIX = "robot_edr:fleet_replay"
_MAX_LOCAL_ENTRIES = 50_000

_local_seen: dict[str, float] = {}
_local_lock = asyncio.Lock()
_fallbacks = 0


def fallback_count() -> int:
    """How many lookups this process answered without Redis since it started."""
    return _fallbacks


async def _seen_locally(entry: str) -> bool:
    async with _local_lock:
        now = time.monotonic()
        if len(_local_seen) >= _MAX_LOCAL_ENTRIES:
            for key in [k for k, exp in _local_seen.items() if exp <= now]:
                del _local_seen[key]
            if len(_local_seen) >= _MAX_LOCAL_ENTRIES:
                _local_seen.clear()
        expires = _local_seen.get(entry)
        if expires is not None and expires > now:
            return True
        _local_seen[entry] = now + WINDOW_SECONDS
        return False


async def seen_before(key_id: str, signature_hex: str) -> bool:
    """Record an authenticated request; return whether it was seen already.

    Args:
        key_id: The ``X-RoboDR-Key-Id`` value.
        signature_hex: The ``X-RoboDR-Signature`` value.

    Returns:
        ``True`` when the same pair authenticated within the window.
    """
    entry = f"{_KEY_PREFIX}:{key_id}:{signature_hex}"
    # A unique value per call: the client retries a SET whose reply was lost,
    # and that retry must not mistake this call's own write for a replay.
    marker = uuid.uuid4().hex
    try:
        client = await get_redis_client()
        stored = await client.set_if_not_exists(
            entry, marker, expire_seconds=WINDOW_SECONDS
        )
        if stored:
            return False
        return await client.get(entry) != marker
    except (RedisError, RuntimeError, OSError, RetryError) as exc:
        global _fallbacks
        _fallbacks += 1
        logger.error(
            "Robot EDR fleet replay cache could not reach Redis; replays are "
            "detected per process only until it is back",
            error_type=type(exc).__name__,
            fallbacks=_fallbacks,
        )
    return await _seen_locally(entry)


async def clear_local() -> None:
    """Forget the per-process fallback entries (tests)."""
    async with _local_lock:
        _local_seen.clear()
