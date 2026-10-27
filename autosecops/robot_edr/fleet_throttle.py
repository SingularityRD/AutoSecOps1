"""Aggregation of refused fleet requests for the audit log.

Every ``401`` (and every other refusal of an identified request) is an audit
event (contract §2.5), but a client repeating a bad request must not turn
into one audit event per request. Refusals are counted per minute by
(source address, presented id) and by source address alone; an event is
written for the 1st, 10th, 100th, ... refusal of a pair, while the source
has at most :data:`SOURCE_EVENTS_PER_MINUTE` refusals that minute or the
source count itself reaches a power of ten. Each event carries the count.

Counts live in Redis so every API replica shares them; without Redis each
process counts on its own (more events, never fewer).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Final

from redis.exceptions import RedisError
from tenacity import RetryError

from autosecops.contexts import ctx_request_audit
from autosecops.logger import logger
from autosecops.redis.client import get_redis_client

SOURCE_EVENTS_PER_MINUTE: Final = 20
_KEY_PREFIX: Final = "robot_edr:fleet_refusals"
_TTL_SECONDS: Final = 120
_MAX_LOCAL_ENTRIES: Final = 50_000

_COUNT_LUA: Final = """
local pair = redis.call('INCR', KEYS[1])
if pair == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local source = redis.call('INCR', KEYS[2])
if source == 1 then redis.call('EXPIRE', KEYS[2], ARGV[1]) end
return {pair, source}
"""

_local_counts: dict[str, int] = {}
_local_lock = asyncio.Lock()


@dataclass(frozen=True, slots=True)
class RefusalCount:
    """This minute's refusals of a (source, presented id) pair and its source."""

    pair: int
    source: int

    @property
    def audit(self) -> bool:
        """Whether this refusal is written to the audit log."""
        return _milestone(self.pair) and (
            self.source <= SOURCE_EVENTS_PER_MINUTE or _milestone(self.source)
        )


def _milestone(count: int) -> bool:
    """1, 10, 100, 1000, ..."""
    while count >= 10 and count % 10 == 0:
        count //= 10
    return count == 1


def source_address() -> str:
    """The client address of the current request, or ``unknown``."""
    audit_context = ctx_request_audit.get()
    return (audit_context.client_ip if audit_context else None) or "unknown"


async def _count_locally(pair_key: str, source_key: str) -> RefusalCount:
    async with _local_lock:
        if len(_local_counts) >= _MAX_LOCAL_ENTRIES:
            _local_counts.clear()
        pair = _local_counts[pair_key] = _local_counts.get(pair_key, 0) + 1
        source = _local_counts[source_key] = _local_counts.get(source_key, 0) + 1
    return RefusalCount(pair=pair, source=source)


async def count_refusal(presented_id: str) -> RefusalCount:
    """Count a refused request of the current source presenting ``presented_id``."""
    minute = int(time.time() // 60)
    source = source_address()
    source_key = f"{_KEY_PREFIX}:{minute}:{source}"
    pair_key = f"{source_key}:{presented_id}"
    try:
        client = await get_redis_client()
        result = await client.eval_script(
            _COUNT_LUA, [pair_key, source_key], [_TTL_SECONDS]
        )
        pair, source_count = (int(value) for value in result)
        return RefusalCount(pair=pair, source=source_count)
    except (
        RedisError,
        RuntimeError,
        OSError,
        RetryError,
        TypeError,
        ValueError,
    ) as exc:
        logger.warning(
            "Robot EDR fleet refusal counter could not reach Redis",
            error_type=type(exc).__name__,
        )
    return await _count_locally(pair_key, source_key)


async def clear_local() -> None:
    """Forget the per-process counts (tests)."""
    async with _local_lock:
        _local_counts.clear()
