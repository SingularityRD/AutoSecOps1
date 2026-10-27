"""Per-sender-key batch rate limit (ingest contract §2.4).

A token bucket of 30 batches refilled at 120 batches per minute, kept in Redis
so every API replica shares it (an atomic Lua script, clocked by the Redis
server). If Redis is unreachable the limiter falls back to an equivalent
bucket in this process, so each replica then enforces the limit on its own
share of the traffic: the limit degrades, ingest keeps working.
"""

from __future__ import annotations

import asyncio
import math
import time
import uuid
from dataclasses import dataclass
from typing import Any

from redis.exceptions import RedisError

from autosecops.logger import logger
from autosecops.redis.client import get_redis_client

BATCHES_PER_MINUTE = 120
BURST = 30
_RATE_PER_SECOND = BATCHES_PER_MINUTE / 60
_KEY_PREFIX = "robot_edr:rate"

_TOKEN_BUCKET_LUA = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end
tokens = math.min(capacity, tokens + math.max(0, now - ts) * rate)
local allowed = 0
local retry_after = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry_after = (1 - tokens) / rate
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('EXPIRE', KEYS[1], math.ceil(capacity / rate) + 1)
return {allowed, tostring(retry_after)}
"""


@dataclass(frozen=True, slots=True)
class RateDecision:
    """Whether a batch may proceed, and when to retry if not."""

    allowed: bool
    retry_after_seconds: int


class _LocalBucket:
    def __init__(self) -> None:
        self.tokens = float(BURST)
        self.updated = time.monotonic()


_local_buckets: dict[uuid.UUID, _LocalBucket] = {}
_local_lock = asyncio.Lock()
_MAX_LOCAL_BUCKETS = 10_000


async def _take_local(sender_key: uuid.UUID) -> RateDecision:
    async with _local_lock:
        bucket = _local_buckets.get(sender_key)
        if bucket is None:
            if len(_local_buckets) >= _MAX_LOCAL_BUCKETS:
                _local_buckets.clear()
            bucket = _local_buckets[sender_key] = _LocalBucket()
        now = time.monotonic()
        bucket.tokens = min(
            BURST, bucket.tokens + (now - bucket.updated) * _RATE_PER_SECOND
        )
        bucket.updated = now
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return RateDecision(allowed=True, retry_after_seconds=0)
        wait = (1 - bucket.tokens) / _RATE_PER_SECOND
        return RateDecision(allowed=False, retry_after_seconds=max(1, math.ceil(wait)))


async def take_batch_token(sender_key: uuid.UUID) -> RateDecision:
    """Consume one batch token for ``sender_key``.

    Args:
        sender_key: The sender key's stable id (``robot_key.id``).

    Returns:
        The decision; ``retry_after_seconds`` is at least 1 when refused.
    """
    result: list[Any] | None = None
    for _attempt in range(2):  # The client reconnects after a transport error.
        try:
            client = await get_redis_client()
            result = await client.eval_script(
                _TOKEN_BUCKET_LUA,
                [f"{_KEY_PREFIX}:{sender_key}"],
                [_RATE_PER_SECOND, BURST],
            )
            break
        except (RedisError, RuntimeError, OSError) as exc:
            logger.warning(
                "Robot EDR rate limiter could not reach Redis",
                error_type=type(exc).__name__,
            )
    if result is None:
        return await _take_local(sender_key)
    allowed, retry_after = result
    if int(allowed) == 1:
        return RateDecision(allowed=True, retry_after_seconds=0)
    wait = float(retry_after)
    return RateDecision(allowed=False, retry_after_seconds=max(1, math.ceil(wait)))
