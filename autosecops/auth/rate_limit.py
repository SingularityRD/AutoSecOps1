"""Redis-backed rate limits for unauthenticated auth endpoints.

Each rule is a fixed-window counter in Redis, so every API replica shares it.
Clients are keyed by the address from ``resolve_client_ip`` (the socket peer,
or ``X-Forwarded-For`` only through ``AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS``
hops) and, where the request names an account, by its normalized email.
Identifiers are hashed before they become Redis keys.

If Redis is unreachable the limiter fails open with a warning: losing the
limit is preferable to taking authentication down with the cache.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request, status
from redis.exceptions import RedisError

from autosecops import config
from autosecops.logger import logger
from autosecops.middleware.request import resolve_client_ip
from autosecops.redis.client import get_redis_client

MINUTE = 60
HOUR = 3600
_KEY_PREFIX = "auth:rate_limit"

# INCR and set the window on first use. A key without a TTL (left by a crash
# between INCR and EXPIRE) gets one here, so it can never block forever.
_CONSUME_LUA = """
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}
"""

_PEEK_LUA = """
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"""


@dataclass(frozen=True, slots=True)
class RateLimit:
    """A fixed-window limit: at most ``limit`` hits per ``window_seconds``."""

    name: str
    limit: int
    window_seconds: int


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Whether a request may proceed, and when to retry if not."""

    allowed: bool
    retry_after_seconds: int


_ALLOW = RateLimitDecision(allowed=True, retry_after_seconds=0)


def _redis_key(rate_limit: RateLimit, identifier: str) -> str:
    digest = hashlib.sha256(identifier.encode()).hexdigest()
    return f"{_KEY_PREFIX}:{rate_limit.name}:{digest}"


def _is_active(rate_limit: RateLimit) -> bool:
    return config.AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED and rate_limit.limit > 0


async def _eval(
    script: str, rate_limit: RateLimit, identifier: str
) -> tuple[int, int] | None:
    """Run a counter script; ``None`` when Redis is unavailable."""
    try:
        client = await get_redis_client()
        result: list[Any] = await client.eval_script(
            script,
            [_redis_key(rate_limit, identifier)],
            [rate_limit.window_seconds],
        )
    except (RedisError, RuntimeError, OSError) as exc:
        logger.warning(
            "Auth rate limiter could not reach Redis; allowing request",
            rule=rate_limit.name,
            error_type=type(exc).__name__,
        )
        return None
    count, ttl = result
    return int(count), int(ttl)


def _decision(rate_limit: RateLimit, *, blocked: bool, ttl: int) -> RateLimitDecision:
    if not blocked:
        return _ALLOW
    retry_after = ttl if ttl > 0 else rate_limit.window_seconds
    return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)


async def consume(rate_limit: RateLimit, identifier: str) -> RateLimitDecision:
    """Count one hit against ``identifier`` and decide whether it is allowed."""
    if not _is_active(rate_limit):
        return _ALLOW
    if (counter := await _eval(_CONSUME_LUA, rate_limit, identifier)) is None:
        return _ALLOW
    count, ttl = counter
    return _decision(rate_limit, blocked=count > rate_limit.limit, ttl=ttl)


async def peek(rate_limit: RateLimit, identifier: str) -> RateLimitDecision:
    """Decide whether ``identifier`` is over the limit without counting a hit."""
    if not _is_active(rate_limit):
        return _ALLOW
    if (counter := await _eval(_PEEK_LUA, rate_limit, identifier)) is None:
        return _ALLOW
    count, ttl = counter
    return _decision(rate_limit, blocked=count >= rate_limit.limit, ttl=ttl)


def too_many_requests(
    request: Request, rate_limit: RateLimit, decision: RateLimitDecision
) -> HTTPException:
    """Build the 429 response for a refused request."""
    logger.warning(
        "Auth rate limit exceeded",
        rule=rate_limit.name,
        path=request.url.path,
        client_ip=resolve_client_ip(request),
    )
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests. Try again later.",
        headers={"Retry-After": str(decision.retry_after_seconds)},
    )


async def enforce(request: Request, *checks: tuple[RateLimit, str]) -> None:
    """Count a hit for every check and raise 429 if any is over its limit.

    Every check is counted even after one refuses, so a client cannot dodge a
    narrow rule by tripping a wider one first.
    """
    refused: tuple[RateLimit, RateLimitDecision] | None = None
    for rate_limit, identifier in checks:
        decision = await consume(rate_limit, identifier)
        if decision.allowed:
            continue
        if refused is None or decision.retry_after_seconds > (
            refused[1].retry_after_seconds
        ):
            refused = (rate_limit, decision)
    if refused is not None:
        raise too_many_requests(request, *refused)


# === Request identifiers === #


def client_ip(request: Request) -> str:
    """The client address used as the rate-limit identity."""
    return resolve_client_ip(request) or "unknown"


def normalize_email(value: object) -> str | None:
    """Lowercase and trim an email-like value; ``None`` if absent."""
    if not isinstance(value, str) or not (email := value.strip().lower()):
        return None
    return email


async def _json_email(request: Request) -> str | None:
    # FastAPI has already read and cached the body for the route's own model.
    try:
        body = await request.json()
    except ValueError:
        return None
    return normalize_email(body.get("email")) if isinstance(body, dict) else None


# === Rules === #


def login_per_ip() -> RateLimit:
    return RateLimit(
        "login_ip", config.AUTOSECOPS__AUTH_RATE_LIMIT_LOGIN_PER_IP, MINUTE
    )


def login_per_account() -> RateLimit:
    return RateLimit(
        "login_account", config.AUTOSECOPS__AUTH_RATE_LIMIT_LOGIN_PER_ACCOUNT, MINUTE
    )


def forgot_password_per_ip() -> RateLimit:
    return RateLimit(
        "forgot_password_ip",
        config.AUTOSECOPS__AUTH_RATE_LIMIT_FORGOT_PASSWORD_PER_IP,
        HOUR,
    )


def forgot_password_per_account() -> RateLimit:
    return RateLimit(
        "forgot_password_account",
        config.AUTOSECOPS__AUTH_RATE_LIMIT_FORGOT_PASSWORD_PER_ACCOUNT,
        HOUR,
    )


def reset_password_per_ip() -> RateLimit:
    return RateLimit(
        "reset_password_ip",
        config.AUTOSECOPS__AUTH_RATE_LIMIT_RESET_PASSWORD_PER_IP,
        MINUTE,
    )


def register_per_ip() -> RateLimit:
    return RateLimit(
        "register_ip", config.AUTOSECOPS__AUTH_RATE_LIMIT_REGISTER_PER_IP, HOUR
    )


def invitation_per_ip() -> RateLimit:
    return RateLimit(
        "invitation_ip", config.AUTOSECOPS__AUTH_RATE_LIMIT_INVITATION_PER_IP, MINUTE
    )


def api_key_failures_per_ip() -> RateLimit:
    return RateLimit(
        "api_key_failures_ip",
        config.AUTOSECOPS__AUTH_RATE_LIMIT_API_KEY_FAILURES_PER_IP,
        MINUTE,
    )


# === Route dependencies === #


async def limit_login(request: Request) -> None:
    """Limit ``POST /auth/login`` per client IP and per client IP plus email."""
    ip = client_ip(request)
    checks = [(login_per_ip(), ip)]
    form = await request.form()
    if email := normalize_email(form.get("username")):
        checks.append((login_per_account(), f"{ip}|{email}"))
    await enforce(request, *checks)


async def limit_forgot_password(request: Request) -> None:
    """Limit ``POST /auth/forgot-password`` per client IP and per email."""
    checks = [(forgot_password_per_ip(), client_ip(request))]
    if email := await _json_email(request):
        checks.append((forgot_password_per_account(), email))
    await enforce(request, *checks)


async def limit_reset_password(request: Request) -> None:
    """Limit ``POST /auth/reset-password`` per client IP."""
    await enforce(request, (reset_password_per_ip(), client_ip(request)))


async def limit_register(request: Request) -> None:
    """Limit ``POST /auth/register`` per client IP."""
    await enforce(request, (register_per_ip(), client_ip(request)))


async def limit_invitation_token(request: Request) -> None:
    """Limit invitation lookups and acceptances by token per client IP."""
    await enforce(request, (invitation_per_ip(), client_ip(request)))


async def check_api_key_failures(request: Request) -> None:
    """Refuse API-key auth from a client IP with too many recent failures."""
    rate_limit = api_key_failures_per_ip()
    decision = await peek(rate_limit, client_ip(request))
    if not decision.allowed:
        raise too_many_requests(request, rate_limit, decision)


async def record_api_key_failure(request: Request) -> None:
    """Count one failed API-key authentication against the client IP."""
    await consume(api_key_failures_per_ip(), client_ip(request))
