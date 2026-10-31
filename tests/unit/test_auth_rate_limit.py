"""Regression tests for the Redis-backed auth endpoint rate limits."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Callable, Sequence
from typing import Annotated, Any
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from autosecops import config
from autosecops.api.app import app as api_app
from autosecops.auth import audit as auth_audit
from autosecops.auth import credentials
from autosecops.auth import rate_limit as rl

PUBLIC_CLIENT = ("203.0.113.9", 4321)
TRUSTED_PROXY = ("10.0.0.5", 4321)


class _RedisAdapter:
    """``RedisClient.eval_script`` over this test worker's Redis database."""

    def __init__(self, client: aioredis.Redis) -> None:
        self.client = client

    async def eval_script(
        self, script: str, keys: Sequence[str], args: Sequence[str | int | float]
    ) -> Any:
        return await self.client.eval(script, len(keys), *keys, *args)  # pyright: ignore[reportGeneralTypeIssues] - redis-py types EVAL for sync and async


@pytest.fixture
async def redis_client(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[aioredis.Redis]:
    client = aioredis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    adapter = _RedisAdapter(client)

    async def _get() -> _RedisAdapter:
        return adapter

    monkeypatch.setattr(rl, "get_redis_client", _get)
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED", True)
    yield client
    await client.aclose()


@pytest.fixture(autouse=True)
def throttle_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture rate-limit audit events instead of resolving a real sink."""
    events: list[dict[str, Any]] = []

    async def fake_emit(**kwargs: Any) -> None:
        events.append(kwargs)

    monkeypatch.setattr(rl, "emit_anonymous_auth_event", fake_emit)
    return events


def _limits(monkeypatch: pytest.MonkeyPatch, **limits: int) -> None:
    for name, value in limits.items():
        monkeypatch.setattr(config, f"AUTOSECOPS__AUTH_RATE_LIMIT_{name}", value)


# === Limiter core === #


@pytest.mark.anyio
async def test_consume_refuses_past_limit_with_retry_after(
    redis_client: aioredis.Redis,
) -> None:
    rule = rl.RateLimit("test", limit=2, window_seconds=60)

    decisions = [await rl.consume(rule, "client") for _ in range(3)]

    assert [d.allowed for d in decisions] == [True, True, False]
    assert 0 < decisions[2].retry_after_seconds <= 60
    assert (await rl.consume(rule, "other-client")).allowed


@pytest.mark.anyio
async def test_peek_does_not_count(redis_client: aioredis.Redis) -> None:
    rule = rl.RateLimit("test", limit=1, window_seconds=60)

    assert (await rl.peek(rule, "client")).allowed
    assert (await rl.peek(rule, "client")).allowed
    await rl.consume(rule, "client")
    assert not (await rl.peek(rule, "client")).allowed


@pytest.mark.anyio
async def test_keys_hash_identifiers_and_expire(redis_client: aioredis.Redis) -> None:
    rule = rl.RateLimit("test", limit=5, window_seconds=60)
    await rl.consume(rule, "203.0.113.9|member@example.com")

    keys = await redis_client.keys("auth:rate_limit:test:*")
    assert len(keys) == 1
    assert "example.com" not in keys[0]
    assert 0 < await redis_client.ttl(keys[0]) <= 60


@pytest.mark.anyio
async def test_zero_limit_or_disabled_flag_never_blocks(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    off = rl.RateLimit("test", limit=0, window_seconds=60)
    assert all([(await rl.consume(off, "client")).allowed for _ in range(3)])

    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED", False)
    on = rl.RateLimit("test", limit=1, window_seconds=60)
    assert all([(await rl.consume(on, "client")).allowed for _ in range(3)])
    assert await redis_client.keys("auth:rate_limit:*") == []


@pytest.mark.anyio
async def test_fails_open_with_warning_when_redis_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _broken() -> Any:
        raise ConnectionError("redis down")

    warning = Mock()
    monkeypatch.setattr(rl, "get_redis_client", _broken)
    monkeypatch.setattr(rl.logger, "warning", warning)
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED", True)
    rule = rl.RateLimit("test", limit=1, window_seconds=60)

    assert (await rl.consume(rule, "client")).allowed
    assert (await rl.consume(rule, "client")).allowed
    assert (await rl.peek(rule, "client")).allowed
    assert warning.call_count == 3


# === Route dependencies === #


class _EmailBody(BaseModel):
    email: str


def _app() -> FastAPI:
    app = FastAPI()

    @app.post("/login", dependencies=[Depends(rl.limit_login)])
    async def login(  # pyright: ignore[reportUnusedFunction] - route handler
        form: Annotated[OAuth2PasswordRequestForm, Depends()],
    ) -> dict[str, str]:
        return {"username": form.username}

    @app.post("/forgot-password", dependencies=[Depends(rl.limit_forgot_password)])
    async def forgot_password(body: _EmailBody) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction] - route handler
        return {"email": body.email}

    return app


def _client(app: FastAPI, peer: tuple[str, int] = PUBLIC_CLIENT) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=peer)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def _login(
    client: httpx.AsyncClient, email: str, headers: dict[str, str] | None = None
) -> httpx.Response:
    return await client.post(
        "/login", data={"username": email, "password": "wrong"}, headers=headers
    )


@pytest.mark.anyio
async def test_login_is_limited_per_ip_and_normalized_email(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limits(monkeypatch, LOGIN_PER_IP=100, LOGIN_PER_ACCOUNT=2)
    async with _client(_app()) as client:
        assert (await _login(client, "member@example.com")).status_code == 200
        assert (await _login(client, " Member@Example.com")).status_code == 200
        limited = await _login(client, "MEMBER@example.com")
        other = await _login(client, "other@example.com")

    assert limited.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert 0 < int(limited.headers["Retry-After"]) <= 60
    assert other.status_code == 200


@pytest.mark.anyio
async def test_login_per_ip_limit_spans_emails(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limits(monkeypatch, LOGIN_PER_IP=2, LOGIN_PER_ACCOUNT=100)
    async with _client(_app()) as client:
        statuses = [
            (await _login(client, f"user{i}@example.com")).status_code for i in range(3)
        ]

    assert statuses == [200, 200, 429]


@pytest.mark.anyio
async def test_forwarded_for_from_untrusted_peer_is_ignored(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limits(monkeypatch, LOGIN_PER_IP=1, LOGIN_PER_ACCOUNT=100)
    async with _client(_app(), PUBLIC_CLIENT) as client:
        first = await _login(
            client, "a@example.com", {"X-Forwarded-For": "198.51.100.1"}
        )
        spoofed = await _login(
            client, "b@example.com", {"X-Forwarded-For": "198.51.100.2"}
        )

    assert first.status_code == 200
    assert spoofed.status_code == 429


@pytest.mark.anyio
async def test_forwarded_for_from_trusted_proxy_keys_by_client(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limits(monkeypatch, LOGIN_PER_IP=1, LOGIN_PER_ACCOUNT=100)
    async with _client(_app(), TRUSTED_PROXY) as client:
        one = await _login(client, "a@example.com", {"X-Forwarded-For": "198.51.100.1"})
        two = await _login(client, "b@example.com", {"X-Forwarded-For": "198.51.100.2"})
        again = await _login(
            client, "c@example.com", {"X-Forwarded-For": "198.51.100.1"}
        )

    assert [one.status_code, two.status_code, again.status_code] == [200, 200, 429]


@pytest.mark.anyio
async def test_forgot_password_is_limited_per_email_across_ips(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limits(monkeypatch, FORGOT_PASSWORD_PER_IP=100, FORGOT_PASSWORD_PER_ACCOUNT=1)
    app = _app()
    body = {"email": "Member@example.com"}
    async with _client(app, ("203.0.113.10", 1)) as client:
        first = await client.post("/forgot-password", json=body)
    async with _client(app, ("203.0.113.11", 1)) as client:
        second = await client.post("/forgot-password", json=body)
        other = await client.post("/forgot-password", json={"email": "x@example.com"})

    assert first.status_code == 200
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) > 60
    assert other.status_code == 200


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method", "path", "setting", "rule", "kwargs"),
    [
        (
            "POST",
            "/auth/login",
            "LOGIN_PER_IP",
            rl.login_per_ip,
            {"data": {"username": "member@example.com", "password": "x"}},
        ),
        (
            "POST",
            "/auth/register",
            "REGISTER_PER_IP",
            rl.register_per_ip,
            {"json": {"email": "member@example.com", "password": "x" * 16}},
        ),
        (
            "POST",
            "/auth/forgot-password",
            "FORGOT_PASSWORD_PER_IP",
            rl.forgot_password_per_ip,
            {"json": {"email": "member@example.com"}},
        ),
        (
            "POST",
            "/auth/reset-password",
            "RESET_PASSWORD_PER_IP",
            rl.reset_password_per_ip,
            {"json": {"token": "bogus", "password": "x" * 16}},
        ),
        (
            "POST",
            "/auth/request-verify-token",
            "VERIFY_REQUEST_PER_IP",
            rl.verify_request_per_ip,
            {"json": {"email": "member@example.com"}},
        ),
        (
            "POST",
            "/auth/verify",
            "VERIFY_PER_IP",
            rl.verify_per_ip,
            {"json": {"token": "bogus"}},
        ),
        (
            "GET",
            "/invitations/token/bogus",
            "INVITATION_PER_IP",
            rl.invitation_per_ip,
            {},
        ),
        (
            "POST",
            "/invitations/accept",
            "INVITATION_PER_IP",
            rl.invitation_per_ip,
            {"json": {"token": "bogus"}},
        ),
    ],
)
async def test_api_auth_routes_are_rate_limited(
    redis_client: aioredis.Redis,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    setting: str,
    rule: Callable[[], rl.RateLimit],
    kwargs: dict[str, Any],
) -> None:
    """The real app mounts the limiter on each auth route."""
    _limits(monkeypatch, **{setting: 1})
    await rl.consume(rule(), PUBLIC_CLIENT[0])

    try:
        async with _client(api_app) as client:
            response = await client.request(method, path, **kwargs)
    finally:
        # Reset the built middleware stack so later tests in this worker can
        # still add middleware to the shared app.
        api_app.middleware_stack = None

    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in response.headers


@pytest.mark.anyio
async def test_verify_request_is_limited_per_email_across_ips(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resend flood for one mailbox is refused whichever client sends it."""
    _limits(monkeypatch, VERIFY_REQUEST_PER_IP=100, VERIFY_REQUEST_PER_ACCOUNT=1)
    await rl.consume(rl.verify_request_per_account(), "member@example.com")

    async with _client(api_app) as client:
        response = await client.post(
            "/auth/request-verify-token", json={"email": "Member@example.com"}
        )

    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


# === API-key failures === #


def _request(peer: tuple[str, int] = PUBLIC_CLIENT) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/workflows",
            "headers": [],
            "client": peer,
        }
    )


@pytest.mark.anyio
async def test_api_key_failures_block_further_attempts_from_ip(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limits(monkeypatch, API_KEY_FAILURES_PER_IP=2)
    inner = AsyncMock(side_effect=credentials.UNAUTHORIZED_EXCEPTION)
    monkeypatch.setattr(credentials, "_authenticate_api_key", inner)

    for _ in range(2):
        with pytest.raises(HTTPException) as exc_info:
            await credentials._authenticate_api_key_rate_limited(
                request=_request(), api_key="tc_org_sk_bad", workspace_id=None
            )
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    with pytest.raises(HTTPException) as exc_info:
        await credentials._authenticate_api_key_rate_limited(
            request=_request(), api_key="tc_org_sk_bad", workspace_id=None
        )
    assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert exc_info.value.headers is not None
    assert "Retry-After" in exc_info.value.headers
    assert inner.await_count == 2


@pytest.mark.anyio
async def test_successful_api_key_auth_is_not_counted(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limits(monkeypatch, API_KEY_FAILURES_PER_IP=1)
    role = Mock()
    monkeypatch.setattr(
        credentials, "_authenticate_api_key", AsyncMock(return_value=role)
    )

    for _ in range(3):
        assert (
            await credentials._authenticate_api_key_rate_limited(
                request=_request(), api_key="tc_org_sk_good", workspace_id=uuid.uuid4()
            )
            is role
        )
    assert await redis_client.keys("auth:rate_limit:*") == []


def _expired_key_error() -> credentials.ExpiredApiKeyError:
    return credentials.ExpiredApiKeyError(
        organization_id=uuid.uuid4(),
        workspace_id=None,
        service_account_id=uuid.uuid4(),
        api_key_id=uuid.uuid4(),
    )


@pytest.mark.anyio
async def test_expired_api_key_does_not_lock_out_the_client_ip(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One expired integration behind a shared egress IP must not block others."""
    _limits(monkeypatch, API_KEY_FAILURES_PER_IP=2)
    monkeypatch.setattr(
        credentials,
        "_authenticate_api_key",
        AsyncMock(side_effect=_expired_key_error()),
    )

    for _ in range(5):
        with pytest.raises(HTTPException) as exc_info:
            await credentials._authenticate_api_key_rate_limited(
                request=_request(), api_key="tc_org_sk_expired", workspace_id=None
            )
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    assert await redis_client.keys("auth:rate_limit:api_key_failures_ip:*") == []
    role = Mock()
    monkeypatch.setattr(
        credentials, "_authenticate_api_key", AsyncMock(return_value=role)
    )
    assert (
        await credentials._authenticate_api_key_rate_limited(
            request=_request(), api_key="tc_org_sk_other", workspace_id=None
        )
        is role
    )


@pytest.mark.anyio
async def test_expired_api_key_refusal_is_audited_once_per_window(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Applies even with rate limiting off: it bounds audit volume, not access.
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED", False)
    key_id, other_key_id = uuid.uuid4(), uuid.uuid4()

    assert await rl.first_expired_api_key_refusal_in_window(key_id)
    assert not await rl.first_expired_api_key_refusal_in_window(key_id)
    assert not await rl.first_expired_api_key_refusal_in_window(key_id)
    assert await rl.first_expired_api_key_refusal_in_window(other_key_id)


@pytest.mark.anyio
async def test_expired_api_key_refusal_is_audited_when_redis_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _broken() -> Any:
        raise ConnectionError("redis down")

    monkeypatch.setattr(rl, "get_redis_client", _broken)
    key_id = uuid.uuid4()

    assert await rl.first_expired_api_key_refusal_in_window(key_id)
    assert await rl.first_expired_api_key_refusal_in_window(key_id)


# === Audit === #


@pytest.mark.anyio
async def test_only_the_tripping_login_is_audited(
    redis_client: aioredis.Redis,
    monkeypatch: pytest.MonkeyPatch,
    throttle_events: list[dict[str, Any]],
) -> None:
    """A flood of refused requests writes one audit event per window."""
    _limits(monkeypatch, LOGIN_PER_IP=100, LOGIN_PER_ACCOUNT=2)
    async with _client(_app()) as client:
        statuses = [
            (await _login(client, "Member@example.com")).status_code for _ in range(6)
        ]

    assert statuses == [200, 200, 429, 429, 429, 429]
    assert throttle_events == [
        {
            "identifier": "member@example.com",
            "action": "throttle",
            "data": {"operation": "login_account", "failure_reason": "rate_limited"},
        }
    ]


@pytest.mark.anyio
async def test_api_key_lockout_is_audited_once(
    redis_client: aioredis.Redis,
    monkeypatch: pytest.MonkeyPatch,
    throttle_events: list[dict[str, Any]],
) -> None:
    _limits(monkeypatch, API_KEY_FAILURES_PER_IP=2)
    monkeypatch.setattr(
        credentials,
        "_authenticate_api_key",
        AsyncMock(side_effect=credentials.UNAUTHORIZED_EXCEPTION),
    )

    for _ in range(4):
        with pytest.raises(HTTPException):
            await credentials._authenticate_api_key_rate_limited(
                request=_request(), api_key="tc_org_sk_bad", workspace_id=None
            )

    assert throttle_events == [
        {
            "identifier": None,
            "action": "throttle",
            "data": {
                "operation": "api_key_failures_ip",
                "failure_reason": "rate_limited",
            },
        }
    ]


@pytest.mark.anyio
async def test_throttle_audit_failure_still_refuses(
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken audit sink must not turn a 429 into an admitted request."""
    _limits(monkeypatch, LOGIN_PER_IP=1, LOGIN_PER_ACCOUNT=100)
    monkeypatch.setattr(
        rl, "emit_anonymous_auth_event", auth_audit.emit_anonymous_auth_event
    )
    monkeypatch.setattr(
        auth_audit.AuditService,
        "with_session",
        Mock(side_effect=RuntimeError("audit sink unavailable")),
    )
    async with _client(_app()) as client:
        first = await _login(client, "member@example.com")
        second = await _login(client, "member@example.com")

    assert first.status_code == 200
    assert second.status_code == status.HTTP_429_TOO_MANY_REQUESTS
