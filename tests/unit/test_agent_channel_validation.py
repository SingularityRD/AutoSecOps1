from __future__ import annotations

import hashlib
import hmac
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from autosecops.agent.channels.dependencies import (
    SLACK_REQUEST_MAX_AGE_SECONDS,
    _verify_slack_signature,
    validate_channel_token,
)
from autosecops.agent.channels.schemas import ChannelType
from autosecops.agent.channels.service import (
    PENDING_SLACK_BOT_TOKEN,
    AgentChannelService,
)


def _build_request(headers: dict[str, str], body: bytes) -> Request:
    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope, receive)


def _build_slack_signature(secret: str, timestamp: str, body: bytes) -> str:
    signature_base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), signature_base, hashlib.sha256).hexdigest()


def test_verify_slack_signature_accepts_valid_request() -> None:
    secret = "signing-secret"
    body = b'{"type":"event_callback"}'
    timestamp = str(int(datetime.now(tz=UTC).timestamp()))
    signature = _build_slack_signature(secret, timestamp, body)
    request = _build_request(
        {
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": signature,
        },
        body,
    )

    _verify_slack_signature(
        request=request,
        body=body,
        slack_signing_secret=secret,
    )


def test_verify_slack_signature_rejects_stale_timestamp() -> None:
    secret = "signing-secret"
    body = b'{"type":"event_callback"}'
    stale_timestamp = str(
        int((datetime.now(tz=UTC) - timedelta(minutes=10)).timestamp())
    )
    signature = _build_slack_signature(secret, stale_timestamp, body)
    request = _build_request(
        {
            "X-Slack-Request-Timestamp": stale_timestamp,
            "X-Slack-Signature": signature,
        },
        body,
    )

    with pytest.raises(HTTPException) as exc_info:
        _verify_slack_signature(
            request=request,
            body=body,
            slack_signing_secret=secret,
        )
    assert exc_info.value.status_code == 401


def test_verify_slack_signature_rejects_invalid_signature() -> None:
    secret = "signing-secret"
    body = b'{"type":"event_callback"}'
    timestamp = str(int(datetime.now(tz=UTC).timestamp()))
    request = _build_request(
        {
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": "v0=invalid",
        },
        body,
    )

    with pytest.raises(HTTPException) as exc_info:
        _verify_slack_signature(
            request=request,
            body=body,
            slack_signing_secret=secret,
        )
    assert exc_info.value.status_code == 401


def _now_timestamp(offset_seconds: int = 0) -> str:
    return str(int(datetime.now(tz=UTC).timestamp()) + offset_seconds)


@pytest.mark.parametrize(
    "headers_for",
    [
        # Clock skew is symmetric: a timestamp from the future is a replay
        # prepared in advance.
        pytest.param(
            lambda secret, body: {
                "X-Slack-Request-Timestamp": (ts := _now_timestamp(301)),
                "X-Slack-Signature": _build_slack_signature(secret, ts, body),
            },
            id="future-timestamp",
        ),
        pytest.param(
            lambda secret, body: {
                "X-Slack-Request-Timestamp": "not-a-number",
                "X-Slack-Signature": _build_slack_signature(
                    secret, "not-a-number", body
                ),
            },
            id="non-numeric-timestamp",
        ),
        pytest.param(
            lambda secret, body: {
                "X-Slack-Signature": _build_slack_signature(
                    secret, _now_timestamp(), body
                )
            },
            id="missing-timestamp",
        ),
        pytest.param(
            lambda secret, body: {"X-Slack-Request-Timestamp": _now_timestamp()},
            id="missing-signature",
        ),
        pytest.param(
            lambda secret, body: {
                "X-Slack-Request-Timestamp": (ts := _now_timestamp()),
                "X-Slack-Signature": _build_slack_signature(
                    secret, ts, b'{"type":"block_actions"}'
                ),
            },
            id="signature-for-another-body",
        ),
        pytest.param(
            lambda secret, body: {
                "X-Slack-Request-Timestamp": (ts := _now_timestamp()),
                "X-Slack-Signature": _build_slack_signature(
                    "another-signing-secret", ts, body
                ),
            },
            id="signed-with-another-secret",
        ),
    ],
)
def test_verify_slack_signature_rejects_untrusted_requests(
    headers_for: Callable[[str, bytes], dict[str, str]],
) -> None:
    secret = "signing-secret"
    body = b'{"type":"event_callback"}'
    request = _build_request(headers_for(secret, body), body)

    with pytest.raises(HTTPException) as exc_info:
        _verify_slack_signature(
            request=request,
            body=body,
            slack_signing_secret=secret,
        )
    assert exc_info.value.status_code == 401


def test_verify_slack_signature_accepts_timestamp_inside_the_window() -> None:
    secret = "signing-secret"
    body = b'{"type":"event_callback"}'
    timestamp = _now_timestamp(-(SLACK_REQUEST_MAX_AGE_SECONDS - 5))
    request = _build_request(
        {
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": _build_slack_signature(secret, timestamp, body),
        },
        body,
    )

    _verify_slack_signature(request=request, body=body, slack_signing_secret=secret)


@pytest.mark.anyio
async def test_validate_channel_token_allows_url_verification_for_pending_inactive_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_id = uuid.uuid4()
    body = b'{"type":"url_verification","challenge":"abc"}'
    timestamp = str(int(datetime.now(tz=UTC).timestamp()))
    signature = _build_slack_signature("signing-secret", timestamp, body)
    request = _build_request(
        {
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": signature,
        },
        body,
    )
    token_record = AsyncMock()
    token_record.id = token_id
    token_record.workspace_id = uuid.uuid4()
    token_record.agent_preset_id = uuid.uuid4()
    token_record.is_active = False
    token_record.config = {
        "slack_bot_token": PENDING_SLACK_BOT_TOKEN,
        "slack_signing_secret": "signing-secret",
    }
    get_token_mock = AsyncMock(return_value=token_record)

    monkeypatch.setattr(
        AgentChannelService,
        "parse_public_token",
        lambda _: (token_id, "sig"),
    )
    monkeypatch.setattr(
        AgentChannelService,
        "verify_public_token_signature",
        lambda _token_id, _sig: True,
    )
    monkeypatch.setattr(
        AgentChannelService,
        "get_token_for_public_request",
        get_token_mock,
    )

    validated = await validate_channel_token(
        channel_type=ChannelType.SLACK,
        token="public-token",
        request=request,
        session=AsyncMock(),
    )

    assert validated.id == token_id
    assert validated.config.slack_bot_token == PENDING_SLACK_BOT_TOKEN
    await_args = get_token_mock.await_args
    assert await_args is not None
    assert await_args.kwargs["require_active"] is False


@pytest.mark.anyio
async def test_validate_channel_token_rejects_inactive_token_for_event_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_id = uuid.uuid4()
    body = b'{"type":"event_callback","event":{"type":"app_mention"}}'
    timestamp = str(int(datetime.now(tz=UTC).timestamp()))
    signature = _build_slack_signature("signing-secret", timestamp, body)
    request = _build_request(
        {
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": signature,
        },
        body,
    )
    token_record = AsyncMock()
    token_record.id = token_id
    token_record.workspace_id = uuid.uuid4()
    token_record.agent_preset_id = uuid.uuid4()
    token_record.is_active = False
    token_record.config = {
        "slack_bot_token": "xoxb-ready",
        "slack_signing_secret": "signing-secret",
    }
    get_token_mock = AsyncMock(return_value=token_record)

    monkeypatch.setattr(
        AgentChannelService,
        "parse_public_token",
        lambda _: (token_id, "sig"),
    )
    monkeypatch.setattr(
        AgentChannelService,
        "verify_public_token_signature",
        lambda _token_id, _sig: True,
    )
    monkeypatch.setattr(
        AgentChannelService,
        "get_token_for_public_request",
        get_token_mock,
    )

    with pytest.raises(HTTPException) as exc_info:
        await validate_channel_token(
            channel_type=ChannelType.SLACK,
            token="public-token",
            request=request,
            session=AsyncMock(),
        )

    assert exc_info.value.status_code == 401
    await_args = get_token_mock.await_args
    assert await_args is not None
    assert await_args.kwargs["require_active"] is True
