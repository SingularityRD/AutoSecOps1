"""Branch coverage for incoming webhook authentication and payload parsing.

The webhook rows here are real ORM instances (not mocks), so the secret is
derived by ``Webhook.secret`` and API keys are checked by the real
``verify_api_key`` against a real salted hash. Only the database session is
replaced, by a stub that returns those rows.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import HTTPException, Request
from starlette.requests import ClientDisconnect

from autosecops.auth.api_keys import generate_api_key
from autosecops.contexts import ctx_role
from autosecops.db.models import Webhook, WebhookApiKey, Workspace
from autosecops.identifiers.workflow import WorkflowUUID
from autosecops.webhooks import dependencies
from autosecops.webhooks.dependencies import (
    API_KEY_HEADER,
    _ip_allowed,
    parse_content_type,
    parse_webhook_payload,
    validate_incoming_webhook,
)


class _Result:
    def __init__(self, value: object | None) -> None:
        self._value = value

    def scalar_one(self) -> object:
        if self._value is None:
            from sqlalchemy.exc import NoResultFound

            raise NoResultFound()
        return self._value


class _StubSession:
    """Returns the webhook row, then the workspace row, and records writes."""

    def __init__(self, webhook: Webhook | None, workspace: Workspace | None) -> None:
        self._results = [_Result(webhook), _Result(workspace)]
        self.added: list[object] = []
        self.commits = 0

    async def execute(self, _stmt: Any) -> _Result:
        return self._results.pop(0)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1


def _webhook(
    *,
    status: str = "online",
    methods: list[str] | None = None,
    cidrs: list[str] | None = None,
) -> Webhook:
    return Webhook(
        id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        workflow_id=uuid.uuid4(),
        status=status,
        methods=methods or ["POST"],
        allowlisted_cidrs=cidrs or [],
        include_headers=False,
    )


def _request(
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    client: tuple[str, int] | None = ("203.0.113.7", 40000),
) -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/",
            "query_string": b"",
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
            ],
            "client": client,
        }
    )


@pytest.fixture
def stub_session(monkeypatch: pytest.MonkeyPatch):
    """Install a stub session factory and return a setter for its rows."""
    holder: dict[str, _StubSession] = {}

    def install(webhook: Webhook | None, workspace: Workspace | None = None):
        session = _StubSession(
            webhook,
            workspace
            if workspace is not None
            else Workspace(id=uuid.uuid4(), organization_id=uuid.uuid4()),
        )

        @asynccontextmanager
        async def _cm() -> AsyncIterator[_StubSession]:
            yield session

        monkeypatch.setattr(
            dependencies, "get_async_session_bypass_rls_context_manager", _cm
        )
        holder["session"] = session
        return session

    return install


async def _validate(webhook: Webhook, secret: str, request: Request) -> None:
    await validate_incoming_webhook(
        WorkflowUUID.new(webhook.workflow_id), secret, request
    )


def _status(exc_info: pytest.ExceptionInfo[HTTPException]) -> int:
    return exc_info.value.status_code


@pytest.mark.anyio
async def test_unknown_workflow_is_unauthorized(stub_session) -> None:
    stub_session(None)
    with pytest.raises(HTTPException) as exc_info:
        await validate_incoming_webhook(
            WorkflowUUID.new_uuid4(), "anything", _request()
        )
    assert _status(exc_info) == 401


@pytest.mark.anyio
async def test_wrong_secret_is_rejected_before_status_is_revealed(
    stub_session,
) -> None:
    """An offline webhook must not reveal it is offline to a wrong secret."""
    webhook = _webhook(status="offline")
    stub_session(webhook)
    with pytest.raises(HTTPException) as exc_info:
        wrong = webhook.secret[:-1] + ("1" if webhook.secret[-1] == "0" else "0")
        await _validate(webhook, wrong, _request())
    assert _status(exc_info) == 401


@pytest.mark.anyio
async def test_offline_webhook_with_correct_secret_is_bad_request(
    stub_session,
) -> None:
    webhook = _webhook(status="offline")
    stub_session(webhook)
    with pytest.raises(HTTPException) as exc_info:
        await _validate(webhook, webhook.secret, _request())
    assert _status(exc_info) == 400


@pytest.mark.anyio
async def test_method_outside_configured_methods_is_405(stub_session) -> None:
    webhook = _webhook(methods=["POST"])
    stub_session(webhook)
    with pytest.raises(HTTPException) as exc_info:
        await _validate(webhook, webhook.secret, _request(method="GET"))
    assert _status(exc_info) == 405


@pytest.mark.anyio
async def test_configured_methods_match_case_insensitively(stub_session) -> None:
    webhook = _webhook(methods=["get", "POST"])
    stub_session(webhook)
    await _validate(webhook, webhook.secret, _request(method="GET"))
    role = ctx_role.get()
    assert role is not None and role.workspace_id == webhook.workspace_id


@pytest.mark.anyio
async def test_allowlist_without_resolvable_client_ip_is_forbidden(
    stub_session,
) -> None:
    webhook = _webhook(cidrs=["203.0.113.0/24"])
    stub_session(webhook)
    with pytest.raises(HTTPException) as exc_info:
        await _validate(webhook, webhook.secret, _request(client=None))
    assert _status(exc_info) == 403


def _with_api_key(webhook: Webhook, *, revoked: bool = False) -> str:
    generated = generate_api_key()
    webhook.api_key = WebhookApiKey(
        id=uuid.uuid4(),
        workspace_id=webhook.workspace_id,
        hashed=generated.hashed,
        salt=generated.salt_b64,
        preview=generated.preview(),
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    return generated.raw


@pytest.mark.anyio
async def test_valid_api_key_is_accepted_and_last_use_is_recorded(
    stub_session,
) -> None:
    webhook = _webhook()
    raw_key = _with_api_key(webhook)
    session = stub_session(webhook)

    await _validate(
        webhook, webhook.secret, _request(headers={API_KEY_HEADER: raw_key})
    )

    assert webhook.api_key is not None
    assert webhook.api_key.last_used_at is not None
    assert session.added == [webhook.api_key]
    assert session.commits == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("header", "revoked"),
    [
        pytest.param(None, False, id="missing_key"),
        pytest.param("tc_sk_not-the-right-key", False, id="wrong_key"),
        pytest.param("", False, id="empty_key"),
        pytest.param("<valid>", True, id="revoked_key_even_if_correct"),
    ],
)
async def test_api_key_protected_webhook_rejects_bad_keys(
    stub_session, header: str | None, revoked: bool
) -> None:
    webhook = _webhook()
    raw_key = _with_api_key(webhook, revoked=revoked)
    session = stub_session(webhook)
    headers = (
        {} if header is None else {API_KEY_HEADER: header.replace("<valid>", raw_key)}
    )

    with pytest.raises(HTTPException) as exc_info:
        await _validate(webhook, webhook.secret, _request(headers=headers))

    assert _status(exc_info) == 401
    assert webhook.api_key is not None and webhook.api_key.last_used_at is None
    assert session.commits == 0
    assert ctx_role.get() is None


@pytest.mark.anyio
async def test_api_key_header_without_configured_key_is_ignored(
    stub_session,
) -> None:
    webhook = _webhook()
    session = stub_session(webhook)
    await _validate(
        webhook, webhook.secret, _request(headers={API_KEY_HEADER: "tc_sk_unused"})
    )
    assert session.commits == 0
    assert ctx_role.get() is not None


def test_ip_allowlist_skips_invalid_entries_and_rejects_bad_client_ip() -> None:
    assert _ip_allowed("203.0.113.7", ["not-a-cidr", "203.0.113.0/24"]) is True
    assert _ip_allowed("203.0.113.7", ["not-a-cidr"]) is False
    assert _ip_allowed("not-an-ip", ["0.0.0.0/0"]) is False


def test_parse_content_type_normalizes_media_type_case() -> None:
    """Media types are case-insensitive (RFC 9110 section 8.3.1)."""
    assert parse_content_type('Application/X-NDJSON; charset="utf-8"; bad') == (
        "application/x-ndjson",
        {"charset": "utf-8"},
    )


def _body_request(body: bytes, content_type: str | None = None) -> Request:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "query_string": b"",
            "headers": (
                [(b"content-type", content_type.encode())] if content_type else []
            ),
        },
        receive,
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("content_type", "body", "expected"),
    [
        pytest.param(
            "Application/x-www-form-urlencoded",
            b"a=1&b=two",
            {"a": "1", "b": "two"},
            id="mixed_case_form",
        ),
        pytest.param(
            "APPLICATION/X-NDJSON",
            b'{"n": 1}\n{"n": 2}',
            [{"n": 1}, {"n": 2}],
            id="upper_case_ndjson",
        ),
    ],
)
async def test_payload_parsing_honours_mixed_case_media_types(
    content_type: str, body: bytes, expected: object
) -> None:
    request = _body_request(body, content_type)
    result = await parse_webhook_payload(request, content_type)
    assert result == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("content_type", "body", "detail"),
    [
        pytest.param("application/json", b"{not json", "Invalid json payload"),
        pytest.param(
            "application/x-ndjson", b'{"ok": 1}\nnot json', "Invalid ndjson payload"
        ),
        pytest.param(None, b"\xff\xfe", "Invalid json payload", id="non_utf8"),
    ],
)
async def test_malformed_payloads_are_bad_requests(
    content_type: str | None, body: bytes, detail: str
) -> None:
    with pytest.raises(HTTPException) as exc_info:
        await parse_webhook_payload(_body_request(body), content_type)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == detail


@pytest.mark.anyio
async def test_client_disconnect_is_a_bad_request_without_chained_context() -> None:
    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    request = Request(
        {"type": "http", "method": "POST", "path": "/", "headers": []}, receive
    )
    with pytest.raises(HTTPException) as exc_info:
        await parse_webhook_payload(request, "application/json")
    assert exc_info.value.status_code == 400
    # Raised outside the except block, so the disconnect is not attached.
    assert not isinstance(exc_info.value.__context__, ClientDisconnect)
