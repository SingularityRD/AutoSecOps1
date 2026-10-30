"""Tests for the best-effort authentication audit writers."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest

from autosecops import config
from autosecops.audit.enums import AuditEventActor, AuditEventStatus
from autosecops.audit.types import AuditActor
from autosecops.auth import audit as auth_audit
from autosecops.auth.audit import (
    ANONYMOUS_ACTOR_ID,
    AuthAuditFailureReason,
    anonymous_actor_id,
    emit_anonymous_auth_event,
    emit_api_key_rejected_event,
    emit_user_auth_event,
)
from autosecops.auth.types import PlatformRole, Role
from autosecops.contexts import ctx_role


class _RecordingAuditService:
    def __init__(self, calls: list[dict[str, Any]], **context: Any) -> None:
        self._calls = calls
        self._context = context

    async def create_event(self, **kwargs: Any) -> None:
        self._calls.append({**self._context, "method": "create_event", **kwargs})

    async def create_actor_event(self, **kwargs: Any) -> None:
        self._calls.append(
            {
                **self._context,
                "method": "create_actor_event",
                "ctx_role": ctx_role.get(),
                **kwargs,
            }
        )


@pytest.fixture
def audit_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    @asynccontextmanager
    async def fake_with_session(
        role: Role | PlatformRole | None = None,
        *,
        session: Any = None,
        audit_sink: Any = None,
    ) -> AsyncIterator[_RecordingAuditService]:
        yield _RecordingAuditService(calls, role=role, audit_sink=audit_sink)

    monkeypatch.setattr(auth_audit.AuditService, "with_session", fake_with_session)
    return calls


@pytest.fixture
def auth_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "USER_AUTH_SECRET", "test-user-auth-secret")


@pytest.mark.usefixtures("auth_secret")
def test_anonymous_actor_id_is_a_stable_keyed_pseudonym(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "Someone@Example.com"

    pseudonym = anonymous_actor_id(email)

    assert pseudonym == anonymous_actor_id("  someone@example.com ")
    assert pseudonym != anonymous_actor_id("other@example.com")
    assert pseudonym != ANONYMOUS_ACTOR_ID
    assert "someone" not in str(pseudonym)
    # Without the server secret the pseudonym cannot be recomputed.
    monkeypatch.setattr(config, "USER_AUTH_SECRET", "a-different-secret")
    assert anonymous_actor_id(email) != pseudonym


def test_anonymous_actor_id_without_identifier_or_secret_is_nil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "USER_AUTH_SECRET", "test-user-auth-secret")
    assert anonymous_actor_id(None) == ANONYMOUS_ACTOR_ID
    assert anonymous_actor_id("   ") == ANONYMOUS_ACTOR_ID
    monkeypatch.setattr(config, "USER_AUTH_SECRET", "")
    assert anonymous_actor_id("someone@example.com") == ANONYMOUS_ACTOR_ID


@pytest.mark.anyio
async def test_user_event_without_org_reaches_platform_sink_only(
    audit_calls: list[dict[str, Any]],
) -> None:
    user_id = uuid.uuid4()

    await emit_user_auth_event(
        user_id=user_id,
        resource_type="auth",
        action="sign_out",
        data={"auth_method": "session"},
    )

    [call] = audit_calls
    assert call["audit_sink"] == "platform"
    assert isinstance(call["role"], PlatformRole)
    assert call["role"].user_id == user_id
    assert call["resource_id"] == user_id
    assert call["status"] == AuditEventStatus.SUCCESS
    assert call["include_actor_label"] is False


@pytest.mark.anyio
async def test_user_event_with_org_reaches_both_sinks_as_the_actor(
    audit_calls: list[dict[str, Any]],
) -> None:
    user_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    org_id = uuid.uuid4()

    await emit_user_auth_event(
        user_id=user_id,
        actor_user_id=admin_id,
        resource_type="user",
        action="update",
        status=AuditEventStatus.SUCCESS,
        organization_id=org_id,
    )

    assert [call["audit_sink"] for call in audit_calls] == ["platform", "organization"]
    for call in audit_calls:
        role = call["role"]
        assert isinstance(role, Role)
        assert role.user_id == admin_id
        assert role.organization_id == org_id
        assert call["resource_id"] == user_id


@pytest.mark.anyio
@pytest.mark.usefixtures("auth_secret")
async def test_anonymous_event_ignores_the_request_role(
    audit_calls: list[dict[str, Any]],
) -> None:
    """An anonymous event must not be scoped into whatever org the context holds."""
    request_role = Role(
        type="user",
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        service_id="autosecops-api",
    )
    token = ctx_role.set(request_role)
    try:
        await emit_anonymous_auth_event(
            identifier="someone@example.com",
            action="sign_in",
            data={"failure_reason": "unknown_account"},
        )
        assert ctx_role.get() is request_role
    finally:
        ctx_role.reset(token)

    [call] = audit_calls
    assert call["audit_sink"] == "platform"
    assert call["ctx_role"] is None
    actor = call["actor"]
    assert isinstance(actor, AuditActor)
    assert actor.actor_type == AuditEventActor.ANONYMOUS
    assert actor.actor_id == anonymous_actor_id("someone@example.com")
    assert actor.actor_label is None
    assert call["status"] == AuditEventStatus.FAILURE
    assert "someone@example.com" not in repr(call)


@pytest.mark.anyio
async def test_api_key_rejection_goes_to_the_org_sink(
    audit_calls: list[dict[str, Any]],
) -> None:
    org_id = uuid.uuid4()
    service_account_id = uuid.uuid4()
    api_key_id = uuid.uuid4()

    await emit_api_key_rejected_event(
        organization_id=org_id,
        workspace_id=None,
        service_account_id=service_account_id,
        api_key_id=api_key_id,
        failure_reason=AuthAuditFailureReason.EXPIRED,
    )

    [call] = audit_calls
    assert call["audit_sink"] == "organization"
    role = call["role"]
    assert isinstance(role, Role)
    assert role.type == "service_account"
    assert role.actor_id == service_account_id
    assert call["resource_type"] == "service_account_api_key"
    assert call["resource_id"] == api_key_id
    assert call["status"] == AuditEventStatus.FAILURE
    assert call["data"] == {
        "auth_method": "api_key",
        "failure_reason": "expired",
        "api_key_id": str(api_key_id),
    }


@pytest.mark.anyio
async def test_writers_never_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing sink must not change the auth decision that emitted the event."""
    monkeypatch.setattr(
        auth_audit.AuditService,
        "with_session",
        MagicMock(side_effect=RuntimeError("audit sink unavailable")),
    )

    role_before = ctx_role.get()

    await emit_user_auth_event(
        user_id=uuid.uuid4(), resource_type="auth", action="sign_in"
    )
    await emit_anonymous_auth_event(identifier=None, action="throttle")
    await emit_api_key_rejected_event(
        organization_id=uuid.uuid4(),
        workspace_id=None,
        service_account_id=uuid.uuid4(),
        api_key_id=uuid.uuid4(),
        failure_reason=AuthAuditFailureReason.EXPIRED,
    )
    assert ctx_role.get() is role_before


@pytest.mark.anyio
async def test_background_audit_task_runs_and_is_released(
    audit_calls: list[dict[str, Any]],
) -> None:
    """A writer spawned off the request path runs and releases its reference."""
    user_id = uuid.uuid4()

    auth_audit.spawn_auth_audit_task(
        emit_user_auth_event(user_id=user_id, resource_type="auth", action="sign_in")
    )
    await auth_audit.drain_auth_audit_tasks()

    [call] = audit_calls
    assert call["resource_id"] == user_id
    assert not auth_audit._pending_audit_tasks
