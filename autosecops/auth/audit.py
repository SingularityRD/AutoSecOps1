"""Best-effort audit events for authentication and credential lifecycle.

Every writer here is best-effort: a missing, failing, or unconfigured audit
sink is logged and never changes the authentication decision that triggered
the event. Callers emit a denial's event before raising the denial, so an
audit failure can neither admit a refused request nor refuse an admitted one.

Events never carry a password, token, or submitted email. A request that names
an account no one holds is attributed to an ``ANONYMOUS`` actor whose
``actor_id`` is a keyed pseudonym of the normalized identifier: stable enough
to correlate repeated attempts against one identifier, not reversible by a
sink reader without the server's ``USER_AUTH_SECRET``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import uuid
from collections.abc import Coroutine
from enum import StrEnum
from typing import Any

from autosecops.audit.enums import AuditEventActor, AuditEventStatus
from autosecops.audit.service import AuditService
from autosecops.audit.types import (
    AuditAction,
    AuditActor,
    AuditMetadata,
    AuditResourceType,
    AuditSink,
)
from autosecops.auth.secrets import get_user_auth_secret
from autosecops.auth.types import PlatformRole, Role
from autosecops.contexts import ctx_role
from autosecops.identifiers import OrganizationID
from autosecops.logger import logger

ANONYMOUS_ACTOR_ID = uuid.UUID(int=0)
"""Actor id of an anonymous event whose request named no account."""

_PSEUDONYM_CONTEXT = b"autosecops:auth-audit:anonymous-actor:v1\x00"


class AuthAuditFailureReason(StrEnum):
    """Why an authentication attempt was refused (``data.failure_reason``)."""

    INVALID_CREDENTIALS = "invalid_credentials"
    """The account exists but the password did not match."""
    UNKNOWN_ACCOUNT = "unknown_account"
    """No account holds the submitted email."""
    INACTIVE_ACCOUNT = "inactive_account"
    """The credentials matched a deactivated account."""
    AUTH_POLICY = "auth_policy"
    """Platform or organization policy forbids this sign-in method."""
    IP_NOT_ALLOWED = "ip_not_allowed"
    """No organization IP allowlist admits the client address."""
    RATE_LIMITED = "rate_limited"
    """The client exceeded an authentication rate limit."""
    EXPIRED = "expired"
    """The credential is past its expiry time."""
    INVALID_TOKEN = "invalid_token"
    """A one-time token, such as a password reset token, was invalid or used."""
    MFA_FAILED = "mfa_failed"
    """The password step passed but the security key or recovery code did not."""


class CredentialOperation(StrEnum):
    """Which credential change a ``user`` event records (``data.operation``)."""

    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET = "password_reset"
    PASSWORD_CHANGE = "password_change"
    """The account holder changed their own password."""
    ADMIN_PASSWORD_SET = "admin_password_set"
    """A platform administrator set another account's password."""


# Strong references to in-flight audit tasks; done callbacks release them.
_pending_audit_tasks: set[asyncio.Task[None]] = set()


def spawn_auth_audit_task(coro: Coroutine[Any, Any, None]) -> None:
    """Run an audit writer off the request path.

    For refusals whose audit work would otherwise make the response time
    depend on the refusal reason. The task inherits the request's context,
    so the client IP and user agent still reach the event.

    Args:
        coro: A best-effort writer from this module; it must not raise.
    """
    task = asyncio.get_running_loop().create_task(coro)
    _pending_audit_tasks.add(task)
    task.add_done_callback(_pending_audit_tasks.discard)


async def drain_auth_audit_tasks() -> None:
    """Wait for every in-flight background audit task (tests and shutdown)."""
    while _pending_audit_tasks:
        await asyncio.gather(*_pending_audit_tasks, return_exceptions=True)


def anonymous_actor_id(identifier: str | None) -> uuid.UUID:
    """Derive the keyed pseudonym an anonymous event is attributed to.

    Args:
        identifier: The account identifier the request named, such as a
            submitted email. It is trimmed and lowercased before hashing.

    Returns:
        A UUID derived from HMAC-SHA256 under ``USER_AUTH_SECRET``, or
        :data:`ANONYMOUS_ACTOR_ID` when no identifier was named or the secret
        is unavailable.
    """
    normalized = identifier.strip().lower() if identifier else ""
    if not normalized:
        return ANONYMOUS_ACTOR_ID
    try:
        key = get_user_auth_secret().encode()
    except ValueError:
        return ANONYMOUS_ACTOR_ID
    digest = hmac.new(
        key, _PSEUDONYM_CONTEXT + normalized.encode(), hashlib.sha256
    ).digest()
    return uuid.UUID(bytes=digest[:16], version=4)


async def _write_role_event(
    role: Role | PlatformRole,
    sink: AuditSink,
    *,
    resource_type: AuditResourceType,
    action: AuditAction,
    status: AuditEventStatus,
    resource_id: uuid.UUID | None,
    data: AuditMetadata | None,
) -> None:
    try:
        async with AuditService.with_session(role=role, audit_sink=sink) as svc:
            await svc.create_event(
                resource_type=resource_type,
                action=action,
                resource_id=resource_id,
                status=status,
                data=data,
                include_actor_label=False,
            )
    except Exception as exc:
        logger.warning(
            "Failed to emit auth audit event",
            resource_type=resource_type,
            action=action,
            status=status.value,
            audit_sink=sink,
            error_type=type(exc).__name__,
        )


async def emit_user_auth_event(
    *,
    user_id: uuid.UUID,
    resource_type: AuditResourceType,
    action: AuditAction,
    status: AuditEventStatus = AuditEventStatus.SUCCESS,
    data: AuditMetadata | None = None,
    organization_id: OrganizationID | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> None:
    """Record an authentication or credential event about a known account.

    Without ``organization_id`` the event reaches the platform sink only.
    With it, the event reaches that organization's sink and the platform
    sink, both carrying the organization's ID. The actor's email is never
    attached; ``actor_id`` is the user's ID.

    Args:
        user_id: The account the event is about, recorded as the resource.
        resource_type: Usually ``auth`` for sign-in events and ``user`` for
            credential changes.
        action: The audited action.
        status: The outcome.
        data: Operational metadata such as ``auth_method``,
            ``failure_reason``, or ``operation``.
        organization_id: The one organization the event is scoped to.
        actor_user_id: The user who acted, when not the account holder, such
            as an administrator setting the password. Defaults to ``user_id``.
    """
    actor_id = actor_user_id or user_id
    if organization_id is None:
        role: Role | PlatformRole = PlatformRole(
            type="user", user_id=actor_id, service_id="autosecops-api"
        )
        sinks: tuple[AuditSink, ...] = ("platform",)
    else:
        role = Role(
            type="user",
            user_id=actor_id,
            organization_id=organization_id,
            service_id="autosecops-api",
        )
        sinks = ("platform", "organization")
    for sink in sinks:
        await _write_role_event(
            role,
            sink,
            resource_type=resource_type,
            action=action,
            status=status,
            resource_id=user_id,
            data=data,
        )


async def emit_anonymous_auth_event(
    *,
    identifier: str | None,
    action: AuditAction,
    data: AuditMetadata | None = None,
) -> None:
    """Record a refused request no known account is attributable to.

    The event reaches the platform sink only, with ``resource_type`` ``auth``
    and status ``FAILURE``.

    Args:
        identifier: The account identifier the request named, if any. Only
            its keyed pseudonym leaves this function.
        action: The audited action, such as ``sign_in`` or ``throttle``.
        data: Operational metadata such as ``failure_reason``.
    """
    actor = AuditActor(
        actor_type=AuditEventActor.ANONYMOUS,
        actor_id=anonymous_actor_id(identifier),
    )
    # An anonymous event has no organization: clear any role the request
    # carries so the service cannot scope the event from it.
    role_token = ctx_role.set(None)
    try:
        async with AuditService.with_session(audit_sink="platform") as svc:
            await svc.create_actor_event(
                actor=actor,
                resource_type="auth",
                action=action,
                status=AuditEventStatus.FAILURE,
                data=data,
            )
    except Exception as exc:
        logger.warning(
            "Failed to emit anonymous auth audit event",
            action=action,
            error_type=type(exc).__name__,
        )
    finally:
        ctx_role.reset(role_token)


async def emit_api_key_rejected_event(
    *,
    organization_id: OrganizationID,
    workspace_id: uuid.UUID | None,
    service_account_id: uuid.UUID,
    api_key_id: uuid.UUID,
    failure_reason: AuthAuditFailureReason,
) -> None:
    """Record a refused service-account API key to its organization's sink.

    Emitted only after the presented secret verified, so a forged key id
    cannot write events against another organization's key.

    Args:
        organization_id: The service account's organization.
        workspace_id: The service account's workspace binding, if any.
        service_account_id: The service account; also the actor.
        api_key_id: The refused key, recorded as the resource.
        failure_reason: Why the key was refused.
    """
    role = Role(
        type="service_account",
        service_id="autosecops-api",
        organization_id=organization_id,
        workspace_id=workspace_id,
        bound_workspace_id=workspace_id,
        service_account_id=service_account_id,
    )
    await _write_role_event(
        role,
        "organization",
        resource_type="service_account_api_key",
        action="sign_in",
        status=AuditEventStatus.FAILURE,
        resource_id=api_key_id,
        data={
            "auth_method": "api_key",
            "failure_reason": failure_reason.value,
            "api_key_id": str(api_key_id),
        },
    )
