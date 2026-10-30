from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

import loguru
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.types import Role
from autosecops.dsl.schemas import ROOT_STREAM, RunContext, StreamID

if TYPE_CHECKING:
    from autosecops.secrets.masking import SecretMaskCollector


ctx_secret_masks: ContextVar[SecretMaskCollector | None] = ContextVar(
    "secret-masks", default=None
)
"""Observed secret-derived values, isolated to one executor invocation."""


__all__ = [
    "ctx_run",
    "ctx_role",
    "ctx_logger",
    "ctx_stream_id",
    "ctx_session",
    "ctx_request_audit",
    "ctx_agent_session_id",
    "ctx_executor_provenance",
    "ctx_service_account_api_key_id",
    "ctx_logical_time",
    "get_env",
    "RequestAuditContext",
    "ExecutorProvenance",
]


@dataclass(frozen=True, slots=True)
class RequestAuditContext:
    """Client attribution captured by request middleware for audit events."""

    client_ip: str | None
    user_agent: str | None
    """Normalized client family/version, safe to forward to audit sinks."""
    raw_user_agent: str | None = None
    """Verbatim User-Agent header, bounded in length."""


@dataclass(frozen=True, slots=True)
class ExecutorProvenance:
    """Run identity from a verified executor token, for audit attribution.

    Set only by executor-token authentication. Every value comes from the
    signed token, never from a request body, so an audit event built from it
    names the run that acted.
    """

    workflow_id: str
    """The token's ``wf_id`` claim: the workflow the run belongs to."""
    run_id: str
    """The token's ``wf_exec_id`` claim, which carries the Temporal run id."""
    execution_id: str | None = None
    """The workflow execution id (``wf-...:exec-...``), when the token has it."""
    trigger_type: str | None = None
    """How the execution started (manual, scheduled, webhook, case, form)."""
    execution_origin: str | None = None
    """The trusted entry point: ``workflow`` or ``agent``."""
    root_action: str | None = None
    """The registry action the executor ran."""
    agent_session_id: uuid.UUID | None = None
    """The verified agent session, for an agent's tool call."""


ctx_run: ContextVar[RunContext | None] = ContextVar("run", default=None)
ctx_role: ContextVar[Role | None] = ContextVar("role", default=None)
ctx_logger: ContextVar[loguru.Logger | None] = ContextVar("logger", default=None)
ctx_request_audit: ContextVar[RequestAuditContext | None] = ContextVar(
    "request-audit", default=None
)
ctx_stream_id: ContextVar[StreamID] = ContextVar("stream-id", default=ROOT_STREAM)
ctx_env: ContextVar[dict[str, str] | None] = ContextVar("env", default=None)
ctx_session: ContextVar[AsyncSession | None] = ContextVar("session", default=None)
ctx_session_id: ContextVar[uuid.UUID | None] = ContextVar("session-id", default=None)
"""ID for a streamable session, if any."""

ctx_agent_session_id: ContextVar[uuid.UUID | None] = ContextVar(
    "agent-session-id", default=None
)
"""Verified agent session associated with the current request, if any."""

ctx_executor_provenance: ContextVar[ExecutorProvenance | None] = ContextVar(
    "executor-provenance", default=None
)
"""Run identity of a verified executor token on the current request, if any."""

ctx_service_account_api_key_id: ContextVar[uuid.UUID | None] = ContextVar(
    "service-account-api-key-id", default=None
)
"""The service-account API key that authenticated the current request, if any."""

ctx_logical_time: ContextVar[datetime | None] = ContextVar("logical-time", default=None)
"""Current logical time = time_anchor + elapsed workflow time. Used by FN.now()."""


@asynccontextmanager
async def with_session(session: AsyncSession):
    """Set the session in the context."""
    token = ctx_session.set(session)
    try:
        yield
    finally:
        ctx_session.reset(token)


def get_env() -> dict[str, str]:
    return ctx_env.get() or {}
