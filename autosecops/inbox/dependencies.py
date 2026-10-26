"""Inbox provider dependencies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from autosecops.inbox.providers.agent_runs import AgentRunsInboxProvider

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from autosecops.auth.types import Role
    from autosecops.inbox.types import InboxProvider


def get_inbox_provider(
    session: AsyncSession,
    role: Role,
) -> InboxProvider | None:
    """Get the inbox provider, sourced from agent runs."""
    return AgentRunsInboxProvider(session, role)
