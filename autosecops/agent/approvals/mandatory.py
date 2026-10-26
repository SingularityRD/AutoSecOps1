"""Tools whose manual approval no preset, skill, or run config can turn off.

A robot action changes the state of a physical machine near people, so an
agent must always pause for a human before calling one. Three layers enforce
this, each sufficient on its own for the path it covers:

* Save time: preset write schemas reject ``tool_approvals`` that set one of
  these tools to ``False`` (``reject_disabled_mandatory_approvals``).
* Policy: ``resolve_tool_policy`` forces ``True`` for every granted mandatory
  tool, which covers stored presets, restored versions, and skill grants
  (``enforce_mandatory_approvals``).
* Runtime: the agent runtime's approval hook requires approval for these
  tools even when the run config omits or disables it, which covers ad hoc
  ``ai.agent`` runs (``requires_mandatory_approval``).

The registry actions additionally refuse to sign a robot request without
platform sign-off form submissions; these layers do not rely on that.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Final

MANDATORY_APPROVAL_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "tools.robodr.request_action",
        "tools.robodr.revert_action",
    }
)
"""Registry actions that always require manual approval in an agent."""


def requires_mandatory_approval(action_name: str) -> bool:
    """Return whether an action must always pause for manual approval.

    Args:
        action_name: Canonical dotted action name, such as
            ``tools.robodr.request_action``.
    """
    return action_name in MANDATORY_APPROVAL_TOOLS


def disabled_mandatory_approvals(
    tool_approvals: Mapping[str, bool] | None,
) -> list[str]:
    """Return the mandatory tools a ``tool_approvals`` map tries to auto-run."""
    return sorted(
        tool
        for tool, required in (tool_approvals or {}).items()
        if requires_mandatory_approval(tool) and required is not True
    )


def reject_disabled_mandatory_approvals(
    tool_approvals: dict[str, bool] | None,
) -> dict[str, bool] | None:
    """Pydantic validator: refuse to save a disabled mandatory approval.

    Raises:
        ValueError: If any mandatory tool is mapped to ``False``.
    """
    if disabled := disabled_mandatory_approvals(tool_approvals):
        raise ValueError(
            "Manual approval cannot be disabled for robot actions: "
            f"{', '.join(disabled)}. Set them to true or remove them."
        )
    return tool_approvals


def enforce_mandatory_approvals(
    tool_approvals: Mapping[str, bool], granted_actions: Iterable[str]
) -> dict[str, bool]:
    """Return approvals with every granted mandatory tool forced to ``True``."""
    approvals = dict(tool_approvals)
    for action in granted_actions:
        if requires_mandatory_approval(action):
            approvals[action] = True
    return approvals
