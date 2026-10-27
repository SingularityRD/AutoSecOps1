"""Robot actions always require manual approval, whatever an agent config says."""

from __future__ import annotations

import uuid
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from claude_agent_sdk.types import HookContext, PreToolUseHookInput
from pydantic import ValidationError

from autosecops.agent.approvals.mandatory import (
    MANDATORY_APPROVAL_TOOLS,
    disabled_mandatory_approvals,
    enforce_mandatory_approvals,
    reject_disabled_mandatory_approvals,
)
from autosecops.agent.common.socket_io import SocketStreamWriter
from autosecops.agent.preset.schemas import AgentPresetCreate, AgentPresetUpdate
from autosecops.agent.preset.tool_policy import (
    apply_registry_approval_defaults,
    resolve_tool_policy,
)
from autosecops.agent.preset.types import PresetToolInputs
from autosecops.agent.runtime.claude_code.runtime import ClaudeAgentRuntime
from autosecops.db.models import SkillVersion, SkillVersionTool

REQUEST = "tools.robodr.request_action"
REVERT = "tools.robodr.revert_action"


def _create(tool_approvals: dict[str, bool] | None) -> AgentPresetCreate:
    return AgentPresetCreate(
        name="Robot agent",
        model_name="gpt-4o-mini",
        model_provider="openai",
        actions=[REQUEST, REVERT],
        tool_approvals=tool_approvals,
    )


def test_mandatory_tools_are_the_state_changing_robot_actions() -> None:
    assert MANDATORY_APPROVAL_TOOLS == {REQUEST, REVERT}


@pytest.mark.parametrize("tool", [REQUEST, REVERT])
def test_create_rejects_disabled_robot_action_approval(tool: str) -> None:
    with pytest.raises(ValidationError, match="cannot be disabled"):
        _create({tool: False})


@pytest.mark.parametrize("tool", [REQUEST, REVERT])
def test_update_rejects_disabled_robot_action_approval(tool: str) -> None:
    with pytest.raises(ValidationError, match="cannot be disabled"):
        AgentPresetUpdate(tool_approvals={"core.cases.get_case": False, tool: False})


def test_required_or_omitted_robot_action_approval_is_accepted() -> None:
    assert _create({REQUEST: True, REVERT: True}).tool_approvals == {
        REQUEST: True,
        REVERT: True,
    }
    assert _create(None).tool_approvals is None
    # Other tools keep their own rules.
    assert AgentPresetUpdate(
        tool_approvals={"core.http_request": False}
    ).tool_approvals == {"core.http_request": False}


def test_validator_helpers() -> None:
    assert disabled_mandatory_approvals({REQUEST: False, "x.y": False}) == [REQUEST]
    assert disabled_mandatory_approvals(None) == []
    with pytest.raises(ValueError, match=REVERT):
        reject_disabled_mandatory_approvals({REVERT: False})


def _inputs(
    actions: list[str],
    approvals: dict[str, bool],
    skill_version_ids: list[uuid.UUID] | None = None,
    namespaces: list[str] | None = None,
) -> PresetToolInputs:
    return PresetToolInputs(
        uuid.uuid4(),
        actions,
        namespaces or [],
        [],
        approvals,
        skill_version_ids or [],
    )


def test_policy_forces_approval_even_when_stored_rule_disables_it() -> None:
    """A preset saved before the guard, or a restored version, still pauses."""
    policy = resolve_tool_policy(
        _inputs([REQUEST, REVERT, "core.cases.get_case"], {REQUEST: False}), {}, {}
    )
    assert policy.tool_approvals[REQUEST] is True
    assert policy.tool_approvals[REVERT] is True
    assert "core.cases.get_case" not in policy.tool_approvals
    # Registry defaults use setdefault and cannot undo the floor.
    applied = apply_registry_approval_defaults(policy, set())
    assert applied.tool_approvals[REQUEST] is True


def test_policy_forces_approval_for_skill_granted_robot_action() -> None:
    version_id = uuid.uuid4()
    version = SkillVersion(id=version_id, skill_id=uuid.uuid4(), name="robots")
    version.tools = [SkillVersionTool(tool_id=REQUEST)]
    version.mcp_tools = []
    policy = resolve_tool_policy(
        _inputs([], {REQUEST: False}, [version_id]), {version_id: version}, {}
    )
    assert policy.actions == (REQUEST,)
    assert policy.tool_approvals == {REQUEST: True}


def test_policy_does_not_grant_ungranted_robot_actions() -> None:
    policy = resolve_tool_policy(_inputs(["core.cases.get_case"], {}), {}, {})
    assert policy.tool_approvals == {}
    blocked = resolve_tool_policy(_inputs([REQUEST], {}, namespaces=["core"]), {}, {})
    assert blocked.actions == ()
    assert enforce_mandatory_approvals({}, blocked.actions) == {}


def _hook_input(tool_name: str, *, agent_type: str | None = None) -> Any:
    hook_input: dict[str, Any] = {
        "session_id": "test-session-id",
        "transcript_path": "/tmp/test-transcript.jsonl",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {},
        "tool_use_id": "call-1",
    }
    if agent_type is not None:
        hook_input["agent_id"] = "agent-1"
        hook_input["agent_type"] = agent_type
    return cast(PreToolUseHookInput, hook_input)


@pytest.fixture
def runtime() -> ClaudeAgentRuntime:
    writer = MagicMock(spec=SocketStreamWriter)
    writer.send_stream_event = AsyncMock()
    rt = ClaudeAgentRuntime(writer, transport_factory=lambda _: MagicMock())
    rt.client = MagicMock()
    rt.client.interrupt = AsyncMock()
    return rt


@pytest.mark.parametrize(
    "tool_approvals",
    [None, {}, {REQUEST: False, REVERT: False}],
    ids=["no-config", "empty", "disabled"],
)
@pytest.mark.parametrize(
    "tool_name",
    [
        "mcp__autosecops-registry__tools__robodr__request_action",
        "mcp__autosecops-registry__tools__robodr__revert_action",
        "mcp.autosecops-registry.tools.robodr.request_action",
    ],
)
def test_runtime_requires_approval_for_robot_actions(
    runtime: ClaudeAgentRuntime,
    tool_approvals: dict[str, bool] | None,
    tool_name: str,
) -> None:
    """Ad hoc ``ai.agent`` runs carry their own tool_approvals; the hook floors them."""
    runtime.tool_approvals = tool_approvals
    assert runtime._tool_call_requires_approval(_hook_input(tool_name), tool_name)


def test_runtime_leaves_other_tools_to_their_rules(
    runtime: ClaudeAgentRuntime,
) -> None:
    tool_name = "mcp__autosecops-registry__tools__robodr__get_robot"
    runtime.tool_approvals = None
    assert not runtime._tool_call_requires_approval(_hook_input(tool_name), tool_name)
    runtime.tool_approvals = {"tools.robodr.get_robot": True}
    assert runtime._tool_call_requires_approval(_hook_input(tool_name), tool_name)


@pytest.mark.anyio
async def test_hook_denies_and_requests_approval_for_disabled_robot_action(
    runtime: ClaudeAgentRuntime,
) -> None:
    """Negative test: the agent cannot send a robot action without approval."""
    interrupt = AsyncMock()
    runtime.client = MagicMock(interrupt=interrupt)
    runtime.tool_approvals = {REQUEST: False}
    result = await runtime._pre_tool_use_hook(
        input_data=_hook_input(
            "mcp__autosecops-registry__tools__robodr__request_action"
        ),
        tool_use_id="call-1",
        context=HookContext(signal=None),
    )
    output = cast(dict[str, Any], result.get("hookSpecificOutput", {}))
    assert output["permissionDecision"] == "deny"
    assert "requires approval" in output["permissionDecisionReason"]
    interrupt.assert_awaited()


def test_runtime_requires_approval_inside_explicit_subagents(
    runtime: ClaudeAgentRuntime,
) -> None:
    """Subagent tool calls skip root approvals, but never for robot actions."""
    runtime._explicit_subagent_aliases = {"helper"}
    runtime.tool_approvals = None
    robot = "mcp__autosecops-registry__tools__robodr__request_action"
    other = "mcp__autosecops-registry__core__http_request"
    assert runtime._tool_call_requires_approval(
        _hook_input(robot, agent_type="helper"), robot
    )
    assert not runtime._tool_call_requires_approval(
        _hook_input(other, agent_type="helper"), other
    )
