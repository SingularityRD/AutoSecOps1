from __future__ import annotations

import pytest

from autosecops import config
from autosecops.agent.channels.service import AgentChannelService
from autosecops.exceptions import AutoSecOpsValidationError


def test_slack_approval_action_token_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__SIGNING_SECRET", "test-signing-secret")
    token = AgentChannelService.create_slack_approval_action_token(
        batch_id="batch-123",
        tool_call_id="tool-123",
        action="approve",
    )

    parsed = AgentChannelService.parse_slack_approval_action_token(token)

    assert parsed == {
        "batch_id": "batch-123",
        "tool_call_id": "tool-123",
        "action": "approve",
    }


def test_slack_approval_action_token_rejects_tamper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__SIGNING_SECRET", "test-signing-secret")
    token = AgentChannelService.create_slack_approval_action_token(
        batch_id="batch-123",
        tool_call_id="tool-123",
        action="deny",
    )
    bad_token = token[:-1] + ("a" if token[-1] != "a" else "b")

    with pytest.raises(AutoSecOpsValidationError):
        AgentChannelService.parse_slack_approval_action_token(bad_token)
