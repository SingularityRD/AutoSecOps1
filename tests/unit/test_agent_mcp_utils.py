from __future__ import annotations

import pytest

from autosecops.agent.mcp.utils import (
    canonical_mcp_tool_name,
    normalize_mcp_tool_name,
)


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        (
            "mcp__autosecops-registry__tools__slack__post_message",
            "tools.slack.post_message",
        ),
        (
            "mcp__autosecops_registry__tools__slack__post_message",
            "tools.slack.post_message",
        ),
        (
            "mcp__autosecops-registry__mcp__Linear__list_issues",
            "mcp.Linear.list_issues",
        ),
        (
            "mcp__autosecops_registry__mcp__Linear__list_issues",
            "mcp.Linear.list_issues",
        ),
    ],
    ids=["canonical", "legacy", "canonical-user-mcp", "legacy-user-mcp"],
)
def test_normalize_mcp_tool_name_registry_prefixes(
    tool_name: str, expected: str
) -> None:
    assert normalize_mcp_tool_name(tool_name) == expected


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("core.http_request", "core.http_request"),
        ("core__http_request", "core.http_request"),
        ("mcp__autosecops-registry__core__http_request", "core.http_request"),
        ("mcp.autosecops_registry.core.http_request", "core.http_request"),
        ("internal__builder__update_preset", "internal.builder.update_preset"),
        ("mcp__Jira__deleteIssue", "mcp__Jira__deleteIssue"),
        ("mcp__autosecops-registry__mcp__Jira__deleteIssue", "mcp__Jira__deleteIssue"),
        ("mcp__example__a__b", "mcp__example__a__b"),
        ("mcp__autosecops-registry__mcp__example__a__b", "mcp__example__a__b"),
    ],
)
def test_canonical_mcp_tool_name_matches_execution_names(
    tool_name: str, expected: str
) -> None:
    assert canonical_mcp_tool_name(tool_name) == expected


@pytest.mark.parametrize(
    "tool_name",
    [
        "mcp.example.a.b",
        "mcp.Jira.deleteIssue",
        "mcp.autosecops-registry.mcp.Jira.deleteIssue",
    ],
)
def test_canonical_mcp_tool_name_rejects_dotted_user_mcp_names(
    tool_name: str,
) -> None:
    with pytest.raises(ValueError, match="Ambiguous user MCP tool name"):
        canonical_mcp_tool_name(tool_name)
