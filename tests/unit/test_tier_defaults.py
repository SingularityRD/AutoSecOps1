"""Tests for single-tenant default entitlement resolution.

Legacy ``AUTOSECOPS__FEATURE_FLAGS`` tokens used to map to paid entitlements on
single-tenant installs. Paid entitlements now come only from a signed license
(see ``tests/unit/test_licensing.py``); these tests pin the free baseline and
confirm the legacy flags no longer change it.
"""

from importlib.metadata import EntryPoint

import pytest

from autosecops import config
from autosecops.agent.backends.constants import AGENT_BACKEND_ENTRY_POINT_GROUP
from autosecops.tiers import defaults as tier_defaults
from autosecops.tiers.defaults import has_installed_agent_backend

_FALSE_BY_DEFAULT = {
    "git_sync": False,
    "agent_addons": False,
    "case_addons": False,
    "rbac_addons": False,
    "service_accounts": False,
    "multi_workspace": False,
    "watchtower": False,
    "external_secret_stores": False,
    "agent_channels": False,
    "semantic_search": False,
    "forms": False,
    "tunnels": False,
    "robot_edr": False,
    "agent_runtime_preview": False,
}


def test_baseline_entitlements_match_fresh_install_defaults() -> None:
    expected = {**_FALSE_BY_DEFAULT, "custom_registry": True, "workspace_chat": True}

    assert tier_defaults.BASELINE_ENTITLEMENTS.model_dump() == expected


@pytest.mark.parametrize(
    "flags",
    [
        pytest.param(None, id="fresh_install"),
        pytest.param(
            "git-sync,agent-approvals,case-durations", id="legacy_feature_flags"
        ),
        pytest.param("AGENT_CHANNELS", id="legacy_agent_channels_flag"),
        pytest.param("git-sync, forms", id="forms_flag"),
        pytest.param(
            " GIT_SYNC , unknown-flag , CASE_TRIGGERS ",
            id="normalizes_and_ignores_unknown",
        ),
    ],
)
def test_legacy_feature_flags_do_not_grant_entitlements(
    monkeypatch: pytest.MonkeyPatch, flags: str | None
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", None)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(),
    )
    if flags is None:
        monkeypatch.delenv("AUTOSECOPS__FEATURE_FLAGS", raising=False)
    else:
        monkeypatch.setenv("AUTOSECOPS__FEATURE_FLAGS", flags)

    entitlements = tier_defaults.get_single_tenant_entitlements()

    assert entitlements == tier_defaults.BASELINE_ENTITLEMENTS


def test_has_installed_agent_backend_reads_entry_point_group(monkeypatch) -> None:
    groups: list[str] = []

    def fake_entry_points(*, group: str) -> list[EntryPoint]:
        groups.append(group)
        return [EntryPoint(name="extra", value="pkg:factory", group=group)]

    monkeypatch.setattr(tier_defaults, "entry_points", fake_entry_points)

    assert has_installed_agent_backend() is True
    assert groups == [AGENT_BACKEND_ENTRY_POINT_GROUP]

    monkeypatch.setattr(tier_defaults, "entry_points", lambda *, group: [])

    assert has_installed_agent_backend() is False
