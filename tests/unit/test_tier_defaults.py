"""Tests for single-tenant default entitlement resolution.

Legacy ``TRACECAT__FEATURE_FLAGS`` tokens used to map to paid entitlements on
single-tenant installs. Paid entitlements now come only from a signed license
(see ``tests/unit/test_licensing.py``); these tests pin the free baseline and
confirm the legacy flags no longer change it.
"""

import pytest

from autosecops import config
from autosecops.tiers import defaults as tier_defaults

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
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", False)
    monkeypatch.setattr(config, "TRACECAT__LICENSE_KEY", None)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(),
    )
    if flags is None:
        monkeypatch.delenv("TRACECAT__FEATURE_FLAGS", raising=False)
    else:
        monkeypatch.setenv("TRACECAT__FEATURE_FLAGS", flags)

    entitlements = tier_defaults.get_single_tenant_entitlements()

    assert entitlements == tier_defaults.BASELINE_ENTITLEMENTS
