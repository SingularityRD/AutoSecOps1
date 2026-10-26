"""Default limits and entitlements for single-tenant/self-hosted deployments."""

from __future__ import annotations

import os

from autosecops import config
from autosecops.licensing.service import get_license_state
from autosecops.logger import logger
from autosecops.tiers.enums import Entitlement
from autosecops.tiers.schemas import EffectiveEntitlements, EffectiveLimits

DEFAULT_TIER_DISPLAY_NAME = "Default"

# Default limits for self-hosted deployments (None = unlimited)
DEFAULT_LIMITS = EffectiveLimits(
    api_rate_limit=None,
    api_burst_capacity=None,
    max_concurrent_workflows=None,
    max_action_executions_per_workflow=None,
    max_concurrent_actions=None,
)

BASELINE_ENTITLEMENTS = EffectiveEntitlements(
    custom_registry=True,
    git_sync=False,
    agent_addons=False,
    case_addons=False,
    rbac_addons=False,
    service_accounts=False,
    workspace_chat=True,
    multi_workspace=False,
    watchtower=False,
    external_secret_stores=False,
    agent_channels=False,
    semantic_search=False,
    forms=False,
    tunnels=False,
)
"""Free entitlements every single-tenant install gets without a license.

Multi-workspace is off: existing workspaces remain accessible; the entitlement
only gates creation beyond the first workspace.
"""

DEFAULT_ENTITLEMENTS = BASELINE_ENTITLEMENTS.model_copy()
"""Single-tenant baseline that a license extends.

Tests patch this attribute to simulate a different baseline; production code
reads entitlements through ``get_single_tenant_entitlements()``.
"""

# Legacy AUTOSECOPS__FEATURE_FLAGS tokens that used to grant paid entitlements on
# single-tenant installs. They no longer do; they only trigger an upgrade warning.
_LEGACY_ENTITLEMENT_FLAGS: dict[str, Entitlement] = {
    "git-sync": Entitlement.GIT_SYNC,
    "agent-approvals": Entitlement.AGENT_ADDONS,
    "agent-presets": Entitlement.AGENT_ADDONS,
    "case-dropdowns": Entitlement.CASE_ADDONS,
    "case-durations": Entitlement.CASE_ADDONS,
    "case-tasks": Entitlement.CASE_ADDONS,
    "case-triggers": Entitlement.CASE_ADDONS,
    "rbac": Entitlement.RBAC_ADDONS,
    "agent-channels": Entitlement.AGENT_CHANNELS,
    "forms": Entitlement.FORMS,
}


def get_single_tenant_entitlements() -> EffectiveEntitlements:
    """Resolve entitlements for a single-tenant install.

    The result is the free baseline plus whatever a valid (or in-grace) signed
    license grants. ``AUTOSECOPS__FEATURE_FLAGS`` never grants entitlements.
    """
    baseline = DEFAULT_ENTITLEMENTS
    granted = get_license_state().granted
    if not granted:
        return baseline.model_copy()
    return baseline.model_copy(update=dict.fromkeys((e.value for e in granted), True))


def _parse_feature_flags(feature_flags_env: str) -> set[str]:
    return {
        raw_flag.strip().lower().replace("_", "-")
        for raw_flag in feature_flags_env.split(",")
        if raw_flag.strip()
    }


def legacy_flag_entitlements(feature_flags_env: str | None) -> set[Entitlement]:
    """Return the entitlements that legacy feature flags used to grant."""
    if not feature_flags_env:
        return set()
    flags = _parse_feature_flags(feature_flags_env)
    return {
        entitlement
        for flag, entitlement in _LEGACY_ENTITLEMENT_FLAGS.items()
        if flag in flags
    }


def warn_on_legacy_entitlement_flags() -> None:
    """Warn when feature flags ask for paid entitlements a license does not grant.

    Before signed licenses, single-tenant installs mapped flags such as
    ``git-sync`` to paid entitlements. Upgraded installs that still set them
    see this warning instead of silently losing access.
    """
    requested = legacy_flag_entitlements(os.environ.get("AUTOSECOPS__FEATURE_FLAGS"))
    missing = requested - get_license_state().granted
    if not missing:
        return
    logger.warning(
        "AUTOSECOPS__FEATURE_FLAGS no longer grants paid entitlements; install a"
        " license key with AUTOSECOPS__LICENSE_KEY to enable them",
        entitlements=sorted(e.value for e in missing),
    )


def log_license_startup() -> None:
    """Log license status and legacy-flag warnings once at API startup."""
    if config.AUTOSECOPS__EE_MULTI_TENANT:
        if config.AUTOSECOPS__LICENSE_KEY:
            logger.info(
                "AUTOSECOPS__LICENSE_KEY is ignored in multi-tenant mode;"
                " entitlements come from database tiers"
            )
        return
    # The first evaluation in a process logs the license state.
    get_license_state()
    warn_on_legacy_entitlement_flags()
