"""Default limits and entitlements for single-tenant/self-hosted deployments."""

from __future__ import annotations

import os
from importlib.metadata import entry_points

from autosecops import config
from autosecops.agent.backends.constants import AGENT_BACKEND_ENTRY_POINT_GROUP
from autosecops.licensing import keys
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


def has_installed_agent_backend() -> bool:
    """Whether a package registers an agent backend besides the built-in one.

    The built-in backend is not an entry point, so any registration is extra.
    Entry points are read without loading them to keep this import cheap.
    """
    return bool(entry_points(group=AGENT_BACKEND_ENTRY_POINT_GROUP))


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
    robot_edr=False,
    # Installing an agent backend package is how a deployment opts in.
    agent_runtime_preview=has_installed_agent_backend(),
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


def get_single_tenant_limits() -> EffectiveLimits:
    """Resolve execution limits for a single-tenant install.

    Starts from ``DEFAULT_LIMITS`` and applies the concurrency and execution
    limits of a valid (or in-grace) license, so the tier permit machinery
    enforces them. A license value never loosens a stricter default.
    """
    limits = get_license_state(log=False).limits
    defaults = DEFAULT_LIMITS
    return defaults.model_copy(
        update={
            "max_concurrent_workflows": _stricter(
                defaults.max_concurrent_workflows, limits.max_concurrent_workflows
            ),
            "max_concurrent_actions": _stricter(
                defaults.max_concurrent_actions, limits.max_concurrent_actions
            ),
            "max_action_executions_per_workflow": _stricter(
                defaults.max_action_executions_per_workflow,
                limits.max_action_executions_per_workflow,
            ),
        }
    )


def _stricter(default: int | None, licensed: int | None) -> int | None:
    """Return the lower of two optional limits, where ``None`` is unlimited."""
    if default is None:
        return licensed
    if licensed is None:
        return default
    return min(default, licensed)


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
    if keys.is_development_public_key(keys.LICENSE_PUBLIC_KEY_PEM):
        logger.error(
            "This build verifies licenses with the DEVELOPMENT license public"
            " key. Release builds must embed the production key",
            public_key_sha256=keys.DEVELOPMENT_PUBLIC_KEY_SHA256,
        )
    if config.AUTOSECOPS__EE_MULTI_TENANT:
        logger.info(
            "Multi-tenant mode is licensed; entitlements come from database tiers"
        )
        return
    if config.AUTOSECOPS__EE_MULTI_TENANT_REQUESTED:
        logger.error(
            "AUTOSECOPS__EE_MULTI_TENANT=true needs a valid license key that"
            " grants multi_tenant; running single-tenant with license-based"
            " entitlements instead"
        )
    # The first evaluation in a process logs the license state.
    get_license_state()
    warn_on_legacy_entitlement_flags()
