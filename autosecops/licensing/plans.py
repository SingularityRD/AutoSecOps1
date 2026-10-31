"""Commercial plan presets: the single source of plan-to-entitlement mapping.

The issuer CLI (``scripts/license_tool.py issue --plan``) expands a plan into
the entitlement keys it signs. Verification never reads this map: a license
grants exactly the keys it lists, whatever its ``plan`` label says.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import timedelta
from types import MappingProxyType

from autosecops.licensing.types import LicenseGrant, LicensePlan
from autosecops.tiers.enums import Entitlement

type PlanGrant = Entitlement | LicenseGrant
"""An organization entitlement or a deployment grant a plan can include."""

FREE_ENTITLEMENTS: frozenset[Entitlement] = frozenset(
    {
        Entitlement.CUSTOM_REGISTRY,
        Entitlement.WORKSPACE_CHAT,
    }
)
"""Entitlements every single-tenant install gets without a license.

Must match the enabled keys of ``autosecops.tiers.defaults.BASELINE_ENTITLEMENTS``;
a unit test enforces it.
"""

TEAM_ENTITLEMENTS: frozenset[PlanGrant] = frozenset(
    {
        Entitlement.CASE_ADDONS,
        Entitlement.AGENT_ADDONS,
        Entitlement.FORMS,
        Entitlement.GIT_SYNC,
        Entitlement.SERVICE_ACCOUNTS,
    }
)

BUSINESS_ENTITLEMENTS: frozenset[PlanGrant] = TEAM_ENTITLEMENTS | {
    Entitlement.RBAC_ADDONS,
    Entitlement.MULTI_WORKSPACE,
    Entitlement.EXTERNAL_SECRET_STORES,
    Entitlement.AGENT_CHANNELS,
    Entitlement.SEMANTIC_SEARCH,
    Entitlement.WATCHTOWER,
}

ENTERPRISE_ENTITLEMENTS: frozenset[PlanGrant] = BUSINESS_ENTITLEMENTS | {
    Entitlement.TUNNELS,
    Entitlement.ROBOT_EDR,
    # Every other entitlement, including ones added after this map was
    # written, so Enterprise always unlocks the whole product.
    *Entitlement,
}

MSSP_ENTITLEMENTS: frozenset[PlanGrant] = ENTERPRISE_ENTITLEMENTS | {
    LicenseGrant.MULTI_TENANT
}

PLAN_ENTITLEMENTS: Mapping[LicensePlan, frozenset[PlanGrant]] = MappingProxyType(
    {
        # Community is the unlicensed free baseline: a license adds nothing.
        LicensePlan.COMMUNITY: frozenset(),
        LicensePlan.TEAM: TEAM_ENTITLEMENTS,
        LicensePlan.BUSINESS: BUSINESS_ENTITLEMENTS,
        LicensePlan.ENTERPRISE: ENTERPRISE_ENTITLEMENTS,
        LicensePlan.MSSP: MSSP_ENTITLEMENTS,
        LicensePlan.PILOT: ENTERPRISE_ENTITLEMENTS,
    }
)
"""Entitlements and deployment grants each plan includes."""

ISSUABLE_PLANS: tuple[LicensePlan, ...] = (
    LicensePlan.TEAM,
    LicensePlan.BUSINESS,
    LicensePlan.ENTERPRISE,
    LicensePlan.MSSP,
    LicensePlan.PILOT,
)
"""Plans the issuer CLI signs; Community needs no license."""

PLAN_ORDER: tuple[LicensePlan, ...] = (
    LicensePlan.COMMUNITY,
    LicensePlan.TEAM,
    LicensePlan.BUSINESS,
    LicensePlan.ENTERPRISE,
    LicensePlan.MSSP,
)
"""Commercial plans from smallest to largest; each includes the previous one.

Pilot is left out: it is a time-boxed trial of Enterprise, not a tier.
"""

PILOT_DURATION = timedelta(days=60)
DEFAULT_PLAN_DURATION = timedelta(days=365)


def plan_entitlements(plan: LicensePlan) -> frozenset[PlanGrant]:
    """Return the entitlements and deployment grants ``plan`` includes."""
    return PLAN_ENTITLEMENTS[plan]


def plan_duration(plan: LicensePlan | None) -> timedelta:
    """Return the default validity period of a license on ``plan``."""
    if plan is LicensePlan.PILOT:
        return PILOT_DURATION
    return DEFAULT_PLAN_DURATION


def minimum_plan(grant: PlanGrant) -> LicensePlan:
    """Return the smallest plan in ``PLAN_ORDER`` that includes ``grant``.

    Free entitlements return ``LicensePlan.COMMUNITY``.
    """
    if grant in FREE_ENTITLEMENTS:
        return LicensePlan.COMMUNITY
    for plan in PLAN_ORDER:
        if grant in PLAN_ENTITLEMENTS[plan]:
            return plan
    raise ValueError(f"No plan includes {grant!r}")


def minimum_plan_for(grants: Iterable[PlanGrant | str]) -> LicensePlan:
    """Return the smallest plan that includes every grant in ``grants``.

    Accepts raw entitlement keys, such as an action's ``required_entitlements``.

    Raises:
        ValueError: If a key is not a known entitlement or deployment grant.
    """
    required = LicensePlan.COMMUNITY
    for raw in grants:
        grant: PlanGrant = Entitlement(raw) if raw in Entitlement else LicenseGrant(raw)
        plan = minimum_plan(grant)
        if PLAN_ORDER.index(plan) > PLAN_ORDER.index(required):
            required = plan
    return required


def plan_label(plan: LicensePlan) -> str:
    """Return the display name of ``plan``, such as ``Business``."""
    return "MSSP" if plan is LicensePlan.MSSP else plan.value.capitalize()
