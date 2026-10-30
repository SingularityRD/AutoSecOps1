"""Shared entitlement access helpers."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from autosecops import config
from autosecops.db.engine import SupportsExecute
from autosecops.db.models import OrganizationTier, Tier
from autosecops.exceptions import EntitlementRequired
from autosecops.identifiers import OrganizationID
from autosecops.licensing.service import ensure_license_deployment_loaded
from autosecops.tiers import defaults as tier_defaults
from autosecops.tiers.enums import Entitlement
from autosecops.tiers.exceptions import DefaultTierNotConfiguredError


async def get_org_tier_and_resolved_tier(
    session: SupportsExecute,
    org_id: OrganizationID,
) -> tuple[OrganizationTier | None, Tier]:
    """Resolve the org tier row (if any) and the effective base tier.

    If an org has an assigned tier, that tier is returned.
    Otherwise, the active default tier is returned.

    Raises:
        DefaultTierNotConfiguredError: If no effective tier can be resolved.
    """
    org_tier_stmt = (
        select(OrganizationTier)
        .options(selectinload(OrganizationTier.tier))
        .where(OrganizationTier.organization_id == org_id)
    )
    org_tier_result = await session.execute(org_tier_stmt)
    org_tier = org_tier_result.scalar_one_or_none()

    if org_tier is not None and org_tier.tier is not None:
        return org_tier, org_tier.tier

    default_tier_stmt = select(Tier).where(
        Tier.is_default.is_(True), Tier.is_active.is_(True)
    )
    default_tier_result = await session.execute(default_tier_stmt)
    default_tier = default_tier_result.scalar_one_or_none()
    if default_tier is None:
        raise DefaultTierNotConfiguredError
    return org_tier, default_tier


async def is_org_entitled(
    session: SupportsExecute,
    org_id: OrganizationID,
    entitlement: Entitlement,
) -> bool:
    """Check if an organization has a specific entitlement."""
    if not config.AUTOSECOPS__EE_MULTI_TENANT:
        await ensure_license_deployment_loaded()
        # Single-tenant mode: free baseline plus signed-license entitlements
        # instead of DB tiers. getattr maps the enum value to its schema field.
        return bool(
            getattr(
                tier_defaults.get_single_tenant_entitlements(),
                entitlement.value,
                False,
            )
        )

    org_tier, tier = await get_org_tier_and_resolved_tier(session, org_id)

    overrides = org_tier.entitlement_overrides or {} if org_tier is not None else {}
    override = overrides.get(entitlement.value)
    if override is not None:
        return bool(override)
    tier_entitlements = tier.entitlements or {}
    return bool(tier_entitlements.get(entitlement.value, False))


async def require_org_entitlement(
    session: AsyncSession,
    org_id: OrganizationID,
    entitlement: Entitlement,
) -> None:
    """Require a specific organization entitlement."""
    if not await is_org_entitled(session, org_id, entitlement):
        raise EntitlementRequired(entitlement.value)
