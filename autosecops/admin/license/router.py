"""Superuser-only license status endpoint."""

from fastapi import APIRouter

from autosecops import config
from autosecops.admin.license.schemas import LicenseRead
from autosecops.auth.credentials import SuperuserRole
from autosecops.db.dependencies import AsyncDBSessionBypass
from autosecops.licensing.clock import (
    effective_now,
    ensure_license_clock_fresh,
    get_license_clock_status,
)
from autosecops.licensing.deployment import ensure_deployment_id
from autosecops.licensing.enforcement import (
    count_active_users,
    count_organizations,
    count_workspaces,
)
from autosecops.licensing.multi_tenant import get_multi_tenant_mode
from autosecops.licensing.schemas import LicenseUsageRead
from autosecops.licensing.service import (
    get_license_state,
    license_days_remaining,
    license_notice_level,
)
from autosecops.tiers.defaults import BASELINE_ENTITLEMENTS
from autosecops.tiers.enums import Entitlement

router = APIRouter(prefix="/license", tags=["admin:license"])


@router.get("", response_model=LicenseRead)
async def get_license(
    role: SuperuserRole, session: AsyncDBSessionBypass
) -> LicenseRead:
    """Get the status, limits, usage, and deployment ID of this installation."""
    # Readable without a license, so a customer can request a bound key.
    deployment_id = await ensure_deployment_id()
    await ensure_license_clock_fresh()
    now = effective_now()
    # Status reads must not emit single-tenant entitlement logs in multi-tenant mode.
    state = get_license_state(now, log=False)
    clock = get_license_clock_status()
    rollback = clock.rollback
    claims = state.claims
    return LicenseRead(
        status=state.status,
        enforced=not config.AUTOSECOPS__EE_MULTI_TENANT,
        license_id=claims.license_id if claims else None,
        customer=claims.customer if claims else None,
        plan=claims.plan if claims else None,
        issued_at=claims.issued_at if claims else None,
        expires_at=claims.expires_at if claims else None,
        grace_ends_at=state.grace_ends_at,
        days_remaining=license_days_remaining(state, now),
        notice=license_notice_level(state, now),
        entitlements=sorted(state.granted),
        grants=sorted(state.grants),
        included_entitlements=sorted(
            Entitlement(key)
            for key, enabled in BASELINE_ENTITLEMENTS.model_dump().items()
            if enabled
        ),
        licensed_entitlements=list(claims.entitlements) if claims else [],
        limits=state.limits,
        licensed_limits=claims.limits if claims else None,
        usage=LicenseUsageRead(
            users=await count_active_users(session),
            workspaces=await count_workspaces(session),
            organizations=await count_organizations(session),
        ),
        deployment_id=deployment_id,
        license_deployment_id=claims.deployment_id if claims else None,
        error=state.error,
        multi_tenant_requested=config.AUTOSECOPS__EE_MULTI_TENANT_REQUESTED,
        multi_tenant_mode=get_multi_tenant_mode(),
        clock_high_water=clock.high_water,
        clock_rollback_detected_at=rollback.observed_at if rollback else None,
        clock_rollback_seconds=int(rollback.behind.total_seconds())
        if rollback
        else None,
    )
