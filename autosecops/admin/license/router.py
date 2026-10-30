"""Superuser-only license status endpoint."""

from datetime import UTC, datetime

from fastapi import APIRouter

from autosecops import config
from autosecops.admin.license.schemas import LicenseRead
from autosecops.auth.credentials import SuperuserRole
from autosecops.db.dependencies import AsyncDBSessionBypass
from autosecops.licensing.deployment import ensure_deployment_id
from autosecops.licensing.enforcement import (
    count_active_users,
    count_organizations,
    count_workspaces,
)
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
    # Status reads must not emit single-tenant entitlement logs in multi-tenant mode.
    state = get_license_state(log=False)
    now = datetime.now(UTC)
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
    )
