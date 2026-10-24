"""Superuser-only license status endpoint."""

from fastapi import APIRouter

from tracecat import config
from tracecat.admin.license.schemas import LicenseRead
from tracecat.auth.credentials import SuperuserRole
from tracecat.licensing.service import get_license_state
from tracecat.tiers.defaults import BASELINE_ENTITLEMENTS
from tracecat.tiers.enums import Entitlement

router = APIRouter(prefix="/license", tags=["admin:license"])


@router.get("", response_model=LicenseRead)
async def get_license(role: SuperuserRole) -> LicenseRead:
    """Get the status of the configured license key."""
    # Status reads must not emit single-tenant entitlement logs in multi-tenant mode.
    state = get_license_state(log=False)
    claims = state.claims
    return LicenseRead(
        status=state.status,
        enforced=not config.TRACECAT__EE_MULTI_TENANT,
        license_id=claims.license_id if claims else None,
        customer=claims.customer if claims else None,
        issued_at=claims.issued_at if claims else None,
        expires_at=claims.expires_at if claims else None,
        grace_ends_at=state.grace_ends_at,
        entitlements=sorted(state.granted),
        included_entitlements=sorted(
            Entitlement(key)
            for key, enabled in BASELINE_ENTITLEMENTS.model_dump().items()
            if enabled
        ),
        licensed_entitlements=list(claims.entitlements) if claims else [],
        error=state.error,
    )
