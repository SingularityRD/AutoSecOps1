"""Fail-safe handling of multi-tenant mode when its license changes.

Config decides ``AUTOSECOPS__EE_MULTI_TENANT`` once per process, at import
time, before the database is reachable. Two situations used to silently
collapse a multi-tenant deployment to single-tenant mode on the next restart,
cutting every organization but the default one off from SSO and organization
selection:

1. The license that grants ``multi_tenant`` expires past its grace period.
   The deployment now keeps running multi-tenant in ``MultiTenantMode.LAPSED``:
   existing tenants keep working with the tiers platform admins assigned, so a
   paying MSSP's customers are never cut off and tenant isolation never
   depends on a fallback path, while creating organizations is blocked and
   platform admins are warned in logs and in the license status API until a
   renewed license is installed.
2. The license no longer lists ``multi_tenant`` at all (removed, replaced by a
   single-tenant license, or failing verification). Nothing proves the
   deployment was licensed for its tenants, and single-tenant mode cannot
   serve them, so ``check_multi_tenant_license_on_startup`` refuses to start
   the API with an explicit error when the database holds more than one
   organization. The fix is to restore the multi-tenant license key.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress

from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.exceptions import MultiTenantLicenseLapsed
from autosecops.licensing.clock import CLOCK_PERSIST_INTERVAL, refresh_license_clock
from autosecops.licensing.enforcement import count_organizations
from autosecops.licensing.service import LICENSE_CONTACT, get_license_state
from autosecops.licensing.types import LicenseGrant, MultiTenantMode
from autosecops.logger import logger


class MultiTenantLicenseRequiredError(RuntimeError):
    """Multi-tenant mode is requested and in use but no license permits it."""


def get_multi_tenant_mode() -> MultiTenantMode:
    """Return whether this process runs multi-tenant, and under what license.

    Callers that may run before the deployment ID is cached must load it first
    (``ensure_license_deployment_loaded``), or a bound license reads as lapsed.
    """
    if not config.AUTOSECOPS__EE_MULTI_TENANT:
        return MultiTenantMode.OFF
    if LicenseGrant.MULTI_TENANT in get_license_state(log=False).grants:
        return MultiTenantMode.ACTIVE
    return MultiTenantMode.LAPSED


def ensure_new_organizations_allowed() -> None:
    """Block organization creation while the multi-tenant license is lapsed.

    Raises:
        MultiTenantLicenseLapsed: If the deployment runs in
            ``MultiTenantMode.LAPSED``.
    """
    if get_multi_tenant_mode() is MultiTenantMode.LAPSED:
        raise MultiTenantLicenseLapsed(contact=LICENSE_CONTACT)


def log_multi_tenant_lapsed() -> None:
    """Log the degraded multi-tenant state as an error for operators."""
    logger.error(
        "MULTI-TENANT LICENSE LAPSED: the license that grants multi_tenant"
        " expired and its grace period ended. Existing organizations keep"
        " working, but creating organizations is blocked. Renew the license"
        f" via {LICENSE_CONTACT}",
    )


async def check_multi_tenant_license_on_startup(session: AsyncSession) -> None:
    """Refuse to strand tenants when multi-tenant mode loses its license.

    Call once at API startup, after the deployment ID is loaded.

    Raises:
        MultiTenantLicenseRequiredError: If ``AUTOSECOPS__EE_MULTI_TENANT=true``
            is set, the license does not permit multi-tenant mode, and the
            database already holds more than one organization.
    """
    match get_multi_tenant_mode():
        case MultiTenantMode.ACTIVE:
            return
        case MultiTenantMode.LAPSED:
            log_multi_tenant_lapsed()
            return
        case MultiTenantMode.OFF:
            pass
    if not config.AUTOSECOPS__EE_MULTI_TENANT_REQUESTED:
        return
    organizations = await count_organizations(session)
    if organizations <= 1:
        return
    raise MultiTenantLicenseRequiredError(
        "AUTOSECOPS__EE_MULTI_TENANT=true is set and the database holds"
        f" {organizations} organizations, but AUTOSECOPS__LICENSE_KEY does not"
        " hold a verified license that grants multi_tenant. Refusing to start"
        " in single-tenant mode, which would cut every organization but the"
        " default one off from sign-in. Restore the multi-tenant license key on"
        f" every service, or contact {LICENSE_CONTACT}"
    )


async def run_license_monitor(stop_event: asyncio.Event) -> None:
    """Refresh the license clock and re-check the license once an hour.

    Runs in every API process until ``stop_event`` is set. Each pass persists
    the clock high-water mark, re-evaluates the license (which, single-tenant,
    logs grace, expired, and invalid states at most hourly), and logs an error while
    multi-tenant mode runs on a lapsed license, so a long-running deployment
    surfaces a lapse without waiting for a restart.
    """
    while not stop_event.is_set():
        try:
            await refresh_license_clock()
            # In multi-tenant mode tenants keep their tier entitlements, so the
            # single-tenant "paid entitlements are disabled" log would be false.
            get_license_state(log=not config.AUTOSECOPS__EE_MULTI_TENANT)
            if get_multi_tenant_mode() is MultiTenantMode.LAPSED:
                log_multi_tenant_lapsed()
        except Exception as exc:
            logger.error("License monitor pass failed", error_type=type(exc).__name__)
        with suppress(TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), CLOCK_PERSIST_INTERVAL.total_seconds()
            )
