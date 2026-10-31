"""Fail-safe handling of multi-tenant mode when its license changes.

Config decides ``AUTOSECOPS__EE_MULTI_TENANT`` once per process, at import
time, before the database is reachable. Two situations used to silently
collapse a multi-tenant deployment to single-tenant mode on the next restart,
cutting every organization but the default one off from SSO and organization
selection:

1. The license that grants ``multi_tenant`` expires past its grace period.
   The deployment keeps running multi-tenant in ``MultiTenantMode.LAPSED`` for
   ``MULTI_TENANT_LAPSE_LIMIT``, so a paying MSSP's customers are not cut off
   overnight and tenant isolation never depends on a fallback path. Lapsed
   mode is commercially bounded:

   - It is allowed only on a deployment that ran multi-tenant under the same
     license while it was valid. While ``ACTIVE``, the API records that in
     ``platform_settings`` (key ``multi_tenant_license_activity``), with an
     HMAC so a plain database edit cannot forge it. An expired key on a fresh
     or never-active deployment makes the API refuse to start.
   - Existing organizations keep the tiers platform admins assigned, but
     creating organizations, changing tiers, and reassigning tiers are blocked,
     and the expired license's own user and workspace limits apply.
   - After ``MULTI_TENANT_LAPSE_LIMIT`` the API refuses to start.

   Platform admins are warned in logs and in the license status API until a
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
import hashlib
import hmac
import uuid
from contextlib import suppress
from datetime import datetime

import orjson
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.secrets import get_db_encryption_key
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import PlatformSetting
from autosecops.exceptions import MultiTenantLicenseLapsed
from autosecops.licensing.clock import (
    CLOCK_PERSIST_INTERVAL,
    effective_now,
    refresh_license_clock,
)
from autosecops.licensing.enforcement import count_organizations
from autosecops.licensing.evaluation import (
    LICENSE_GRACE_PERIOD,
    multi_tenant_lapse_ends_at,
)
from autosecops.licensing.service import (
    LICENSE_CONTACT,
    ensure_license_deployment_loaded,
    get_configured_claims,
    get_license_state,
)
from autosecops.licensing.types import (
    LicenseClaims,
    LicenseGrant,
    MultiTenantLapsedAction,
    MultiTenantMode,
)
from autosecops.logger import logger

MULTI_TENANT_ACTIVITY_SETTING_KEY = "multi_tenant_license_activity"
"""``platform_settings.key`` that records multi-tenant use under a valid license."""

_ACTIVITY_MAC_CONTEXT = b"autosecops.licensing.multi_tenant_activity.v1"


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


async def ensure_tier_changes_allowed() -> None:
    """Block tier changes while the multi-tenant license is lapsed.

    Tiers decide each organization's entitlements in multi-tenant mode, so
    editing them on a lapsed license would grant paid features without one.

    Raises:
        MultiTenantLicenseLapsed: If the deployment runs in
            ``MultiTenantMode.LAPSED``.
    """
    if not config.AUTOSECOPS__EE_MULTI_TENANT:
        return
    await ensure_license_deployment_loaded()
    if get_multi_tenant_mode() is MultiTenantMode.LAPSED:
        raise MultiTenantLicenseLapsed(
            contact=LICENSE_CONTACT, action=MultiTenantLapsedAction.MANAGE_TIERS
        )


def log_multi_tenant_lapsed(claims: LicenseClaims | None = None) -> None:
    """Log the degraded multi-tenant state as an error for operators."""
    ends_at = multi_tenant_lapse_ends_at(claims) if claims else None
    logger.error(
        "MULTI-TENANT LICENSE LAPSED: the license that grants multi_tenant"
        " expired and its grace period ended. Existing organizations keep"
        " working, but creating organizations and changing tiers are blocked,"
        " and the API refuses to start after lapsed mode ends. Renew the"
        f" license via {LICENSE_CONTACT}",
        lapsed_mode_ends_at=ends_at.isoformat() if ends_at else None,
    )


def _activity_mac(license_id: str, last_active_at: str) -> str:
    key = hmac.new(
        get_db_encryption_key().encode(), _ACTIVITY_MAC_CONTEXT, hashlib.sha256
    ).digest()
    message = f"{license_id}\n{last_active_at}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


async def record_multi_tenant_activity(
    session: AsyncSession, claims: LicenseClaims, now: datetime
) -> None:
    """Record that this deployment ran multi-tenant under ``claims`` at ``now``.

    Call only while ``MultiTenantMode.ACTIVE``. Commits the session.
    """
    last_active_at = now.isoformat()
    value = orjson.dumps(
        {
            "license_id": claims.license_id,
            "last_active_at": last_active_at,
            "mac": _activity_mac(claims.license_id, last_active_at),
        }
    )
    await session.execute(
        insert(PlatformSetting)
        .values(
            id=uuid.uuid4(),
            key=MULTI_TENANT_ACTIVITY_SETTING_KEY,
            value=value,
            value_type="json",
            is_encrypted=False,
        )
        .on_conflict_do_update(
            index_elements=[PlatformSetting.key], set_={"value": value}
        )
    )
    await session.commit()


async def ran_multi_tenant_under(session: AsyncSession, claims: LicenseClaims) -> bool:
    """Whether this deployment ran multi-tenant under ``claims`` while it was valid."""
    stmt = select(PlatformSetting.value).where(
        PlatformSetting.key == MULTI_TENANT_ACTIVITY_SETTING_KEY
    )
    raw = (await session.execute(stmt)).scalar_one_or_none()
    if raw is None:
        return False
    try:
        record = orjson.loads(raw)
    except orjson.JSONDecodeError:
        return False
    match record:
        case {
            "license_id": str(license_id),
            "last_active_at": str(last_active_at),
            "mac": str(mac),
        }:
            pass
        case _:
            return False
    expected = _activity_mac(license_id, last_active_at)
    if not hmac.compare_digest(mac, expected) or license_id != claims.license_id:
        return False
    try:
        active_at = datetime.fromisoformat(last_active_at)
    except ValueError:
        return False
    if active_at.tzinfo is None:
        return False
    # The license granted multi_tenant (valid or in grace) at that time.
    return active_at < claims.expires_at + LICENSE_GRACE_PERIOD


async def check_multi_tenant_license_on_startup(session: AsyncSession) -> None:
    """Refuse to strand tenants, or to run multi-tenant without a license.

    Call once at API startup, after the deployment ID and the license clock
    are loaded. While multi-tenant mode is licensed, records that for a later
    lapse.

    Raises:
        MultiTenantLicenseRequiredError: If ``AUTOSECOPS__EE_MULTI_TENANT=true``
            is set and either the license does not permit multi-tenant mode
            and the database already holds more than one organization, or the
            license lapsed and this deployment never ran multi-tenant under it
            while it was valid, or lapsed mode has ended.
    """
    match get_multi_tenant_mode():
        case MultiTenantMode.ACTIVE:
            if (claims := get_configured_claims()) is not None:
                await record_multi_tenant_activity(session, claims, effective_now())
            return
        case MultiTenantMode.LAPSED:
            await _check_lapsed_multi_tenant(session)
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


async def _check_lapsed_multi_tenant(session: AsyncSession) -> None:
    claims = get_configured_claims()
    if claims is None:
        raise MultiTenantLicenseRequiredError(
            "AUTOSECOPS__EE_MULTI_TENANT=true is set but the license that"
            " grants multi_tenant no longer verifies on this installation."
            f" Install a valid multi-tenant license, or contact {LICENSE_CONTACT}"
        )
    ends_at = multi_tenant_lapse_ends_at(claims)
    if effective_now() >= ends_at:
        raise MultiTenantLicenseRequiredError(
            "The license that grants multi_tenant expired, and lapsed"
            f" multi-tenant mode ended at {ends_at.isoformat()}. Refusing to"
            " start. Install a renewed multi-tenant license on every service,"
            f" or contact {LICENSE_CONTACT}"
        )
    if not await ran_multi_tenant_under(session, claims):
        raise MultiTenantLicenseRequiredError(
            "AUTOSECOPS__EE_MULTI_TENANT=true is set, but the license that"
            " grants multi_tenant has expired and this deployment never ran"
            " multi-tenant under it while it was valid. An expired license"
            " cannot turn multi-tenant mode on. Install a valid multi-tenant"
            " license, or unset AUTOSECOPS__EE_MULTI_TENANT to run"
            f" single-tenant. Contact {LICENSE_CONTACT}"
        )
    log_multi_tenant_lapsed(claims)


async def _monitor_pass() -> None:
    await refresh_license_clock()
    # In multi-tenant mode tenants keep their tier entitlements, so the
    # single-tenant "paid entitlements are disabled" log would be false.
    get_license_state(log=not config.AUTOSECOPS__EE_MULTI_TENANT)
    match get_multi_tenant_mode():
        case MultiTenantMode.ACTIVE:
            if (claims := get_configured_claims()) is not None:
                async with get_async_session_bypass_rls_context_manager() as session:
                    await record_multi_tenant_activity(session, claims, effective_now())
        case MultiTenantMode.LAPSED:
            log_multi_tenant_lapsed(get_configured_claims())
        case MultiTenantMode.OFF:
            pass


async def run_license_monitor(stop_event: asyncio.Event) -> None:
    """Refresh the license clock and re-check the license once an hour.

    Runs in every API process until ``stop_event`` is set. Each pass persists
    the clock high-water mark, re-evaluates the license (which, single-tenant,
    logs grace, expired, and invalid states at most hourly), records
    multi-tenant use while it is licensed, and logs an error while multi-tenant
    mode runs on a lapsed license, so a long-running deployment surfaces a
    lapse without waiting for a restart.
    """
    while not stop_event.is_set():
        try:
            await _monitor_pass()
        except Exception as exc:
            logger.error("License monitor pass failed", error_type=type(exc).__name__)
        with suppress(TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), CLOCK_PERSIST_INTERVAL.total_seconds()
            )
