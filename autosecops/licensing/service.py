"""Evaluate the configured license key for single-tenant installs.

Signature verification runs once per distinct token; expiry is re-evaluated on
every call so a long-running process moves into the grace period and then back
to the free baseline without a restart.

A license bound to a deployment ID is compared with the process's cached
deployment ID (``autosecops.licensing.deployment``). Async entry points call
``ensure_license_deployment_loaded()`` first, which loads that ID from the
database once per process, and only when the configured license is bound.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from autosecops import config
from autosecops.licensing import keys
from autosecops.licensing.clock import effective_now, ensure_license_clock_fresh
from autosecops.licensing.deployment import (
    ensure_deployment_id,
    get_cached_deployment_id,
)
from autosecops.licensing.evaluation import state_from_claims
from autosecops.licensing.token import (
    LicenseVerificationError,
    decode_license,
    load_public_key,
)
from autosecops.licensing.types import (
    LicenseClaims,
    LicenseErrorCode,
    LicenseNoticeLevel,
    LicenseState,
    LicenseStatus,
)
from autosecops.logger import logger

LICENSE_CONTACT = "info@singularityrd.com"

LICENSE_EXPIRY_WARNING_DAYS = 30
"""Warn administrators this many days before a license expires."""

_REPEAT_LOG_INTERVAL_SECONDS = 3600.0
"""Re-log non-healthy license states at most this often per process."""

_last_logged: tuple[LicenseStatus, float] | None = None


@lru_cache(maxsize=1)
def _embedded_public_key(pem: bytes) -> Ed25519PublicKey:
    return load_public_key(pem)


@lru_cache(maxsize=8)
def _decode_cached(token: str, pem: bytes) -> LicenseClaims | LicenseErrorCode:
    """Verify once per (token, key); cache the error code instead of raising."""
    try:
        return decode_license(token, _embedded_public_key(pem))
    except LicenseVerificationError as exc:
        return exc.code


def get_configured_claims() -> LicenseClaims | None:
    """Return the verified claims of ``AUTOSECOPS__LICENSE_KEY``, if any."""
    token = config.AUTOSECOPS__LICENSE_KEY
    if not token:
        return None
    match _decode_cached(token, keys.LICENSE_PUBLIC_KEY_PEM):
        case LicenseClaims() as claims:
            return claims
        case LicenseErrorCode():
            return None


def get_license_state(now: datetime | None = None, *, log: bool = True) -> LicenseState:
    """Evaluate ``AUTOSECOPS__LICENSE_KEY`` against the embedded public key.

    Without ``now``, expiry is evaluated against ``effective_now()``: the later
    of the wall clock and the latest time this deployment has observed, so
    turning the clock back cannot revive an expired license. With ``log``, logs the state when it changes and re-logs grace, expired,
    and invalid states at most once per hour.
    """
    token = config.AUTOSECOPS__LICENSE_KEY
    if not token:
        state = LicenseState(status=LicenseStatus.MISSING)
    else:
        match _decode_cached(token, keys.LICENSE_PUBLIC_KEY_PEM):
            case LicenseErrorCode() as code:
                state = LicenseState(status=LicenseStatus.INVALID, error=code)
            case LicenseClaims() as claims:
                state = state_from_claims(
                    claims,
                    now=now or effective_now(),
                    deployment_id=get_cached_deployment_id(),
                )
    if log:
        _maybe_log(state)
    return state


def license_days_remaining(state: LicenseState, now: datetime) -> int | None:
    """Whole days until the license expires; negative once it has expired."""
    if state.claims is None:
        return None
    return (state.claims.expires_at - now) // timedelta(days=1)


def license_notice_level(
    state: LicenseState, now: datetime
) -> LicenseNoticeLevel | None:
    """Return why administrators should be warned, or ``None`` if they need not be.

    An unlicensed Community install (``MISSING``) never gets a notice.
    """
    match state.status:
        case LicenseStatus.MISSING:
            return None
        case LicenseStatus.GRACE:
            return LicenseNoticeLevel.GRACE
        case LicenseStatus.EXPIRED:
            return LicenseNoticeLevel.EXPIRED
        case LicenseStatus.INVALID:
            return LicenseNoticeLevel.INVALID
        case LicenseStatus.VALID:
            days = license_days_remaining(state, now)
            if days is not None and days < LICENSE_EXPIRY_WARNING_DAYS:
                return LicenseNoticeLevel.EXPIRING
            return None


async def ensure_license_deployment_loaded() -> None:
    """Load the license state that lives in the database for this process.

    Loads the deployment ID if the configured license is bound to one, and
    refreshes the license clock high-water mark at most once an hour (see
    ``autosecops.licensing.clock``). Both are no-ops without a license key, so
    unlicensed installs never query for them here.
    """
    claims = get_configured_claims()
    if claims is None:
        return
    await ensure_license_clock_fresh()
    if get_cached_deployment_id() is not None or claims.deployment_id is None:
        return
    await ensure_deployment_id()


class LicenseDeploymentMismatchError(RuntimeError):
    """A multi-tenant license is bound to a different installation."""


def check_multi_tenant_deployment_binding() -> None:
    """Refuse multi-tenant mode under a license bound to another installation.

    Config grants multi-tenant mode at import time, before the deployment ID
    can be read, so the API re-checks the binding once the ID is loaded.

    Raises:
        LicenseDeploymentMismatchError: If multi-tenant mode is on and the
            license's ``deployment_id`` differs from this installation's.
    """
    if not config.AUTOSECOPS__EE_MULTI_TENANT:
        return
    claims = get_configured_claims()
    if claims is None or claims.deployment_id is None:
        return
    if claims.deployment_id == get_cached_deployment_id():
        return
    raise LicenseDeploymentMismatchError(
        "The license that grants multi_tenant is bound to a different"
        f" deployment ID. Contact {LICENSE_CONTACT} for a license bound to"
        f" this installation's deployment ID ({get_cached_deployment_id()})"
    )


def _maybe_log(state: LicenseState) -> None:
    global _last_logged
    current = time.monotonic()
    if _last_logged is not None:
        last_status, last_time = _last_logged
        unchanged = last_status == state.status
        quiet = state.status in (LicenseStatus.MISSING, LicenseStatus.VALID)
        recent = current - last_time < _REPEAT_LOG_INTERVAL_SECONDS
        if unchanged and (quiet or recent):
            return
    _last_logged = (state.status, current)
    log_license_state(state)


def log_license_state(state: LicenseState) -> None:
    """Log a license state at a level that matches its severity."""
    claims = state.claims
    # Structured logging context passed as keyword arguments to the logger.
    fields: dict[str, str | list[str] | None] = {
        "license_status": state.status.value,
        "license_id": claims.license_id if claims else None,
        "customer": claims.customer if claims else None,
        "expires_at": claims.expires_at.isoformat() if claims else None,
        "plan": claims.plan.value if claims and claims.plan else None,
        "entitlements": sorted(
            [e.value for e in state.granted] + [g.value for g in state.grants]
        ),
    }
    match state.status:
        case LicenseStatus.MISSING:
            logger.info(
                "No license key configured; paid entitlements are disabled",
                **fields,
            )
        case LicenseStatus.VALID:
            logger.info("License key verified", **fields)
        case LicenseStatus.GRACE:
            logger.warning(
                "LICENSE EXPIRED: paid entitlements stay enabled until the grace"
                f" period ends. Renew the license via {LICENSE_CONTACT}",
                grace_ends_at=state.grace_ends_at.isoformat()
                if state.grace_ends_at
                else None,
                **fields,
            )
        case LicenseStatus.EXPIRED:
            logger.error(
                "LICENSE EXPIRED: the grace period ended and paid entitlements are"
                f" disabled. Renew the license via {LICENSE_CONTACT}",
                **fields,
            )
        case LicenseStatus.INVALID:
            logger.error(
                "License key is invalid; paid entitlements are disabled",
                error=state.error.value if state.error else None,
                **fields,
            )
    if state.unknown_entitlements:
        logger.warning(
            "License grants entitlements this release does not recognize",
            unknown_entitlements=list(state.unknown_entitlements),
        )
