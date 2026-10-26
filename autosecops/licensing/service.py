"""Evaluate the configured license key for single-tenant installs.

Signature verification runs once per distinct token; expiry is re-evaluated on
every call so a long-running process moves into the grace period and then back
to the free baseline without a restart.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from autosecops import config
from autosecops.licensing import keys
from autosecops.licensing.evaluation import state_from_claims
from autosecops.licensing.token import (
    LicenseVerificationError,
    decode_license,
    load_public_key,
)
from autosecops.licensing.types import (
    LicenseClaims,
    LicenseErrorCode,
    LicenseState,
    LicenseStatus,
)
from autosecops.logger import logger

LICENSE_CONTACT = "sales@singularityrd.com"

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


def get_license_state(now: datetime | None = None, *, log: bool = True) -> LicenseState:
    """Evaluate ``AUTOSECOPS__LICENSE_KEY`` against the embedded public key.

    With ``log``, logs the state when it changes and re-logs grace, expired,
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
                state = state_from_claims(claims, now=now or datetime.now(UTC))
    if log:
        _maybe_log(state)
    return state


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
