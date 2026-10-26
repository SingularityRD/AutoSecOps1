"""Evaluate signed license tokens at a point in time.

This module must not import ``autosecops.config``: config imports it to decide
whether ``AUTOSECOPS__EE_MULTI_TENANT`` may take effect.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from autosecops.licensing import keys
from autosecops.licensing.token import (
    LicenseVerificationError,
    decode_license,
    load_public_key,
)
from autosecops.licensing.types import (
    LicenseClaims,
    LicenseErrorCode,
    LicenseGrant,
    LicenseState,
    LicenseStatus,
)
from autosecops.tiers.enums import Entitlement

LICENSE_GRACE_PERIOD = timedelta(days=14)
"""How long paid entitlements keep working after a license expires."""

LICENSE_CLOCK_SKEW = timedelta(minutes=5)
"""How far ``issued_at`` may lie in the future before a license is rejected."""


def _split_entitlements(
    raw: list[str],
) -> tuple[frozenset[Entitlement], frozenset[LicenseGrant], tuple[str, ...]]:
    entitlements: set[Entitlement] = set()
    grants: set[LicenseGrant] = set()
    unknown: list[str] = []
    for value in raw:
        if value in Entitlement:
            entitlements.add(Entitlement(value))
        elif value in LicenseGrant:
            grants.add(LicenseGrant(value))
        else:
            unknown.append(value)
    return frozenset(entitlements), frozenset(grants), tuple(unknown)


def evaluate_license(
    token: str | None,
    *,
    now: datetime,
    public_key: Ed25519PublicKey,
) -> LicenseState:
    """Evaluate a license token at ``now``.

    Never raises for a bad token: malformed or unverifiable tokens evaluate to
    ``LicenseStatus.INVALID`` so a garbled key cannot stop the app from starting.
    """
    if not token:
        return LicenseState(status=LicenseStatus.MISSING)
    try:
        claims = decode_license(token, public_key)
    except LicenseVerificationError as exc:
        return LicenseState(status=LicenseStatus.INVALID, error=exc.code)
    return state_from_claims(claims, now=now)


def state_from_claims(claims: LicenseClaims, *, now: datetime) -> LicenseState:
    """Evaluate verified claims at ``now``."""
    # ``LicenseClaims`` caps expires_at well below datetime.max, so this
    # addition cannot overflow.
    grace_ends_at = claims.expires_at + LICENSE_GRACE_PERIOD
    # Compare the difference rather than computing ``issued_at - skew``, which
    # could underflow for dates near datetime.min.
    if claims.issued_at - now > LICENSE_CLOCK_SKEW:
        return LicenseState(
            status=LicenseStatus.INVALID,
            claims=claims,
            grace_ends_at=grace_ends_at,
            error=LicenseErrorCode.NOT_YET_VALID,
        )
    entitlements, grants, unknown = _split_entitlements(claims.entitlements)
    if now < claims.expires_at:
        status = LicenseStatus.VALID
    elif now < grace_ends_at:
        status = LicenseStatus.GRACE
    else:
        status = LicenseStatus.EXPIRED
        entitlements = frozenset()
        grants = frozenset()
    return LicenseState(
        status=status,
        claims=claims,
        granted=entitlements,
        grants=grants,
        unknown_entitlements=unknown,
        grace_ends_at=grace_ends_at,
    )


def license_grants_multi_tenant(
    token: str | None, *, now: datetime | None = None
) -> bool:
    """Whether ``token`` is valid or in grace and grants ``multi_tenant``.

    Verifies against the embedded public key in ``keys``.
    """
    if not token:
        return False
    state = evaluate_license(
        token,
        now=now or datetime.now(UTC),
        public_key=load_public_key(keys.LICENSE_PUBLIC_KEY_PEM),
    )
    return LicenseGrant.MULTI_TENANT in state.grants
