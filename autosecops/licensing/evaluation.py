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
    LicenseLimits,
    LicenseState,
    LicenseStatus,
)
from autosecops.tiers.enums import Entitlement

LICENSE_GRACE_PERIOD = timedelta(days=14)
"""How long paid entitlements keep working after a license expires."""

MULTI_TENANT_LAPSE_LIMIT = timedelta(days=30)
"""How long after its grace period an expired multi-tenant license keeps
multi-tenant mode on, in ``MultiTenantMode.LAPSED``. After that the API refuses
to start until a renewed license is installed."""

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
    deployment_id: str | None = None,
    check_deployment: bool = True,
) -> LicenseState:
    """Evaluate a license token at ``now``.

    Never raises for a bad token: malformed or unverifiable tokens evaluate to
    ``LicenseStatus.INVALID`` so a garbled key cannot stop the app from starting.

    Args:
        token: The license token, or ``None`` when none is configured.
        now: The evaluation time.
        public_key: The key that verifies the signature.
        deployment_id: This installation's deployment ID, or ``None`` if unknown.
        check_deployment: Whether to enforce a ``deployment_id`` claim. Only
            callers that cannot know the installation (the issuer CLI, the
            import-time multi-tenant check) turn it off.
    """
    if not token:
        return LicenseState(status=LicenseStatus.MISSING)
    try:
        claims = decode_license(token, public_key)
    except LicenseVerificationError as exc:
        return LicenseState(status=LicenseStatus.INVALID, error=exc.code)
    return state_from_claims(
        claims,
        now=now,
        deployment_id=deployment_id,
        check_deployment=check_deployment,
    )


def state_from_claims(
    claims: LicenseClaims,
    *,
    now: datetime,
    deployment_id: str | None = None,
    check_deployment: bool = True,
) -> LicenseState:
    """Evaluate verified claims at ``now``.

    A license bound to a deployment ID is INVALID with
    ``LicenseErrorCode.DEPLOYMENT_MISMATCH`` unless ``deployment_id`` equals
    it. An unknown ``deployment_id`` (``None``) never matches, so a bound
    license fails closed until the installation's ID is loaded.
    """
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
    bound_to = claims.deployment_id
    if check_deployment and bound_to is not None and bound_to != deployment_id:
        return LicenseState(
            status=LicenseStatus.INVALID,
            claims=claims,
            grace_ends_at=grace_ends_at,
            error=LicenseErrorCode.DEPLOYMENT_MISMATCH,
        )
    entitlements, grants, unknown = _split_entitlements(claims.entitlements)
    limits = claims.limits or LicenseLimits()
    if now < claims.expires_at:
        status = LicenseStatus.VALID
    elif now < grace_ends_at:
        status = LicenseStatus.GRACE
    else:
        # Past the grace period the install falls back to the free baseline,
        # which has no license limits.
        status = LicenseStatus.EXPIRED
        entitlements = frozenset()
        grants = frozenset()
        limits = LicenseLimits()
    return LicenseState(
        status=status,
        claims=claims,
        granted=entitlements,
        grants=grants,
        limits=limits,
        unknown_entitlements=unknown,
        grace_ends_at=grace_ends_at,
    )


def license_grants_multi_tenant(
    token: str | None, *, now: datetime | None = None
) -> bool:
    """Whether ``token`` is valid or in grace and grants ``multi_tenant``.

    Verifies against the embedded public key in ``keys``. Config calls this at
    import time, before the database is reachable, so a ``deployment_id``
    claim is not checked here; the API checks it at startup instead (see
    ``autosecops.licensing.service.check_multi_tenant_deployment_binding``).
    """
    if not token:
        return False
    state = evaluate_license(
        token,
        now=now or datetime.now(UTC),
        public_key=load_public_key(keys.LICENSE_PUBLIC_KEY_PEM),
        check_deployment=False,
    )
    return LicenseGrant.MULTI_TENANT in state.grants


def license_permits_multi_tenant_mode(
    token: str | None, *, now: datetime | None = None
) -> bool:
    """Whether ``token`` lets ``AUTOSECOPS__EE_MULTI_TENANT=true`` take effect.

    True when the license verifies, is not otherwise invalid, and lists
    ``multi_tenant``, including for ``MULTI_TENANT_LAPSE_LIMIT`` after its
    grace period ends. A multi-tenant deployment whose license lapses must not
    silently fall back to single-tenant mode on its next restart: that would
    cut every organization but the default one off from SSO and organization
    selection. Instead it keeps running multi-tenant in
    ``MultiTenantMode.LAPSED``, where existing organizations keep working and
    tier and organization changes are blocked. The API startup check (see
    ``autosecops.licensing.multi_tenant``) allows that only on a deployment
    that ran multi-tenant under the same license while it was valid, so an
    expired key cannot turn multi-tenant mode on for a fresh install.

    Like ``license_grants_multi_tenant``, this runs at import time, before the
    database is reachable, so it does not check a ``deployment_id`` claim.
    """
    if not token:
        return False
    at = now or datetime.now(UTC)
    state = evaluate_license(
        token,
        now=at,
        public_key=load_public_key(keys.LICENSE_PUBLIC_KEY_PEM),
        check_deployment=False,
    )
    claims = state.claims
    if claims is None or state.status is LicenseStatus.INVALID:
        return False
    if LicenseGrant.MULTI_TENANT.value not in claims.entitlements:
        return False
    if state.status is LicenseStatus.EXPIRED:
        return at < multi_tenant_lapse_ends_at(claims)
    return True


def multi_tenant_lapse_ends_at(claims: LicenseClaims) -> datetime:
    """When an expired multi-tenant license stops keeping multi-tenant mode on."""
    return claims.expires_at + LICENSE_GRACE_PERIOD + MULTI_TENANT_LAPSE_LIMIT
