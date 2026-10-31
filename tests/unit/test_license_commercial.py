"""Tests for license limits, deployment binding, plan presets, and notices."""

from __future__ import annotations

import base64
import csv
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import license_tool
import orjson
import pytest
from autosecops_ee.admin.users.schemas import AdminUserCreate
from autosecops_ee.admin.users.service import AdminUserService
from autosecops_ee.scim.provisioning import ScimProvisioningService
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped

from autosecops import config
from autosecops.admin.license import router as admin_license_router
from autosecops.admin.license.router import get_license
from autosecops.auth.schemas import UserCreate
from autosecops.auth.types import PlatformRole, Role
from autosecops.auth.users import LicensedUserDatabase, UserManager
from autosecops.db.models import OAuthAccount, Organization, User
from autosecops.exceptions import LicenseLimitExceeded
from autosecops.licensing import deployment as license_deployment
from autosecops.licensing import enforcement, keys
from autosecops.licensing import multi_tenant as license_multi_tenant
from autosecops.licensing import service as license_service
from autosecops.licensing.deployment import (
    DEPLOYMENT_ID_PREFIX,
    generate_deployment_id,
    load_or_create_deployment_id,
)
from autosecops.licensing.evaluation import evaluate_license
from autosecops.licensing.plans import (
    BUSINESS_ENTITLEMENTS,
    ENTERPRISE_ENTITLEMENTS,
    ISSUABLE_PLANS,
    MSSP_ENTITLEMENTS,
    PLAN_ENTITLEMENTS,
    TEAM_ENTITLEMENTS,
    plan_duration,
    plan_entitlements,
)
from autosecops.licensing.token import decode_license, encode_license
from autosecops.licensing.types import (
    LicenseClaims,
    LicenseErrorCode,
    LicenseGrant,
    LicenseLimitName,
    LicenseLimits,
    LicenseNoticeLevel,
    LicensePlan,
    LicenseState,
    LicenseStatus,
)
from autosecops.organization import management as organization_management
from autosecops.organization import router as organization_router
from autosecops.organization.management import create_organization
from autosecops.tiers import defaults as tier_defaults
from autosecops.tiers.enums import Entitlement
from autosecops.tiers.service import TierService

DEPLOYMENT_ID = "dep_00000000000000000000000000000001"
OTHER_DEPLOYMENT_ID = "dep_00000000000000000000000000000002"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _claims(
    *,
    days: int = 30,
    entitlements: list[str] | None = None,
    limits: LicenseLimits | None = None,
    deployment_id: str | None = None,
    plan: LicensePlan | None = None,
) -> LicenseClaims:
    now = datetime.now(UTC)
    return LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=days),
        entitlements=entitlements if entitlements is not None else ["git_sync"],
        limits=limits,
        deployment_id=deployment_id,
        plan=plan,
    )


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def reset_deployment_cache() -> Iterator[None]:
    """Each test starts with no deployment ID loaded."""
    license_deployment.set_cached_deployment_id(None)
    yield
    license_deployment.set_cached_deployment_id(None)


@pytest.fixture
def embedded_key(
    monkeypatch: pytest.MonkeyPatch, private_key: Ed25519PrivateKey
) -> Iterator[Ed25519PrivateKey]:
    """Swap the embedded public key for a per-test key and reset caches."""
    pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    monkeypatch.setattr(keys, "LICENSE_PUBLIC_KEY_PEM", pem)
    monkeypatch.setattr(license_service, "_last_logged", None)
    license_service._decode_cached.cache_clear()
    license_service._embedded_public_key.cache_clear()
    yield private_key
    license_service._decode_cached.cache_clear()
    license_service._embedded_public_key.cache_clear()


@pytest.fixture
def single_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(),
    )


def _install(
    monkeypatch: pytest.MonkeyPatch, key: Ed25519PrivateKey, claims: LicenseClaims
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", encode_license(claims, key))


# --- Claims parsing and backward compatibility --------------------------------


def test_token_from_older_issuer_still_verifies(
    private_key: Ed25519PrivateKey,
) -> None:
    """A payload signed before the optional claims existed stays VALID."""
    now = datetime.now(UTC)
    legacy_payload = orjson.dumps(
        {
            "version": 1,
            "license_id": "lic_legacy",
            "customer": "Synthetic Customer",
            "issued_at": (now - timedelta(days=1)).isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "entitlements": ["git_sync"],
        },
        option=orjson.OPT_SORT_KEYS,
    )
    token = f"{_b64(legacy_payload)}.{_b64(private_key.sign(legacy_payload))}"

    state = evaluate_license(token, now=now, public_key=private_key.public_key())

    assert state.status == LicenseStatus.VALID
    assert state.claims is not None
    assert state.claims.limits is None
    assert state.claims.deployment_id is None
    assert state.claims.plan is None
    assert state.limits == LicenseLimits()
    assert state.granted == frozenset({Entitlement.GIT_SYNC})


def test_claims_without_new_fields_encode_like_older_releases(
    private_key: Ed25519PrivateKey,
) -> None:
    """Unset optional claims are omitted, so older payloads stay byte-identical."""
    token = encode_license(_claims(), private_key)
    payload = base64.urlsafe_b64decode(token.split(".")[0] + "==")

    assert set(orjson.loads(payload)) == {
        "version",
        "license_id",
        "customer",
        "issued_at",
        "expires_at",
        "entitlements",
    }


def test_new_claims_round_trip(private_key: Ed25519PrivateKey) -> None:
    claims = _claims(
        limits=LicenseLimits(max_users=10, max_workspaces=2),
        deployment_id=DEPLOYMENT_ID,
        plan=LicensePlan.BUSINESS,
    )

    decoded = decode_license(
        encode_license(claims, private_key), private_key.public_key()
    )

    assert decoded == claims
    assert decoded.limits == LicenseLimits(max_users=10, max_workspaces=2)


def test_unknown_plan_and_limit_keys_are_ignored(
    private_key: Ed25519PrivateKey,
) -> None:
    """A newer issuer's plan labels and limit names never invalidate a key."""
    now = datetime.now(UTC)
    payload = orjson.dumps(
        {
            "version": 1,
            "license_id": "lic_future",
            "customer": "Synthetic Customer",
            "issued_at": (now - timedelta(days=1)).isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "entitlements": [],
            "plan": "future_plan",
            "limits": {"max_users": 5, "max_future_things": 3},
        }
    )
    token = f"{_b64(payload)}.{_b64(private_key.sign(payload))}"

    state = evaluate_license(token, now=now, public_key=private_key.public_key())

    assert state.status == LicenseStatus.VALID
    assert state.claims is not None
    assert state.claims.plan is None
    assert state.limits == LicenseLimits(max_users=5)


@pytest.mark.parametrize("value", [0, -1])
def test_non_positive_limits_are_rejected(value: int) -> None:
    with pytest.raises(ValueError):
        LicenseLimits.model_validate({"max_users": value})


def test_limits_apply_only_while_valid_or_in_grace(
    private_key: Ed25519PrivateKey,
) -> None:
    limits = LicenseLimits(max_users=3)
    token = encode_license(_claims(days=30, limits=limits), private_key)
    public_key = private_key.public_key()
    now = datetime.now(UTC)

    valid = evaluate_license(token, now=now, public_key=public_key)
    grace = evaluate_license(token, now=now + timedelta(days=35), public_key=public_key)
    expired = evaluate_license(
        token, now=now + timedelta(days=60), public_key=public_key
    )

    assert valid.limits == limits
    assert grace.status == LicenseStatus.GRACE
    assert grace.limits == limits
    assert expired.status == LicenseStatus.EXPIRED
    assert expired.limits == LicenseLimits()


# --- Deployment binding -------------------------------------------------------


def test_bound_license_is_valid_on_its_deployment(
    private_key: Ed25519PrivateKey,
) -> None:
    token = encode_license(_claims(deployment_id=DEPLOYMENT_ID), private_key)

    state = evaluate_license(
        token,
        now=datetime.now(UTC),
        public_key=private_key.public_key(),
        deployment_id=DEPLOYMENT_ID,
    )

    assert state.status == LicenseStatus.VALID
    assert state.granted == frozenset({Entitlement.GIT_SYNC})


@pytest.mark.parametrize("deployment_id", [OTHER_DEPLOYMENT_ID, None])
def test_bound_license_on_other_deployment_is_invalid(
    private_key: Ed25519PrivateKey, deployment_id: str | None
) -> None:
    token = encode_license(
        _claims(deployment_id=DEPLOYMENT_ID, limits=LicenseLimits(max_users=1)),
        private_key,
    )

    state = evaluate_license(
        token,
        now=datetime.now(UTC),
        public_key=private_key.public_key(),
        deployment_id=deployment_id,
    )

    assert state.status == LicenseStatus.INVALID
    assert state.error == LicenseErrorCode.DEPLOYMENT_MISMATCH
    assert state.granted == frozenset()
    assert state.limits == LicenseLimits()
    assert state.claims is not None


def test_binding_check_can_be_skipped(private_key: Ed25519PrivateKey) -> None:
    token = encode_license(_claims(deployment_id=DEPLOYMENT_ID), private_key)

    state = evaluate_license(
        token,
        now=datetime.now(UTC),
        public_key=private_key.public_key(),
        check_deployment=False,
    )

    assert state.status == LicenseStatus.VALID


def test_get_license_state_uses_cached_deployment_id(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _install(monkeypatch, embedded_key, _claims(deployment_id=DEPLOYMENT_ID))

    assert license_service.get_license_state(log=False).status == LicenseStatus.INVALID

    license_deployment.set_cached_deployment_id(DEPLOYMENT_ID)
    assert license_service.get_license_state(log=False).status == LicenseStatus.VALID

    license_deployment.set_cached_deployment_id(OTHER_DEPLOYMENT_ID)
    state = license_service.get_license_state(log=False)
    assert state.status == LicenseStatus.INVALID
    assert state.error == LicenseErrorCode.DEPLOYMENT_MISMATCH


@pytest.mark.anyio
async def test_deployment_id_loads_only_for_bound_licenses(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    load = AsyncMock(return_value=DEPLOYMENT_ID)
    monkeypatch.setattr(license_service, "ensure_deployment_id", load)

    _install(monkeypatch, embedded_key, _claims())
    await license_service.ensure_license_deployment_loaded()
    load.assert_not_awaited()

    _install(monkeypatch, embedded_key, _claims(deployment_id=DEPLOYMENT_ID))
    await license_service.ensure_license_deployment_loaded()
    load.assert_awaited_once()

    license_deployment.set_cached_deployment_id(DEPLOYMENT_ID)
    await license_service.ensure_license_deployment_loaded()
    load.assert_awaited_once()


def test_multi_tenant_refuses_license_bound_to_other_deployment(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    _install(
        monkeypatch,
        embedded_key,
        _claims(entitlements=["multi_tenant"], deployment_id=DEPLOYMENT_ID),
    )

    license_deployment.set_cached_deployment_id(OTHER_DEPLOYMENT_ID)
    with pytest.raises(license_service.LicenseDeploymentMismatchError):
        license_service.check_multi_tenant_deployment_binding()

    license_deployment.set_cached_deployment_id(DEPLOYMENT_ID)
    license_service.check_multi_tenant_deployment_binding()


def test_generated_deployment_ids_are_prefixed_and_unique() -> None:
    first, second = generate_deployment_id(), generate_deployment_id()

    assert first.startswith(DEPLOYMENT_ID_PREFIX)
    assert len(first) == len(DEPLOYMENT_ID_PREFIX) + 32
    assert first != second


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_deployment_id_is_created_once_and_stable(session: AsyncSession) -> None:
    first = await load_or_create_deployment_id(session)
    second = await load_or_create_deployment_id(session)

    assert first.startswith(DEPLOYMENT_ID_PREFIX)
    assert first == second


# --- Tier limit merge ---------------------------------------------------------


@pytest.mark.usefixtures("single_tenant")
def test_single_tenant_limits_merge_license_values(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _install(
        monkeypatch,
        embedded_key,
        _claims(
            limits=LicenseLimits(
                max_concurrent_workflows=4,
                max_concurrent_actions=8,
                max_action_executions_per_workflow=100,
            )
        ),
    )

    limits = tier_defaults.get_single_tenant_limits()

    assert limits.max_concurrent_workflows == 4
    assert limits.max_concurrent_actions == 8
    assert limits.max_action_executions_per_workflow == 100
    assert limits.api_rate_limit == tier_defaults.DEFAULT_LIMITS.api_rate_limit


@pytest.mark.usefixtures("single_tenant")
def test_license_limits_never_loosen_stricter_defaults(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_LIMITS",
        tier_defaults.DEFAULT_LIMITS.model_copy(update={"max_concurrent_workflows": 2}),
    )
    _install(
        monkeypatch,
        embedded_key,
        _claims(limits=LicenseLimits(max_concurrent_workflows=50)),
    )

    assert tier_defaults.get_single_tenant_limits().max_concurrent_workflows == 2


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_tier_service_single_tenant_limits_come_from_license(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", None)
    unlicensed = await TierService(AsyncMock()).get_effective_limits(uuid.uuid4())
    assert unlicensed == tier_defaults.DEFAULT_LIMITS

    _install(
        monkeypatch,
        embedded_key,
        _claims(limits=LicenseLimits(max_concurrent_actions=3)),
    )
    licensed = await TierService(AsyncMock()).get_effective_limits(uuid.uuid4())
    assert licensed.max_concurrent_actions == 3


# --- Enforcement helpers -------------------------------------------------------


def _licensed_state(limits: LicenseLimits) -> LicenseState:
    return LicenseState(status=LicenseStatus.VALID, limits=limits)


def _patch_limits(
    monkeypatch: pytest.MonkeyPatch,
    limits: LicenseLimits,
    *,
    users: int = 0,
    workspaces: int = 0,
    organizations: int = 0,
) -> None:
    monkeypatch.setattr(
        enforcement, "get_license_state", lambda log: _licensed_state(limits)
    )
    monkeypatch.setattr(enforcement, "ensure_license_deployment_loaded", AsyncMock())
    monkeypatch.setattr(
        enforcement, "count_active_users", AsyncMock(return_value=users)
    )
    monkeypatch.setattr(
        enforcement, "count_workspaces", AsyncMock(return_value=workspaces)
    )
    monkeypatch.setattr(
        enforcement, "count_organizations", AsyncMock(return_value=organizations)
    )


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_user_limit_blocks_at_limit_with_clear_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_limits(monkeypatch, LicenseLimits(max_users=5), users=5)

    with pytest.raises(LicenseLimitExceeded) as exc_info:
        await enforcement.enforce_user_limit(AsyncMock())

    exc = exc_info.value
    assert exc.limit == LicenseLimitName.MAX_USERS
    assert (exc.current, exc.maximum) == (5, 5)
    assert "max_users" in str(exc)
    assert "5 of 5" in str(exc)
    assert license_service.LICENSE_CONTACT in str(exc)
    assert exc.detail == {"limit": "max_users", "current": 5, "maximum": 5}


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_user_limit_allows_below_limit_and_without_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_limits(monkeypatch, LicenseLimits(max_users=5), users=4)
    await enforcement.enforce_user_limit(AsyncMock())

    session = AsyncMock()
    _patch_limits(monkeypatch, LicenseLimits(), users=10_000)
    await enforcement.enforce_user_limit(session)
    session.execute.assert_not_awaited()


@pytest.mark.anyio
async def test_user_and_workspace_limits_do_not_apply_in_multi_tenant_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    _patch_limits(
        monkeypatch,
        LicenseLimits(max_users=1, max_workspaces=1),
        users=9,
        workspaces=9,
    )

    await enforcement.enforce_user_limit(AsyncMock())
    await enforcement.enforce_workspace_limit(AsyncMock())


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_workspace_limit_blocks_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_limits(monkeypatch, LicenseLimits(max_workspaces=3), workspaces=3)

    with pytest.raises(LicenseLimitExceeded) as exc_info:
        await enforcement.enforce_workspace_limit(AsyncMock())

    assert exc_info.value.limit == LicenseLimitName.MAX_WORKSPACES
    assert "3 of 3" in str(exc_info.value)


@pytest.mark.anyio
async def test_organization_limit_applies_only_in_multi_tenant_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_limits(monkeypatch, LicenseLimits(max_organizations=2), organizations=2)

    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    await enforcement.enforce_organization_limit(AsyncMock())

    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    with pytest.raises(LicenseLimitExceeded) as exc_info:
        await enforcement.enforce_organization_limit(AsyncMock())
    assert exc_info.value.limit == LicenseLimitName.MAX_ORGANIZATIONS


@pytest.mark.anyio
async def test_create_organization_is_blocked_at_org_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    _patch_limits(monkeypatch, LicenseLimits(max_organizations=1), organizations=1)
    monkeypatch.setattr(
        license_multi_tenant,
        "get_license_state",
        lambda log: LicenseState(
            status=LicenseStatus.VALID, grants=frozenset({LicenseGrant.MULTI_TENANT})
        ),
    )
    monkeypatch.setattr(
        organization_management, "ensure_license_deployment_loaded", AsyncMock()
    )
    session = AsyncMock()
    session.add = MagicMock()

    with pytest.raises(LicenseLimitExceeded):
        await create_organization(session, name="Synthetic Org", slug="synthetic")

    session.add.assert_not_called()


# --- User creation paths ------------------------------------------------------


@pytest.fixture
def auth_session(session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the auth bulkhead session at the test session."""

    @asynccontextmanager
    async def _session_cm() -> AsyncIterator[AsyncSession]:
        yield session

    monkeypatch.setattr(
        "autosecops.auth.users.get_async_session_auth_context_manager",
        _session_cm,
    )


@pytest.fixture
async def seeded_org(session: AsyncSession) -> Organization:
    """An organization plus one user, so no path takes the first-user branch."""
    org_id = uuid.uuid4()
    org = Organization(id=org_id, name="Seat Org", slug=f"seat-org-{org_id.hex[:8]}")
    session.add(org)
    session.add(
        User(
            id=uuid.uuid4(),
            email=f"seed-{uuid.uuid4().hex[:8]}@autosecops.example",
            hashed_password="x",
        )
    )
    await session.flush()
    return org


@pytest.fixture
def user_manager(session: AsyncSession) -> UserManager:
    return UserManager(LicensedUserDatabase(session, User, OAuthAccount))


@pytest.fixture
def seats_full(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    _patch_limits(monkeypatch, LicenseLimits(max_users=2), users=2)


async def _user_exists(session: AsyncSession, email: str) -> bool:
    user_email = cast(Mapped[str], User.email)
    stmt = select(func.count()).select_from(User).where(user_email == email)
    return bool(await session.scalar(stmt))


def _new_email() -> str:
    return f"seat-{uuid.uuid4().hex[:8]}@autosecops.example"


pytest_db_paths = pytest.mark.usefixtures(
    "db", "auth_session", "seeded_org", "seats_full"
)


@pytest.mark.anyio
@pytest_db_paths
@pytest.mark.parametrize("invitation_token", [None, "synthetic-invitation-token"])
async def test_signup_and_invite_acceptance_are_blocked_at_user_limit(
    session: AsyncSession, user_manager: UserManager, invitation_token: str | None
) -> None:
    email = _new_email()

    with pytest.raises(LicenseLimitExceeded):
        await user_manager.create(
            UserCreate(
                email=email,
                password="synthetic-password-1234",
                invitation_token=invitation_token,
            )
        )

    assert not await _user_exists(session, email)


@pytest.mark.anyio
@pytest_db_paths
async def test_oidc_oauth_jit_is_blocked_at_user_limit(
    session: AsyncSession, user_manager: UserManager
) -> None:
    email = _new_email()

    with pytest.raises(LicenseLimitExceeded):
        await user_manager.oauth_callback(
            "openid",
            "synthetic-access-token",
            f"account-{uuid.uuid4().hex[:8]}",
            email,
            associate_by_email=True,
            is_verified_by_default=True,
        )

    assert not await _user_exists(session, email)


@pytest.mark.anyio
@pytest_db_paths
async def test_saml_jit_is_blocked_at_user_limit(
    session: AsyncSession, user_manager: UserManager
) -> None:
    email = _new_email()

    with pytest.raises(LicenseLimitExceeded):
        await user_manager.saml_callback(email=email)

    assert not await _user_exists(session, email)


@pytest.mark.anyio
@pytest_db_paths
async def test_existing_user_sign_in_is_never_blocked(
    session: AsyncSession, user_manager: UserManager
) -> None:
    """A full license blocks new accounts only; existing users keep working."""
    email = _new_email()
    session.add(User(id=uuid.uuid4(), email=email, hashed_password="x"))
    await session.flush()

    user = await user_manager.saml_callback(email=email)

    assert user.email == email


@pytest.mark.anyio
@pytest_db_paths
async def test_scim_provisioning_is_blocked_at_user_limit(
    session: AsyncSession, seeded_org: Organization
) -> None:
    role = Role(
        type="scim",
        organization_id=seeded_org.id,
        scim_connection_id=uuid.uuid4(),
        service_id="autosecops-api",
        scopes=frozenset({"org:member:remove"}),
    )
    service = ScimProvisioningService(session, role=role)
    email = _new_email()

    with pytest.raises(LicenseLimitExceeded):
        await service.provision_user(external_id="idp-seat", email=email)

    assert not await _user_exists(session, email)


@pytest.mark.anyio
@pytest_db_paths
async def test_admin_user_creation_is_blocked_at_user_limit(
    session: AsyncSession,
) -> None:
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")
    service = AdminUserService(session, role=role)
    email = _new_email()

    with pytest.raises(LicenseLimitExceeded):
        await service.create_user(
            AdminUserCreate(email=email, password="synthetic-password-1234")
        )

    assert not await _user_exists(session, email)


@pytest.mark.anyio
async def test_licensed_user_db_skips_inactive_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enforce = AsyncMock()
    monkeypatch.setattr("autosecops.auth.users.enforce_user_limit", enforce)
    create = AsyncMock(return_value=MagicMock())
    monkeypatch.setattr(SQLAlchemyUserDatabase, "create", create)
    user_db = LicensedUserDatabase(AsyncMock(), User, OAuthAccount)

    await user_db.create({"email": _new_email(), "is_active": False})
    enforce.assert_not_awaited()

    await user_db.create({"email": _new_email()})
    enforce.assert_awaited_once()


# --- Plan presets -------------------------------------------------------------


def test_plan_presets_nest_and_cover_every_entitlement() -> None:
    assert TEAM_ENTITLEMENTS < BUSINESS_ENTITLEMENTS < ENTERPRISE_ENTITLEMENTS
    assert ENTERPRISE_ENTITLEMENTS < MSSP_ENTITLEMENTS
    assert set(Entitlement) <= ENTERPRISE_ENTITLEMENTS
    assert LicenseGrant.MULTI_TENANT not in ENTERPRISE_ENTITLEMENTS
    assert MSSP_ENTITLEMENTS - ENTERPRISE_ENTITLEMENTS == {LicenseGrant.MULTI_TENANT}
    assert set(PLAN_ENTITLEMENTS) == set(LicensePlan)


def test_plan_preset_contents() -> None:
    assert plan_entitlements(LicensePlan.COMMUNITY) == frozenset()
    assert plan_entitlements(LicensePlan.TEAM) == {
        Entitlement.CASE_ADDONS,
        Entitlement.AGENT_ADDONS,
        Entitlement.FORMS,
        Entitlement.GIT_SYNC,
        Entitlement.SERVICE_ACCOUNTS,
    }
    assert plan_entitlements(LicensePlan.BUSINESS) - TEAM_ENTITLEMENTS == {
        Entitlement.RBAC_ADDONS,
        Entitlement.MULTI_WORKSPACE,
        Entitlement.EXTERNAL_SECRET_STORES,
        Entitlement.AGENT_CHANNELS,
        Entitlement.SEMANTIC_SEARCH,
        Entitlement.WATCHTOWER,
    }
    assert {Entitlement.TUNNELS, Entitlement.ROBOT_EDR} <= plan_entitlements(
        LicensePlan.ENTERPRISE
    )
    assert plan_entitlements(LicensePlan.PILOT) == ENTERPRISE_ENTITLEMENTS
    assert LicensePlan.COMMUNITY not in ISSUABLE_PLANS


def test_plan_durations() -> None:
    assert plan_duration(LicensePlan.PILOT) == timedelta(days=60)
    assert plan_duration(LicensePlan.BUSINESS) == timedelta(days=365)
    assert plan_duration(None) == timedelta(days=365)


# --- Issuer CLI ---------------------------------------------------------------


@pytest.fixture
def key_files(tmp_path: Path) -> tuple[Ed25519PrivateKey, Path]:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return private_key, private_path


def _issue(private_path: Path, *extra: str) -> int:
    return license_tool.main(
        [
            "issue",
            "--private-key",
            str(private_path),
            "--customer",
            "Synthetic Customer",
            *extra,
        ]
    )


def test_license_tool_plan_preset_with_overrides_and_limits(
    key_files: tuple[Ed25519PrivateKey, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    private_key, private_path = key_files

    exit_code = _issue(
        private_path,
        "--plan",
        "team",
        "--add",
        "tunnels",
        "--remove",
        "forms",
        "--max-users",
        "25",
        "--max-workspaces",
        "3",
        "--max-concurrent-workflows",
        "10",
        "--deployment-id",
        DEPLOYMENT_ID,
    )
    claims = decode_license(capsys.readouterr().out.strip(), private_key.public_key())

    assert exit_code == 0
    assert claims.plan == LicensePlan.TEAM
    expected = {e.value for e in TEAM_ENTITLEMENTS} - {"forms"} | {"tunnels"}
    assert set(claims.entitlements) == expected
    assert claims.limits == LicenseLimits(
        max_users=25, max_workspaces=3, max_concurrent_workflows=10
    )
    assert claims.deployment_id == DEPLOYMENT_ID
    assert claims.expires_at - claims.issued_at == timedelta(days=365)


@pytest.mark.parametrize(
    ("args", "days"),
    [
        (["--plan", "pilot"], 60),
        (["--plan", "enterprise"], 365),
        (["--plan", "pilot", "--days", "14"], 14),
    ],
)
def test_license_tool_default_validity(
    key_files: tuple[Ed25519PrivateKey, Path],
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    days: int,
) -> None:
    private_key, private_path = key_files

    assert _issue(private_path, *args) == 0
    claims = decode_license(capsys.readouterr().out.strip(), private_key.public_key())

    assert claims.expires_at - claims.issued_at == timedelta(days=days)


def test_license_tool_mssp_includes_multi_tenant(
    key_files: tuple[Ed25519PrivateKey, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    private_key, private_path = key_files

    assert _issue(private_path, "--plan", "mssp", "--max-organizations", "20") == 0
    claims = decode_license(capsys.readouterr().out.strip(), private_key.public_key())

    assert "multi_tenant" in claims.entitlements
    assert claims.limits == LicenseLimits(max_organizations=20)


@pytest.mark.parametrize(
    "args",
    [
        ["--plan", "team", "--add", "not_real"],
        ["--plan", "team", "--remove", "not_real"],
        ["--plan", "team", "--max-users", "0"],
    ],
)
def test_license_tool_rejects_bad_issue_arguments(
    key_files: tuple[Ed25519PrivateKey, Path], args: list[str]
) -> None:
    _, private_path = key_files

    assert _issue(private_path, *args) == 2


@pytest.mark.parametrize(
    "args",
    [
        ["--plan", "community"],
        ["--expires", "2030-01-01", "--days", "10"],
    ],
)
def test_license_tool_rejects_invalid_flag_combinations(
    key_files: tuple[Ed25519PrivateKey, Path], args: list[str]
) -> None:
    _, private_path = key_files

    with pytest.raises(SystemExit) as exc_info:
        _issue(private_path, *args)

    assert exc_info.value.code == 2


def test_license_tool_ledger_records_metadata_without_token(
    key_files: tuple[Ed25519PrivateKey, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, private_path = key_files
    ledger = tmp_path / "ledger.csv"

    assert (
        _issue(
            private_path,
            "--plan",
            "business",
            "--max-users",
            "50",
            "--deployment-id",
            DEPLOYMENT_ID,
            "--ledger",
            str(ledger),
        )
        == 0
    )
    first_token = capsys.readouterr().out.strip()
    assert _issue(private_path, "--plan", "pilot", "--ledger", str(ledger)) == 0
    second_token = capsys.readouterr().out.strip()

    content = ledger.read_text()
    with ledger.open(newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 2
    assert list(rows[0]) == list(license_tool.LEDGER_FIELDS)
    assert rows[0]["customer"] == "Synthetic Customer"
    assert rows[0]["plan"] == "business"
    assert rows[0]["deployment_id"] == DEPLOYMENT_ID
    assert orjson.loads(rows[0]["limits"]) == {"max_users": 50}
    assert "rbac_addons" in rows[0]["entitlements"].split()
    assert rows[1]["plan"] == "pilot"
    assert rows[1]["deployment_id"] == ""
    for token in (first_token, second_token):
        payload_part, signature_part = token.split(".")
        assert token not in content
        assert payload_part not in content
        assert signature_part not in content
    assert "PRIVATE KEY" not in content


def test_license_tool_inspect_prints_new_fields(
    key_files: tuple[Ed25519PrivateKey, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_key, private_path = key_files
    public_path = tmp_path / "public.pem"
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
    )
    assert (
        _issue(
            private_path,
            "--plan",
            "team",
            "--max-users",
            "5",
            "--deployment-id",
            DEPLOYMENT_ID,
        )
        == 0
    )
    token = capsys.readouterr().out.strip()

    assert license_tool.main(["inspect", token, "--public-key", str(public_path)]) == 0
    report = orjson.loads(capsys.readouterr().out)
    assert report["plan"] == "team"
    assert report["deployment_id"] == DEPLOYMENT_ID
    assert report["limits"] == {"max_users": 5}

    mismatch = [
        "inspect",
        token,
        "--public-key",
        str(public_path),
        "--deployment-id",
        OTHER_DEPLOYMENT_ID,
    ]
    assert license_tool.main(mismatch) == 1
    assert orjson.loads(capsys.readouterr().out)["error"] == "deployment_mismatch"


# --- API responses ------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_admin_license_endpoint_reports_limits_usage_and_deployment(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    claims = _claims(
        days=10,
        limits=LicenseLimits(max_users=10, max_workspaces=2),
        deployment_id=DEPLOYMENT_ID,
        plan=LicensePlan.BUSINESS,
    )
    _install(monkeypatch, embedded_key, claims)
    license_deployment.set_cached_deployment_id(DEPLOYMENT_ID)
    monkeypatch.setattr(
        admin_license_router,
        "ensure_deployment_id",
        AsyncMock(return_value=DEPLOYMENT_ID),
    )
    monkeypatch.setattr(
        admin_license_router, "count_active_users", AsyncMock(return_value=7)
    )
    monkeypatch.setattr(
        admin_license_router, "count_workspaces", AsyncMock(return_value=2)
    )
    monkeypatch.setattr(
        admin_license_router, "count_organizations", AsyncMock(return_value=1)
    )
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")

    result = await get_license(role, AsyncMock())

    body = result.model_dump(mode="json")
    assert body["status"] == "valid"
    assert body["plan"] == "business"
    assert body["customer"] == "Synthetic Customer"
    assert body["days_remaining"] == 9
    assert body["notice"] == "expiring"
    assert body["limits"]["max_users"] == 10
    assert body["limits"]["max_workspaces"] == 2
    assert body["limits"]["max_concurrent_workflows"] is None
    assert body["usage"] == {"users": 7, "workspaces": 2, "organizations": 1}
    assert body["deployment_id"] == DEPLOYMENT_ID
    assert body["license_deployment_id"] == DEPLOYMENT_ID
    assert body["grace_ends_at"] is not None


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_admin_license_endpoint_reports_deployment_id_without_license(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", None)
    monkeypatch.setattr(
        admin_license_router,
        "ensure_deployment_id",
        AsyncMock(return_value=DEPLOYMENT_ID),
    )
    for name in ("count_active_users", "count_workspaces", "count_organizations"):
        monkeypatch.setattr(admin_license_router, name, AsyncMock(return_value=1))
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")

    result = await get_license(role, AsyncMock())

    assert result.status == LicenseStatus.MISSING
    assert result.deployment_id == DEPLOYMENT_ID
    assert result.notice is None
    assert result.limits == LicenseLimits()
    assert result.days_remaining is None


def _org_admin_role() -> Role:
    return Role(
        type="user",
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        service_id="autosecops-api",
        scopes=frozenset({"org:settings:update"}),
    )


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
@pytest.mark.parametrize(
    ("days", "level"),
    [
        (90, None),
        (10, LicenseNoticeLevel.EXPIRING),
        (-3, LicenseNoticeLevel.GRACE),
        (-30, LicenseNoticeLevel.EXPIRED),
    ],
)
async def test_org_license_notice_levels(
    monkeypatch: pytest.MonkeyPatch,
    embedded_key: Ed25519PrivateKey,
    days: int,
    level: LicenseNoticeLevel | None,
) -> None:
    now = datetime.now(UTC)
    claims = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=now - timedelta(days=400),
        expires_at=now + timedelta(days=days, hours=1),
        plan=LicensePlan.TEAM,
    )
    _install(monkeypatch, embedded_key, claims)

    notice = await organization_router.get_organization_license_notice(
        role=_org_admin_role()
    )

    assert notice.level == level
    if level is None:
        assert notice.status is None
    else:
        assert notice.plan == LicensePlan.TEAM
        assert notice.days_remaining == days


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_org_license_notice_hidden_for_community_installs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", None)

    notice = await organization_router.get_organization_license_notice(
        role=_org_admin_role()
    )

    assert notice.level is None


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_org_license_notice_reports_invalid_key(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _install(monkeypatch, embedded_key, _claims(deployment_id=DEPLOYMENT_ID))
    license_deployment.set_cached_deployment_id(OTHER_DEPLOYMENT_ID)

    notice = await organization_router.get_organization_license_notice(
        role=_org_admin_role()
    )

    assert notice.level == LicenseNoticeLevel.INVALID
    assert notice.status == LicenseStatus.INVALID


@pytest.mark.anyio
async def test_org_license_notice_hidden_in_multi_tenant_mode(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    _install(monkeypatch, embedded_key, _claims(days=5))

    notice = await organization_router.get_organization_license_notice(
        role=_org_admin_role()
    )

    assert notice.level is None
