"""License key loading, deployment binding storage, and limits on a real DB.

Existing enforcement tests replace the counters with mocks; these run the real
counting queries and advisory lock against PostgreSQL so a regression in what
counts toward a limit (inactive users, other tables) is caught.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from unittest.mock import AsyncMock

import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.db.models import Organization, PlatformSetting, User, Workspace
from autosecops.exceptions import LicenseLimitExceeded
from autosecops.licensing import deployment as license_deployment
from autosecops.licensing import enforcement
from autosecops.licensing.deployment import (
    DEPLOYMENT_ID_SETTING_KEY,
    _decode_setting_value,
    ensure_deployment_id,
    load_or_create_deployment_id,
)
from autosecops.licensing.token import load_private_key, load_public_key
from autosecops.licensing.types import (
    LicenseLimitName,
    LicenseLimits,
    LicenseState,
    LicenseStatus,
)

# --- Key loading ---------------------------------------------------------------


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_public_key_loader_rejects_non_ed25519_keys() -> None:
    pem = (
        _ec_key()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(ValueError, match="Ed25519"):
        load_public_key(pem)


def test_private_key_loader_rejects_non_ed25519_keys() -> None:
    pem = _ec_key().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    with pytest.raises(ValueError, match="Ed25519"):
        load_private_key(pem)


def test_key_loaders_round_trip_ed25519() -> None:
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    loaded = load_private_key(private_pem)
    signature = loaded.sign(b"payload")
    load_public_key(public_pem).verify(signature, b"payload")


# --- Deployment ID storage -----------------------------------------------------


@pytest.fixture(autouse=True)
def reset_deployment_cache() -> Iterator[None]:
    license_deployment.set_cached_deployment_id(None)
    yield
    license_deployment.set_cached_deployment_id(None)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (orjson.dumps("dep_abc"), "dep_abc"),
        (orjson.dumps(""), None),
        (orjson.dumps(42), None),
        (orjson.dumps(None), None),
        (b"{not json", None),
    ],
)
def test_decode_setting_value_accepts_only_non_empty_strings(
    raw: bytes, expected: str | None
) -> None:
    assert _decode_setting_value(raw) == expected


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_unreadable_deployment_id_raises_and_is_never_overwritten(
    session: AsyncSession,
) -> None:
    """Overwriting the row would silently unbind every license issued for it."""
    corrupt = b"{corrupt"
    await session.execute(
        insert(PlatformSetting)
        .values(
            id=uuid.uuid4(),
            key=DEPLOYMENT_ID_SETTING_KEY,
            value=corrupt,
            value_type="json",
            is_encrypted=False,
        )
        .on_conflict_do_update(
            index_elements=[PlatformSetting.key], set_={"value": corrupt}
        )
    )

    with pytest.raises(RuntimeError, match="unreadable"):
        await load_or_create_deployment_id(session)

    stored = (
        await session.execute(
            select(PlatformSetting.value).where(
                PlatformSetting.key == DEPLOYMENT_ID_SETTING_KEY
            )
        )
    ).scalar_one()
    assert stored == corrupt


@pytest.mark.anyio
async def test_ensure_deployment_id_loads_once_per_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loader = AsyncMock(return_value="dep_" + "1" * 32)
    monkeypatch.setattr(license_deployment, "load_or_create_deployment_id", loader)

    assert await ensure_deployment_id() == "dep_" + "1" * 32
    assert await ensure_deployment_id() == "dep_" + "1" * 32

    assert loader.await_count == 1
    assert license_deployment.get_cached_deployment_id() == "dep_" + "1" * 32


# --- Limits counted on the real database --------------------------------------


def _install_limits(monkeypatch: pytest.MonkeyPatch, limits: LicenseLimits) -> None:
    state = LicenseState(status=LicenseStatus.VALID, limits=limits)
    monkeypatch.setattr(enforcement, "get_license_state", lambda log: state)
    monkeypatch.setattr(enforcement, "ensure_license_deployment_loaded", AsyncMock())


def _user(*, active: bool) -> User:
    return User(
        id=uuid.uuid4(),
        email=f"limit-{uuid.uuid4().hex[:10]}@example.com",
        hashed_password="x",
        is_active=active,
    )


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_inactive_users_do_not_count_toward_the_user_limit(
    session: AsyncSession,
) -> None:
    before = await enforcement.count_active_users(session)
    session.add_all([_user(active=True), _user(active=False), _user(active=False)])
    await session.flush()

    assert await enforcement.count_active_users(session) == before + 1


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_workspace_and_organization_counts_track_new_rows(
    session: AsyncSession,
) -> None:
    workspaces_before = await enforcement.count_workspaces(session)
    orgs_before = await enforcement.count_organizations(session)

    org_id = uuid.uuid4()
    session.add(
        Organization(id=org_id, name="Limit org", slug=f"limit-{org_id.hex[:12]}")
    )
    await session.flush()
    session.add(Workspace(id=uuid.uuid4(), name="Limit ws", organization_id=org_id))
    await session.flush()

    assert await enforcement.count_workspaces(session) == workspaces_before + 1
    assert await enforcement.count_organizations(session) == orgs_before + 1


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_user_limit_is_enforced_with_real_counts_and_lock(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    current = await enforcement.count_active_users(session)

    _install_limits(monkeypatch, LicenseLimits(max_users=current + 1))
    await enforcement.enforce_user_limit(session)  # one free seat

    session.add(_user(active=True))
    await session.flush()
    with pytest.raises(LicenseLimitExceeded) as exc_info:
        await enforcement.enforce_user_limit(session)
    assert (exc_info.value.current, exc_info.value.maximum) == (
        current + 1,
        current + 1,
    )

    # Deactivated accounts free their seat again.
    session.add(_user(active=False))
    await session.flush()
    with pytest.raises(LicenseLimitExceeded):
        await enforcement.enforce_user_limit(session)


@pytest.mark.anyio
async def test_only_creation_limits_have_a_licensed_maximum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_limits(
        monkeypatch,
        LicenseLimits(max_users=1, max_workspaces=2, max_organizations=3),
    )
    assert await enforcement._licensed_maximum(LicenseLimitName.MAX_USERS) == 1
    assert await enforcement._licensed_maximum(LicenseLimitName.MAX_WORKSPACES) == 2
    assert await enforcement._licensed_maximum(LicenseLimitName.MAX_ORGANIZATIONS) == 3
    with pytest.raises(ValueError, match="not a creation limit"):
        await enforcement._licensed_maximum(LicenseLimitName.MAX_CONCURRENT_WORKFLOWS)


def test_each_limit_locks_independently() -> None:
    keys = {enforcement._advisory_lock_key(limit) for limit in LicenseLimitName}
    assert len(keys) == len(LicenseLimitName)
    assert all(-(2**31) <= key < 2**31 for key in keys)
