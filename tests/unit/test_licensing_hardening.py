"""Tests for the multi-tenant license fail-safe and clock-rollback resistance."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from autosecops import config
from autosecops.admin.license import router as admin_license_router
from autosecops.admin.license import service as admin_license_service
from autosecops.admin.license.router import get_license
from autosecops.admin.license.router import (
    reset_license_clock as reset_license_clock_endpoint,
)
from autosecops.api.app import multi_tenant_license_lapsed_exception_handler
from autosecops.auth.types import PlatformRole
from autosecops.db.models import PlatformSetting
from autosecops.exceptions import MultiTenantLicenseLapsed
from autosecops.licensing import clock as license_clock
from autosecops.licensing import keys
from autosecops.licensing import multi_tenant as license_multi_tenant
from autosecops.licensing import service as license_service
from autosecops.licensing.clock import (
    CLOCK_FORWARD_JUMP_SETTLE_TIME,
    CLOCK_PERSIST_INTERVAL,
    CLOCK_SETTLE_TIME,
    LICENSE_CLOCK_RESET_SETTING_KEY,
    LICENSE_CLOCK_ROLLBACK_SETTING_KEY,
    LICENSE_CLOCK_SETTING_KEY,
    ClockRollback,
    DeploymentClockStatus,
    LicenseClockResetError,
    effective_now,
    get_license_clock_status,
    persist_high_water,
    read_deployment_clock_status,
    refresh_license_clock,
    reset_high_water,
    reset_license_clock,
)
from autosecops.licensing.evaluation import (
    LICENSE_GRACE_PERIOD,
    license_permits_multi_tenant_mode,
)
from autosecops.licensing.multi_tenant import (
    MultiTenantLicenseRequiredError,
    check_multi_tenant_license_on_startup,
    ensure_new_organizations_allowed,
    get_multi_tenant_mode,
    run_license_monitor,
)
from autosecops.licensing.token import encode_license
from autosecops.licensing.types import (
    LicenseClaims,
    LicenseStatus,
    MultiTenantMode,
)
from autosecops.organization import management as organization_management
from autosecops.organization.management import create_organization

NOW = datetime(2026, 6, 1, tzinfo=UTC)


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


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


class FakeMonotonic:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta.total_seconds()


@pytest.fixture(autouse=True)
def mono(monkeypatch: pytest.MonkeyPatch) -> FakeMonotonic:
    fake = FakeMonotonic()
    monkeypatch.setattr(license_clock, "_monotonic", fake)
    return fake


@pytest.fixture(autouse=True)
def fresh_clock(mono: FakeMonotonic) -> Iterator[None]:
    """Each test starts with no high-water mark and no pending refresh."""
    reset_license_clock()
    yield
    reset_license_clock()


@pytest.fixture
def clock_db(monkeypatch: pytest.MonkeyPatch, session: AsyncSession) -> AsyncSession:
    """Route the clock's own sessions to the test session."""

    @asynccontextmanager
    async def _session() -> AsyncIterator[AsyncSession]:
        yield session

    monkeypatch.setattr(
        license_clock, "get_async_session_bypass_rls_context_manager", _session
    )
    return session


def _token(
    key: Ed25519PrivateKey,
    *,
    entitlements: list[str],
    expires_at: datetime,
    issued_at: datetime | None = None,
) -> str:
    return encode_license(
        LicenseClaims(
            license_id="lic_test",
            customer="Synthetic Customer",
            issued_at=issued_at or expires_at - timedelta(days=365),
            expires_at=expires_at,
            entitlements=entitlements,
        ),
        key,
    )


def _install(monkeypatch: pytest.MonkeyPatch, token: str | None) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", token)


def _multi_tenant(monkeypatch: pytest.MonkeyPatch, *, requested: bool = True) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT_REQUESTED", requested)
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", requested)


# --- Import-time decision ------------------------------------------------------


@pytest.mark.parametrize(
    ("expires_in", "entitlements", "expected"),
    [
        pytest.param(timedelta(days=30), ["multi_tenant"], True, id="valid"),
        pytest.param(timedelta(days=-1), ["multi_tenant"], True, id="grace"),
        pytest.param(
            -(LICENSE_GRACE_PERIOD + timedelta(days=1)),
            ["multi_tenant"],
            True,
            id="past-grace-stays-multi-tenant",
        ),
        pytest.param(timedelta(days=30), ["git_sync"], False, id="no-grant"),
    ],
)
def test_license_permits_multi_tenant_mode(
    embedded_key: Ed25519PrivateKey,
    expires_in: timedelta,
    entitlements: list[str],
    expected: bool,
) -> None:
    token = _token(embedded_key, entitlements=entitlements, expires_at=NOW + expires_in)

    assert license_permits_multi_tenant_mode(token, now=NOW) is expected


def test_invalid_or_missing_license_never_permits_multi_tenant_mode(
    embedded_key: Ed25519PrivateKey,
) -> None:
    other_key = Ed25519PrivateKey.generate()
    foreign = _token(
        other_key, entitlements=["multi_tenant"], expires_at=NOW + timedelta(days=30)
    )
    future = _token(
        embedded_key,
        entitlements=["multi_tenant"],
        issued_at=NOW + timedelta(days=1),
        expires_at=NOW + timedelta(days=30),
    )

    assert not license_permits_multi_tenant_mode(None, now=NOW)
    assert not license_permits_multi_tenant_mode("garbage", now=NOW)
    assert not license_permits_multi_tenant_mode(foreign, now=NOW)
    assert not license_permits_multi_tenant_mode(future, now=NOW)


# --- Runtime mode and organization creation --------------------------------------


def test_multi_tenant_mode_reports_off_active_and_lapsed(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    now = datetime.now(UTC)
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    assert get_multi_tenant_mode() is MultiTenantMode.OFF

    _multi_tenant(monkeypatch)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=now + timedelta(days=30),
        ),
    )
    assert get_multi_tenant_mode() is MultiTenantMode.ACTIVE

    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=now - LICENSE_GRACE_PERIOD - timedelta(days=1),
        ),
    )
    assert get_multi_tenant_mode() is MultiTenantMode.LAPSED


@pytest.mark.anyio
async def test_lapsed_multi_tenant_blocks_new_organizations(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _multi_tenant(monkeypatch)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=datetime.now(UTC) - LICENSE_GRACE_PERIOD - timedelta(days=1),
        ),
    )
    monkeypatch.setattr(
        organization_management, "ensure_license_deployment_loaded", AsyncMock()
    )
    session = AsyncMock()
    session.add = MagicMock()

    with pytest.raises(MultiTenantLicenseLapsed) as exc_info:
        await create_organization(session, name="Synthetic Org", slug="synthetic")

    session.add.assert_not_called()
    assert exc_info.value.detail == {"grant": "multi_tenant"}
    assert "info@singularityrd.com" in str(exc_info.value)


def test_active_multi_tenant_allows_new_organizations(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _multi_tenant(monkeypatch)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
    )

    ensure_new_organizations_allowed()


def test_lapsed_exception_handler_returns_403_with_type() -> None:
    request = Request(
        {"type": "http", "method": "POST", "path": "/organizations", "headers": []}
    )

    response = multi_tenant_license_lapsed_exception_handler(
        request, MultiTenantLicenseLapsed(contact="info@singularityrd.com")
    )

    assert response.status_code == 403
    body = orjson.loads(bytes(response.body))
    assert body["type"] == "MultiTenantLicenseLapsed"
    assert body["detail"] == {"grant": "multi_tenant"}


# --- Startup check -----------------------------------------------------------------


@pytest.mark.anyio
async def test_startup_refuses_to_strand_tenants_without_a_license(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    """Requested multi-tenant with several orgs and no grant must not degrade."""
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT_REQUESTED", True)
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    _install(monkeypatch, None)
    monkeypatch.setattr(
        license_multi_tenant, "count_organizations", AsyncMock(return_value=3)
    )

    with pytest.raises(MultiTenantLicenseRequiredError, match="3 organizations"):
        await check_multi_tenant_license_on_startup(AsyncMock())


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("requested", "organizations"), [(True, 1), (True, 0), (False, 5)]
)
async def test_startup_allows_single_tenant_when_no_tenant_is_stranded(
    monkeypatch: pytest.MonkeyPatch,
    embedded_key: Ed25519PrivateKey,
    requested: bool,
    organizations: int,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT_REQUESTED", requested)
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    _install(monkeypatch, None)
    monkeypatch.setattr(
        license_multi_tenant,
        "count_organizations",
        AsyncMock(return_value=organizations),
    )

    await check_multi_tenant_license_on_startup(AsyncMock())


@pytest.mark.anyio
async def test_startup_logs_lapsed_multi_tenant_and_keeps_running(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _multi_tenant(monkeypatch)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=datetime.now(UTC) - LICENSE_GRACE_PERIOD - timedelta(days=1),
        ),
    )
    count = AsyncMock(return_value=4)
    monkeypatch.setattr(license_multi_tenant, "count_organizations", count)
    mock_logger = MagicMock()
    monkeypatch.setattr(license_multi_tenant, "logger", mock_logger)

    await check_multi_tenant_license_on_startup(AsyncMock())

    messages = [call.args[0] for call in mock_logger.error.call_args_list]
    assert any("MULTI-TENANT LICENSE LAPSED" in message for message in messages)
    count.assert_not_awaited()


@pytest.mark.anyio
async def test_license_monitor_runs_a_pass_and_stops(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _multi_tenant(monkeypatch)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=datetime.now(UTC) - LICENSE_GRACE_PERIOD - timedelta(days=1),
        ),
    )
    refresh = AsyncMock()
    monkeypatch.setattr(license_multi_tenant, "refresh_license_clock", refresh)
    mock_logger = MagicMock()
    monkeypatch.setattr(license_multi_tenant, "logger", mock_logger)
    stop = asyncio.Event()

    task = asyncio.create_task(run_license_monitor(stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=5)

    refresh.assert_awaited_once()
    assert mock_logger.error.called


@pytest.mark.anyio
async def test_license_monitor_does_not_log_single_tenant_expiry_when_lapsed(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    """Lapsed tenants keep their tiers, so "entitlements are disabled" is false."""
    _multi_tenant(monkeypatch)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=datetime.now(UTC) - LICENSE_GRACE_PERIOD - timedelta(days=1),
        ),
    )
    monkeypatch.setattr(license_multi_tenant, "refresh_license_clock", AsyncMock())
    monkeypatch.setattr(license_multi_tenant, "logger", MagicMock())
    service_logger = MagicMock()
    monkeypatch.setattr(license_service, "logger", service_logger)
    stop = asyncio.Event()

    task = asyncio.create_task(run_license_monitor(stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=5)

    service_logger.error.assert_not_called()


# --- Admin status ----------------------------------------------------------------


_NO_CLOCK_ISSUES = DeploymentClockStatus(
    high_water=None, rollback=None, rollback_first_detected_at=None, last_reset_at=None
)


async def _admin_license(
    monkeypatch: pytest.MonkeyPatch,
    clock: DeploymentClockStatus = _NO_CLOCK_ISSUES,
):
    monkeypatch.setattr(
        admin_license_router,
        "read_deployment_clock_status",
        AsyncMock(return_value=clock),
    )
    monkeypatch.setattr(
        admin_license_router,
        "ensure_deployment_id",
        AsyncMock(return_value="dep_" + "0" * 32),
    )
    monkeypatch.setattr(admin_license_router, "ensure_license_clock_fresh", AsyncMock())
    for name in ("count_active_users", "count_workspaces", "count_organizations"):
        monkeypatch.setattr(admin_license_router, name, AsyncMock(return_value=2))
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")
    return await get_license(role, AsyncMock())


@pytest.mark.anyio
async def test_admin_status_reports_lapsed_multi_tenant(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _multi_tenant(monkeypatch)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["multi_tenant"],
            expires_at=datetime.now(UTC) - LICENSE_GRACE_PERIOD - timedelta(days=1),
        ),
    )

    result = await _admin_license(monkeypatch)

    assert result.multi_tenant_requested is True
    assert result.multi_tenant_mode is MultiTenantMode.LAPSED
    assert result.status is LicenseStatus.EXPIRED


@pytest.mark.anyio
async def test_admin_status_reports_clock_rollback(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    _install(monkeypatch, None)
    now = datetime.now(UTC)
    future = now + timedelta(days=2)
    clock = DeploymentClockStatus(
        high_water=future,
        rollback=ClockRollback(observed_at=now, high_water=future),
        rollback_first_detected_at=now - timedelta(hours=3),
        last_reset_at=None,
    )

    result = await _admin_license(monkeypatch, clock)

    assert result.clock_high_water == future
    assert result.clock_rollback_detected_at == now - timedelta(hours=3)
    assert result.clock_rollback_seconds == int(timedelta(days=2).total_seconds())


@pytest.mark.anyio
async def test_admin_clock_reset_is_audited_and_refused_with_409(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The reset runs through the fail-closed audit decorator.
    assert hasattr(admin_license_service.reset_license_clock_high_water, "__wrapped__")
    refused = AsyncMock(side_effect=LicenseClockResetError("nothing to reset"))
    monkeypatch.setattr(admin_license_router, "reset_license_clock_high_water", refused)
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")

    with pytest.raises(HTTPException) as exc_info:
        await reset_license_clock_endpoint(role, AsyncMock())

    assert exc_info.value.status_code == 409

    monkeypatch.setattr(
        admin_license_router,
        "reset_license_clock_high_water",
        AsyncMock(return_value=NOW),
    )
    result = await reset_license_clock_endpoint(role, AsyncMock())
    assert result.clock_high_water == NOW


# --- Clock high-water mark ------------------------------------------------------------


def test_effective_now_never_moves_backwards_in_process(
    monkeypatch: pytest.MonkeyPatch, mono: FakeMonotonic
) -> None:
    mock_logger = MagicMock()
    monkeypatch.setattr(license_clock, "logger", mock_logger)
    # The process has loaded (or trusted) the mark NOW.
    reset_license_clock(high_water=NOW)

    assert effective_now(NOW) == NOW
    # A small step back within the tolerance is held but not reported.
    assert effective_now(NOW - timedelta(minutes=1)) == NOW
    assert get_license_clock_status().rollback is None
    # A large step back is held and reported once.
    assert effective_now(NOW - timedelta(days=30)) == NOW
    assert effective_now(NOW - timedelta(days=29)) == NOW
    rollback = get_license_clock_status().rollback
    assert rollback is not None
    assert rollback.behind == timedelta(days=30)
    assert mock_logger.error.call_count == 1
    # The mark keeps moving with real (monotonic) time while the clock is wrong.
    mono.advance(timedelta(hours=1))
    assert effective_now(NOW - timedelta(days=30)) == NOW + timedelta(hours=1)
    # Once the clock is fixed, the rollback clears without a restart.
    fixed = NOW + timedelta(hours=1)
    assert effective_now(fixed) == fixed
    assert get_license_clock_status().rollback is None
    mock_logger.info.assert_called_once()


def test_transient_future_reading_does_not_stick(
    monkeypatch: pytest.MonkeyPatch, mono: FakeMonotonic
) -> None:
    """A host clock that reads years ahead until NTP syncs must not stick."""
    monkeypatch.setattr(license_clock, "logger", MagicMock())
    reset_license_clock(high_water=NOW)
    glitch = NOW + timedelta(days=5 * 365)

    assert effective_now(glitch) == glitch
    mono.advance(timedelta(seconds=5))
    # NTP stepped the clock back: license time follows real time again.
    corrected = NOW + timedelta(seconds=5)
    assert effective_now(corrected) == corrected
    assert get_license_clock_status().high_water == corrected
    assert get_license_clock_status().rollback is None


def test_steady_forward_reading_is_trusted_after_settling(
    monkeypatch: pytest.MonkeyPatch, mono: FakeMonotonic
) -> None:
    monkeypatch.setattr(license_clock, "logger", MagicMock())
    reset_license_clock(high_water=NOW)
    ahead = NOW + timedelta(days=3)

    effective_now(ahead)
    mono.advance(CLOCK_SETTLE_TIME)
    settled = ahead + CLOCK_SETTLE_TIME
    assert effective_now(settled) == settled
    # Now trusted, a rollback to the old time is held at the new mark.
    assert effective_now(NOW) == settled


def test_rolled_back_clock_cannot_revive_an_expired_license(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    real_now = datetime.now(UTC)
    _install(
        monkeypatch,
        _token(
            embedded_key,
            entitlements=["git_sync"],
            expires_at=real_now - LICENSE_GRACE_PERIOD - timedelta(days=1),
        ),
    )
    monkeypatch.setattr(license_clock, "logger", MagicMock())
    # The deployment has already observed the real time ...
    reset_license_clock(high_water=real_now)

    # ... so a wall clock set back before the expiry does not help.
    rolled_back = real_now - timedelta(days=60)
    state = license_service.get_license_state(
        license_clock.effective_now(rolled_back), log=False
    )
    assert state.status is LicenseStatus.EXPIRED
    assert not state.granted

    # Without a high-water mark, the same rollback would have revived it.
    revived = license_service.get_license_state(rolled_back, log=False)
    assert revived.status is LicenseStatus.VALID


async def _stored_high_water(session: AsyncSession) -> datetime:
    value = (
        await session.execute(
            select(PlatformSetting.value).where(
                PlatformSetting.key == LICENSE_CLOCK_SETTING_KEY
            )
        )
    ).scalar_one()
    return datetime.fromisoformat(orjson.loads(value))


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_high_water_is_persisted_hourly_and_never_decreases(
    session: AsyncSession,
) -> None:
    assert await persist_high_water(session, NOW) == NOW
    assert await _stored_high_water(session) == NOW

    # Within the persist interval nothing is written.
    within = NOW + CLOCK_PERSIST_INTERVAL - timedelta(minutes=1)
    assert await persist_high_water(session, within) == within
    assert await _stored_high_water(session) == NOW

    # After the interval the newer time is written.
    after = NOW + CLOCK_PERSIST_INTERVAL
    assert await persist_high_water(session, after) == after
    assert await _stored_high_water(session) == after

    # A rolled-back clock never lowers the stored value.
    assert await persist_high_water(session, NOW - timedelta(days=30)) == after
    assert await _stored_high_water(session) == after


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_unreadable_high_water_is_reset_to_now(session: AsyncSession) -> None:
    await session.execute(
        insert(PlatformSetting)
        .values(
            id=uuid.uuid4(),
            key=LICENSE_CLOCK_SETTING_KEY,
            value=b"{corrupt",
            value_type="json",
            is_encrypted=False,
        )
        .on_conflict_do_update(
            index_elements=[PlatformSetting.key], set_={"value": b"{corrupt"}
        )
    )

    assert await persist_high_water(session, NOW) == NOW
    assert await _stored_high_water(session) == NOW


async def _store_high_water(session: AsyncSession, value: datetime) -> None:
    encoded = orjson.dumps(value.isoformat())
    await session.execute(
        insert(PlatformSetting)
        .values(
            id=uuid.uuid4(),
            key=LICENSE_CLOCK_SETTING_KEY,
            value=encoded,
            value_type="json",
            is_encrypted=False,
        )
        .on_conflict_do_update(
            index_elements=[PlatformSetting.key], set_={"value": encoded}
        )
    )
    await session.commit()


async def _setting_exists(session: AsyncSession, key: str) -> bool:
    stmt = select(PlatformSetting.id).where(PlatformSetting.key == key)
    return (await session.execute(stmt)).scalar_one_or_none() is not None


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_far_forward_reading_needs_a_long_steady_clock_to_persist(
    session: AsyncSession,
) -> None:
    await persist_high_water(session, NOW)
    glitch = NOW + timedelta(days=5 * 365)

    assert await persist_high_water(session, glitch) == NOW
    assert await _stored_high_water(session) == NOW

    assert await persist_high_water(session, glitch, allow_forward_jump=True) == glitch
    assert await _stored_high_water(session) == glitch


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_refresh_never_persists_an_unsteady_reading(
    monkeypatch: pytest.MonkeyPatch, clock_db: AsyncSession, mono: FakeMonotonic
) -> None:
    """A future clock at process start never reaches the deployment mark."""
    monkeypatch.setattr(license_clock, "logger", MagicMock())
    await _store_high_water(clock_db, NOW)
    glitch = NOW + timedelta(days=5 * 365)

    status = await refresh_license_clock(now=glitch)
    assert await _stored_high_water(clock_db) == NOW
    assert status.high_water == NOW

    # Steady for the settle time, but still far ahead of the stored mark.
    mono.advance(CLOCK_SETTLE_TIME)
    await refresh_license_clock(now=glitch + CLOCK_SETTLE_TIME)
    assert await _stored_high_water(clock_db) == NOW

    # A clock that stays steady for an hour is believed (a long outage).
    mono.advance(CLOCK_FORWARD_JUMP_SETTLE_TIME)
    steady = glitch + CLOCK_SETTLE_TIME + CLOCK_FORWARD_JUMP_SETTLE_TIME
    await refresh_license_clock(now=steady)
    assert await _stored_high_water(clock_db) == steady


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_refresh_persists_a_steady_reading(
    clock_db: AsyncSession, mono: FakeMonotonic
) -> None:
    await refresh_license_clock(now=NOW)
    assert not await _setting_exists(clock_db, LICENSE_CLOCK_SETTING_KEY)

    mono.advance(CLOCK_SETTLE_TIME)
    steady = NOW + CLOCK_SETTLE_TIME
    await refresh_license_clock(now=steady)
    assert await _stored_high_water(clock_db) == steady


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_rollback_is_shared_through_the_database_and_clears(
    monkeypatch: pytest.MonkeyPatch, clock_db: AsyncSession, mono: FakeMonotonic
) -> None:
    monkeypatch.setattr(license_clock, "logger", MagicMock())
    stored = NOW + timedelta(days=10)
    await _store_high_water(clock_db, stored)

    status = await refresh_license_clock(now=NOW)

    assert status.high_water == stored
    assert status.rollback is not None
    assert status.rollback.behind == timedelta(days=10)
    assert effective_now(NOW) == stored
    assert await _setting_exists(clock_db, LICENSE_CLOCK_ROLLBACK_SETTING_KEY)
    # Another replica, with no in-process state, reports the same rollback.
    later = NOW + timedelta(minutes=5)
    shared = await read_deployment_clock_status(clock_db, now=later)
    assert shared.rollback is not None
    assert shared.rollback_first_detected_at == NOW

    # The clock is fixed: every replica stops reporting it, no restart needed.
    mono.advance(timedelta(seconds=1))
    caught_up = stored + timedelta(seconds=1)
    status = await refresh_license_clock(now=caught_up)
    assert status.rollback is None
    assert not await _setting_exists(clock_db, LICENSE_CLOCK_ROLLBACK_SETTING_KEY)
    shared = await read_deployment_clock_status(clock_db, now=caught_up)
    assert shared.rollback is None
    assert shared.rollback_first_detected_at is None


@pytest.mark.anyio
async def test_concurrent_freshness_checks_refresh_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    release = asyncio.Event()

    async def slow_refresh() -> None:
        nonlocal calls
        calls += 1
        await release.wait()

    monkeypatch.setattr(license_clock, "refresh_license_clock", slow_refresh)

    waiters = [
        asyncio.create_task(license_clock.ensure_license_clock_fresh())
        for _ in range(40)
    ]
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(*waiters)

    assert calls == 1


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_superuser_reset_lowers_the_mark_everywhere(
    monkeypatch: pytest.MonkeyPatch, clock_db: AsyncSession, mono: FakeMonotonic
) -> None:
    monkeypatch.setattr(license_clock, "logger", MagicMock())
    glitch = NOW + timedelta(days=5 * 365)
    await _store_high_water(clock_db, glitch)
    await refresh_license_clock(now=NOW)
    assert effective_now(NOW) == glitch

    # The clock must be steady before the reset is accepted.
    with pytest.raises(LicenseClockResetError, match="steady"):
        await reset_high_water(clock_db, now=NOW)

    mono.advance(CLOCK_SETTLE_TIME)
    real = NOW + CLOCK_SETTLE_TIME
    assert await reset_high_water(clock_db, now=real) == real
    assert await _stored_high_water(clock_db) == real
    assert effective_now(real) == real
    status = await read_deployment_clock_status(clock_db, now=real)
    assert status.rollback is None
    assert status.last_reset_at == real

    # Nothing left to reset.
    with pytest.raises(LicenseClockResetError, match="nothing to reset"):
        await reset_high_water(clock_db, now=real)


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_other_processes_drop_their_mark_after_a_reset(
    monkeypatch: pytest.MonkeyPatch, clock_db: AsyncSession, mono: FakeMonotonic
) -> None:
    monkeypatch.setattr(license_clock, "logger", MagicMock())
    glitch = NOW + timedelta(days=5 * 365)
    await _store_high_water(clock_db, glitch)
    await refresh_license_clock(now=NOW)
    assert effective_now(NOW) == glitch

    # Another replica resets the mark ...
    await _store_high_water(clock_db, NOW)
    await clock_db.execute(
        insert(PlatformSetting).values(
            id=uuid.uuid4(),
            key=LICENSE_CLOCK_RESET_SETTING_KEY,
            value=orjson.dumps({"reset_id": "r1", "reset_at": NOW.isoformat()}),
            value_type="json",
            is_encrypted=False,
        )
    )
    await clock_db.commit()

    # ... and this process follows on its next refresh.
    mono.advance(timedelta(seconds=1))
    later = NOW + timedelta(seconds=1)
    status = await refresh_license_clock(now=later)
    assert status.rollback is None
    assert effective_now(later) == later


@pytest.mark.anyio
async def test_refresh_failure_is_logged_and_retried_later(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failing = AsyncMock(side_effect=OSError("db down"))
    monkeypatch.setattr(license_clock, "persist_high_water", failing)
    mock_logger = MagicMock()
    monkeypatch.setattr(license_clock, "logger", mock_logger)

    status = await refresh_license_clock(now=NOW)
    await license_clock.ensure_license_clock_fresh()

    assert status.rollback is None
    assert mock_logger.error.call_count == 1
    # The retry back-off stops ensure_license_clock_fresh from hammering the DB.
    assert failing.await_count == 1
