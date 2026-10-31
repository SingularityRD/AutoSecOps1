"""Tunnel gateway sync and reconcile decisions, against the test database."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest
from autosecops_ee.tunnels import gateways
from autosecops_ee.tunnels.k8s import GatewaySpec, KubernetesError
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.secrets import get_db_encryption_key
from autosecops.db.models import Organization, Workspace, WorkspaceTunnel
from autosecops.secrets.encryption import encrypt_value
from autosecops.tiers.enums import Entitlement

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]

SECRET = "machine-client-secret"
GATEWAY_KEY = "gateway-key-material"


@dataclass
class FakeGateways:
    """Records what the gateway layer asked Kubernetes to do."""

    applied: list[GatewaySpec] = field(default_factory=list)
    deleted: list[uuid.UUID] = field(default_factory=list)
    reconciled: list[list[GatewaySpec]] = field(default_factory=list)
    error: Exception | None = None
    is_ready: bool | None = True

    def __call__(self, _client: Any) -> FakeGateways:
        return self

    def _maybe_fail(self) -> None:
        if self.error is not None:
            raise self.error

    async def apply(self, spec: GatewaySpec) -> None:
        self._maybe_fail()
        self.applied.append(spec)

    async def delete(self, tunnel_id: uuid.UUID) -> None:
        self._maybe_fail()
        self.deleted.append(tunnel_id)

    async def ready(self, _tunnel_id: uuid.UUID) -> bool | None:
        self._maybe_fail()
        return self.is_ready

    async def reconcile(self, specs: list[GatewaySpec]) -> tuple[int, int]:
        self._maybe_fail()
        self.reconciled.append(specs)
        return len(specs), 1


class _Client:
    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None


@pytest.fixture
def k8s(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeGateways]:
    fake = FakeGateways()
    monkeypatch.setattr(config, "AUTOSECOPS__TUNNEL_GATEWAY_BACKEND", "kubernetes")
    monkeypatch.setattr(gateways, "KubernetesClient", _Client)
    monkeypatch.setattr(gateways, "KubernetesGateways", fake)
    yield fake


def _encrypt(value: str) -> bytes:
    return encrypt_value(value.encode(), key=get_db_encryption_key())


async def _tunnel(
    session: AsyncSession,
    workspace: Workspace,
    *,
    name: str,
    enabled: bool = True,
    gateway_key: str | None = GATEWAY_KEY,
) -> WorkspaceTunnel:
    tunnel = WorkspaceTunnel(
        workspace_id=workspace.id,
        name=name,
        endpoint="https://pangolin.example.com",
        client_id=f"client-{name}",
        encrypted_client_secret=_encrypt(SECRET),
        encrypted_gateway_key=None if gateway_key is None else _encrypt(gateway_key),
        allowed_targets=[{"host": "splunk.corp.example", "ports": [8089]}],
        enabled=enabled,
    )
    session.add(tunnel)
    await session.commit()
    return tunnel


async def test_gateway_backend_none_makes_every_call_a_no_op(
    session: AsyncSession, svc_workspace: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__TUNNEL_GATEWAY_BACKEND", "none")
    client = AsyncMock(side_effect=AssertionError("must not reach Kubernetes"))
    monkeypatch.setattr(gateways, "KubernetesClient", client)
    tunnel = await _tunnel(session, svc_workspace, name="noop")

    await gateways.sync_gateway(tunnel)
    await gateways.delete_gateway(tunnel.id)
    assert await gateways.gateway_ready(tunnel.id) is None
    with pytest.raises(gateways.TunnelGatewayUnavailableError):
        gateways.require_kubernetes_gateways()


async def test_invalid_gateway_backend_is_a_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__TUNNEL_GATEWAY_BACKEND", "docker")

    with pytest.raises(ValueError, match="must be 'kubernetes' or 'none'"):
        gateways.kubernetes_enabled()


async def test_sync_applies_decrypted_spec_or_deletes_keyless_gateway(
    session: AsyncSession, svc_workspace: Workspace, k8s: FakeGateways
) -> None:
    gateways.require_kubernetes_gateways()
    keyed = await _tunnel(session, svc_workspace, name="keyed", enabled=False)
    keyless = await _tunnel(session, svc_workspace, name="keyless", gateway_key=None)

    await gateways.sync_gateway(keyed)
    await gateways.sync_gateway(keyless)

    [spec] = k8s.applied
    assert spec.tunnel_id == keyed.id
    assert (spec.client_secret, spec.gateway_key) == (SECRET, GATEWAY_KEY)
    assert spec.enabled is False
    # Plaintext never appears in the spec's repr (and so never in logs).
    assert SECRET not in repr(spec) and GATEWAY_KEY not in repr(spec)
    assert k8s.deleted == [keyless.id]


async def test_kubernetes_failures_are_left_to_the_reconciler(
    session: AsyncSession, svc_workspace: Workspace, k8s: FakeGateways
) -> None:
    tunnel = await _tunnel(session, svc_workspace, name="flaky")
    k8s.error = KubernetesError(503, "apiserver unavailable")

    await gateways.sync_gateway(tunnel)
    await gateways.delete_gateway(tunnel.id)
    assert await gateways.gateway_ready(tunnel.id) is None

    k8s.error = OSError("connection reset")
    await gateways.sync_gateway(tunnel)
    assert await gateways.gateway_ready(tunnel.id) is None

    k8s.error = RuntimeError("programming error")
    with pytest.raises(RuntimeError):
        await gateways.sync_gateway(tunnel)


async def test_gateway_ready_reports_pod_state(
    k8s: FakeGateways,
) -> None:
    k8s.is_ready = False
    assert await gateways.gateway_ready(uuid.uuid4()) is False
    k8s.is_ready = None
    assert await gateways.gateway_ready(uuid.uuid4()) is None


async def test_desired_specs_scale_unentitled_and_disabled_tunnels_to_zero(
    session: AsyncSession,
    svc_workspace: Workspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unentitled_org = Organization(
        id=uuid.uuid4(), name="Lapsed", slug=f"lapsed-{uuid.uuid4().hex[:8]}"
    )
    session.add(unentitled_org)
    await session.flush()
    lapsed_workspace = Workspace(name="lapsed-ws", organization_id=unentitled_org.id)
    session.add(lapsed_workspace)
    await session.commit()

    live = await _tunnel(session, svc_workspace, name="live")
    disabled = await _tunnel(session, svc_workspace, name="disabled", enabled=False)
    keyless = await _tunnel(session, svc_workspace, name="pending", gateway_key=None)
    lapsed = await _tunnel(session, lapsed_workspace, name="lapsed")

    checked: list[tuple[uuid.UUID, Entitlement]] = []

    async def _entitled(
        _session: AsyncSession, org_id: uuid.UUID, entitlement: Entitlement
    ) -> bool:
        checked.append((org_id, entitlement))
        return org_id != unentitled_org.id

    monkeypatch.setattr(gateways, "is_org_entitled", _entitled)

    specs = {
        spec.tunnel_id: spec for spec in await gateways.desired_gateway_specs(session)
    }

    assert specs[live.id].enabled is True
    assert specs[disabled.id].enabled is False
    assert specs[lapsed.id].enabled is False
    assert keyless.id not in specs
    # Entitlement is checked once per organization, not once per tunnel.
    org_checks = [org for org, _ in checked]
    assert len(org_checks) == len(set(org_checks))
    assert {entitlement for _, entitlement in checked} == {Entitlement.TUNNELS}


async def test_reconcile_runs_only_while_holding_the_leader_lock(
    k8s: FakeGateways, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = AsyncMock()
    lock = {"acquired": False, "released": 0}
    lock_keys: list[int] = []

    @asynccontextmanager
    async def _session_cm():
        yield session

    @asynccontextmanager
    async def _hold_lock(_engine: Any, key: int, *, wait: bool = True):
        assert wait is False
        lock_keys.append(key)
        try:
            yield AsyncMock() if lock["acquired"] else None
        finally:
            lock["released"] += 1

    monkeypatch.setattr(
        gateways, "get_async_session_bypass_rls_context_manager", _session_cm
    )
    monkeypatch.setattr(gateways, "get_async_engine", lambda: object())
    monkeypatch.setattr(gateways, "hold_pg_advisory_xact_lock", _hold_lock)
    monkeypatch.setattr(gateways, "desired_gateway_specs", AsyncMock(return_value=[]))

    await gateways.reconcile_gateways_once()
    assert k8s.reconciled == []

    lock["acquired"] = True
    await gateways.reconcile_gateways_once()
    assert k8s.reconciled == [[]]

    # The lock is released even when Kubernetes fails mid-reconcile.
    k8s.error = KubernetesError(500, "boom")
    with pytest.raises(KubernetesError):
        await gateways.reconcile_gateways_once()
    assert lock["released"] == 3
    assert len(set(lock_keys)) == 1
