from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from inspect import signature
from typing import Any

import httpx
import pytest
from autosecops_ee.admin.settings import router as admin_settings_router
from fastapi import status
from fastapi.testclient import TestClient

from autosecops.audit import service as audit_service_module
from autosecops.auth.types import Role
from autosecops.outbound import OutboundRequestDenied
from autosecops.settings import router as settings_router
from autosecops.settings.schemas import AuditSettingsUpdate
from tests.support.outbound_network import (
    RecordingNetwork,
    install_recording_network,
    resolve_all_to,
)

_TEST_BODY: dict[str, Any] = {
    "audit_webhook_url": "https://audit.example.test/ingest",
    "audit_webhook_custom_headers": {
        "X-Custom-Audit": "secret-value",
        "x-autosecops-test": "false",
    },
    "audit_webhook_custom_payload": {"customer_field": "customer-value"},
    "audit_webhook_verify_ssl": False,
    "audit_webhook_payload_attribute": "event",
}


class FakeAuditWebhookClient:
    status_code = status.HTTP_200_OK
    calls: list[dict[str, Any]] = []

    def __init__(self, *, timeout: float, verify: bool) -> None:
        self.timeout = timeout
        self.verify = verify

    async def __aenter__(self) -> FakeAuditWebhookClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, Any],
        headers: dict[str, str],
    ) -> AsyncIterator[httpx.Response]:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "json": json,
                "headers": headers,
                "timeout": self.timeout,
                "verify": self.verify,
            }
        )
        yield httpx.Response(self.status_code)


class HangingAuditWebhookClient(FakeAuditWebhookClient):
    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, Any],
        headers: dict[str, str],
    ) -> AsyncIterator[httpx.Response]:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "json": json,
                "headers": headers,
                "timeout": self.timeout,
                "verify": self.verify,
            }
        )
        await asyncio.Event().wait()
        raise AssertionError("wall-clock timeout should cancel the request")
        yield httpx.Response(self.status_code)


@pytest.fixture(autouse=True)
def reset_fake_client() -> None:
    FakeAuditWebhookClient.status_code = status.HTTP_200_OK
    FakeAuditWebhookClient.calls = []
    HangingAuditWebhookClient.calls = []


@pytest.fixture
def recording_network(monkeypatch: pytest.MonkeyPatch) -> RecordingNetwork:
    """Run the real outbound client against synthetic sockets."""
    return install_recording_network(monkeypatch)


def test_audit_webhook_test_routes_do_not_hold_request_sessions() -> None:
    assert "session" not in signature(settings_router.test_audit_webhook).parameters
    assert (
        "session" not in signature(admin_settings_router.test_audit_webhook).parameters
    )


@pytest.mark.anyio
async def test_org_audit_webhook_test_posts_marked_event_from_submitted_config(
    client: TestClient,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client", FakeAuditWebhookClient
    )

    response = client.post("/settings/audit/test", json=_TEST_BODY)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "ok": True,
        "receiver_status_code": status.HTTP_200_OK,
        "error_category": None,
    }
    assert len(FakeAuditWebhookClient.calls) == 1
    call = FakeAuditWebhookClient.calls[0]
    assert call["url"] == "https://audit.example.test/ingest"
    assert call["verify"] is False
    assert call["timeout"] == 5.0
    assert call["headers"]["X-Custom-Audit"] == "secret-value"
    assert "x-autosecops-test" not in call["headers"]
    assert call["headers"]["X-AutoSecOps-Test"] == "true"
    event = call["json"]["event"]
    assert event["organization_id"] == str(test_admin_role.organization_id)
    assert event["actor_id"] == str(test_admin_role.user_id)
    assert event["resource_type"] == "organization_setting"
    assert event["resource_id"] is None
    assert event["action"] == "connect"
    assert event["data"] == {"test": True}
    assert event["customer_field"] == "customer-value"


@pytest.mark.anyio
async def test_org_audit_webhook_test_probes_submitted_not_saved_url(
    client: TestClient,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The probe must target exactly the submitted configuration."""
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client", FakeAuditWebhookClient
    )

    client.post("/settings/audit/test", json=_TEST_BODY)
    updated_body = {
        **_TEST_BODY,
        "audit_webhook_url": "https://audit.example.test/updated",
    }
    client.post("/settings/audit/test", json=updated_body)

    assert len(FakeAuditWebhookClient.calls) == 2
    assert (
        FakeAuditWebhookClient.calls[1]["url"] == "https://audit.example.test/updated"
    )


@pytest.mark.anyio
async def test_org_audit_webhook_test_surfaces_receiver_error(
    client: TestClient,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeAuditWebhookClient.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client", FakeAuditWebhookClient
    )

    response = client.post("/settings/audit/test", json=_TEST_BODY)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "ok": False,
        "receiver_status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "error_category": "receiver_error",
    }


@pytest.mark.anyio
async def test_org_audit_webhook_test_enforces_wall_clock_timeout(
    client: TestClient,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "autosecops.audit.service._AUDIT_WEBHOOK_TEST_TIMEOUT_SECONDS", 0.01
    )
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client",
        HangingAuditWebhookClient,
    )

    response = client.post("/settings/audit/test", json=_TEST_BODY)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "ok": False,
        "receiver_status_code": None,
        "error_category": "timeout",
    }
    assert len(HangingAuditWebhookClient.calls) == 1
    assert HangingAuditWebhookClient.calls[0]["headers"]["X-AutoSecOps-Test"] == "true"


@pytest.mark.anyio
async def test_probe_timeout_includes_dns_resolution(
    test_admin_role: Role,
    recording_network: RecordingNetwork,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wall clock bounds the outbound client's own DNS lookup."""

    async def _hang(*args: object, **kwargs: object) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(
        "autosecops.audit.service._AUDIT_WEBHOOK_TEST_TIMEOUT_SECONDS", 0.01
    )
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", _hang)

    result = await audit_service_module.AuditService.probe_webhook(
        sink="organization",
        organization_id=test_admin_role.organization_id,
        role=test_admin_role,
        settings=AuditSettingsUpdate(
            audit_webhook_url="https://audit.example.test/ingest"
        ),
    )

    assert result.ok is False
    assert result.receiver_status_code is None
    assert result.error_category == "timeout"
    assert recording_network.connections == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "body",
    [
        {},
        {"audit_webhook_url": None},
        {"audit_webhook_url": "   "},
    ],
)
async def test_org_audit_webhook_test_returns_400_without_url(
    client: TestClient,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
    body: dict[str, Any],
) -> None:
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client", FakeAuditWebhookClient
    )

    response = client.post("/settings/audit/test", json=body)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Audit webhook is not configured"}
    assert FakeAuditWebhookClient.calls == []


@pytest.mark.anyio
async def test_probe_times_out_when_socket_budget_exhausted(
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A probe shares the delivery socket cap and honors the wall clock."""
    monkeypatch.setattr(
        "autosecops.audit.service._AUDIT_WEBHOOK_TEST_TIMEOUT_SECONDS", 0.05
    )
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client", FakeAuditWebhookClient
    )
    loop = asyncio.get_running_loop()
    audit_service_module._post_semaphores[loop] = asyncio.Semaphore(0)
    try:
        result = await audit_service_module.AuditService.probe_webhook(
            sink="organization",
            organization_id=test_admin_role.organization_id,
            role=test_admin_role,
            settings=AuditSettingsUpdate(
                audit_webhook_url="https://audit.example.test/ingest"
            ),
        )
    finally:
        audit_service_module._post_semaphores.pop(loop, None)

    assert result.ok is False
    assert result.error_category == "timeout"
    assert FakeAuditWebhookClient.calls == []


class DeniedAuditWebhookClient(FakeAuditWebhookClient):
    """Stands in for the outbound client refusing the resolved address."""

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, Any],
        headers: dict[str, str],
    ) -> AsyncIterator[httpx.Response]:
        raise OutboundRequestDenied("Host is not allowed")
        yield httpx.Response(self.status_code)


@pytest.mark.anyio
async def test_probe_route_maps_denied_target_to_400(
    client: TestClient,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The outbound client's refusal is a 400 without the address."""
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client",
        DeniedAuditWebhookClient,
    )

    response = client.post("/settings/audit/test", json=_TEST_BODY)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Audit webhook URL is not allowed"}


@pytest.mark.anyio
@pytest.mark.parametrize("address", ["10.0.0.10", "127.0.0.1", "169.254.169.254"])
async def test_probe_rejects_private_address_without_connecting(
    test_admin_role: Role,
    recording_network: RecordingNetwork,
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    """A URL resolving to a non-public address is refused and never connects."""
    resolve_all_to(monkeypatch, address)

    with pytest.raises(audit_service_module.AuditWebhookUrlNotAllowedError):
        await audit_service_module.AuditService.probe_webhook(
            sink="organization",
            organization_id=test_admin_role.organization_id,
            role=test_admin_role,
            settings=AuditSettingsUpdate(
                audit_webhook_url="https://audit.example.test/ingest"
            ),
        )

    assert recording_network.connections == []


@pytest.mark.anyio
async def test_probe_rejects_loopback_literal_without_connecting(
    test_admin_role: Role, recording_network: RecordingNetwork
) -> None:
    """A loopback literal is refused without any DNS lookup or socket."""
    with pytest.raises(audit_service_module.AuditWebhookUrlNotAllowedError):
        await audit_service_module.AuditService.probe_webhook(
            sink="organization",
            organization_id=test_admin_role.organization_id,
            role=test_admin_role,
            settings=AuditSettingsUpdate(
                audit_webhook_url="http://127.0.0.1:9000/ingest"
            ),
        )

    assert recording_network.connections == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:99999/hook",
        "https://[::1/hook",
        # An over-long DNS label makes getaddrinfo raise UnicodeError, not
        # gaierror; the guard must still map it to a client error.
        f"https://{'a' * 64}.example.test/hook",
    ],
)
async def test_org_audit_webhook_test_returns_400_for_malformed_url(
    client: TestClient,
    test_admin_role: Role,
    url: str,
    recording_network: RecordingNetwork,
) -> None:
    response = client.post(
        "/settings/audit/test", json={**_TEST_BODY, "audit_webhook_url": url}
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Audit webhook URL is not allowed"}
    assert recording_network.connections == []


@pytest.mark.anyio
async def test_platform_audit_webhook_test_posts_platform_event(
    client: TestClient,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "autosecops.audit.service.create_outbound_http_client", FakeAuditWebhookClient
    )

    response = client.post("/admin/settings/audit/test", json=_TEST_BODY)

    assert response.status_code == status.HTTP_200_OK
    assert len(FakeAuditWebhookClient.calls) == 1
    event = FakeAuditWebhookClient.calls[0]["json"]["event"]
    assert event["organization_id"] is None
    assert event["actor_id"] == str(test_admin_role.user_id)
    assert event["resource_type"] == "platform_setting"
    assert event["resource_id"] is None
    assert event["data"] == {"test": True}
