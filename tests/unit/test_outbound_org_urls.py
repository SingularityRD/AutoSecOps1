"""Organization-configured URLs go through the shared outbound egress guard.

Each path must refuse a private or loopback target by default, reach it once
the operator allowlists it in ``AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS``,
and dial exactly the address it checked. DNS and sockets are synthetic; the
real HTTPX stack and egress policy run unchanged.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from autosecops.audit.service import (
    AuditService,
    AuditWebhookUrlNotAllowedError,
    _AuditDelivery,
    _deliver,
)
from autosecops.auth.types import Role
from autosecops.authz.scopes import ADMIN_SCOPES, ORG_ADMIN_SCOPES
from autosecops.git.types import GitUrl
from autosecops.integrations.providers.base import (
    BaseOAuthProvider,
    _fetch_oauth_discovery_response_sync,
)
from autosecops.integrations.service import IntegrationService
from autosecops.network import DisallowedUrlError
from autosecops.settings.schemas import AuditSettingsUpdate
from autosecops.vcs.bitbucket.app import BitbucketError
from autosecops.vcs.bitbucket_data_center.app import BitbucketDataCenterTokenService
from autosecops.vcs.bitbucket_data_center.schemas import (
    BitbucketDataCenterTokenCredentials,
)
from autosecops.vcs.gitlab.app import GitLabError
from autosecops.vcs.gitlab.schemas import GitLabTokenCredentials
from autosecops.workspace_sync.transport import (
    BitbucketDataCenterWorkspaceSyncTransport,
    GitLabWorkspaceSyncTransport,
)
from tests.support.outbound_network import (
    RecordingNetwork,
    allow_private_cidrs,
    install_recording_network,
    resolve_all_to,
    resolve_all_to_in_any_loop,
)

PRIVATE_IP = "10.0.0.5"
LOOPBACK_IP = "127.0.0.1"
TOKEN = "synthetic-outbound-test-token"


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> RecordingNetwork:
    return install_recording_network(monkeypatch)


def _role() -> Role:
    return Role(
        type="user",
        workspace_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        service_id="autosecops-api",
        scopes=ADMIN_SCOPES | ORG_ADMIN_SCOPES,
    )


# Audit webhook live delivery


def _audit_delivery(url: str) -> _AuditDelivery:
    return _AuditDelivery(
        webhook_url=url,
        request_payload={"event": "synthetic"},
        headers={"X-Custom": "value"},
        verify_ssl=True,
        resource_type="workflow",
        action="create",
        organization_id=None,
        workspace_id=None,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("address", [PRIVATE_IP, LOOPBACK_IP])
async def test_audit_delivery_refuses_private_sink_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    resolve_all_to(monkeypatch, address)

    with pytest.raises(DisallowedUrlError):
        await _deliver(
            _audit_delivery("https://siem.internal.test/ingest"),
            raise_on_failure=True,
        )

    assert network.connections == []


@pytest.mark.anyio
async def test_audit_delivery_refuses_private_literal_without_dns(
    network: RecordingNetwork,
) -> None:
    with pytest.raises(DisallowedUrlError):
        await _deliver(
            _audit_delivery(f"http://{LOOPBACK_IP}:8080/ingest"),
            raise_on_failure=True,
        )

    assert network.connections == []


@pytest.mark.anyio
async def test_audit_delivery_reaches_allowlisted_private_sink(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, PRIVATE_IP)
    allow_private_cidrs(monkeypatch, f"{PRIVATE_IP}/32")

    await _deliver(
        _audit_delivery("https://siem.internal.test/ingest"), raise_on_failure=True
    )

    assert network.connections == [(PRIVATE_IP, 443)]
    sent = network.sent()
    assert b"POST /ingest HTTP/1.1" in sent
    assert b"Host: siem.internal.test" in sent
    assert b"X-Custom: value" in sent
    assert network.streams[0].server_hostname == "siem.internal.test"


# Audit webhook test probe


@pytest.mark.anyio
@pytest.mark.parametrize("address", [PRIVATE_IP, LOOPBACK_IP])
async def test_audit_probe_refuses_private_target_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    resolve_all_to(monkeypatch, address)

    with pytest.raises(AuditWebhookUrlNotAllowedError):
        await AuditService.probe_webhook(
            sink="organization",
            organization_id=uuid.uuid4(),
            role=_role(),
            settings=AuditSettingsUpdate(
                audit_webhook_url="https://siem.internal.test/ingest"
            ),
        )

    assert network.connections == []


@pytest.mark.anyio
async def test_audit_probe_reaches_allowlisted_private_target(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, PRIVATE_IP)
    allow_private_cidrs(monkeypatch, "10.0.0.0/24")

    result = await AuditService.probe_webhook(
        sink="organization",
        organization_id=uuid.uuid4(),
        role=_role(),
        settings=AuditSettingsUpdate(
            audit_webhook_url="https://siem.internal.test/ingest"
        ),
    )

    assert result.ok is True
    assert result.receiver_status_code == 200
    assert network.connections == [(PRIVATE_IP, 443)]
    assert b"X-AutoSecOps-Test: true" in network.sent()


@pytest.mark.anyio
async def test_audit_probe_dials_the_address_it_checked(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rebinding resolver gets one lookup; its first answer is the one dialed."""
    answers = [
        [(2, 1, 6, "", ("8.8.8.8", 443))],
        [(2, 1, 6, "", (LOOPBACK_IP, 443))],
    ]
    resolver = AsyncMock(side_effect=answers)
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)

    result = await AuditService.probe_webhook(
        sink="organization",
        organization_id=uuid.uuid4(),
        role=_role(),
        settings=AuditSettingsUpdate(
            audit_webhook_url="https://siem.example.test/ingest"
        ),
    )

    assert result.ok is True
    assert resolver.await_count == 1
    assert network.connections == [("8.8.8.8", 443)]


# Workspace sync: GitLab


def _gitlab_transport() -> GitLabWorkspaceSyncTransport:
    return GitLabWorkspaceSyncTransport(session=AsyncMock(), role=_role())


def _gitlab_credentials() -> GitLabTokenCredentials:
    return GitLabTokenCredentials(
        base_url="https://gitlab.internal.test", token=SecretStr(TOKEN)
    )


@pytest.mark.anyio
@pytest.mark.parametrize("address", [PRIVATE_IP, LOOPBACK_IP])
async def test_gitlab_sync_refuses_private_instance_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    resolve_all_to(monkeypatch, address)
    transport = _gitlab_transport()

    async with transport._client(_gitlab_credentials()) as client:
        with pytest.raises(GitLabError, match="not allowed"):
            await transport._gitlab_response(client, "GET", "/projects/1")

    assert network.connections == []


@pytest.mark.anyio
async def test_gitlab_sync_reaches_allowlisted_private_instance(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, PRIVATE_IP)
    allow_private_cidrs(monkeypatch, f"{PRIVATE_IP}/32")
    transport = _gitlab_transport()

    async with transport._client(_gitlab_credentials()) as client:
        response = await transport._gitlab_response(client, "GET", "/projects/1")

    assert response.status_code == 200
    assert network.connections == [(PRIVATE_IP, 443)]
    sent = network.sent()
    assert b"GET /api/v4/projects/1 HTTP/1.1" in sent
    assert b"Host: gitlab.internal.test" in sent


@pytest.mark.anyio
async def test_gitlab_sync_token_never_leaves_configured_origin(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, "8.8.8.8")
    transport = _gitlab_transport()

    async with transport._client(_gitlab_credentials()) as client:
        with pytest.raises(GitLabError, match="not allowed"):
            await transport._gitlab_response(
                client, "GET", "https://elsewhere.example.test/api/v4/projects/1"
            )

    assert network.connections == []


# Workspace sync: Bitbucket Data Center


def _data_center_credentials() -> BitbucketDataCenterTokenCredentials:
    return BitbucketDataCenterTokenCredentials(
        base_url="https://bitbucket.internal.test/bitbucket", token=SecretStr(TOKEN)
    )


_DATA_CENTER_URL = GitUrl(host="bitbucket.internal.test", org="DEMO", repo="sync")


@pytest.mark.anyio
@pytest.mark.parametrize("address", [PRIVATE_IP, LOOPBACK_IP])
async def test_data_center_sync_refuses_private_instance_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    resolve_all_to(monkeypatch, address)
    transport = BitbucketDataCenterWorkspaceSyncTransport(
        session=AsyncMock(), role=_role()
    )

    with patch.object(
        BitbucketDataCenterTokenService,
        "get_bitbucket_data_center_token_credentials",
        new=AsyncMock(return_value=_data_center_credentials()),
    ):
        with pytest.raises(BitbucketError, match="not allowed"):
            async with transport._connection(_DATA_CENTER_URL):
                pytest.fail("the connection must be refused before any traffic")

    assert network.connections == []


@pytest.mark.anyio
async def test_data_center_sync_reaches_allowlisted_private_instance(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, PRIVATE_IP)
    allow_private_cidrs(monkeypatch, f"{PRIVATE_IP}/32")
    transport = BitbucketDataCenterWorkspaceSyncTransport(
        session=AsyncMock(), role=_role()
    )

    with patch.object(
        BitbucketDataCenterTokenService,
        "get_bitbucket_data_center_token_credentials",
        new=AsyncMock(return_value=_data_center_credentials()),
    ):
        async with transport._connection(_DATA_CENTER_URL) as (client, _git, path):
            response = await transport._request(client, "GET", f"{path}/branches")

    assert response.status_code == 200
    assert network.connections == [(PRIVATE_IP, 443)]
    sent = network.sent()
    assert (
        b"GET /bitbucket/rest/api/1.0/projects/DEMO/repos/sync/branches HTTP/1.1"
        in sent
    )
    assert b"Host: bitbucket.internal.test" in sent


# OAuth discovery and dynamic client registration


@pytest.mark.anyio
@pytest.mark.parametrize("address", [PRIVATE_IP, LOOPBACK_IP])
async def test_mcp_oauth_discovery_refuses_private_host_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    resolve_all_to(monkeypatch, address)

    with pytest.raises(ValueError, match="OAuth endpoint host is not allowed"):
        await IntegrationService._send_mcp_oauth_request(
            "https://mcp.internal.test/.well-known/oauth-protected-resource"
        )

    assert network.connections == []


@pytest.mark.anyio
async def test_mcp_oauth_discovery_reaches_allowlisted_private_host(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, PRIVATE_IP)
    allow_private_cidrs(monkeypatch, f"{PRIVATE_IP}/32")

    response = await IntegrationService._send_mcp_oauth_request(
        "https://mcp.internal.test/.well-known/oauth-protected-resource"
    )

    assert response.status_code == 200
    assert network.connections == [(PRIVATE_IP, 443)]


@pytest.mark.anyio
async def test_mcp_dynamic_registration_refuses_private_host_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, PRIVATE_IP)

    with pytest.raises(ValueError, match="OAuth endpoint host is not allowed"):
        await IntegrationService._send_mcp_oauth_request(
            "https://auth.internal.test/register", json_body={"client_name": "x"}
        )

    assert network.connections == []


@pytest.mark.anyio
async def test_provider_dynamic_registration_refuses_private_host_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, LOOPBACK_IP)

    with pytest.raises(ValueError, match="OAuth endpoint host is not allowed"):
        await BaseOAuthProvider._submit_registration_request(
            "https://auth.internal.test/register", {"client_name": "synthetic"}
        )

    assert network.connections == []


@pytest.mark.anyio
async def test_provider_dynamic_registration_reaches_allowlisted_private_host(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to(monkeypatch, PRIVATE_IP)
    allow_private_cidrs(monkeypatch, f"{PRIVATE_IP}/32")
    body = b'{"client_id":"synthetic-client"}'
    network.response = (
        b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )

    registration = await BaseOAuthProvider._submit_registration_request(
        "https://auth.internal.test/register", {"client_name": "synthetic"}
    )

    assert registration.client_id == "synthetic-client"
    assert network.connections == [(PRIVATE_IP, 443)]


@pytest.mark.parametrize("address", [PRIVATE_IP, LOOPBACK_IP])
def test_provider_sync_discovery_refuses_private_host_by_default(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    resolve_all_to_in_any_loop(monkeypatch, address)

    with pytest.raises(ValueError, match="OAuth endpoint host is not allowed"):
        _fetch_oauth_discovery_response_sync(
            "https://mcp.internal.test/.well-known/oauth-authorization-server"
        )

    assert network.connections == []


def test_provider_sync_discovery_reaches_allowlisted_private_host(
    network: RecordingNetwork, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_all_to_in_any_loop(monkeypatch, PRIVATE_IP)
    allow_private_cidrs(monkeypatch, f"{PRIVATE_IP}/32")

    response = _fetch_oauth_discovery_response_sync(
        "https://mcp.internal.test/.well-known/oauth-authorization-server"
    )

    assert response.status_code == 200
    assert network.connections == [(PRIVATE_IP, 443)]
