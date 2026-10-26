"""Provider SDK token requests follow AUTOSECOPS__OUTBOUND_PROXY_URL."""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import orjson
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from google.auth import exceptions as google_auth_exceptions
from litellm.llms.vertex_ai.vertex_llm_base import VertexBase

from autosecops import config, outbound_auth
from autosecops.agent import service as agent_service
from autosecops.agent.gateway_outbound import install_outbound_http_policy
from autosecops.outbound_auth import (
    OutboundGoogleAuthRequest,
    azure_identity_proxy_kwargs,
)

TOKEN_URI = "http://oauth2.example.test/token"


class _RecordingHandler(BaseHTTPRequestHandler):
    seen: list[str]

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.seen.append(f"{self.command} {self.path}")  # pyright: ignore[reportAttributeAccessIssue]
        body = orjson.dumps({"access_token": "synthetic-token", "expires_in": 3600})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


@pytest.fixture
def proxy_server() -> Iterator[tuple[str, list[str]]]:
    """A local listener that records requests and returns a token."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    seen: list[str] = []
    server.seen = seen  # pyright: ignore[reportAttributeAccessIssue]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    """Resolve every proxied target to a public address without real DNS."""
    checked: list[tuple[str, int]] = []

    def resolve(host: str, port: int) -> list[ipaddress.IPv4Address]:
        checked.append((host, port))
        return [ipaddress.IPv4Address("8.8.8.8")]

    monkeypatch.setattr(outbound_auth, "resolve_outbound_addresses_sync", resolve)
    return checked


def _service_account_blob(token_uri: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return orjson.dumps(
        {
            "type": "service_account",
            "project_id": "synthetic-project",
            "private_key_id": "synthetic",
            "private_key": pem,
            "client_email": "sa@synthetic-project.iam.gserviceaccount.com",
            "client_id": "1",
            "token_uri": token_uri,
        }
    ).decode()


def test_vertex_token_refresh_uses_egress_proxy(
    monkeypatch: pytest.MonkeyPatch,
    proxy_server: tuple[str, list[str]],
    public_dns: list[tuple[str, int]],
) -> None:
    proxy_url, seen = proxy_server
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_PROXY_URL", proxy_url)
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_NO_PROXY", ())

    token = agent_service._refresh_vertex_token(_service_account_blob(TOKEN_URI))

    assert token == "synthetic-token"
    # Absolute-form request line: the proxy, not the target, received it.
    assert seen == [f"POST {TOKEN_URI}"]
    assert public_dns == [("oauth2.example.test", 80)]


def test_google_auth_request_honors_no_proxy(
    monkeypatch: pytest.MonkeyPatch, proxy_server: tuple[str, list[str]]
) -> None:
    server_url, seen = proxy_server
    monkeypatch.setattr(
        config, "AUTOSECOPS__OUTBOUND_PROXY_URL", "http://proxy.invalid:3128"
    )
    monkeypatch.setattr(
        config, "AUTOSECOPS__OUTBOUND_NO_PROXY", (ipaddress.ip_network("127.0.0.1"),)
    )

    response = OutboundGoogleAuthRequest()(f"{server_url}/token", method="POST")

    assert response.status == 200
    # Origin-form request line: a direct connection that skipped the proxy.
    assert seen == ["POST /token"]


def test_google_auth_request_refuses_private_targets_before_proxy(
    monkeypatch: pytest.MonkeyPatch, proxy_server: tuple[str, list[str]]
) -> None:
    proxy_url, seen = proxy_server
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_PROXY_URL", proxy_url)
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_NO_PROXY", ())
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS", ())

    with pytest.raises(google_auth_exceptions.TransportError, match="not allowed"):
        OutboundGoogleAuthRequest()("http://169.254.169.254/token", method="POST")

    assert seen == []


@pytest.mark.anyio
async def test_azure_token_request_uses_egress_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_url = "http://user:secret@proxy.example.test:3128"
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_PROXY_URL", proxy_url)
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_NO_PROXY", ())
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    checked: list[tuple[str, int]] = []

    async def resolve(host: str, port: int) -> list[ipaddress.IPv4Address]:
        checked.append((host, port))
        return [ipaddress.IPv4Address("8.8.8.8")]

    monkeypatch.setattr(outbound_auth, "resolve_outbound_addresses", resolve)
    captured: dict[str, Any] = {}

    class _Token:
        token = "synthetic-azure-token"

    class _Credential:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        async def get_token(self, *scopes: str) -> _Token:
            del scopes
            return _Token()

        async def close(self) -> None:
            return None

    monkeypatch.setattr(agent_service, "ClientSecretCredential", _Credential)

    resolved = await agent_service._resolve_azure_ad_token(
        {
            "AZURE_TENANT_ID": "tenant",
            "AZURE_CLIENT_ID": "client",
            "AZURE_CLIENT_SECRET": "secret",
        }
    )

    assert resolved["AZURE_AD_TOKEN"] == "synthetic-azure-token"
    assert captured["proxies"] == {"http": proxy_url, "https": proxy_url}
    assert checked == [("login.microsoftonline.com", 443)]


@pytest.mark.anyio
async def test_azure_proxy_kwargs_respect_no_proxy_and_unset_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_PROXY_URL", None)
    assert await azure_identity_proxy_kwargs("login.microsoftonline.com") == {}

    monkeypatch.setattr(
        config, "AUTOSECOPS__OUTBOUND_PROXY_URL", "http://proxy.example.test:3128"
    )
    monkeypatch.setattr(
        config, "AUTOSECOPS__OUTBOUND_NO_PROXY", ("microsoftonline.com",)
    )
    assert await azure_identity_proxy_kwargs("login.microsoftonline.com") == {}


def test_litellm_vertex_refresh_uses_proxy_aware_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(VertexBase, "refresh_auth", VertexBase.refresh_auth)
    install_outbound_http_policy()
    requests_seen: list[object] = []

    class _Credentials:
        def refresh(self, request: object) -> None:
            requests_seen.append(request)

    VertexBase().refresh_auth(_Credentials())  # pyright: ignore[reportArgumentType]

    assert len(requests_seen) == 1
    assert isinstance(requests_seen[0], OutboundGoogleAuthRequest)
