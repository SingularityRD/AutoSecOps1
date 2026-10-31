from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from autosecops import config
from autosecops.mcp import __main__ as mcp_main
from autosecops.temporal.codec import reset_temporal_payload_secret_cache


@pytest.fixture(autouse=True)
def _plaintext_payloads(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED", False)
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING", None)
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING_ARN", None)
    reset_temporal_payload_secret_cache()


def _stateless_replica_app():
    server = FastMCP("replica-test")

    @server.tool()
    def ping() -> str:  # pyright: ignore[reportUnusedFunction]
        return "pong"

    return server.http_app(
        path="/mcp",
        transport="streamable-http",
        stateless_http=True,
        json_response=True,
    )


def test_stateless_transport_accepts_followup_on_another_replica() -> None:
    """Initialize on replica A, then list tools through replica B."""
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    with (
        TestClient(_stateless_replica_app()) as replica_a,
        TestClient(_stateless_replica_app()) as replica_b,
    ):
        initialized = replica_a.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "replica-test", "version": "1"},
                },
            },
        )
        listed = replica_b.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

    assert initialized.status_code == 200
    assert initialized.headers.get("mcp-session-id") is None
    assert listed.status_code == 200
    assert listed.json()["result"]["tools"][0]["name"] == "ping"


def test_run_mcp_server_uses_stateless_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_kwargs: dict[str, object] = {}

    class _MCP:
        def run(self, **kwargs: object) -> None:
            run_kwargs.update(kwargs)

    monkeypatch.delitem(sys.modules, "autosecops.mcp.server", raising=False)
    monkeypatch.setattr(
        mcp_main.importlib,
        "import_module",
        lambda _name: SimpleNamespace(mcp=_MCP()),
    )

    mcp_main._run_mcp_server()

    assert run_kwargs["transport"] == "streamable-http"
    assert run_kwargs["stateless_http"] is True


def test_main_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[int] = []

    def _run_mcp_server() -> None:
        attempts.append(1)
        if len(attempts) < 3:
            raise ValueError("missing oidc config")

    monkeypatch.setattr(mcp_main, "_run_mcp_server", _run_mcp_server)
    monkeypatch.setattr(mcp_main, "AUTOSECOPS_MCP__STARTUP_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(mcp_main, "AUTOSECOPS_MCP__STARTUP_RETRY_DELAY_SECONDS", 0.0)
    monkeypatch.setattr(mcp_main.time, "sleep", lambda _: None)

    mcp_main.main()

    assert len(attempts) == 3


def test_main_exits_after_max_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[int] = []

    def _run_mcp_server() -> None:
        attempts.append(1)
        raise ValueError("missing oidc config")

    monkeypatch.setattr(mcp_main, "_run_mcp_server", _run_mcp_server)
    monkeypatch.setattr(mcp_main, "AUTOSECOPS_MCP__STARTUP_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(mcp_main, "AUTOSECOPS_MCP__STARTUP_RETRY_DELAY_SECONDS", 0.0)
    monkeypatch.setattr(mcp_main.time, "sleep", lambda _: None)

    with pytest.raises(SystemExit, match="1"):
        mcp_main.main()

    assert len(attempts) == 3


def test_main_stops_on_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[int] = []

    def _run_mcp_server() -> None:
        attempts.append(1)
        raise KeyboardInterrupt

    monkeypatch.setattr(mcp_main, "_run_mcp_server", _run_mcp_server)
    monkeypatch.setattr(mcp_main, "AUTOSECOPS_MCP__STARTUP_MAX_ATTEMPTS", 3)

    mcp_main.main()

    assert len(attempts) == 1


def test_main_exits_without_retry_when_payload_encryption_has_no_keyring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[int] = []
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED", True)
    monkeypatch.setattr(mcp_main, "_run_mcp_server", lambda: attempts.append(1))
    monkeypatch.setattr(mcp_main, "AUTOSECOPS_MCP__STARTUP_MAX_ATTEMPTS", 3)

    with pytest.raises(SystemExit, match="1"):
        mcp_main.main()

    assert attempts == []


def test_main_starts_when_payload_encryption_has_a_keyring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[int] = []
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED", True)
    monkeypatch.setattr(
        config,
        "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING",
        '{"current_key_id": "v1", "keys": {"v1": "' + "a" * 64 + '"}}',
    )
    monkeypatch.setattr(mcp_main, "_run_mcp_server", lambda: attempts.append(1))

    mcp_main.main()

    assert attempts == [1]
