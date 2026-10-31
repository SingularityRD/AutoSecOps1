"""Direct-backend stdio MCP probes run untrusted servers as the worker's user.

These tests start real fake MCP servers through the direct probe and check the
isolation it still provides without nsjail: a private home, an allowlisted
environment, resource limits, bounded output and reaping of leftover processes.
"""

from __future__ import annotations

import asyncio
import json
import os
import resource
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from autosecops.agent.mcp import stdio_probe
from autosecops.agent.mcp.stdio_probe import (
    DIRECT_PROBE_MAX_FILE_SIZE_MB,
    DIRECT_PROBE_MAX_OPEN_FILES,
    MCP_STDIO_PROBE_HARD_TIMEOUT_BUFFER,
    probe_stdio_mcp_tools_in_sandbox,
)
from autosecops.agent.sandbox.config import AGENT_SANDBOX_BASE_ENV
from autosecops.executor.enums import ExecutorBackendType
from autosecops.process_env import trusted_path

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="rlimits and /proc are Linux-only"
)

# Reports what the server process can see in its tool description.
INTROSPECTING_SERVER = """
import json
import os
import resource

from fastmcp import FastMCP

limits = {
    name: resource.getrlimit(getattr(resource, name))[0]
    for name in ("RLIMIT_CORE", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE", "RLIMIT_AS")
}
report = {
    "home": os.environ.get("HOME"),
    "cwd": os.getcwd(),
    "path": os.environ.get("PATH"),
    "environ": sorted(os.environ),
    "limits": limits,
}

mcp = FastMCP("introspect")


@mcp.tool(description=json.dumps(report))
def introspect() -> str:
    return "ok"


mcp.run()
"""

# Starts a detached helper that would outlive the server, then serves.
LEAKING_SERVER = """
import os
import subprocess
import sys

from fastmcp import FastMCP

helper = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(120)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
with open(os.environ["HELPER_PID_FILE"], "w") as handle:
    handle.write(str(helper.pid))

mcp = FastMCP("leaky")


@mcp.tool
def noop() -> str:
    \"\"\"Do nothing.\"\"\"
    return "ok"


mcp.run()
"""

# Advertises a tool list larger than the host's result cap.
OVERSIZED_SERVER = """
from fastmcp import FastMCP

mcp = FastMCP("oversized")


@mcp.tool(description="x" * 200_000)
def big() -> str:
    return "ok"


mcp.run()
"""


@pytest.fixture
def direct_backend() -> Iterator[None]:
    """Use the direct backend with the plain-subprocess path on every host."""
    with (
        patch(
            "autosecops.agent.mcp.stdio_probe.config.AUTOSECOPS__EXECUTOR_BACKEND",
            ExecutorBackendType.DIRECT,
        ),
        patch(
            "autosecops.agent.mcp.stdio_probe.pid_namespace_available",
            new_callable=AsyncMock,
            return_value=False,
        ),
    ):
        yield


async def _introspect(tmp_path: Path) -> dict[str, object]:
    server = tmp_path / "server.py"
    server.write_text(INTROSPECTING_SERVER, encoding="utf-8")
    result = await probe_stdio_mcp_tools_in_sandbox(
        command=sys.executable, args=[str(server)], env=None, timeout=30
    )
    assert result.success is True, result.error
    assert result.tools[0].description is not None
    report = json.loads(result.tools[0].description)
    assert isinstance(report, dict)
    return report


@pytest.mark.anyio
@pytest.mark.usefixtures("direct_backend")
async def test_direct_probe_server_gets_private_home_not_worker_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker_home = tmp_path / "worker-home"
    worker_home.mkdir()
    monkeypatch.setenv("HOME", str(worker_home))

    report = await _introspect(tmp_path)

    home = str(report["home"])
    assert home != str(worker_home)
    assert Path(home).name == "home"
    assert Path(home).parent.name.startswith("mcp-stdio-probe-")
    # The server runs from its private directory, not the shared /tmp.
    assert report["cwd"] == home
    # The private home is removed with the job directory.
    assert not Path(home).exists()


@pytest.mark.anyio
@pytest.mark.usefixtures("direct_backend")
async def test_direct_probe_never_passes_worker_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUTOSECOPS__SERVICE_KEY", "synthetic-service-key")
    monkeypatch.setenv("AUTOSECOPS__DB_URI", "postgresql://u:synthetic@db/x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-aws-secret")

    report = await _introspect(tmp_path)

    environ = report["environ"]
    assert isinstance(environ, list)
    for name in ("AUTOSECOPS__SERVICE_KEY", "AUTOSECOPS__DB_URI"):
        assert name not in environ
    assert "AWS_SECRET_ACCESS_KEY" not in environ


def test_direct_probe_env_is_allowlisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUTOSECOPS__SERVICE_KEY", "synthetic-service-key")
    monkeypatch.setenv("TEMPORAL__API_KEY", "synthetic-temporal-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://user:synthetic@proxy.test:3128")
    monkeypatch.setenv("PYTHONUSERBASE", str(tmp_path / "userbase"))
    planted_bin = tmp_path / "bin"
    planted_bin.mkdir()
    monkeypatch.setenv("PATH", f"{planted_bin}:{os.environ.get('PATH', '')}")

    env = stdio_probe._direct_probe_env(tmp_path)

    assert "AUTOSECOPS__SERVICE_KEY" not in env
    assert "TEMPORAL__API_KEY" not in env
    assert "PYTHONUSERBASE" not in env
    # The operator proxy stays usable, without its credentials.
    assert env["HTTPS_PROXY"] == "http://proxy.test:3128"
    assert env["HOME"] == str(tmp_path / "home")
    assert env["TMPDIR"] == str(tmp_path / "tmp")
    assert env["PYTHONNOUSERSITE"] == "1"
    # The probe resolves the command on the agent runtime's PATH, never on
    # directories from the worker's PATH.
    assert env["PATH"] == trusted_path(AGENT_SANDBOX_BASE_ENV["PATH"])
    assert str(planted_bin) not in env["PATH"]
    assert (tmp_path / "home").stat().st_mode & 0o777 == 0o700


@pytest.mark.anyio
@pytest.mark.usefixtures("direct_backend")
async def test_direct_probe_applies_resource_limits_to_server(
    tmp_path: Path,
) -> None:
    report = await _introspect(tmp_path)

    limits = report["limits"]
    assert isinstance(limits, dict)
    assert limits["RLIMIT_CORE"] == 0
    assert limits["RLIMIT_CPU"] == 30 + MCP_STDIO_PROBE_HARD_TIMEOUT_BUFFER
    assert limits["RLIMIT_FSIZE"] == DIRECT_PROBE_MAX_FILE_SIZE_MB * 1024 * 1024
    assert limits["RLIMIT_NOFILE"] == DIRECT_PROBE_MAX_OPEN_FILES
    assert limits["RLIMIT_AS"] != resource.RLIM_INFINITY
    assert limits["RLIMIT_AS"] == stdio_probe._direct_probe_rlimits(30)["RLIMIT_AS"]


def test_direct_probe_address_space_honours_configured_cap() -> None:
    with patch(
        "autosecops.agent.sandbox.config.AUTOSECOPS__AGENT_SANDBOX_ADDRESS_SPACE_MB",
        3072,
    ):
        limits = stdio_probe._direct_probe_rlimits(10)
    assert limits["RLIMIT_AS"] == 3072 * 1024 * 1024


@pytest.mark.anyio
@pytest.mark.usefixtures("direct_backend")
async def test_direct_probe_fails_closed_when_limit_cannot_apply(
    tmp_path: Path,
) -> None:
    server = tmp_path / "server.py"
    server.write_text(INTROSPECTING_SERVER, encoding="utf-8")
    with patch.object(
        stdio_probe,
        "_direct_probe_rlimits",
        return_value={"RLIMIT_NOT_A_LIMIT": 1},
    ):
        result = await probe_stdio_mcp_tools_in_sandbox(
            command=sys.executable, args=[str(server)], env=None, timeout=30
        )

    assert result.success is False
    assert result.tools == []


def _is_running(pid: int) -> bool:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    state = next(
        (line for line in status.splitlines() if line.startswith("State:")), ""
    )
    # A killed process that its new parent has not reaped yet is a zombie.
    return "Z" not in state.split(":", 1)[-1].split()[:1]


@pytest.mark.anyio
@pytest.mark.usefixtures("direct_backend")
async def test_direct_probe_reaps_processes_the_server_left_behind(
    tmp_path: Path,
) -> None:
    server = tmp_path / "server.py"
    server.write_text(LEAKING_SERVER, encoding="utf-8")
    pid_file = tmp_path / "helper.pid"

    result = await probe_stdio_mcp_tools_in_sandbox(
        command=sys.executable,
        args=[str(server)],
        env={"HELPER_PID_FILE": str(pid_file)},
        timeout=30,
    )

    assert result.success is True, result.error
    helper_pid = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    while _is_running(helper_pid) and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    assert not _is_running(helper_pid)


@pytest.mark.anyio
@pytest.mark.usefixtures("direct_backend")
async def test_direct_probe_refuses_oversized_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = tmp_path / "server.py"
    server.write_text(OVERSIZED_SERVER, encoding="utf-8")
    monkeypatch.setattr(stdio_probe, "DIRECT_PROBE_RESULT_LIMIT_BYTES", 64 * 1024)

    result = await probe_stdio_mcp_tools_in_sandbox(
        command=sys.executable, args=[str(server)], env=None, timeout=30
    )

    assert result.success is False
    assert result.tools == []
    assert result.error is not None
    assert "exceeded" in result.error


@pytest.mark.anyio
async def test_read_bounded_keeps_head_and_drains_the_rest() -> None:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('a' * 1000 + 'b' * 4_000_000)",
        stdout=asyncio.subprocess.PIPE,
    )
    output = await stdio_probe._read_bounded(process.stdout, 1000)
    # The writer finished, so the pipe was drained rather than abandoned.
    assert await asyncio.wait_for(process.wait(), timeout=30) == 0
    assert output == b"a" * 1000
