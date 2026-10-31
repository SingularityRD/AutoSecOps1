"""Sandboxed stdio MCP connection probing."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import sysconfig
import tempfile
import textwrap
from contextlib import suppress
from pathlib import Path
from typing import Any

import orjson
from mcp.types import CallToolResult

from autosecops import config
from autosecops.agent.mcp.stdio_probe_types import (
    MCP_STDIO_PERSIST_ACTIVITY_NAME,
    MCP_STDIO_PROBE_ACTIVITY_NAME,
    MCP_STDIO_PROBE_HARD_TIMEOUT_BUFFER,
    MCP_STDIO_PROBE_TIMEOUT_CAP,
    MCP_STDIO_PROBE_WORKFLOW_ID_PREFIX,
    StdioMCPPersistInput,
    StdioMCPProbeInput,
    StdioMCPProbeResult,
    StdioMCPProbeWorkflowInput,
    build_stdio_mcp_probe_workflow_id,
    sanitize_stdio_probe_error,
)
from autosecops.agent.mcp.stdio_runner import (
    StdioMCPRunnerUnsupportedError,
    StdioMCPServer,
)
from autosecops.agent.mcp.utils import MCP_TOOL_NAME_RE
from autosecops.agent.sandbox.cgroup import sandbox_cgroup
from autosecops.agent.sandbox.config import AGENT_SANDBOX_BASE_ENV, AgentResourceLimits
from autosecops.integrations.schemas import MCPToolSummary
from autosecops.logger import logger
from autosecops.process_env import BASE_ENV_NAMES, select_env, trusted_path
from autosecops.sandbox.exceptions import SandboxTimeoutError
from autosecops.sandbox.executor import NsjailExecutor
from autosecops.sandbox.types import (
    ResourceLimits,
    SandboxConfig,
    SandboxErrorCode,
    SandboxNetworkPurpose,
    SandboxNetworkRequest,
    SandboxResult,
)
from autosecops.sandbox.utils import pid_namespace_available

__all__ = [
    "MCP_STDIO_PERSIST_ACTIVITY_NAME",
    "MCP_STDIO_PROBE_ACTIVITY_NAME",
    "MCP_STDIO_PROBE_HARD_TIMEOUT_BUFFER",
    "MCP_STDIO_PROBE_TIMEOUT_CAP",
    "MCP_STDIO_PROBE_WORKFLOW_ID_PREFIX",
    "NsjailStdioMCPRunner",
    "StdioMCPPersistInput",
    "StdioMCPProbeInput",
    "StdioMCPProbeResult",
    "StdioMCPProbeWorkflowInput",
    "build_stdio_mcp_probe_workflow_id",
    "probe_stdio_mcp_tools_in_sandbox",
    "sanitize_stdio_probe_error",
]

_SANDBOX_PROBE_SCRIPT = r"""
from __future__ import annotations

import asyncio
import ctypes
import json
import os
import re
import resource
import signal
import traceback
from pathlib import Path
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


def _enforce_payload_rlimits(limits: dict[str, int]) -> None:
    # Direct-backend probes have no jail, so the host passes the resource caps
    # in the payload and this trusted entrypoint applies them before the MCP
    # command starts. The command inherits them. Limits are only ever lowered.
    for name, value in limits.items():
        try:
            resource_id = getattr(resource, name)
            _soft, hard = resource.getrlimit(resource_id)
            target = int(value)
            if target < 0:
                raise ValueError(f"negative cap: {target}")
            if hard != resource.RLIM_INFINITY:
                target = min(target, hard)
            resource.setrlimit(resource_id, (target, target))
        except (AttributeError, ValueError, OSError, OverflowError) as exc:
            # Fail closed: never run the untrusted command without its caps.
            raise SystemExit(
                f"_enforce_payload_rlimits: could not enforce {name}: "
                f"{type(exc).__name__}"
            ) from exc


_PR_SET_CHILD_SUBREAPER = 36


def _become_subreaper() -> bool:
    # The MCP SDK starts the server in its own session, and kills that session
    # only when the server ignores shutdown. Processes the server leaves behind
    # would outlive the probe. As a subreaper, every orphaned descendant is
    # re-parented to this process, so _kill_descendants can reap them.
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def _child_pids() -> list[int]:
    me = os.getpid()
    children: list[int] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            stat = Path(f"/proc/{entry}/stat").read_text()
        except OSError:
            continue
        fields = stat.rsplit(")", 1)[-1].split()
        if len(fields) > 1 and fields[1] == str(me):
            children.append(int(entry))
    return children


def _kill_descendants() -> None:
    # Killing a child re-parents its own children here; repeat until none.
    for _ in range(100):
        try:
            children = _child_pids()
        except OSError:
            return
        if not children:
            return
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def _read_stderr_tail(path: Path, limit: int = 65536) -> str:
    # The server controls how much it writes; read only the tail.
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - limit))
        return handle.read(limit).decode("utf-8", errors="replace")


def _enforce_nproc_limit() -> None:
    # Cap the jail's process count via RLIMIT_NPROC before the MCP command runs.
    #
    # nsjail cannot enforce rlimit_nproc when it creates a user namespace
    # (clone_newuser), so the host injects the configured limit via
    # AUTOSECOPS__SANDBOX_RLIMIT_NPROC and this trusted entrypoint applies it
    # before spawning the user-selected MCP command. The command inherits the
    # rlimit, containing fork bombs to this probe's configured process cap.
    raw = os.environ.get("AUTOSECOPS__SANDBOX_RLIMIT_NPROC")
    if not raw:
        return
    try:
        limit = int(raw)
        if limit <= 0:
            raise ValueError(f"non-positive cap: {limit}")
        _soft, current_hard = resource.getrlimit(resource.RLIMIT_NPROC)
        finite = current_hard != resource.RLIM_INFINITY
        # Already capped when the inherited hard cap is at or below the
        # requested limit (including 0 = no child processes), or when a
        # stricter finite soft limit is in force: raising either would only
        # relax enforcement.
        already_capped = (
            0 <= current_hard <= limit
            if finite
            else 0 < _soft <= limit
        )
        if not already_capped:
            resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))
    except (ValueError, OSError, OverflowError) as exc:
        # Values are host-injected; a malformed value or an unenforceable
        # rlimit means the process cap is not in place. Exit instead of
        # running untrusted code without the enforced cap.
        raise SystemExit(
            f"_enforce_nproc_limit: could not enforce RLIMIT_NPROC={raw!r}: "
            f"{type(exc).__name__}"
        ) from exc

URL_PATTERN = re.compile(r"\bhttps?://\S+", re.IGNORECASE)
URL_USERINFO_PATTERN = re.compile(r"^(https?://)[^/@]*@", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
BEARER_TOKEN_PATTERN = re.compile(
    r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE
)
AUTHORIZATION_VALUE_PATTERN = re.compile(
    r"\b(Authorization\s*:\s*)[^\r\n]+", re.IGNORECASE | re.MULTILINE
)
COOKIE_VALUE_PATTERN = re.compile(
    r"\b((?:Set-)?Cookie\s*:\s*)[^\r\n]+", re.IGNORECASE | re.MULTILINE
)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?P<prefix>['\"]?\b(?:api[ _-]?key|access[ _-]?token|refresh[ _-]?token|"
    r"id[ _-]?token|client[ _-]?secret|private[ _-]?key|secret[ _-]?key|token|"
    r"password|passwd|secret)\b['\"]?\s*[:=]\s*)"
    r"(?:"
    r'(?P<double_quoted>"(?:\\.|[^"\\\r\n])*")|'
    r"(?P<single_quoted>'(?:\\.|[^'\\\r\n])*')|"
    r"(?P<unquoted>[^\s,;}\]\"']+)"
    r")",
    re.IGNORECASE,
)


def sanitize_urls(text: str) -> str:
    def sanitize(match: re.Match[str]) -> str:
        url = URL_USERINFO_PATTERN.sub(r"\1", match.group(0))
        return re.sub(r"[?#].*$", "", url)

    return URL_PATTERN.sub(sanitize, text)


def redact(text: str, env: dict[str, str]) -> str:
    sanitized = sanitize_urls(text)
    for value in env.values():
        if isinstance(value, str) and len(value) >= 4:
            sanitized = sanitized.replace(value, "[redacted]")
            sanitized_value = sanitize_urls(value)
            if sanitized_value != value:
                sanitized = sanitized.replace(sanitized_value, "[redacted]")
    sanitized = EMAIL_PATTERN.sub("[redacted email]", sanitized)
    sanitized = BEARER_TOKEN_PATTERN.sub(r"\1[redacted]", sanitized)
    sanitized = AUTHORIZATION_VALUE_PATTERN.sub(r"\1[redacted]", sanitized)
    sanitized = COOKIE_VALUE_PATTERN.sub(r"\1[redacted]", sanitized)
    sanitized = JWT_PATTERN.sub("[redacted token]", sanitized)
    sanitized = SENSITIVE_VALUE_PATTERN.sub(redact_sensitive_value, sanitized)
    # Dependency installers and server banners can put the useful failure at
    # the end of stderr. Keep a bounded head and tail so the outer process can
    # discard startup noise without losing the root cause.
    if len(sanitized) <= 12000:
        return sanitized
    return f"{sanitized[:1000]}\n…\n{sanitized[-10997:]}"


def redact_sensitive_value(match: re.Match[str]) -> str:
    if match.group("double_quoted") is not None:
        redacted = '"[redacted]"'
    elif match.group("single_quoted") is not None:
        redacted = "'[redacted]'"
    else:
        redacted = "[redacted]"
    return f"{match.group('prefix')}{redacted}"


def write_result(result: dict[str, Any]) -> None:
    Path("result.json").write_text(json.dumps(result), encoding="utf-8")


async def main() -> None:
    # Apply the process cap before anything untrusted (the MCP command) runs.
    _enforce_nproc_limit()

    payload = json.loads(Path("input.json").read_text(encoding="utf-8"))
    _enforce_payload_rlimits(payload.get("rlimits") or {})
    _become_subreaper()
    command = payload["command"]
    args = payload.get("args") or []
    env = payload.get("env") or {}
    timeout = int(payload["timeout"])
    stderr_log = Path("mcp-server.stderr.log")

    try:
        transport = StdioTransport(
            command=command,
            args=args,
            env=env,
            cwd=payload.get("cwd") or "/tmp",
            keep_alive=False,
            log_file=stderr_log,
        )
        async with asyncio.timeout(timeout):
            async with Client(transport) as client:
                tools = await client.list_tools()
        write_result(
            {
                "success": True,
                "output": {
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "input_schema": tool.inputSchema,
                        }
                        for tool in tools
                    ]
                },
                "stdout": "",
                "stderr": "",
                "error": None,
            }
        )
    except TimeoutError:
        write_result(
            {
                "success": False,
                "output": None,
                "stdout": "",
                "stderr": "",
                "error": f"Timed out after {timeout}s while probing stdio MCP server",
                "error_code": "timeout",
            }
        )
    except BaseException as exc:
        stderr = ""
        if stderr_log.exists():
            stderr = _read_stderr_tail(stderr_log)
        detail = f"{type(exc).__name__}: {exc}"
        if stderr:
            detail = f"{detail}\n{stderr}"
        else:
            detail = f"{detail}\n{traceback.format_exc(limit=3)}"
        write_result(
            {
                "success": False,
                "output": None,
                "stdout": "",
                "stderr": "",
                "error": redact(detail, env),
            }
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        _kill_descendants()
"""


def _site_packages_dir() -> Path:
    site_packages = sysconfig.get_path("purelib")
    if not site_packages:
        raise RuntimeError("Could not resolve Python site-packages path")
    return Path(site_packages)


def _parse_probe_tools(output: object) -> list[MCPToolSummary]:
    if not isinstance(output, dict):
        return []
    raw_tools = output.get("tools")
    if not isinstance(raw_tools, list):
        return []
    tools: list[MCPToolSummary] = []
    for raw_tool in raw_tools:
        if not isinstance(raw_tool, dict):
            continue
        name = raw_tool.get("name")
        if not isinstance(name, str) or not name:
            continue
        if not MCP_TOOL_NAME_RE.fullmatch(name):
            logger.warning(
                "Skipping stdio MCP tool with unsupported name",
                tool_name=name,
            )
            continue
        description = raw_tool.get("description")
        input_schema = raw_tool.get("input_schema")
        tools.append(
            MCPToolSummary(
                name=name,
                description=description if isinstance(description, str) else None,
                input_schema=input_schema if isinstance(input_schema, dict) else None,
            )
        )
    return tools


DIRECT_PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
"""Bytes of probe stdout and stderr the host keeps; the rest is discarded."""

DIRECT_PROBE_RESULT_LIMIT_BYTES = 8 * 1024 * 1024
"""Largest ``result.json`` the host reads from a direct-backend probe."""

DIRECT_PROBE_MAX_FILE_SIZE_MB = 256
DIRECT_PROBE_MAX_OPEN_FILES = 512

_DIRECT_PROBE_INHERITED_ENV_NAMES = BASE_ENV_NAMES - {
    "PYTHONPATH",
    "PYTHONUSERBASE",
    "VIRTUAL_ENV",
}
"""Worker variables a direct-backend probe keeps: plumbing, locale, CA bundles
and the operator proxy, never credentials or the worker's Python roots."""


def _kill_probe_process_group(process: asyncio.subprocess.Process) -> None:
    """Kill everything left in the probe's process group.

    The probe starts in its own session, so its process group id is its pid.
    The kernel never hands out a pid that is still in use as a group id, so
    this cannot hit an unrelated process after the probe itself has exited.
    """
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)


def _kill_probe_process_tree(process: asyncio.subprocess.Process) -> None:
    """Kill the probe and its spawned MCP server on timeout."""
    _kill_probe_process_group(process)
    with suppress(ProcessLookupError):
        process.kill()


def _direct_probe_env(job_dir: Path) -> dict[str, str]:
    """Return the environment for a direct-backend probe.

    The probe and the MCP server it starts run as the worker's user, so they
    start from an allowlist instead of the worker's environment. ``PATH`` is
    the agent runtime's, so the probe resolves the command the way agent runs
    will, reduced to directories this user cannot write. ``HOME`` is private
    instead of the worker's, whose dotfiles (``.npmrc``, ``.netrc``, caches)
    the server must not read or poison.
    """
    home = job_dir / "home"
    tmp = job_dir / "tmp"
    home.mkdir(mode=0o700, exist_ok=True)
    tmp.mkdir(mode=0o700, exist_ok=True)
    env = select_env(os.environ, names=_DIRECT_PROBE_INHERITED_ENV_NAMES)
    env.update(
        {
            "PATH": trusted_path(AGENT_SANDBOX_BASE_ENV["PATH"]) or os.devnull,
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "PYTHONPATH": str(_site_packages_dir()),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def _direct_probe_rlimits(timeout_seconds: int) -> dict[str, int]:
    """Resource caps the probe applies to itself and the MCP server.

    Mirrors the nsjail probe without cgroups: CPU time, file size, open files
    and no core dumps. There is deliberately no address-space cap
    (``RLIMIT_AS``): runtimes such as Node (WebAssembly, ``fetch``), the JVM
    and .NET reserve large virtual ranges up front and fail under one, and
    direct-mode agent runs start the same servers uncapped. There is no
    per-user process cap either: ``RLIMIT_NPROC`` counts every process of the
    worker's user, so it cannot bound the probe alone.
    """
    return {
        "RLIMIT_CORE": 0,
        "RLIMIT_CPU": timeout_seconds + MCP_STDIO_PROBE_HARD_TIMEOUT_BUFFER,
        "RLIMIT_FSIZE": DIRECT_PROBE_MAX_FILE_SIZE_MB * 1024 * 1024,
        "RLIMIT_NOFILE": DIRECT_PROBE_MAX_OPEN_FILES,
    }


async def _read_bounded(stream: asyncio.StreamReader | None, limit: int) -> bytes:
    """Read a stream to EOF, keeping at most ``limit`` bytes.

    The rest is read and discarded so the child never blocks on a full pipe
    and never makes the worker buffer unbounded output.
    """
    if stream is None:
        return b""
    kept = bytearray()
    while chunk := await stream.read(64 * 1024):
        if len(kept) < limit:
            kept.extend(chunk[: limit - len(kept)])
    return bytes(kept)


class _ProbeResultTooLargeError(Exception):
    """The probe wrote a result file larger than the host reads."""


def _read_probe_result(result_path: Path) -> object | None:
    """Read the probe's result file, refusing one larger than the cap.

    Raises:
        _ProbeResultTooLargeError: If the file exceeds the cap.
    """
    try:
        if result_path.stat().st_size > DIRECT_PROBE_RESULT_LIMIT_BYTES:
            raise _ProbeResultTooLargeError
        return orjson.loads(result_path.read_bytes())
    except (OSError, orjson.JSONDecodeError):
        return None


async def _execute_probe_without_nsjail(
    job_dir: Path,
    *,
    timeout_seconds: int,
) -> SandboxResult:
    """Run the probe with best-effort isolation for the direct backend.

    Mirrors ``UnsafePidExecutor``: ``unshare --pid --fork --kill-child`` when
    the host supports it, otherwise a plain subprocess in its own session so
    the process tree can still be reaped. The probe gets an allowlisted
    environment, a private home, rlimits (applied by the probe script from
    ``input.json``) and bounded output. There is no filesystem or network
    isolation on this path.
    """
    # The worker's own interpreter: a PATH lookup could pick another Python
    # that cannot import the worker's site-packages.
    cmd = [sys.executable, "probe.py"]
    if await pid_namespace_available():
        cmd = ["unshare", "--pid", "--fork", "--kill-child", *cmd]

    process = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=job_dir,
        env=_direct_probe_env(job_dir),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        # The +10s buffer lets the probe script's internal timeout produce a
        # graceful result before the hard kill, matching the nsjail path.
        async with asyncio.timeout(timeout_seconds + 10):
            stdout_bytes, stderr_bytes, _ = await asyncio.gather(
                _read_bounded(process.stdout, DIRECT_PROBE_OUTPUT_LIMIT_BYTES),
                _read_bounded(process.stderr, DIRECT_PROBE_OUTPUT_LIMIT_BYTES),
                process.wait(),
            )
    except TimeoutError as exc:
        _kill_probe_process_tree(process)
        await process.wait()
        raise SandboxTimeoutError(
            f"Timed out after {timeout_seconds}s while probing stdio MCP server"
        ) from exc
    finally:
        # Reap MCP server processes that outlived the probe in this group.
        _kill_probe_process_group(process)

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    result_path = job_dir / "result.json"
    if result_path.exists():
        try:
            result_data = _read_probe_result(result_path)
        except _ProbeResultTooLargeError:
            return SandboxResult(
                success=False,
                error=(
                    "Stdio MCP server's tool list exceeded the "
                    f"{DIRECT_PROBE_RESULT_LIMIT_BYTES // (1024 * 1024)} MiB limit"
                ),
                exit_code=process.returncode,
            )
        if isinstance(result_data, dict):
            return SandboxResult(
                success=result_data.get("success", False),
                output=result_data.get("output"),
                stdout=result_data.get("stdout", stdout),
                stderr=result_data.get("stderr", stderr),
                error=result_data.get("error"),
                error_code=(
                    SandboxErrorCode(error_code)
                    if (error_code := result_data.get("error_code"))
                    else None
                ),
                exit_code=process.returncode,
            )

    return SandboxResult(
        success=False,
        error="Stdio MCP probe exited without producing a result",
        stdout=stdout,
        stderr=stderr[:500],
        exit_code=process.returncode,
    )


async def probe_stdio_mcp_tools_in_sandbox(
    *,
    command: str,
    args: list[str] | None,
    env: dict[str, str] | None,
    timeout: int,
) -> StdioMCPProbeResult:
    """Run a stdio MCP server using the configured backend and list its tools.

    AUTOSECOPS__EXECUTOR_BACKEND selects nsjail or direct execution. The nsjail
    backend returns probe failures without falling back to direct execution.
    The direct backend uses the same best-effort PID-level isolation as
    unsandboxed Python actions, regardless of nsjail availability.
    """
    timeout_seconds = timeout
    hard_timeout_seconds = timeout_seconds + MCP_STDIO_PROBE_HARD_TIMEOUT_BUFFER
    payload: dict[str, Any] = {
        "command": command,
        "args": args or [],
        "env": env or {},
        "timeout": timeout_seconds,
    }
    uses_nsjail = config.AUTOSECOPS__EXECUTOR_BACKEND.uses_nsjail
    if not uses_nsjail:
        # nsjail applies these itself; the direct probe applies them in-process.
        payload["rlimits"] = _direct_probe_rlimits(timeout_seconds)

    try:
        with tempfile.TemporaryDirectory(prefix="mcp-stdio-probe-") as temp_dir:
            job_dir = Path(temp_dir)
            (job_dir / "probe.py").write_text(
                textwrap.dedent(_SANDBOX_PROBE_SCRIPT).lstrip(),
                encoding="utf-8",
            )
            if not uses_nsjail:
                # Run the server from a private directory, not the shared /tmp.
                payload["cwd"] = str(job_dir / "home")
            (job_dir / "input.json").write_bytes(orjson.dumps(payload))

            if uses_nsjail:
                probe_limits = AgentResourceLimits(
                    memory_mb=min(1024, config.AUTOSECOPS__AGENT_SANDBOX_MEMORY_MB)
                )
                sandbox = NsjailExecutor(cgroup_mount=sandbox_cgroup())
                result = await sandbox.execute(
                    job_dir,
                    SandboxConfig(
                        network=SandboxNetworkRequest(SandboxNetworkPurpose.AGENT),
                        resources=ResourceLimits(
                            memory_mb=probe_limits.memory_mb,
                            address_space_mb=probe_limits.address_space_mb,
                            cpu_seconds=hard_timeout_seconds,
                            max_open_files=512,
                            max_processes=128,
                            timeout_seconds=hard_timeout_seconds,
                        ),
                        python_path_dirs=[_site_packages_dir()],
                    ),
                    script_name="probe.py",
                )
            else:
                logger.warning(
                    "Running stdio MCP probe without nsjail; applying "
                    "best-effort PID isolation and resource limits only"
                )
                result = await _execute_probe_without_nsjail(
                    job_dir,
                    timeout_seconds=timeout_seconds,
                )
    except SandboxTimeoutError:
        return StdioMCPProbeResult(
            success=False,
            message="Connection to the MCP server timed out",
            error=f"Timed out after {timeout_seconds}s while probing stdio MCP server",
        )
    except Exception as exc:
        error = sanitize_stdio_probe_error(str(exc), env=env)
        return StdioMCPProbeResult(
            success=False,
            message="Failed to run stdio MCP probe in the sandbox",
            error=error,
        )

    if not result.success:
        if result.error_code is SandboxErrorCode.TIMEOUT:
            return StdioMCPProbeResult(
                success=False,
                message="Connection to the MCP server timed out",
                error=f"Timed out after {timeout_seconds}s while probing stdio MCP server",
            )
        # Python-sandbox probes report string errors; stringify defensively in
        # case a structured action-style error ever reaches this path.
        probe_error = (
            result.error
            if isinstance(result.error, str) or result.error is None
            else str(result.error)
        )
        error = sanitize_stdio_probe_error(probe_error or result.stderr, env=env)
        return StdioMCPProbeResult(
            success=False,
            message="Failed to connect to the stdio MCP server",
            error=error,
        )

    tools = _parse_probe_tools(result.output)
    return StdioMCPProbeResult(
        success=True,
        tools=tools,
        message=f"Connected successfully — {len(tools)} tools available",
    )


class NsjailStdioMCPRunner:
    """Built-in stdio MCP runner: probes under nsjail and refuses tool calls.

    Runtimes that use the built-in runner start stdio servers themselves, so
    the trusted MCP server never routes a stdio call here. Calls are refused
    rather than run, because untrusted server code must not run in the
    trusted plane.
    """

    async def list_tools(
        self, server: StdioMCPServer, env: dict[str, str] | None
    ) -> StdioMCPProbeResult:
        return await probe_stdio_mcp_tools_in_sandbox(
            command=server.command,
            args=list(server.args),
            env=env,
            timeout=MCP_STDIO_PROBE_TIMEOUT_CAP,
        )

    async def call_tool(
        self,
        server: StdioMCPServer,
        env: dict[str, str] | None,
        tool: str,
        args: dict[str, Any],
    ) -> CallToolResult:
        del env, tool, args
        raise StdioMCPRunnerUnsupportedError(
            f"Stdio MCP server '{server.name}' can't be called through the "
            "AutoSecOps MCP server: no stdio MCP runner is installed"
        )
