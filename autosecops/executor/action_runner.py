"""Action runner for subprocess-based execution (untrusted mode).

This module provides the ActionRunner class that executes registry actions
in isolated subprocesses with registry artifact caching.

All execution is untrusted - DB credentials are never passed to subprocesses.
Secrets and variables are pre-resolved on the host.

Key features:
- Registry artifacts: Materializes pre-built registry environments from S3
- Caching: Reuses materialized environments by cache key for fast subsequent runs
- Subprocess execution: Runs actions via minimal_runner.py
- nsjail sandboxing: Optional OS-level isolation with resource limits
- Timeout handling: Kills subprocess on timeouts
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import os
import shutil
import socket
import sys
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson
from autosecops_ee.tunnels.routing import (
    TunnelRouteError,
    effective_tunnel,
    tunnel_proxy_env,
)
from pydantic_core import to_json

from autosecops import config
from autosecops.contexts import ctx_secret_masks
from autosecops.executor.action_env import (
    build_direct_action_env,
    local_registry_import_paths,
)
from autosecops.executor.action_gateway.config import (
    ACTION_GATEWAY_SANDBOX_SOCKET,
    action_gateway_socket_path,
)
from autosecops.executor.minimal_runner import RUNNER_READY
from autosecops.executor.registry_artifacts import RegistryArtifactCache
from autosecops.executor.schemas import (
    ExecutorActionErrorInfo,
    ResolvedContext,
)
from autosecops.executor.secret_preprocessors import (
    SecretEnvProjection,
    project_secret_env,
)
from autosecops.logger import logger
from autosecops.outbound import TUNNEL_PROXY_ENV
from autosecops.process_env import which_trusted
from autosecops.sandbox.cgroup import sandbox_cgroup
from autosecops.sandbox.exceptions import (
    raise_for_sandbox_error_code,
    sandbox_resource_limit_message,
)
from autosecops.sandbox.executor import (
    ActionSandboxConfig,
    NsjailExecutor,
    workload_stderr_tail,
)
from autosecops.sandbox.networking import gateway_only_network_policy
from autosecops.sandbox.types import (
    ResourceLimits,
    SandboxErrorCode,
    SandboxNetworkPurpose,
    SandboxNetworkRequest,
)
from autosecops.sandbox.utils import (
    communicate_process_group,
    terminate_supervised_process,
)
from autosecops.secrets.common import (
    apply_masks_object,
)

if TYPE_CHECKING:
    from autosecops.auth.types import Role
    from autosecops.dsl.schemas import RunActionInput

type ExecutionResult = Any | ExecutorActionErrorInfo


def _get_autosecops_app_dir() -> Path:
    """Get the autosecops package directory for sandbox mounting.

    Returns the directory containing the autosecops package, which will be
    mounted read-only in the sandbox at /app.
    """
    # Check if explicitly configured
    if config.AUTOSECOPS__EXECUTOR_AUTOSECOPS_APP_DIR:
        return Path(config.AUTOSECOPS__EXECUTOR_AUTOSECOPS_APP_DIR)

    # Auto-detect from installed package location
    import autosecops

    autosecops_path = Path(autosecops.__file__).parent
    # Return parent (site-packages) so sandbox can import autosecops
    return autosecops_path.parent


def _get_site_packages_dir() -> Path | None:
    """Get the site-packages directory containing Python dependencies.

    Returns the site-packages directory where autosecops's dependencies
    (orjson, pydantic, sqlalchemy, etc.) are installed.
    """
    # Check if explicitly configured
    if config.AUTOSECOPS__EXECUTOR_SITE_PACKAGES_DIR:
        return Path(config.AUTOSECOPS__EXECUTOR_SITE_PACKAGES_DIR)

    # Auto-detect using sysconfig
    import sysconfig

    site_packages = sysconfig.get_path("purelib")
    if site_packages:
        return Path(site_packages)
    return None


# Keeps the whole message under the 2048-char cap that
# EventFailure.sanitize_error_text applies before the UI sees it.
_WORKLOAD_STDERR_MESSAGE_CHARS = 1900


def _sandbox_failure_message(
    error_code: SandboxErrorCode | None,
    *,
    stderr: str = "",
    mask_values: Iterable[str] = (),
) -> str:
    """Return the message carried by the typed exception a sandbox code selects.

    Infrastructure and resource-limit failures never quote sandbox output.
    Other workload failures append the masked tail of the workload's stderr so
    the action author sees the traceback that ended the run.
    """
    match error_code:
        case SandboxErrorCode.INFRASTRUCTURE_FAILURE:
            return "Action sandbox infrastructure failed before producing a result"
        case SandboxErrorCode.RESOURCE_LIMIT_EXCEEDED:
            return sandbox_resource_limit_message(
                memory_mb=config.AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB,
                memory_env_var="AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB",
            )
        case _:
            message = "Action sandbox workload stopped before producing a result"
            tail = workload_stderr_tail(stderr, limit=_WORKLOAD_STDERR_MESSAGE_CHARS)
            if not tail:
                return message
            masked_tail = apply_masks_object(tail, masks=mask_values)
            return f"{message}. Workload stderr (tail):\n{masked_tail}"


async def _send_payload_when_ready(
    payload_socket: socket.socket, payload: bytes, *, timeout: float
) -> None:
    """Send the runner its payload once it reports that it is protected.

    Args:
        payload_socket: The executor's end of the runner's stdin socket.
        payload: The serialized payload, including secrets.
        timeout: Seconds the runner may take to become ready.
    """
    loop = asyncio.get_running_loop()
    payload_socket.setblocking(False)
    try:
        async with asyncio.timeout(timeout):
            ready = await loop.sock_recv(payload_socket, len(RUNNER_READY))
    except TimeoutError:
        logger.error("Action runner did not become ready", timeout=timeout)
        payload_socket.shutdown(socket.SHUT_RDWR)
        return
    if ready != RUNNER_READY:
        # The runner exited or misbehaved; it gets no payload.
        payload_socket.shutdown(socket.SHUT_RDWR)
        return
    await loop.sock_sendall(payload_socket, payload)
    payload_socket.shutdown(socket.SHUT_WR)


def _direct_subprocess_command(minimal_runner_path: Path) -> list[str]:
    """Build a contained direct-action command with privileges disabled."""
    # Isolated mode (-I) ignores PYTHONPATH, the user site directory and the
    # working directory, all of which action code can write; the runner adds
    # the registry import roots itself. -B keeps bytecode out of those roots.
    runner_command = [sys.executable, "-I", "-B", str(minimal_runner_path)]
    # Only directories this user cannot write may supply setpriv.
    setpriv = which_trusted("setpriv")
    if setpriv is None:
        raise RuntimeError("setpriv is required for direct action subprocess isolation")

    supervisor_path = Path(__file__).with_name("process_supervisor.py")
    return [
        setpriv,
        "--no-new-privs",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        sys.executable,
        # Keep registry-controlled PYTHONPATH out of the supervisor interpreter.
        # Isolated mode leaves the environment intact for the nested action.
        "-I",
        str(supervisor_path),
        *runner_command,
    ]


class ActionRunner:
    """Runs registry actions in subprocesses with registry artifact caching.

    This runner:
    1. Materializes registry artifact URIs to cached Python paths
    2. Builds subprocess or sandbox execution environments
    3. Executes the action in a subprocess with PYTHONPATH set
    4. Returns the result or error
    """

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or Path(
            config.AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_DIR
        )
        self.registry_artifacts = RegistryArtifactCache(self.cache_dir)
        logger.info("ActionRunner initialized", cache_dir=str(self.cache_dir))

    async def execute_action(
        self,
        input: RunActionInput,
        role: Role,
        resolved_context: ResolvedContext,
        artifact_uris: list[str] | None = None,
        env_vars: dict[str, str] | None = None,
        timeout: float | None = None,
        use_sandbox: bool | None = None,
    ) -> ExecutionResult:
        """Execute an action in a subprocess (untrusted mode).

        All execution is in untrusted mode - DB credentials are never passed
        to subprocesses. Secrets and variables are pre-resolved on the host.

        Args:
            input: The RunActionInput containing task and context
            role: The Role for authorization
            artifact_uris: List of registry artifact S3 URIs (deterministic order)
            env_vars: Additional environment variables for the subprocess
            timeout: Execution timeout in seconds
            use_sandbox: Explicit subprocess mode; defaults to the configured backend.
            resolved_context: Pre-resolved context from service layer (optional,
                will be resolved here if not provided)

        Returns:
            The action result, or ExecutorActionErrorInfo on error
        """
        timeout = timeout or config.AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT

        # Both execution modes treat registry artifacts as shared import inputs.
        if use_sandbox is None:
            use_sandbox = config.AUTOSECOPS__EXECUTOR_BACKEND.uses_nsjail

        # Materialize each registry artifact, collect paths in deterministic order.
        # The lease is held for the whole subprocess execution so cache eviction
        # cannot delete a directory the subprocess is still importing from.
        async with self.registry_artifacts.lease(artifact_uris) as registry_paths:
            logger.debug(
                "Using sandbox execution",
                use_sandbox=use_sandbox,
            )

            secret_projection = resolved_context.secret_projection
            if secret_projection is None:
                secret_projection = await project_secret_env(
                    secrets=resolved_context.secrets,
                    role=role,
                    run_context=input.run_context,
                )

            if use_sandbox:
                return await self._execute_sandboxed(
                    input=input,
                    role=role,
                    registry_paths=registry_paths,
                    secret_projection=secret_projection,
                    env_vars=env_vars,
                    timeout=timeout,
                    resolved_context=resolved_context,
                )
            return await self._execute_direct(
                input=input,
                role=role,
                registry_paths=registry_paths,
                secret_projection=secret_projection,
                env_vars=env_vars,
                timeout=timeout,
                resolved_context=resolved_context,
            )

    async def _execute_sandboxed(
        self,
        input: RunActionInput,
        role: Role,
        registry_paths: list[Path],
        secret_projection: SecretEnvProjection,
        resolved_context: ResolvedContext,
        env_vars: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> ExecutionResult:
        """Execute an action in an nsjail sandbox (untrusted mode).

        All sandbox execution is untrusted - DB credentials are never passed.
        Secrets and variables must be pre-resolved and passed via resolved_context.

        Args:
            input: The RunActionInput containing task and context
            role: The Role for authorization
            registry_paths: List of directories containing extracted registry tarballs
            resolved_context: Pre-resolved secrets, variables, and action impl
            env_vars: Additional environment variables for the subprocess
            timeout: Execution timeout in seconds
        """
        timeout = timeout or config.AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT

        # Create temporary directory for file-based IPC
        job_dir = Path(tempfile.mkdtemp(prefix="autosecops_action_"))

        try:
            # Build payload with resolved_context
            payload: dict[str, Any] = {
                "input": input,
                "role": role,
                "resolved_context": resolved_context,
                "secret_env": secret_projection.env,
                "secret_mask_values": sorted(masks.values)
                if (masks := ctx_secret_masks.get())
                else [],
                "timeout_seconds": timeout,
            }
            # The runner times the function call; the jail only backstops
            # startup and serialization around it.
            hard_timeout = (
                timeout + config.AUTOSECOPS__EXECUTOR_SUBPROCESS_STARTUP_GRACE
            )

            # Write input JSON to job directory
            input_json = to_json(payload)
            input_path = job_dir / "input.json"
            input_path.write_bytes(input_json)

            # Copy minimal_runner.py to job directory
            from autosecops.executor import minimal_runner as minimal_runner_module

            minimal_runner_src = Path(minimal_runner_module.__file__)
            minimal_runner_dst = job_dir / "minimal_runner.py"
            shutil.copy2(minimal_runner_src, minimal_runner_dst)

            # Build environment variables for sandbox (untrusted mode only)
            # NOTE: DB credentials are intentionally NOT passed
            sandbox_env: dict[str, str] = {}
            if env_vars:
                sandbox_env.update(env_vars)
            # Only the executor may route an action through a tunnel.
            sandbox_env.pop(TUNNEL_PROXY_ENV, None)

            # SDK context for any registry SDK operations
            sandbox_env["AUTOSECOPS__API_URL"] = config.AUTOSECOPS__API_URL
            sandbox_env["AUTOSECOPS__WORKSPACE_ID"] = (
                str(role.workspace_id) if role.workspace_id else ""
            )
            sandbox_env["AUTOSECOPS__WORKFLOW_ID"] = str(input.run_context.wf_id)
            sandbox_env["AUTOSECOPS__RUN_ID"] = str(input.run_context.wf_run_id)
            sandbox_env["AUTOSECOPS__WF_EXEC_ID"] = str(input.run_context.wf_exec_id)
            sandbox_env["AUTOSECOPS__ENVIRONMENT"] = input.run_context.environment
            action_gateway_socket = action_gateway_socket_path()
            sandbox_env["AUTOSECOPS__ACTION_GATEWAY_SOCKET"] = str(
                ACTION_GATEWAY_SANDBOX_SOCKET
            )

            # Preserve the signed execution provenance from the service boundary.
            sandbox_env["AUTOSECOPS__EXECUTOR_TOKEN"] = resolved_context.executor_token

            network = SandboxNetworkRequest(SandboxNetworkPurpose.ACTION)
            if route := _tunnel_route(input, resolved_context):
                proxy_url, gateway_ip, gateway_port = route
                sandbox_env.update(tunnel_proxy_env(proxy_url))
                network = SandboxNetworkRequest(
                    SandboxNetworkPurpose.ACTION,
                    policy=gateway_only_network_policy(gateway_ip, gateway_port),
                )

            logger.debug(
                "Using untrusted mode - no DB credentials passed to sandbox",
                action=input.task.action,
            )

            # Configure sandbox
            sandbox_config = ActionSandboxConfig(
                registry_paths=registry_paths,
                autosecops_app_dir=_get_autosecops_app_dir(),
                site_packages_dir=_get_site_packages_dir(),
                env_vars=sandbox_env,
                network=network,
                action_gateway_socket=action_gateway_socket,
                action_gateway_socket_mount_path=ACTION_GATEWAY_SANDBOX_SOCKET,
                resources=ResourceLimits(
                    memory_mb=config.AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB,
                    address_space_mb=config.AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB,
                    timeout_seconds=math.ceil(hard_timeout),
                ),
                timeout_seconds=hard_timeout,
            )

            logger.debug(
                "Executing action in nsjail sandbox",
                action=input.task.action,
                job_dir=str(job_dir),
                registry_paths_count=len(registry_paths),
            )

            # Execute in sandbox
            start_time = time.monotonic()
            executor = NsjailExecutor(cgroup_mount=sandbox_cgroup())
            result = await executor.execute_action(job_dir, sandbox_config)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.info(
                "Sandbox execution completed",
                action=input.task.action,
                elapsed_ms=f"{elapsed_ms:.1f}",
                success=result.success,
                exit_code=result.exit_code,
            )

            # Process result
            if result.success:
                return result.output

            raise_for_sandbox_error_code(
                result.error_code,
                _sandbox_failure_message(
                    result.error_code,
                    stderr=result.stderr,
                    mask_values=secret_projection.mask_values,
                ),
            )

            # Handle error from sandbox
            if result.error:
                masked_error = apply_masks_object(
                    result.error, masks=secret_projection.mask_values
                )
                # Try to parse as ExecutorActionErrorInfo
                if isinstance(masked_error, dict):
                    return ExecutorActionErrorInfo.model_validate(masked_error)
                return ExecutorActionErrorInfo(
                    type="SandboxError",
                    message=str(masked_error),
                    action_name=input.task.action,
                    filename="<sandbox>",
                    function="execute_action",
                )

            return ExecutorActionErrorInfo(
                type="SandboxError",
                message=f"Sandbox execution failed with exit code {result.exit_code}",
                action_name=input.task.action,
                filename="<sandbox>",
                function="execute_action",
            )

        finally:
            # Cleanup job directory
            shutil.rmtree(job_dir, ignore_errors=True)

    async def _execute_direct(
        self,
        input: RunActionInput,
        role: Role,
        registry_paths: list[Path],
        secret_projection: SecretEnvProjection,
        env_vars: dict[str, str] | None = None,
        timeout: float | None = None,
        resolved_context: ResolvedContext | None = None,
    ) -> ExecutionResult:
        """Execute an action in a direct subprocess (no sandbox).

        Every exit kills lingering descendants before the registry-path lease
        protecting their imports can unwind.
        """
        timeout = timeout or config.AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT

        # Actions start from an allowlist, never the executor's environment:
        # it carries platform credentials (DB URI, encryption and service keys).
        env = build_direct_action_env(
            os.environ,
            passthrough=config.AUTOSECOPS__EXECUTOR_ENV_PASSTHROUGH,
        )
        if env_vars:
            env.update(env_vars)
        env.pop(TUNNEL_PROXY_ENV, None)
        # Credentials travel in the stdin payload, not the process environment,
        # and the runner applies them only after it is protected from other
        # same-user processes. A process's initial environment stays readable
        # through /proc until then, and its supervisor's for its whole life.
        runtime_env: dict[str, str] = {}

        # Ensure SDK context is available for registry actions executed by minimal_runner.
        if resolved_context is not None:
            env["AUTOSECOPS__API_URL"] = config.AUTOSECOPS__API_URL
            env["AUTOSECOPS__WORKSPACE_ID"] = resolved_context.workspace_id
            env["AUTOSECOPS__WORKFLOW_ID"] = resolved_context.workflow_id
            env["AUTOSECOPS__RUN_ID"] = resolved_context.run_id
            env["AUTOSECOPS__WF_EXEC_ID"] = str(input.run_context.wf_exec_id)
            env["AUTOSECOPS__ENVIRONMENT"] = input.run_context.environment
            env["AUTOSECOPS__ACTION_GATEWAY_SOCKET"] = str(action_gateway_socket_path())
            runtime_env["AUTOSECOPS__EXECUTOR_TOKEN"] = resolved_context.executor_token
            if route := _tunnel_route(input, resolved_context):
                proxy_env = tunnel_proxy_env(route[0])
                for name in proxy_env:
                    env.pop(name, None)
                runtime_env.update(proxy_env)
        elif effective_tunnel(input):
            raise TunnelRouteError("Tunneled actions require a resolved tunnel route")

        # Prepare input JSON for subprocess
        payload: dict[str, Any] = {"input": input, "role": role}
        if resolved_context is not None:
            payload["resolved_context"] = resolved_context
            payload["secret_env"] = secret_projection.env
            masks = ctx_secret_masks.get()
            payload["secret_mask_values"] = sorted(masks.values) if masks else []
        payload["runtime_env"] = runtime_env
        payload["timeout_seconds"] = timeout
        input_json = to_json(payload)
        # The runner times the function call; this only backstops startup and
        # serialization around it.
        hard_timeout = timeout + config.AUTOSECOPS__EXECUTOR_SUBPROCESS_STARTUP_GRACE

        # Build PYTHONPATH with multiple registry paths (deterministic order)
        pythonpath_parts = [str(p) for p in registry_paths if p.exists()]
        existing_pythonpath = env.get("PYTHONPATH", "")
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        pythonpath_parts.extend(local_registry_import_paths())
        env["PYTHONPATH"] = ":".join(pythonpath_parts) if pythonpath_parts else ""
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        # Get path to minimal_runner.py for subprocess execution
        from autosecops.executor import minimal_runner as minimal_runner_module

        minimal_runner_path = Path(minimal_runner_module.__file__)
        try:
            command = _direct_subprocess_command(minimal_runner_path)
        except RuntimeError as e:
            logger.error("Failed to prepare direct action subprocess", error=str(e))
            return ExecutorActionErrorInfo(
                type="SubprocessError",
                message=str(e),
                action_name=input.task.action,
                filename="<subprocess>",
                function="execute_action",
            )

        logger.debug(
            "Executing action in subprocess",
            action=input.task.action,
            timeout=timeout,
        )

        start_time = time.monotonic()
        # The payload (workspace secrets, executor token) travels over a socket
        # rather than a pipe: same-user code can open a dumpable process's pipe
        # through /proc/<pid>/fd, but never a socket. The runner asks for the
        # payload only after it has protected itself.
        payload_socket, runner_socket = socket.socketpair()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=runner_socket.fileno(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
        except BaseException:
            payload_socket.close()
            raise
        finally:
            runner_socket.close()
        payload_task = asyncio.create_task(
            _send_payload_when_ready(
                payload_socket,
                input_json,
                timeout=min(
                    hard_timeout, config.AUTOSECOPS__EXECUTOR_SUBPROCESS_STARTUP_GRACE
                ),
            )
        )

        try:
            stdout, stderr = await communicate_process_group(
                proc,
                timeout=hard_timeout,
                terminate=terminate_supervised_process,
            )
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.info(
                "Subprocess execution completed",
                action=input.task.action,
                elapsed_ms=f"{elapsed_ms:.1f}",
                returncode=proc.returncode,
            )
        except TimeoutError:
            logger.error(
                "Action subprocess outlived its timeout, killing it",
                action=input.task.action,
                timeout=timeout,
                hard_timeout=hard_timeout,
            )
            return ExecutorActionErrorInfo(
                type="TimeoutError",
                message=(
                    f"Action did not stop at its {timeout:g}s timeout and was "
                    f"killed by the executor's backstop after {hard_timeout:g}s"
                ),
                action_name=input.task.action,
                filename="<subprocess>",
                function="execute_action",
            )
        finally:
            payload_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await payload_task
            payload_socket.close()
        # Check for subprocess crash
        if proc.returncode != 0:
            logger.error(
                "Subprocess failed",
                action=input.task.action,
                returncode=proc.returncode,
                stderr_bytes=len(stderr),
            )
            return ExecutorActionErrorInfo(
                type="SubprocessError",
                message=f"Subprocess exited with code {proc.returncode}",
                action_name=input.task.action,
                filename="<subprocess>",
                function="execute_action",
            )

        # Parse result from stdout. Child-controlled bytes are never logged.
        try:
            result_data = orjson.loads(stdout)
        except orjson.JSONDecodeError as e:
            logger.error(
                "Failed to parse subprocess output",
                action=input.task.action,
                stdout_bytes=len(stdout),
                parser_position=e.pos,
            )
            return ExecutorActionErrorInfo(
                type="ProtocolError",
                message=f"Failed to parse subprocess output at byte {e.pos}",
                action_name=input.task.action,
                filename="<subprocess>",
                function="execute_action",
            )

        # Handle success or error
        if result_data.get("success"):
            return result_data["result"]

        # Reconstruct error info
        error_data = result_data.get("error")
        if error_data:
            return ExecutorActionErrorInfo.model_validate(
                apply_masks_object(error_data, masks=secret_projection.mask_values)
            )

        return ExecutorActionErrorInfo(
            type="UnknownError",
            message="Subprocess returned neither success nor error",
            action_name=input.task.action,
            filename="<subprocess>",
            function="execute_action",
        )


# Lazy singleton - no lifespan required
_action_runner: ActionRunner | None = None


def get_action_runner() -> ActionRunner:
    """Get the global ActionRunner instance (lazy initialized)."""
    global _action_runner
    if _action_runner is None:
        _action_runner = ActionRunner()
    return _action_runner


def _tunnel_route(
    input: RunActionInput, resolved_context: ResolvedContext
) -> tuple[str, str, int] | None:
    """Return the action's gateway route; fail closed if it was not resolved."""
    if not effective_tunnel(input):
        return None
    if (
        resolved_context.tunnel_proxy_url is None
        or resolved_context.tunnel_gateway_ip is None
        or resolved_context.tunnel_gateway_port is None
    ):
        raise TunnelRouteError("Tunneled actions require a resolved tunnel route")
    return (
        resolved_context.tunnel_proxy_url,
        resolved_context.tunnel_gateway_ip,
        resolved_context.tunnel_gateway_port,
    )
