from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import subprocess
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING

import aiofiles
import paramiko
from pydantic import SecretStr
from slugify import slugify
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.types import Role
from autosecops.contexts import ctx_role
from autosecops.exceptions import AutoSecOpsCredentialsError
from autosecops.logger import logger
from autosecops.process_env import tool_subprocess_env
from autosecops.secrets.schemas import SSHKeyTarget
from autosecops.secrets.service import SecretsService

if TYPE_CHECKING:
    from autosecops.git.types import GitUrl

# Export list for backward compatibility
__all__ = [
    "SshEnv",
    "temporary_ssh_agent",
    "add_host_to_known_hosts",
    "add_ssh_key_to_agent",
    "get_ssh_command",
    "prepare_ssh_key_file",
    "ssh_context",
    "get_git_ssh_command",
]


_AGENT_START_SECONDS = 10.0
_AGENT_STDERR_LIMIT = 4096
_MAX_UNIX_SOCKET_PATH = 108
_AGENT_STOP_SECONDS = 10.0

INVALID_SSH_KEY_MESSAGE = (
    "Invalid SSH key: AutoSecOps supports only unencrypted Ed25519 private keys."
)


@dataclass
class SshEnv:
    ssh_auth_sock: str
    ssh_agent_pid: str
    known_hosts_path: str | None = None
    """Private known_hosts file for this agent's connections."""
    identity_path: str | None = None
    """Public key selecting the one agent identity ssh may offer."""

    def ssh_command(self) -> str | None:
        """Return the ``GIT_SSH_COMMAND`` that pins ssh to this context.

        ``~/.ssh`` is writable by any code running as the platform user, so
        ssh reads no user configuration (``-F /dev/null``), trusts only this
        context's known_hosts file, and offers only this context's key.

        Returns:
            The command, or None for an agent without a private context.
        """
        if self.known_hosts_path is None:
            return None
        parts = [
            "ssh",
            "-F",
            os.devnull,
            "-o",
            f"UserKnownHostsFile={self.known_hosts_path}",
            "-o",
            f"GlobalKnownHostsFile={os.devnull}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "BatchMode=yes",
        ]
        if self.identity_path is not None:
            parts += [
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                f"IdentityFile={self.identity_path}",
            ]
        return shlex.join(parts)

    def to_dict(self) -> dict[str, str]:
        env = {
            "SSH_AUTH_SOCK": self.ssh_auth_sock,
            "SSH_AGENT_PID": self.ssh_agent_pid,
        }
        if (command := self.ssh_command()) is not None:
            env["GIT_SSH_COMMAND"] = command
        return env


@asynccontextmanager
async def temporary_ssh_agent(
    *, socket_dir: Path | None = None
) -> AsyncIterator[SshEnv]:
    """Run a dedicated SSH agent without mutating the worker environment.

    The agent runs in the foreground (``-D``) as a child of this process and
    is stopped and reaped on exit. A daemonized agent would be reparented to
    PID 1, the worker itself, which never reaps it.

    Args:
        socket_dir: Optional private directory in which to create the agent socket.

    Yields:
        Connection details for the dedicated agent.
    """
    with contextlib.ExitStack() as stack:
        if socket_dir is None:
            socket_dir = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="autosecops-agent-")
                )
            )
        socket_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        socket_dir.chmod(0o700)
        socket_path = socket_dir / "agent.sock"
        if len(os.fsencode(socket_path)) >= _MAX_UNIX_SOCKET_PATH:
            # AF_UNIX paths are limited to 108 bytes; fall back to a short
            # private directory under /tmp.
            socket_path = (
                Path(stack.enter_context(tempfile.TemporaryDirectory(dir="/tmp")))
                / "agent.sock"
            )
        logger.debug("Starting ssh-agent")
        try:
            process = await asyncio.create_subprocess_exec(
                "ssh-agent",
                "-D",
                "-a",
                str(socket_path),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                limit=_AGENT_STDERR_LIMIT,
                # The agent lives as long as the sync; it must not hold
                # platform credentials in an environment readable via /proc.
                env=tool_subprocess_env(),
                start_new_session=True,
            )
        except OSError as e:
            logger.error("Failed to start ssh-agent", error=str(e))
            raise RuntimeError("Failed to start ssh-agent") from e
        stderr_tail = bytearray()
        drain = asyncio.create_task(_drain_agent_stderr(process, stderr_tail))
        try:
            await _wait_for_agent_socket(process, socket_path, stderr_tail)
            env = SshEnv(
                ssh_auth_sock=str(socket_path),
                ssh_agent_pid=str(process.pid),
            )
            logger.debug("Started ssh-agent", SSH_AUTH_SOCK=env.ssh_auth_sock)
            yield env
        finally:
            logger.debug("Stopping ssh-agent")
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=_AGENT_STOP_SECONDS)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
            drain.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await drain


async def _drain_agent_stderr(
    process: asyncio.subprocess.Process, tail: bytearray
) -> None:
    """Keep the agent's stderr pipe empty, remembering its last few KiB."""
    if process.stderr is None:
        return
    while chunk := await process.stderr.read(_AGENT_STDERR_LIMIT):
        tail += chunk
        del tail[: max(0, len(tail) - _AGENT_STDERR_LIMIT)]


async def _wait_for_agent_socket(
    process: asyncio.subprocess.Process, socket_path: Path, stderr_tail: bytearray
) -> None:
    """Wait until a foreground ssh-agent listens on its socket."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _AGENT_START_SECONDS
    while not socket_path.exists():
        if process.returncode is not None:
            await asyncio.sleep(0)
            logger.error(
                "Failed to start ssh-agent",
                stderr=bytes(stderr_tail).decode(errors="replace"),
            )
            raise RuntimeError("Failed to start ssh-agent")
        if loop.time() >= deadline:
            logger.error("SSH-agent execution timed out")
            raise RuntimeError("SSH-agent execution timed out")
        await asyncio.sleep(0.01)


def _split_host_port(url: str) -> tuple[str, str | None]:
    """Split a host string into host and port components."""

    if url.startswith("[") and "]" in url:
        closing_idx = url.index("]")
        host_part = url[1:closing_idx]
        remainder = url[closing_idx + 1 :]
        if remainder.startswith(":") and remainder[1:].isdigit():
            return host_part, remainder[1:]
        if not remainder:
            return host_part, None
        return url, None

    # Only treat single-colon inputs as host:port; IPv6 literals contain multiple colons
    if url.count(":") == 1:
        host_part, port_part = url.rsplit(":", 1)
        if port_part.isdigit():
            return host_part, port_part
    return url, None


def add_host_to_known_hosts_sync(url: str, env: SshEnv) -> None:
    """Synchronously add the host to the known hosts file if not already present.

    Args:
        url: The host URL to add
        env: SSH environment variables

    Raises:
        Exception: If ssh-keyscan fails to get the host key
    """
    try:
        if env.known_hosts_path is not None:
            known_hosts_file = Path(env.known_hosts_path)
        else:
            # Ensure the ~/.ssh directory exists
            ssh_dir = Path.home() / ".ssh"
            ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            known_hosts_file = ssh_dir / "known_hosts"

        host, port = _split_host_port(url)
        if port:
            formatted_host = f"[{host}]:{port}"
            known_host_tokens = {url, formatted_host, host}
        else:
            formatted_host = host
            known_host_tokens = {url, formatted_host}

        # Check if host already exists in known_hosts
        if known_hosts_file.exists():
            with known_hosts_file.open("r") as f:
                # Look for the hostname in existing entries
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    entry_host = stripped.split()[0]
                    # known_hosts entries can list multiple hosts separated by commas
                    matching_host = next(
                        (
                            host
                            for host in entry_host.split(",")
                            if host in known_host_tokens
                        ),
                        None,
                    )
                    if matching_host:
                        logger.debug(
                            "Host already in known_hosts file",
                            url=url,
                            entry_host=matching_host,
                        )
                        return
        # Use ssh-keyscan to get the host key
        cmd = ["ssh-keyscan"]
        if port:
            cmd.extend(["-p", port])
        cmd.append(host)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=tool_subprocess_env(env.to_dict()),
            check=False,
            timeout=30.0,  # Prevent indefinite hang if network is unavailable
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to get host key: {result.stderr.strip()}")

        output_lines = result.stdout.splitlines(keepends=True)
        if port:
            rewritten_lines = []
            for line in output_lines:
                if line.startswith(host):
                    rewritten_lines.append(formatted_host + line[len(host) :])
                else:
                    rewritten_lines.append(line)
            output = "".join(rewritten_lines)
        else:
            output = "".join(output_lines)

        # Append the host key to the known_hosts file
        with known_hosts_file.open("a") as f:
            f.write(output)

        logger.info("Added host to known hosts", url=url)
    except Exception as e:
        logger.error("Error adding host to known hosts", error=e)
        raise


async def add_host_to_known_hosts(url: str, *, env: SshEnv) -> None:
    """Asynchronously add the host to the known hosts file."""
    return await asyncio.to_thread(add_host_to_known_hosts_sync, url, env)


def _pinned_known_hosts() -> str:
    """Return the operator's pinned known_hosts entries, if configured."""
    path = config.AUTOSECOPS__GIT_SSH_KNOWN_HOSTS_FILE
    if not path:
        return ""
    try:
        return Path(path).read_text()
    except OSError as e:
        raise RuntimeError("Cannot read AUTOSECOPS__GIT_SSH_KNOWN_HOSTS_FILE") from e


def _public_key_line(key_data: str) -> str:
    """Return the OpenSSH public key line for an Ed25519 private key."""
    key_with_newline = key_data if key_data.endswith("\n") else key_data + "\n"
    try:
        key = paramiko.Ed25519Key.from_private_key(StringIO(key_with_newline))
    except paramiko.SSHException as e:
        raise AutoSecOpsCredentialsError(INVALID_SSH_KEY_MESSAGE) from e
    return f"{key.get_name()} {key.get_base64()}\n"


def add_ssh_key_to_agent_sync(
    key_data: str,
    env: SshEnv,
    *,
    lifetime_seconds: int | None = None,
    destination: str | None = None,
    known_hosts_path: Path | None = None,
) -> None:
    """Synchronously add the SSH key to the agent without writing to disk.

    Uses stdin to pass the key directly to ssh-add, avoiding any filesystem writes.
    This is important for multi-tenant security.
    """
    # Ensure key ends with newline (required by ssh-add)
    key_with_newline = key_data if key_data.endswith("\n") else key_data + "\n"

    # Validate the key using paramiko (reads from string, no disk)
    try:
        paramiko.Ed25519Key.from_private_key(StringIO(key_with_newline))
    except paramiko.SSHException as e:
        logger.error(f"Invalid SSH key: {str(e)}")
        raise AutoSecOpsCredentialsError(INVALID_SSH_KEY_MESSAGE) from e

    try:
        cmd = ["ssh-add"]
        if lifetime_seconds is not None:
            cmd.extend(["-t", str(lifetime_seconds)])
        if destination is not None:
            if known_hosts_path is None:
                raise ValueError(
                    "known_hosts_path is required for an SSH destination constraint"
                )
            cmd.extend(["-H", str(known_hosts_path), "-h", destination])
        cmd.append("-")

        # Pass key via stdin using '-' - private key material never touches disk.
        result = subprocess.run(
            cmd,
            input=key_with_newline,
            capture_output=True,
            text=True,
            env=tool_subprocess_env(env.to_dict()),
            check=False,
            timeout=30.0,  # Prevent indefinite hang
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to add SSH key: {result.stderr.strip()}")

        logger.info("Added SSH key to agent (via stdin, no disk write)")
    except Exception as e:
        logger.error("Error adding SSH key", error=e)
        raise


async def add_ssh_key_to_agent(
    key_data: str,
    env: SshEnv,
    *,
    lifetime_seconds: int | None = None,
    destination: str | None = None,
    known_hosts_path: Path | None = None,
) -> None:
    """Asynchronously add one key to an SSH agent."""
    return await asyncio.to_thread(
        add_ssh_key_to_agent_sync,
        key_data,
        env,
        lifetime_seconds=lifetime_seconds,
        destination=destination,
        known_hosts_path=known_hosts_path,
    )


async def get_ssh_command(git_url: GitUrl, role: Role, session: AsyncSession) -> str:
    """Get an SSH command for the given Git URL and SSH key."""
    role = role or ctx_role.get()
    service = SecretsService(session=session, role=role)
    ssh_key = await service.get_ssh_key()
    ssh_cmd = await prepare_ssh_key_file(git_url=git_url, ssh_key=ssh_key)
    return ssh_cmd


async def prepare_ssh_key_file(git_url: GitUrl, ssh_key: SecretStr) -> str:
    """Prepare an SSH key file for use in an SSH command."""
    key_dir = Path.home().joinpath(".autosecops")
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_path = key_dir / slugify(f"{git_url.host}_{git_url.org}_{git_url.repo}")

    # Write the key content to the file with proper permissions
    async with aiofiles.open(key_path, mode="w", encoding="utf-8") as f:
        await f.write(ssh_key.get_secret_value())
        await f.flush()

    # Set strict permissions after writing (important!)
    os.chmod(key_path, 0o600)

    logger.debug("Created SSH key file", key_path=key_path)

    # Use the key file in SSH command with more permissive host key checking.
    # -F /dev/null: ~/.ssh/config is writable by direct-mode action code.
    ssh_cmd = (
        f"ssh -F /dev/null -i {key_path!s} -o IdentitiesOnly=yes "
        "-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile={Path.home().joinpath('.ssh/known_hosts')!s}"
    )
    return ssh_cmd


@asynccontextmanager
async def ssh_context(
    *,
    git_url: GitUrl | None = None,
    session: AsyncSession,
    role: Role | None = None,
    key_name: str | None = None,
    target: SSHKeyTarget = "registry",
) -> AsyncIterator[SshEnv | None]:
    """Context manager for SSH environment variables."""
    if git_url is None:
        yield None
    else:
        sec_svc = SecretsService(session, role=role)
        secret = await sec_svc.get_ssh_key(key_name=key_name, target=target)
        # Keep the agent socket, known_hosts and the selected identity out of
        # ~/.ssh, which any code running as the platform user can rewrite.
        with tempfile.TemporaryDirectory(prefix="autosecops-ssh-") as raw_dir:
            context_dir = Path(raw_dir)
            async with temporary_ssh_agent(socket_dir=context_dir / "agent") as agent:
                known_hosts = context_dir / "known_hosts"
                known_hosts.touch(mode=0o600)
                known_hosts.write_text(_pinned_known_hosts())
                identity = context_dir / "identity.pub"
                identity.write_text(_public_key_line(secret.get_secret_value()))
                env = replace(
                    agent,
                    known_hosts_path=str(known_hosts),
                    identity_path=str(identity),
                )
                await add_ssh_key_to_agent(secret.get_secret_value(), env=env)
                await add_host_to_known_hosts(git_url.host, env=env)
                yield env


# New SSH helper functions for Git operations


async def get_git_ssh_command(
    git_url: GitUrl, *, session: AsyncSession, role: Role | None
) -> str:
    """Get a Git SSH command for the given Git URL.

    Args:
        git_url: Git URL object containing repository information.
        session: Database session.
        role: User role for permissions.

    Returns:
        SSH command string for use with GIT_SSH_COMMAND.

    Raises:
        Exception: If SSH key retrieval or file preparation fails.
    """
    role = role or ctx_role.get()
    service = SecretsService(session=session, role=role)
    ssh_key = await service.get_ssh_key(target="registry")
    ssh_cmd = await prepare_ssh_key_file(git_url=git_url, ssh_key=ssh_key)
    return ssh_cmd
