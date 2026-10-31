"""
Subprocess utilities for running registry sync operations in isolation.

The calling process installs the repository, which needs settings, SSH keys and
the database. A subprocess then imports the installed package, which runs
repository code. It receives an allowlisted environment without platform
credentials, so repository code cannot read the database URI, encryption,
service or signing keys, or cloud credentials. The subprocess also keeps
importlib.reload side effects out of the calling process.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from pydantic import UUID4, ValidationError

from autosecops import config
from autosecops.auth.types import Role
from autosecops.authz.scopes import SERVICE_PRINCIPAL_SCOPES
from autosecops.exceptions import (
    AutoSecOpsCredentialsError,
    EntitlementRequired,
    RegistryError,
)
from autosecops.executor.action_env import ACTION_ENV_ALLOWED_NAMES
from autosecops.logger import logger
from autosecops.process_env import select_env
from autosecops.process_hardening import protect_process_from_inspection
from autosecops.registry.constants import DEFAULT_REGISTRY_ORIGIN
from autosecops.registry.repository import Repository
from autosecops.registry.sync.schemas import (
    SyncResultAdapter,
    SyncResultError,
    SyncResultSuccess,
)
from autosecops.sandbox.utils import communicate_process_group
from autosecops.settings.service import get_setting

MIN_DISCOVERY_TIMEOUT_SECONDS = 30.0
"""Seconds discovery may always run, even when installation used up the sync
timeout. The discovery timeout error reports the budget it actually had."""

REGISTRY_DISCOVERY_ENV_NAMES = ACTION_ENV_ALLOWED_NAMES | frozenset(
    {
        "AUTOSECOPS__APP_ENV",
        "AUTOSECOPS__LOG_FORMAT",
        "LOG_LEVEL",
        "AUTOSECOPS__LOCAL_REPOSITORY_ENABLED",
        "AUTOSECOPS__LOCAL_REPOSITORY_PATH",
        "AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH",
        "AUTOSECOPS__BUILTIN_REGISTRY_SOURCE_PATH",
    }
)
"""Variables the registry discovery subprocess inherits. None are credentials."""


def registry_discovery_env() -> dict[str, str]:
    """Return the environment for the subprocess that imports repository code.

    Returns:
        Process plumbing, Python import roots, proxies, CA bundles and the
        non-secret registry and logging settings. Platform credentials are
        never included.
    """
    env = select_env(os.environ, names=REGISTRY_DISCOVERY_ENV_NAMES)
    # Settings that may only have their code default in this process.
    if config.AUTOSECOPS__LOCAL_REPOSITORY_ENABLED:
        env["AUTOSECOPS__LOCAL_REPOSITORY_ENABLED"] = "true"
    if config.AUTOSECOPS__LOCAL_REPOSITORY_PATH:
        env["AUTOSECOPS__LOCAL_REPOSITORY_PATH"] = str(
            config.AUTOSECOPS__LOCAL_REPOSITORY_PATH
        )
    if config.AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH:
        env["AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH"] = str(
            config.AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH
        )
    if config.AUTOSECOPS__APP_ENV:
        env["AUTOSECOPS__APP_ENV"] = config.AUTOSECOPS__APP_ENV
    return env


async def fetch_actions_from_subprocess(
    origin: str,
    repository_id: UUID4,
    commit_sha: str | None = None,
    validate: bool = False,
    git_repo_package_name: str | None = None,
    timeout: float = 300.0,
    organization_id: UUID4 | None = None,
) -> SyncResultSuccess:
    """Install a repository here, then discover its actions in a subprocess.

    Installation needs settings, SSH keys and the database, so it runs in this
    process. ``python -m autosecops.registry.sync.entrypoint`` then imports the
    installed package without platform credentials; its stdout carries the
    JSON result and its stderr the logs.

    Args:
        origin: The repository origin (e.g., "autosecops_registry", "local", or git URL).
        repository_id: The UUID of the repository in the database.
        commit_sha: Optional commit SHA to checkout (for remote repos).
        validate: Whether to validate template actions.
        git_repo_package_name: Optional override for the git repository package name.
        timeout: Seconds for installation and discovery together (default: 5
            minutes). Discovery always gets at least
            ``MIN_DISCOVERY_TIMEOUT_SECONDS``.
        organization_id: Optional organization ID for accessing org-scoped secrets (e.g., SSH keys).

    Returns:
        SyncResultSuccess containing parsed actions, commit SHA, and any errors.

    Raises:
        RegistryError: If installation times out, or the subprocess fails or
            returns invalid JSON. Installation errors keep their own types,
            such as ``RegistryDependencyConflictError``.
    """
    # Repository code runs in children of this process. Whichever service runs
    # the sync (executor or API), keep it unreadable to them through /proc.
    protect_process_from_inspection()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    role = Role(
        type="service",
        service_id="autosecops-service",
        organization_id=organization_id,
        scopes=SERVICE_PRINCIPAL_SCOPES["autosecops-service"],
    )
    should_validate = validate or bool(
        await get_setting(
            "app_registry_validation_enabled",
            role=role,
            default=False,
        )
    )

    # Each sync installs into its own directory, which only the discovery
    # subprocess imports from and which is removed afterwards.
    with tempfile.TemporaryDirectory(prefix="autosecops-registry-") as target:
        site_dir: Path | None = None
        if origin == DEFAULT_REGISTRY_ORIGIN:
            package_name = DEFAULT_REGISTRY_ORIGIN
            resolved_commit_sha = commit_sha
        else:
            logger.info("Installing registry repository", origin=origin)
            scope = asyncio.timeout_at(deadline)
            try:
                async with scope:
                    installation = await Repository(
                        origin=origin,
                        role=role,
                        package_name_override=git_repo_package_name,
                    ).install_from_origin(
                        commit_sha=commit_sha, target_dir=Path(target)
                    )
            except TimeoutError as e:
                if scope.expired():
                    raise RegistryError(
                        f"Registry install timed out after {timeout:g}s for {origin!r}"
                    ) from None
                raise RegistryError(f"Failed to install {origin!r}: {e}") from e
            except (RegistryError, AutoSecOpsCredentialsError, EntitlementRequired):
                # Typed errors keep their type, e.g. dependency conflicts.
                raise
            except Exception as e:
                # Callers map RegistryError to a client error with this reason.
                raise RegistryError(f"Failed to install {origin!r}: {e}") from e
            package_name = installation.package_name
            resolved_commit_sha = installation.commit_sha
            site_dir = installation.site_dir

        cmd = [
            sys.executable,
            # No user site directory and no working directory on sys.path.
            "-s",
            "-P",
            "-m",
            "autosecops.registry.sync.entrypoint",
            "--origin",
            origin,
            "--package-name",
            package_name,
            "--repository-id",
            str(repository_id),
        ]
        if site_dir is not None:
            cmd.extend(["--site-dir", str(site_dir)])
        if resolved_commit_sha is not None:
            cmd.extend(["--commit-sha", resolved_commit_sha])
        if should_validate:
            cmd.append("--validate")
        if organization_id is not None:
            cmd.extend(["--organization-id", str(organization_id)])

        logger.info(
            "Starting sync subprocess",
            origin=origin,
            repository_id=str(repository_id),
            commit_sha=resolved_commit_sha,
            organization_id=str(organization_id) if organization_id else None,
        )
        budget = max(deadline - loop.time(), MIN_DISCOVERY_TIMEOUT_SECONDS)
        return await _run_discovery_subprocess(cmd, origin=origin, timeout=budget)


async def _run_discovery_subprocess(
    cmd: list[str], *, origin: str, timeout: float
) -> SyncResultSuccess:
    """Run the discovery CLI and parse its typed JSON result.

    Args:
        cmd: The discovery command.
        origin: The repository origin, for logs and errors.
        timeout: Seconds the subprocess may run before its process group is
            killed.

    Returns:
        The parsed discovery result.

    Raises:
        RegistryError: If the subprocess fails, times out, or returns invalid
            JSON.
    """
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=registry_discovery_env(),
        start_new_session=True,
    )
    try:
        stdout_bytes, stderr_bytes = await communicate_process_group(
            process, timeout=timeout
        )
    except TimeoutError:
        logger.error("Sync subprocess timed out", origin=origin, timeout=timeout)
        raise RegistryError(
            f"Registry discovery timed out after {timeout:g}s for {origin!r}"
        ) from None

    # Decode outputs
    stdout_str = stdout_bytes.decode("utf-8").strip()
    stderr_str = stderr_bytes.decode("utf-8").strip()

    # Log stderr (contains all logging from the subprocess)
    if stderr_str:
        for line in stderr_str.split("\n"):
            logger.debug("sync subprocess", output=line)

    # Check exit code
    if process.returncode != 0:
        logger.error(
            "Sync subprocess failed",
            exit_code=process.returncode,
            stderr=stderr_str,
        )
        # Try to parse the typed error from stdout
        if stdout_str:
            try:
                result_data = json.loads(stdout_str)
                if isinstance(result_data, dict) and "error" in result_data:
                    raise SyncResultError.model_validate(result_data).to_exception()
            except (json.JSONDecodeError, ValidationError):
                pass
        raise RegistryError(f"Sync subprocess exited with code {process.returncode}")

    # Parse JSON output
    if not stdout_str:
        raise RegistryError("Sync subprocess returned empty output")

    try:
        # Use the type adapter to parse the JSON into the correct type
        result = SyncResultAdapter.validate_json(stdout_str)
    except Exception as e:
        logger.error(
            "Failed to parse subprocess JSON output",
            error=str(e),
            stdout=stdout_str[:500],
        )
        raise RegistryError(f"Invalid JSON from sync subprocess: {e}") from e

    # Check for error result
    if isinstance(result, SyncResultError):
        raise result.to_exception()

    logger.info(
        "Sync subprocess completed",
        origin=origin,
        num_actions=len(result.actions),
        commit_sha=result.commit_sha,
        num_validation_errors=len(result.validation_errors),
    )

    return result
