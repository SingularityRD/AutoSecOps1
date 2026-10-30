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

from pydantic import UUID4, ValidationError

from autosecops import config
from autosecops.auth.types import Role
from autosecops.authz.scopes import SERVICE_PRINCIPAL_SCOPES
from autosecops.exceptions import RegistryError
from autosecops.executor.action_env import ACTION_ENV_ALLOWED_NAMES
from autosecops.logger import logger
from autosecops.process_env import select_env
from autosecops.registry.constants import DEFAULT_REGISTRY_ORIGIN
from autosecops.registry.repository import Repository
from autosecops.registry.sync.schemas import (
    SyncResultAdapter,
    SyncResultError,
    SyncResultSuccess,
)

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
    """Run the sync CLI script in a subprocess and parse its JSON output.

    This function invokes `python -m autosecops.registry.sync` with the given
    parameters, captures stdout (JSON result), and logs stderr.

    Args:
        origin: The repository origin (e.g., "autosecops_registry", "local", or git URL).
        repository_id: The UUID of the repository in the database.
        commit_sha: Optional commit SHA to checkout (for remote repos).
        validate: Whether to validate template actions.
        git_repo_package_name: Optional override for the git repository package name.
        timeout: Maximum time to wait for the subprocess (default: 5 minutes).
        organization_id: Optional organization ID for accessing org-scoped secrets (e.g., SSH keys).

    Returns:
        SyncResultSuccess containing parsed actions, commit SHA, and any errors.

    Raises:
        RegistryError: If the subprocess fails or returns invalid JSON.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    role = Role(
        type="service",
        service_id="autosecops-service",
        organization_id=organization_id,
        scopes=SERVICE_PRINCIPAL_SCOPES["autosecops-service"],
    )

    if origin == DEFAULT_REGISTRY_ORIGIN:
        package_name = DEFAULT_REGISTRY_ORIGIN
        resolved_commit_sha = commit_sha
    else:
        logger.info("Installing registry repository", origin=origin)
        try:
            async with asyncio.timeout_at(deadline):
                installation = await Repository(
                    origin=origin,
                    role=role,
                    package_name_override=git_repo_package_name,
                ).install_from_origin(commit_sha=commit_sha)
        except TimeoutError:
            raise RegistryError(
                f"Sync subprocess timed out after {timeout}s for {origin!r}"
            ) from None
        except Exception as e:
            # Surface the same typed error the sync subprocess reported before
            # installation moved out of it.
            raise SyncResultError.from_exception(e).to_exception() from e
        package_name = installation.package_name
        resolved_commit_sha = installation.commit_sha

    cmd = [
        sys.executable,
        "-m",
        "autosecops.registry.sync.entrypoint",
        "--origin",
        origin,
        "--package-name",
        package_name,
        "--repository-id",
        str(repository_id),
    ]
    if resolved_commit_sha is not None:
        cmd.extend(["--commit-sha", resolved_commit_sha])
    if validate:
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

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=registry_discovery_env(),
    )

    # Wait for completion with timeout
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=max(deadline - loop.time(), 0),
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        logger.error(
            "Sync subprocess timed out",
            origin=origin,
            timeout=timeout,
        )
        raise RegistryError(
            f"Sync subprocess timed out after {timeout}s for {origin!r}"
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
