"""
Subprocess utilities for running registry sync operations in isolation.

This module provides helper functions to invoke the sync CLI script
(autosecops.registry.sync) in a subprocess, preventing environment
contamination from uv install and importlib.reload operations.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from pydantic import UUID4, ValidationError

from autosecops import config
from autosecops.exceptions import RegistryError
from autosecops.logger import logger
from autosecops.registry.sync.schemas import (
    SyncResultAdapter,
    SyncResultError,
    SyncResultSuccess,
)


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
    # Build command arguments
    cmd = [
        sys.executable,
        "-m",
        "autosecops.registry.sync.entrypoint",
        "--origin",
        origin,
        "--repository-id",
        str(repository_id),
    ]

    if commit_sha is not None:
        cmd.extend(["--commit-sha", commit_sha])

    if validate:
        cmd.append("--validate")

    if git_repo_package_name is not None:
        cmd.extend(["--git-repo-package-name", git_repo_package_name])

    if organization_id is not None:
        cmd.extend(["--organization-id", str(organization_id)])

    logger.info(
        "Starting sync subprocess",
        origin=origin,
        repository_id=str(repository_id),
        commit_sha=commit_sha,
        organization_id=str(organization_id) if organization_id else None,
    )

    # Build environment for subprocess
    # Inherit current environment and add autosecops-specific config
    subprocess_env = os.environ.copy()

    # Pass through critical config values as environment variables
    # so the subprocess has access to them
    if config.AUTOSECOPS__LOCAL_REPOSITORY_ENABLED:
        subprocess_env["AUTOSECOPS__LOCAL_REPOSITORY_ENABLED"] = "true"
    if config.AUTOSECOPS__LOCAL_REPOSITORY_PATH:
        subprocess_env["AUTOSECOPS__LOCAL_REPOSITORY_PATH"] = str(
            config.AUTOSECOPS__LOCAL_REPOSITORY_PATH
        )
    if config.AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH:
        subprocess_env["AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH"] = str(
            config.AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH
        )
    if config.AUTOSECOPS__APP_ENV:
        subprocess_env["AUTOSECOPS__APP_ENV"] = config.AUTOSECOPS__APP_ENV

    # Start the subprocess
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=subprocess_env,
    )

    # Wait for completion with timeout
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
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
