"""
CLI script for importing an installed registry package and serializing actions.

The executor installs a repository first (``Repository.install_from_origin``),
which needs settings, SSH keys and the database. This script then imports the
installed package, which runs repository code, in a subprocess that receives no
platform credentials and never touches the database.

Usage:
    python -m autosecops.registry.sync.entrypoint --origin <origin> \
        --package-name <package> --repository-id <uuid> [--commit-sha <sha>]

The script outputs a JSON object to stdout containing:
    - actions: List of serialized RegistryActionCreate objects
    - commit_sha: The resolved commit SHA (or null for local/builtin repos)
    - validation_errors: Any validation errors encountered (if validation is enabled)

All logging is sent to stderr to avoid polluting the JSON output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import defaultdict
from pathlib import Path
from uuid import UUID

from pydantic import UUID4

from autosecops.auth.types import Role
from autosecops.authz.scopes import SERVICE_PRINCIPAL_SCOPES
from autosecops.contexts import ctx_role
from autosecops.logger import logger
from autosecops.registry.actions.enums import TemplateActionValidationErrorType
from autosecops.registry.actions.schemas import (
    RegistryActionCreate,
    RegistryActionValidationErrorInfo,
)
from autosecops.registry.actions.service import validate_action_template
from autosecops.registry.constants import DEFAULT_REGISTRY_ORIGIN
from autosecops.registry.repository import Repository
from autosecops.registry.sync.schemas import (
    SyncResultError,
    SyncResultSuccess,
)


def _create_service_role(organization_id: UUID4 | None) -> Role:
    """Create the restricted service role used while discovering actions."""
    role = Role(
        type="service",
        service_id="autosecops-service",
        organization_id=organization_id,
        scopes=SERVICE_PRINCIPAL_SCOPES["autosecops-service"],
    )
    ctx_role.set(role)
    return role


async def _serialize_loaded_repository(
    *,
    repo: Repository,
    role: Role,
    origin: str,
    repository_id: UUID4,
    resolved_commit_sha: str | None,
    validate: bool,
) -> SyncResultSuccess:
    """Validate and serialize an already-loaded registry repository."""
    validation_errors: dict[str, list[RegistryActionValidationErrorInfo]] = {}
    if validate:
        logger.info("Validating template actions")
        extra_repos: list[Repository] = []
        if origin != DEFAULT_REGISTRY_ORIGIN:
            base_repo = Repository(origin=DEFAULT_REGISTRY_ORIGIN, role=role)
            await base_repo.load_from_origin()
            extra_repos.append(base_repo)
        val_errs: dict[str, list[RegistryActionValidationErrorInfo]] = defaultdict(list)
        for action in repo.store.values():
            if not action.is_template:
                continue
            if errs := await validate_action_template(
                action,
                repo,
                check_db=False,
                extra_repos=extra_repos or None,
            ):
                val_errs[action.action].extend(errs)
        validation_errors = dict(val_errs)
        if validation_errors:
            logger.warning(
                "Validation errors found",
                num_errors=sum(len(v) for v in validation_errors.values()),
            )

    serialized_actions: list[RegistryActionCreate] = []
    for bound_action in repo.store.values():
        try:
            create_dto = RegistryActionCreate.from_bound(bound_action, repository_id)
            serialized_actions.append(create_dto)
        except Exception as e:
            logger.error(
                "Failed to serialize action",
                action=bound_action.action,
                error=str(e),
            )
            if bound_action.action not in validation_errors:
                validation_errors[bound_action.action] = []
            validation_errors[bound_action.action].append(
                RegistryActionValidationErrorInfo(
                    type=TemplateActionValidationErrorType.SERIALIZATION_ERROR,
                    details=[str(e)],
                    is_template=bound_action.is_template,
                    loc_primary=bound_action.action,
                    loc_secondary=None,
                )
            )

    logger.info(
        "Serialization complete",
        num_actions=len(serialized_actions),
        num_errors=len(validation_errors),
    )

    return SyncResultSuccess(
        actions=serialized_actions,
        commit_sha=resolved_commit_sha,
        validation_errors=validation_errors,
    )


async def load_and_serialize_actions(
    origin: str,
    repository_id: UUID4,
    commit_sha: str | None = None,
    validate: bool = False,
    git_repo_package_name: str | None = None,
    organization_id: UUID4 | None = None,
) -> SyncResultSuccess:
    """Load a repository and serialize its actions to a typed result.

    Args:
        origin: The repository origin (e.g., "autosecops_registry", "local", or a git URL).
        repository_id: The UUID of the repository in the database.
        commit_sha: Optional commit SHA to checkout (for remote repos).
        validate: Whether to validate template actions.
        git_repo_package_name: Optional override for the git repository package name.
        organization_id: Optional organization ID for accessing org-scoped secrets.

    Returns:
        SyncResultSuccess containing actions, commit_sha, and validation_errors.
    """
    role = _create_service_role(organization_id)

    # Load the repository (this triggers uv install / reload)
    logger.info("Loading repository", origin=origin, commit_sha=commit_sha)
    repo = Repository(
        origin=origin,
        role=role,
        package_name_override=git_repo_package_name,
    )
    resolved_commit_sha = await repo.load_from_origin(commit_sha=commit_sha)
    logger.info(
        "Repository loaded",
        origin=origin,
        resolved_commit_sha=resolved_commit_sha,
        num_actions=len(repo.store),
    )

    return await _serialize_loaded_repository(
        repo=repo,
        role=role,
        origin=origin,
        repository_id=repository_id,
        resolved_commit_sha=resolved_commit_sha,
        validate=validate,
    )


async def load_and_serialize_installed_actions(
    *,
    origin: str,
    package_name: str,
    repository_id: UUID4,
    commit_sha: str | None = None,
    validate: bool = False,
    organization_id: UUID4 | None = None,
) -> SyncResultSuccess:
    """Discover actions from a package installed by a separate sandbox phase."""
    role = _create_service_role(organization_id)
    repo = Repository(origin=origin, role=role, package_name_override=package_name)

    logger.info(
        "Loading installed registry package",
        origin=origin,
        package_name=package_name,
        commit_sha=commit_sha,
    )
    if origin == DEFAULT_REGISTRY_ORIGIN:
        await repo.load_from_origin(commit_sha=commit_sha)
    else:
        await repo.load_installed(package_name)

    logger.info(
        "Installed registry package loaded",
        origin=origin,
        package_name=package_name,
        num_actions=len(repo.store),
    )
    return await _serialize_loaded_repository(
        repo=repo,
        role=role,
        origin=origin,
        repository_id=repository_id,
        resolved_commit_sha=commit_sha,
        validate=validate,
    )


async def load_and_serialize_preinstalled_actions(
    *,
    origin: str,
    package_name: str,
    repository_id: UUID4,
    commit_sha: str | None = None,
    validate: bool = False,
    organization_id: UUID4 | None = None,
    site_dir: Path | None = None,
) -> SyncResultSuccess:
    """Import a package installed by ``Repository.install_from_origin``.

    Args:
        origin: The repository origin.
        package_name: The installed package to import.
        repository_id: The UUID of the repository in the database.
        commit_sha: The commit the installation resolved to.
        validate: Whether to validate template actions.
        organization_id: Organization the sync runs for.
        site_dir: The installation's ``--target`` directory.

    Returns:
        SyncResultSuccess containing actions, commit_sha, and validation_errors.
    """
    role = _create_service_role(organization_id)
    repo = Repository(origin=origin, role=role, package_name_override=package_name)
    if origin == DEFAULT_REGISTRY_ORIGIN:
        await repo.load_from_origin()
    else:
        await repo.import_installed_origin(package_name, site_dir=site_dir)
    logger.info(
        "Installed registry package imported",
        origin=origin,
        package_name=package_name,
        num_actions=len(repo.store),
    )
    return await _serialize_loaded_repository(
        repo=repo,
        role=role,
        origin=origin,
        repository_id=repository_id,
        resolved_commit_sha=commit_sha,
        validate=validate,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import an installed registry package and serialize actions to JSON."
    )
    parser.add_argument(
        "--origin",
        required=True,
        help="The repository origin (e.g., 'autosecops_registry', 'local', or a git URL).",
    )
    parser.add_argument(
        "--package-name",
        required=True,
        help="The installed Python package to import.",
    )
    parser.add_argument(
        "--repository-id",
        required=True,
        help="The UUID of the repository in the database.",
    )
    parser.add_argument(
        "--site-dir",
        default=None,
        help="The installation's --target directory to import from.",
    )
    parser.add_argument(
        "--commit-sha",
        default=None,
        help="The commit the installation resolved to.",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Whether to validate template actions.",
    )
    parser.add_argument(
        "--organization-id",
        default=None,
        help="Organization the sync runs for.",
    )
    return parser.parse_args()


async def main() -> int:
    """Main entry point for the CLI script."""
    args = _parse_args()
    try:
        repository_id = UUID(args.repository_id)
        organization_id = UUID(args.organization_id) if args.organization_id else None
    except ValueError as e:
        logger.error("Invalid identifier", error=str(e))
        print(json.dumps({"error": f"Invalid identifier: {e}"}), file=sys.stdout)
        return 1

    try:
        result = await load_and_serialize_preinstalled_actions(
            origin=args.origin,
            package_name=args.package_name,
            repository_id=repository_id,
            commit_sha=args.commit_sha,
            validate=args.validate,
            organization_id=organization_id,
            site_dir=Path(args.site_dir) if args.site_dir else None,
        )
        # Output result as JSON to stdout using Pydantic serialization
        print(result.model_dump_json(), file=sys.stdout)
        return 0

    except Exception as e:
        logger.exception("Failed to load repository", error=str(e))
        # Output error as typed JSON
        error_result = SyncResultError.from_exception(e)
        print(error_result.model_dump_json(), file=sys.stdout)
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
