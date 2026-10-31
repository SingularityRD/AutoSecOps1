"""Platform processes never import customer registry code, and say why syncs fail."""

from __future__ import annotations

import uuid
from inspect import unwrap
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from autosecops.db.models import RegistryAction
from autosecops.exceptions import RegistryValidationError
from autosecops.registry import loaders
from autosecops.registry.actions.schemas import (
    ActionStep,
    TemplateAction,
    TemplateActionDefinition,
)
from autosecops.registry.actions.service import validate_action_template
from autosecops.registry.constants import DEFAULT_REGISTRY_ORIGIN
from autosecops.registry.loaders import (
    get_bound_action_from_metadata,
    imports_customer_code,
)
from autosecops.registry.repositories import router as registry_repos_router
from autosecops.registry.repositories.service import RegistryReposService
from autosecops.registry.repository import Repository
from autosecops.registry.sync import subprocess as sync_subprocess

CUSTOMER_ORIGIN = "git+ssh://git@github.com/example-org/registry.git"


def _customer_udf() -> RegistryAction:
    return RegistryAction(
        name="lookup",
        namespace="tools.example",
        description="Customer lookup",
        origin=CUSTOMER_ORIGIN,
        implementation={
            "type": "udf",
            "url": CUSTOMER_ORIGIN,
            "module": "example_registry.lookup",
            "name": "lookup",
        },
        interface={
            "expects": {
                "type": "object",
                "properties": {"query": {"type": "string"}, "limit": {}},
                "required": ["query"],
                "additionalProperties": False,
            },
            "returns": None,
        },
        secrets=None,
    )


@pytest.fixture
def no_customer_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("customer registry code was imported")

    monkeypatch.setattr(loaders, "import_and_reload", refuse)
    monkeypatch.setattr(loaders.importlib, "import_module", refuse)


@pytest.mark.usefixtures("no_customer_imports")
def test_customer_udf_binds_from_metadata_without_importing() -> None:
    action = _customer_udf()
    assert imports_customer_code(action)

    bound = get_bound_action_from_metadata(action)

    assert bound.validate_args(args={"query": "${{ inputs.q }}"}) == {
        "query": "${{ inputs.q }}",
        "limit": None,
    }
    with pytest.raises(RegistryValidationError):
        bound.validate_args(args={"limit": 3})
    with pytest.raises(RegistryValidationError):
        bound.validate_args(args={"query": "x", "unknown": 1})


def test_builtin_udfs_are_platform_code() -> None:
    builtin = _customer_udf()
    builtin.origin = DEFAULT_REGISTRY_ORIGIN

    assert not imports_customer_code(builtin)


@pytest.mark.anyio
@pytest.mark.usefixtures("no_customer_imports")
async def test_template_validation_checks_customer_steps_without_importing(
    mocker,
) -> None:
    template = TemplateAction(
        type="action",
        definition=TemplateActionDefinition(
            title="Wrapper",
            description="Wraps a customer action",
            name="wrapper",
            namespace="tools.example",
            display_group="Testing",
            expects={},
            steps=[ActionStep(ref="first", action="tools.example.lookup", args={})],
            returns="${{ steps.first.result }}",
        ),
    )
    repo = Repository()
    repo.register_template_action(template, origin="test")
    bound = repo.store["tools.example.wrapper"]
    ra_service = mocker.Mock()
    ra_service.logger = mocker.Mock()
    ra_service.get_action_or_none = mocker.AsyncMock(return_value=_customer_udf())

    errors = await validate_action_template(
        bound, repo, check_db=True, ra_service=ra_service
    )

    # The missing required argument is still reported, from metadata alone.
    assert [error.loc_secondary for error in errors] == ["tools.example.lookup"]


@pytest.mark.anyio
async def test_sync_install_failure_returns_400_with_reason(mocker) -> None:
    """A bad ref or clone failure is a client error, not an unexpected 500."""
    repository = SimpleNamespace(id=uuid.uuid4(), origin=CUSTOMER_ORIGIN)
    mocker.patch.object(
        RegistryReposService,
        "get_repository_by_id",
        mocker.AsyncMock(return_value=repository),
    )
    mocker.patch.object(
        Repository,
        "install_from_origin",
        mocker.AsyncMock(
            side_effect=RuntimeError(
                "Failed to install repository: fatal: couldn't find remote ref main"
            )
        ),
    )
    mocker.patch.object(
        sync_subprocess, "get_setting", mocker.AsyncMock(return_value=False)
    )

    async def sync_repository(*_args: Any, **_kwargs: Any) -> Any:
        return await sync_subprocess.fetch_actions_from_subprocess(
            origin=CUSTOMER_ORIGIN, repository_id=repository.id
        )

    mocker.patch.object(
        RegistryReposService, "sync_repository", side_effect=sync_repository
    )
    sync = unwrap(registry_repos_router.sync_registry_repository)

    with pytest.raises(HTTPException) as exc_info:
        await sync(
            role=mocker.Mock(),
            session=mocker.Mock(),
            repository_id=repository.id,
            sync_params=None,
        )

    assert exc_info.value.status_code == 400
    assert "couldn't find remote ref main" in str(exc_info.value.detail)
