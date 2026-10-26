"""The opt-in Robot SOC preset seed against a real database."""

from __future__ import annotations

import uuid
from typing import get_args
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.agent.preset.robot_soc import (
    ROBOT_SOC_ACTIONS,
    ROBOT_SOC_LIBRARY_SKILLS,
    ROBOT_SOC_SLUG,
    robot_soc_preset_create,
    seed_robot_soc_preset,
)
from autosecops.agent.preset.router import router
from autosecops.agent.preset.schemas import AgentPresetUpdate
from autosecops.agent.preset.service import AgentPresetService
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.auth.types import Role
from autosecops.db.engine import get_async_session
from autosecops.db.models import (
    AgentPreset,
    RegistryIndex,
    RegistryRepository,
    RegistryVersion,
    SkillLibraryInstall,
    Workspace,
)
from autosecops.exceptions import TracecatValidationError
from autosecops.registry.versions.schemas import (
    RegistryVersionManifest,
    RegistryVersionManifestAction,
)

pytestmark = pytest.mark.usefixtures("db")

APPROVAL_DEFAULT = {"tools.robodr.request_action", "tools.robodr.revert_action"}


async def _register(
    session: AsyncSession, workspace: Workspace, actions: tuple[str, ...]
) -> None:
    repo = RegistryRepository(organization_id=workspace.organization_id, origin="test")
    session.add(repo)
    await session.flush()
    manifest = RegistryVersionManifest(
        actions={
            action: RegistryVersionManifestAction(
                namespace=action.rsplit(".", 1)[0],
                name=action.rsplit(".", 1)[1],
                action_type="udf",
                description=f"{action} test action",
                interface={"expects": {}, "returns": {}},
                implementation={"type": "udf"},
            )
            for action in actions
        }
    )
    version = RegistryVersion(
        organization_id=workspace.organization_id,
        repository_id=repo.id,
        version="test-version",
        manifest=manifest.model_dump(mode="json"),
        tarball_uri="s3://test/test.tar.gz",
    )
    session.add(version)
    await session.flush()
    repo.current_version_id = version.id
    for action in actions:
        namespace, name = action.rsplit(".", 1)
        options: dict[str, bool] = {"include_in_schema": True}
        if action in APPROVAL_DEFAULT:
            options["requires_approval"] = True
        session.add(
            RegistryIndex(
                organization_id=workspace.organization_id,
                registry_version_id=version.id,
                namespace=namespace,
                name=name,
                action_type="udf",
                description=f"{action} test action",
                options=options,
            )
        )
    await session.commit()


@pytest.mark.anyio
async def test_seed_is_opt_in_idempotent_and_keeps_edits(
    session: AsyncSession, svc_workspace: Workspace, svc_role: Role
) -> None:
    await _register(session, svc_workspace, ROBOT_SOC_ACTIONS)
    service = AgentPresetService(session=session, role=svc_role)
    assert await service.get_preset_by_slug(ROBOT_SOC_SLUG) is None

    params = robot_soc_preset_create(model_name="gpt-4o-mini", model_provider="openai")
    preset, created = await seed_robot_soc_preset(service, params)
    assert created
    assert preset.slug == ROBOT_SOC_SLUG
    assert set(preset.actions or []) == set(ROBOT_SOC_ACTIONS)
    assert preset.library_skills == sorted(ROBOT_SOC_LIBRARY_SKILLS)
    installed = set(
        (
            await session.scalars(
                select(SkillLibraryInstall.library_slug).where(
                    SkillLibraryInstall.workspace_id == svc_workspace.id
                )
            )
        ).all()
    )
    assert set(ROBOT_SOC_LIBRARY_SKILLS) <= installed

    policy = (await service.resolve_tool_policies([preset]))[preset.id]
    assert {tool for tool, on in policy.tool_approvals.items() if on} == (
        APPROVAL_DEFAULT
    )

    # A user edit survives a second seed, which creates nothing.
    preset = await service.update_preset(
        preset, AgentPresetUpdate(description="Edited by the team")
    )
    again, created_again = await seed_robot_soc_preset(service, params)
    assert not created_again
    assert again.id == preset.id
    assert again.description == "Edited by the team"
    count = len(
        (
            await session.scalars(
                select(AgentPreset.id).where(
                    AgentPreset.workspace_id == svc_workspace.id,
                    AgentPreset.slug == ROBOT_SOC_SLUG,
                )
            )
        ).all()
    )
    assert count == 1


@pytest.mark.anyio
async def test_seeded_preset_cannot_be_edited_to_auto_run_robot_actions(
    session: AsyncSession, svc_workspace: Workspace, svc_role: Role
) -> None:
    await _register(session, svc_workspace, ROBOT_SOC_ACTIONS)
    service = AgentPresetService(session=session, role=svc_role)
    preset, _ = await seed_robot_soc_preset(
        service,
        robot_soc_preset_create(model_name="gpt-4o-mini", model_provider="openai"),
    )
    with pytest.raises(ValidationError, match="cannot be disabled"):
        AgentPresetUpdate(tool_approvals={"tools.robodr.request_action": False})

    # Even a stored rule that bypassed the schema (an older version, a direct
    # write) resolves to "requires approval" for every run.
    assert preset.current_version_id is not None
    version = await service.get_version(preset.current_version_id)
    assert version is not None
    version.tool_approvals = {
        "tools.robodr.request_action": False,
        "tools.robodr.revert_action": False,
    }
    session.add(version)
    await session.commit()
    config = await service.resolve_agent_preset_config(preset_id=preset.id)
    assert config.tool_approvals is not None
    assert config.tool_approvals["tools.robodr.request_action"] is True
    assert config.tool_approvals["tools.robodr.revert_action"] is True


@pytest.mark.anyio
async def test_seed_fails_cleanly_without_robodr_tools(
    session: AsyncSession, svc_workspace: Workspace, svc_role: Role
) -> None:
    service = AgentPresetService(session=session, role=svc_role)
    with pytest.raises(TracecatValidationError):
        await seed_robot_soc_preset(
            service,
            robot_soc_preset_create(model_name="gpt-4o-mini", model_provider="openai"),
        )


def test_install_route_maps_missing_tools_to_400() -> None:
    role = Role(
        type="service",
        service_id="tracecat-api",
        workspace_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scopes=frozenset({"agent:create"}),
    )
    app = FastAPI()
    app.include_router(router)
    role_dependency = get_args(WorkspaceActorRouteRole)[1].dependency
    app.dependency_overrides[role_dependency] = lambda: role
    app.dependency_overrides[get_async_session] = lambda: AsyncMock(spec=AsyncSession)
    seed = AsyncMock(side_effect=TracecatValidationError("tools missing"))
    with (
        patch("autosecops.agent.preset.router.seed_robot_soc_preset", seed),
        TestClient(app) as client,
    ):
        response = client.post(
            "/agent/presets/robot-soc",
            json={"model_name": "test-model", "model_provider": "openai"},
        )
    assert response.status_code == 400
    assert seed.await_args is not None
    params = seed.await_args.args[1]
    assert params.slug == ROBOT_SOC_SLUG
    assert params.tool_approvals == {
        "tools.robodr.request_action": True,
        "tools.robodr.revert_action": True,
    }
