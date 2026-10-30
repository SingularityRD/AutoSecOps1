"""DurableAgentWorkflow binding of gateway models to catalog rows by name."""

from __future__ import annotations

import uuid
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from autosecops_ee.agent.workflows.durable import DurableAgentWorkflow

from autosecops.agent.preset.activities import (
    CustomModelProviderConfigResult,
    resolve_custom_model_provider_config_activity,
)
from autosecops.agent.types import AgentConfig
from autosecops.auth.types import Role
from autosecops.temporal.patches import DurableAgentWorkflowPatch

_PATCHED = "autosecops_ee.agent.workflows.durable.workflow.patched"
_EXECUTE_ACTIVITY = "autosecops_ee.agent.workflows.durable.workflow.execute_activity"


def _workflow() -> DurableAgentWorkflow:
    # Bypass __init__: only ``role`` is read by the method under test.
    instance = DurableAgentWorkflow.__new__(DurableAgentWorkflow)
    instance.role = Role(
        type="service",
        service_id="autosecops-api",
        workspace_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
    )
    return instance


def _config(
    *,
    model_provider: str = "ollama",
    catalog_id: uuid.UUID | None = None,
) -> AgentConfig:
    agent_config_ctor = cast(Any, AgentConfig)
    return agent_config_ctor(
        model_name="llama3",
        model_provider=model_provider,
        catalog_id=catalog_id,
    )


@pytest.mark.anyio
async def test_apply_gateway_config_binds_resolved_catalog_row() -> None:
    workflow_instance = _workflow()
    cfg = _config()
    resolved_id = uuid.uuid4()
    execute = AsyncMock(
        return_value=CustomModelProviderConfigResult(
            base_url="http://ollama.internal/v1",
            catalog_id=resolved_id,
        )
    )

    with (
        patch(_PATCHED, return_value=True) as patched_mock,
        patch(_EXECUTE_ACTIVITY, execute),
    ):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    patched_mock.assert_called_once_with(
        DurableAgentWorkflowPatch.RESOLVE_GATEWAY_CATALOG_BY_MODEL
    )
    assert execute.await_args is not None
    assert execute.await_args.args == (resolve_custom_model_provider_config_activity,)
    assert execute.await_args.kwargs["args"] == (
        workflow_instance.role,
        None,
        False,
        "ollama",
        "llama3",
    )
    assert cfg.catalog_id == resolved_id
    assert cfg.base_url == "http://ollama.internal/v1"


@pytest.mark.anyio
async def test_apply_gateway_config_replays_pre_patch_history_shape() -> None:
    """Histories without the marker keep four arguments and no catalog binding."""
    workflow_instance = _workflow()
    cfg = _config()
    execute = AsyncMock(
        return_value=CustomModelProviderConfigResult(
            base_url="http://workspace-ollama/v1",
            catalog_id=uuid.uuid4(),
        )
    )

    with patch(_PATCHED, return_value=False), patch(_EXECUTE_ACTIVITY, execute):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    assert execute.await_args is not None
    assert execute.await_args.kwargs["args"] == (
        workflow_instance.role,
        None,
        False,
        "ollama",
    )
    assert cfg.catalog_id is None
    assert cfg.base_url == "http://workspace-ollama/v1"


@pytest.mark.anyio
async def test_apply_gateway_config_keeps_existing_catalog_id() -> None:
    workflow_instance = _workflow()
    catalog_id = uuid.uuid4()
    cfg = _config(catalog_id=catalog_id)
    execute = AsyncMock(
        return_value=CustomModelProviderConfigResult(
            base_url="http://ollama.internal/v1",
            catalog_id=uuid.uuid4(),
        )
    )

    with patch(_PATCHED, return_value=True), patch(_EXECUTE_ACTIVITY, execute):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    assert cfg.catalog_id == catalog_id


@pytest.mark.anyio
async def test_apply_gateway_config_skips_direct_providers() -> None:
    """Direct providers schedule nothing and record no patch marker."""
    workflow_instance = _workflow()
    cfg = _config(model_provider="openai")
    execute = AsyncMock()

    with patch(_PATCHED) as patched_mock, patch(_EXECUTE_ACTIVITY, execute):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    patched_mock.assert_not_called()
    execute.assert_not_awaited()
