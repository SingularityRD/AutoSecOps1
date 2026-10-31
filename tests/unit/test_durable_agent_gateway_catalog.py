"""DurableAgentWorkflow binding of gateway models to catalog rows by name."""

from __future__ import annotations

import uuid
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from autosecops_ee.agent.workflows.durable import (
    GATEWAY_CATALOG_LOOKUP_RETRY_POLICY,
    GATEWAY_CATALOG_LOOKUP_SCHEDULE_TO_CLOSE,
    DurableAgentWorkflow,
)

from autosecops.agent.preset.activities import (
    CustomModelProviderConfigResult,
    ResolveGatewayCatalogByModelActivityInput,
    ResolveGatewayCatalogByModelActivityResult,
    resolve_custom_model_provider_config_activity,
    resolve_gateway_catalog_by_model_activity,
)
from autosecops.agent.types import AgentConfig
from autosecops.agent.worker import get_activities
from autosecops.auth.types import Role
from autosecops.temporal.patches import DurableAgentWorkflowPatch

_PATCHED = "autosecops_ee.agent.workflows.durable.workflow.patched"
_EXECUTE_ACTIVITY = "autosecops_ee.agent.workflows.durable.workflow.execute_activity"
_BASE_URL = "http://ollama.internal/v1"


def _workflow() -> DurableAgentWorkflow:
    # Bypass __init__: only ``role`` is read by the methods under test.
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


def _execute(lookup_catalog_id: uuid.UUID | None) -> AsyncMock:
    """Fake ``workflow.execute_activity`` answering both gateway activities."""

    async def _run(activity_fn: object, *_args: object, **_kwargs: object) -> object:
        if activity_fn is resolve_gateway_catalog_by_model_activity:
            return ResolveGatewayCatalogByModelActivityResult(
                catalog_id=lookup_catalog_id
            )
        return CustomModelProviderConfigResult(base_url=_BASE_URL)

    return AsyncMock(side_effect=_run)


@pytest.mark.anyio
async def test_apply_gateway_config_binds_resolved_catalog_row() -> None:
    workflow_instance = _workflow()
    cfg = _config()
    resolved_id = uuid.uuid4()
    execute = _execute(resolved_id)

    with (
        patch(_PATCHED, return_value=True) as patched_mock,
        patch(_EXECUTE_ACTIVITY, execute),
    ):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    patched_mock.assert_called_once_with(
        DurableAgentWorkflowPatch.RESOLVE_GATEWAY_CATALOG_BY_MODEL
    )
    lookup_call, config_call = execute.await_args_list
    assert lookup_call.args == (
        resolve_gateway_catalog_by_model_activity,
        ResolveGatewayCatalogByModelActivityInput(
            role=workflow_instance.role,
            model_provider="ollama",
            model_name="llama3",
        ),
    )
    assert lookup_call.kwargs["retry_policy"] is GATEWAY_CATALOG_LOOKUP_RETRY_POLICY
    assert (
        lookup_call.kwargs["schedule_to_close_timeout"]
        == GATEWAY_CATALOG_LOOKUP_SCHEDULE_TO_CLOSE
    )
    # The config activity keeps the four-argument shape that agent workers on
    # the previous version accept during a rolling upgrade.
    assert config_call.args == (resolve_custom_model_provider_config_activity,)
    assert config_call.kwargs["args"] == (
        workflow_instance.role,
        resolved_id,
        False,
        "ollama",
    )
    assert cfg.catalog_id == resolved_id
    assert cfg.base_url == _BASE_URL


@pytest.mark.anyio
async def test_apply_gateway_config_keeps_workspace_secret_path() -> None:
    """No bound row leaves catalog_id unset so workspace credentials apply."""
    workflow_instance = _workflow()
    cfg = _config()
    execute = _execute(None)

    with patch(_PATCHED, return_value=True), patch(_EXECUTE_ACTIVITY, execute):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    assert execute.await_args_list[1].kwargs["args"] == (
        workflow_instance.role,
        None,
        False,
        "ollama",
    )
    assert cfg.catalog_id is None


@pytest.mark.anyio
async def test_apply_gateway_config_replays_pre_patch_history_shape() -> None:
    """Histories without the marker schedule only the config activity."""
    workflow_instance = _workflow()
    cfg = _config()
    execute = _execute(uuid.uuid4())

    with patch(_PATCHED, return_value=False), patch(_EXECUTE_ACTIVITY, execute):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    assert len(execute.await_args_list) == 1
    assert execute.await_args_list[0].kwargs["args"] == (
        workflow_instance.role,
        None,
        False,
        "ollama",
    )
    assert cfg.catalog_id is None


@pytest.mark.anyio
async def test_apply_gateway_config_with_catalog_id_skips_lookup_and_patch() -> None:
    """UI-selected models schedule exactly what earlier versions scheduled."""
    workflow_instance = _workflow()
    catalog_id = uuid.uuid4()
    cfg = _config(catalog_id=catalog_id)
    execute = _execute(uuid.uuid4())

    with (
        patch(_PATCHED) as patched_mock,
        patch(_EXECUTE_ACTIVITY, execute),
    ):
        await workflow_instance._apply_custom_model_provider_config(cfg)

    patched_mock.assert_not_called()
    assert len(execute.await_args_list) == 1
    assert execute.await_args_list[0].kwargs["args"] == (
        workflow_instance.role,
        catalog_id,
        False,
        "ollama",
    )
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


def test_lookup_retry_policy_tolerates_unregistered_activity() -> None:
    """A previous-version worker fails the task as NotFoundError; retry it."""
    policy = GATEWAY_CATALOG_LOOKUP_RETRY_POLICY
    assert policy.non_retryable_error_types is not None
    assert "NotFoundError" not in policy.non_retryable_error_types
    assert policy.maximum_attempts > 1


def test_agent_worker_registers_gateway_catalog_lookup() -> None:
    activities = get_activities()
    assert resolve_gateway_catalog_by_model_activity in activities
    assert resolve_custom_model_provider_config_activity in activities
