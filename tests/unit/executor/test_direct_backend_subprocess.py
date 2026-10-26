from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from autosecops.auth.types import Role
from autosecops.dsl.schemas import (
    ActionStatement,
    ExecutionContext,
    RunActionInput,
    RunContext,
)
from autosecops.executor.backends.direct import DirectBackend
from autosecops.executor.schemas import (
    ActionImplementation,
    ResolvedContext,
)
from autosecops.identifiers.workflow import ExecutionUUID, WorkflowUUID
from autosecops.registry.lock.types import RegistryLock


def _make_input() -> RunActionInput:
    wf_id = WorkflowUUID.new_uuid4()
    exec_id = ExecutionUUID.new_uuid4()
    return RunActionInput(
        task=ActionStatement(
            action="core.transform.reshape",
            args={"value": {"x": 1}},
            ref="test_action",
        ),
        exec_context=ExecutionContext(ACTIONS={}, TRIGGER=None),
        run_context=RunContext(
            wf_id=wf_id,
            wf_exec_id=f"{wf_id.short()}/{exec_id.short()}",
            wf_run_id=uuid.uuid4(),
            environment="default",
            logical_time=datetime.now(UTC),
        ),
        registry_lock=RegistryLock(
            origins={"autosecops_registry": "test-version"},
            actions={"core.transform.reshape": "autosecops_registry"},
        ),
    )


def _make_role() -> Role:
    return Role(
        type="service",
        service_id="tracecat-executor",
        workspace_id=uuid.UUID("38be3315-c172-4332-aea6-53fc4b93f053"),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
    )


def _make_resolved_context() -> ResolvedContext:
    return ResolvedContext(
        secrets={},
        variables={},
        action_impl=ActionImplementation(
            type="udf",
            action_name="core.transform.reshape",
            module="autosecops_registry.core.transform",
            name="reshape",
            origin="autosecops_registry",
        ),
        evaluated_args={"value": {"x": 1}},
        workspace_id=str(uuid.uuid4()),
        workflow_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        executor_token="test-token",
        logical_time=datetime.now(UTC),
    )


@pytest.mark.anyio
async def test_direct_backend_fails_without_tarballs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = DirectBackend()
    input_data = _make_input()
    role = _make_role()
    resolved_context = _make_resolved_context()

    async def _get_tarballs(_input: RunActionInput, _role: Role) -> list[str]:
        return []

    monkeypatch.setattr(
        "autosecops.executor.backends.direct.config.TRACECAT__LOCAL_REPOSITORY_ENABLED",
        False,
    )
    monkeypatch.setattr(backend, "_get_artifact_uris", _get_tarballs)

    result = await backend.execute(
        input=input_data,
        role=role,
        resolved_context=resolved_context,
        timeout=15.0,
    )

    assert result.type == "failure"
    assert result.error.type == "RegistryError"
