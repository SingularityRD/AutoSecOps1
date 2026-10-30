"""Untrusted runner: pre-resolved UDF execution without database access."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from autosecops_registry import secrets as registry_secrets
from autosecops_registry.context import get_context

from autosecops.auth.types import Role
from autosecops.contexts import ctx_role
from autosecops.dsl.common import create_default_execution_context
from autosecops.dsl.schemas import ActionStatement, RunActionInput, RunContext
from autosecops.executor import untrusted_runner
from autosecops.executor.schemas import ActionImplementation, ResolvedContext
from autosecops.executor.secret_preprocessors import SecretEnvProjection
from autosecops.identifiers.workflow import WorkflowUUID, generate_exec_id
from autosecops.registry.lock.types import RegistryLock

pytestmark = pytest.mark.anyio

ROLE = Role(
    type="service",
    service_id="autosecops-executor",
    workspace_id=UUID(int=7, version=4),
)


def _input() -> RunActionInput:
    wf_id = WorkflowUUID.new_uuid4()
    return RunActionInput(
        task=ActionStatement(ref="step", action="testing.udf", args={}),
        exec_context=create_default_execution_context(),
        run_context=RunContext(
            wf_id=wf_id,
            wf_exec_id=generate_exec_id(wf_id),
            wf_run_id=UUID(int=3, version=4),
            environment="default",
            logical_time=datetime.now(UTC),
        ),
        registry_lock=RegistryLock(origins={}, actions={}),
    )


def _context(
    *,
    module: str | None,
    name: str | None,
    args: dict[str, object],
    action_type: str = "udf",
    env: dict[str, str] | None = None,
) -> ResolvedContext:
    return ResolvedContext(
        action_impl=ActionImplementation(type=action_type, module=module, name=name),
        evaluated_args=args,
        workspace_id=str(ROLE.workspace_id),
        workflow_id="wf",
        run_id="run",
        executor_token="token",
        secret_projection=(
            None if env is None else SecretEnvProjection(env=env, mask_values=set())
        ),
    )


async def test_sync_udf_sees_secrets_only_for_the_call() -> None:
    resolved = _context(
        module=registry_secrets.__name__,
        name="get",
        args={"name": "API_TOKEN"},
        env={"API_TOKEN": "s3cr3t"},
    )

    result = await untrusted_runner.run_action_untrusted(_input(), ROLE, resolved)

    # The threadpool call inherits the per-call secret context ...
    assert result == "s3cr3t"
    # ... which is reset once the action returns.
    assert registry_secrets.get_or_default("API_TOKEN") is None
    assert ctx_role.get() == ROLE


async def test_async_udf_is_awaited_and_internal_args_are_stripped() -> None:
    resolved = _context(
        module="asyncio",
        name="sleep",
        args={"delay": 0, "result": {"ok": True}, "__autosecops": {"internal": 1}},
        env={},
    )

    assert await untrusted_runner.run_action_untrusted(_input(), ROLE, resolved) == {
        "ok": True
    }


async def test_secret_projection_is_built_when_not_cached() -> None:
    resolved = _context(module="json", name="dumps", args={"obj": [1, 2]})

    result = await untrusted_runner.run_action_untrusted(_input(), ROLE, resolved)

    assert json.loads(result) == [1, 2]


async def test_secret_context_is_reset_when_the_udf_raises() -> None:
    resolved = _context(
        module="json",
        name="loads",
        args={"s": "{not json"},
        env={"API_TOKEN": "s3cr3t"},
    )

    with pytest.raises(json.JSONDecodeError):
        await untrusted_runner.run_action_untrusted(_input(), ROLE, resolved)

    assert registry_secrets.get_or_default("API_TOKEN") is None


async def test_templates_are_refused_inside_the_sandbox() -> None:
    resolved = _context(module=None, name=None, args={}, action_type="template")

    with pytest.raises(NotImplementedError):
        await untrusted_runner.run_action_untrusted(_input(), ROLE, resolved)


@pytest.mark.parametrize(
    ("module", "name"), [(None, "dumps"), ("json", None), ("", "")]
)
async def test_udf_without_module_or_name_is_rejected(
    module: str | None, name: str | None
) -> None:
    resolved = _context(module=module, name=name, args={}, env={})

    with pytest.raises(ValueError, match="missing module or name"):
        await untrusted_runner.run_action_untrusted(_input(), ROLE, resolved)


@pytest.mark.parametrize("missing", ["action_impl", "evaluated_args"])
async def test_incomplete_resolved_context_is_rejected(missing: str) -> None:
    resolved = _context(module="json", name="dumps", args={}, env={})
    incomplete = ResolvedContext.model_construct(**{**dict(resolved), missing: None})

    with pytest.raises(ValueError, match=f"Missing {missing}"):
        await untrusted_runner.run_action_untrusted(_input(), ROLE, incomplete)


def test_registry_sdk_context_comes_from_executor_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOSECOPS__WORKSPACE_ID", "ws-1")
    monkeypatch.setenv("AUTOSECOPS__WORKFLOW_ID", "wf-1")
    monkeypatch.setenv("AUTOSECOPS__RUN_ID", "run-1")
    monkeypatch.setenv("AUTOSECOPS__API_URL", "http://api.test")
    monkeypatch.setenv("AUTOSECOPS__EXECUTOR_TOKEN", "executor-token")
    monkeypatch.delenv("AUTOSECOPS__ENVIRONMENT", raising=False)

    untrusted_runner._setup_registry_sdk_context()

    context = get_context()
    assert (context.workspace_id, context.workflow_id, context.run_id) == (
        "ws-1",
        "wf-1",
        "run-1",
    )
    assert context.environment == "default"
    assert context.api_url == "http://api.test"
    assert context.token == "executor-token"
