"""The executor worker's workflow sandbox must accept its workflows.

Temporal validates every registered workflow by importing it inside the
sandbox when the worker starts. ``autosecops.config`` imports the license
verifier, which imports cryptography; its Rust extension cannot be imported a
second time inside the sandbox, so the executor worker crashed on startup with
"Failed validating workflow RegistrySyncWorkflow".
"""

import pytest
from temporalio.workflow import _Definition

from autosecops.executor.worker import new_sandbox_runner
from autosecops.registry.sync.workflow import RegistrySyncWorkflow


@pytest.mark.anyio
async def test_executor_sandbox_validates_registry_sync_workflow() -> None:
    runner = new_sandbox_runner()
    runner.prepare_workflow(_Definition.must_from_class(RegistrySyncWorkflow))
