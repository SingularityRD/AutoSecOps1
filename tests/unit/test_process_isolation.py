"""Direct-mode action code cannot inspect the executor through /proc."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from autosecops.process_hardening import is_process_dumpable

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setpriv") is None,
    reason="process inspection protection and direct actions need Linux and setpriv",
)

SECRET = "synthetic-executor-secret-value"

PROBE_MODULE = """
import ctypes
import os


def probe(targets):
    libc = ctypes.CDLL(None, use_errno=True)
    outcome = {"runner_dumpable": libc.prctl(3, 0, 0, 0, 0)}
    for label, path in targets.items():
        try:
            with open(path, "rb") as file:
                data = file.read(1 << 20)
        except OSError as exc:
            outcome[label] = "denied:" + type(exc).__name__
        else:
            outcome[label] = "leaked" if SECRET_PLACEHOLDER.encode() in data else "readable"
    return outcome
"""

# Runs as a stand-in executor worker: it holds a platform secret in its
# environment, optionally protects itself as the real worker does, then runs a
# direct-mode action that tries to read the worker's and PID 1's /proc files.
EXECUTOR_SCRIPT = """
import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from autosecops.process_hardening import protect_process_from_inspection

if sys.argv[1] == "protect":
    protect_process_from_inspection()

from autosecops.auth.types import Role
from autosecops.authz.scopes import SERVICE_PRINCIPAL_SCOPES
from autosecops.dsl.common import create_default_execution_context
from autosecops.dsl.schemas import ActionStatement, RunActionInput, RunContext
from autosecops.executor.action_runner import ActionRunner
from autosecops.executor.schemas import ActionImplementation, ResolvedContext
from autosecops.executor.secret_preprocessors import SecretEnvProjection
from autosecops.identifiers.workflow import WorkflowUUID
from autosecops.registry.lock.types import RegistryLock

work = Path(sys.argv[2])
pid = os.getpid()
targets = {
    "executor_environ": f"/proc/{pid}/environ",
    "executor_mem": f"/proc/{pid}/mem",
    "pid1_environ": "/proc/1/environ",
}
wf_id = WorkflowUUID.new_uuid4()
run_input = RunActionInput(
    task=ActionStatement(action="test.proc_probe", args={}, ref="probe"),
    exec_context=create_default_execution_context(),
    run_context=RunContext(
        wf_id=wf_id,
        wf_exec_id=f"{wf_id.short()}/exec_test",
        wf_run_id=uuid.uuid4(),
        environment="default",
        logical_time=datetime.now(UTC),
    ),
    registry_lock=RegistryLock(
        origins={"autosecops_registry": "test-version"},
        actions={"test.proc_probe": "autosecops_registry"},
    ),
)
role = Role(
    type="service",
    service_id="autosecops-executor",
    workspace_id=uuid.uuid4(),
    organization_id=uuid.uuid4(),
    user_id=uuid.uuid4(),
    scopes=SERVICE_PRINCIPAL_SCOPES["autosecops-executor"],
)
context = ResolvedContext(
    action_impl=ActionImplementation(
        type="udf",
        action_name="test.proc_probe",
        module="proc_probe_action",
        name="probe",
    ),
    evaluated_args={"targets": targets},
    workspace_id=str(role.workspace_id),
    workflow_id=str(wf_id),
    run_id=str(run_input.run_context.wf_run_id),
    executor_token="synthetic-executor-token",
)
result = asyncio.run(
    ActionRunner(cache_dir=work / "cache")._execute_direct(
        input=run_input,
        role=role,
        registry_paths=[work / "registry"],
        secret_projection=SecretEnvProjection(env={}, mask_values=set()),
        timeout=60.0,
        resolved_context=context,
    )
)
print("RESULT:" + json.dumps(result if isinstance(result, dict) else str(result)))
"""


@pytest.fixture
def work_dir() -> Iterator[Path]:
    """Create a work directory the unprivileged test user can use."""
    with tempfile.TemporaryDirectory(prefix="proc-isolation-") as raw:
        work = Path(raw)
        registry = work / "registry"
        registry.mkdir()
        (registry / "proc_probe_action.py").write_text(
            PROBE_MODULE.replace("SECRET_PLACEHOLDER", repr(SECRET))
        )
        (work / "cache").mkdir()
        (work / "executor.py").write_text(EXECUTOR_SCRIPT)
        for path in (work, registry, work / "cache"):
            path.chmod(0o777)
        for path in (registry / "proc_probe_action.py", work / "executor.py"):
            path.chmod(0o644)
        yield work


def _usable_by_others(path: Path) -> bool:
    """Return whether every directory above ``path`` is traversable by others."""
    return all(parent.stat().st_mode & 0o001 for parent in path.parents)


def _run_executor(work: Path, mode: str) -> dict[str, object]:
    """Run the stand-in executor as an unprivileged user and return the probe."""
    command = [sys.executable, str(work / "executor.py"), mode, str(work)]
    if os.geteuid() == 0:
        # Root keeps CAP_SYS_PTRACE and would read everything; production
        # executors run as an unprivileged user.
        if not _usable_by_others(Path(sys.executable)):
            pytest.skip("the interpreter is not usable by an unprivileged user")
        command = [
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            *command,
        ]
    env = {**os.environ, "AUTOSECOPS__SYNTHETIC_PLATFORM_KEY": SECRET}
    env["HOME"] = str(work)
    env["TMPDIR"] = str(work)
    completed = subprocess.run(
        command,
        env=env,
        cwd=work,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    lines = [
        line for line in completed.stdout.splitlines() if line.startswith("RESULT:")
    ]
    assert lines, completed.stderr[-4000:]
    result = json.loads(lines[-1].removeprefix("RESULT:"))
    assert isinstance(result, dict), result
    return result


def test_protection_clears_dumpable_flag() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from autosecops.process_hardening import "
            "protect_process_from_inspection, is_process_dumpable; "
            "print(protect_process_from_inspection(), is_process_dumpable())",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.split() == ["True", "False"]
    # The test process itself stays dumpable.
    assert is_process_dumpable()


def test_action_cannot_read_protected_executor_proc_files(work_dir: Path) -> None:
    result = _run_executor(work_dir, "protect")

    assert str(result["executor_environ"]).startswith("denied:")
    assert str(result["executor_mem"]).startswith("denied:")
    assert result["pid1_environ"] != "leaked"
    # The runner protects itself from other actions as well.
    assert result["runner_dumpable"] == 0


def test_unprotected_executor_is_readable_control(work_dir: Path) -> None:
    """Without the protection the same probe reads the secret.

    This keeps the protected test meaningful on this kernel.
    """
    result = _run_executor(work_dir, "unprotected")

    assert result["executor_environ"] == "leaked"
