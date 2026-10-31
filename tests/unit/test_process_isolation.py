"""Direct-mode action and registry code cannot inspect platform processes."""

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

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setpriv") is None,
    reason="process inspection protection and direct actions need Linux and setpriv",
)

SECRET = "synthetic-executor-secret-value"

PROBE_MODULE = """
import ctypes
import os
import time
from pathlib import Path

SECRET = SECRET_PLACEHOLDER


def _read(path):
    try:
        with open(path, "rb") as file:
            data = file.read(1 << 20)
    except OSError as exc:
        return "denied:" + type(exc).__name__
    return "leaked" if SECRET.encode() in data else "readable"


def _write(path):
    try:
        with open(path, "wb", buffering=0) as file:
            file.write(b'{"success": true, "result": "forged"}')
    except OSError as exc:
        return "denied:" + type(exc).__name__
    return "written"


def _dumpable():
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.prctl(3, 0, 0, 0, 0)


def probe(targets):
    outcome = {"runner_dumpable": _dumpable()}
    for label, path in targets.items():
        outcome[label] = _read(path)
    return outcome


def wait(seconds):
    time.sleep(seconds)
    return "victim-finished"


def _ancestors():
    pids = set()
    pid = os.getpid()
    while pid > 1:
        pids.add(pid)
        stat = Path(f"/proc/{pid}/stat").read_text()
        pid = int(stat[stat.rfind(")") + 2 :].split()[1])
    return pids


def _read_nonblocking(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        return "denied:" + type(exc).__name__
    try:
        data = os.read(fd, 1 << 20)
    except BlockingIOError:
        data = b""
    except OSError as exc:
        return "denied:" + type(exc).__name__
    finally:
        os.close(fd)
    return "leaked" if SECRET.encode() in data else "readable"


def watch_startups(seconds):
    # Race every new action process for its payload while it starts up.
    mine = _ancestors()
    deadline = time.monotonic() + seconds
    seen = {}
    while time.monotonic() < deadline:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal() or int(entry.name) in mine:
                continue
            try:
                cmdline = (entry / "cmdline").read_bytes()
            except OSError:
                continue
            if b"minimal_runner.py" not in cmdline and b"process_supervisor.py" not in cmdline:
                continue
            outcomes = seen.setdefault(entry.name, set())
            outcomes.add("stdin:" + _read_nonblocking(entry / "fd" / "0"))
            outcomes.add("stdout:" + _read_nonblocking(entry / "fd" / "1"))
            outcomes.add("stderr:" + _read_nonblocking(entry / "fd" / "2"))
            outcomes.add("stdout-write:" + _write(entry / "fd" / "1"))
            outcomes.add("environ:" + _read(entry / "environ"))
    return {pid: sorted(outcomes) for pid, outcomes in seen.items()}


def attack_other_actions():
    mine = _ancestors()
    outcome = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal() or int(entry.name) in mine:
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\\0", b" ")
        except OSError:
            continue
        if b"process_supervisor.py" not in cmdline and b"minimal_runner.py" not in cmdline:
            continue
        outcome[entry.name] = {
            "environ": _read(entry / "environ"),
            "stdin": _read(entry / "fd" / "0"),
            "stdout": _write(entry / "fd" / "1"),
            "stdout_read": _read_nonblocking(entry / "fd" / "1"),
            "stderr": _write(entry / "fd" / "2"),
        }
    return {"runner_dumpable": _dumpable(), "targets": outcome}
"""

# Runs as a stand-in executor worker: it holds a platform secret in its
# environment, optionally protects itself as the real worker does, then runs
# direct-mode actions as the worker would.
EXECUTOR_SCRIPT = """
import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from autosecops.process_hardening import protect_process_from_inspection

mode = sys.argv[1]
if mode != "unprotected":
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
runner = ActionRunner(cache_dir=work / "cache")


async def run(name, args, secret_env):
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
            name=name,
        ),
        evaluated_args=args,
        workspace_id=str(role.workspace_id),
        workflow_id=str(wf_id),
        run_id=str(run_input.run_context.wf_run_id),
        executor_token=os.environ["AUTOSECOPS__SYNTHETIC_PLATFORM_KEY"],
    )
    result = await runner._execute_direct(
        input=run_input,
        role=role,
        registry_paths=[work / "registry"],
        secret_projection=SecretEnvProjection(env=secret_env, mask_values=set()),
        timeout=60.0,
        resolved_context=context,
    )
    return result if isinstance(result, (dict, str)) else str(result)


async def concurrent():
    victim = asyncio.create_task(run("wait", {"seconds": 4}, {"VICTIM_KEY": "x"}))
    await asyncio.sleep(2)
    attacker = await run("attack_other_actions", {}, {})
    return {"victim": await victim, "attacker": attacker}


async def startup_race():
    attacker = asyncio.create_task(run("watch_startups", {"seconds": 8}, {}))
    await asyncio.sleep(2)
    victims = [
        await run("wait", {"seconds": 0}, {"VICTIM_KEY": os.environ["AUTOSECOPS__SYNTHETIC_PLATFORM_KEY"]})
        for _ in range(5)
    ]
    return {"victims": victims, "attacker": await attacker}


if mode == "concurrent":
    result = asyncio.run(concurrent())
elif mode == "startup":
    result = asyncio.run(startup_race())
else:
    pid = os.getpid()
    targets = {
        "executor_environ": f"/proc/{pid}/environ",
        "executor_mem": f"/proc/{pid}/mem",
        "pid1_environ": "/proc/1/environ",
    }
    result = asyncio.run(run("probe", {"targets": targets}, {}))
print("RESULT:" + json.dumps(result))
"""

# Runs registry sync as the API or executor would: installation is stubbed to
# drop a package into the per-sync target, then the real discovery subprocess
# imports it. The package reports what it could read from its parent.
SYNC_SCRIPT = """
import asyncio
import json
import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

from autosecops.registry.repository import Repository, RepositoryInstallation
from autosecops.registry.sync import subprocess as sync_subprocess

work = Path(sys.argv[1])
out = work / "sync-probe.json"
PACKAGE = '''
import json
import os
from pathlib import Path


def _read(path):
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        return "denied:" + type(exc).__name__
    return "leaked" if SECRET.encode() in data else "readable"


Path(OUT).write_text(json.dumps({
    "parent_environ": _read(f"/proc/{os.getppid()}/environ"),
    "pid1_environ": _read("/proc/1/environ"),
}))
'''.replace("SECRET", repr(sys.argv[2])).replace("OUT", repr(str(out)))


async def install(*, commit_sha=None, target_dir):
    package = target_dir / "sync_probe"
    package.mkdir()
    (package / "__init__.py").write_text(PACKAGE)
    return RepositoryInstallation(
        package_name="sync_probe", commit_sha=None, site_dir=target_dir
    )


async def main():
    with (
        patch.object(Repository, "install_from_origin", AsyncMock(side_effect=install)),
        patch.object(sync_subprocess, "get_setting", AsyncMock(return_value=False)),
    ):
        await sync_subprocess.fetch_actions_from_subprocess(
            origin="git+ssh://git@github.com/example-org/sync_probe.git",
            repository_id=uuid.uuid4(),
            timeout=120.0,
        )


asyncio.run(main())
print("RESULT:" + out.read_text())
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
        (work / "sync.py").write_text(SYNC_SCRIPT)
        for path in (work, registry, work / "cache"):
            path.chmod(0o777)
        for path in (
            registry / "proc_probe_action.py",
            work / "executor.py",
            work / "sync.py",
        ):
            path.chmod(0o644)
        yield work


def _usable_by_others(path: Path) -> bool:
    """Return whether every directory above ``path`` is traversable by others."""
    return all(parent.stat().st_mode & 0o001 for parent in path.parents)


def _run_unprivileged(work: Path, *args: str) -> dict[str, object]:
    """Run a helper script as an unprivileged user and return its result."""
    command = [sys.executable, *args]
    if os.geteuid() == 0:
        # Root keeps CAP_SYS_PTRACE and would read everything; production
        # platform processes run as an unprivileged user.
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


def _run_executor(work: Path, mode: str) -> dict[str, object]:
    return _run_unprivileged(work, str(work / "executor.py"), mode, str(work))


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


def test_action_cannot_read_protected_executor_proc_files(work_dir: Path) -> None:
    result = _run_executor(work_dir, "protect")

    assert str(result["executor_environ"]).startswith("denied:")
    assert str(result["executor_mem"]).startswith("denied:")
    assert result["pid1_environ"] != "leaked"
    # The runner protects itself from other actions as well.
    assert result["runner_dumpable"] == 0


def test_unprotected_executor_is_readable_control(work_dir: Path) -> None:
    """Without the protection the same probe reads the secret.

    This keeps the protected tests meaningful on this kernel.
    """
    result = _run_executor(work_dir, "unprotected")

    assert result["executor_environ"] == "leaked"


def test_action_cannot_reach_another_actions_supervisor_or_runner(
    work_dir: Path,
) -> None:
    """A second action cannot read the first's environment, stdin, or stdout."""
    result = _run_executor(work_dir, "concurrent")

    assert result["victim"] == "victim-finished"
    attacker = result["attacker"]
    assert isinstance(attacker, dict), attacker
    targets = attacker["targets"]
    # The victim's supervisor, monitor and runner are all visible.
    assert len(targets) >= 3, targets
    for pid, outcome in targets.items():
        assert outcome["environ"].startswith("denied:"), (pid, outcome)
        assert outcome["stdin"].startswith("denied:"), (pid, outcome)
        assert outcome["stdout"].startswith("denied:"), (pid, outcome)
        assert outcome["stdout_read"].startswith("denied:"), (pid, outcome)
        assert outcome["stderr"].startswith("denied:"), (pid, outcome)


def test_registry_code_cannot_read_the_syncing_process(work_dir: Path) -> None:
    """Repository code imported during sync cannot read its parent's secrets."""
    result = _run_unprivileged(
        work_dir, str(work_dir / "sync.py"), str(work_dir), SECRET
    )

    assert str(result["parent_environ"]).startswith("denied:")
    assert result["pid1_environ"] != "leaked"


def test_action_cannot_read_another_actions_payload_during_startup(
    work_dir: Path,
) -> None:
    """The payload is never in a channel another action can open.

    Before the runner protects itself it is briefly readable through /proc, so
    the payload (workspace secrets) arrives over a socket, which /proc cannot
    open, and only after the runner reports that it is ready.
    """
    result = _run_executor(work_dir, "startup")

    assert result["victims"] == ["victim-finished"] * 5
    attacker = result["attacker"]
    assert isinstance(attacker, dict), attacker
    assert attacker, "the attacker never saw a victim process start"
    for pid, outcomes in attacker.items():
        assert not any(outcome.endswith("leaked") for outcome in outcomes), (
            pid,
            outcomes,
        )
        # stdin, stdout and stderr are sockets, which /proc never opens, so
        # no payload, result or diagnostics can be read or forged.
        for stream in ("stdin", "stdout", "stderr"):
            assert f"{stream}:readable" not in outcomes, (pid, outcomes)
        assert "stdout-write:written" not in outcomes, (pid, outcomes)
