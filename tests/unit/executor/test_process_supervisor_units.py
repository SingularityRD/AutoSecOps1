"""In-process checks of the process supervisor's failure and bookkeeping paths.

``test_process_supervisor.py`` runs the supervisor as a real subprocess tree,
which coverage cannot see. These tests drive the same functions directly with
the dangerous system calls replaced.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path

import pytest

from autosecops.executor import process_supervisor


@pytest.mark.parametrize(
    ("wait_status", "expected"),
    [
        (0, 0),
        (3 << 8, 3),
        (signal.SIGKILL, 128 + signal.SIGKILL),
        (signal.SIGTERM, 128 + signal.SIGTERM),
    ],
)
def test_exit_code_is_shell_compatible(wait_status: int, expected: int) -> None:
    assert process_supervisor._exit_code(wait_status) == expected


def test_parent_pid_parsing_tolerates_hostile_process_names(tmp_path: Path) -> None:
    stat = tmp_path / "stat"
    # comm may contain spaces and ")"; only the last ")" ends it, so a name
    # that fakes a parent PID of 1 does not fool the parser.
    stat.write_text("4242 (evil) S 1 (x) R 99 4242 4242 0 -1\n")
    assert process_supervisor._proc_parent_pid(stat) == 99

    stat.write_text("4242 (no-fields)")
    with pytest.raises(RuntimeError, match="Malformed"):
        process_supervisor._proc_parent_pid(stat)


def test_waitpid_retries_after_signal_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []

    def _waitpid(pid: int, options: int) -> tuple[int, int]:
        calls.append((pid, options))
        if len(calls) < 3:
            raise InterruptedError
        return pid, 0

    monkeypatch.setattr(process_supervisor.os, "waitpid", _waitpid)

    assert process_supervisor._waitpid(17, os.WNOHANG) == (17, 0)
    assert calls == [(17, os.WNOHANG)] * 3


def test_kill_loop_repeats_until_no_adopted_children_remain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reaping the first generation orphans a grandchild, which is adopted next.
    generations = [[10, 11], [12], []]
    killed: list[int] = []
    reaped: list[int] = []

    def _kill(pid: int, sig: int) -> None:
        assert sig == signal.SIGKILL
        if pid == 11:
            raise ProcessLookupError
        killed.append(pid)

    def _waitpid(pid: int, options: int = 0) -> tuple[int, int]:
        if pid == 12:
            raise ChildProcessError
        reaped.append(pid)
        return pid, 0

    monkeypatch.setattr(
        process_supervisor, "_direct_child_pids", lambda: generations.pop(0)
    )
    monkeypatch.setattr(process_supervisor.os, "kill", _kill)
    monkeypatch.setattr(process_supervisor, "_waitpid", _waitpid)

    process_supervisor._kill_and_reap_children()

    assert killed == [10, 12]
    assert reaped == [10, 11]
    assert generations == []


def test_direct_children_fall_back_when_children_file_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unavailable() -> list[int]:
        raise FileNotFoundError

    monkeypatch.setattr(
        process_supervisor, "_direct_child_pids_from_children_file", _unavailable
    )
    monkeypatch.setattr(
        process_supervisor, "_direct_child_pids_from_proc_stat", lambda: [5]
    )

    assert process_supervisor._direct_child_pids() == [5]


def test_supervise_rejects_unsupported_platforms_and_empty_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="command is required"):
        process_supervisor.supervise([])

    monkeypatch.setattr(process_supervisor.sys, "platform", "darwin")
    with pytest.raises(RuntimeError, match="requires Linux"):
        process_supervisor.supervise(["true"])


def test_exec_failure_reports_and_exits_127(monkeypatch: pytest.MonkeyPatch) -> None:
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    written: list[bytes] = []

    def _execvpe(*_args: object) -> None:
        raise FileNotFoundError

    def _exit(code: int) -> None:
        raise SystemExit(code)

    monkeypatch.setattr(process_supervisor.os, "execvpe", _execvpe)
    monkeypatch.setattr(process_supervisor.os, "_exit", _exit)
    monkeypatch.setattr(
        process_supervisor.os, "write", lambda fd, data: written.append(data)
    )

    with pytest.raises(SystemExit) as exc_info:
        process_supervisor._exec(["/nonexistent/action"], read_fd)

    assert exc_info.value.code == 127
    assert written == [b"Failed to execute supervised process\n"]
    # The control pipe is never inherited by the action.
    with pytest.raises(OSError):
        os.fstat(read_fd)


@pytest.fixture
def monitor_env(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Neutralise process-wide side effects of ``_run_monitor``."""
    events: list[str] = []
    monkeypatch.setattr(process_supervisor.signal, "signal", lambda *_: None)
    monkeypatch.setattr(
        process_supervisor,
        "_set_parent_death_signal",
        lambda sig: events.append(f"pdeathsig:{sig}"),
    )
    monkeypatch.setattr(
        process_supervisor,
        "_kill_and_reap_children",
        lambda: events.append("reaped"),
    )
    monkeypatch.setattr(
        process_supervisor.os, "setsid", lambda: events.append("setsid")
    )
    monkeypatch.setattr(
        process_supervisor.os, "write", lambda fd, data: events.append(data.decode())
    )
    return events


def test_monitor_refuses_to_start_once_reparented(monitor_env: list[str]) -> None:
    read_fd, write_fd = os.pipe()
    os.close(write_fd)

    status = process_supervisor._run_monitor(
        read_fd, ["true"], supervisor_pid=os.getppid() + 1_000_000
    )

    # The original supervisor is gone: never start the untrusted command.
    assert status == 128 + signal.SIGTERM
    assert "setsid" not in monitor_env
    assert monitor_env == [f"pdeathsig:{signal.SIGCONT}"]
    with pytest.raises(OSError):
        os.fstat(read_fd)


def test_monitor_failure_still_kills_children(
    monitor_env: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def _no_subreaper() -> None:
        raise PermissionError(1, "prctl denied")

    monkeypatch.setattr(process_supervisor, "_set_child_subreaper", _no_subreaper)
    read_fd, write_fd = os.pipe()
    os.close(write_fd)

    status = process_supervisor._run_monitor(
        read_fd, ["true"], supervisor_pid=os.getppid()
    )

    assert status == 1
    assert monitor_env[-2:] == ["reaped", "Process supervisor failed\n"]
    with pytest.raises(OSError):
        os.fstat(read_fd)
