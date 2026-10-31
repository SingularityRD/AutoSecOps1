"""The agent-executor worker must protect itself before running agent code.

Direct-mode agent runtimes, their Bash tool and stdio MCP servers run as the
worker's own user. Unless the worker is non-dumpable they can read its
``/proc/<pid>/environ`` and memory, which hold the database URI, service key
and every other platform credential. ``test_process_isolation`` shows the
protection itself holds; these tests pin that the agent worker applies it.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from unittest.mock import Mock

import pytest

from autosecops.agent import executor_worker


class _Protected(Exception):
    """Raised by the stand-in protection to stop startup right there."""


@pytest.mark.anyio
async def test_main_protects_the_worker_before_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = Mock(side_effect=AssertionError("started before protection"))
    monkeypatch.setattr(executor_worker, "executor_lifecycle", lifecycle)
    monkeypatch.setattr(
        executor_worker,
        "protect_process_from_inspection",
        Mock(side_effect=_Protected),
    )

    with pytest.raises(_Protected):
        await executor_worker.main()

    lifecycle.assert_not_called()


@pytest.mark.anyio
async def test_main_refuses_to_start_when_protection_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Running agents from an inspectable worker is never a silent fallback."""
    lifecycle = Mock(side_effect=AssertionError("started without protection"))
    monkeypatch.setattr(executor_worker, "executor_lifecycle", lifecycle)
    monkeypatch.setattr(
        executor_worker,
        "protect_process_from_inspection",
        Mock(side_effect=RuntimeError("still dumpable")),
    )

    with pytest.raises(RuntimeError, match="still dumpable"):
        await executor_worker.main()

    lifecycle.assert_not_called()


def test_entrypoint_protects_before_running_the_worker() -> None:
    """``python -m autosecops.agent.executor_worker`` protects first."""
    source = Path(inspect.getsourcefile(executor_worker) or "").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    main_guard = next(
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
    )
    calls = [
        node.value.func.id
        for node in main_guard.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
    ]
    assert calls[0] == "protect_process_from_inspection"
    assert "run_worker_entrypoint" in calls
