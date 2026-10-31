"""Spawn-context process pools whose workers start without platform credentials.

``multiprocessing`` starts spawn workers and its resource tracker with the
parent's full environment. Linux keeps that environment readable in
``/proc/<pid>/environ`` for the life of the process, and a freshly executed
worker is dumpable again, so any code running as the same user could read the
platform credentials from it. :func:`scrubbed_spawn_context` returns a spawn
context whose processes start from an allowlisted environment instead.
"""

from __future__ import annotations

import _posixsubprocess
import contextlib
import multiprocessing.context as mp_context
import os
import sys
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from multiprocessing import popen_spawn_posix, resource_tracker, util
from typing import Any, cast

from autosecops.process_env import BASE_ENV_NAMES, BASE_ENV_PREFIXES, select_env

_LAUNCH_LOCK = threading.Lock()

# Typeshed's fork_exec stub does not admit the None values CPython 3.12's own
# multiprocessing passes for cwd and preexec_fn, so the call goes untyped.
_FORK_EXEC: Any = _posixsubprocess.fork_exec

SCRUBBED_SPAWN_SUPPORTED = sys.platform.startswith("linux") and sys.version_info[
    :2
] == (3, 12)
"""Whether this interpreter's ``spawnv_passfds`` matches the replacement below.

The replacement mirrors CPython 3.12's ``multiprocessing.util.spawnv_passfds``
with an explicit environment. Other versions fall back to running work in the
calling process rather than starting workers with the full environment.
"""


def _spawnv_passfds_with_env(
    env: Mapping[str, str],
) -> Callable[[str, list[str], Iterable[int]], int]:
    """Return ``spawnv_passfds`` that starts the child with ``env`` only."""
    env_list = [
        os.fsencode(name) + b"=" + os.fsencode(value) for name, value in env.items()
    ]

    def spawnv_passfds(path: str, args: list[str], passfds: Iterable[int]) -> int:
        fds = tuple(sorted(map(int, passfds)))
        errpipe_read, errpipe_write = os.pipe()
        try:
            return _FORK_EXEC(
                args,
                [os.fsencode(path)],
                True,
                fds,
                None,
                env_list,
                -1,
                -1,
                -1,
                -1,
                -1,
                -1,
                errpipe_read,
                errpipe_write,
                False,
                False,
                -1,
                None,
                None,
                None,
                -1,
                None,
                False,
            )
        finally:
            os.close(errpipe_read)
            os.close(errpipe_write)

    return spawnv_passfds


@contextlib.contextmanager
def _scrubbed_spawnv(env: Mapping[str, str]) -> Iterator[None]:
    """Make multiprocessing start processes with ``env`` while inside.

    popen_spawn_posix and resource_tracker look ``spawnv_passfds`` up on the
    util module at call time, so the swap covers both.
    """
    with _LAUNCH_LOCK:
        original = util.spawnv_passfds
        util.spawnv_passfds = _spawnv_passfds_with_env(env)
        try:
            yield
        finally:
            util.spawnv_passfds = original


_CHILD_ENV: dict[str, str] = {}
"""Environment every scrubbed spawn in this process starts with.

multiprocessing pickles the Process object to the child by class reference, so
the class is module level and the environment lives here rather than on a
per-context subclass. Each :func:`scrubbed_spawn_context` call replaces it."""


class _ScrubbedPopen(popen_spawn_posix.Popen):
    """Spawn launcher that hands the child an allowlisted environment."""

    def _launch(self, process_obj: Any) -> None:
        with _scrubbed_spawnv(_CHILD_ENV):
            # Typeshed omits the private _launch hook this subclass extends.
            cast(Any, super())._launch(process_obj)


class _ScrubbedProcess(mp_context.SpawnProcess):
    """Spawn process started by :class:`_ScrubbedPopen`."""

    _start_method = "spawn"

    @staticmethod
    def _Popen(process_obj: Any) -> Any:  # noqa: N802 - multiprocessing API
        return _ScrubbedPopen(process_obj)


class ScrubbedSpawnContext(mp_context.SpawnContext):
    """Spawn context whose processes start from an allowlisted environment."""

    Process = _ScrubbedProcess

    def __init__(self, child_env: dict[str, str]) -> None:
        super().__init__()
        _CHILD_ENV.clear()
        _CHILD_ENV.update(child_env)
        # Queues and locks start the shared resource tracker on first use; it
        # lives as long as this process, so start it without credentials too.
        with _scrubbed_spawnv(_CHILD_ENV):
            resource_tracker.ensure_running()


def scrubbed_spawn_context(
    *,
    names: Iterable[str] = (),
    prefixes: tuple[str, ...] = (),
) -> ScrubbedSpawnContext:
    """Return a spawn context whose workers get an allowlisted environment.

    Args:
        names: Variables the workers need beyond ``BASE_ENV_NAMES``.
        prefixes: Name prefixes the workers need beyond ``LC_``.

    Returns:
        A spawn context for ``ProcessPoolExecutor(mp_context=...)``.

    Raises:
        RuntimeError: If this interpreter is not supported; check
            ``SCRUBBED_SPAWN_SUPPORTED`` first.
    """
    if not SCRUBBED_SPAWN_SUPPORTED:
        raise RuntimeError("Scrubbed spawn workers need CPython 3.12 on Linux")
    return ScrubbedSpawnContext(
        select_env(
            os.environ,
            names=BASE_ENV_NAMES | frozenset(names),
            prefixes=BASE_ENV_PREFIXES + prefixes,
        )
    )
