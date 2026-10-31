"""Spawn workers start without the parent's platform credentials."""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import resource_tracker
from pathlib import Path
from typing import Any

import pytest

from autosecops import process_spawn
from autosecops.process_spawn import SCRUBBED_SPAWN_SUPPORTED, scrubbed_spawn_context

SECRET = "synthetic-api-service-key"

pytestmark = pytest.mark.skipif(
    not SCRUBBED_SPAWN_SUPPORTED, reason="scrubbed spawn needs CPython 3.12 on Linux"
)


def test_spawn_workers_and_resource_tracker_get_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOSECOPS__SERVICE_KEY", SECRET)
    monkeypatch.setenv("AUTOSECOPS__ROBOT_EDR_CHECK_WORKERS", "1")

    context = scrubbed_spawn_context(prefixes=("AUTOSECOPS__ROBOT_EDR_",))
    # No protecting initializer here: a non-dumpable worker could not read its
    # own /proc/self/environ as a non-root user.
    with ProcessPoolExecutor(max_workers=1, mp_context=context) as pool:
        worker_secret = pool.submit(os.getenv, "AUTOSECOPS__SERVICE_KEY").result()
        worker_setting = pool.submit(
            os.getenv, "AUTOSECOPS__ROBOT_EDR_CHECK_WORKERS"
        ).result()
        worker_environ = pool.submit(
            Path.read_bytes, Path("/proc/self/environ")
        ).result()

    assert worker_secret is None
    assert worker_setting == "1"
    assert SECRET.encode() not in worker_environ
    # The tracker's pid is private; typeshed does not declare it.
    tracker_pid = vars(resource_tracker._resource_tracker).get("_pid")  # noqa: SLF001
    if tracker_pid is not None and os.access(f"/proc/{tracker_pid}/environ", os.R_OK):
        assert SECRET.encode() not in Path(f"/proc/{tracker_pid}/environ").read_bytes()


def test_self_test_fails_closed_when_children_inherit_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOSECOPS__SERVICE_KEY", SECRET)
    real = process_spawn._spawnv_passfds_with_env

    def leaky(env: Any) -> Any:
        return real({**os.environ, **env})

    monkeypatch.setattr(process_spawn, "_spawnv_passfds_with_env", leaky)

    assert process_spawn._self_test() is False


def test_self_test_passes_with_a_scrubbed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOSECOPS__SERVICE_KEY", SECRET)

    assert process_spawn._self_test() is True
