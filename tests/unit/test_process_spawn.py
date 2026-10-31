"""Spawn workers start without the parent's platform credentials."""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import resource_tracker
from pathlib import Path

import pytest

from autosecops.process_hardening import protect_process_from_inspection
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
    with ProcessPoolExecutor(
        max_workers=1,
        mp_context=context,
        initializer=protect_process_from_inspection,
    ) as pool:
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
    if tracker_pid is not None and os.geteuid() == 0:
        assert SECRET.encode() not in Path(f"/proc/{tracker_pid}/environ").read_bytes()
