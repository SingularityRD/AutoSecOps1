"""Worker liveness/readiness marker files and the container probe that reads them."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from autosecops.temporal import healthcheck, worker_lifecycle
from autosecops.temporal.healthcheck import (
    DEFAULT_LIVE_MAX_AGE_SECONDS,
    DEFAULT_READY_MAX_AGE_SECONDS,
    ProbeKind,
    file_age_seconds,
    probe_failure,
)
from autosecops.temporal.worker_lifecycle import (
    run_worker_until_shutdown,
    temporal_worker_readiness_check,
    worker_liveness,
    worker_readiness,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _age(path: Path, seconds: float) -> None:
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))


def test_probe_fails_when_marker_is_missing(tmp_path: Path) -> None:
    failure = probe_failure(
        "live",
        max_age_seconds=60,
        alive_path=tmp_path / "alive",
        ready_path=tmp_path / "ready",
    )
    assert failure is not None and "missing" in failure


@pytest.mark.parametrize("kind", ["live", "ready"])
def test_probe_checks_marker_freshness(tmp_path: Path, kind: ProbeKind) -> None:
    alive, ready = tmp_path / "alive", tmp_path / "ready"
    alive.touch()
    ready.touch()
    assert (
        probe_failure(kind, max_age_seconds=30, alive_path=alive, ready_path=ready)
        is None
    )

    _age(alive if kind == "live" else ready, 45)
    failure = probe_failure(
        kind, max_age_seconds=30, alive_path=alive, ready_path=ready
    )
    assert failure is not None and "stale" in failure


def test_live_and_ready_markers_are_independent(tmp_path: Path) -> None:
    alive, ready = tmp_path / "alive", tmp_path / "ready"
    alive.touch()
    assert (
        probe_failure("live", max_age_seconds=30, alive_path=alive, ready_path=ready)
        is None
    )
    assert probe_failure(
        "ready", max_age_seconds=30, alive_path=alive, ready_path=ready
    )


def test_future_mtime_counts_as_fresh(tmp_path: Path) -> None:
    path = tmp_path / "alive"
    path.touch()
    assert file_age_seconds(path, now=path.stat().st_mtime - 100) == 0.0


def test_main_uses_kind_specific_default_age(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alive, ready = tmp_path / "alive", tmp_path / "ready"
    alive.touch()
    ready.touch()
    monkeypatch.setattr(healthcheck, "WORKER_ALIVE_FILE", alive)
    monkeypatch.setattr(healthcheck, "WORKER_READY_FILE", ready)
    monkeypatch.setattr(
        healthcheck,
        "probe_failure",
        lambda kind, *, max_age_seconds: probe_failure(
            kind, max_age_seconds=max_age_seconds, alive_path=alive, ready_path=ready
        ),
    )
    # Between the two defaults: stale for readiness, fresh for liveness.
    between = (DEFAULT_LIVE_MAX_AGE_SECONDS + DEFAULT_READY_MAX_AGE_SECONDS) / 2
    _age(alive, between)
    _age(ready, between)
    assert healthcheck.main(["live"]) == 0
    assert healthcheck.main(["ready"]) == 1
    assert healthcheck.main(["ready", "--max-age", str(between + 30)]) == 0


def test_main_rejects_max_age_below_refresh_interval() -> None:
    with pytest.raises(SystemExit):
        healthcheck.main(["live", "--max-age", "5"])


def test_probe_module_imports_only_the_standard_library() -> None:
    """The probe runs every few seconds; it must not import the application."""
    code = (
        "import sys; import autosecops.temporal.healthcheck as h; "
        "loaded = [m for m in sys.modules if m.startswith(('autosecops', 'temporalio', "
        "'pydantic', 'sqlalchemy'))]; "
        "assert sorted(loaded) == ['autosecops', 'autosecops.temporal', "
        "'autosecops.temporal.healthcheck'], loaded"
    )
    subprocess.run(
        [sys.executable, "-c", code], check=True, cwd=REPO_ROOT, env={**os.environ}
    )


@pytest.mark.anyio
async def test_liveness_heartbeat_refreshes_and_cleans_up(tmp_path: Path) -> None:
    alive = tmp_path / "alive"
    async with worker_liveness(alive, interval=0.01):
        assert alive.is_file()
        _age(alive, 100)
        await asyncio.sleep(0.05)
        age = file_age_seconds(alive)
        assert age is not None and age < 5
    assert not alive.exists()


@pytest.mark.anyio
async def test_liveness_survives_unwritable_marker(tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing" / "alive"
    async with worker_liveness(missing_dir, interval=0.01):
        await asyncio.sleep(0.03)
    assert not missing_dir.exists()


@pytest.mark.anyio
async def test_worker_main_runs_inside_liveness_heartbeat(tmp_path: Path) -> None:
    alive = tmp_path / "alive"
    seen: list[bool] = []

    async def main(shutdown_event: asyncio.Event) -> None:
        seen.append(alive.is_file())
        shutdown_event.set()

    await run_worker_until_shutdown(main, alive_path=alive)
    assert seen == [True]
    assert not alive.exists()


@pytest.mark.anyio
async def test_readiness_follows_the_check(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    healthy = True

    async def check() -> bool:
        return healthy

    async with worker_readiness(ready, check=check, interval=0.01):
        assert ready.is_file()
        healthy = False
        await asyncio.sleep(0.05)
        assert not ready.exists()
        healthy = True
        await asyncio.sleep(0.05)
        assert ready.is_file()
    assert not ready.exists()


@pytest.mark.anyio
async def test_readiness_treats_check_errors_and_hangs_as_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker_lifecycle, "READINESS_CHECK_TIMEOUT_SECONDS", 0.01)
    ready = tmp_path / "ready"

    async def failing() -> bool:
        raise RuntimeError("temporal unreachable")

    async with worker_readiness(ready, check=failing, interval=0.01):
        await asyncio.sleep(0.05)
        assert not ready.exists()

    async def hanging() -> bool:
        await asyncio.sleep(10)
        return True

    async with worker_readiness(ready, check=hanging, interval=0.01):
        await asyncio.sleep(0.1)
        assert not ready.exists()


@pytest.mark.anyio
async def test_temporal_readiness_requires_running_worker_and_healthy_frontend() -> (
    None
):
    worker = Mock(is_running=True)
    client = Mock()
    client.service_client.check_health = AsyncMock(return_value=True)
    check = temporal_worker_readiness_check(worker, client)

    assert await check() is True
    client.service_client.check_health.assert_awaited_once()

    client.service_client.check_health.return_value = False
    assert await check() is False

    worker.is_running = False
    client.service_client.check_health.reset_mock()
    assert await check() is False
    client.service_client.check_health.assert_not_awaited()
