from __future__ import annotations

import asyncio
import signal
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager, suppress
from datetime import timedelta
from pathlib import Path
from typing import Protocol

from temporalio.client import Client
from temporalio.worker import Worker

from autosecops.logger import logger
from autosecops.temporal.healthcheck import (
    HEALTH_REFRESH_INTERVAL_SECONDS,
    WORKER_ALIVE_FILE,
    WORKER_READY_FILE,
)

__all__ = [
    "WORKER_ALIVE_FILE",
    "WORKER_READY_FILE",
    "ReadinessCheck",
    "install_worker_shutdown_signal_handlers",
    "run_worker_entrypoint",
    "run_worker_until_shutdown",
    "temporal_worker_readiness_check",
    "worker_readiness",
]

WORKER_SHUTDOWN_SIGNALS = (signal.SIGINT, signal.SIGTERM)
WorkerMain = Callable[[asyncio.Event], Awaitable[None]]
type ReadinessCheck = Callable[[], Awaitable[bool]]
"""Async callable that returns True while the worker can take tasks."""

READINESS_CHECK_TIMEOUT_SECONDS = 5.0
"""Upper bound for one readiness check, kept below the refresh interval."""

_unwritable_health_paths: set[Path] = set()


def _touch_health_file(path: Path) -> bool:
    """Refresh a health marker file; warn once per path when it cannot be written.

    Marker writes never fail the worker: a worker started outside the container
    image (for example on a developer host) has no ``/var/run/autosecops``, and
    there the probes are simply not configured.
    """
    try:
        path.touch()
    except OSError as e:
        if path not in _unwritable_health_paths:
            _unwritable_health_paths.add(path)
            logger.warning(
                "Cannot write worker health file; container probes will fail",
                path=str(path),
                error=str(e),
            )
        return False
    _unwritable_health_paths.discard(path)
    return True


async def _refresh_liveness(path: Path, interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        _touch_health_file(path)


@asynccontextmanager
async def worker_liveness(
    path: Path = WORKER_ALIVE_FILE,
    *,
    interval: float = HEALTH_REFRESH_INTERVAL_SECONDS,
) -> AsyncIterator[None]:
    """Touch ``path`` from the event loop for as long as the context is open.

    The heartbeat runs on the worker's own event loop, so a blocked loop stops
    refreshing the file and the liveness probe reports it. It keeps running
    through a graceful Temporal drain, so a draining worker is not killed.
    """
    _touch_health_file(path)
    task = asyncio.create_task(
        _refresh_liveness(path, interval), name="worker_liveness_heartbeat"
    )
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        with suppress(OSError):
            path.unlink(missing_ok=True)


def temporal_worker_readiness_check(
    worker: Worker,
    client: Client,
    *,
    timeout: float = READINESS_CHECK_TIMEOUT_SECONDS,
) -> ReadinessCheck:
    """Build a check that passes while ``worker`` polls a reachable Temporal.

    A running worker has validated its namespace and started its pollers; a
    fatal poller error stops it. The frontend health check confirms the
    connection is still usable between task polls.
    """

    async def check() -> bool:
        if not worker.is_running:
            return False
        return await client.service_client.check_health(
            timeout=timedelta(seconds=timeout)
        )

    return check


async def _run_readiness_check(check: ReadinessCheck, timeout: float) -> bool:
    try:
        async with asyncio.timeout(timeout):
            return await check()
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning(
            "Worker readiness check failed",
            error_type=type(e).__name__,
            error=str(e),
        )
        return False


async def _refresh_readiness(
    path: Path, check: ReadinessCheck | None, interval: float
) -> None:
    ready = True
    while True:
        await asyncio.sleep(interval)
        healthy = (
            True
            if check is None
            else await _run_readiness_check(check, READINESS_CHECK_TIMEOUT_SECONDS)
        )
        if healthy:
            _touch_health_file(path)
            if not ready:
                logger.info("Worker is ready again", path=str(path))
        else:
            with suppress(OSError):
                path.unlink(missing_ok=True)
            if ready:
                logger.warning("Worker is not ready", path=str(path))
        ready = healthy


@asynccontextmanager
async def worker_readiness(
    path: Path = WORKER_READY_FILE,
    *,
    check: ReadinessCheck | None = None,
    interval: float = HEALTH_REFRESH_INTERVAL_SECONDS,
) -> AsyncIterator[None]:
    """Mark an initialized worker ready until its shutdown begins.

    Enter this after the Temporal worker so LIFO exit removes readiness before
    Temporal drains. While open, ``check`` runs every ``interval`` seconds: a
    passing check refreshes the file, a failing one removes it until the check
    passes again. Without ``check`` the file is refreshed unconditionally.
    """
    _touch_health_file(path)
    task = asyncio.create_task(
        _refresh_readiness(path, check, interval), name="worker_readiness_refresh"
    )
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        path.unlink(missing_ok=True)


class SignalHandlingLoop(Protocol):
    def add_signal_handler(
        self, sig: int, callback: Callable[..., object], *args: object
    ) -> None: ...

    def remove_signal_handler(self, sig: int) -> bool: ...


@contextmanager
def install_worker_shutdown_signal_handlers(
    shutdown_event: asyncio.Event,
    *,
    loop: SignalHandlingLoop | None = None,
    signals: Sequence[signal.Signals] = WORKER_SHUTDOWN_SIGNALS,
) -> Iterator[None]:
    """Wake a worker shutdown event from the running event loop's signal path."""
    event_loop = loop or asyncio.get_running_loop()
    installed: list[signal.Signals] = []

    def request_shutdown(sig: signal.Signals) -> None:
        logger.info("Received shutdown signal", signal=sig.name)
        shutdown_event.set()

    try:
        for sig in signals:
            event_loop.add_signal_handler(sig, request_shutdown, sig)
            installed.append(sig)
        yield
    finally:
        for sig in installed:
            event_loop.remove_signal_handler(sig)


async def run_worker_until_shutdown(
    main: WorkerMain, *, alive_path: Path = WORKER_ALIVE_FILE
) -> None:
    """Run a Temporal worker main coroutine until SIGINT/SIGTERM requests drain.

    The liveness heartbeat starts before ``main`` connects to Temporal, so a
    worker waiting on an unreachable Temporal stays live but not ready.
    """
    shutdown_event = asyncio.Event()
    with install_worker_shutdown_signal_handlers(shutdown_event):
        async with worker_liveness(alive_path):
            await main(shutdown_event)


def run_worker_entrypoint(main: WorkerMain) -> None:
    """Run a Temporal worker process entrypoint with explicit loop lifecycle."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_task_factory(asyncio.eager_task_factory)
    try:
        loop.run_until_complete(run_worker_until_shutdown(main))
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()
