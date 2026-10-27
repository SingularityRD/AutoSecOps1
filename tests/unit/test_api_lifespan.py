import asyncio
import gc

import pytest

from autosecops.api.lifespan import (
    LifespanTaskSupervisor,
    freeze_startup_heap,
    freeze_startup_heap_after,
    unfreeze_startup_heap,
)


@pytest.mark.anyio
async def test_drain_awaits_finite_task_completion() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    completed = asyncio.Event()

    async def task() -> None:
        await asyncio.sleep(0)
        completed.set()

    supervisor.spawn(task(), name="finite_task")
    await supervisor.drain()

    assert completed.is_set()
    assert supervisor.draining


@pytest.mark.anyio
async def test_drain_cancels_long_running_consumers() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    started = asyncio.Event()
    stopped = asyncio.Event()
    keep_running = asyncio.Event()

    async def consume() -> None:
        started.set()
        try:
            await keep_running.wait()
        finally:
            stopped.set()

    supervisor.spawn(consume(), name="consumer", kind="long_running")
    await started.wait()
    await supervisor.drain()

    assert stopped.is_set()


@pytest.mark.anyio
async def test_drain_cancels_finite_tasks_past_the_deadline() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=0.0)
    started = asyncio.Event()
    cancelled = asyncio.Event()
    keep_running = asyncio.Event()

    async def slow_task() -> None:
        started.set()
        try:
            await keep_running.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    supervisor.spawn(slow_task(), name="slow_finite_task")
    await started.wait()
    await supervisor.drain()

    assert cancelled.is_set()


@pytest.mark.anyio
async def test_drain_abandons_tasks_that_ignore_cancellation() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=0.0)
    started = asyncio.Event()
    swallow_gate = asyncio.Event()
    released = asyncio.Event()

    async def stubborn_task() -> None:
        started.set()
        try:
            await swallow_gate.wait()
        except asyncio.CancelledError:
            # Simulate a task that ignores cancellation past the deadline.
            await released.wait()
            raise

    task = supervisor.spawn(stubborn_task(), name="stubborn_task")
    await started.wait()

    async def release_later() -> None:
        await asyncio.sleep(0)
        released.set()

    # Unblock the stubborn task while drain waits in phase 3.
    asyncio.get_running_loop().create_task(release_later())  # noqa: RUF006
    await asyncio.wait_for(supervisor.drain(), timeout=5.0)

    assert task.done()


@pytest.mark.anyio
async def test_spawn_is_rejected_after_drain_starts() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=0.0)

    async def noop() -> None:
        await asyncio.sleep(0)

    coro = noop()
    await supervisor.drain()
    with pytest.raises(RuntimeError, match="draining"):
        supervisor.spawn(coro, name="late_task")
    # The rejected coroutine never becomes a task; close it explicitly.
    coro.close()


@pytest.mark.anyio
async def test_drain_with_no_tasks_is_a_noop() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=0.0)
    await supervisor.drain()
    assert supervisor.draining


@pytest.mark.anyio
async def test_unexpected_task_failure_is_surfaced_without_unretrieved_warning(
    recwarn: pytest.WarningsRecorder,
) -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)

    async def failing_task() -> None:
        await asyncio.sleep(0)
        raise ValueError("boom")

    supervisor.spawn(failing_task(), name="failing_task")
    await supervisor.drain()
    # Let done callbacks run.
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert not any(
        "Task exception was never retrieved" in str(warning.message)
        for warning in recwarn.list
    )


@pytest.mark.anyio
async def test_drain_completes_with_failed_finite_task() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    ran_after = asyncio.Event()

    async def failing_task() -> None:
        raise ValueError("boom")

    supervisor.spawn(failing_task(), name="failing_task")
    await supervisor.drain()

    # Drain must not raise or hang when a finite task fails.
    ran_after.set()
    assert ran_after.is_set()


@pytest.mark.anyio
async def test_drain_stops_stoppable_consumer_gracefully() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    started = asyncio.Event()
    batch_done = asyncio.Event()
    batch_gate = asyncio.Event()
    injected_stop_event: asyncio.Event | None = None

    def factory(stop_event: asyncio.Event):
        nonlocal injected_stop_event
        injected_stop_event = stop_event

        async def consume() -> None:
            while not stop_event.is_set():
                started.set()
                # Simulate an in-flight batch being processed.
                await batch_gate.wait()
            # Current batch finishes after the stop signal.
            batch_done.set()

        return consume()

    task = supervisor.spawn_stoppable(
        factory,
        name="stoppable_consumer",
    )
    await started.wait()
    assert injected_stop_event is not None
    assert not injected_stop_event.is_set()

    drain_task = asyncio.create_task(supervisor.drain())
    # Let drain signal the stop event, then let the in-flight batch finish.
    await asyncio.sleep(0)
    assert injected_stop_event.is_set()
    batch_gate.set()
    await asyncio.wait_for(drain_task, timeout=5.0)

    assert batch_done.is_set()
    assert not task.cancelled()


@pytest.mark.anyio
async def test_drain_cancels_stoppable_consumer_past_the_deadline() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=0.0)
    started = asyncio.Event()
    stopped = asyncio.Event()
    hang_gate = asyncio.Event()

    def factory(stop_event: asyncio.Event):
        assert not stop_event.is_set()

        async def consume() -> None:
            started.set()
            # Ignore the injected stop event; the deadline must cancel this.
            await hang_gate.wait()
            stopped.set()

        return consume()

    task = supervisor.spawn_stoppable(
        factory,
        name="stubborn_consumer",
    )
    await started.wait()
    await supervisor.drain()

    assert task.cancelled()
    assert not stopped.is_set()


@pytest.mark.anyio
async def test_spawn_stoppable_rejects_after_drain_without_invoking_factory() -> None:
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    factory_called = False

    def factory(stop_event: asyncio.Event):
        nonlocal factory_called
        factory_called = True

        async def consume() -> None:
            await stop_event.wait()

        return consume()

    await supervisor.drain()
    with pytest.raises(RuntimeError, match="draining"):
        supervisor.spawn_stoppable(factory, name="late_stoppable_task")

    assert not factory_called


@pytest.mark.anyio
async def test_drain_surfaces_completed_task_errors_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from autosecops.api import lifespan as lifespan_module

    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    logged_errors: list[tuple[str, dict[str, object]]] = []
    captured_failures: list[tuple[BaseException, str]] = []

    def capture_error(message: str, **kwargs: object) -> None:
        logged_errors.append((message, kwargs))

    monkeypatch.setattr(lifespan_module.logger, "error", capture_error)

    def capture_failure(
        error: BaseException,
        *,
        task_name: str,
    ) -> None:
        captured_failures.append((error, task_name))

    monkeypatch.setattr(
        lifespan_module,
        "capture_api_background_task_failure",
        capture_failure,
    )

    async def failing_task() -> None:
        raise ValueError("boom")

    supervisor.spawn(failing_task(), name="failing_task")
    # Drain must not raise or hang when a finite task fails.
    await supervisor.drain()
    await asyncio.sleep(0)

    assert len(logged_errors) == 1
    message, context = logged_errors[0]
    assert message == "Supervised lifespan task failed"
    assert context["task"] == "failing_task"
    assert isinstance(context["err"], ValueError)
    assert len(captured_failures) == 1
    captured_error, task_name = captured_failures[0]
    assert captured_error is context["err"]
    assert task_name == "failing_task"


def test_freeze_startup_heap_moves_survivors_out_of_full_collections() -> None:
    before = gc.get_freeze_count()
    freeze_startup_heap()
    try:
        assert gc.get_freeze_count() > before
        # New objects stay collectable while the start-up heap is frozen.
        cycle: list[object] = []
        cycle.append(cycle)
        del cycle
        assert gc.collect() >= 1
    finally:
        unfreeze_startup_heap()
    assert gc.get_freeze_count() == 0


@pytest.mark.anyio
async def test_start_up_heap_is_frozen_only_after_the_start_up_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "autosecops.api.lifespan.config.AUTOSECOPS__LOCAL_REPOSITORY_ENABLED", False
    )
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    release = asyncio.Event()
    frozen_while_syncing: list[int] = []

    async def registry_sync() -> None:
        await release.wait()
        frozen_while_syncing.append(gc.get_freeze_count())

    async def failing_load() -> None:
        raise RuntimeError("catalog unavailable")

    sync = supervisor.spawn(registry_sync(), name="sync")
    load = supervisor.spawn(failing_load(), name="load")
    freezer = supervisor.spawn(
        freeze_startup_heap_after(supervisor, [sync, load]), name="freeze"
    )
    try:
        await asyncio.sleep(0.01)
        assert gc.get_freeze_count() == 0
        release.set()
        await freezer
        assert frozen_while_syncing == [0]
        assert gc.get_freeze_count() > 0
    finally:
        await supervisor.drain()
        unfreeze_startup_heap()


@pytest.mark.anyio
@pytest.mark.parametrize("local_repository, draining", [(True, False), (False, True)])
async def test_start_up_heap_is_not_frozen_for_reloads_or_after_shutdown(
    monkeypatch: pytest.MonkeyPatch, local_repository: bool, draining: bool
) -> None:
    monkeypatch.setattr(
        "autosecops.api.lifespan.config.AUTOSECOPS__LOCAL_REPOSITORY_ENABLED",
        local_repository,
    )
    supervisor = LifespanTaskSupervisor(drain_timeout=5.0)
    if draining:
        await supervisor.drain()
    await freeze_startup_heap_after(supervisor, [])
    assert gc.get_freeze_count() == 0
