import asyncio

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.db.session_events import AfterCommitQueue


@pytest.mark.anyio
async def test_checkpointed_discards_callbacks_on_cancellation() -> None:
    """Cancellation removes callbacks registered after the guard checkpoint."""
    session = AsyncSession()

    async def existing_callback() -> None:
        pass

    async def cancelled_callback() -> None:
        pass

    try:
        queue = AfterCommitQueue.of(session)
        queue.add(existing_callback)

        with pytest.raises(asyncio.CancelledError):
            with queue.checkpointed():
                queue.add(cancelled_callback)
                raise asyncio.CancelledError

        assert queue.callbacks == [existing_callback]
    finally:
        await session.close()


@pytest.mark.anyio
async def test_outer_rollback_discards_callbacks_before_later_commit() -> None:
    session = AsyncSession()
    called = asyncio.Event()

    async def callback() -> None:
        called.set()

    try:
        await session.begin()
        queue = AfterCommitQueue.of(session)
        queue.add(callback)
        await session.rollback()

        assert queue.callbacks == []
        await session.commit()
        await asyncio.sleep(0)
        assert not called.is_set()
    finally:
        await session.close()


@pytest.mark.anyio
async def test_nested_rollback_preserves_callbacks_for_outer_commit() -> None:
    session = AsyncSession()
    called = asyncio.Event()

    async def callback() -> None:
        called.set()

    try:
        await session.begin()
        queue = AfterCommitQueue.of(session)
        queue.add(callback)
        nested = await session.begin_nested()
        await nested.rollback()

        assert queue.callbacks == [callback]
        await session.commit()
        await asyncio.wait_for(called.wait(), timeout=1)
    finally:
        await session.close()


@pytest.mark.anyio
async def test_callbacks_of_one_commit_run_in_registration_order() -> None:
    """A slow callback finishes before the next one starts.

    Case events of one transaction are delivered by separate callbacks (the
    bulk path's ``case_created`` entries, then ``tag_added``); consumers rely
    on the stream order matching the event order.
    """
    session = AsyncSession()
    order: list[str] = []
    done = asyncio.Event()

    async def slow_first() -> None:
        await asyncio.sleep(0.05)
        order.append("first")

    async def failing_second() -> None:
        order.append("second")
        raise RuntimeError("delivery failed")

    async def fast_third() -> None:
        order.append("third")
        done.set()

    try:
        await session.begin()
        queue = AfterCommitQueue.of(session)
        queue.add(slow_first)
        queue.add(failing_second)
        queue.add(fast_third)
        await session.commit()
        await asyncio.wait_for(done.wait(), timeout=1)
        assert order == ["first", "second", "third"]
    finally:
        await session.close()
