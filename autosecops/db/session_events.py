from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final

import sqlalchemy.orm
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.logger import logger

_QUEUE_KEY: Final[str] = "after_commit_queue"
AsyncCallback = Callable[[], Awaitable[Any]]


@dataclass
class AfterCommitQueue:
    """Per-session queue of side effects to run after the session commits."""

    callbacks: list[AsyncCallback] = field(default_factory=list)
    defer_depth: int = 0
    loop: asyncio.AbstractEventLoop | None = None

    @classmethod
    def of(cls, session: AsyncSession | sqlalchemy.orm.Session) -> AfterCommitQueue:
        """Get or create the queue attached to this session."""
        info = (
            session.sync_session.info
            if isinstance(session, AsyncSession)
            else session.info
        )
        queue: AfterCommitQueue | None = info.get(_QUEUE_KEY)
        if queue is None:
            queue = info[_QUEUE_KEY] = cls()
        return queue

    def add(self, callback: AsyncCallback) -> None:
        """Register a callable to run after this session commits."""
        logger.debug("Adding after_commit callback", callback=callback)
        self.callbacks.append(callback)
        if self.loop is None:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

    @contextmanager
    def deferred(self) -> Generator[None]:
        """Defer callbacks across savepoint releases until the outer commit."""
        self.defer_depth += 1
        try:
            yield
        finally:
            self.defer_depth -= 1

    @contextmanager
    def checkpointed(self) -> Generator[None]:
        """Discard callbacks registered by work that raises and is rolled back."""
        checkpoint = len(self.callbacks)
        try:
            yield
        except BaseException:
            del self.callbacks[checkpoint:]
            raise

    def drain_on_commit(self) -> None:
        """Run and clear queued callbacks unless delivery is deferred."""
        if self.defer_depth:
            return

        callbacks, self.callbacks = self.callbacks, []
        if not callbacks:
            return
        logger.debug("Running after_commit callbacks", callbacks=callbacks)
        if self.loop is None:
            logger.error("Expected event loop not found in session info")
            return
        asyncio.run_coroutine_threadsafe(_run_in_order(callbacks), self.loop)

    def discard_on_rollback(self) -> None:
        """Discard side effects registered by a rolled-back transaction."""
        self.callbacks.clear()


async def _run_in_order(callbacks: list[AsyncCallback]) -> None:
    """Run one commit's callbacks one after another, in registration order.

    Side effects of one transaction keep their order (case events published
    to Redis streams in event order, for example): a callback starts only
    after the previous one finished. A failing callback is logged and does
    not stop the ones after it.
    """
    for cb in callbacks:
        try:
            result = cb()
            if asyncio.iscoroutine(result):
                logger.debug("Running after_commit callback", callback=result)
                await result
            else:
                logger.warning("Callback did not return a coroutine", callback=cb)
        except Exception as e:
            logger.error("after_commit callback failed", error=str(e))


@event.listens_for(sqlalchemy.orm.Session, "after_commit")
def _run_after_commit(session: sqlalchemy.orm.Session) -> None:  # pyright: ignore[reportUnusedFunction]
    """Drain callbacks after a session commits."""
    queue: AfterCommitQueue | None = session.info.get(_QUEUE_KEY)
    if queue is not None:
        queue.drain_on_commit()


@event.listens_for(sqlalchemy.orm.Session, "after_soft_rollback")
def _discard_after_outer_rollback(  # pyright: ignore[reportUnusedFunction]
    session: sqlalchemy.orm.Session,
    previous_transaction: sqlalchemy.orm.SessionTransaction,
) -> None:
    """Discard callbacks when the outermost transaction rolls back."""
    if previous_transaction.parent is None:
        queue: AfterCommitQueue | None = session.info.get(_QUEUE_KEY)
        if queue is not None:
            queue.discard_on_rollback()
