"""Serve API routers against the per-test database session.

Router tests built on ``tests/unit/api/conftest.py`` replace the database with
a mock, so they cannot show that a route rejects another tenant's row. This
harness mounts the routers under test on a bare FastAPI app with the real
application exception handlers, binds every database dependency to the test's
``session`` fixture, and resolves every ``RoleACL`` dependency to a role the
test can swap between requests.

Scope: these tests cover application-level tenant isolation only, meaning the
``organization_id`` and ``workspace_id`` filters in services and routes. Row
level security is not exercised here, even with ``AUTOSECOPS__RLS_MODE=enforce``:
the shared session connects as the test database owner and never runs
``_initialize_session_rls_context``, so no policy applies. RLS policies are
covered by ``tests/unit/test_rls_policies.py``, which connects as a non-owner
role.

Each request runs like a production request: it starts from committed state,
and anything it flushed without committing is rolled back when it ends, as
production discards it when it closes the request session.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import APIRouter, FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.api.app import app as api_app
from autosecops.auth.credentials import authenticated_user_only
from autosecops.auth.types import Role
from autosecops.contexts import ctx_role
from autosecops.db.engine import get_async_session, get_async_session_bypass_rls


@dataclass
class RoleSwitch:
    """The role the next request authenticates as."""

    role: Role


def _role_dependencies(dependant: Dependant) -> Iterable[Any]:
    for dependency in dependant.dependencies:
        call = dependency.call
        # Dependencies may be callable instances without ``__name__``.
        name = getattr(call, "__name__", "")
        if call is authenticated_user_only or (
            call is not None and name.startswith("role_dependency")
        ):
            yield call
        yield from _role_dependencies(dependency)


def _routes(router: APIRouter) -> Iterable[APIRoute]:
    for route in router.routes:
        if isinstance(route, APIRoute):
            yield route


@asynccontextmanager
async def db_api_client(
    *routers: APIRouter,
    session: AsyncSession,
    caller: RoleSwitch,
    prefix: str = "",
) -> AsyncIterator[httpx.AsyncClient]:
    """Yield an HTTP client for ``routers`` bound to ``session`` and ``caller``."""
    app = FastAPI()
    for router in routers:
        app.include_router(router, prefix=prefix)
    # Reuse the production handlers so domain errors map to real status codes.
    app.exception_handlers.update(api_app.exception_handlers)

    # Async, like production ``role_dependency``: FastAPI runs sync
    # dependencies in a worker thread on a copied context, so a ``ctx_role``
    # set there would never reach the endpoint.
    async def _current_role() -> Role:
        ctx_role.set(caller.role)
        return caller.role

    # A route's dependant already includes its router-level dependencies.
    for router in routers:
        for route in _routes(router):
            for call in _role_dependencies(route.dependant):
                app.dependency_overrides[call] = _current_role

    # Writes flushed since the last commit or rollback. A request that leaves
    # any behind would lose them in production, where the session is closed
    # without a commit.
    unsaved_writes = False

    def _on_flush(*_: object) -> None:
        nonlocal unsaved_writes
        unsaved_writes = True

    def _on_transaction_end(*_: object) -> None:
        nonlocal unsaved_writes
        unsaved_writes = False

    sync_session = session.sync_session
    event.listen(sync_session, "after_flush", _on_flush)
    event.listen(sync_session, "after_commit", _on_transaction_end)
    event.listen(sync_session, "after_soft_rollback", _on_transaction_end)

    async def _session() -> AsyncGenerator[AsyncSession, None]:
        # A production request reads only committed state. Commit releases
        # the savepoint holding the test's own seed writes; the outer
        # transaction still discards them at teardown.
        if session.in_transaction():
            await session.commit()
        try:
            yield session
        finally:
            # Production closes the request session without committing, which
            # discards whatever the route flushed but did not commit, and
            # discards a failed flush. Roll back to the savepoint so such a
            # write cannot reach later requests or the test's own reads.
            # Rollback expires every loaded instance, so a clean request
            # (nothing pending, nothing flushed since its last commit) skips it.
            pending = session.new or session.dirty or session.deleted
            if unsaved_writes or pending or not session.is_active:
                await session.rollback()

    app.dependency_overrides[get_async_session] = _session
    app.dependency_overrides[get_async_session_bypass_rls] = _session

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            yield client
    finally:
        event.remove(sync_session, "after_flush", _on_flush)
        event.remove(sync_session, "after_commit", _on_transaction_end)
        event.remove(sync_session, "after_soft_rollback", _on_transaction_end)
