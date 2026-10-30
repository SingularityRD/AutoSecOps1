"""Serve API routers against the per-test database session.

Router tests built on ``tests/unit/api/conftest.py`` replace the database with
a mock, so they cannot show that a route rejects another tenant's row. This
harness mounts the routers under test on a bare FastAPI app with the real
application exception handlers, binds every database dependency to the test's
``session`` fixture, and resolves every ``RoleACL`` dependency to a role the
test can swap between requests.
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

    def _current_role() -> Role:
        ctx_role.set(caller.role)
        return caller.role

    # A route's dependant already includes its router-level dependencies.
    for router in routers:
        for route in _routes(router):
            for call in _role_dependencies(route.dependant):
                app.dependency_overrides[call] = _current_role

    async def _session() -> AsyncGenerator[AsyncSession, None]:
        yield session

    app.dependency_overrides[get_async_session] = _session
    app.dependency_overrides[get_async_session_bypass_rls] = _session

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
