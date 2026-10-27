"""HTTP-level tests for workflow schedule routes."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from autosecops.api.app import app as api_app
from autosecops.auth.types import Role
from autosecops.db.engine import get_async_session
from autosecops.workflow.schedules import router as schedules_router


@pytest.mark.anyio
async def test_search_schedules_is_not_shadowed_by_schedule_id(
    client: TestClient,
    test_admin_role: Role,
) -> None:
    """GET /schedules/search must reach the search route, not /{schedule_id}."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    session = AsyncMock()
    session.execute.return_value = result
    api_app.dependency_overrides[get_async_session] = lambda: session

    response = client.request(
        "GET",
        "/schedules/search",
        params={"workspace_id": str(test_admin_role.workspace_id)},
        json={},
    )

    assert response.status_code == status.HTTP_200_OK, response.text
    assert response.json() == []
    session.execute.assert_awaited_once()


@pytest.mark.anyio
@pytest.mark.parametrize("schedule_id", ["0", "not-a-schedule-id"])
async def test_get_schedule_rejects_malformed_id(
    client: TestClient,
    test_admin_role: Role,
    schedule_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed schedule ID is a client error, not a 500."""
    service_cls = MagicMock()
    monkeypatch.setattr(schedules_router, "WorkflowSchedulesService", service_cls)

    response = client.get(
        f"/schedules/{schedule_id}",
        params={"workspace_id": str(test_admin_role.workspace_id)},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.json()["detail"][0]["loc"] == ["path", "schedule_id"]
    service_cls.assert_not_called()
