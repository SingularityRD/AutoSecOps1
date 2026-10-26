"""HTTP-level tests for workflow tag definition routes."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.exc import NoResultFound

from autosecops.auth.types import Role
from autosecops.tags import router as tags_router


@pytest.mark.anyio
async def test_create_duplicate_tag_returns_400(
    client: TestClient,
    test_admin_role: Role,
) -> None:
    """A duplicate tag slug is a client error, not a 500."""
    with patch.object(tags_router, "TagsService") as mock_service_cls:
        mock_service = AsyncMock()
        mock_service.create_tag.side_effect = ValueError(
            "Tag with slug 'dup-tag' already exists"
        )
        mock_service_cls.return_value = mock_service

        response = client.post(
            "/tags",
            params={"workspace_id": str(test_admin_role.workspace_id)},
            json={"name": "dup-tag"},
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Tag with slug 'dup-tag' already exists"


@pytest.mark.anyio
async def test_update_missing_tag_returns_404(
    client: TestClient,
    test_admin_role: Role,
) -> None:
    with patch.object(tags_router, "TagsService") as mock_service_cls:
        mock_service = AsyncMock()
        mock_service.get_tag.side_effect = NoResultFound()
        mock_service_cls.return_value = mock_service

        response = client.patch(
            f"/tags/{uuid.uuid4()}",
            params={"workspace_id": str(test_admin_role.workspace_id)},
            json={"name": "renamed"},
        )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    mock_service.update_tag.assert_not_called()


@pytest.mark.anyio
async def test_list_workflows_with_malformed_cursor_returns_400(
    client: TestClient,
    test_admin_role: Role,
) -> None:
    """GET /workflows?cursor=null is a client error, not a 500."""
    response = client.get(
        "/workflows",
        params={"workspace_id": str(test_admin_role.workspace_id), "cursor": "null"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["type"] == "PaginationError"
