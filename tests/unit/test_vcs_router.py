from __future__ import annotations

import uuid
from typing import Any, Never
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from autosecops.auth.types import Role
from autosecops.exceptions import EntitlementRequired
from autosecops.tiers.enums import Entitlement
from autosecops.vcs import router as vcs_router
from autosecops.vcs.schemas import (
    GitHubAppCredentialsRequest,
    GitLabTokenCredentialsRequest,
)


class _EntitlementFailingGitLabTokenService:
    def __init__(self, *, session: Any, role: Role) -> None:
        del session, role

    def _raise_entitlement(self) -> Never:
        raise EntitlementRequired(Entitlement.GIT_SYNC)

    async def save_gitlab_token_credentials(
        self, *, base_url: str, token: SecretStr
    ) -> tuple[Any, bool]:
        del base_url, token
        self._raise_entitlement()

    async def delete_gitlab_token_credentials(self) -> None:
        self._raise_entitlement()

    async def get_gitlab_token_credentials_status(self) -> dict[str, Any]:
        self._raise_entitlement()


def _org_settings_role(scope: str) -> Role:
    return Role(
        type="user",
        workspace_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        service_id="autosecops-api",
        scopes=frozenset({scope}),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("endpoint", ["save", "delete", "status"])
async def test_gitlab_credentials_endpoints_reraise_entitlement_required(
    endpoint: str,
) -> None:
    with patch.object(
        vcs_router,
        "GitLabTokenService",
        _EntitlementFailingGitLabTokenService,
    ):
        with pytest.raises(EntitlementRequired, match=Entitlement.GIT_SYNC.value):
            match endpoint:
                case "save":
                    await vcs_router.save_gitlab_token_credentials(
                        session=AsyncMock(),
                        role=_org_settings_role("org:settings:update"),
                        request=GitLabTokenCredentialsRequest(
                            base_url="https://gitlab.example.test",
                            token=SecretStr("test-token"),
                        ),
                    )
                case "delete":
                    await vcs_router.delete_gitlab_token_credentials(
                        session=AsyncMock(),
                        role=_org_settings_role("org:settings:delete"),
                    )
                case "status":
                    await vcs_router.get_gitlab_token_credentials_status(
                        session=AsyncMock(),
                        role=_org_settings_role("org:settings:read"),
                    )


class _EntitlementFailingGitHubAppService:
    def __init__(self, *, session: Any, role: Role) -> None:
        del session, role

    def _raise_entitlement(self) -> Never:
        raise EntitlementRequired(Entitlement.GIT_SYNC)

    async def save_github_app_credentials(self, **kwargs: Any) -> tuple[Any, bool]:
        del kwargs
        self._raise_entitlement()

    async def delete_github_app_credentials(self) -> None:
        self._raise_entitlement()

    async def get_github_app_credentials_status(self) -> dict[str, Any]:
        self._raise_entitlement()


@pytest.mark.anyio
@pytest.mark.parametrize("endpoint", ["save", "delete", "status"])
async def test_github_credentials_endpoints_reraise_entitlement_required(
    endpoint: str,
) -> None:
    """Missing git_sync must reach the global 403 handler, not become a 400/500."""
    with patch.object(
        vcs_router,
        "GitHubAppService",
        _EntitlementFailingGitHubAppService,
    ):
        with pytest.raises(EntitlementRequired, match=Entitlement.GIT_SYNC.value):
            match endpoint:
                case "save":
                    await vcs_router.save_github_app_credentials(
                        session=AsyncMock(),
                        role=_org_settings_role("org:settings:update"),
                        request=GitHubAppCredentialsRequest(
                            app_id="12345",
                            private_key=SecretStr("test-private-key"),
                            webhook_secret=None,
                            client_id=None,
                        ),
                    )
                case "delete":
                    await vcs_router.delete_github_app_credentials(
                        session=AsyncMock(),
                        role=_org_settings_role("org:settings:delete"),
                    )
                case "status":
                    await vcs_router.get_github_app_credentials_status(
                        session=AsyncMock(),
                        role=_org_settings_role("org:settings:read"),
                    )
