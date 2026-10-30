"""Platform OIDC login callback: failed authorization-code exchanges."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from httpx_oauth.integrations.fastapi import OAuth2AuthorizeCallback
from httpx_oauth.oauth2 import BaseOAuth2, GetAccessTokenError

from autosecops.api.common import generic_exception_handler, http_exception_handler

TOKEN_ENDPOINT = "https://idp.example.com/realms/internal/protocol/openid-connect/token"


class _RefusingClient(BaseOAuth2[dict[str, Any]]):
    def __init__(self, provider_status: int) -> None:
        super().__init__(
            "client-id",
            "client-secret",
            "https://idp.example.com/authorize",
            TOKEN_ENDPOINT,
        )
        self.provider_status = provider_status

    async def get_access_token(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> Any:
        response = httpx.Response(
            self.provider_status,
            request=httpx.Request("POST", TOKEN_ENDPOINT),
            json={"error": "invalid_grant"},
        )
        raise GetAccessTokenError(
            f"Client error '{self.provider_status}' for url '{TOKEN_ENDPOINT}'",
            response,
        )


def _client(provider_status: int) -> TestClient:
    callback = OAuth2AuthorizeCallback(
        _RefusingClient(provider_status),
        redirect_url="https://app.example.com/auth/oauth/callback",
    )
    app = FastAPI()

    @app.get("/auth/oauth/callback")
    async def oauth_callback(  # pyright: ignore[reportUnusedFunction]
        token_state: Any = Depends(callback),
    ) -> None:
        raise AssertionError("the code exchange must fail first")

    app.add_exception_handler(Exception, generic_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    ("provider_status", "expected_status"),
    [
        # A reused, expired, or forged code: the provider rejects the grant.
        (400, 400),
        (401, 400),
        # The provider itself failed.
        (503, 502),
    ],
)
def test_failed_code_exchange_hides_provider_error(
    provider_status: int, expected_status: int
) -> None:
    response = _client(provider_status).get(
        "/auth/oauth/callback", params={"code": "used-code", "state": "state"}
    )

    assert response.status_code == expected_status
    assert response.json() == {"detail": "OAUTH_CODE_EXCHANGE_FAILED"}
    assert "idp.example.com" not in response.text


def test_provider_error_parameter_still_returns_400() -> None:
    response = _client(400).get(
        "/auth/oauth/callback", params={"error": "access_denied", "state": "state"}
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "access_denied"}
