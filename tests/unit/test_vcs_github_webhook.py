"""GitHub App webhook deliveries must be signed with the app's webhook secret."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from pydantic import SecretStr

from autosecops.secrets.encryption import encrypt_keyvalues
from autosecops.secrets.schemas import SecretKeyValue
from autosecops.vcs import router as vcs_router
from autosecops.vcs.github import webhooks
from autosecops.vcs.github.webhooks import compute_github_signature

WEBHOOK_PATH = "/organization/vcs/github/webhook"
WEBHOOK_SECRET = "synthetic-webhook-secret"
APP_ID = "12345"


@pytest.fixture
def webhook_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    async def fake_load(app_id: str | None) -> list[str]:
        return [WEBHOOK_SECRET] if app_id in (None, APP_ID) else []

    monkeypatch.setattr(webhooks, "load_github_app_webhook_secrets", fake_load)
    app = FastAPI()
    app.include_router(vcs_router.org_router)
    with TestClient(app) as client:
        yield client


def _post(
    client: TestClient, body: bytes, headers: dict[str, str] | None = None
) -> Any:
    return client.post(
        WEBHOOK_PATH,
        content=body,
        headers={"content-type": "application/json", **(headers or {})},
    )


def test_unsigned_webhook_is_rejected(webhook_client: TestClient) -> None:
    response = _post(webhook_client, b"{}")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_webhook_with_wrong_signature_is_rejected(webhook_client: TestClient) -> None:
    body = b'{"action": "created"}'
    response = _post(
        webhook_client,
        body,
        {"x-hub-signature-256": compute_github_signature(body, "wrong-secret")},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_webhook_signature_must_cover_the_body(webhook_client: TestClient) -> None:
    signature = compute_github_signature(b'{"action": "created"}', WEBHOOK_SECRET)
    response = _post(
        webhook_client,
        b'{"action": "deleted"}',
        {"x-hub-signature-256": signature},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_webhook_for_other_app_is_rejected(webhook_client: TestClient) -> None:
    body = b"{}"
    response = _post(
        webhook_client,
        body,
        {
            "x-hub-signature-256": compute_github_signature(body, WEBHOOK_SECRET),
            "x-github-hook-installation-target-id": "99999",
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_signed_webhook_is_accepted(webhook_client: TestClient) -> None:
    body = json.dumps(
        {"action": "created", "installation": {"id": 1, "account": {"login": "x"}}}
    ).encode()
    response = _post(
        webhook_client,
        body,
        {
            "x-hub-signature-256": compute_github_signature(body, WEBHOOK_SECRET),
            "x-github-hook-installation-target-id": APP_ID,
        },
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"message": "Webhook processed successfully"}


@pytest.mark.anyio
async def test_load_webhook_secrets_filters_by_app_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Fernet.generate_key().decode()

    def encrypted(app_id: str, webhook_secret: str | None) -> bytes:
        keys = [SecretKeyValue(key="app_id", value=SecretStr(app_id))]
        if webhook_secret is not None:
            keys.append(
                SecretKeyValue(key="webhook_secret", value=SecretStr(webhook_secret))
            )
        return encrypt_keyvalues(keys, key=key)

    rows = [
        encrypted(APP_ID, "secret-a"),
        encrypted("777", "secret-b"),
        encrypted("888", None),
        b"not-a-fernet-token",
    ]
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows
    session = AsyncMock()
    session.execute.return_value = result
    session_cm = AsyncMock()
    session_cm.__aenter__.return_value = session
    monkeypatch.setattr(
        webhooks,
        "get_async_session_bypass_rls_context_manager",
        lambda: session_cm,
    )
    monkeypatch.setattr(webhooks, "get_db_encryption_key", lambda: key)

    assert await webhooks.load_github_app_webhook_secrets(APP_ID) == ["secret-a"]
    assert await webhooks.load_github_app_webhook_secrets(None) == [
        "secret-a",
        "secret-b",
    ]
