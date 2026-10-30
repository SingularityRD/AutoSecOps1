"""GitHub App webhook secret lookup against real organization secrets.

The signature check accepts a delivery signed by any returned secret, so the
query must return only GitHub App credentials in the default environment, and
a bad row must not hide the secrets stored after it.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.db.models import Organization, OrganizationSecret
from autosecops.secrets.constants import DEFAULT_SECRETS_ENVIRONMENT
from autosecops.secrets.encryption import encrypt_keyvalues
from autosecops.secrets.schemas import SecretKeyValue
from autosecops.vcs.github import webhooks
from autosecops.vcs.github.webhooks import GITHUB_APP_SECRET_NAME


@pytest.fixture
def fernet_key(session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> str:
    """Point the lookup at the test session and a per-test encryption key."""
    key = Fernet.generate_key().decode()

    @asynccontextmanager
    async def _session_cm() -> AsyncIterator[AsyncSession]:
        yield session

    monkeypatch.setattr(
        webhooks, "get_async_session_bypass_rls_context_manager", _session_cm
    )
    monkeypatch.setattr(webhooks, "get_db_encryption_key", lambda: key)
    return key


async def _org(session: AsyncSession) -> uuid.UUID:
    org_id = uuid.uuid4()
    session.add(Organization(id=org_id, name="GH org", slug=f"gh-{org_id.hex[:12]}"))
    await session.flush()
    return org_id


def _credentials(key: str, *, app_id: str, webhook_secret: str) -> bytes:
    return encrypt_keyvalues(
        [
            SecretKeyValue(key="app_id", value=SecretStr(app_id)),
            SecretKeyValue(key="webhook_secret", value=SecretStr(webhook_secret)),
        ],
        key=key,
    )


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_lookup_returns_only_default_environment_github_app_secrets(
    session: AsyncSession, fernet_key: str
) -> None:
    app_id, other_app_id = uuid.uuid4().hex, uuid.uuid4().hex
    rows: list[tuple[str, str, bytes]] = [
        # Inserted first: a corrupt row and another app must be skipped, not
        # end the scan.
        (GITHUB_APP_SECRET_NAME, DEFAULT_SECRETS_ENVIRONMENT, b"not-a-fernet-token"),
        (
            GITHUB_APP_SECRET_NAME,
            DEFAULT_SECRETS_ENVIRONMENT,
            _credentials(fernet_key, app_id=other_app_id, webhook_secret="other-app"),
        ),
        (
            GITHUB_APP_SECRET_NAME,
            DEFAULT_SECRETS_ENVIRONMENT,
            _credentials(fernet_key, app_id=app_id, webhook_secret="wanted-1"),
        ),
        (
            GITHUB_APP_SECRET_NAME,
            DEFAULT_SECRETS_ENVIRONMENT,
            _credentials(fernet_key, app_id=app_id, webhook_secret="wanted-2"),
        ),
        # Same app, but not GitHub App credentials or not the default env.
        (
            "unrelated-secret",
            DEFAULT_SECRETS_ENVIRONMENT,
            _credentials(fernet_key, app_id=app_id, webhook_secret="wrong-name"),
        ),
        (
            GITHUB_APP_SECRET_NAME,
            "staging",
            _credentials(fernet_key, app_id=app_id, webhook_secret="wrong-env"),
        ),
        # Decoys that sort before the real name and environment too.
        (
            "aaa-unrelated-secret",
            DEFAULT_SECRETS_ENVIRONMENT,
            _credentials(fernet_key, app_id=app_id, webhook_secret="wrong-name"),
        ),
        (
            GITHUB_APP_SECRET_NAME,
            "aaa-env",
            _credentials(fernet_key, app_id=app_id, webhook_secret="wrong-env"),
        ),
    ]
    for name, environment, encrypted in rows:
        session.add(
            OrganizationSecret(
                organization_id=await _org(session),
                name=name,
                environment=environment,
                encrypted_keys=encrypted,
            )
        )
        await session.flush()

    assert sorted(await webhooks.load_github_app_webhook_secrets(app_id)) == [
        "wanted-1",
        "wanted-2",
    ]
    assert await webhooks.load_github_app_webhook_secrets(other_app_id) == ["other-app"]
    everything = await webhooks.load_github_app_webhook_secrets(None)
    assert {"wanted-1", "wanted-2", "other-app"} <= set(everything)
    assert not {"wrong-name", "wrong-env"} & set(everything)


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_signature_verification_uses_the_database_secret(
    session: AsyncSession, fernet_key: str
) -> None:
    app_id = uuid.uuid4().hex
    session.add(
        OrganizationSecret(
            organization_id=await _org(session),
            name=GITHUB_APP_SECRET_NAME,
            environment=DEFAULT_SECRETS_ENVIRONMENT,
            encrypted_keys=_credentials(
                fernet_key, app_id=app_id, webhook_secret="db-secret"
            ),
        )
    )
    await session.flush()
    body = b'{"action": "opened"}'
    good = webhooks.compute_github_signature(body, "db-secret")

    assert await webhooks.verify_github_webhook(
        body=body, signature=good, app_id=app_id
    )
    assert not await webhooks.verify_github_webhook(
        body=body + b" ", signature=good, app_id=app_id
    )
    assert not await webhooks.verify_github_webhook(
        body=body, signature=good.removeprefix("sha256="), app_id=app_id
    )
    assert not await webhooks.verify_github_webhook(
        body=body, signature=good, app_id=uuid.uuid4().hex
    )
