"""Signature verification for GitHub App webhook deliveries."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.fernet import InvalidToken
from sqlalchemy import select

from autosecops.auth.secrets import get_db_encryption_key
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import OrganizationSecret
from autosecops.logger import logger
from autosecops.secrets.constants import DEFAULT_SECRETS_ENVIRONMENT
from autosecops.secrets.encryption import decrypt_keyvalues

GITHUB_APP_SECRET_NAME = "github-app-credentials"
SIGNATURE_PREFIX = "sha256="


def compute_github_signature(body: bytes, webhook_secret: str) -> str:
    """Return the ``X-Hub-Signature-256`` value GitHub sends for ``body``."""
    digest = hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def signature_matches(body: bytes, signature: str, webhook_secret: str) -> bool:
    """Check a ``X-Hub-Signature-256`` header value in constant time."""
    expected = compute_github_signature(body, webhook_secret)
    return hmac.compare_digest(expected.encode(), signature.encode())


async def load_github_app_webhook_secrets(app_id: str | None) -> list[str]:
    """Return the webhook secrets stored for GitHub Apps.

    GitHub App credentials, including the webhook secret GitHub generated for
    the app, are stored per organization. A webhook delivery carries no
    organization context, so every stored GitHub App is considered. When the
    delivery names its app (``X-GitHub-Hook-Installation-Target-ID``), only
    credentials for that app are returned.
    """
    async with get_async_session_bypass_rls_context_manager() as session:
        result = await session.execute(
            select(OrganizationSecret.encrypted_keys).where(
                OrganizationSecret.name == GITHUB_APP_SECRET_NAME,
                OrganizationSecret.environment == DEFAULT_SECRETS_ENVIRONMENT,
            )
        )
        rows = result.scalars().all()

    key = get_db_encryption_key()
    webhook_secrets: list[str] = []
    for encrypted_keys in rows:
        try:
            values = {
                kv.key: kv.value.get_secret_value()
                for kv in decrypt_keyvalues(encrypted_keys, key=key)
            }
        except (InvalidToken, ValueError) as e:
            logger.warning(
                "Skipping unreadable GitHub App credentials",
                error_type=type(e).__name__,
            )
            continue
        if app_id is not None and values.get("app_id") != app_id:
            continue
        if webhook_secret := values.get("webhook_secret"):
            webhook_secrets.append(webhook_secret)
    return webhook_secrets


async def verify_github_webhook(
    *, body: bytes, signature: str | None, app_id: str | None
) -> bool:
    """Return whether a webhook delivery is signed by a configured GitHub App.

    Unsigned deliveries, and deliveries when no GitHub App webhook secret is
    configured, are rejected.
    """
    if not signature or not signature.startswith(SIGNATURE_PREFIX):
        return False
    webhook_secrets = await load_github_app_webhook_secrets(app_id)
    return any(
        signature_matches(body, signature, webhook_secret)
        for webhook_secret in webhook_secrets
    )
