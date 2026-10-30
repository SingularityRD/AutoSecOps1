"""Tests for platform OIDC client configuration."""

import importlib
import logging
from unittest.mock import patch

import pytest
from httpx_oauth.clients.openid import OpenID

from autosecops import config
from autosecops.auth.enums import AuthType
from autosecops.auth.oidc import (
    PlatformOpenID,
    create_platform_oauth_client,
    oidc_auth_type_enabled,
)


def test_oidc_auth_type_enabled(monkeypatch) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_TYPES", {AuthType.BASIC})
    assert oidc_auth_type_enabled() is False

    monkeypatch.setattr(config, "AUTOSECOPS__AUTH_TYPES", {AuthType.OIDC})
    assert oidc_auth_type_enabled() is True


def test_create_platform_oauth_client_uses_openid_when_issuer_set(
    monkeypatch,
) -> None:
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://auth.example.com")
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", "oidc-client-id")
    monkeypatch.setattr(config, "OIDC_CLIENT_SECRET", "oidc-client-secret")
    monkeypatch.setattr(config, "OIDC_SCOPES", ("openid", "email", "profile"))

    with patch("autosecops.auth.oidc.PlatformOpenID", autospec=True) as mock_openid:
        mock_client = object()
        mock_openid.return_value = mock_client

        client = create_platform_oauth_client()

    assert client is mock_client
    mock_openid.assert_called_once_with(
        client_id="oidc-client-id",
        client_secret="oidc-client-secret",
        openid_configuration_endpoint=(
            "https://auth.example.com/.well-known/openid-configuration"
        ),
        name="oidc",
        base_scopes=["openid", "email", "profile"],
    )


def test_create_platform_oauth_client_requires_issuer(
    monkeypatch,
) -> None:
    monkeypatch.setattr(config, "OIDC_ISSUER", "")
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", "legacy-client-id")
    monkeypatch.setattr(config, "OIDC_CLIENT_SECRET", "legacy-client-secret")
    monkeypatch.setattr(config, "OIDC_SCOPES", ("openid", "email"))

    with patch("autosecops.auth.oidc.PlatformOpenID", autospec=True) as mock_openid:
        with pytest.raises(ValueError, match="OIDC_ISSUER must be configured"):
            create_platform_oauth_client()

    mock_openid.assert_not_called()


def test_config_defaults_to_basic_when_auth_types_unset(monkeypatch) -> None:
    with monkeypatch.context() as env:
        env.delenv("AUTOSECOPS__AUTH_TYPES", raising=False)
        env.delenv("OIDC_ISSUER", raising=False)
        importlib.reload(config)

        assert config.AUTOSECOPS__AUTH_TYPES == {AuthType.BASIC}

    importlib.reload(config)


def test_config_ignores_removed_google_oauth_auth_type(
    monkeypatch, caplog: pytest.LogCaptureFixture
) -> None:
    with monkeypatch.context() as env:
        env.setenv("AUTOSECOPS__AUTH_TYPES", "basic,google_oauth")
        env.delenv("OIDC_ISSUER", raising=False)
        with caplog.at_level(logging.WARNING):
            importlib.reload(config)

        assert config.AUTOSECOPS__AUTH_TYPES == {AuthType.BASIC}
        assert "Ignoring removed auth type 'google_oauth'" in caplog.text

    importlib.reload(config)


def test_config_rejects_removed_google_oauth_only_auth_type(monkeypatch) -> None:
    with monkeypatch.context() as env:
        env.setenv("AUTOSECOPS__AUTH_TYPES", "google_oauth")
        env.delenv("OIDC_ISSUER", raising=False)
        with pytest.raises(
            ValueError,
            match="AUTOSECOPS__AUTH_TYPES must include at least one supported auth type",
        ):
            importlib.reload(config)

    importlib.reload(config)


def test_config_rejects_empty_auth_types(monkeypatch) -> None:
    with monkeypatch.context() as env:
        env.setenv("AUTOSECOPS__AUTH_TYPES", "")
        env.delenv("OIDC_ISSUER", raising=False)
        importlib.reload(config)

        assert config.AUTOSECOPS__AUTH_TYPES == {AuthType.BASIC}

    importlib.reload(config)


def test_config_keeps_oauth_aliases_for_oidc_credentials(monkeypatch) -> None:
    with monkeypatch.context() as env:
        env.setenv("AUTOSECOPS__AUTH_TYPES", "basic")
        env.delenv("OIDC_CLIENT_ID", raising=False)
        env.delenv("OIDC_CLIENT_SECRET", raising=False)
        env.setenv("OAUTH_CLIENT_ID", "legacy-client-id")
        env.setenv("OAUTH_CLIENT_SECRET", "legacy-client-secret")
        env.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
        env.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
        importlib.reload(config)

        assert config.OIDC_CLIENT_ID == "legacy-client-id"
        assert config.OIDC_CLIENT_SECRET == "legacy-client-secret"

    importlib.reload(config)


def test_config_ignores_google_oauth_env_aliases(monkeypatch) -> None:
    with monkeypatch.context() as env:
        env.setenv("AUTOSECOPS__AUTH_TYPES", "basic")
        env.delenv("OIDC_CLIENT_ID", raising=False)
        env.delenv("OIDC_CLIENT_SECRET", raising=False)
        env.delenv("OAUTH_CLIENT_ID", raising=False)
        env.delenv("OAUTH_CLIENT_SECRET", raising=False)
        env.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-client-id")
        env.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "google-client-secret")
        importlib.reload(config)

        assert config.OIDC_CLIENT_ID == ""
        assert config.OIDC_CLIENT_SECRET == ""

    importlib.reload(config)


def _platform_client() -> PlatformOpenID:
    with patch.object(OpenID, "__init__", return_value=None):
        client = PlatformOpenID(
            client_id="oidc-client-id",
            client_secret="oidc-client-secret",
            openid_configuration_endpoint="https://auth.example.com/.well-known/openid-configuration",
        )
    client.name = "oidc"
    return client


@pytest.mark.anyio
@pytest.mark.parametrize("email_verified", [False, "false", "FALSE"])
async def test_platform_openid_rejects_unverified_email(
    email_verified: object,
) -> None:
    """An email the provider marks unverified must not reach email linking."""
    client = _platform_client()
    profile = {
        "sub": "attacker-sub",
        "email": "owner@example.com",
        "email_verified": email_verified,
    }
    with patch.object(PlatformOpenID, "get_profile", return_value=profile):
        assert await client.get_id_email("token") == ("attacker-sub", None)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "profile",
    [
        {"sub": "user-sub", "email": "user@example.com", "email_verified": True},
        {"sub": "user-sub", "email": "user@example.com", "email_verified": "true"},
        # Providers such as Microsoft Entra ID omit the claim.
        {"sub": "user-sub", "email": "user@example.com"},
    ],
)
async def test_platform_openid_returns_verified_or_unflagged_email(
    profile: dict[str, object],
) -> None:
    client = _platform_client()
    with patch.object(PlatformOpenID, "get_profile", return_value=profile):
        assert await client.get_id_email("token") == ("user-sub", "user@example.com")
