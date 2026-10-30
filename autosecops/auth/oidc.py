"""Platform OIDC/OAuth client configuration utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from httpx_oauth.clients.openid import OpenID
from httpx_oauth.exceptions import GetIdEmailError, GetProfileError
from httpx_oauth.oauth2 import BaseOAuth2

from autosecops import config
from autosecops.auth.enums import AuthType
from autosecops.logger import logger

_DEFAULT_OIDC_SCOPES: Final[tuple[str, ...]] = ("openid", "profile", "email")


@dataclass(frozen=True)
class OIDCProviderConfig:
    """Normalized OIDC provider configuration."""

    issuer: str | None
    client_id: str
    client_secret: str
    scopes: tuple[str, ...]

    @property
    def discovery_endpoint(self) -> str | None:
        if self.issuer is None:
            return None
        return f"{self.issuer}/.well-known/openid-configuration"


def _is_explicitly_unverified(email_verified: Any) -> bool:
    """Whether the provider says the email is unverified.

    Some providers send the claim as a string or a number; providers that
    omit it (for example Microsoft Entra ID) are trusted as before.
    """
    if isinstance(email_verified, bool):
        return email_verified is False
    if isinstance(email_verified, str):
        return email_verified.strip().lower() in {"false", "0"}
    if isinstance(email_verified, int | float):
        return email_verified == 0
    return False


class PlatformOpenID(OpenID):
    """OpenID client that refuses emails the provider marks as unverified.

    Login links accounts by email, so an unverified email would let anyone who
    can set an arbitrary address at the provider sign in as that user.
    """

    async def get_id_email(self, token: str) -> tuple[str, str | None]:
        try:
            profile = await self.get_profile(token)
        except GetProfileError as e:
            raise GetIdEmailError(response=e.response) from e
        account_id = str(profile["sub"])
        email = profile.get("email")
        if email is not None and _is_explicitly_unverified(
            profile.get("email_verified")
        ):
            logger.warning(
                "Rejected OIDC login with an unverified email",
                oauth_name=self.name,
            )
            return account_id, None
        return account_id, email


def oidc_auth_type_enabled() -> bool:
    """Whether platform auth policy allows OIDC-style login."""
    return AuthType.OIDC in config.AUTOSECOPS__AUTH_TYPES


def get_platform_oidc_config() -> OIDCProviderConfig:
    """Return normalized OIDC config."""
    issuer = config.OIDC_ISSUER.strip().rstrip("/") or None
    scopes = config.OIDC_SCOPES or _DEFAULT_OIDC_SCOPES
    return OIDCProviderConfig(
        issuer=issuer,
        client_id=config.OIDC_CLIENT_ID,
        client_secret=config.OIDC_CLIENT_SECRET,
        scopes=scopes,
    )


def create_platform_oauth_client() -> BaseOAuth2:
    """Create the platform OAuth client used for login/callback routes."""
    oidc_config = get_platform_oidc_config()
    scopes = list(oidc_config.scopes)
    discovery_endpoint = oidc_config.discovery_endpoint
    if discovery_endpoint is None:
        raise ValueError("OIDC_ISSUER must be configured for OIDC login.")
    return PlatformOpenID(
        client_id=oidc_config.client_id,
        client_secret=oidc_config.client_secret,
        openid_configuration_endpoint=discovery_endpoint,
        name="oidc",
        base_scopes=scopes,
    )
