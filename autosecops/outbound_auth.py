"""Route provider SDK token requests through the operator egress proxy.

Google Auth and Azure Identity use their own HTTP stacks, so the shared
outbound client never sees their token requests. These helpers apply
``AUTOSECOPS__OUTBOUND_PROXY_URL`` and ``AUTOSECOPS__OUTBOUND_NO_PROXY`` to
them, with the same local target check the shared client runs before it uses
the proxy. Without a configured proxy the SDKs keep their default behavior.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from azure.identity import AzureAuthorityHosts
from google.auth import exceptions as google_auth_exceptions
from google.auth import transport as google_auth_transport
from google.auth.transport import requests as google_auth_requests

from autosecops.outbound import (
    OutboundRequestDenied,
    egress_proxy_url_for,
    resolve_outbound_addresses,
    resolve_outbound_addresses_sync,
)

_GOOGLE_AUTH_DEFAULT_TIMEOUT = 120
"""Seconds; google-auth's own default for token requests."""


class OutboundGoogleAuthRequest(google_auth_transport.Request):
    """google-auth transport that sends token requests through the egress proxy.

    Wraps google-auth's requests transport and adds per-request proxies.
    """

    def __init__(self) -> None:
        self._request = google_auth_requests.Request()

    def __call__(
        self,
        url: str,
        method: str = "GET",
        body: Any = None,
        headers: Any = None,
        timeout: Any = _GOOGLE_AUTH_DEFAULT_TIMEOUT,
        **kwargs: Any,
    ) -> google_auth_transport.Response:
        if (proxy_url := egress_proxy_url_for(url)) is not None:
            target = httpx.URL(url)
            port = target.port or (443 if target.scheme == "https" else 80)
            try:
                resolve_outbound_addresses_sync(target.host, port)
            except OutboundRequestDenied as exc:
                raise google_auth_exceptions.TransportError(str(exc)) from exc
            kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
        return self._request(
            url, method=method, body=body, headers=headers, timeout=timeout, **kwargs
        )


def _azure_authority_host(authority: str | None) -> str:
    authority = (
        authority
        or os.environ.get("AZURE_AUTHORITY_HOST")
        or AzureAuthorityHosts.AZURE_PUBLIC_CLOUD
    )
    if "://" not in authority:
        authority = f"https://{authority}"
    return authority


async def azure_identity_proxy_kwargs(
    authority: str | None = None,
) -> dict[str, dict[str, str]]:
    """Return Azure Identity credential options that use the egress proxy.

    Empty when no proxy applies to the authority host, so the credential keeps
    its default transport settings.
    """
    authority_url = _azure_authority_host(authority)
    proxy_url = egress_proxy_url_for(authority_url)
    if proxy_url is None:
        return {}
    target = httpx.URL(authority_url)
    await resolve_outbound_addresses(target.host, target.port or 443)
    return {"proxies": {"http": proxy_url, "https": proxy_url}}
