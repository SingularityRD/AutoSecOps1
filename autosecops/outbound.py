"""HTTP clients for caller-controlled destinations on the trusted backend.

Resolve and validate at the socket boundary, then dial the validated numeric IP.
HTTPcore retains the original origin for connection pooling, Host and TLS SNI.
These clients must not be used for trusted internal API or gateway traffic.

With ``TRACECAT__OUTBOUND_PROXY_URL`` set, requests go through that operator
forward proxy instead. The target is still validated and resolved locally first,
but the proxy resolves it again, so a DNS answer that changes between the two
lookups is not covered. Configure the proxy's own egress policy accordingly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from collections.abc import Iterable
from types import TracebackType
from typing import Any

import anyio
import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend

from autosecops import config
from autosecops.network import DisallowedUrlError, is_disallowed_address

type SocketOption = (
    tuple[int, int, int]
    | tuple[int, int, bytes | bytearray]
    | tuple[int, int, None, int]
)


class OutboundRequestDenied(DisallowedUrlError):
    """A deterministic policy rejection, not a retryable upstream failure."""

    # LiteLLM's HTTP handler preserves this status when wrapping exceptions.
    status_code = 403


class OutboundNetworkBackend(httpcore.AsyncNetworkBackend):
    """Validate every DNS answer and connect without resolving the host again."""

    def __init__(self) -> None:
        self._backend: httpcore.AsyncNetworkBackend = AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            # DNS and all address attempts share the connection timeout budget.
            async with asyncio.timeout(timeout):
                addresses = await resolve_outbound_addresses(host, port)
                return await self._connect_addresses(
                    addresses,
                    port,
                    timeout,
                    local_address,
                    tuple(socket_options) if socket_options is not None else None,
                )
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout("Outbound connection timed out") from exc

    async def _connect_addresses(
        self,
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
        port: int,
        timeout: float | None,
        local_address: str | None,
        socket_options: tuple[SocketOption, ...] | None,
    ) -> httpcore.AsyncNetworkStream:
        connected: httpcore.AsyncNetworkStream | None = None
        errors: list[httpcore.ConnectError | httpcore.ConnectTimeout] = []
        caller = asyncio.current_task()
        cancellation_count = caller.cancelling() if caller is not None else 0

        async def attempt(address: str, done: anyio.Event) -> None:
            nonlocal connected
            try:
                stream = await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                errors.append(exc)
            else:
                if connected is None:
                    connected = stream
                    group.cancel_scope.cancel()
                else:
                    # A competing connection may complete as cancellation arrives.
                    with anyio.CancelScope(shield=True):
                        await stream.aclose()
            finally:
                done.set()

        try:
            async with anyio.create_task_group() as group:
                for address in addresses:
                    done = anyio.Event()
                    group.start_soon(attempt, str(address), done)
                    # Preserve failover without repeating DNS resolution. A
                    # failed attempt starts the next immediately; a stalled one
                    # gets a short head start, all within the caller's deadline.
                    with anyio.move_on_after(0.25):
                        await done.wait()
            # Our winner cancels the task group's scope. Preserve a concurrent
            # external cancellation even if that scope consumed its exception.
            if caller is not None and caller.cancelling() > cancellation_count:
                raise asyncio.CancelledError
        except BaseException:
            if connected is not None:
                with anyio.CancelScope(shield=True):
                    await connected.aclose()
            raise

        if connected is not None:
            return connected
        raise errors[-1]

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


async def resolve_outbound_addresses(
    host: str, port: int
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a host and reject the whole result if any address is prohibited."""
    if "%" in host:
        raise OutboundRequestDenied("Scoped addresses are not allowed")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
            addresses = list(
                dict.fromkeys(ipaddress.ip_address(i[4][0]) for i in infos)
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise OutboundRequestDenied("Host could not be resolved") from exc
    else:
        addresses = [literal]
    if not addresses:
        raise OutboundRequestDenied("Host could not be resolved")
    for address in addresses:
        # Classify mapped IPv4 identically to its native IPv4 representation.
        effective = (
            address.ipv4_mapped or address
            if isinstance(address, ipaddress.IPv6Address)
            else address
        )
        allowed = any(
            effective in network
            for network in config.TRACECAT__OUTBOUND_ALLOWED_PRIVATE_CIDRS
        )
        if is_disallowed_address(effective) and not allowed:
            raise OutboundRequestDenied("Host is not allowed")
    return addresses


def _validate_url(url: httpx.URL) -> None:
    if url.scheme not in {"http", "https"} or not url.host:
        raise OutboundRequestDenied("URL must use HTTP or HTTPS and include a host")
    if url.userinfo or "%" in url.host:
        raise OutboundRequestDenied(
            "URL credentials and scoped addresses are not allowed"
        )


def _origin(url: httpx.URL) -> tuple[str, str, int]:
    return url.scheme, url.host, url.port or (443 if url.scheme == "https" else 80)


TUNNEL_PROXY_ENV = "TRACECAT__TUNNEL_PROXY_URL"
"""Set by the executor only for tunneled actions; never read from user input."""


def tunnel_proxy_url() -> str | None:
    """Return the tunnel gateway proxy URL when running a tunneled action."""
    return os.environ.get(TUNNEL_PROXY_ENV) or None


def _bypasses_egress_proxy(host: str) -> bool:
    """Return whether TRACECAT__OUTBOUND_NO_PROXY sends this host direct."""
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for entry in config.TRACECAT__OUTBOUND_NO_PROXY:
        if isinstance(entry, str):
            if address is None and (host == entry or host.endswith(f".{entry}")):
                return True
        elif address is not None and address in entry:
            return True
    return False


def _create_egress_proxy_transport(
    proxy_url: str, **kwargs: Any
) -> httpx.AsyncHTTPTransport:
    """Create the transport that forwards requests to the operator proxy."""
    proxy = httpx.Proxy(proxy_url)
    if proxy.url.scheme == "https":
        # Trust operator CA bundles for TLS to the proxy, as for targets.
        proxy = httpx.Proxy(
            proxy_url,
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=True),
        )
    transport = httpx.AsyncHTTPTransport(proxy=proxy, trust_env=False, **kwargs)
    # Every connection this pool opens goes to the operator-configured proxy,
    # never to the target, so dial it without the destination policy: corporate
    # proxies usually have private addresses. Targets are checked per request.
    transport._pool._network_backend = AnyIOBackend()
    return transport


class OutboundHTTPTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport with socket-level egress policy and optional origin binding.

    In a tunneled action every request goes to the tunnel gateway instead. The
    gateway's exact host/port allowlist decides which targets are reachable, so
    the local address check is skipped; URL and origin checks still apply.

    Otherwise, when an operator egress proxy is configured, requests to hosts
    outside TRACECAT__OUTBOUND_NO_PROXY go through it after the target host
    passes the same local DNS and address policy as a direct connection.
    """

    def __init__(
        self,
        *,
        origin_url: str | None = None,
        tunnel_proxy: str | None = None,
        **kwargs: Any,
    ) -> None:
        # HTTPX exposes no public constructor-options type. The factory below
        # forwards only TLS, protocol and pool options, never proxy or UDS.
        if kwargs.get("verify", True) is True:
            # Trust operator-provided CA bundles without enabling env proxies.
            # Explicit verify contexts/paths retain their normal precedence.
            kwargs["verify"] = httpx.create_ssl_context(verify=True, trust_env=True)
        # The tunnel gateway takes precedence over the operator egress proxy.
        self._egress_proxy: httpx.AsyncHTTPTransport | None = None
        if tunnel_proxy is None and config.TRACECAT__OUTBOUND_PROXY_URL is not None:
            self._egress_proxy = _create_egress_proxy_transport(
                config.TRACECAT__OUTBOUND_PROXY_URL, **kwargs
            )
        if tunnel_proxy is not None:
            kwargs["proxy"] = httpx.Proxy(tunnel_proxy)
        super().__init__(trust_env=False, **kwargs)
        self._origin = None
        if origin_url is not None:
            url = httpx.URL(origin_url)
            _validate_url(url)
            self._origin = _origin(url)
        # HTTPX 0.28.1 does not expose HTTPcore's network_backend argument.
        # Set it before any connection exists, keeping HTTPX's TLS setup,
        # streaming adapter and exception mapping. Covered by socket-level tests.
        if tunnel_proxy is None:
            self._pool._network_backend = OutboundNetworkBackend()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        _validate_url(request.url)
        if self._origin is not None and _origin(request.url) != self._origin:
            raise OutboundRequestDenied(
                "Cross-origin outbound requests are not allowed"
            )
        if self._egress_proxy is not None and not _bypasses_egress_proxy(
            request.url.host
        ):
            await _check_proxied_target(request)
            response = await self._egress_proxy.handle_async_request(request)
        else:
            response = await super().handle_async_request(request)
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location")
            if location is not None:
                try:
                    target = request.url.join(location)
                    _validate_url(target)
                    if _origin(target) != _origin(request.url):
                        raise OutboundRequestDenied(
                            "Cross-origin outbound redirects are not allowed"
                        )
                except (DisallowedUrlError, httpx.InvalidURL):
                    await response.aclose()
                    raise
        return response

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        try:
            await super().__aexit__(exc_type, exc_value, traceback)
        finally:
            if self._egress_proxy is not None:
                await self._egress_proxy.__aexit__(exc_type, exc_value, traceback)

    async def aclose(self) -> None:
        try:
            await super().aclose()
        finally:
            if self._egress_proxy is not None:
                await self._egress_proxy.aclose()


async def _check_proxied_target(request: httpx.Request) -> None:
    """Apply the direct-connection address policy before using the proxy.

    The proxy dials the target itself, so without this check it would reach
    private, loopback and metadata addresses on the backend's behalf.
    """
    _, host, port = _origin(request.url)
    timeouts = request.extensions.get("timeout", {})
    try:
        # DNS shares the connect budget, as on the direct path.
        async with asyncio.timeout(timeouts.get("connect")):
            await resolve_outbound_addresses(host, port)
    except TimeoutError as exc:
        raise httpx.ConnectTimeout(
            "Outbound connection timed out", request=request
        ) from exc


def create_outbound_http_client(
    *,
    origin_url: str | None = None,
    tunnel_proxy: str | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create a direct HTTP client whose network policy cannot be overridden.

    ``origin_url`` binds all requests, including redirects and SSE message URLs,
    to one origin. Use it whenever the client carries credentials for one server.
    ``tunnel_proxy`` sends every request through a tunnel gateway. Shared
    services (api, agent-executor) must pass it per client; otherwise the
    executor's per-action tunnel environment applies.
    Without a tunnel, ``TRACECAT__OUTBOUND_PROXY_URL`` applies; it never comes
    from callers.
    Extra HTTPX options use Any because HTTPX exposes no public constructor
    options type; transport/proxy overrides are deliberately rejected.
    """
    if any(key in kwargs for key in ("transport", "mounts", "proxy")):
        raise ValueError("Outbound clients do not support transport or proxy overrides")
    if kwargs.pop("trust_env", False):
        raise ValueError("Outbound clients do not support environment proxies")
    transport_options = {
        key: kwargs.pop(key)
        for key in ("verify", "cert", "http1", "http2", "limits")
        if key in kwargs
    }
    return httpx.AsyncClient(
        transport=OutboundHTTPTransport(
            origin_url=origin_url,
            tunnel_proxy=tunnel_proxy or tunnel_proxy_url(),
            **transport_options,
        ),
        trust_env=False,
        **kwargs,
    )
