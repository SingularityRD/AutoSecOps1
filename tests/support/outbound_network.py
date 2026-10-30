"""Socket-level fakes for tests of code that uses the shared outbound client.

The fakes sit below HTTPX/HTTPcore, so the real egress policy, DNS pinning and
redirect checks in ``autosecops.outbound`` run unchanged; only DNS answers and
the dialed sockets are synthetic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field

import httpcore
import pytest

from autosecops import config
from autosecops.outbound import SocketOption

OK_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"


class RecordingStream(httpcore.AsyncNetworkStream):
    """A socket that records writes and replays one canned HTTP response."""

    def __init__(self, response: bytes) -> None:
        self.response = response
        self.writes: list[bytes] = []
        self.server_hostname: str | None = None

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        chunk, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return chunk

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.writes.append(buffer)

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.server_hostname = server_hostname
        return self

    async def aclose(self) -> None:
        return None


@dataclass
class RecordingNetwork(httpcore.AsyncNetworkBackend):
    """Records every dialed address; each connection answers ``response``."""

    response: bytes = OK_RESPONSE
    connections: list[tuple[str, int]] = field(default_factory=list)
    streams: list[RecordingStream] = field(default_factory=list)

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connections.append((host, port))
        stream = RecordingStream(self.response)
        self.streams.append(stream)
        return stream

    def sent(self) -> bytes:
        """Return every byte written across all connections."""
        return b"".join(b"".join(stream.writes) for stream in self.streams)


def install_recording_network(monkeypatch: pytest.MonkeyPatch) -> RecordingNetwork:
    """Replace the outbound client's socket dialer and clear any allowlist."""
    network = RecordingNetwork()
    monkeypatch.setattr("autosecops.outbound.AnyIOBackend", lambda: network)
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS", ())
    monkeypatch.setattr(config, "AUTOSECOPS__OUTBOUND_PROXY_URL", None)
    return network


def allow_private_cidrs(monkeypatch: pytest.MonkeyPatch, *cidrs: str) -> None:
    """Set ``AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS`` for one test."""
    monkeypatch.setattr(
        config,
        "AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS",
        tuple(ipaddress.ip_network(cidr) for cidr in cidrs),
    )


type AddrInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple]


def _answer(address: str) -> list[AddrInfo]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))]


def resolve_all_to(
    monkeypatch: pytest.MonkeyPatch, address: str, *, host: str | None = None
) -> None:
    """Answer async DNS lookups on the running loop with ``address``.

    With ``host``, only that name is faked and every other lookup (such as the
    test database's) resolves normally.
    """
    loop = asyncio.get_running_loop()
    original = loop.getaddrinfo

    async def getaddrinfo(
        name: bytes | str | None, port: bytes | str | int | None, **kwargs: int
    ) -> list[AddrInfo]:
        if host is None or name == host:
            return _answer(address)
        return await original(name, port, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)


def resolve_all_to_in_any_loop(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    """Answer every ``socket.getaddrinfo`` call, in any thread, with ``address``.

    For code that runs the outbound client on its own event loop.
    """

    def getaddrinfo(*args: object, **kwargs: object) -> list[AddrInfo]:
        return _answer(address)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
