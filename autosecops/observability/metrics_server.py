"""Internal HTTP listener that serves a metrics registry at ``/metrics``.

The listener is deliberately tiny: it answers ``GET``/``HEAD /metrics`` and
nothing else, reads at most one bounded request per connection, closes the
connection after responding, and serves a bounded number of connections at once. It runs on its own port so the public API router,
Caddy, and the Helm ingress never expose it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Final

from autosecops.logger import logger
from autosecops.observability.prometheus import CONTENT_TYPE

METRICS_PATH: Final = "/metrics"
MAX_REQUEST_LINE_BYTES: Final = 8192
"""Stream reader limit, which bounds each request and header line."""
MAX_HEADER_LINES: Final = 100
REQUEST_TIMEOUT_SECONDS: Final = 5.0
MAX_CONCURRENT_CONNECTIONS: Final = 16
"""Connections served at once; extra connections are closed without a reply.

A scraper needs one connection per scrape, so this only bounds how many file
descriptors and tasks idle peers can hold in the host process.
"""


def _response(status: str, body: bytes, content_type: str, *, head: bool) -> bytes:
    headers = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    return headers if head else headers + body


def build_response(request_line: bytes, render: Callable[[], str]) -> bytes:
    """Return the full HTTP response for one request line."""
    parts = request_line.decode("latin-1").strip().split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return _response("400 Bad Request", b"bad request\n", "text/plain", head=False)
    method, target, _version = parts
    head = method == "HEAD"
    if method not in ("GET", "HEAD"):
        return _response(
            "405 Method Not Allowed", b"method not allowed\n", "text/plain", head=head
        )
    if target.split("?", 1)[0] != METRICS_PATH:
        return _response("404 Not Found", b"not found\n", "text/plain", head=head)
    body = render().encode("utf-8")
    return _response("200 OK", body, CONTENT_TYPE, head=head)


class MetricsServer:
    """Serve ``render()`` output at ``/metrics`` on ``host:port``."""

    def __init__(self, render: Callable[[], str], *, host: str, port: int) -> None:
        self._render = render
        self.host = host
        self.port = port
        self._server: asyncio.Server | None = None
        self._active_connections = 0

    @property
    def bound_port(self) -> int | None:
        """The port actually bound (useful when ``port`` is 0), if started."""
        if self._server is None or not self._server.sockets:
            return None
        return self._server.sockets[0].getsockname()[1]

    async def start(self) -> None:
        """Bind the listener and start accepting connections."""
        self._server = await asyncio.start_server(
            self._handle,
            host=self.host,
            port=self.port,
            limit=MAX_REQUEST_LINE_BYTES,
        )
        logger.info("Metrics listener started", host=self.host, port=self.bound_port)

    async def stop(self) -> None:
        """Stop accepting connections and wait for the listener to close."""
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._active_connections >= MAX_CONCURRENT_CONNECTIONS:
            writer.close()
            return
        self._active_connections += 1
        try:
            await self._serve(reader, writer)
        finally:
            self._active_connections -= 1

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                request_line = await reader.readline()
                for _ in range(MAX_HEADER_LINES):
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                else:
                    return
                writer.write(build_response(request_line, self._render))
                await writer.drain()
        except (TimeoutError, ValueError, ConnectionError, asyncio.IncompleteReadError):
            # Oversized, slow, or dropped requests are closed without a reply.
            pass
        except Exception as e:
            logger.warning("Metrics request failed", error=str(e))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
