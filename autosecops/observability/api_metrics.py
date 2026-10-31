"""Prometheus metrics for the API process.

Exposes HTTP request counts and latency labelled by route template, process
resource usage, database pool usage, and license expiry. Served by
``autosecops.observability.metrics_server`` on an internal listener when
``AUTOSECOPS__API_METRICS_ENABLED`` is true; never on the public API port.

HTTP labels are bounded by construction: ``route`` is always the matched route
template (``/workflows/{workflow_id}``), or a fixed placeholder, never the raw
request path, so IDs, emails, and other request values cannot reach a label.
"""

from __future__ import annotations

import os
import platform
import resource
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Final

from starlette.routing import BaseRoute, Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from autosecops import __version__
from autosecops.db.engine import get_pool_usage
from autosecops.licensing.service import get_license_state
from autosecops.licensing.types import LicenseStatus
from autosecops.observability.prometheus import (
    CallbackMetric,
    Counter,
    Gauge,
    Histogram,
    LabelValues,
    Registry,
)

UNMATCHED_ROUTE: Final = "<unmatched>"
"""Route label for requests that matched no route (404s, CORS preflights)."""

MOUNTED_ROUTE_SUFFIX: Final = "/{path}"
"""Appended to a mount's prefix; the sub-application path is not a template."""

OTHER_METHOD: Final = "OTHER"
KNOWN_METHODS: Final = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)

HTTP_DURATION_BUCKETS: Final = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
)

_FASTAPI_SCOPE_KEY: Final = "fastapi"
_FASTAPI_EFFECTIVE_ROUTE_KEY: Final = "effective_route_context"


def _route_path_format(route: object) -> str | None:
    match route:
        case Mount(path_format=path_format):
            return f"{path_format.rstrip('/')}{MOUNTED_ROUTE_SUFFIX}"
        case Route(path_format=path_format) if path_format:
            return path_format
        case BaseRoute():
            return None
    # FastAPI's effective route context is a private dataclass, so it is matched
    # structurally rather than imported.
    match route:
        case object(path_format=str(path_format)) if path_format.startswith("/"):
            return path_format
    return None


def route_template(scope: Scope) -> str:
    """Return the full route template the router matched for ``scope``.

    FastAPI records the effective route of an included router, whose
    ``path_format`` carries every router prefix, under ``scope["fastapi"]``.
    ``scope["route"]`` is the fallback; for included routers it holds only the
    router-local path, which is still a template. Anything else maps to
    ``UNMATCHED_ROUTE``, so the label never contains a raw request path.
    """
    match scope.get(_FASTAPI_SCOPE_KEY):
        case {"effective_route_context": context} if template := _route_path_format(
            context
        ):
            return template
    if template := _route_path_format(scope.get("route")):
        return template
    return UNMATCHED_ROUTE


def method_label(method: str) -> str:
    """Return ``method`` if it is a standard HTTP method, else ``OTHER``."""
    upper = method.upper()
    return upper if upper in KNOWN_METHODS else OTHER_METHOD


@dataclass(frozen=True, slots=True)
class HttpMetrics:
    """Metrics the HTTP middleware records."""

    requests: Counter
    duration: Histogram
    in_progress: Gauge


class PrometheusMiddleware:
    """ASGI middleware recording request count, latency, and concurrency.

    Duration covers the whole response, including streamed bodies. A request
    that raises before sending a response is counted as status 500.
    """

    def __init__(self, app: ASGIApp, metrics: HttpMetrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle one ASGI connection."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = method_label(scope["method"])
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        self.metrics.in_progress.inc((method,))
        start = time.perf_counter()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - start
            self.metrics.in_progress.dec((method,))
            route = route_template(scope)
            self.metrics.requests.inc((method, route, str(status)))
            self.metrics.duration.observe(elapsed, (method, route))


_CLOCK_TICKS: Final = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_PAGE_SIZE: Final = resource.getpagesize()
_PROC_SELF: Final = Path("/proc/self")


@dataclass(frozen=True, slots=True)
class _ProcStat:
    cpu_seconds: float
    virtual_bytes: float
    resident_bytes: float
    start_ticks: float


def _read_proc_stat() -> _ProcStat | None:
    try:
        raw = (_PROC_SELF / "stat").read_text()
    except OSError:
        return None
    # The command name may contain spaces; fields resume after its ")".
    fields = raw[raw.rindex(")") + 2 :].split()
    utime, stime = float(fields[11]), float(fields[12])
    return _ProcStat(
        cpu_seconds=(utime + stime) / _CLOCK_TICKS,
        start_ticks=float(fields[19]),
        virtual_bytes=float(fields[20]),
        resident_bytes=float(fields[21]) * _PAGE_SIZE,
    )


def _boot_time() -> float | None:
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except OSError:
        return None
    return None


def _process_cpu_seconds() -> Iterable[tuple[LabelValues, float]]:
    if stat := _read_proc_stat():
        return [((), stat.cpu_seconds)]
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return [((), usage.ru_utime + usage.ru_stime)]


def _process_resident_memory() -> Iterable[tuple[LabelValues, float]]:
    stat = _read_proc_stat()
    return [((), stat.resident_bytes)] if stat else []


def _process_virtual_memory() -> Iterable[tuple[LabelValues, float]]:
    stat = _read_proc_stat()
    return [((), stat.virtual_bytes)] if stat else []


def _process_open_fds() -> Iterable[tuple[LabelValues, float]]:
    try:
        return [((), float(len(os.listdir(_PROC_SELF / "fd"))))]
    except OSError:
        return []


def _process_max_fds() -> Iterable[tuple[LabelValues, float]]:
    soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    return [((), float(soft))]


def _process_start_time() -> Iterable[tuple[LabelValues, float]]:
    stat = _read_proc_stat()
    boot = _boot_time()
    if stat is None or boot is None:
        return []
    return [((), boot + stat.start_ticks / _CLOCK_TICKS)]


def _db_pool_in_use() -> Iterable[tuple[LabelValues, float]]:
    return [((usage.pool,), float(usage.in_use)) for usage in get_pool_usage()]


def _db_pool_idle() -> Iterable[tuple[LabelValues, float]]:
    return [((usage.pool,), float(usage.idle)) for usage in get_pool_usage()]


def _db_pool_max() -> Iterable[tuple[LabelValues, float]]:
    return [((usage.pool,), float(usage.max_connections)) for usage in get_pool_usage()]


def _license_status() -> Iterable[tuple[LabelValues, float]]:
    current = get_license_state(log=False).status
    return [((status.value,), float(status == current)) for status in LicenseStatus]


def _license_expiry() -> Iterable[tuple[LabelValues, float]]:
    state = get_license_state(now=datetime.now(UTC), log=False)
    if state.claims is None:
        return []
    return [((), state.claims.expires_at.timestamp())]


@dataclass(frozen=True, slots=True)
class ApiMetrics:
    """The API registry and the metrics its middleware records."""

    registry: Registry
    http: HttpMetrics


def build_api_metrics() -> ApiMetrics:
    """Create a registry with every API metric registered."""
    registry = Registry()
    http = HttpMetrics(
        requests=registry.register(
            Counter(
                "autosecops_http_requests",
                "HTTP requests handled by the API, by method, route template, and status.",
                ("method", "route", "status"),
            )
        ),
        duration=registry.register(
            Histogram(
                "autosecops_http_request_duration_seconds",
                "HTTP request duration in seconds, by method and route template.",
                ("method", "route"),
                buckets=HTTP_DURATION_BUCKETS,
            )
        ),
        in_progress=registry.register(
            Gauge(
                "autosecops_http_requests_in_progress",
                "HTTP requests currently being handled by the API.",
                ("method",),
            )
        ),
    )
    build_info = registry.register(
        Gauge(
            "autosecops_build_info",
            "AutoSecOps build information; always 1.",
            ("version", "python_version"),
        )
    )
    build_info.set(1.0, (__version__, platform.python_version()))
    callbacks = (
        CallbackMetric(
            "process_cpu_seconds_total",
            "Total user and system CPU time spent in seconds.",
            _process_cpu_seconds,
            kind="counter",
        ),
        CallbackMetric(
            "process_resident_memory_bytes",
            "Resident memory size in bytes.",
            _process_resident_memory,
        ),
        CallbackMetric(
            "process_virtual_memory_bytes",
            "Virtual memory size in bytes.",
            _process_virtual_memory,
        ),
        CallbackMetric(
            "process_open_fds", "Number of open file descriptors.", _process_open_fds
        ),
        CallbackMetric(
            "process_max_fds",
            "Maximum number of open file descriptors.",
            _process_max_fds,
        ),
        CallbackMetric(
            "process_start_time_seconds",
            "Start time of the process since unix epoch in seconds.",
            _process_start_time,
        ),
        CallbackMetric(
            "autosecops_db_pool_connections_in_use",
            "Database connections checked out of this process's pool.",
            _db_pool_in_use,
            ("pool",),
        ),
        CallbackMetric(
            "autosecops_db_pool_connections_idle",
            "Open database connections idle in this process's pool.",
            _db_pool_idle,
            ("pool",),
        ),
        CallbackMetric(
            "autosecops_db_pool_connections_max",
            "Connections this process's pool can open (pool size plus overflow).",
            _db_pool_max,
            ("pool",),
        ),
        CallbackMetric(
            "autosecops_license_status",
            "Current license status; 1 for the active status, 0 otherwise.",
            _license_status,
            ("status",),
        ),
        CallbackMetric(
            "autosecops_license_expiry_timestamp_seconds",
            "License expiry as a unix timestamp; absent without a verified license.",
            _license_expiry,
        ),
    )
    for metric in callbacks:
        registry.register(metric)
    return ApiMetrics(registry=registry, http=http)


@cache
def get_api_metrics() -> ApiMetrics:
    """Return the process-wide API metrics, created on first use."""
    return build_api_metrics()
