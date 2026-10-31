"""API Prometheus metrics: exposition format, route-template labels, listener."""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient

from autosecops import config
from autosecops.api.app import app as api_app
from autosecops.api.app import create_app
from autosecops.db.types import DbPoolUsage
from autosecops.licensing.types import LicenseState, LicenseStatus
from autosecops.observability import api_metrics
from autosecops.observability.api_metrics import (
    UNMATCHED_ROUTE,
    PrometheusMiddleware,
    build_api_metrics,
    method_label,
)
from autosecops.observability.metrics_server import (
    MAX_REQUEST_LINE_BYTES,
    MetricsServer,
    build_response,
)
from autosecops.observability.prometheus import (
    CallbackMetric,
    Counter,
    Gauge,
    Histogram,
    Registry,
)

SECRET_VALUE = "person@example.com"


def _sample_lines(text: str, name: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(name)]


def test_counter_exposition_uses_total_suffix_and_escapes_labels() -> None:
    registry = Registry()
    counter = registry.register(Counter("jobs", "Jobs run.", ("kind",)))
    counter.inc(('a"b\\c\nd',))
    counter.inc(('a"b\\c\nd',), 2)
    text = registry.render()
    assert "# HELP jobs_total Jobs run.\n# TYPE jobs_total counter\n" in text
    assert 'jobs_total{kind="a\\"b\\\\c\\nd"} 3\n' in text
    with pytest.raises(ValueError):
        counter.inc(("x",), -1)
    with pytest.raises(ValueError):
        counter.inc(("x", "y"))


def test_histogram_buckets_are_cumulative() -> None:
    registry = Registry()
    histogram = registry.register(
        Histogram("latency_seconds", "Latency.", ("route",), buckets=(0.1, 1.0))
    )
    for value in (0.05, 0.5, 0.5, 5.0, float("nan")):
        histogram.observe(value, ("/x",))
    text = registry.render()
    assert 'latency_seconds_bucket{route="/x",le="0.1"} 1\n' in text
    assert 'latency_seconds_bucket{route="/x",le="1"} 3\n' in text
    assert 'latency_seconds_bucket{route="/x",le="+Inf"} 4\n' in text
    assert 'latency_seconds_count{route="/x"} 4\n' in text
    assert 'latency_seconds_sum{route="/x"} 6.05\n' in text


def test_series_cap_drops_new_label_values() -> None:
    gauge = Gauge("g", "G.", ("k",), max_series=2)
    for key in ("a", "b", "c"):
        gauge.set(1, (key,))
    gauge.set(5, ("a",))
    assert {sample.labels: sample.value for sample in gauge.samples()} == {
        (("k", "a"),): 5,
        (("k", "b"),): 1,
    }


def test_failing_collector_does_not_break_the_scrape() -> None:
    registry = Registry()

    def broken() -> list[tuple[tuple[str, ...], float]]:
        raise RuntimeError("boom")

    registry.register(CallbackMetric("broken", "Broken.", broken))
    registry.register(Gauge("ok", "Ok.")).set(1)
    text = registry.render()
    assert "broken" not in text
    assert "ok 1\n" in text


def test_duplicate_metric_names_are_rejected() -> None:
    registry = Registry()
    registry.register(Gauge("dup", "Dup."))
    with pytest.raises(ValueError):
        registry.register(Gauge("dup", "Dup."))


def test_callback_counter_name_must_end_in_total() -> None:
    with pytest.raises(ValueError):
        CallbackMetric("cpu_seconds", "CPU.", list, kind="counter")


@pytest.mark.parametrize(
    ("method", "label"),
    [("get", "GET"), ("PATCH", "PATCH"), ("PROPFIND", "OTHER"), ("x" * 50, "OTHER")],
)
def test_method_label_is_bounded(method: str, label: str) -> None:
    assert method_label(method) == label


def _instrumented(app: FastAPI) -> tuple[TestClient, api_metrics.ApiMetrics]:
    metrics = build_api_metrics()
    client = TestClient(
        PrometheusMiddleware(app, metrics.http), raise_server_exceptions=False
    )
    return client, metrics


def _request_labels(metrics: api_metrics.ApiMetrics) -> set[tuple[str, str, str]]:
    return {
        (labels[0][1], labels[1][1], labels[2][1])
        for labels in (sample.labels for sample in metrics.http.requests.samples())
    }


def test_route_labels_are_templates_of_nested_routers() -> None:
    app = FastAPI()
    items = APIRouter(prefix="/items")

    def get_item(item_id: str) -> dict[str, str]:
        if item_id == "missing":
            raise HTTPException(status_code=404)
        return {"id": item_id}

    def fail(item_id: str) -> None:
        raise RuntimeError("unhandled")

    items.add_api_route("/{item_id}", get_item, methods=["GET"])
    items.add_api_route("/{item_id}/fail", fail, methods=["POST"])

    workspaces = APIRouter(prefix="/workspaces/{workspace_id}")
    workspaces.include_router(items)
    app.include_router(workspaces)

    client, metrics = _instrumented(app)
    assert (
        client.get(f"/workspaces/{uuid.uuid4()}/items/{SECRET_VALUE}").status_code
        == 200
    )
    assert client.get("/workspaces/w/items/missing").status_code == 404
    assert client.post("/workspaces/w/items/x/fail").status_code == 500
    assert client.get(f"/no-such-route/{SECRET_VALUE}").status_code == 404
    assert client.request("PROPFIND", "/workspaces/w/items/x").status_code == 405

    template = "/workspaces/{workspace_id}/items/{item_id}"
    assert _request_labels(metrics) == {
        ("GET", template, "200"),
        ("GET", template, "404"),
        ("POST", f"{template}/fail", "500"),
        ("GET", UNMATCHED_ROUTE, "404"),
        ("OTHER", template, "405"),
    }
    text = metrics.registry.render()
    assert SECRET_VALUE not in text
    assert "no-such-route" not in text
    assert 'autosecops_http_requests_in_progress{method="GET"} 0\n' in text
    count = _sample_lines(
        text,
        'autosecops_http_request_duration_seconds_count{method="GET",'
        f'route="{template}"}}',
    )
    assert count == [
        'autosecops_http_request_duration_seconds_count{method="GET",'
        f'route="{template}"}} 2'
    ]


def test_route_labels_on_the_real_api_are_templates() -> None:
    client, metrics = _instrumented(api_app)
    workflow_id = f"wf_{uuid.uuid4().hex}"
    client.get("/health")
    client.get(f"/workflows/{workflow_id}", params={"workspace_id": str(uuid.uuid4())})
    routes = {route for _method, route, _status in _request_labels(metrics)}
    assert routes == {"/health", "/workflows/{workflow_id}"}
    assert workflow_id not in metrics.registry.render()


def test_api_registry_exposes_process_pool_and_license_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        api_metrics,
        "get_pool_usage",
        lambda: [DbPoolUsage(pool="main", in_use=7, idle=3, max_connections=70)],
    )
    expires = datetime.now(UTC) + timedelta(days=10)
    monkeypatch.setattr(
        api_metrics,
        "get_license_state",
        lambda **_: LicenseState(
            status=LicenseStatus.VALID, claims=Mock(expires_at=expires)
        ),
    )
    text = build_api_metrics().registry.render()
    assert 'autosecops_db_pool_connections_in_use{pool="main"} 7\n' in text
    assert 'autosecops_db_pool_connections_idle{pool="main"} 3\n' in text
    assert 'autosecops_db_pool_connections_max{pool="main"} 70\n' in text
    assert 'autosecops_license_status{status="valid"} 1\n' in text
    assert 'autosecops_license_status{status="expired"} 0\n' in text
    assert (
        f"autosecops_license_expiry_timestamp_seconds {expires.timestamp()!r}\n" in text
    )
    assert "# TYPE process_cpu_seconds_total counter\n" in text
    assert re.search(r"^process_resident_memory_bytes \d+$", text, re.MULTILINE)
    assert re.search(r"^process_start_time_seconds [\d.e+]+$", text, re.MULTILINE)
    assert re.search(r'^autosecops_build_info\{version="[^"]+",', text, re.MULTILINE)


def test_license_expiry_is_absent_without_a_license(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        api_metrics,
        "get_license_state",
        lambda **_: LicenseState(status=LicenseStatus.MISSING),
    )
    text = build_api_metrics().registry.render()
    assert 'autosecops_license_status{status="missing"} 1\n' in text
    assert not _sample_lines(text, "autosecops_license_expiry_timestamp_seconds ")


@pytest.mark.parametrize(
    ("request_line", "status"),
    [
        (b"GET /metrics HTTP/1.1\r\n", b"200 OK"),
        (b"GET /metrics?x=1 HTTP/1.1\r\n", b"200 OK"),
        (b"GET /health HTTP/1.1\r\n", b"404 Not Found"),
        (b"GET /api/metrics HTTP/1.1\r\n", b"404 Not Found"),
        (b"POST /metrics HTTP/1.1\r\n", b"405 Method Not Allowed"),
        (b"garbage\r\n", b"400 Bad Request"),
    ],
)
def test_metrics_listener_routes(request_line: bytes, status: bytes) -> None:
    response = build_response(request_line, lambda: "m 1\n")
    assert response.startswith(b"HTTP/1.1 " + status + b"\r\n")
    assert response.endswith(b"m 1\n") == (status == b"200 OK")


def test_metrics_listener_head_has_no_body() -> None:
    response = build_response(b"HEAD /metrics HTTP/1.1\r\n", lambda: "m 1\n")
    assert response.endswith(b"\r\n\r\n")
    assert b"Content-Length: 4\r\n" in response


async def _http_get(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data


@pytest.mark.anyio
async def test_metrics_listener_serves_and_rejects_oversized_requests() -> None:
    server = MetricsServer(lambda: "up 1\n", host="127.0.0.1", port=0)
    await server.start()
    try:
        port = server.bound_port
        assert port is not None
        ok = await _http_get(port, b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        assert ok.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"text/plain; version=0.0.4" in ok
        assert ok.endswith(b"\r\n\r\nup 1\n")

        oversized = (
            b"GET /" + b"a" * (MAX_REQUEST_LINE_BYTES * 2) + b" HTTP/1.1\r\n\r\n"
        )
        assert await _http_get(port, oversized) == b""
    finally:
        await server.stop()


@pytest.mark.parametrize("enabled", [True, False])
def test_create_app_adds_middleware_only_when_enabled(
    monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__API_METRICS_ENABLED", enabled)
    app = create_app()
    classes = [middleware.cls for middleware in app.user_middleware]
    assert (PrometheusMiddleware in classes) is enabled
    if enabled:
        # Outermost, so its duration covers every other middleware.
        assert classes[0] is PrometheusMiddleware
