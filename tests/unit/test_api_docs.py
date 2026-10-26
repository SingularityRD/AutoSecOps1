"""The API docs pages must only load assets the API's CSP allows."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from autosecops import config
from autosecops.api.app import create_app
from autosecops.middleware.security import SecurityHeadersMiddleware

_EXTERNAL_SCRIPT = re.compile(r'<script[^>]*\ssrc="(https?://[^"]+)"')
_EXTERNAL_STYLESHEET = re.compile(r'<link[^>]*\shref="(https?://[^"]+)"')


def _csp_sources(csp: str, directive: str) -> set[str]:
    for part in csp.split(";"):
        name, *sources = part.split()
        if name == directive:
            return set(sources)
    raise AssertionError(f"CSP has no {directive} directive: {csp}")


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    # Production installs the middleware when APP_ENV is not "development".
    app.add_middleware(SecurityHeadersMiddleware)
    return TestClient(app)


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
@pytest.mark.parametrize("posthog_key", [None, "phc_test"])
def test_docs_assets_are_allowed_by_csp(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    posthog_key: str | None,
) -> None:
    if posthog_key is None:
        monkeypatch.delenv("POSTHOG_KEY", raising=False)
    else:
        monkeypatch.setenv("POSTHOG_KEY", posthog_key)

    response = client.get(path)

    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    scripts = set(_EXTERNAL_SCRIPT.findall(response.text))
    stylesheets = set(_EXTERNAL_STYLESHEET.findall(response.text))
    assert scripts, "docs page should load its UI bundle"
    assert scripts <= _csp_sources(csp, "script-src")
    assert stylesheets <= _csp_sources(csp, "style-src")
    # Pinned versions only, never floating npm tags such as `@5`.
    for url in scripts | stylesheets:
        assert re.search(r"@\d+\.\d+\.\d+/", url), url


def test_docs_favicon_is_same_origin(client: TestClient) -> None:
    for path in ("/docs", "/redoc"):
        html = client.get(path).text
        assert "fastapi.tiangolo.com" not in html
        assert 'href="/favicon.png"' in html


def test_swagger_oauth2_redirect_is_served(client: TestClient) -> None:
    response = client.get("/docs/oauth2-redirect")

    assert response.status_code == 200
    assert "oauth2" in response.text.lower()


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_docs_load_openapi_from_root_path(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """Behind Caddy's `/api` prefix the page must fetch `<root>/openapi.json`."""
    monkeypatch.setattr(config, "AUTOSECOPS__API_ROOT_PATH", "/api")
    app = create_app()
    html = TestClient(app).get(path).text

    assert "/api/openapi.json" in html
