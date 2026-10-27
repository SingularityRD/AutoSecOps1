"""The API docs pages must load vendored, same-origin assets the CSP allows."""

from __future__ import annotations

import hashlib
import re

import pytest
from fastapi.testclient import TestClient

from autosecops import config
from autosecops.api.app import create_app
from autosecops.api.docs import DOCS_ASSETS, DocsAsset
from autosecops.middleware.security import SecurityHeadersMiddleware

_SCRIPT = re.compile(r'<script[^>]*\ssrc="([^"]+)"')
_STYLESHEET = re.compile(r'<link[^>]*\srel="stylesheet"[^>]*\shref="([^"]+)"')
_ANY_EXTERNAL_URL = re.compile(r'(?:src|href)="(?:https?:)?//')


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
def test_docs_assets_are_same_origin_and_allowed_by_csp(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    posthog_key: str | None,
) -> None:
    """Air-gapped deployments have no CDN, so the pages load nothing remote."""
    if posthog_key is None:
        monkeypatch.delenv("POSTHOG_KEY", raising=False)
    else:
        monkeypatch.setenv("POSTHOG_KEY", posthog_key)

    response = client.get(path)

    assert response.status_code == 200
    assert not _ANY_EXTERNAL_URL.search(response.text)
    csp = response.headers["Content-Security-Policy"]
    for directive in ("script-src", "style-src"):
        sources = _csp_sources(csp, directive)
        assert "'self'" in sources
        assert not any("://" in source for source in sources), sources
    scripts = set(_SCRIPT.findall(response.text))
    stylesheets = set(_STYLESHEET.findall(response.text))
    assert scripts, "docs page should load its UI bundle"
    # Pinned versions only, never floating npm tags such as `@5`.
    asset_urls = {asset.url for asset in DOCS_ASSETS}
    for url in scripts | stylesheets:
        assert url.startswith(config.AUTOSECOPS__API_ROOT_PATH.rstrip("/") + "/"), url
        app_url = url.removeprefix(config.AUTOSECOPS__API_ROOT_PATH.rstrip("/"))
        assert app_url in asset_urls, url
        assert re.search(r"@\d+\.\d+\.\d+/", url), url
        asset = client.get(app_url)
        assert asset.status_code == 200, url
        assert "immutable" in asset.headers["Cache-Control"]


def test_swagger_ui_does_not_call_the_public_validator(client: TestClient) -> None:
    html = client.get("/docs").text

    assert "validator.swagger.io" not in html
    assert '"validatorUrl": null' in html


@pytest.mark.parametrize("asset", DOCS_ASSETS, ids=lambda asset: asset.filename)
def test_vendored_docs_assets_match_pinned_hash(asset: DocsAsset) -> None:
    digest = hashlib.sha256(asset.path.read_bytes()).hexdigest()

    assert digest == asset.sha256


@pytest.mark.parametrize("asset", DOCS_ASSETS, ids=lambda asset: asset.filename)
def test_vendored_docs_assets_keep_license(asset: DocsAsset) -> None:
    assert (asset.path.parent / "LICENSE").is_file()


@pytest.mark.parametrize("asset", DOCS_ASSETS, ids=lambda asset: asset.filename)
def test_vendored_docs_assets_are_served_with_media_type(
    client: TestClient, asset: DocsAsset
) -> None:
    response = client.get(asset.url)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(asset.media_type)
    assert response.content == asset.path.read_bytes()


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
