"""Interactive API docs pages served by the AutoSecOps API.

FastAPI's built-in `/docs` and `/redoc` pages load floating CDN tags such as
`swagger-ui-dist@5`. Those requests fail in air-gapped deployments and the
API's Content-Security-Policy does not allow them, so the pages render blank.
These routes mirror FastAPI's defaults but load exact asset versions vendored
under `autosecops/api/static/docs`, served from the API's own origin.

Each vendored directory keeps the upstream license files next to the assets.
To upgrade, download the npm tarball, copy the files listed in `DOCS_ASSETS`
verbatim, and update the version and SHA-256 below.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import FileResponse, HTMLResponse

DOCS_URL = "/docs"
REDOC_URL = "/redoc"
SWAGGER_UI_OAUTH2_REDIRECT_URL = "/docs/oauth2-redirect"
DOCS_ASSETS_URL = "/docs/assets"
# Served by the UI on the same origin, which the CSP `img-src 'self'` allows.
DOCS_FAVICON_URL = "/favicon.png"

STATIC_DOCS_DIR = Path(__file__).parent / "static" / "docs"

# The asset URLs carry the package version, so browsers may cache them forever.
_IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"


@dataclass(frozen=True, slots=True)
class DocsAsset:
    """A vendored file from an npm package, served at a versioned URL."""

    package: str
    version: str
    filename: str
    media_type: str
    sha256: str

    @property
    def path(self) -> Path:
        return STATIC_DOCS_DIR / self.package / self.filename

    @property
    def url(self) -> str:
        return f"{DOCS_ASSETS_URL}/{self.package}@{self.version}/{self.filename}"


SWAGGER_UI_JS = DocsAsset(
    package="swagger-ui-dist",
    version="5.9.0",
    filename="swagger-ui-bundle.js",
    media_type="text/javascript",
    sha256="2a556306524bed2ca668ec5ae19b1dbd4d9cdaa34795c9063a1c44b29a9c6097",
)
SWAGGER_UI_CSS = DocsAsset(
    package="swagger-ui-dist",
    version="5.9.0",
    filename="swagger-ui.css",
    media_type="text/css",
    sha256="c24ecffd63fc797d37bed1c68ea030479ad1c7a30638ffb6b5a2559ea98bc431",
)
REDOC_JS = DocsAsset(
    package="redoc",
    version="2.5.4",
    filename="redoc.standalone.js",
    media_type="text/javascript",
    sha256="dcaf76612bc4a3fbcc923a8966dee2f6146a5f32e5ce1b6f02dd60cbbf89500b",
)
DOCS_ASSETS: tuple[DocsAsset, ...] = (SWAGGER_UI_JS, SWAGGER_UI_CSS, REDOC_JS)


def _asset_endpoint(asset: DocsAsset) -> Callable[[Request], Awaitable[FileResponse]]:
    """Build a route handler that serves one vendored docs asset."""

    async def serve_asset(_req: Request) -> FileResponse:
        return FileResponse(
            asset.path,
            media_type=asset.media_type,
            headers={"Cache-Control": _IMMUTABLE_CACHE_CONTROL},
        )

    return serve_asset


def install_api_docs(app: FastAPI) -> None:
    """Register the Swagger UI and ReDoc pages and their vendored assets.

    The app must be created with `docs_url=None` and `redoc_url=None` so
    FastAPI does not register its own pages on the same paths.

    Args:
        app: The FastAPI application to add the docs routes to.
    """
    openapi_path = app.openapi_url
    if not openapi_path:
        return

    async def swagger_ui_html(req: Request) -> HTMLResponse:
        root_path = req.scope.get("root_path", "").rstrip("/")
        return get_swagger_ui_html(
            openapi_url=root_path + openapi_path,
            title=f"{app.title} - Swagger UI",
            swagger_js_url=root_path + SWAGGER_UI_JS.url,
            swagger_css_url=root_path + SWAGGER_UI_CSS.url,
            swagger_favicon_url=DOCS_FAVICON_URL,
            oauth2_redirect_url=root_path + SWAGGER_UI_OAUTH2_REDIRECT_URL,
            init_oauth=app.swagger_ui_init_oauth,
            # Swagger UI otherwise sends the spec URL to validator.swagger.io.
            swagger_ui_parameters={
                "validatorUrl": None,
                **(app.swagger_ui_parameters or {}),
            },
        )

    async def swagger_ui_redirect(_req: Request) -> HTMLResponse:
        return get_swagger_ui_oauth2_redirect_html()

    async def redoc_html(req: Request) -> HTMLResponse:
        root_path = req.scope.get("root_path", "").rstrip("/")
        return get_redoc_html(
            openapi_url=root_path + openapi_path,
            title=f"{app.title} - ReDoc",
            redoc_js_url=root_path + REDOC_JS.url,
            redoc_favicon_url=DOCS_FAVICON_URL,
            # Google Fonts stylesheets are not allowed by the CSP.
            with_google_fonts=False,
        )

    app.add_route(DOCS_URL, swagger_ui_html, include_in_schema=False)
    app.add_route(
        SWAGGER_UI_OAUTH2_REDIRECT_URL, swagger_ui_redirect, include_in_schema=False
    )
    app.add_route(REDOC_URL, redoc_html, include_in_schema=False)
    for asset in DOCS_ASSETS:
        app.add_route(asset.url, _asset_endpoint(asset), include_in_schema=False)
