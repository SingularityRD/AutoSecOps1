"""Interactive API docs pages served by the AutoSecOps API.

FastAPI's built-in `/docs` and `/redoc` pages load floating CDN tags such as
`swagger-ui-dist@5`, which the API's Content-Security-Policy does not allow, so
the pages render blank. These routes mirror FastAPI's defaults but load the
exact asset versions that `SecurityHeadersMiddleware` allows.
"""

from fastapi import FastAPI, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import HTMLResponse

from autosecops.middleware.security import (
    REDOC_JS_URL,
    SWAGGER_UI_CSS_URL,
    SWAGGER_UI_JS_URL,
)

DOCS_URL = "/docs"
REDOC_URL = "/redoc"
SWAGGER_UI_OAUTH2_REDIRECT_URL = "/docs/oauth2-redirect"
# Served by the UI on the same origin, which the CSP `img-src 'self'` allows.
DOCS_FAVICON_URL = "/favicon.png"


def install_api_docs(app: FastAPI) -> None:
    """Register the Swagger UI and ReDoc pages with pinned asset URLs.

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
            swagger_js_url=SWAGGER_UI_JS_URL,
            swagger_css_url=SWAGGER_UI_CSS_URL,
            swagger_favicon_url=DOCS_FAVICON_URL,
            oauth2_redirect_url=root_path + SWAGGER_UI_OAUTH2_REDIRECT_URL,
            init_oauth=app.swagger_ui_init_oauth,
            swagger_ui_parameters=app.swagger_ui_parameters,
        )

    async def swagger_ui_redirect(_req: Request) -> HTMLResponse:
        return get_swagger_ui_oauth2_redirect_html()

    async def redoc_html(req: Request) -> HTMLResponse:
        root_path = req.scope.get("root_path", "").rstrip("/")
        return get_redoc_html(
            openapi_url=root_path + openapi_path,
            title=f"{app.title} - ReDoc",
            redoc_js_url=REDOC_JS_URL,
            redoc_favicon_url=DOCS_FAVICON_URL,
            # Google Fonts stylesheets are not allowed by the CSP.
            with_google_fonts=False,
        )

    app.add_route(DOCS_URL, swagger_ui_html, include_in_schema=False)
    app.add_route(
        SWAGGER_UI_OAUTH2_REDIRECT_URL, swagger_ui_redirect, include_in_schema=False
    )
    app.add_route(REDOC_URL, redoc_html, include_in_schema=False)
