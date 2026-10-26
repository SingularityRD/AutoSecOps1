import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# Exact, pinned CDN assets for the API docs pages (`/docs` and `/redoc`).
# The docs routes in `autosecops.api.docs` load these same URLs, so the CSP and
# the rendered HTML cannot drift apart when FastAPI changes its defaults.
SWAGGER_UI_JS_URL = (
    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"
)
SWAGGER_UI_CSS_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css"
REDOC_JS_URL = "https://cdn.jsdelivr.net/npm/redoc@2.5.4/bundles/redoc.standalone.js"

_SCRIPT_SRC = f"script-src 'self' 'unsafe-inline' {SWAGGER_UI_JS_URL} {REDOC_JS_URL}"
_STYLE_SRC = f"style-src 'self' 'unsafe-inline' {SWAGGER_UI_CSS_URL}"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if os.getenv("POSTHOG_KEY"):
            csp_directives = [
                "connect-src 'self' https://*.posthog.com",
                "default-src 'self'",
                "worker-src 'self' blob:",
                "frame-ancestors 'none'",
                "img-src 'self' data:",
                "object-src 'none'",
                _SCRIPT_SRC,
                _STYLE_SRC,
            ]
        else:
            csp_directives = [
                "connect-src 'self'",
                "default-src 'self'",
                "worker-src 'self' blob:",
                "frame-ancestors 'none'",
                "img-src 'self' data:",
                "object-src 'none'",
                _SCRIPT_SRC,
                _STYLE_SRC,
            ]
        headers = {
            "Strict-Transport-Security": "max-age=7776000; includeSubDomains",
            "Content-Security-Policy": "; ".join(csp_directives),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "document-domain=()",
        }
        response.headers.update(headers)
        return response
