import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# The API docs pages (`/docs` and `/redoc`) load vendored assets from the API's
# own origin (see `autosecops.api.docs`), so no CDN host is allowed here.
_SCRIPT_SRC = "script-src 'self' 'unsafe-inline'"
_STYLE_SRC = "style-src 'self' 'unsafe-inline'"


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
