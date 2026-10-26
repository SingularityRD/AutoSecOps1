"""Public `robodr.fleet` endpoints, authenticated only by RoboDR keys.

Mounted like the ingest router: no user session, API key or cookie is read,
so the routes need no CSRF protection. Behind the stock Caddy front end they
are served below ``/api`` (Caddy strips the prefix); the request target a
robot signs includes it (contract §2.5), so the configured API root path is
put back before verification.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Request, status
from fastapi.responses import ORJSONResponse, Response

from autosecops import config
from autosecops.contexts import ctx_request_audit
from autosecops.middleware.request import build_request_audit_context
from autosecops.robot_edr import fleet
from autosecops.robot_edr.fleet import (
    AUTH_HEADERS,
    FleetAnswer,
    FleetRejectedError,
    FleetRequest,
)
from autosecops.robot_edr.fleet_wire import MAX_DRAFT_BYTES, MAX_ENVELOPE_BYTES
from autosecops.robot_edr.ingest_router import arrived_over_tls
from autosecops.robot_edr.schemas import FleetDraftReceipt, FleetErrorResponse
from autosecops.robot_edr.types import FleetErrorCode

router = APIRouter(prefix="/robot-edr/v2/fleet", tags=["public"])

_ERRORS: dict[int | str, dict[str, object]] = {
    code: {"model": FleetErrorResponse}
    for code in (400, 401, 403, 404, 409, 410, 413, 415, 503)
}
_ENVELOPE_BODY = {
    "requestBody": {
        "required": True,
        "content": {"application/json": {"schema": {"type": "object"}}},
    }
}
_HEADERS = ("content-type", *AUTH_HEADERS)

type _Handler = Callable[[FleetRequest], Awaitable[FleetAnswer]]


def _error(exc: FleetRejectedError) -> ORJSONResponse:
    return ORJSONResponse(
        status_code=exc.status,
        content={"code": exc.code.value, "detail": exc.detail},
    )


def _target(request: Request) -> str:
    """The origin-form target as the robot sent it, base path included."""
    raw = request.scope.get("raw_path")
    path = raw.decode("latin-1") if isinstance(raw, bytes) else request.url.path
    query = request.scope.get("query_string", b"")
    if query:
        path = f"{path}?{query.decode('latin-1')}"
    base = config.TRACECAT__API_ROOT_PATH.rstrip("/")
    if base and not path.startswith(f"{base}/"):
        path = f"{base}{path}"
    return path


async def _read_body(request: Request, limit: int) -> bytes:
    """Read the body, stopping one byte past ``limit``.

    One extra byte is enough for the handler to refuse the body with ``413``
    after its ``415`` check (contract §3.3 step 1 order).
    """
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            break
    return b"".join(chunks)[: limit + 1]


async def _serve(
    request: Request, handler: _Handler, *, body_limit: int = 0
) -> Response:
    # The app middleware normally sets this; 401 audit entries carry the
    # source address and must not depend on middleware order.
    audit_token = (
        ctx_request_audit.set(build_request_audit_context(request))
        if ctx_request_audit.get() is None
        else None
    )
    try:
        if config.TRACECAT__ROBOT_EDR_REQUIRE_TLS and not arrived_over_tls(request):
            raise FleetRejectedError(
                403, FleetErrorCode.TLS_REQUIRED, "TLS is required"
            )
        body = await _read_body(request, body_limit) if body_limit else b""
        fleet_request = FleetRequest(
            method=request.method,
            target=_target(request),
            headers={name: request.headers.getlist(name) for name in _HEADERS},
            body=body,
        )
        answer = await handler(fleet_request)
    except FleetRejectedError as exc:
        return _error(exc)
    finally:
        if audit_token is not None:
            ctx_request_audit.reset(audit_token)
    return Response(
        content=answer.body,
        status_code=status.HTTP_200_OK,
        media_type="application/json",
    )


@router.post("/enroll", responses=_ERRORS, openapi_extra=_ENVELOPE_BODY)
async def fleet_enroll(request: Request) -> Response:
    """Enroll a robot with a single-use token (`enroll-request` envelope)."""
    return await _serve(request, fleet.enroll, body_limit=MAX_ENVELOPE_BYTES)


@router.post("/keys/rotate", responses=_ERRORS, openapi_extra=_ENVELOPE_BODY)
async def fleet_rotate_key(request: Request) -> Response:
    """Register a robot's next key (overlap with the current one)."""
    return await _serve(request, fleet.rotate, body_limit=MAX_ENVELOPE_BYTES)


@router.post("/keys/retire", responses=_ERRORS, openapi_extra=_ENVELOPE_BODY)
async def fleet_retire_key(request: Request) -> Response:
    """Retire the old key of a rotation."""
    return await _serve(request, fleet.retire, body_limit=MAX_ENVELOPE_BYTES)


@router.post("/keys/cancel", responses=_ERRORS, openapi_extra=_ENVELOPE_BODY)
async def fleet_cancel_rotation(request: Request) -> Response:
    """Cancel a rotation the robot will not complete."""
    return await _serve(request, fleet.cancel, body_limit=MAX_ENVELOPE_BYTES)


@router.get("/revocations/{platform}", responses=_ERRORS)
async def fleet_get_revocations(request: Request, platform: str) -> Response:
    """The root-signed revocation list of a platform, verbatim."""

    async def handler(fleet_request: FleetRequest) -> FleetAnswer:
        return await fleet.get_revocation_list(fleet_request, platform)

    return await _serve(request, handler)


@router.post(
    "/profiles/drafts",
    responses={200: {"model": FleetDraftReceipt}, **_ERRORS},
    openapi_extra=_ENVELOPE_BODY,
)
async def fleet_publish_draft(request: Request) -> Response:
    """Queue a draft profile for review."""
    return await _serve(request, fleet.publish_draft, body_limit=MAX_DRAFT_BYTES)


@router.get("/profiles/current", responses=_ERRORS)
async def fleet_get_profile_offer(request: Request) -> Response:
    """The locked profile offered to the robot (unsigned wrapper)."""
    return await _serve(request, fleet.get_profile_offer)


@router.get("/profiles/approvals/{digest_hex}", responses=_ERRORS)
async def fleet_get_approval(request: Request, digest_hex: str) -> Response:
    """The approval-key-signed approval of a profile digest."""

    async def handler(fleet_request: FleetRequest) -> FleetAnswer:
        return await fleet.get_approval(fleet_request, digest_hex)

    return await _serve(request, handler)


@router.get("/ring", responses=_ERRORS)
async def fleet_get_ring(request: Request) -> Response:
    """The fleet-key-signed update-ring information."""
    return await _serve(request, fleet.get_ring)
