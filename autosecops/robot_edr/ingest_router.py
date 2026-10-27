"""Public RoboDR ingest endpoint, authenticated only by the batch signature.

Mounted like the webhook router: no user session, no API key and no cookie
are read, so the route needs no CSRF protection. Behind the stock Caddy front
end it is served at ``/api/robot-edr/v2/ingest`` (Caddy strips ``/api``).
"""

from __future__ import annotations

from ipaddress import ip_address

from fastapi import APIRouter, Request, status
from fastapi.responses import ORJSONResponse

from autosecops import config
from autosecops.contexts import ctx_request_audit
from autosecops.middleware.request import (
    build_request_audit_context,
    resolve_client_ip,
)
from autosecops.robot_edr.ingest import (
    BATCH_ID_HEADER,
    KEY_ID_HEADER,
    MAX_BODY_BYTES,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    IngestRejectedError,
    IngestRequest,
    ingest,
)
from autosecops.robot_edr.schemas import IngestErrorResponse, IngestResponse
from autosecops.robot_edr.types import IngestErrorCode

NDJSON_MEDIA_TYPE = "application/x-ndjson"

router = APIRouter(prefix="/robot-edr/v2", tags=["public"])

_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    code: {"model": IngestErrorResponse} for code in (400, 401, 403, 409, 413, 415, 429)
}


def _is_loopback(value: str | None) -> bool:
    if value is None:
        return False
    try:
        return ip_address(value).is_loopback
    except ValueError:
        return False


def _is_trusted_proxy(value: str | None) -> bool:
    if value is None:
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return any(address in net for net in config.AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS)


def arrived_over_tls(request: Request) -> bool:
    """Whether the request used TLS, or is plain HTTP from loopback.

    A ``X-Forwarded-Proto`` header is honoured only from a trusted proxy.
    """
    if request.url.scheme == "https":
        return True
    peer = request.client.host if request.client is not None else None
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto is not None and _is_trusted_proxy(peer):
        if forwarded_proto.split(",")[0].strip().lower() == "https":
            return True
        return _is_loopback(resolve_client_ip(request))
    return _is_loopback(peer)


def _is_ndjson(values: list[str]) -> bool:
    """One Content-Type: the NDJSON media type, case-insensitive, no parameters."""
    return len(values) == 1 and values[0].strip().lower() == NDJSON_MEDIA_TYPE


def _error(exc: IngestRejectedError) -> ORJSONResponse:
    headers = (
        {"Retry-After": str(exc.retry_after)} if exc.retry_after is not None else None
    )
    return ORJSONResponse(
        status_code=exc.status,
        content={"code": exc.code.value, "detail": exc.detail},
        headers=headers,
    )


async def _read_body(request: Request) -> bytes:
    """Read the body, refusing it as soon as it exceeds the 4 MiB cap."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _too_large()
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise _too_large()
        chunks.append(chunk)
    return b"".join(chunks)


def _too_large() -> IngestRejectedError:
    return IngestRejectedError(
        413,
        IngestErrorCode.BODY_TOO_LARGE,
        f"request body exceeds {MAX_BODY_BYTES} bytes",
    )


@router.post(
    "/ingest",
    status_code=status.HTTP_200_OK,
    response_model=IngestResponse,
    responses=_ERROR_RESPONSES,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {NDJSON_MEDIA_TYPE: {"schema": {"type": "string"}}},
        }
    },
)
async def ingest_robodr_findings(request: Request) -> ORJSONResponse:
    """Ingest a signed NDJSON batch of `robodr.findings` 2.x values.

    Authentication is the Ed25519 batch signature in the `X-RoboDR-*` headers
    (ingest contract §2.2); the sender key determines the workspace.
    """
    # The app's request middleware normally sets this; the ingest audit trail
    # (401s carry the source address) must not depend on middleware order.
    audit_token = (
        ctx_request_audit.set(build_request_audit_context(request))
        if ctx_request_audit.get() is None
        else None
    )
    try:
        if not _is_ndjson(request.headers.getlist("content-type")):
            raise IngestRejectedError(
                415,
                IngestErrorCode.UNSUPPORTED_MEDIA_TYPE,
                f"Content-Type must be the media type {NDJSON_MEDIA_TYPE} "
                "without parameters",
            )
        if config.AUTOSECOPS__ROBOT_EDR_REQUIRE_TLS and not arrived_over_tls(request):
            raise IngestRejectedError(
                403, IngestErrorCode.TLS_REQUIRED, "TLS is required"
            )
        body = await _read_body(request)
        headers = {
            name: request.headers.getlist(name)
            for name in (
                KEY_ID_HEADER,
                BATCH_ID_HEADER,
                TIMESTAMP_HEADER,
                SIGNATURE_HEADER,
            )
        }
        response = await ingest(IngestRequest(headers=headers, body=body))
    except IngestRejectedError as exc:
        return _error(exc)
    finally:
        if audit_token is not None:
            ctx_request_audit.reset(audit_token)
    return ORJSONResponse(status_code=status.HTTP_200_OK, content=response)
