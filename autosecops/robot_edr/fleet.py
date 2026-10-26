"""SOC side of the `robodr.fleet` API v1 (robot-facing endpoints).

Implements contract ``robodr.fleet-api.md`` §2.5-§7 exactly: enrollment
with a single-use token (§3.3), key rotation, retirement and cancellation
(§5), and distribution of revocation lists, draft profiles, profile offers,
approvals and update-ring information (§4.1, §6, §7). Every check runs in
the contract's order; the first failure decides the answer.

Robots carry no user identity: an enrollment request is authenticated by the
token MAC and the signatures of its three new keys, every other request by
an active ``uplink`` key (§2.5). Requests therefore run on a session that
bypasses tenant RLS and act only on the workspace the token or key belongs
to. Every action, and every ``401``, is written to the audit log.
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.service import AuditService
from autosecops.audit.types import AuditAction, AuditMetadataValue
from autosecops.auth.types import Role
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import (
    Robot,
    RobotFleetApproval,
    RobotFleetProfileDraft,
    RobotFleetProfileOffer,
    RobotFleetRevocationList,
    RobotFleetRing,
    RobotFleetRotation,
    RobotFleetSocKey,
    RobotFleetToken,
    RobotKey,
    Workspace,
)
from autosecops.logger import logger
from autosecops.robot_edr import fleet_replay
from autosecops.robot_edr import fleet_wire as wire
from autosecops.robot_edr.fleet_keys import active_signing_key, decrypt_secret
from autosecops.robot_edr.fleet_profiles import ProfileFileError, check_draft_profile
from autosecops.robot_edr.types import (
    FleetErrorCode,
    FleetFailureReason,
    FleetRobot,
    FleetRotationStatus,
    FleetSocKeyKind,
    RobotKeyRole,
)
from autosecops.tiers.access import is_org_entitled
from autosecops.tiers.enums import Entitlement

KEY_ID_HEADER: Final = "x-robodr-key-id"
TIMESTAMP_HEADER: Final = "x-robodr-timestamp"
SIGNATURE_HEADER: Final = "x-robodr-signature"
AUTH_HEADERS: Final = (KEY_ID_HEADER, TIMESTAMP_HEADER, SIGNATURE_HEADER)
JSON_MEDIA_TYPE: Final = "application/json"
_TIMESTAMP_RE: Final = re.compile(r"0|[1-9][0-9]{0,19}")
_DIGEST_HEX_RE: Final = re.compile(r"[0-9a-f]{64}")
_FLEET_SCOPES: Final = frozenset({"robot:read", "robot:update"})
_KEY_REGISTRATION_LOCK: Final = "robot_edr_fleet_key_registration"
_UNKNOWN_ACTOR_NAMESPACE: Final = uuid.UUID("4c7d5a0e-2f2b-4b1e-9a51-0b6f3f3e8d21")


def now_ms() -> int:
    """Server clock in Unix milliseconds (a seam for contract test vectors)."""
    return int(time.time() * 1000)


class FleetRejectedError(Exception):
    """The request is refused with ``status`` and a contract error code."""

    def __init__(self, status: int, code: FleetErrorCode, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class FleetRequest:
    """One HTTP request, as the router hands it over."""

    method: str
    target: str
    """The origin-form target as sent, base path included (§2.5)."""
    headers: Mapping[str, Sequence[str]]
    """Lower-case header names to every value received."""
    body: bytes


@dataclass(frozen=True, slots=True)
class FleetAnswer:
    """A ``200`` body."""

    body: bytes


def _reject(status: int, code: FleetErrorCode, detail: str) -> FleetRejectedError:
    return FleetRejectedError(status, code, detail)


def _bad_request(detail: str) -> FleetRejectedError:
    return _reject(400, FleetErrorCode.BAD_REQUEST, detail)


def _ms_to_datetime(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


def fleet_role(workspace_id: uuid.UUID, organization_id: uuid.UUID) -> Role:
    """The role fleet processing acts under in a robot's workspace."""
    return Role(
        type="service",
        service_id="tracecat-api",
        workspace_id=workspace_id,
        organization_id=organization_id,
        scopes=_FLEET_SCOPES,
    )


def check_json_body(request: FleetRequest, max_bytes: int) -> None:
    """``415`` unless exactly one ``application/json`` Content-Type; ``413`` if too large."""
    values = request.headers.get("content-type", ())
    if len(values) != 1 or values[0].strip().lower() != JSON_MEDIA_TYPE:
        raise _reject(
            415,
            FleetErrorCode.UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json without parameters",
        )
    if len(request.body) > max_bytes:
        raise _reject(413, FleetErrorCode.TOO_LARGE, f"body exceeds {max_bytes} bytes")


# --- audit ------------------------------------------------------------------------


async def _audit(
    *,
    actor_id: uuid.UUID,
    workspace_id: uuid.UUID | None,
    organization_id: uuid.UUID | None,
    action: AuditAction,
    status: AuditEventStatus,
    data: Mapping[str, AuditMetadataValue],
) -> None:
    """Best-effort audit event whose actor is a robot key (or a derived id)."""
    role = (
        fleet_role(workspace_id, organization_id)
        if workspace_id is not None and organization_id is not None
        else None
    )
    try:
        async with get_async_session_bypass_rls_context_manager() as session:
            audit = AuditService(
                session,
                role=role,
                audit_sink="organization" if role is not None else "platform",
            )
            await audit.create_robot_event(
                actor_id=actor_id,
                resource_type="robot_fleet",
                action=action,
                status=status,
                data=data,
            )
    except Exception as exc:  # Audit delivery is best-effort; the answer stands.
        logger.warning(
            "Robot EDR fleet audit event failed", error_type=type(exc).__name__
        )


def _unknown_actor(presented: str) -> uuid.UUID:
    return uuid.uuid5(_UNKNOWN_ACTOR_NAMESPACE, presented)


async def _audit_auth_failure(
    *,
    presented_key_id: str,
    reason: FleetFailureReason,
    operation: str,
    robot: FleetRobot | None = None,
) -> None:
    """Log and audit a ``401`` (key id, source address, reason; no body)."""
    logger.warning(
        "Robot EDR fleet authentication failed",
        presented_key_id=presented_key_id,
        reason=reason.value,
        operation=operation,
    )
    await _audit(
        actor_id=robot.key_fk if robot else _unknown_actor(presented_key_id),
        workspace_id=robot.workspace_id if robot else None,
        organization_id=robot.organization_id if robot else None,
        action="read" if operation.startswith("get_") else "update",
        status=AuditEventStatus.FAILURE,
        data={
            "presented_key_id": presented_key_id,
            "failure_reason": reason.value,
            "operation": operation,
        },
    )


async def _audit_success(
    robot: FleetRobot, action: AuditAction, operation: str, **ids: str | None
) -> None:
    await _audit(
        actor_id=robot.key_fk,
        workspace_id=robot.workspace_id,
        organization_id=robot.organization_id,
        action=action,
        status=AuditEventStatus.SUCCESS,
        data={"operation": operation, "robot_id": robot.robot_id, **ids},
    )


# --- request authentication (§2.5) ------------------------------------------------


def _one_header(request: FleetRequest, name: str) -> str:
    values = request.headers.get(name, ())
    if len(values) != 1:
        raise _reject(400, FleetErrorCode.BAD_HEADER, f"{name} missing or repeated")
    return values[0]


async def _lookup_uplink(
    session: AsyncSession, key_id: str
) -> tuple[FleetRobot, bytes] | None:
    now = datetime.now(UTC)
    row = (
        await session.execute(
            select(
                RobotKey.id,
                RobotKey.public_key,
                Robot.id,
                Robot.robot_id,
                Robot.fleet_workspace,
                Robot.workspace_id,
                Workspace.organization_id,
            )
            .join(Robot, Robot.id == RobotKey.robot_fk)
            .join(Workspace, Workspace.id == RobotKey.workspace_id)
            .where(
                RobotKey.key_id == key_id,
                RobotKey.role == RobotKeyRole.UPLINK.value,
                RobotKey.revoked_at.is_(None),
                or_(RobotKey.expires_at.is_(None), RobotKey.expires_at > now),
            )
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    key_fk, public_key, robot_fk, robot_id, label, workspace_id, org_id = row
    robot = FleetRobot(
        robot_fk=robot_fk,
        robot_id=robot_id,
        workspace_id=workspace_id,
        organization_id=org_id,
        fleet_workspace=label or str(workspace_id),
        key_fk=key_fk,
        key_id=key_id,
    )
    return robot, public_key


async def authenticate(
    session: AsyncSession, request: FleetRequest, operation: str
) -> FleetRobot:
    """Authenticate a fleet request by its uplink key (§2.5).

    Raises:
        FleetRejectedError: ``400 bad_header``, or ``401`` ``unknown_key``,
            ``stale_timestamp``, ``bad_signature`` or ``replayed_request``
            (every ``401`` is audited first).
    """
    key_id = _one_header(request, KEY_ID_HEADER)
    timestamp = _one_header(request, TIMESTAMP_HEADER)
    signature = _one_header(request, SIGNATURE_HEADER)
    if not wire.is_key_id(key_id):
        raise _reject(400, FleetErrorCode.BAD_HEADER, "X-RoboDR-Key-Id")
    if _TIMESTAMP_RE.fullmatch(timestamp) is None or int(timestamp) > wire.MAX_U64:
        raise _reject(400, FleetErrorCode.BAD_HEADER, "X-RoboDR-Timestamp")
    if not wire.is_lower_hex(signature, 128):
        raise _reject(400, FleetErrorCode.BAD_HEADER, "X-RoboDR-Signature")
    found = await _lookup_uplink(session, key_id)
    if found is None:
        await _audit_auth_failure(
            presented_key_id=key_id,
            reason=FleetFailureReason.UNKNOWN_KEY,
            operation=operation,
        )
        raise _reject(401, FleetErrorCode.UNKNOWN_KEY, "not an active uplink key")
    robot, public_key = found
    if abs(now_ms() - int(timestamp)) > wire.MAX_SKEW_MS:
        await _audit_auth_failure(
            presented_key_id=key_id,
            reason=FleetFailureReason.STALE_TIMESTAMP,
            operation=operation,
            robot=robot,
        )
        raise _reject(
            401,
            FleetErrorCode.STALE_TIMESTAMP,
            "X-RoboDR-Timestamp is more than 300 s from the server clock",
        )
    message = wire.request_message(
        request.method, request.target, key_id, int(timestamp), request.body
    )
    if not wire.verify_hex(public_key, message, signature):
        await _audit_auth_failure(
            presented_key_id=key_id,
            reason=FleetFailureReason.BAD_SIGNATURE,
            operation=operation,
            robot=robot,
        )
        raise _reject(401, FleetErrorCode.BAD_SIGNATURE, "request signature")
    if await fleet_replay.seen_before(key_id, signature):
        await _audit_auth_failure(
            presented_key_id=key_id,
            reason=FleetFailureReason.REPLAYED_REQUEST,
            operation=operation,
            robot=robot,
        )
        raise _reject(
            401,
            FleetErrorCode.REPLAYED_REQUEST,
            "these request headers were used already",
        )
    return robot


async def _require_entitled(session: AsyncSession, organization_id: uuid.UUID) -> None:
    if not await is_org_entitled(session, organization_id, Entitlement.ROBOT_EDR):
        raise _reject(
            403,
            FleetErrorCode.NOT_ENTITLED,
            "Robot EDR is not enabled for this workspace",
        )


async def _fleet_key(session: AsyncSession, workspace_id: uuid.UUID) -> wire.SigningKey:
    key = await active_signing_key(session, workspace_id, FleetSocKeyKind.FLEET)
    if key is None:
        raise _reject(
            503,
            FleetErrorCode.NO_FLEET_KEY,
            "the workspace has no active SOC fleet key",
        )
    return key


async def _key_conflict(
    session: AsyncSession, key_ids: Sequence[str], public_keys: Sequence[bytes]
) -> bool:
    """Whether a key id or public key (fingerprint) is registered anywhere (§4).

    Takes a transaction-scoped advisory lock first, so concurrent enrollments
    and rotations cannot register the same key twice.
    """
    await session.execute(
        select(func.pg_advisory_xact_lock(func.hashtext(_KEY_REGISTRATION_LOCK)))
    )
    robot_hit = await session.scalar(
        select(RobotKey.id)
        .where(or_(RobotKey.key_id.in_(key_ids), RobotKey.public_key.in_(public_keys)))
        .limit(1)
    )
    if robot_hit is not None:
        return True
    soc_hit = await session.scalar(
        select(RobotFleetSocKey.id)
        .where(
            or_(
                RobotFleetSocKey.key_id.in_(key_ids),
                RobotFleetSocKey.public_key.in_(public_keys),
            )
        )
        .limit(1)
    )
    return soc_hit is not None


# --- enrollment (§3.3) ------------------------------------------------------------


async def enroll(request: FleetRequest) -> FleetAnswer:
    """Process an enrollment request (contract §3.3, first failure decides).

    Raises:
        FleetRejectedError: The contract's refusal.
    """
    check_json_body(request, wire.MAX_ENVELOPE_BYTES)
    try:
        opened = wire.parse_envelope(request.body, wire.T_ENROLL_REQUEST)
        enroll_request = wire.parse_enroll_request(opened.payload)
    except wire.WireError as exc:
        raise _bad_request(str(exc)) from exc
    if opened.mac is None or opened.mac.token_id != enroll_request.token_id:
        raise _bad_request("mac.token_id differs from the request's token_id")
    async with get_async_session_bypass_rls_context_manager() as session:
        answer, robot = await _enroll(session, opened, enroll_request)
    if robot is not None:
        await _audit_success(
            robot,
            "enroll",
            "enroll",
            token_id=enroll_request.token_id,
            request_id=enroll_request.request_id,
        )
    return FleetAnswer(body=answer)


async def _token_failure(token_id: str, reason: FleetFailureReason) -> None:
    await _audit_auth_failure(
        presented_key_id=token_id, reason=reason, operation="enroll"
    )


async def _enroll(
    session: AsyncSession, opened: wire.Opened, request: wire.EnrollRequest
) -> tuple[bytes, FleetRobot | None]:
    token = await session.scalar(
        select(RobotFleetToken)
        .where(RobotFleetToken.token_id == request.token_id)
        .with_for_update()
    )
    if token is None or token.revoked_at is not None:
        await _token_failure(request.token_id, FleetFailureReason.BAD_TOKEN)
        raise _reject(401, FleetErrorCode.BAD_TOKEN, "unknown token")
    if not opened.verify_mac(decrypt_secret(token.encrypted_nonce)):
        await _token_failure(request.token_id, FleetFailureReason.BAD_TOKEN)
        raise _reject(401, FleetErrorCode.BAD_TOKEN, "token mac")
    key_ids = [k.key_id for k in request.keys]
    if opened.signers != key_ids or not all(
        opened.verify_by(k.key_id, k.public_key) for k in request.keys
    ):
        await _token_failure(request.token_id, FleetFailureReason.BAD_SIGNATURE)
        raise _reject(
            401,
            FleetErrorCode.BAD_SIGNATURE,
            "must be signed by the request's uplink, finding and blackbox keys, in that order",
        )
    request_digest = opened.payload_digest
    if token.consumed_at is not None:
        if token.request_digest == request_digest and token.answer is not None:
            return token.answer, None
        raise _reject(409, FleetErrorCode.TOKEN_USED, "token already consumed")
    server_now = now_ms()
    if server_now > token.expires_at_ms:
        raise _reject(410, FleetErrorCode.TOKEN_EXPIRED, "token expired")
    if request.workspace != token.fleet_workspace:
        raise _reject(
            403,
            FleetErrorCode.WORKSPACE_MISMATCH,
            "request names another workspace than its token",
        )
    if request.robot_id != token.robot_id or request.site != token.site:
        raise _reject(
            403,
            FleetErrorCode.ROBOT_MISMATCH,
            "request names another robot or site than its token",
        )
    organization_id = await session.scalar(
        select(Workspace.organization_id).where(Workspace.id == token.workspace_id)
    )
    if organization_id is None:
        raise _reject(401, FleetErrorCode.BAD_TOKEN, "unknown token")
    await _require_entitled(session, organization_id)
    fleet_key = await _fleet_key(session, token.workspace_id)
    if await _key_conflict(session, key_ids, [k.public_key for k in request.keys]):
        raise _reject(409, FleetErrorCode.KEY_CONFLICT, "a key is already registered")

    robot = await _register_enrollment(session, token, request, server_now)
    payload = wire.enroll_answer_payload(
        request, request_digest=request_digest, enrolled_at_ms=server_now
    )
    answer = wire.sign_envelope(wire.T_ENROLL_ANSWER, payload, [fleet_key])
    token.consumed_at = _ms_to_datetime(server_now)
    token.request_digest = request_digest
    token.answer = answer
    token.robot_fk = robot.id
    await session.commit()
    uplink = next(k for k in request.keys if k.role == RobotKeyRole.UPLINK.value)
    uplink_fk = await session.scalar(
        select(RobotKey.id).where(
            RobotKey.workspace_id == token.workspace_id,
            RobotKey.key_id == uplink.key_id,
        )
    )
    return answer, FleetRobot(
        robot_fk=robot.id,
        robot_id=robot.robot_id,
        workspace_id=token.workspace_id,
        organization_id=organization_id,
        fleet_workspace=token.fleet_workspace,
        key_fk=uplink_fk or _unknown_actor(uplink.key_id),
        key_id=uplink.key_id,
    )


async def _register_enrollment(
    session: AsyncSession,
    token: RobotFleetToken,
    request: wire.EnrollRequest,
    server_now: int,
) -> Robot:
    """§3.3 step 9: replace the robot's keys and record its enrollment."""
    enrolled_at = _ms_to_datetime(server_now)
    robot = await session.scalar(
        select(Robot)
        .where(
            Robot.workspace_id == token.workspace_id,
            Robot.robot_id == request.robot_id,
        )
        .with_for_update()
    )
    if robot is None:
        robot = Robot(workspace_id=token.workspace_id, robot_id=request.robot_id)
        session.add(robot)
    robot.site = request.site
    robot.fleet_workspace = request.workspace
    robot.fleet_enrolled_at = enrolled_at
    robot.fleet_agentd_version = request.agentd_version
    robot.fleet_profile_digest = request.profile_digest
    await session.flush()
    # A re-enrollment replaces every key the robot had, and ends its open
    # rotations (their keys are gone): a later resend is refused as cancelled.
    await session.execute(
        update(RobotKey)
        .where(RobotKey.robot_fk == robot.id, RobotKey.revoked_at.is_(None))
        .values(revoked_at=enrolled_at)
    )
    await session.execute(
        update(RobotFleetRotation)
        .where(
            RobotFleetRotation.robot_fk == robot.id,
            RobotFleetRotation.status == FleetRotationStatus.OPEN.value,
        )
        .values(status=FleetRotationStatus.CANCELLED.value, closed_at=enrolled_at)
    )
    for key in request.keys:
        session.add(
            RobotKey(
                workspace_id=token.workspace_id,
                key_id=key.key_id,
                role=key.role,
                robot_fk=robot.id,
                public_key=key.public_key,
                created_by=token.created_by,
            )
        )
    await session.flush()
    return robot


# --- authenticated endpoints ------------------------------------------------------


async def _authenticated(
    session: AsyncSession, request: FleetRequest, operation: str
) -> FleetRobot:
    robot = await authenticate(session, request, operation)
    await _require_entitled(session, robot.organization_id)
    return robot


async def rotate(request: FleetRequest) -> FleetAnswer:
    """``POST …/keys/rotate`` (contract §5.1).

    Raises:
        FleetRejectedError: The contract's refusal.
    """
    check_json_body(request, wire.MAX_ENVELOPE_BYTES)
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "rotate")
        answer, rotation_id = await _rotate(session, robot, request.body)
    await _audit_success(robot, "rotate", "rotate", rotation_id=rotation_id)
    return FleetAnswer(body=answer)


async def _wrong_key(
    robot: FleetRobot, operation: str, detail: str
) -> FleetRejectedError:
    await _audit_auth_failure(
        presented_key_id=robot.key_id,
        reason=FleetFailureReason.WRONG_KEY,
        operation=operation,
        robot=robot,
    )
    return _reject(401, FleetErrorCode.WRONG_KEY, detail)


async def _rotation(
    session: AsyncSession, rotation_id: str
) -> RobotFleetRotation | None:
    return await session.scalar(
        select(RobotFleetRotation)
        .where(RobotFleetRotation.rotation_id == rotation_id)
        .with_for_update()
    )


async def _robot_key(
    session: AsyncSession, robot: FleetRobot, key_id: str, role: str
) -> RobotKey | None:
    return await session.scalar(
        select(RobotKey).where(
            RobotKey.robot_fk == robot.robot_fk,
            RobotKey.key_id == key_id,
            RobotKey.role == role,
        )
    )


async def _rotate(
    session: AsyncSession, robot: FleetRobot, body: bytes
) -> tuple[bytes, str]:
    try:
        opened = wire.parse_envelope(body, wire.T_ROTATE_REQUEST)
        req = wire.parse_rotate_request(opened.payload)
    except wire.WireError as exc:
        raise _bad_request(str(exc)) from exc
    if req.workspace != robot.fleet_workspace or req.robot_id != robot.robot_id:
        raise _reject(
            403,
            FleetErrorCode.ROBOT_MISMATCH,
            "rotation for another robot or workspace",
        )
    if req.role == RobotKeyRole.UPLINK.value and robot.key_id != req.old_key_id:
        raise await _wrong_key(
            robot, "rotate", "an uplink rotation is authenticated by its old uplink key"
        )
    request_digest = opened.payload_digest
    if (known := await _rotation(session, req.rotation_id)) is not None:
        if known.status == FleetRotationStatus.CANCELLED.value:
            raise _reject(
                409, FleetErrorCode.ROTATION_CANCELLED, "this rotation was cancelled"
            )
        if known.request_digest == request_digest and known.rotate_answer is not None:
            return known.rotate_answer, req.rotation_id
        raise _reject(
            409,
            FleetErrorCode.ROTATION_ID_REUSE,
            "rotation id known with another request",
        )
    old = await _robot_key(session, robot, req.old_key_id, req.role)
    if (
        old is None
        or old.revoked_at is not None
        or wire.fingerprint(old.public_key) != req.old_fingerprint
    ):
        raise _reject(
            409,
            FleetErrorCode.STALE_KEY,
            "old key is not this robot's active key of that role",
        )
    if (
        opened.signers != [req.old_key_id, req.new_key_id]
        or not opened.verify_by(req.old_key_id, old.public_key)
        or not opened.verify_by(req.new_key_id, req.new_public_key)
    ):
        raise _reject(
            401,
            FleetErrorCode.BAD_SIGNATURE,
            "must be signed by the old key, then the new key",
        )
    open_rotation = await session.scalar(
        select(RobotFleetRotation.id).where(
            RobotFleetRotation.robot_fk == robot.robot_fk,
            RobotFleetRotation.role == req.role,
            RobotFleetRotation.status == FleetRotationStatus.OPEN.value,
        )
    )
    if open_rotation is not None:
        raise _rotation_in_progress()
    fleet_key = await _fleet_key(session, robot.workspace_id)
    if await _key_conflict(session, [req.new_key_id], [req.new_public_key]):
        raise _reject(
            409, FleetErrorCode.KEY_CONFLICT, "the new key is already registered"
        )
    server_now = now_ms()
    payload = wire.key_answer_payload(
        answer_format=wire.ROTATE_ANSWER_FORMAT,
        rotation_id=req.rotation_id,
        request_digest=request_digest,
        workspace=req.workspace,
        robot_id=robot.robot_id,
        role=req.role,
        old_key_id=req.old_key_id,
        new_key_id=req.new_key_id,
        status="overlap",
        at_ms=server_now,
    )
    answer = wire.sign_envelope(wire.T_ROTATE_ANSWER, payload, [fleet_key])
    session.add(
        RobotKey(
            workspace_id=robot.workspace_id,
            key_id=req.new_key_id,
            role=req.role,
            robot_fk=robot.robot_fk,
            public_key=req.new_public_key,
        )
    )
    session.add(
        RobotFleetRotation(
            workspace_id=robot.workspace_id,
            rotation_id=req.rotation_id,
            robot_fk=robot.robot_fk,
            role=req.role,
            old_key_id=req.old_key_id,
            new_key_id=req.new_key_id,
            status=FleetRotationStatus.OPEN.value,
            request_digest=request_digest,
            rotate_answer=answer,
        )
    )
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise _rotation_in_progress() from exc
    return answer, req.rotation_id


def _rotation_in_progress() -> FleetRejectedError:
    return _reject(
        409,
        FleetErrorCode.ROTATION_IN_PROGRESS,
        "another rotation of this role is open",
    )


async def retire(request: FleetRequest) -> FleetAnswer:
    """``POST …/keys/retire`` (contract §5.3).

    Raises:
        FleetRejectedError: The contract's refusal.
    """
    check_json_body(request, wire.MAX_ENVELOPE_BYTES)
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "retire")
        answer, rotation_id = await _retire(session, robot, request.body)
    await _audit_success(robot, "retire", "retire", rotation_id=rotation_id)
    return FleetAnswer(body=answer)


async def _retire(
    session: AsyncSession, robot: FleetRobot, body: bytes
) -> tuple[bytes, str]:
    try:
        opened = wire.parse_envelope(body, wire.T_RETIRE_REQUEST)
        req = wire.parse_retire_request(opened.payload)
    except wire.WireError as exc:
        raise _bad_request(str(exc)) from exc
    rotation = await _rotation(session, req.rotation_id)
    if rotation is None:
        raise _reject(404, FleetErrorCode.UNKNOWN_ROTATION, "no such rotation")
    if (
        rotation.robot_fk != robot.robot_fk
        or req.robot_id != robot.robot_id
        or req.workspace != robot.fleet_workspace
    ):
        raise _reject(403, FleetErrorCode.ROBOT_MISMATCH, "rotation of another robot")
    if (
        req.role != rotation.role
        or req.old_key_id != rotation.old_key_id
        or req.new_key_id != rotation.new_key_id
    ):
        raise _bad_request("retire request does not match the rotation")
    if req.role == RobotKeyRole.UPLINK.value and robot.key_id != req.new_key_id:
        raise await _wrong_key(
            robot,
            "retire",
            "an uplink retirement is authenticated by the new uplink key",
        )
    if rotation.status == FleetRotationStatus.CANCELLED.value:
        raise _reject(
            409, FleetErrorCode.ROTATION_CANCELLED, "this rotation was cancelled"
        )
    new_key = await _robot_key(session, robot, req.new_key_id, req.role)
    if (
        new_key is None
        or opened.signers != [req.new_key_id]
        or not opened.verify_by(req.new_key_id, new_key.public_key)
    ):
        raise _reject(
            401, FleetErrorCode.BAD_SIGNATURE, "must be signed by the new key"
        )
    request_digest = opened.payload_digest
    if rotation.status == FleetRotationStatus.RETIRED.value:
        if (
            rotation.retire_digest == request_digest
            and rotation.retire_answer is not None
        ):
            return rotation.retire_answer, req.rotation_id
        raise _reject(
            409,
            FleetErrorCode.ALREADY_RETIRED,
            "rotation already retired by another request",
        )
    fleet_key = await _fleet_key(session, robot.workspace_id)
    server_now = now_ms()
    payload = wire.key_answer_payload(
        answer_format=wire.RETIRE_ANSWER_FORMAT,
        rotation_id=req.rotation_id,
        request_digest=request_digest,
        workspace=req.workspace,
        robot_id=robot.robot_id,
        role=req.role,
        old_key_id=req.old_key_id,
        new_key_id=req.new_key_id,
        status="retired",
        at_ms=server_now,
    )
    answer = wire.sign_envelope(wire.T_RETIRE_ANSWER, payload, [fleet_key])
    retired_at = _ms_to_datetime(server_now)
    await session.execute(
        update(RobotKey)
        .where(
            RobotKey.robot_fk == robot.robot_fk,
            RobotKey.key_id == req.old_key_id,
            RobotKey.revoked_at.is_(None),
        )
        .values(revoked_at=retired_at)
    )
    rotation.status = FleetRotationStatus.RETIRED.value
    rotation.retire_digest = request_digest
    rotation.retire_answer = answer
    rotation.closed_at = retired_at
    await session.commit()
    return answer, req.rotation_id


async def cancel(request: FleetRequest) -> FleetAnswer:
    """``POST …/keys/cancel`` (contract §5.5).

    Raises:
        FleetRejectedError: The contract's refusal.
    """
    check_json_body(request, wire.MAX_ENVELOPE_BYTES)
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "cancel")
        answer, rotation_id = await _cancel(session, robot, request.body)
    await _audit_success(robot, "cancel", "cancel", rotation_id=rotation_id)
    return FleetAnswer(body=answer)


async def _cancel(
    session: AsyncSession, robot: FleetRobot, body: bytes
) -> tuple[bytes, str]:
    try:
        opened = wire.parse_envelope(body, wire.T_CANCEL_REQUEST)
        req = wire.parse_cancel_request(opened.payload)
    except wire.WireError as exc:
        raise _bad_request(str(exc)) from exc
    if req.workspace != robot.fleet_workspace or req.robot_id != robot.robot_id:
        raise _reject(403, FleetErrorCode.ROBOT_MISMATCH, "rotation of another robot")
    if req.role == RobotKeyRole.UPLINK.value and robot.key_id != req.old_key_id:
        raise await _wrong_key(
            robot,
            "cancel",
            "an uplink cancellation is authenticated by the old uplink key",
        )
    rotation = await _rotation(session, req.rotation_id)
    if rotation is not None:
        if rotation.robot_fk != robot.robot_fk:
            raise _reject(
                403, FleetErrorCode.ROBOT_MISMATCH, "rotation of another robot"
            )
        if (
            req.role != rotation.role
            or req.old_key_id != rotation.old_key_id
            or req.new_key_id != rotation.new_key_id
            or req.request_digest != rotation.request_digest
        ):
            raise _bad_request("cancel request does not match the rotation")
    old = await _robot_key(session, robot, req.old_key_id, req.role)
    if old is None:
        raise _reject(
            409, FleetErrorCode.STALE_KEY, "old key is not a key of this robot and role"
        )
    if opened.signers != [req.old_key_id] or not opened.verify_by(
        req.old_key_id, old.public_key
    ):
        raise _reject(
            401, FleetErrorCode.BAD_SIGNATURE, "must be signed by the old key only"
        )
    request_digest = opened.payload_digest
    if rotation is not None:
        if rotation.status == FleetRotationStatus.CANCELLED.value:
            if rotation.cancel_digest == request_digest and rotation.cancel_answer:
                return rotation.cancel_answer, req.rotation_id
            raise _reject(
                409,
                FleetErrorCode.ALREADY_CANCELLED,
                "rotation already cancelled by another request",
            )
        if rotation.status == FleetRotationStatus.RETIRED.value:
            raise _reject(
                409, FleetErrorCode.ALREADY_RETIRED, "the rotation is complete"
            )
    if old.revoked_at is not None:
        raise _reject(
            409,
            FleetErrorCode.STALE_KEY,
            "old key is not this robot's active key of that role",
        )
    fleet_key = await _fleet_key(session, robot.workspace_id)
    server_now = now_ms()
    payload = wire.key_answer_payload(
        answer_format=wire.CANCEL_ANSWER_FORMAT,
        rotation_id=req.rotation_id,
        request_digest=request_digest,
        workspace=req.workspace,
        robot_id=robot.robot_id,
        role=req.role,
        old_key_id=req.old_key_id,
        new_key_id=req.new_key_id,
        status="cancelled",
        at_ms=server_now,
    )
    answer = wire.sign_envelope(wire.T_CANCEL_ANSWER, payload, [fleet_key])
    cancelled_at = _ms_to_datetime(server_now)
    if rotation is None:
        # Never received: remember the id so the late rotate request is refused.
        rotation = RobotFleetRotation(
            workspace_id=robot.workspace_id,
            rotation_id=req.rotation_id,
            robot_fk=robot.robot_fk,
            role=req.role,
            old_key_id=req.old_key_id,
            new_key_id=req.new_key_id,
            request_digest=req.request_digest,
        )
        session.add(rotation)
    else:
        await session.execute(
            update(RobotKey)
            .where(
                RobotKey.robot_fk == robot.robot_fk,
                RobotKey.key_id == req.new_key_id,
                RobotKey.revoked_at.is_(None),
            )
            .values(revoked_at=cancelled_at)
        )
    rotation.status = FleetRotationStatus.CANCELLED.value
    rotation.cancel_digest = request_digest
    rotation.cancel_answer = answer
    rotation.closed_at = cancelled_at
    await session.commit()
    return answer, req.rotation_id


async def publish_draft(request: FleetRequest) -> FleetAnswer:
    """``POST …/profiles/drafts`` (contract §6.1): queue a draft for review.

    Raises:
        FleetRejectedError: The contract's refusal (``400 invalid_profile``).
    """
    check_json_body(request, wire.MAX_DRAFT_BYTES)
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "publish_draft")
        try:
            draft_digest = check_draft_profile(request.body)
        except ProfileFileError as exc:
            raise _reject(400, FleetErrorCode.INVALID_PROFILE, str(exc)) from exc
        exists = await session.scalar(
            select(RobotFleetProfileDraft.id).where(
                RobotFleetProfileDraft.robot_fk == robot.robot_fk,
                RobotFleetProfileDraft.digest == draft_digest,
            )
        )
        if exists is None:
            session.add(
                RobotFleetProfileDraft(
                    workspace_id=robot.workspace_id,
                    robot_fk=robot.robot_fk,
                    digest=draft_digest,
                    body=request.body,
                )
            )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()  # The same draft, published concurrently.
    await _audit_success(
        robot, "publish", "publish_draft", profile_digest_id=draft_digest
    )
    return FleetAnswer(
        body=wire.dumps_compact({"digest": draft_digest, "status": "received"})
    )


async def get_revocation_list(request: FleetRequest, platform: str) -> FleetAnswer:
    """``GET …/revocations/{platform}`` (contract §4.1): the list, verbatim.

    Raises:
        FleetRejectedError: Authentication, or ``404 no_list``.
    """
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "get_revocations")
        body = None
        if wire.is_label(platform):
            body = await session.scalar(
                select(RobotFleetRevocationList.body)
                .where(
                    RobotFleetRevocationList.workspace_id == robot.workspace_id,
                    RobotFleetRevocationList.platform == platform,
                )
                .order_by(RobotFleetRevocationList.serial.desc())
                .limit(1)
            )
    if body is None:
        raise _reject(
            404, FleetErrorCode.NO_LIST, "no revocation list for this platform"
        )
    await _audit_success(robot, "read", "get_revocations")
    return FleetAnswer(body=body)


async def get_profile_offer(request: FleetRequest) -> FleetAnswer:
    """``GET …/profiles/current`` (contract §6.2).

    Raises:
        FleetRejectedError: Authentication, or ``404 no_profile``.
    """
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "get_profile_offer")
        body = await session.scalar(
            select(RobotFleetProfileOffer.body).where(
                RobotFleetProfileOffer.robot_fk == robot.robot_fk
            )
        )
    if body is None:
        raise _reject(
            404, FleetErrorCode.NO_PROFILE, "no profile published for this robot"
        )
    await _audit_success(robot, "read", "get_profile_offer")
    return FleetAnswer(body=body)


async def get_approval(request: FleetRequest, digest_hex: str) -> FleetAnswer:
    """``GET …/profiles/approvals/{hex}`` (contract §6.3).

    Raises:
        FleetRejectedError: Authentication, ``404 not_found`` for a malformed
            digest, or ``404 no_approval``.
    """
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "get_approval")
        if _DIGEST_HEX_RE.fullmatch(digest_hex) is None:
            raise _reject(404, FleetErrorCode.NOT_FOUND, "no such endpoint")
        envelope = await session.scalar(
            select(RobotFleetApproval.envelope)
            .where(
                RobotFleetApproval.robot_fk == robot.robot_fk,
                RobotFleetApproval.profile_digest == f"sha256:{digest_hex}",
                RobotFleetApproval.envelope.is_not(None),
            )
            .order_by(RobotFleetApproval.issued_at_ms.desc())
            .limit(1)
        )
    if envelope is None:
        raise _reject(404, FleetErrorCode.NO_APPROVAL, "no approval for this digest")
    await _audit_success(robot, "read", "get_approval")
    return FleetAnswer(body=envelope)


async def get_ring(request: FleetRequest) -> FleetAnswer:
    """``GET …/ring`` (contract §7).

    Raises:
        FleetRejectedError: Authentication, or ``404 no_ring``.
    """
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = await _authenticated(session, request, "get_ring")
        envelope = await session.scalar(
            select(RobotFleetRing.envelope)
            .where(RobotFleetRing.robot_fk == robot.robot_fk)
            .order_by(RobotFleetRing.serial.desc())
            .limit(1)
        )
    if envelope is None:
        raise _reject(404, FleetErrorCode.NO_RING, "no ring assigned")
    await _audit_success(robot, "read", "get_ring")
    return FleetAnswer(body=envelope)


def not_found() -> FleetRejectedError:
    """``404 not_found`` for a path below the fleet prefix that names no endpoint."""
    return _reject(404, FleetErrorCode.NOT_FOUND, "no such endpoint")
