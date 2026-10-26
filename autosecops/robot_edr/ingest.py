"""`POST /robot-edr/v2/ingest` processing (ingest contract §4-§6).

The router reads the body under the size cap and hands an
:class:`IngestRequest` to :func:`ingest`, which applies the contract's steps
in order; the first step that fails decides the response:

1. syntax: content type (router), body size (router), line count, the four
   ``X-RoboDR-*`` headers, empty body (``415``/``413``/``400``);
2. key lookup, timestamp skew and batch signature (``401``, audited); then
   the workspace's ``robot_edr`` entitlement (``403 not_entitled``);
3. replay of a batch answered within 7 days (same body: stored response;
   other body: ``409 batch_id_reuse``);
4. the per-sender-key rate limit (``429``);
5. every line in order: framing, validation, robot binding, per-finding
   signature, dedup and case upsert.

Step 5 and the stored response share one database transaction: the response
is recorded atomically with the batch's effects, a failed batch (``5xx``)
leaves nothing behind, and a concurrent retry of the same batch waits on the
batch row and then answers from it.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import noload

from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.service import AuditService
from autosecops.auth.types import Role
from autosecops.cases.enums import CaseSeverity, CaseStatus
from autosecops.cases.event_schemas import (
    FieldDiff,
    FieldsChangedEvent,
    PayloadChangedEvent,
    PriorityChangedEvent,
    SeverityChangedEvent,
    TagAddedEvent,
)
from autosecops.cases.schemas import CaseCreate, CaseFieldCreate
from autosecops.cases.service import CaseEventsService, CaseFieldsService, CasesService
from autosecops.contexts import ctx_role
from autosecops.db.engine import (
    get_async_session_bypass_rls_context_manager,
    get_async_session_context_manager,
)
from autosecops.db.models import (
    Case,
    CaseTag,
    CaseTagLink,
    Robot,
    RobotFinding,
    RobotFindingEvent,
    RobotIngestBatch,
    RobotKey,
    Workspace,
)
from autosecops.logger import logger
from autosecops.robot_edr import rendering
from autosecops.robot_edr.crypto import (
    batch_signing_message,
    finding_signing_message,
    verify_strict,
)
from autosecops.robot_edr.ndjson import ParsedLine, parse_line, split_lines
from autosecops.robot_edr.rate_limit import take_batch_token
from autosecops.robot_edr.types import (
    SENDER_KEY_ROLES,
    AuthFailureReason,
    IngestErrorCode,
    LineErrorCode,
    LineRejection,
    RobotKeyRole,
    SenderKey,
    UpsertOutcome,
)
from autosecops.robot_edr.validator import (
    FindingValidationError,
    UnsupportedContractError,
    ValidatedFinding,
    parse_and_validate,
)
from autosecops.tables.enums import SqlType
from autosecops.tiers.access import is_org_entitled
from autosecops.tiers.enums import Entitlement

MAX_BODY_BYTES: Final = 4 * 1024 * 1024
MAX_LINES: Final = 1000
MAX_VALUE_BYTES: Final = 256 * 1024
MAX_CLOCK_SKEW_MS: Final = 300_000
REPLAY_WINDOW: Final = timedelta(days=7)
GLOBAL_SWEEP_INTERVAL_SECONDS: Final = 600.0
GLOBAL_SWEEP_LIMIT: Final = 1000

KEY_ID_HEADER: Final = "x-robodr-key-id"
BATCH_ID_HEADER: Final = "x-robodr-batch-id"
TIMESTAMP_HEADER: Final = "x-robodr-timestamp"
SIGNATURE_HEADER: Final = "x-robodr-signature"
KEY_ID_RE: Final = re.compile(r"ed25519:[0-9a-f]{16}")
BATCH_ID_RE: Final = re.compile(r"[A-Za-z0-9._:-]{1,64}")
TIMESTAMP_RE: Final = re.compile(r"0|[1-9][0-9]{0,19}")
SIGNATURE_RE: Final = re.compile(r"[0-9a-f]{128}")

INGEST_SCOPES: Final = frozenset({"case:read", "case:create", "case:update"})
_UNKNOWN_KEY_NAMESPACE: Final = uuid.UUID("6f1b8c1e-6d1f-4d0b-9a4b-7c3c2a1e5d10")
_SETUP_LOCK_PREFIX: Final = "robot_edr_case_setup:"
_DETAIL_MAX: Final = 300

_last_global_sweep = 0.0


def now_ms() -> int:
    """Server clock in Unix milliseconds (a seam for contract test vectors)."""
    return int(time.time() * 1000)


class IngestRejectedError(Exception):
    """The whole request is refused with ``status`` and a contract error code."""

    def __init__(
        self,
        status: int,
        code: IngestErrorCode,
        detail: str,
        *,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class IngestRequest:
    """Transport-independent view of one ingest request.

    ``headers`` holds every value of each ``X-RoboDR-*`` header (lower-case
    names) so a repeated header can be refused.
    """

    headers: Mapping[str, Sequence[str]]
    body: bytes


@dataclass(frozen=True, slots=True)
class BatchHeaders:
    """The four well-formed `X-RoboDR-*` headers (contract §2.1)."""

    key_id: str
    batch_id: str
    timestamp_ms: int
    signature: bytes


@dataclass(frozen=True, slots=True)
class _RobotRef:
    """The registered robot a finding is bound to (plain values, no ORM)."""

    id: uuid.UUID
    robot_id: str
    site: str | None
    require_finding_signature: bool


@dataclass(slots=True)
class _Tally:
    created: int = 0
    updated: int = 0
    duplicates: int = 0
    rejected: list[LineRejection] = field(default_factory=list)

    def response(self, batch_id: str) -> dict[str, Any]:
        return {
            "batch_id": batch_id,
            "replayed": False,
            "accepted": self.created + self.updated + self.duplicates,
            "created": self.created,
            "updated": self.updated,
            "duplicates": self.duplicates,
            "rejected": [
                {"line": r.line, "code": r.code.value, "detail": r.detail}
                for r in self.rejected
            ],
        }


def ingest_role(sender: SenderKey) -> Role:
    """The role ingest acts under in the sender key's workspace."""
    return Role(
        type="service",
        service_id="tracecat-api",
        workspace_id=sender.workspace_id,
        organization_id=sender.organization_id,
        scopes=INGEST_SCOPES,
    )


def _ms_to_datetime(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


def _bad_header(detail: str) -> IngestRejectedError:
    return IngestRejectedError(400, IngestErrorCode.BAD_HEADER, detail)


def _single(request: IngestRequest, name: str) -> str:
    values = request.headers.get(name, ())
    if len(values) != 1:
        raise _bad_header(f"{name} must appear exactly once")
    return values[0]


def parse_headers(request: IngestRequest) -> BatchHeaders:
    """Contract §2.1: each `X-RoboDR-*` header exactly once and well formed.

    Raises:
        IngestRejectedError: ``400 bad_header``.
    """
    key_id = _single(request, KEY_ID_HEADER)
    batch_id = _single(request, BATCH_ID_HEADER)
    timestamp = _single(request, TIMESTAMP_HEADER)
    signature = _single(request, SIGNATURE_HEADER)
    if not KEY_ID_RE.fullmatch(key_id):
        raise _bad_header("X-RoboDR-Key-Id must be ed25519:<16 lower-case hex>")
    if not BATCH_ID_RE.fullmatch(batch_id):
        raise _bad_header(
            "X-RoboDR-Batch-Id must be 1-64 characters of [A-Za-z0-9._:-]"
        )
    if not TIMESTAMP_RE.fullmatch(timestamp) or int(timestamp) >= 2**64:
        raise _bad_header("X-RoboDR-Timestamp must be unsigned decimal milliseconds")
    if not SIGNATURE_RE.fullmatch(signature):
        raise _bad_header("X-RoboDR-Signature must be 128 lower-case hex digits")
    return BatchHeaders(
        key_id=key_id,
        batch_id=batch_id,
        timestamp_ms=int(timestamp),
        signature=bytes.fromhex(signature),
    )


def check_syntax(request: IngestRequest) -> tuple[list[bytes], BatchHeaders]:
    """Contract §4 step 1 after the router's content-type and size checks.

    Returns:
        The body's lines and the parsed headers.

    Raises:
        IngestRejectedError: ``413 too_many_lines``, ``400 bad_header`` or
            ``400 empty_batch``, in that order.
    """
    lines = split_lines(request.body)
    if len(lines) > MAX_LINES:
        raise IngestRejectedError(
            413,
            IngestErrorCode.TOO_MANY_LINES,
            f"batch has {len(lines)} lines; at most {MAX_LINES} are allowed",
        )
    headers = parse_headers(request)
    if not request.body:
        raise IngestRejectedError(400, IngestErrorCode.EMPTY_BATCH, "the body is empty")
    return lines, headers


async def ingest(request: IngestRequest) -> dict[str, Any]:
    """Run the whole contract §4 pipeline; return the ``200`` body.

    Raises:
        IngestRejectedError: Any whole-request refusal.
    """
    lines, headers = check_syntax(request)
    return await RobotIngestService(headers, request.body).run(lines)


class RobotIngestService:
    """Authenticate and process one `robodr.ingest` batch."""

    def __init__(self, headers: BatchHeaders, body: bytes) -> None:
        self.headers = headers
        self.body = body
        self.body_sha256 = hashlib.sha256(body).hexdigest()

    # --- step 2: authentication -------------------------------------------------

    async def authenticate(self) -> SenderKey:
        """Resolve and verify the sender key (contract §4 step 2).

        Raises:
            IngestRejectedError: ``401`` with ``unknown_key``,
                ``stale_timestamp`` or ``bad_signature``; every refusal is
                written to the audit log first.
        """
        sender, reason = await self._lookup_sender(self.headers.key_id)
        if sender is None or reason is not None:
            await self._audit_auth_failure(sender, reason)
            raise IngestRejectedError(
                401, IngestErrorCode.UNKNOWN_KEY, "unknown sender key"
            )
        if abs(now_ms() - self.headers.timestamp_ms) > MAX_CLOCK_SKEW_MS:
            await self._audit_auth_failure(sender, AuthFailureReason.STALE_TIMESTAMP)
            raise IngestRejectedError(
                401,
                IngestErrorCode.STALE_TIMESTAMP,
                "X-RoboDR-Timestamp is more than 300 s from the server clock",
            )
        message = batch_signing_message(
            key_id=sender.key_id,
            batch_id=self.headers.batch_id,
            timestamp_ms=self.headers.timestamp_ms,
            body=self.body,
        )
        if not verify_strict(sender.public_key, message, self.headers.signature):
            await self._audit_auth_failure(sender, AuthFailureReason.BAD_SIGNATURE)
            raise IngestRejectedError(
                401, IngestErrorCode.BAD_SIGNATURE, "batch signature does not verify"
            )
        return sender

    async def _lookup_sender(
        self, key_id: str
    ) -> tuple[SenderKey | None, AuthFailureReason | None]:
        """Find the sender key across workspaces (the request names none)."""
        async with get_async_session_bypass_rls_context_manager() as session:
            rows = (
                await session.execute(
                    select(RobotKey, Workspace.organization_id, Robot.robot_id)
                    .join(Workspace, Workspace.id == RobotKey.workspace_id)
                    .outerjoin(Robot, Robot.id == RobotKey.robot_fk)
                    .where(RobotKey.key_id == key_id)
                )
            ).all()
        if not rows:
            return None, AuthFailureReason.UNKNOWN_KEY
        senders = [r for r in rows if r[0].role in SENDER_KEY_ROLES]
        if not senders:
            key, org_id, robot_id = rows[0]
            return self._sender(key, org_id, robot_id), AuthFailureReason.WRONG_ROLE
        active = [r for r in senders if r[0].revoked_at is None]
        key, org_id, robot_id = active[0] if active else senders[0]
        sender = self._sender(key, org_id, robot_id)
        if key.revoked_at is not None:
            return sender, AuthFailureReason.REVOKED_KEY
        if key.expires_at is not None and key.expires_at <= datetime.now(UTC):
            return sender, AuthFailureReason.EXPIRED_KEY
        return sender, None

    @staticmethod
    def _sender(key: RobotKey, org_id: uuid.UUID, robot_id: str | None) -> SenderKey:
        return SenderKey(
            id=key.id,
            key_id=key.key_id,
            role=RobotKeyRole(key.role),
            public_key=key.public_key,
            workspace_id=key.workspace_id,
            organization_id=org_id,
            robot_fk=key.robot_fk,
            robot_id=robot_id,
            site=key.site,
            vouches_origin=key.vouches_origin,
        )

    async def _audit_auth_failure(
        self, sender: SenderKey | None, reason: AuthFailureReason | None
    ) -> None:
        """Log and audit a ``401`` (key id, source address, reason; no body)."""
        reason = reason or AuthFailureReason.UNKNOWN_KEY
        presented = self.headers.key_id
        logger.warning(
            "Robot EDR ingest authentication failed",
            sender_key_id=presented,
            reason=reason.value,
            workspace_id=str(sender.workspace_id) if sender else None,
        )
        actor_id = (
            sender.id
            if sender is not None
            else uuid.uuid5(_UNKNOWN_KEY_NAMESPACE, presented)
        )
        try:
            async with get_async_session_bypass_rls_context_manager() as session:
                audit = AuditService(
                    session,
                    role=ingest_role(sender) if sender is not None else None,
                    audit_sink="organization" if sender is not None else "platform",
                )
                await audit.create_robot_event(
                    actor_id=actor_id,
                    resource_type="robot_ingest",
                    action="ingest",
                    status=AuditEventStatus.FAILURE,
                    data={
                        "sender_key_id": presented,
                        "batch_id": self.headers.batch_id,
                        "failure_reason": reason.value,
                    },
                )
        except Exception as exc:  # Audit delivery is best-effort; the 401 stands.
            logger.warning(
                "Robot EDR audit event failed", error_type=type(exc).__name__
            )

    # --- steps 2b-6 ---------------------------------------------------------------

    async def run(self, lines: Sequence[bytes]) -> dict[str, Any]:
        """Authenticate and process the batch; return the ``200`` body.

        Raises:
            IngestRejectedError: Any whole-request refusal.
        """
        sender = await self.authenticate()
        role = ingest_role(sender)
        token = ctx_role.set(role)
        try:
            # ctx_role is set first, so the session gets this role's RLS context.
            async with get_async_session_context_manager() as session:
                return await self._process(session, role, sender, lines)
        finally:
            ctx_role.reset(token)

    async def _process(
        self,
        session: AsyncSession,
        role: Role,
        sender: SenderKey,
        lines: Sequence[bytes],
    ) -> dict[str, Any]:
        if not await is_org_entitled(
            session, sender.organization_id, Entitlement.ROBOT_EDR
        ):
            raise IngestRejectedError(
                403,
                IngestErrorCode.NOT_ENTITLED,
                "Robot EDR is not enabled for this workspace",
            )
        if (stored := await self._stored_response(session, sender)) is not None:
            await session.rollback()
            return stored

        decision = await take_batch_token(sender.id)
        if not decision.allowed:
            raise IngestRejectedError(
                429,
                IngestErrorCode.RATE_LIMITED,
                "batch rate limit exceeded for this sender key",
                retry_after=decision.retry_after_seconds,
            )

        setup = await prepare_workspace(session, role)
        try:
            claim = await self._claim(session, sender)
            if isinstance(claim, dict):
                await session.rollback()
                return claim
            processor = _BatchProcessor(session, role, sender, setup)
            tally = await processor.process(lines)
            response = tally.response(self.headers.batch_id)
            await session.execute(
                update(RobotIngestBatch)
                .where(RobotIngestBatch.id == claim)
                .values(response=response)
            )
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        await self._cleanup(session, sender)
        await self._audit_success(session, role, sender, tally)
        return response

    def _replay(self, body_sha256: str, response: dict[str, Any]) -> dict[str, Any]:
        if body_sha256 != self.body_sha256:
            raise IngestRejectedError(
                409,
                IngestErrorCode.BATCH_ID_REUSE,
                "this batch id was used with another body",
            )
        return {**response, "replayed": True}

    async def _stored_response(
        self, session: AsyncSession, sender: SenderKey
    ) -> dict[str, Any] | None:
        row = (
            await session.execute(
                select(RobotIngestBatch.body_sha256, RobotIngestBatch.response).where(
                    RobotIngestBatch.workspace_id == sender.workspace_id,
                    RobotIngestBatch.sender_key_fk == sender.id,
                    RobotIngestBatch.batch_id == self.headers.batch_id,
                    RobotIngestBatch.response.is_not(None),
                    RobotIngestBatch.created_at >= func.now() - REPLAY_WINDOW,
                )
            )
        ).first()
        if row is None:
            return None
        return self._replay(row[0], row[1])

    async def _claim(
        self, session: AsyncSession, sender: SenderKey
    ) -> uuid.UUID | dict[str, Any]:
        """Insert this batch's row inside the batch transaction.

        A concurrent request for the same batch blocks on the unique index
        until this transaction ends; it then answers from the stored row (or
        processes afresh if this one rolled back).
        """
        # A record older than the replay window no longer identifies a retry.
        await session.execute(
            delete(RobotIngestBatch).where(
                RobotIngestBatch.sender_key_fk == sender.id,
                RobotIngestBatch.batch_id == self.headers.batch_id,
                RobotIngestBatch.created_at < func.now() - REPLAY_WINDOW,
            )
        )
        claimed = await session.scalar(
            pg_insert(RobotIngestBatch)
            .values(
                id=uuid.uuid4(),
                workspace_id=sender.workspace_id,
                sender_key_fk=sender.id,
                batch_id=self.headers.batch_id,
                body_sha256=self.body_sha256,
            )
            .on_conflict_do_nothing(index_elements=["sender_key_fk", "batch_id"])
            .returning(RobotIngestBatch.id)
        )
        if claimed is not None:
            return claimed
        row = (
            await session.execute(
                select(RobotIngestBatch.body_sha256, RobotIngestBatch.response).where(
                    RobotIngestBatch.sender_key_fk == sender.id,
                    RobotIngestBatch.batch_id == self.headers.batch_id,
                )
            )
        ).first()
        if row is None or row[1] is None:
            raise RuntimeError("concurrent batch row vanished")
        return self._replay(row[0], row[1])

    async def _cleanup(self, session: AsyncSession, sender: SenderKey) -> None:
        """Drop replay records older than 7 days (this key; all keys every 10 min)."""
        global _last_global_sweep
        await session.execute(
            delete(RobotIngestBatch).where(
                RobotIngestBatch.sender_key_fk == sender.id,
                RobotIngestBatch.created_at < func.now() - REPLAY_WINDOW,
            )
        )
        await session.commit()
        now = time.monotonic()
        if now - _last_global_sweep < GLOBAL_SWEEP_INTERVAL_SECONDS:
            return
        _last_global_sweep = now
        await purge_expired_batches()

    async def _audit_success(
        self, session: AsyncSession, role: Role, sender: SenderKey, tally: _Tally
    ) -> None:
        try:
            audit = AuditService(session, role=role, audit_sink="organization")
            await audit.create_robot_event(
                actor_id=sender.id,
                resource_type="robot_ingest",
                action="ingest",
                status=AuditEventStatus.SUCCESS,
                data={
                    "sender_key_id": sender.key_id,
                    "batch_id": self.headers.batch_id,
                    "created_count": tally.created,
                    "updated_count": tally.updated,
                    "duplicate_count": tally.duplicates,
                    "rejected_count": len(tally.rejected),
                },
            )
        except Exception as exc:
            logger.warning(
                "Robot EDR audit event failed", error_type=type(exc).__name__
            )


async def purge_expired_batches(limit: int = GLOBAL_SWEEP_LIMIT) -> int:
    """Delete up to ``limit`` replay records older than 7 days, all workspaces.

    Returns:
        The number of records deleted.
    """
    async with get_async_session_bypass_rls_context_manager() as session:
        expired = (
            select(RobotIngestBatch.id)
            .where(RobotIngestBatch.created_at < func.now() - REPLAY_WINDOW)
            .limit(limit)
            .scalar_subquery()
        )
        result = await session.execute(
            delete(RobotIngestBatch)
            .where(RobotIngestBatch.id.in_(expired))
            .returning(RobotIngestBatch.id)
        )
        deleted = len(result.all())
        await session.commit()
        return deleted


# --- workspace setup -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WorkspaceSetup:
    """Per-workspace case setup RoboDR cases rely on."""

    writable_fields: frozenset[str]
    tag_id: uuid.UUID
    tag_ref: str
    tag_name: str


async def prepare_workspace(session: AsyncSession, role: Role) -> WorkspaceSetup:
    """Create the RoboDR case fields and the `robodr` case tag (idempotent).

    Runs in its own short transactions before the batch transaction; field
    creation is serialised per workspace by a transaction-scoped advisory
    lock. A field that exists with another type is left alone and not
    written.
    """
    fields = CaseFieldsService(session, role=role)
    lock_key = f"{_SETUP_LOCK_PREFIX}{role.workspace_id}"
    writable: set[str] = set()
    schema = await fields.get_field_schema()
    for name, sql_type in rendering.ROBOT_CASE_FIELDS.items():
        if name not in schema:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": lock_key},
            )
            schema = await fields.get_field_schema()
            if name not in schema:
                await fields.create_field(
                    CaseFieldCreate(
                        name=name,
                        type=SqlType(sql_type),
                        display_name=name.replace("_", " ").capitalize(),
                    )
                )
                schema = await fields.get_field_schema()
        existing = schema.get(name)
        existing_type = existing.get("type") if isinstance(existing, dict) else None
        if isinstance(existing_type, str) and existing_type.upper() == sql_type:
            writable.add(name)
        else:
            logger.warning(
                "Robot EDR case field exists with another type; not written",
                field=name,
            )
    await session.execute(
        pg_insert(CaseTag)
        .values(
            id=uuid.uuid4(),
            workspace_id=role.workspace_id,
            name=rendering.ROBODR_CASE_TAG,
            ref=rendering.ROBODR_CASE_TAG,
        )
        .on_conflict_do_nothing()
    )
    tag = (
        await session.execute(
            select(CaseTag.id, CaseTag.ref, CaseTag.name).where(
                CaseTag.workspace_id == role.workspace_id,
                CaseTag.ref == rendering.ROBODR_CASE_TAG,
            )
        )
    ).one()
    await session.commit()
    return WorkspaceSetup(
        writable_fields=frozenset(writable),
        tag_id=tag[0],
        tag_ref=tag[1],
        tag_name=tag[2],
    )


# --- step 5 ------------------------------------------------------------------------


class _BatchProcessor:
    """Validate, bind, verify and upsert each line, in line order."""

    def __init__(
        self,
        session: AsyncSession,
        role: Role,
        sender: SenderKey,
        setup: WorkspaceSetup,
    ) -> None:
        self.session = session
        self.role = role
        self.sender = sender
        self.setup = setup
        self.cases = CasesService(session, role=role)
        self.events = CaseEventsService(session, role=role)
        self._robots: dict[str, _RobotRef | None] = {}
        self._finding_keys: dict[tuple[uuid.UUID, str], bytes | None] = {}

    async def process(self, lines: Sequence[bytes]) -> _Tally:
        tally = _Tally()
        for number, raw in enumerate(lines, start=1):
            outcome = await self._line(number, raw)
            match outcome:
                case LineRejection():
                    tally.rejected.append(outcome)
                case UpsertOutcome.CREATED:
                    tally.created += 1
                case UpsertOutcome.UPDATED:
                    tally.updated += 1
                case UpsertOutcome.DUPLICATE:
                    tally.duplicates += 1
        return tally

    async def _line(self, number: int, raw: bytes) -> LineRejection | UpsertOutcome:
        parsed = parse_line(number, raw)
        if isinstance(parsed, LineRejection):
            return parsed
        value = parsed.value.encode("utf-8")
        if len(value) > MAX_VALUE_BYTES:
            return _reject(
                number,
                LineErrorCode.TOO_LARGE,
                f"decoded value is {len(value)} bytes; at most {MAX_VALUE_BYTES}",
            )
        try:
            finding = parse_and_validate(value)
            inputs = rendering.case_inputs(parsed.value)
        except UnsupportedContractError as exc:
            return _reject(
                number,
                LineErrorCode.UNSUPPORTED_CONTRACT,
                f"contract version {exc.contract_version[:32]!r} is not 2.x",
            )
        except FindingValidationError as exc:
            return _reject(
                number, LineErrorCode.INVALID_FINDING, "; ".join(exc.problems[:3])
            )
        except rendering.CaseRenderError as exc:
            return _reject(number, LineErrorCode.INVALID_FINDING, str(exc))

        robot = await self._bound_robot(number, finding)
        if isinstance(robot, LineRejection):
            return robot
        signature_key_id = await self._check_signature(number, parsed, value, robot)
        if isinstance(signature_key_id, LineRejection):
            return signature_key_id
        return await self._upsert(finding, inputs, value, robot, signature_key_id)

    async def _robot(self, robot_id: str) -> _RobotRef | None:
        if robot_id not in self._robots:
            row = (
                await self.session.execute(
                    select(
                        Robot.id,
                        Robot.robot_id,
                        Robot.site,
                        Robot.require_finding_signature,
                    ).where(
                        Robot.workspace_id == self.sender.workspace_id,
                        Robot.robot_id == robot_id,
                    )
                )
            ).first()
            self._robots[robot_id] = (
                _RobotRef(
                    id=row[0],
                    robot_id=row[1],
                    site=row[2],
                    require_finding_signature=row[3],
                )
                if row is not None
                else None
            )
        return self._robots[robot_id]

    async def _bound_robot(
        self, number: int, finding: ValidatedFinding
    ) -> _RobotRef | LineRejection:
        """Step 5.3: the sender key may report on the finding's robot."""
        if (
            self.sender.role is RobotKeyRole.UPLINK
            and finding.robot_id != self.sender.robot_id
        ):
            return _reject(
                number,
                LineErrorCode.ROBOT_MISMATCH,
                f"finding names robot {finding.robot_id}, key is bound to "
                f"{self.sender.robot_id}",
            )
        robot = await self._robot(finding.robot_id)
        if robot is None:
            return _reject(
                number,
                LineErrorCode.UNKNOWN_ROBOT,
                f"robot {finding.robot_id} is not registered in this workspace",
            )
        if self.sender.site is not None and robot.site != self.sender.site:
            return _reject(
                number,
                LineErrorCode.SITE_MISMATCH,
                f"robot {finding.robot_id} is not registered at the relay key's site",
            )
        return robot

    async def _finding_key(self, robot: _RobotRef, key_id: str) -> bytes | None:
        cache_key = (robot.id, key_id)
        if cache_key not in self._finding_keys:
            now = datetime.now(UTC)
            self._finding_keys[cache_key] = await self.session.scalar(
                select(RobotKey.public_key).where(
                    RobotKey.workspace_id == self.sender.workspace_id,
                    RobotKey.robot_fk == robot.id,
                    RobotKey.role == RobotKeyRole.FINDING.value,
                    RobotKey.key_id == key_id,
                    RobotKey.revoked_at.is_(None),
                    (RobotKey.expires_at.is_(None)) | (RobotKey.expires_at > now),
                )
            )
        return self._finding_keys[cache_key]

    async def _check_signature(
        self, number: int, parsed: ParsedLine, value: bytes, robot: _RobotRef
    ) -> str | None | LineRejection:
        """Step 5.4: verify a present `sig`; require one if the robot does."""
        if parsed.sig is None:
            if robot.require_finding_signature and not self.sender.vouches_origin:
                return _reject(
                    number,
                    LineErrorCode.MISSING_FINDING_SIGNATURE,
                    f"robot {robot.robot_id} requires signed findings",
                )
            return None
        sig = parsed.sig
        public_key = await self._finding_key(robot, sig.key_id)
        if public_key is None:
            return _reject(
                number,
                LineErrorCode.BAD_FINDING_SIGNATURE,
                f"no active finding key {sig.key_id[:64]!r} for robot {robot.robot_id}",
            )
        message = finding_signing_message(alg=sig.alg, key_id=sig.key_id, value=value)
        if not verify_strict(public_key, message, sig.sig):
            return _reject(
                number,
                LineErrorCode.BAD_FINDING_SIGNATURE,
                "finding signature does not verify",
            )
        return sig.key_id

    # --- step 5.5: dedup and cases --------------------------------------------------

    async def _upsert(
        self,
        finding: ValidatedFinding,
        inputs: rendering.CaseInputs,
        value: bytes,
        robot: _RobotRef,
        signature_key_id: str | None,
    ) -> UpsertOutcome:
        columns: dict[str, Any] = {
            "finding_id": finding.finding_id,
            "robot_fk": robot.id,
            "robot_id": finding.robot_id,
            "rule_id": finding.rule_id,
            "severity_id": finding.severity_id,
            "last_seen": _ms_to_datetime(finding.last_seen_ms),
            "occurrence_count": finding.occurrence_count,
            "last_event_uid": finding.event_uid,
            "contract_version": finding.contract_version,
            "data_source": finding.data_source,
            "raw_value": value.decode("utf-8"),
            "adversary_controlled_fields": list(finding.adversary_controlled_fields),
            "signature_key_id": signature_key_id,
            "sender_key_fk": self.sender.id,
        }
        existing = await self._locked_finding(finding.external_id)
        if existing is None:
            inserted = await self.session.scalar(
                pg_insert(RobotFinding)
                .values(
                    id=uuid.uuid4(),
                    workspace_id=self.sender.workspace_id,
                    external_id=finding.external_id,
                    first_seen=_ms_to_datetime(finding.first_seen_ms),
                    **columns,
                )
                .on_conflict_do_nothing(index_elements=["workspace_id", "external_id"])
                .returning(RobotFinding.id)
            )
            if inserted is not None:
                await self._record_event(inserted, finding)
                case = await self._create_case(finding, inputs)
                await self._link_case(inserted, case.id)
                return UpsertOutcome.CREATED
            existing = await self._locked_finding(finding.external_id)
            if existing is None:  # Unreachable: the conflicting row is committed.
                raise RuntimeError("robot finding vanished during upsert")

        if not await self._record_event(existing.id, finding):
            return UpsertOutcome.DUPLICATE
        await self._apply_new_event(existing, finding, inputs, columns)
        return UpsertOutcome.UPDATED

    async def _record_event(
        self, finding_row: uuid.UUID, finding: ValidatedFinding
    ) -> bool:
        """Record an emission; ``False`` if its event uid is already known."""
        recorded = await self.session.scalar(
            pg_insert(RobotFindingEvent)
            .values(
                id=uuid.uuid4(),
                workspace_id=self.sender.workspace_id,
                finding_fk=finding_row,
                event_uid=finding.event_uid,
                occurrence_count=finding.occurrence_count,
                last_seen=_ms_to_datetime(finding.last_seen_ms),
                severity_id=finding.severity_id,
                sender_key_fk=self.sender.id,
            )
            .on_conflict_do_nothing(index_elements=["finding_fk", "event_uid"])
            .returning(RobotFindingEvent.id)
        )
        return recorded is not None

    async def _apply_new_event(
        self,
        existing: RobotFinding,
        finding: ValidatedFinding,
        inputs: rendering.CaseInputs,
        columns: dict[str, Any],
    ) -> None:
        """Contract §5 for a new event uid of a known finding.

        ``last_seen`` and ``occurrence_count`` only move forward, severity only
        rises, and the stored payload is the emission with the latest
        ``last_seen_time``. An emission older than the stored one still gets
        a case event.
        """
        stored_last_seen = round(existing.last_seen.timestamp() * 1000)
        newer = finding.last_seen_ms > stored_last_seen or (
            finding.last_seen_ms == stored_last_seen
            and finding.occurrence_count > existing.occurrence_count
        )
        count = max(existing.occurrence_count, finding.occurrence_count)
        old_severity = rendering.case_severity(existing.severity_id)
        new_severity = rendering.case_severity(finding.severity_id)
        rises = (
            rendering.SEVERITY_RANK[new_severity]
            > rendering.SEVERITY_RANK[old_severity]
        )
        values: dict[str, Any] = (
            dict(columns) if newer else {"sender_key_fk": self.sender.id}
        )
        values["occurrence_count"] = count
        values["last_seen"] = _ms_to_datetime(
            max(stored_last_seen, finding.last_seen_ms)
        )
        values["severity_id"] = finding.severity_id if rises else existing.severity_id
        values["first_seen"] = min(
            existing.first_seen, _ms_to_datetime(finding.first_seen_ms)
        )
        await self.session.execute(
            update(RobotFinding).where(RobotFinding.id == existing.id).values(**values)
        )

        case = await self._existing_case(existing.case_id)
        if case is None:  # The case was deleted: open a new one.
            case = await self._create_case(finding, inputs)
            await self._link_case(existing.id, case.id)
            return
        fields = self._fields(inputs) if newer else {}
        if "occurrence_count" in self.setup.writable_fields:
            fields["occurrence_count"] = count
        fields_changed = await self._write_fields(case, fields, record_event=True)
        await self._update_case(
            case,
            payload=inputs.payload if newer else None,
            severity=new_severity if rises else None,
            record_anyway=not fields_changed,
        )

    async def _update_case(
        self,
        case: Case,
        *,
        payload: dict[str, Any] | None,
        severity: CaseSeverity | None,
        record_anyway: bool,
    ) -> None:
        """Apply a RoboDR update to a case and record its activity events.

        Writes the same columns and events as ``CasesService.update_case``
        for a payload/severity/priority change (``payload_changed``,
        ``severity_changed``, ``priority_changed``) without reloading the
        case and its relationships. With nothing to change and
        ``record_anyway`` set, a ``payload_changed`` event still records the
        emission (contract §5: an older event is recorded as a case event).
        """
        values: dict[str, Any] = {}
        events: list[Any] = []
        if payload is not None:
            values["payload"] = payload
            events.append(PayloadChangedEvent())
        if severity is not None and severity != case.severity:
            priority = rendering.SEVERITY_TO_PRIORITY[severity]
            values["severity"] = severity
            events.append(SeverityChangedEvent(old=case.severity, new=severity))
            if priority != case.priority:
                values["priority"] = priority
                events.append(PriorityChangedEvent(old=case.priority, new=priority))
        if values:
            await self.session.execute(
                update(Case).where(Case.id == case.id).values(**values)
            )
        elif record_anyway:
            events.append(PayloadChangedEvent())
        for event in events:
            await self.events.create_event(case=case, event=event)

    async def _write_fields(
        self, case: Case, fields: dict[str, Any], *, record_event: bool
    ) -> bool:
        """Write RoboDR case field values directly to the workspace table.

        Only fields :func:`prepare_workspace` verified to exist with the
        expected type reach this point, and the values already have their
        storage types (TEXT strings, an INTEGER count), so this skips the
        generic normalisation and its per-call column reflection, which
        dominated ingest latency. A ``fields_changed`` case event records
        what changed, as the case service does.

        Returns:
            Whether a ``fields_changed`` event was recorded.
        """
        if not fields:
            return False
        service = self.cases.fields
        await service.ensure_workspace_row(case.id)
        table = sa.table(
            service.sanitized_table_name,
            sa.column("case_id", UUID(as_uuid=True)),
            *(_field_column(name) for name in fields),
            schema=service.schema_name,
        )
        old: dict[str, Any] = {}
        if record_event:
            row = (
                await self.session.execute(
                    sa.select(*(table.c[name] for name in fields)).where(
                        table.c.case_id == case.id
                    )
                )
            ).first()
            old = dict(row._mapping) if row is not None else {}
        await self.session.execute(
            sa.update(table).where(table.c.case_id == case.id).values(**fields)
        )
        if not record_event:
            return False
        diffs = [
            FieldDiff(field=name, old=old.get(name), new=value)
            for name, value in fields.items()
            if old.get(name) != value
        ]
        if not diffs:
            return False
        await self.events.create_event(
            case=case, event=FieldsChangedEvent(changes=diffs)
        )
        return True

    async def _link_case(self, finding_row: uuid.UUID, case_id: uuid.UUID) -> None:
        await self.session.execute(
            update(RobotFinding)
            .where(RobotFinding.id == finding_row)
            .values(case_id=case_id)
        )

    async def _locked_finding(self, external_id: str) -> RobotFinding | None:
        return await self.session.scalar(
            select(RobotFinding)
            .where(
                RobotFinding.workspace_id == self.sender.workspace_id,
                RobotFinding.external_id == external_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )

    async def _existing_case(self, case_id: uuid.UUID | None) -> Case | None:
        if case_id is None:
            return None
        return await self.session.scalar(
            select(Case)
            .options(noload("*"))
            .where(Case.workspace_id == self.sender.workspace_id, Case.id == case_id)
        )

    def _fields(self, inputs: rendering.CaseInputs) -> dict[str, Any]:
        return {
            name: value
            for name, value in inputs.fields.items()
            if name in self.setup.writable_fields and value is not None
        }

    async def _create_case(
        self, finding: ValidatedFinding, inputs: rendering.CaseInputs
    ) -> Case:
        severity = rendering.case_severity(finding.severity_id)
        case = await self.cases.create_case(
            CaseCreate(
                summary=inputs.summary,
                description=inputs.description,
                status=CaseStatus.NEW,
                priority=rendering.SEVERITY_TO_PRIORITY[severity],
                severity=severity,
                payload=inputs.payload,
            ),
            commit=False,
        )
        await self._write_fields(case, self._fields(inputs), record_event=False)
        self.session.add(CaseTagLink(case_id=case.id, tag_id=self.setup.tag_id))
        await self.events.create_event(
            case=case,
            event=TagAddedEvent(
                tag_id=self.setup.tag_id,
                tag_ref=self.setup.tag_ref,
                tag_name=self.setup.tag_name,
            ),
        )
        return case


def _field_column(name: str) -> sa.ColumnClause[Any]:
    """A typed column of the workspace case-fields table."""
    if rendering.ROBOT_CASE_FIELDS[name] == "INTEGER":
        return sa.column(name, sa.BigInteger())
    return sa.column(name, sa.Text())


def _reject(number: int, code: LineErrorCode, detail: str) -> LineRejection:
    return LineRejection(line=number, code=code, detail=detail[:_DETAIL_MAX])
