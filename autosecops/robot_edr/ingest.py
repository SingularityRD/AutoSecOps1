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
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.audit.enums import AuditEventStatus
from autosecops.audit.service import AuditService
from autosecops.auth.types import Role
from autosecops.cases.bulk import BulkCasesService
from autosecops.cases.enums import CasePriority, CaseSeverity, CaseStatus
from autosecops.cases.event_schemas import (
    CaseEventVariant,
    FieldDiff,
    FieldsChangedEvent,
    PayloadChangedEvent,
    PriorityChangedEvent,
    SeverityChangedEvent,
    TagAddedEvent,
)
from autosecops.cases.events import CaseEventItem
from autosecops.cases.schemas import CaseCreate, CaseFieldCreate
from autosecops.cases.service import CaseFieldsService
from autosecops.contexts import ctx_role
from autosecops.db.engine import (
    get_async_session_bypass_rls_context_manager,
    get_async_session_context_manager,
)
from autosecops.db.models import (
    Base,
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
from autosecops.robot_edr.line_checks import (
    CheckedLine,
    LineCheck,
    SignatureJob,
    check_lines,
    reject,
    verify_signatures,
    warm_pool,
)
from autosecops.robot_edr.ndjson import split_lines
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
from autosecops.robot_edr.validator import ValidatedFinding
from autosecops.tables.enums import SqlType
from autosecops.tiers.access import is_org_entitled
from autosecops.tiers.enums import Entitlement

MAX_BODY_BYTES: Final = 4 * 1024 * 1024
MAX_LINES: Final = 1000
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
_UPSERT_LOCK_PREFIX: Final = "robot_edr_upsert:"

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

        # The per-line CPU work runs before the batch transaction.
        warm_pool()
        checked = await check_lines(lines)
        setup = await prepare_workspace(session, role)
        results = await _LineChecker(session, sender).bind_and_verify(checked)
        try:
            claim = await self._claim(session, sender)
            if isinstance(claim, dict):
                await session.rollback()
                return claim
            tally = await _BatchUpsert(session, role, sender, setup).process(results)
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
        await self._cleanup()
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
        # Records older than the replay window no longer identify a retry:
        # drop this key's (this batch id's included) in the batch transaction.
        await session.execute(
            delete(RobotIngestBatch).where(
                RobotIngestBatch.sender_key_fk == sender.id,
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

    async def _cleanup(self) -> None:
        """Drop all keys' replay records older than 7 days, every 10 minutes.

        Each batch drops its own key's expired records in ``_claim``.
        """
        global _last_global_sweep
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
#
# Step 5 runs in two phases. ``check_lines`` does the per-line CPU work
# (framing, validation, rendering; in worker processes for large batches)
# and ``_LineChecker`` the robot binding and finding signatures, with two
# set-based lookups (robots, finding keys), all before the batch transaction
# starts. ``_BatchUpsert`` then applies dedup and the case effects inside the
# batch transaction with a constant number of statements: it takes the
# workspace's upsert lock (batches of a workspace upsert one at a time) and
# locks the batch's known findings in one query; replays the batch line by
# line in memory against that state, which yields exactly the per-line
# outcomes and case events of processing the lines one at a time; and writes
# the resulting rows set-based.


@dataclass(frozen=True, slots=True)
class _Accepted:
    """A line that passed every check before dedup (steps 5.1-5.4)."""

    number: int
    value: bytes
    finding: ValidatedFinding
    inputs: rendering.CaseInputs
    robot: _RobotRef
    signature_key_id: str | None


type _LineResult = LineRejection | _Accepted


class _LineChecker:
    """Steps 5.1-5.4 for a whole batch, outside the batch transaction."""

    def __init__(self, session: AsyncSession, sender: SenderKey) -> None:
        self.session = session
        self.sender = sender

    async def bind_and_verify(self, checked: Sequence[LineCheck]) -> list[_LineResult]:
        """Steps 5.3-5.4: robot binding and finding signatures.

        The robots and finding keys are read in two queries; the read
        transaction ends before the signatures are verified.
        """
        valid = [c for c in checked if isinstance(c, CheckedLine)]
        robots = await self._robots({c.finding.robot_id for c in valid})
        wanted = {
            (robot.id, c.sig.key_id)
            for c in valid
            if c.sig is not None
            and (robot := robots.get(c.finding.robot_id)) is not None
        }
        keys = await self._finding_keys(wanted)
        await self.session.commit()

        # Binding and key lookup per line; the signatures are then verified
        # together (in the worker pool for large batches).
        pending: list[LineRejection | tuple[CheckedLine, _RobotRef]] = []
        jobs: list[SignatureJob] = []
        for item in checked:
            if isinstance(item, LineRejection):
                pending.append(item)
                continue
            robot = self._bound_robot(item, robots)
            if isinstance(robot, LineRejection):
                pending.append(robot)
                continue
            job = self._signature_job(item, robot, keys)
            if isinstance(job, LineRejection):
                pending.append(job)
                continue
            if job is not None:
                jobs.append(job)
            pending.append((item, robot))
        verified = iter(await verify_signatures(jobs))

        results: list[_LineResult] = []
        for entry in pending:
            if isinstance(entry, LineRejection):
                results.append(entry)
                continue
            item, robot = entry
            sig = item.sig
            if sig is not None and not next(verified):
                results.append(
                    reject(
                        item.number,
                        LineErrorCode.BAD_FINDING_SIGNATURE,
                        "finding signature does not verify",
                    )
                )
                continue
            results.append(
                _Accepted(
                    number=item.number,
                    value=item.value,
                    finding=item.finding,
                    inputs=item.inputs,
                    robot=robot,
                    signature_key_id=sig.key_id if sig is not None else None,
                )
            )
        return results

    async def _robots(self, robot_ids: set[str]) -> dict[str, _RobotRef]:
        if not robot_ids:
            return {}
        rows = await self.session.execute(
            select(
                Robot.id, Robot.robot_id, Robot.site, Robot.require_finding_signature
            ).where(
                Robot.workspace_id == self.sender.workspace_id,
                Robot.robot_id == sa.any_(_text_array(robot_ids)),
            )
        )
        return {
            robot_id: _RobotRef(
                id=row_id,
                robot_id=robot_id,
                site=site,
                require_finding_signature=require_signature,
            )
            for row_id, robot_id, site, require_signature in rows.tuples().all()
        }

    async def _finding_keys(
        self, wanted: set[tuple[uuid.UUID, str]]
    ) -> dict[tuple[uuid.UUID, str], bytes]:
        """Active finding keys per (robot, key id)."""
        if not wanted:
            return {}
        now = datetime.now(UTC)
        rows = await self.session.execute(
            select(RobotKey.robot_fk, RobotKey.key_id, RobotKey.public_key)
            .where(
                RobotKey.workspace_id == self.sender.workspace_id,
                RobotKey.robot_fk == sa.any_(_uuid_array({r for r, _ in wanted})),
                RobotKey.role == RobotKeyRole.FINDING.value,
                RobotKey.key_id == sa.any_(_text_array({k for _, k in wanted})),
                RobotKey.revoked_at.is_(None),
                (RobotKey.expires_at.is_(None)) | (RobotKey.expires_at > now),
            )
            .order_by(RobotKey.surrogate_id)
        )
        keys: dict[tuple[uuid.UUID, str], bytes] = {}
        for robot_fk, key_id, public_key in rows.tuples().all():
            if robot_fk is not None:
                keys.setdefault((robot_fk, key_id), public_key)
        return keys

    def _bound_robot(
        self, item: CheckedLine, robots: Mapping[str, _RobotRef]
    ) -> _RobotRef | LineRejection:
        """Step 5.3: the sender key may report on the finding's robot."""
        finding = item.finding
        if (
            self.sender.role is RobotKeyRole.UPLINK
            and finding.robot_id != self.sender.robot_id
        ):
            return reject(
                item.number,
                LineErrorCode.ROBOT_MISMATCH,
                f"finding names robot {finding.robot_id}, key is bound to "
                f"{self.sender.robot_id}",
            )
        robot = robots.get(finding.robot_id)
        if robot is None:
            return reject(
                item.number,
                LineErrorCode.UNKNOWN_ROBOT,
                f"robot {finding.robot_id} is not registered in this workspace",
            )
        if self.sender.site is not None and robot.site != self.sender.site:
            return reject(
                item.number,
                LineErrorCode.SITE_MISMATCH,
                f"robot {finding.robot_id} is not registered at the relay key's site",
            )
        return robot

    def _signature_job(
        self,
        item: CheckedLine,
        robot: _RobotRef,
        keys: Mapping[tuple[uuid.UUID, str], bytes],
    ) -> SignatureJob | None | LineRejection:
        """Step 5.4: a present `sig` needs an active key; some robots need one.

        Returns:
            The verification to run, ``None`` for an acceptable unsigned
            line, or the line's rejection.
        """
        sig = item.sig
        if sig is None:
            if robot.require_finding_signature and not self.sender.vouches_origin:
                return reject(
                    item.number,
                    LineErrorCode.MISSING_FINDING_SIGNATURE,
                    f"robot {robot.robot_id} requires signed findings",
                )
            return None
        public_key = keys.get((robot.id, sig.key_id))
        if public_key is None:
            return reject(
                item.number,
                LineErrorCode.BAD_FINDING_SIGNATURE,
                f"no active finding key {sig.key_id[:64]!r} for robot {robot.robot_id}",
            )
        message = finding_signing_message(
            alg=sig.alg, key_id=sig.key_id, value=item.value
        )
        return SignatureJob(public_key=public_key, message=message, signature=sig.sig)


# --- step 5.5: dedup and cases ---------------------------------------------------


@dataclass(slots=True)
class _FindingState:
    """A locked `robot_finding` row as the batch has left it so far."""

    id: uuid.UUID
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    severity_id: int
    stored_case_id: uuid.UUID | None = None
    """The case the row linked when it was locked."""
    case: _CaseState | None = None
    """The finding's case, if it exists (``None``: deleted or not yet)."""
    insert_row: dict[str, Any] | None = None
    """A new finding's row as its first line creates it (not inserted yet)."""
    pending: dict[str, Any] = field(default_factory=dict)
    """Column values set by later lines and the case link, merged in order."""


@dataclass(slots=True)
class _CaseState:
    """A case the batch creates or updates, as the batch has left it so far."""

    severity: CaseSeverity
    priority: CasePriority
    id: uuid.UUID | None = None
    """``None`` until a case this batch creates is inserted."""
    fields: dict[str, Any] = field(default_factory=dict)
    """Current values of the RoboDR fields (loaded before the updates)."""
    pending: dict[str, Any] = field(default_factory=dict)
    """`case` column values to write back."""
    pending_fields: dict[str, Any] = field(default_factory=dict)
    """Custom-field values to write back."""

    @property
    def case_id(self) -> uuid.UUID:
        if self.id is None:
            raise RuntimeError("case is not inserted yet")
        return self.id


@dataclass(frozen=True, slots=True)
class _NewCase:
    """A case to create for a line (its finding's first or after deletion)."""

    state: _CaseState
    finding: _FindingState
    accepted: _Accepted


@dataclass(frozen=True, slots=True)
class _CaseUpdate:
    """A line's case effects on an existing case (contract §5)."""

    case: _CaseState
    fields: dict[str, Any]
    payload: dict[str, Any] | None
    severity: CaseSeverity | None


_FINDING_STATE_COLUMNS: Final = (
    RobotFinding.id,
    RobotFinding.external_id,
    RobotFinding.first_seen,
    RobotFinding.last_seen,
    RobotFinding.occurrence_count,
    RobotFinding.severity_id,
    RobotFinding.case_id,
)


class _BatchUpsert:
    """Step 5.5 for every accepted line, inside the batch transaction."""

    def __init__(
        self,
        session: AsyncSession,
        role: Role,
        sender: SenderKey,
        setup: WorkspaceSetup,
    ) -> None:
        self.session = session
        self.sender = sender
        self.setup = setup
        self.cases = BulkCasesService(session, role=role)
        self.events: list[CaseEventItem] = []
        self.finding_events: list[dict[str, Any]] = []
        self.new_cases: list[_NewCase] = []
        self.case_updates: list[_CaseUpdate] = []

    async def process(self, results: Sequence[_LineResult]) -> _Tally:
        """Apply the accepted lines in order; tally every line's outcome."""
        accepted = [r for r in results if isinstance(r, _Accepted)]
        findings, created = await self._lock_findings(accepted)
        known = await self._known_events(findings, accepted)
        cases = await self._existing_cases(findings)
        for state in findings.values():
            if state.stored_case_id is not None:
                state.case = cases.get(state.stored_case_id)

        tally = _Tally()
        for result in results:
            if isinstance(result, LineRejection):
                tally.rejected.append(result)
                continue
            outcome = self._replay(result, findings, created, known)
            match outcome:
                case UpsertOutcome.CREATED:
                    tally.created += 1
                case UpsertOutcome.UPDATED:
                    tally.updated += 1
                case UpsertOutcome.DUPLICATE:
                    tally.duplicates += 1

        await self._create_cases()
        await self._load_case_fields()
        for case_update in self.case_updates:
            self._apply_case_update(case_update)
        await self._write(findings)
        return tally

    # --- locking and preloading ---------------------------------------------------

    async def _lock_findings(
        self, accepted: Sequence[_Accepted]
    ) -> tuple[dict[str, _FindingState], set[str]]:
        """Lock the workspace's upserts and the batch's known findings.

        Batches of one workspace apply their upserts one at a time (a
        transaction-scoped advisory lock), so a finding absent here stays
        absent until this transaction ends: new findings are inserted once,
        at the end, already linked to their new case.

        Returns:
            Every finding the batch names, by external id, and the external
            ids that are new.
        """
        first: dict[str, _Accepted] = {}
        for item in accepted:
            first.setdefault(item.finding.external_id, item)
        if not first:
            return {}, set()
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": f"{_UPSERT_LOCK_PREFIX}{self.sender.workspace_id}"},
        )
        findings = await self._select_locked(sorted(first))
        created = set(first) - set(findings)
        for external_id in created:
            row = self._insert_row(first[external_id])
            findings[external_id] = _FindingState(
                id=row["id"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                occurrence_count=row["occurrence_count"],
                severity_id=row["severity_id"],
                insert_row=row,
            )
        return findings, created

    async def _select_locked(
        self, external_ids: Sequence[str]
    ) -> dict[str, _FindingState]:
        rows = await self.session.execute(
            select(*_FINDING_STATE_COLUMNS)
            .where(
                RobotFinding.workspace_id == self.sender.workspace_id,
                RobotFinding.external_id == sa.any_(_text_array(external_ids)),
            )
            .order_by(RobotFinding.external_id)
            .with_for_update()
        )
        return {
            external_id: _FindingState(
                id=row_id,
                first_seen=first_seen,
                last_seen=last_seen,
                occurrence_count=count,
                severity_id=severity_id,
                stored_case_id=case_id,
            )
            for (
                row_id,
                external_id,
                first_seen,
                last_seen,
                count,
                severity_id,
                case_id,
            ) in rows.tuples().all()
        }

    def _insert_row(self, item: _Accepted) -> dict[str, Any]:
        return {
            "id": uuid.uuid4(),
            "workspace_id": self.sender.workspace_id,
            "external_id": item.finding.external_id,
            "first_seen": _ms_to_datetime(item.finding.first_seen_ms),
            "case_id": None,
            **self._columns(item),
        }

    async def _known_events(
        self, findings: Mapping[str, _FindingState], accepted: Sequence[_Accepted]
    ) -> set[tuple[uuid.UUID, str]]:
        """Event uids already recorded for the batch's (locked) findings."""
        if not findings:
            return set()
        rows = await self.session.execute(
            select(RobotFindingEvent.finding_fk, RobotFindingEvent.event_uid).where(
                RobotFindingEvent.finding_fk
                == sa.any_(_uuid_array({f.id for f in findings.values()})),
                RobotFindingEvent.event_uid
                == sa.any_(_text_array({a.finding.event_uid for a in accepted})),
            )
        )
        return set(rows.tuples().all())

    async def _existing_cases(
        self, findings: Mapping[str, _FindingState]
    ) -> dict[uuid.UUID, _CaseState]:
        """The still-existing cases of the batch's known findings."""
        case_ids = {
            f.stored_case_id for f in findings.values() if f.stored_case_id is not None
        }
        if not case_ids:
            return {}
        rows = await self.session.execute(
            select(Case.id, Case.severity, Case.priority).where(
                Case.workspace_id == self.sender.workspace_id,
                Case.id == sa.any_(_uuid_array(case_ids)),
            )
        )
        return {
            case_id: _CaseState(id=case_id, severity=severity, priority=priority)
            for case_id, severity, priority in rows.tuples().all()
        }

    # --- the in-memory replay -----------------------------------------------------

    def _replay(
        self,
        item: _Accepted,
        findings: Mapping[str, _FindingState],
        created: set[str],
        known: set[tuple[uuid.UUID, str]],
    ) -> UpsertOutcome:
        """One line's dedup outcome and effects, as if processed alone."""
        finding = item.finding
        state = findings[finding.external_id]
        event_key = (state.id, finding.event_uid)
        if finding.external_id in created:
            created.discard(finding.external_id)
            self._record_event(state, item, event_key, known)
            self._new_case(state, item)
            return UpsertOutcome.CREATED
        if event_key in known:
            return UpsertOutcome.DUPLICATE
        self._record_event(state, item, event_key, known)
        self._apply_new_event(state, item)
        return UpsertOutcome.UPDATED

    def _record_event(
        self,
        state: _FindingState,
        item: _Accepted,
        event_key: tuple[uuid.UUID, str],
        known: set[tuple[uuid.UUID, str]],
    ) -> None:
        known.add(event_key)
        self.finding_events.append(
            {
                "id": uuid.uuid4(),
                "workspace_id": self.sender.workspace_id,
                "finding_fk": state.id,
                "event_uid": item.finding.event_uid,
                "occurrence_count": item.finding.occurrence_count,
                "last_seen": _ms_to_datetime(item.finding.last_seen_ms),
                "severity_id": item.finding.severity_id,
                "sender_key_fk": self.sender.id,
            }
        )

    def _new_case(self, state: _FindingState, item: _Accepted) -> None:
        severity = rendering.case_severity(item.finding.severity_id)
        case = _CaseState(
            severity=severity, priority=rendering.SEVERITY_TO_PRIORITY[severity]
        )
        state.case = case
        state.pending["case_id"] = case
        self.new_cases.append(_NewCase(state=case, finding=state, accepted=item))

    def _apply_new_event(self, state: _FindingState, item: _Accepted) -> None:
        """Contract §5 for a new event uid of a known finding.

        ``last_seen`` and ``occurrence_count`` only move forward, severity only
        rises, and the stored payload is the emission with the latest
        ``last_seen_time``. An emission older than the stored one still gets
        a case event.
        """
        finding = item.finding
        stored_last_seen = round(state.last_seen.timestamp() * 1000)
        newer = finding.last_seen_ms > stored_last_seen or (
            finding.last_seen_ms == stored_last_seen
            and finding.occurrence_count > state.occurrence_count
        )
        count = max(state.occurrence_count, finding.occurrence_count)
        old_severity = rendering.case_severity(state.severity_id)
        new_severity = rendering.case_severity(finding.severity_id)
        rises = (
            rendering.SEVERITY_RANK[new_severity]
            > rendering.SEVERITY_RANK[old_severity]
        )
        values: dict[str, Any] = (
            self._columns(item) if newer else {"sender_key_fk": self.sender.id}
        )
        values["occurrence_count"] = count
        values["last_seen"] = _ms_to_datetime(
            max(stored_last_seen, finding.last_seen_ms)
        )
        values["severity_id"] = finding.severity_id if rises else state.severity_id
        values["first_seen"] = min(
            state.first_seen, _ms_to_datetime(finding.first_seen_ms)
        )
        state.pending.update(values)
        state.occurrence_count = count
        state.last_seen = values["last_seen"]
        state.severity_id = values["severity_id"]
        state.first_seen = values["first_seen"]

        if state.case is None:  # The case was deleted: open a new one.
            self._new_case(state, item)
            return
        fields = self._fields(item.inputs) if newer else {}
        if "occurrence_count" in self.setup.writable_fields:
            fields["occurrence_count"] = count
        self.case_updates.append(
            _CaseUpdate(
                case=state.case,
                fields=fields,
                payload=item.inputs.payload if newer else None,
                severity=new_severity if rises else None,
            )
        )

    def _apply_case_update(self, update: _CaseUpdate) -> None:
        """A line's case events and values, as ``CasesService.update_case``.

        Records ``fields_changed`` for the fields whose value changes, then
        ``payload_changed`` / ``severity_changed`` / ``priority_changed``;
        with nothing else to record, a ``payload_changed`` event still
        records the emission (contract §5).
        """
        case = update.case
        diffs = [
            FieldDiff(field=name, old=case.fields.get(name), new=value)
            for name, value in update.fields.items()
            if case.fields.get(name) != value
        ]
        case.fields.update(update.fields)
        case.pending_fields.update(update.fields)
        if diffs:
            self._event(case, FieldsChangedEvent(changes=diffs))

        events: list[CaseEventVariant] = []
        changed = False
        if update.payload is not None:
            case.pending["payload"] = update.payload
            changed = True
            events.append(PayloadChangedEvent())
        severity = update.severity
        if severity is not None and severity != case.severity:
            priority = rendering.SEVERITY_TO_PRIORITY[severity]
            case.pending["severity"] = severity
            events.append(SeverityChangedEvent(old=case.severity, new=severity))
            case.severity = severity
            changed = True
            if priority != case.priority:
                case.pending["priority"] = priority
                events.append(PriorityChangedEvent(old=case.priority, new=priority))
                case.priority = priority
        if not changed and not diffs:
            events.append(PayloadChangedEvent())
        for event in events:
            self._event(case, event)

    def _event(self, case: _CaseState, event: CaseEventVariant) -> None:
        self.events.append(CaseEventItem(case_id=case.case_id, event=event))

    # --- writes ---------------------------------------------------------------------

    async def _create_cases(self) -> None:
        """Create the batch's new cases (with fields), tag them `robodr`."""
        if not self.new_cases:
            return
        created = await self.cases.create_cases(
            [
                CaseCreate(
                    summary=new.accepted.inputs.summary,
                    description=new.accepted.inputs.description,
                    status=CaseStatus.NEW,
                    priority=new.state.priority,
                    severity=new.state.severity,
                    payload=new.accepted.inputs.payload,
                    fields=self._fields(new.accepted.inputs),
                )
                for new in self.new_cases
            ]
        )
        case_ids = [case.id for case in created]
        for new, case_id in zip(self.new_cases, case_ids, strict=True):
            new.state.id = case_id
        await self.session.execute(
            sa.insert(_table_of(CaseTagLink)),
            [{"case_id": case_id, "tag_id": self.setup.tag_id} for case_id in case_ids],
        )
        tag_added = TagAddedEvent(
            tag_id=self.setup.tag_id,
            tag_ref=self.setup.tag_ref,
            tag_name=self.setup.tag_name,
        )
        self.events.extend(
            CaseEventItem(case_id=case_id, event=tag_added) for case_id in case_ids
        )

    async def _load_case_fields(self) -> None:
        """Read the current RoboDR field values of every case to update.

        A case without a custom-fields row gets one first, as
        ``CaseFieldsService.ensure_workspace_row`` does.
        """
        names = sorted(self.setup.writable_fields)
        cases = {u.case.case_id: u.case for u in self.case_updates}
        with_fields = {u.case.case_id for u in self.case_updates if u.fields}
        if not cases or not names:
            return
        fields = self.cases.fields
        table = sa.table(
            fields.sanitized_table_name,
            sa.column("id", UUID(as_uuid=True)),
            sa.column("case_id", UUID(as_uuid=True)),
            *(_field_column(name) for name in names),
            schema=fields.schema_name,
        )
        if with_fields:
            await fields._ensure_schema_ready()
            await self.session.execute(
                pg_insert(table).on_conflict_do_nothing(index_elements=["case_id"]),
                [{"id": uuid.uuid4(), "case_id": case_id} for case_id in with_fields],
            )
        rows = await self.session.execute(
            sa.select(table.c.case_id, *(table.c[name] for name in names)).where(
                table.c.case_id == sa.any_(_uuid_array(set(cases)))
            )
        )
        for row in rows.mappings().all():
            cases[row["case_id"]].fields = {name: row[name] for name in names}

    async def _write(self, findings: Mapping[str, _FindingState]) -> None:
        """Write the batch's case, event and finding changes."""
        updated_cases = {u.case.case_id: u.case for u in self.case_updates}
        await self._write_case_fields(updated_cases.values())
        await _update_many(
            self.session,
            _table_of(Case),
            "id",
            [(case.case_id, case.pending) for case in updated_cases.values()],
            extra_where=_table_of(Case).c.workspace_id == self.sender.workspace_id,
        )
        await self.cases.events.create_events(self.events)
        new_findings = [
            {**state.insert_row, **_resolve_case_ids(state.pending)}
            for state in findings.values()
            if state.insert_row is not None
        ]
        if new_findings:
            await self.session.execute(sa.insert(_table_of(RobotFinding)), new_findings)
        if self.finding_events:
            await self.session.execute(
                sa.insert(_table_of(RobotFindingEvent)), self.finding_events
            )
        await _update_many(
            self.session,
            _table_of(RobotFinding),
            "id",
            [
                (state.id, _resolve_case_ids(state.pending))
                for state in findings.values()
                if state.insert_row is None
            ],
        )

    async def _write_case_fields(self, cases: Iterable[_CaseState]) -> None:
        fields = self.cases.fields
        await _update_many(
            self.session,
            None,
            "case_id",
            [(case.case_id, case.pending_fields) for case in cases],
            table_factory=lambda names: sa.table(
                fields.sanitized_table_name,
                sa.column("case_id", UUID(as_uuid=True)),
                *(_field_column(name) for name in names),
                schema=fields.schema_name,
            ),
        )

    # --- helpers --------------------------------------------------------------------

    def _columns(self, item: _Accepted) -> dict[str, Any]:
        """The `robot_finding` columns a newer emission sets."""
        finding = item.finding
        return {
            "finding_id": finding.finding_id,
            "robot_fk": item.robot.id,
            "robot_id": finding.robot_id,
            "rule_id": finding.rule_id,
            "severity_id": finding.severity_id,
            "last_seen": _ms_to_datetime(finding.last_seen_ms),
            "occurrence_count": finding.occurrence_count,
            "last_event_uid": finding.event_uid,
            "contract_version": finding.contract_version,
            "data_source": finding.data_source,
            "raw_value": item.value.decode("utf-8"),
            "adversary_controlled_fields": list(finding.adversary_controlled_fields),
            "signature_key_id": item.signature_key_id,
            "sender_key_fk": self.sender.id,
        }

    def _fields(self, inputs: rendering.CaseInputs) -> dict[str, Any]:
        return {
            name: value
            for name, value in inputs.fields.items()
            if name in self.setup.writable_fields and value is not None
        }


def _resolve_case_ids(pending: dict[str, Any]) -> dict[str, Any]:
    """Replace a pending case link with the inserted case's id."""
    case = pending.get("case_id")
    if isinstance(case, _CaseState):
        return {**pending, "case_id": case.case_id}
    return pending


async def _update_many(
    session: AsyncSession,
    table: sa.TableClause | sa.Table | None,
    key: str,
    rows: Sequence[tuple[uuid.UUID, dict[str, Any]]],
    *,
    extra_where: sa.ColumnElement[bool] | None = None,
    table_factory: Callable[[tuple[str, ...]], sa.TableClause] | None = None,
) -> None:
    """``UPDATE table SET ... WHERE key = ...`` for many rows (executemany).

    Rows are grouped by the columns they set; rows that set nothing are
    skipped. ``onupdate`` column defaults (``updated_at``) apply as for a
    single-row update.
    """
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for row_key, values in rows:
        if values:
            names = tuple(sorted(values))
            groups.setdefault(names, []).append(
                {"b_key": row_key, **{f"b_{name}": values[name] for name in names}}
            )
    for names, params in groups.items():
        target = table_factory(names) if table_factory is not None else table
        if target is None:
            raise ValueError("a table or a table factory is required")
        statement = (
            sa.update(target)
            .where(target.c[key] == sa.bindparam("b_key"))
            .values({name: sa.bindparam(f"b_{name}") for name in names})
        )
        if extra_where is not None:
            statement = statement.where(extra_where)
        await session.execute(statement, params)


def _text_array(values: Iterable[str]) -> sa.BindParameter[Sequence[str]]:
    """An array bind for ``column = ANY(:values)``."""
    return sa.bindparam(None, list(values), type_=ARRAY(sa.Text()))


def _uuid_array(values: Iterable[uuid.UUID]) -> sa.BindParameter[Sequence[uuid.UUID]]:
    """An array bind for ``column = ANY(:values)``."""
    return sa.bindparam(None, list(values), type_=ARRAY(UUID(as_uuid=True)))


def _field_column(name: str) -> sa.ColumnClause[Any]:
    """A typed column of the workspace case-fields table."""
    if rendering.ROBOT_CASE_FIELDS[name] == "INTEGER":
        return sa.column(name, sa.BigInteger())
    return sa.column(name, sa.Text())


def _table_of(model: type[Base]) -> sa.Table:
    """The mapped table of a model (typed for Core statements)."""
    table = model.__table__
    if not isinstance(table, sa.Table):
        raise TypeError(f"{model.__name__} is not mapped to a single table")
    return table
