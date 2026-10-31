"""Invitation email delivery poller. The invitation row is its own outbox."""

from __future__ import annotations

import asyncio
import contextlib
import enum
import uuid
from typing import Final

from sqlalchemy import bindparam, exists, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import (
    Invitation,
    InvitationGrant,
    Organization,
    Role,
    Workspace,
)
from autosecops.email.transport import EmailDeliveryError, SMTPTransport
from autosecops.invitations.email import InvitationGrantLine, invitation_email
from autosecops.invitations.enums import InvitationStatus
from autosecops.invitations.service import (
    InvitationTokenUnrecoverableError,
    reveal_stored_invitation_token,
)
from autosecops.logger import logger

POLL_INTERVAL_SECONDS: Final = 2.0
CLAIM_BATCH_SIZE: Final = 20
MAX_EMAIL_ATTEMPTS: Final = 3
# Wait after the 1st, 2nd, and later consecutive deferred sends. Polling at
# POLL_INTERVAL_SECONDS would spend every attempt on a relay restart of a few
# seconds; this spreads MAX_EMAIL_ATTEMPTS over about two and a half minutes.
RETRY_BACKOFF_SECONDS: Final = (30.0, 120.0, 300.0)


class _Outcome(enum.Enum):
    IDLE = "idle"
    """Nothing left to claim."""
    HANDLED = "handled"
    """The claimed row was sent or given up on."""
    DEFERRED = "deferred"
    """The relay asked for a retry; the claim was released."""
    GAVE_UP = "gave_up"
    """The relay asked for a retry, but the row reached the attempt cap."""


async def load_invitation_grants(
    session: AsyncSession, invitation_id: uuid.UUID
) -> list[InvitationGrantLine]:
    """Resolve one invitation's grants into workspace and role display names.

    Args:
        session: The session to query.
        invitation_id: The invitation whose grants to load.

    Returns:
        One line per grant, org-wide grants first, then workspaces by name.
    """
    result = await session.execute(
        select(Workspace.name, Role.name)
        .select_from(InvitationGrant)
        .join(Role, Role.id == InvitationGrant.role_id)
        .outerjoin(Workspace, Workspace.id == InvitationGrant.workspace_id)
        .where(InvitationGrant.invitation_id == invitation_id)
        .order_by(Workspace.name.nulls_first())
    )
    return [
        InvitationGrantLine(workspace_name=workspace_name, role_name=role_name)
        for workspace_name, role_name in result.tuples()
    ]


async def deliver_next_invitation(
    session: AsyncSession, transport: SMTPTransport
) -> bool:
    """Claim the oldest unsent invitation and send it.

    Returns False when nothing is left to claim or the relay asked for a retry.
    One row is claimed per send, so a crash strands at most that row, never a batch.
    """
    return await _deliver_next(session, transport) is _Outcome.HANDLED


async def _deliver_next(session: AsyncSession, transport: SMTPTransport) -> _Outcome:
    next_id = (
        select(Invitation.id)
        .where(
            Invitation.email_claimed_at.is_(None),
            # Rendered inline so a generic plan can still prove the partial index.
            Invitation.status
            == bindparam("pending", InvitationStatus.PENDING, literal_execute=True),
            Invitation.expires_at > func.now(),
            Invitation.email_attempts
            < bindparam("attempt_cap", MAX_EMAIL_ATTEMPTS, literal_execute=True),
            # A deleted role or workspace cascades the grants away; the link
            # would 404, so the row is never emailed.
            exists().where(InvitationGrant.invitation_id == Invitation.id),
        )
        .order_by(Invitation.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    claimed = await session.execute(
        update(Invitation)
        .execution_options(synchronize_session=False)
        .where(
            Invitation.id == next_id,
            Organization.id == Invitation.organization_id,
        )
        .values(
            email_claimed_at=func.now(),
            email_attempts=Invitation.email_attempts + 1,
        )
        .returning(
            Invitation.id,
            Invitation.email,
            Invitation.token,
            Invitation.token_hashed,
            Invitation.encrypted_token,
            Invitation.email_attempts,
            Organization.name,
        )
    )
    row = claimed.one_or_none()
    if row is None:
        await session.commit()
        return _Outcome.IDLE

    (
        invitation_id,
        email,
        stored_token,
        token_hashed,
        encrypted_token,
        attempts,
        organization_name,
    ) = row.tuple()
    # Build the message inside the claim transaction: a failure here rolls the
    # claim back, since nothing has been sent yet.
    try:
        token = await reveal_stored_invitation_token(
            session,
            invitation_id=invitation_id,
            token=stored_token,
            token_hashed=token_hashed,
            encrypted_token=encrypted_token,
        )
    except InvitationTokenUnrecoverableError:
        # Retrying cannot help, and rolling the claim back would hand this row
        # to the next poll again, stalling every invitation behind it. Park it
        # at the attempt cap so only a resend re-enters it.
        await session.execute(
            update(Invitation)
            .where(Invitation.id == invitation_id)
            .values(email_claimed_at=None, email_attempts=MAX_EMAIL_ATTEMPTS)
        )
        await session.commit()
        logger.exception(
            "Invitation email skipped: its stored token cannot be decrypted with "
            "the configured database encryption key. Revoke the invitation and "
            "invite the user again",
            invitation_id=str(invitation_id),
        )
        return _Outcome.HANDLED
    grants = await load_invitation_grants(session, invitation_id)
    message = invitation_email(
        to=email,
        organization_name=organization_name,
        token=token,
        grants=grants,
    )
    # Commit the claim before SMTP: a crash mid-send leaves the row claimed
    # and unsent rather than risking a duplicate email.
    await session.commit()
    try:
        await transport.send(message)
    except EmailDeliveryError as error:
        if not error.retryable:
            logger.exception(
                "Invitation email delivery failed", invitation_id=str(invitation_id)
            )
            return _Outcome.HANDLED
        await session.execute(
            update(Invitation)
            .where(Invitation.id == invitation_id)
            .values(email_claimed_at=None)
        )
        await session.commit()
        if attempts >= MAX_EMAIL_ATTEMPTS:
            # The row is over the cap, so only a resend from the members page
            # re-enters it. Say so instead of logging another deferral.
            logger.error(
                "Invitation email delivery gave up after the attempt cap",
                invitation_id=str(invitation_id),
                attempts=attempts,
                error=str(error),
            )
            # Nothing will retry this row, so the consumer must not back off
            # for it: a resend or the next invitation goes out on the next poll.
            return _Outcome.GAVE_UP
        logger.warning(
            "Invitation email delivery deferred",
            invitation_id=str(invitation_id),
            attempts=attempts,
            error=str(error),
        )
        # Ending the tick lets the consumer back off before the retry.
        return _Outcome.DEFERRED

    await session.execute(
        update(Invitation)
        .where(Invitation.id == invitation_id)
        # Cooldown starts when sending finishes, not when the transaction began.
        .values(email_sent_at=func.clock_timestamp())
    )
    await session.commit()
    return _Outcome.HANDLED


async def run_invitation_email_tick(
    stop_event: asyncio.Event | None = None,
) -> int:
    """Deliver up to one batch. Returns the number of rows sent or given up on.

    An unconfigured relay claims nothing, so rows wait until SMTP is set up.
    A set stop event ends the batch before the next claim, so a drain-deadline
    cancel cannot strand a row claimed after the stop was signalled.
    """
    delivered, _ = await _run_batch(stop_event)
    return delivered


async def _run_batch(stop_event: asyncio.Event | None) -> tuple[int, bool]:
    """Deliver up to one batch. Returns the handled count and whether the
    batch ended on a deferred send."""
    transport = SMTPTransport.from_config()
    if transport is None:
        return 0, False
    delivered = 0
    async with get_async_session_bypass_rls_context_manager() as session:
        while delivered < CLAIM_BATCH_SIZE:
            if stop_event is not None and stop_event.is_set():
                break
            outcome = await _deliver_next(session, transport)
            if outcome is _Outcome.DEFERRED:
                return delivered, True
            if outcome is _Outcome.IDLE or outcome is _Outcome.GAVE_UP:
                break
            delivered += 1
    return delivered, False


def next_poll_delay(consecutive_deferrals: int) -> float:
    """Seconds to wait before the next tick, backing off while the relay fails."""
    if consecutive_deferrals <= 0:
        return POLL_INTERVAL_SECONDS
    index = min(consecutive_deferrals, len(RETRY_BACKOFF_SECONDS)) - 1
    return RETRY_BACKOFF_SECONDS[index]


async def _wait_for_stop(stop_event: asyncio.Event, timeout: float) -> None:
    """Sleep for `timeout` seconds, returning early once the stop event is set."""
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop_event.wait(), timeout=timeout)


async def start_invitation_email_consumer(
    stop_event: asyncio.Event | None = None,
) -> None:
    """Poll the invitation outbox until cancelled or stopped."""
    stop_event = stop_event or asyncio.Event()
    logger.info("Starting invitation email consumer")
    consecutive_deferrals = 0
    while not stop_event.is_set():
        deferred = False
        try:
            _, deferred = await _run_batch(stop_event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Invitation email tick failed")
        consecutive_deferrals = consecutive_deferrals + 1 if deferred else 0
        await _wait_for_stop(stop_event, next_poll_delay(consecutive_deferrals))
    logger.info("Invitation email consumer stopped")
