"""Email verification: token minting, the outbox, and the delivery poller.

A request writes one ``email_verification_outbox`` row per account. No token
is stored: the poller mints a signed, short-lived token when it claims the row,
so neither the database nor a backup holds a usable verification link. The
token is a JWT signed with the user auth secret, bound to the account ID and
its current email, and spent once the account is verified. Redeeming it also
sets the account password (see ``UserManager.verify_with_password``).
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import uuid
from datetime import timedelta
from html import escape
from typing import Final
from urllib.parse import urlencode

from fastapi_users import BaseUserManager
from fastapi_users.jwt import generate_jwt
from sqlalchemy import and_, bindparam, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops import config
from autosecops.auth.secrets import get_user_auth_secret
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import EmailVerificationOutbox, User
from autosecops.email.transport import (
    SEND_DEADLINE_SECONDS,
    EmailDeliveryError,
    OutboundEmail,
    SMTPTransport,
)
from autosecops.logger import logger

VERIFY_EMAIL_PATH: Final = "/verify-email"
VERIFY_TOKEN_AUDIENCE: Final = BaseUserManager.verification_token_audience
POLL_INTERVAL_SECONDS: Final = 2.0
CLAIM_BATCH_SIZE: Final = 20
MAX_EMAIL_ATTEMPTS: Final = 3
RETRY_BACKOFF_SECONDS: Final = (30.0, 120.0, 300.0)
RESEND_COOLDOWN: Final = timedelta(seconds=60)
"""Minimum time between two verification emails to one account."""
STALE_CLAIM: Final = timedelta(seconds=SEND_DEADLINE_SECONDS * 4)
"""A claim older than this was stranded by a crash and may be re-requested."""


# fastapi-users declares the user columns without SQLAlchemy typing, so the
# queries here go through the table's typed column collection.
_USERS = User.__table__


class _Outcome(enum.Enum):
    IDLE = "idle"
    HANDLED = "handled"
    DEFERRED = "deferred"
    GAVE_UP = "gave_up"


def email_verification_available() -> bool:
    """Whether verification emails can be delivered (SMTP is configured)."""
    return SMTPTransport.from_config() is not None


def create_verification_token(*, user_id: uuid.UUID, email: str) -> str:
    """Mint a verification token that ``BaseUserManager.verify`` accepts.

    Args:
        user_id: The account to verify.
        email: The account's current email; a later change voids the token.

    Returns:
        A signed JWT valid for the configured verification lifetime.
    """
    return generate_jwt(
        {"sub": str(user_id), "email": email, "aud": VERIFY_TOKEN_AUDIENCE},
        get_user_auth_secret(),
        config.AUTOSECOPS__AUTH_EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS,
    )


def verification_url(token: str) -> str:
    """Build the frontend link that submits ``token``."""
    base = config.AUTOSECOPS__PUBLIC_APP_URL.rstrip("/")
    return f"{base}{VERIFY_EMAIL_PATH}?{urlencode({'token': token})}"


def verification_email(*, to: str, token: str) -> OutboundEmail:
    """Render the verification email for one account."""
    url = verification_url(token)
    safe_url = escape(url, quote=True)
    minutes = config.AUTOSECOPS__AUTH_EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS // 60
    logo_url = escape(
        f"{config.AUTOSECOPS__PUBLIC_APP_URL.rstrip('/')}/icon.png", quote=True
    )
    subject = "Verify your email for AutoSecOps"
    body = (
        "Confirm this email address and set the password for your AutoSecOps "
        f"account. The link expires in {minutes} minutes and works once."
    )
    footer = (
        "If you didn't create an AutoSecOps account, you can ignore this email. "
        "Nobody can sign in to the account until a password is set from this link."
    )
    html = f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f5f5f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#111114;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f7;padding:40px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border:1px solid #e6e6ea;border-radius:10px;">
            <tr><td style="padding:32px 32px 0 32px;"><img src="{logo_url}" width="36" height="36" alt="AutoSecOps" style="display:block;border-radius:9px;" /></td></tr>
            <tr><td style="padding:24px 32px 0 32px;font-size:20px;font-weight:600;">Verify your email</td></tr>
            <tr><td style="padding:12px 32px 0 32px;font-size:14px;line-height:1.6;color:#3c3c43;">{escape(body)}</td></tr>
            <tr><td style="padding:24px 32px 0 32px;"><a href="{safe_url}" style="display:inline-block;background:#111114;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 18px;border-radius:8px;">Verify email</a></td></tr>
            <tr><td style="padding:24px 32px 32px 32px;font-size:12px;line-height:1.6;color:#6e6e78;">{escape(footer)}</td></tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
    text = f"{body}\n\nVerify your email: {url}\n\n{footer}\n"
    return OutboundEmail(to=(to,), subject=subject, html=html, text=text)


async def enqueue_verification_email(session: AsyncSession, user_id: uuid.UUID) -> bool:
    """Queue a verification email for one account, honouring the resend cooldown.

    A row that is waiting is left in place; one sent within ``RESEND_COOLDOWN``
    or claimed by a sender within ``STALE_CLAIM`` is not re-queued.

    Args:
        session: The session to write with. The caller commits.
        user_id: The account to send to.

    Returns:
        Whether the account now has a send waiting.
    """
    now = func.now()
    in_flight = and_(
        EmailVerificationOutbox.claimed_at.is_not(None),
        or_(
            EmailVerificationOutbox.sent_at.is_(None),
            EmailVerificationOutbox.sent_at < EmailVerificationOutbox.claimed_at,
        ),
        EmailVerificationOutbox.claimed_at > now - STALE_CLAIM,
    )
    cooled_down = or_(
        EmailVerificationOutbox.sent_at.is_(None),
        EmailVerificationOutbox.sent_at < now - RESEND_COOLDOWN,
    )
    statement = (
        pg_insert(EmailVerificationOutbox)
        .values(user_id=user_id, attempts=0)
        .on_conflict_do_update(
            index_elements=[EmailVerificationOutbox.user_id],
            set_={"requested_at": now, "claimed_at": None, "attempts": 0},
            where=and_(~in_flight, cooled_down),
        )
        .returning(EmailVerificationOutbox.user_id)
    )
    result = await session.execute(statement)
    return result.scalar_one_or_none() is not None


async def clear_verification_email(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Drop any queued verification email for an account. The caller commits."""
    await session.execute(
        delete(EmailVerificationOutbox).where(
            EmailVerificationOutbox.user_id == user_id
        )
    )


async def deliver_next_verification(
    session: AsyncSession, transport: SMTPTransport
) -> bool:
    """Claim the oldest waiting verification email and send it.

    Returns:
        False when nothing is left or the relay asked for a retry.
    """
    return await _deliver_next(session, transport) is _Outcome.HANDLED


async def _deliver_next(session: AsyncSession, transport: SMTPTransport) -> _Outcome:
    next_id = (
        select(EmailVerificationOutbox.user_id)
        .join(_USERS, _USERS.c.id == EmailVerificationOutbox.user_id)
        .where(
            EmailVerificationOutbox.claimed_at.is_(None),
            EmailVerificationOutbox.attempts
            < bindparam("attempt_cap", MAX_EMAIL_ATTEMPTS, literal_execute=True),
            # A verified or deactivated account is never mailed.
            _USERS.c.is_verified.is_(False),
            _USERS.c.is_active.is_(True),
        )
        .order_by(EmailVerificationOutbox.requested_at)
        .limit(1)
        .with_for_update(of=EmailVerificationOutbox, skip_locked=True)
        .scalar_subquery()
    )
    claimed = await session.execute(
        update(EmailVerificationOutbox)
        .execution_options(synchronize_session=False)
        .where(
            EmailVerificationOutbox.user_id == next_id,
            _USERS.c.id == EmailVerificationOutbox.user_id,
        )
        .values(
            claimed_at=func.now(),
            attempts=EmailVerificationOutbox.attempts + 1,
        )
        .returning(
            EmailVerificationOutbox.user_id,
            _USERS.c.email,
            EmailVerificationOutbox.attempts,
        )
    )
    row = claimed.one_or_none()
    if row is None:
        await session.commit()
        return _Outcome.IDLE

    user_id, email, attempts = row
    message = verification_email(
        to=email, token=create_verification_token(user_id=user_id, email=email)
    )
    # Commit the claim before SMTP: a crash mid-send leaves the row claimed
    # rather than risking a duplicate email.
    await session.commit()
    try:
        await transport.send(message)
    except EmailDeliveryError as error:
        if not error.retryable:
            logger.exception("Verification email delivery failed", user_id=str(user_id))
            return _Outcome.HANDLED
        await session.execute(
            update(EmailVerificationOutbox)
            .where(EmailVerificationOutbox.user_id == user_id)
            .values(claimed_at=None)
        )
        await session.commit()
        if attempts >= MAX_EMAIL_ATTEMPTS:
            logger.error(
                "Verification email delivery gave up after the attempt cap",
                user_id=str(user_id),
                attempts=attempts,
                error=str(error),
            )
            return _Outcome.GAVE_UP
        logger.warning(
            "Verification email delivery deferred",
            user_id=str(user_id),
            attempts=attempts,
            error=str(error),
        )
        return _Outcome.DEFERRED

    await session.execute(
        update(EmailVerificationOutbox)
        .where(EmailVerificationOutbox.user_id == user_id)
        .values(sent_at=func.clock_timestamp())
    )
    await session.commit()
    logger.info("Verification email sent", user_id=str(user_id))
    return _Outcome.HANDLED


async def _run_batch(stop_event: asyncio.Event | None) -> tuple[int, bool]:
    """Deliver up to one batch; return the handled count and whether it deferred."""
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


async def run_verification_email_tick(stop_event: asyncio.Event | None = None) -> int:
    """Deliver up to one batch. Returns the number of rows sent or given up on."""
    delivered, _ = await _run_batch(stop_event)
    return delivered


def next_poll_delay(consecutive_deferrals: int) -> float:
    """Seconds to wait before the next tick, backing off while the relay fails."""
    if consecutive_deferrals <= 0:
        return POLL_INTERVAL_SECONDS
    index = min(consecutive_deferrals, len(RETRY_BACKOFF_SECONDS)) - 1
    return RETRY_BACKOFF_SECONDS[index]


async def start_verification_email_consumer(
    stop_event: asyncio.Event | None = None,
) -> None:
    """Poll the verification outbox until cancelled or stopped."""
    stop_event = stop_event or asyncio.Event()
    logger.info("Starting email verification consumer")
    consecutive_deferrals = 0
    while not stop_event.is_set():
        deferred = False
        try:
            _, deferred = await _run_batch(stop_event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Email verification tick failed")
        consecutive_deferrals = consecutive_deferrals + 1 if deferred else 0
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), timeout=next_poll_delay(consecutive_deferrals)
            )
    logger.info("Email verification consumer stopped")
