"""Add the email verification outbox and grandfather existing accounts.

Revision ID: 7e3c9b1d5a20
Revises: d3a7e5c1b9f2
Create Date: 2026-10-31 12:00:00.000000

Password sign-in now requires a verified email. Accounts that exist before this
release were admitted under the old policy, so they are marked verified here
and nobody is locked out on upgrade. The new table is additive; the previous
app version never reads it.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "7e3c9b1d5a20"
down_revision: str | None = "d3a7e5c1b9f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "email_verification_outbox",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "requested_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "attempts", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("sent_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    # Grandfather every existing account: before this release no flow could
    # verify an address, so is_verified=false carried no meaning.
    op.execute(sa.text('UPDATE "user" SET is_verified = true WHERE NOT is_verified'))


def downgrade() -> None:
    # The is_verified backfill is intentionally kept: earlier versions do not
    # gate sign-in on it, and the pre-upgrade values are not recoverable.
    op.drop_table("email_verification_outbox")
