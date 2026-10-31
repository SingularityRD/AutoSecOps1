"""Add columns for storing session and invitation tokens as digests.

Revision ID: 3f7a9c2d5b81
Revises: 9b4d6e2f1a37
Create Date: 2026-10-30 22:00:00.000000

Session cookies (``access_token.token``) and invitation links
(``invitation.token``) were stored raw, so read access to the database was
enough to hijack a session or accept an invitation. From this release the app
writes only ``hash_bearer_token(raw)``: unpadded URL-safe base64 of SHA-256,
43 characters.

This is the expand step only. It adds columns and rewrites no existing data,
because the Helm pre-upgrade job (and any rolling Fargate deployment) keeps the
previous app version serving against the migrated schema:

- ``access_token.token_hashed`` and ``invitation.token_hashed`` (NOT NULL,
  server default false) mark which rows hold a digest. Every existing row, and
  every row the previous app version inserts during the rollout, keeps its raw
  token with the flag false, so both app versions keep reading it the same way.
  The new app matches a raw row by raw value only while the flag is false.
- ``invitation.encrypted_token`` holds the raw token of rows the new app writes,
  encrypted with ``AUTOSECOPS__DB_ENCRYPTION_KEY``, so the email outbox and the
  copy-link actions can still rebuild the link. The key is not in the database.

Adding a NOT NULL column with a constant default is a catalog-only change on
PostgreSQL 11 and later: the ACCESS EXCLUSIVE locks are held only briefly and
no table is rewritten.

Contract step (a later release, once no pre-hashing app version can run):
delete expired ``access_token`` rows so only live sessions are rewritten, hash
the rows still flagged false (including ``organization_invitation``), flip the
server defaults to true, and drop the raw-value fallback. Invitations hashed
there have no ``encrypted_token``; the app already issues them a fresh token
the next time it must reveal one.

Downgrade drops the new columns. The previous version cannot use a digest:

- Sessions created after the upgrade are deleted, so those users sign in again.
- Pending invitations created after the upgrade are revoked (the count is
  logged), so their stored digest can never be accepted as a link token by the
  previous version. Invite those users again after the downgrade.

Rows written before the upgrade are untouched and keep working. To roll back
without these effects, restore the database from the backup taken before the
upgrade instead of downgrading.
"""

import logging
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "3f7a9c2d5b81"
down_revision: str | None = "9b4d6e2f1a37"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    op.add_column(
        "access_token",
        sa.Column(
            "token_hashed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "invitation",
        sa.Column(
            "token_hashed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "invitation",
        sa.Column("encrypted_token", sa.LargeBinary(), nullable=True),
    )


def downgrade() -> None:
    bind = op.get_bind()
    # The previous version cannot match a digest, so these sessions are dead
    # either way; deleting them makes that explicit.
    deleted = bind.execute(
        sa.text("DELETE FROM access_token WHERE token_hashed")
    ).rowcount
    # The previous version would treat a stored digest as the link token, so
    # anyone able to read it could accept the invitation. Revoke them instead.
    revoked = bind.execute(
        sa.text(
            "UPDATE invitation SET status = 'REVOKED'"
            " WHERE token_hashed AND status = 'PENDING'"
        )
    ).rowcount
    logger.warning(
        "Downgrade of 3f7a9c2d5b81 deleted %d hashed sessions and revoked %d "
        "pending invitations created after the upgrade; invite those users again",
        deleted,
        revoked,
    )
    op.drop_column("access_token", "token_hashed")
    op.drop_column("invitation", "encrypted_token")
    op.drop_column("invitation", "token_hashed")
