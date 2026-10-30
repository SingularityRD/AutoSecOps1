"""Store session and invitation bearer tokens as SHA-256 digests.

Revision ID: 3f7a9c2d5b81
Revises: 9b4d6e2f1a37
Create Date: 2026-10-30 22:00:00.000000

Session cookies (``access_token.token``) and invitation links
(``invitation.token``) were stored raw, so read access to the database was
enough to hijack a session or accept an invitation. The app now stores only
``hash_bearer_token(raw)``: unpadded URL-safe base64 of SHA-256, 43 characters.

Expand step:

- ``access_token.token_hashed`` and ``invitation.token_hashed`` (NOT NULL,
  server default false) mark which rows hold a digest. Rows the previous app
  version inserts during the rollout get false and keep working: the new app
  matches them by raw value only while the flag is false, so a digest read from
  the database is never accepted as a token.
- ``invitation.encrypted_token`` holds the raw token encrypted with
  ``AUTOSECOPS__DB_ENCRYPTION_KEY`` so the email outbox and the copy-link
  actions can still rebuild the link. The key is not in the database.

Data rewrite: every existing token is replaced by its digest in place. The
cookie and emailed link values are the raw tokens, so current sessions and
outstanding invitation links keep working. Rows hashed here have no
``encrypted_token``; the app issues them a fresh token the next time it must
reveal one (outbox send, resend, copy link, pending list), which retires the
link emailed earlier for that invitation. ``organization_invitation`` is no
longer read by the app and is hashed for at-rest hygiene only.

Rollout: while old app pods still run after this migration, they cannot match
hashed sessions or invitation links, so users routed to them must sign in
again. The contract step (a later release) rehashes rows still flagged false,
drops the raw-value fallback, and flips the server default.

Downgrade restores the previous schema but cannot recover raw tokens:

- Hashed sessions are deleted, so every user signs in again.
- Hashed invitations keep their digest in ``token``. The previous app version
  treats that value as the token, so links emailed before the downgrade stop
  working; resend the invitation or copy its link again to issue a working one.

If those effects are unacceptable, restore the database from the backup taken
before the upgrade instead of downgrading.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "3f7a9c2d5b81"
down_revision: str | None = "9b4d6e2f1a37"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Must match autosecops.auth.crypto.hash_bearer_token. encode(..., 'base64')
# wraps only past 76 characters, and a 32-byte digest encodes to 44.
HASH_TOKEN_SQL = (
    "rtrim(translate(encode(sha256(convert_to(token, 'UTF8')), 'base64'),"
    " '+/', '-_'), '=')"
)


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
    op.execute(
        f"UPDATE access_token SET token = {HASH_TOKEN_SQL}, token_hashed = true"
        " WHERE NOT token_hashed"
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
    op.execute(
        f"UPDATE invitation SET token = {HASH_TOKEN_SQL}, token_hashed = true"
        " WHERE NOT token_hashed"
    )

    op.execute(f"UPDATE organization_invitation SET token = {HASH_TOKEN_SQL}")


def downgrade() -> None:
    # The previous version cannot match a digest, so these sessions are dead
    # either way; deleting them makes that explicit.
    op.execute("DELETE FROM access_token WHERE token_hashed")
    op.drop_column("access_token", "token_hashed")
    op.drop_column("invitation", "encrypted_token")
    op.drop_column("invitation", "token_hashed")
