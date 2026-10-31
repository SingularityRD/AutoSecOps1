"""Add an optional expiry time to service account API keys.

Revision ID: d3a7e5c1b9f2
Revises: 21042b4645f1
Create Date: 2026-10-30 23:30:00.000000

Expand-only: the column is nullable and existing keys keep ``NULL``, which
means "never expires", so every key that authenticates today keeps working.
The previous app version neither reads nor writes the column. The downgrade
drops it, which discards the expiry of keys issued with one; those keys then
never expire under the previous app version.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d3a7e5c1b9f2"
down_revision: str | None = "21042b4645f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "service_account_api_key",
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("service_account_api_key", "expires_at")
