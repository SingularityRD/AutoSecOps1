"""Record the names a RoboDR robot action sends.

Revision ID: 4c8e2a9f6b13
Revises: 7d3e9b1c4a52
Create Date: 2026-10-30 13:00:00.000000

Expand-only: adds two nullable columns to ``robot_action_audit``, the
``requested_by`` and ``approved_by`` names the robot is sent, checked against
the sign-off submitters. The previous app version never reads or writes
them; existing rows keep ``NULL`` (not reported).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "4c8e2a9f6b13"
down_revision: str | None = "7d3e9b1c4a52"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "robot_action_audit",
        sa.Column("requested_by_name", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "robot_action_audit",
        sa.Column(
            "approved_by_names",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("robot_action_audit", "approved_by_names")
    op.drop_column("robot_action_audit", "requested_by_name")
