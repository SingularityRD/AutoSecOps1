"""Add RoboDR robot action audit attempts.

Revision ID: 7d3e9b1c4a52
Revises: b8d2f4a61c37
Create Date: 2026-10-30 10:00:00.000000

Expand-only: creates the workspace-scoped ``robot_action_audit`` table
(tenant RLS). Each row is the audited attempt of one robot action request or
revert; the outcome event of the same call must match an open row and closes
it. The previous app version never reads or writes it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from autosecops.db.tenant_rls import (
    disable_workspace_table_rls,
    enable_workspace_table_rls,
)

revision: str = "7d3e9b1c4a52"
down_revision: str | None = "b8d2f4a61c37"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "robot_action_audit",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column("robot_id", sa.String(length=64), nullable=False),
        sa.Column("robot_action", sa.String(length=80), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("request_submission_id", sa.UUID(), nullable=False),
        sa.Column(
            "approval_submission_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("requested_by_user_id", sa.UUID(), nullable=False),
        sa.Column(
            "approved_by_user_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("workflow_id", sa.String(length=255), nullable=False),
        sa.Column("run_id", sa.String(length=255), nullable=False),
        sa.Column("agent_session_id", sa.UUID(), nullable=True),
        sa.Column("closed_phase", sa.String(length=16), nullable=True),
        sa.Column("closed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_action_audit_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_action_audit")),
    )
    op.create_index(
        op.f("ix_robot_action_audit_id"),
        "robot_action_audit",
        ["id"],
        unique=True,
    )
    op.execute(enable_workspace_table_rls("robot_action_audit"))


def downgrade() -> None:
    op.execute(disable_workspace_table_rls("robot_action_audit"))
    op.drop_index(op.f("ix_robot_action_audit_id"), table_name="robot_action_audit")
    op.drop_table("robot_action_audit")
