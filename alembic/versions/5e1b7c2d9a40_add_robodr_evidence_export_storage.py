"""Add RoboDR evidence export storage rows and the evidence-report file mark.

Revision ID: 5e1b7c2d9a40
Revises: 73f4dc2103c4
Create Date: 2026-10-26 16:20:00.000000

Expand-only: creates the workspace-scoped ``robot_evidence_export`` table
(tenant RLS) that records each stored RoboDR evidence export's object-storage
prefix and size, and adds ``file.robodr_evidence`` (NOT NULL, server default
``false``, a metadata-only change on PostgreSQL 11+). The previous app version
never reads either; its file inserts get ``false`` from the server default.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from autosecops.db.tenant_rls import (
    disable_workspace_table_rls,
    enable_workspace_table_rls,
)

revision: str = "5e1b7c2d9a40"
down_revision: str | None = "73f4dc2103c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "file",
        sa.Column(
            "robodr_evidence",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.create_table(
        "robot_evidence_export",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("robot_id", sa.String(length=64), nullable=False),
        sa.Column("export_id", sa.String(length=128), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("bundle_sha256", sa.String(length=64), nullable=False),
        sa.Column("bundle_bytes", sa.BigInteger(), nullable=False),
        sa.Column("storage_prefix", sa.String(length=512), nullable=False),
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
            ["case_id"],
            ["case.id"],
            name=op.f("fk_robot_evidence_export_case_id_case"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_evidence_export_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_evidence_export")),
        sa.UniqueConstraint(
            "storage_prefix", name=op.f("uq_robot_evidence_export_storage_prefix")
        ),
    )
    op.create_index(
        op.f("ix_robot_evidence_export_case_id"),
        "robot_evidence_export",
        ["case_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_robot_evidence_export_id"),
        "robot_evidence_export",
        ["id"],
        unique=True,
    )
    op.execute(enable_workspace_table_rls("robot_evidence_export"))


def downgrade() -> None:
    op.execute(disable_workspace_table_rls("robot_evidence_export"))
    op.drop_index(
        op.f("ix_robot_evidence_export_id"), table_name="robot_evidence_export"
    )
    op.drop_index(
        op.f("ix_robot_evidence_export_case_id"), table_name="robot_evidence_export"
    )
    op.drop_table("robot_evidence_export")
    op.drop_column("file", "robodr_evidence")
