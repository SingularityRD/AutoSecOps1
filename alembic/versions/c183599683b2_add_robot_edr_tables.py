"""Add RoboDR robot registry, keys, findings, finding events, ingest batches.

Revision ID: c183599683b2
Revises: 07c9a895bd57
Create Date: 2026-10-26 10:10:56.669416

Expand-only: creates five new workspace-scoped tables with tenant RLS. The
previous app version never reads them, so it keeps running unchanged.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from autosecops.db.tenant_rls import (
    disable_workspace_table_rls,
    enable_workspace_table_rls,
)

revision: str = "c183599683b2"
down_revision: str | None = "07c9a895bd57"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = (
    "robot",
    "robot_key",
    "robot_finding",
    "robot_finding_event",
    "robot_ingest_batch",
)


def upgrade() -> None:
    op.create_table(
        "robot",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("robot_id", sa.String(length=64), nullable=False),
        sa.Column("site", sa.String(length=128), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("morphology", sa.String(length=64), nullable=True),
        sa.Column(
            "require_finding_signature",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
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
            name=op.f("fk_robot_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot")),
        sa.UniqueConstraint(
            "workspace_id", "robot_id", name=op.f("uq_robot_workspace_id_robot_id")
        ),
    )
    op.create_index(op.f("ix_robot_id"), "robot", ["id"], unique=True)
    op.create_table(
        "robot_key",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=True),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("site", sa.String(length=128), nullable=True),
        sa.Column(
            "vouches_origin",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
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
        sa.CheckConstraint(
            "(role = 'relay') = (robot_fk IS NULL)",
            name=op.f("ck_robot_key_robot_binding"),
        ),
        sa.CheckConstraint(
            "role IN ('uplink', 'relay', 'finding')", name=op.f("ck_robot_key_role")
        ),
        sa.CheckConstraint(
            "octet_length(public_key) = 32", name=op.f("ck_robot_key_public_key_length")
        ),
        sa.CheckConstraint(
            "role = 'relay' OR (site IS NULL AND NOT vouches_origin)",
            name=op.f("ck_robot_key_relay_only_options"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["user.id"],
            name=op.f("fk_robot_key_created_by_user"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_key_robot_fk_robot"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_key_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_key")),
        sa.UniqueConstraint(
            "workspace_id", "key_id", name=op.f("uq_robot_key_workspace_id_key_id")
        ),
    )
    op.create_index(
        "ix_robot_key_active_sender_key_id",
        "robot_key",
        ["key_id"],
        unique=True,
        postgresql_where=sa.text("role IN ('uplink', 'relay') AND revoked_at IS NULL"),
    )
    op.create_index(op.f("ix_robot_key_id"), "robot_key", ["id"], unique=True)
    op.create_index(op.f("ix_robot_key_key_id"), "robot_key", ["key_id"], unique=False)
    op.create_index(
        op.f("ix_robot_key_robot_fk"), "robot_key", ["robot_fk"], unique=False
    )
    op.create_table(
        "robot_finding",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=True),
        sa.Column("robot_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("severity_id", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.BigInteger(), nullable=False),
        sa.Column("last_event_uid", sa.String(length=36), nullable=False),
        sa.Column("contract_version", sa.String(length=32), nullable=False),
        sa.Column("data_source", sa.String(length=64), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=False),
        sa.Column(
            "adversary_controlled_fields",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("signature_key_id", sa.String(length=128), nullable=True),
        sa.Column("sender_key_fk", sa.UUID(), nullable=True),
        sa.Column("case_id", sa.UUID(), nullable=True),
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
            name=op.f("fk_robot_finding_case_id_case"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_finding_robot_fk_robot"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["sender_key_fk"],
            ["robot_key.id"],
            name=op.f("fk_robot_finding_sender_key_fk_robot_key"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_finding_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_finding")),
        sa.UniqueConstraint(
            "workspace_id",
            "external_id",
            name=op.f("uq_robot_finding_workspace_id_external_id"),
        ),
    )
    op.create_index(
        op.f("ix_robot_finding_case_id"), "robot_finding", ["case_id"], unique=False
    )
    op.create_index(op.f("ix_robot_finding_id"), "robot_finding", ["id"], unique=True)
    op.create_index(
        "ix_robot_finding_robot_fk_last_seen",
        "robot_finding",
        ["robot_fk", "last_seen"],
        unique=False,
    )
    op.create_table(
        "robot_finding_event",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("finding_fk", sa.UUID(), nullable=False),
        sa.Column("event_uid", sa.String(length=36), nullable=False),
        sa.Column("occurrence_count", sa.BigInteger(), nullable=False),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("severity_id", sa.Integer(), nullable=False),
        sa.Column("sender_key_fk", sa.UUID(), nullable=True),
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
            ["finding_fk"],
            ["robot_finding.id"],
            name=op.f("fk_robot_finding_event_finding_fk_robot_finding"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["sender_key_fk"],
            ["robot_key.id"],
            name=op.f("fk_robot_finding_event_sender_key_fk_robot_key"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_finding_event_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_finding_event")),
        sa.UniqueConstraint(
            "finding_fk",
            "event_uid",
            name=op.f("uq_robot_finding_event_finding_fk_event_uid"),
        ),
    )
    op.create_index(
        op.f("ix_robot_finding_event_id"), "robot_finding_event", ["id"], unique=True
    )
    op.create_table(
        "robot_ingest_batch",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("sender_key_fk", sa.UUID(), nullable=False),
        sa.Column("batch_id", sa.String(length=64), nullable=False),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column("response", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
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
            ["sender_key_fk"],
            ["robot_key.id"],
            name=op.f("fk_robot_ingest_batch_sender_key_fk_robot_key"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_ingest_batch_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_ingest_batch")),
        sa.UniqueConstraint(
            "sender_key_fk",
            "batch_id",
            name=op.f("uq_robot_ingest_batch_sender_key_fk_batch_id"),
        ),
    )
    op.create_index(
        "ix_robot_ingest_batch_created_at",
        "robot_ingest_batch",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_robot_ingest_batch_id"), "robot_ingest_batch", ["id"], unique=True
    )
    for table in _TABLES:
        op.execute(enable_workspace_table_rls(table))


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(disable_workspace_table_rls(table))
    op.drop_table("robot_ingest_batch")
    op.drop_table("robot_finding_event")
    op.drop_table("robot_finding")
    op.drop_table("robot_key")
    op.drop_table("robot")
