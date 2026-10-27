"""Add RoboDR fleet enrollment, key rotation, distribution and SOC keys.

Revision ID: 73f4dc2103c4
Revises: c183599683b2
Create Date: 2026-10-26 15:25:19.592966

Expand-only (robodr.fleet API v1): creates eight new workspace-scoped tables
with tenant RLS, adds four nullable fleet columns to ``robot``, an index on
``robot_key.public_key`` (SOC-wide fingerprint uniqueness) and widens the
``robot_key`` role check with ``blackbox``. The previous app version never
reads the new tables or columns and never writes a ``blackbox`` key, so it
keeps running unchanged. ``downgrade()`` refuses to narrow the role check
while ``blackbox`` keys exist (delete them first or restore a backup).
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from autosecops.db.tenant_rls import (
    disable_workspace_table_rls,
    enable_workspace_table_rls,
)

revision: str = "73f4dc2103c4"
down_revision: str | None = "c183599683b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = (
    "robot_fleet_soc_key",
    "robot_fleet_token",
    "robot_fleet_rotation",
    "robot_fleet_revocation_list",
    "robot_fleet_profile_draft",
    "robot_fleet_profile_offer",
    "robot_fleet_approval",
    "robot_fleet_ring",
)


def upgrade() -> None:
    op.create_table(
        "robot_fleet_revocation_list",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("serial", sa.BigInteger(), nullable=False),
        sa.Column("list_digest", sa.String(length=71), nullable=False),
        sa.Column("signer_key_id", sa.String(length=64), nullable=False),
        sa.Column(
            "signature_checked",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            ["created_by"],
            ["user.id"],
            name=op.f("fk_robot_fleet_revocation_list_created_by_user"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_revocation_list_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "surrogate_id", name=op.f("pk_robot_fleet_revocation_list")
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "platform",
            "serial",
            name=op.f("uq_robot_fleet_revocation_list_workspace_id_platform_serial"),
        ),
    )
    op.create_index(
        op.f("ix_robot_fleet_revocation_list_id"),
        "robot_fleet_revocation_list",
        ["id"],
        unique=True,
    )
    op.create_table(
        "robot_fleet_soc_key",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_seed", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("activated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("retired_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            "kind IN ('fleet', 'approval')", name=op.f("ck_robot_fleet_soc_key_kind")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'retired')",
            name=op.f("ck_robot_fleet_soc_key_status"),
        ),
        sa.CheckConstraint(
            "octet_length(public_key) = 32",
            name=op.f("ck_robot_fleet_soc_key_public_key_length"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["user.id"],
            name=op.f("fk_robot_fleet_soc_key_created_by_user"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_soc_key_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_fleet_soc_key")),
        sa.UniqueConstraint("key_id", name=op.f("uq_robot_fleet_soc_key_key_id")),
    )
    op.create_index(
        "ix_robot_fleet_soc_key_active_kind",
        "robot_fleet_soc_key",
        ["workspace_id", "kind"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        op.f("ix_robot_fleet_soc_key_id"), "robot_fleet_soc_key", ["id"], unique=True
    )
    op.create_table(
        "robot_fleet_approval",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("approval_id", sa.String(length=64), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("profile_digest", sa.String(length=71), nullable=False),
        sa.Column("profile_version", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("validity_ms", sa.BigInteger(), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=True),
        sa.Column("approved_by", sa.UUID(), nullable=True),
        sa.Column("issued_at_ms", sa.BigInteger(), nullable=True),
        sa.Column("expires_at_ms", sa.BigInteger(), nullable=True),
        sa.Column("signer_key_id", sa.String(length=32), nullable=True),
        sa.Column("envelope", sa.LargeBinary(), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            "status IN ('pending', 'signed', 'cancelled')",
            name=op.f("ck_robot_fleet_approval_status"),
        ),
        sa.CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name=op.f("ck_robot_fleet_approval_two_person"),
        ),
        sa.CheckConstraint(
            "validity_ms > 0 AND validity_ms <= 604800000",
            name=op.f("ck_robot_fleet_approval_validity"),
        ),
        sa.ForeignKeyConstraint(
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_fleet_approval_robot_fk_robot"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_approval_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_fleet_approval")),
        sa.UniqueConstraint(
            "approval_id", name=op.f("uq_robot_fleet_approval_approval_id")
        ),
    )
    op.create_index(
        op.f("ix_robot_fleet_approval_id"), "robot_fleet_approval", ["id"], unique=True
    )
    op.create_index(
        "ix_robot_fleet_approval_robot_digest",
        "robot_fleet_approval",
        ["robot_fk", "profile_digest"],
        unique=False,
    )
    op.create_table(
        "robot_fleet_profile_draft",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=False),
        sa.Column("digest", sa.String(length=71), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_fleet_profile_draft_robot_fk_robot"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_profile_draft_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "surrogate_id", name=op.f("pk_robot_fleet_profile_draft")
        ),
        sa.UniqueConstraint(
            "robot_fk",
            "digest",
            name=op.f("uq_robot_fleet_profile_draft_robot_fk_digest"),
        ),
    )
    op.create_index(
        op.f("ix_robot_fleet_profile_draft_id"),
        "robot_fleet_profile_draft",
        ["id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_robot_fleet_profile_draft_robot_fk"),
        "robot_fleet_profile_draft",
        ["robot_fk"],
        unique=False,
    )
    op.create_table(
        "robot_fleet_profile_offer",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=False),
        sa.Column("profile_version", sa.BigInteger(), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("digest", sa.String(length=71), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            ["created_by"],
            ["user.id"],
            name=op.f("fk_robot_fleet_profile_offer_created_by_user"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_fleet_profile_offer_robot_fk_robot"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_profile_offer_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "surrogate_id", name=op.f("pk_robot_fleet_profile_offer")
        ),
        sa.UniqueConstraint(
            "robot_fk", name=op.f("uq_robot_fleet_profile_offer_robot_fk")
        ),
    )
    op.create_index(
        op.f("ix_robot_fleet_profile_offer_id"),
        "robot_fleet_profile_offer",
        ["id"],
        unique=True,
    )
    op.create_table(
        "robot_fleet_ring",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=False),
        sa.Column("serial", sa.BigInteger(), nullable=False),
        sa.Column("ring", sa.Integer(), nullable=False),
        sa.Column("target_version", sa.String(length=64), nullable=True),
        sa.Column("bundle_sha256", sa.String(length=64), nullable=True),
        sa.Column("min_version", sa.String(length=64), nullable=True),
        sa.Column("issued_at_ms", sa.BigInteger(), nullable=False),
        sa.Column("expires_at_ms", sa.BigInteger(), nullable=False),
        sa.Column("envelope", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            ["created_by"],
            ["user.id"],
            name=op.f("fk_robot_fleet_ring_created_by_user"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_fleet_ring_robot_fk_robot"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_ring_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_fleet_ring")),
        sa.UniqueConstraint(
            "robot_fk", "serial", name=op.f("uq_robot_fleet_ring_robot_fk_serial")
        ),
    )
    op.create_index(
        op.f("ix_robot_fleet_ring_id"), "robot_fleet_ring", ["id"], unique=True
    )
    op.create_table(
        "robot_fleet_rotation",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("rotation_id", sa.String(length=40), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("old_key_id", sa.String(length=32), nullable=False),
        sa.Column("new_key_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("request_digest", sa.String(length=71), nullable=False),
        sa.Column("rotate_answer", sa.LargeBinary(), nullable=True),
        sa.Column("retire_digest", sa.String(length=71), nullable=True),
        sa.Column("retire_answer", sa.LargeBinary(), nullable=True),
        sa.Column("cancel_digest", sa.String(length=71), nullable=True),
        sa.Column("cancel_answer", sa.LargeBinary(), nullable=True),
        sa.Column("closed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            "role IN ('uplink', 'finding')", name=op.f("ck_robot_fleet_rotation_role")
        ),
        sa.CheckConstraint(
            "status IN ('open', 'retired', 'cancelled')",
            name=op.f("ck_robot_fleet_rotation_status"),
        ),
        sa.ForeignKeyConstraint(
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_fleet_rotation_robot_fk_robot"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_rotation_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_fleet_rotation")),
        sa.UniqueConstraint(
            "rotation_id", name=op.f("uq_robot_fleet_rotation_rotation_id")
        ),
    )
    op.create_index(
        op.f("ix_robot_fleet_rotation_id"), "robot_fleet_rotation", ["id"], unique=True
    )
    op.create_index(
        "ix_robot_fleet_rotation_open_role",
        "robot_fleet_rotation",
        ["robot_fk", "role"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )
    op.create_index(
        op.f("ix_robot_fleet_rotation_robot_fk"),
        "robot_fleet_rotation",
        ["robot_fk"],
        unique=False,
    )
    op.create_table(
        "robot_fleet_token",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("token_id", sa.String(length=64), nullable=False),
        sa.Column("fleet_workspace", sa.String(length=64), nullable=False),
        sa.Column("robot_id", sa.String(length=64), nullable=False),
        sa.Column("site", sa.String(length=64), nullable=True),
        sa.Column("soc_key_id", sa.String(length=32), nullable=False),
        sa.Column("issued_at_ms", sa.BigInteger(), nullable=False),
        sa.Column("expires_at_ms", sa.BigInteger(), nullable=False),
        sa.Column("encrypted_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("robot_fk", sa.UUID(), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("request_digest", sa.String(length=71), nullable=True),
        sa.Column("answer", sa.LargeBinary(), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("surrogate_id", sa.Integer(), nullable=False),
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
            "expires_at_ms > issued_at_ms AND expires_at_ms - issued_at_ms <= 604800000",
            name=op.f("ck_robot_fleet_token_validity"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["user.id"],
            name=op.f("fk_robot_fleet_token_created_by_user"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["robot_fk"],
            ["robot.id"],
            name=op.f("fk_robot_fleet_token_robot_fk_robot"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f("fk_robot_fleet_token_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f("pk_robot_fleet_token")),
        sa.UniqueConstraint("token_id", name=op.f("uq_robot_fleet_token_token_id")),
    )
    op.create_index(
        op.f("ix_robot_fleet_token_id"), "robot_fleet_token", ["id"], unique=True
    )
    op.create_index(
        op.f("ix_robot_fleet_token_robot_fk"),
        "robot_fleet_token",
        ["robot_fk"],
        unique=False,
    )
    op.add_column(
        "robot", sa.Column("fleet_workspace", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "robot",
        sa.Column("fleet_enrolled_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "robot", sa.Column("fleet_agentd_version", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "robot", sa.Column("fleet_profile_digest", sa.String(length=71), nullable=True)
    )

    op.create_index(
        "ix_robot_key_public_key", "robot_key", ["public_key"], unique=False
    )
    # Widen the role check: add the new constraint before dropping the old one.
    op.create_check_constraint(
        op.f("ck_robot_key_role_v2"),
        "robot_key",
        "role IN ('uplink', 'relay', 'finding', 'blackbox')",
    )
    op.drop_constraint(op.f("ck_robot_key_role"), "robot_key", type_="check")
    for table in _TABLES:
        op.execute(enable_workspace_table_rls(table))


def downgrade() -> None:
    bind = op.get_bind()
    blackbox = bind.execute(
        sa.text("SELECT count(*) FROM robot_key WHERE role = 'blackbox'")
    ).scalar_one()
    if blackbox:
        raise NotImplementedError(
            "robot_key holds blackbox keys, which the previous role check "
            "refuses: delete them (or restore a backup) before downgrading"
        )
    op.create_check_constraint(
        op.f("ck_robot_key_role"),
        "robot_key",
        "role IN ('uplink', 'relay', 'finding')",
    )
    op.drop_constraint(op.f("ck_robot_key_role_v2"), "robot_key", type_="check")
    op.drop_index("ix_robot_key_public_key", table_name="robot_key")
    for column in (
        "fleet_profile_digest",
        "fleet_agentd_version",
        "fleet_enrolled_at",
        "fleet_workspace",
    ):
        op.drop_column("robot", column)
    for table in reversed(_TABLES):
        op.execute(disable_workspace_table_rls(table))
        op.drop_table(table)
