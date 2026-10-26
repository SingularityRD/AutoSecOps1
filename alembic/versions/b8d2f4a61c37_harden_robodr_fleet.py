"""Harden the RoboDR fleet API: trust roots, key registry, offline approvals.

Revision ID: b8d2f4a61c37
Revises: 5e1b7c2d9a40
Create Date: 2026-10-26 17:00:00.000000

Expand-only:

* ``robot_fleet_trust_root`` (workspace-scoped, tenant RLS): the trust roots
  revocation lists must verify under before they are published.
* ``robot_key_registry`` (global, no RLS, public material only): the derived
  key id and public key of every robot and SOC key ever registered, unique,
  never deleted; backfilled from ``robot_key`` and ``robot_fleet_soc_key`` (a
  later duplicate of an earlier row is skipped).
* Nullable columns: ``robot_key.provenance`` (backfilled from how each key
  was inserted: the three keys of one enrollment share a transaction time; a
  rotation names its new key), revocation-list trust root and withdrawal
  columns, ``robot_fleet_approval.payload``, ``robot_fleet_soc_key.
  activated_by``; ``robot_fleet_soc_key.custody`` (NOT NULL, server default
  ``'online'``, so the previous app version's inserts are unchanged).
* ``robot_fleet_soc_key.encrypted_seed`` becomes nullable (offline approval
  keys) with a check that only an ``offline`` approval key lacks a seed.
* The approval status check gains ``prepared``.
* ``robot_fleet_rotation``: rotation ids become unique per robot
  (``robot_fk``, ``rotation_id``) instead of SOC-wide. The SOC-wide unique
  constraint is relaxed, which the previous app version does not depend on:
  it looks rotations up with ``scalar()`` (first row) and checks the robot
  afterwards, exactly as with one row.

The previous app version never reads the new table, columns or status, and
never writes a NULL seed. Rows the new version writes that it cannot read
(``prepared`` approvals, offline approval keys) only exist once the new
version ran; roll the app back before them or restore a backup.

``downgrade()`` drops the new structures. It refuses (the constraint
recreation fails) when two robots share a rotation id, a SOC key has no seed
or an approval is ``prepared``: delete those rows or restore a backup.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from autosecops.db.tenant_rls import (
    disable_workspace_table_rls,
    enable_workspace_table_rls,
)

revision: str = "b8d2f4a61c37"
down_revision: str | None = "5e1b7c2d9a40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRUST_ROOT = "robot_fleet_trust_root"
_REGISTRY = "robot_key_registry"
# The RoboDR derived key id (autosecops.robot_edr.crypto.derive_key_id): the
# registry names a key by it, whatever id a manual finding key was given.
_DERIVED_KEY_ID = (
    "'ed25519:' || encode(substring(sha256("
    "convert_to('robodr-blackbox/ed25519-key-id/v1', 'UTF8') || '\\x00'::bytea "
    "|| public_key) FROM 1 FOR 8), 'hex')"
)


def _user_fk(table: str, column: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column],
        ["user.id"],
        name=op.f(f"fk_{table}_{column}_user"),
        ondelete="SET NULL",
    )


def _create_trust_root_table() -> None:
    op.create_table(
        _TRUST_ROOT,
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.UUID(), nullable=True),
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
            "octet_length(public_key) = 32",
            name=op.f(f"ck_{_TRUST_ROOT}_public_key_length"),
        ),
        _user_fk(_TRUST_ROOT, "created_by"),
        _user_fk(_TRUST_ROOT, "revoked_by"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name=op.f(f"fk_{_TRUST_ROOT}_workspace_id_workspace"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f(f"pk_{_TRUST_ROOT}")),
        sa.UniqueConstraint(
            "workspace_id",
            "public_key",
            name=op.f(f"uq_{_TRUST_ROOT}_workspace_id_public_key"),
        ),
    )
    op.create_index(op.f(f"ix_{_TRUST_ROOT}_id"), _TRUST_ROOT, ["id"], unique=True)
    op.execute(enable_workspace_table_rls(_TRUST_ROOT))


def _create_key_registry() -> None:
    op.create_table(
        _REGISTRY,
        sa.Column("surrogate_id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column(
            "registered_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('robot', 'soc')", name=op.f(f"ck_{_REGISTRY}_kind")
        ),
        sa.CheckConstraint(
            "octet_length(public_key) = 32",
            name=op.f(f"ck_{_REGISTRY}_public_key_length"),
        ),
        sa.PrimaryKeyConstraint("surrogate_id", name=op.f(f"pk_{_REGISTRY}")),
        sa.UniqueConstraint("key_id", name=op.f(f"uq_{_REGISTRY}_key_id")),
        sa.UniqueConstraint("public_key", name=op.f(f"uq_{_REGISTRY}_public_key")),
    )
    op.execute(
        f"""
        INSERT INTO {_REGISTRY} (key_id, public_key, kind, registered_at)
        SELECT {_DERIVED_KEY_ID}, public_key, 'robot', created_at FROM robot_key
        WHERE octet_length(public_key) = 32
        ORDER BY created_at, surrogate_id
        ON CONFLICT DO NOTHING
        """
    )
    op.execute(
        f"""
        INSERT INTO {_REGISTRY} (key_id, public_key, kind, registered_at)
        SELECT key_id, public_key, 'soc', created_at FROM robot_fleet_soc_key
        ORDER BY created_at, surrogate_id
        ON CONFLICT DO NOTHING
        """
    )


def _add_key_provenance() -> None:
    op.add_column(
        "robot_key", sa.Column("provenance", sa.String(length=16), nullable=True)
    )
    # Rotation: the rotation row names the key it registered.
    op.execute(
        """
        UPDATE robot_key AS k SET provenance = 'rotation'
        FROM robot_fleet_rotation AS r
        WHERE r.robot_fk = k.robot_fk AND r.new_key_id = k.key_id
          AND r.rotate_answer IS NOT NULL
        """
    )
    # Enrollment: its uplink, finding and blackbox keys share a transaction.
    op.execute(
        """
        UPDATE robot_key AS k SET provenance = 'enrollment'
        WHERE k.provenance IS NULL AND k.robot_fk IS NOT NULL
          AND (
            SELECT count(DISTINCT o.role) FROM robot_key AS o
            WHERE o.robot_fk = k.robot_fk AND o.created_at = k.created_at
              AND o.role IN ('uplink', 'finding', 'blackbox')
          ) = 3
        """
    )
    op.execute("UPDATE robot_key SET provenance = 'manual' WHERE provenance IS NULL")


def upgrade() -> None:
    _create_trust_root_table()
    _create_key_registry()
    _add_key_provenance()

    op.add_column(
        "robot_fleet_soc_key",
        sa.Column(
            "custody",
            sa.String(length=16),
            server_default=sa.text("'online'"),
            nullable=False,
        ),
    )
    op.add_column(
        "robot_fleet_soc_key", sa.Column("activated_by", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_robot_fleet_soc_key_activated_by_user"),
        "robot_fleet_soc_key",
        "user",
        ["activated_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.alter_column(
        "robot_fleet_soc_key",
        "encrypted_seed",
        existing_type=sa.LargeBinary(),
        nullable=True,
    )
    op.create_check_constraint(
        op.f("ck_robot_fleet_soc_key_custody"),
        "robot_fleet_soc_key",
        "(custody = 'online') = (encrypted_seed IS NOT NULL) "
        "AND (custody = 'online' OR kind = 'approval')",
    )

    op.add_column(
        "robot_fleet_approval", sa.Column("payload", sa.LargeBinary(), nullable=True)
    )
    op.drop_constraint(
        op.f("ck_robot_fleet_approval_status"), "robot_fleet_approval", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_robot_fleet_approval_status_v2"),
        "robot_fleet_approval",
        "status IN ('pending', 'prepared', 'signed', 'cancelled')",
    )

    revocations = "robot_fleet_revocation_list"
    op.add_column(
        revocations,
        sa.Column("trust_root_key_id", sa.String(length=32), nullable=True),
    )
    op.add_column(
        revocations,
        sa.Column("withdrawal_reason", sa.String(length=512), nullable=True),
    )
    for column in ("withdrawal_requested_by", "withdrawn_by"):
        op.add_column(revocations, sa.Column(column, sa.UUID(), nullable=True))
        op.create_foreign_key(
            op.f(f"fk_{revocations}_{column}_user"),
            revocations,
            "user",
            [column],
            ["id"],
            ondelete="SET NULL",
        )
    for column in ("withdrawal_requested_at", "withdrawn_at"):
        op.add_column(
            revocations,
            sa.Column(column, sa.TIMESTAMP(timezone=True), nullable=True),
        )

    op.create_unique_constraint(
        op.f("uq_robot_fleet_rotation_robot_fk_rotation_id"),
        "robot_fleet_rotation",
        ["robot_fk", "rotation_id"],
    )
    op.drop_constraint(
        op.f("uq_robot_fleet_rotation_rotation_id"),
        "robot_fleet_rotation",
        type_="unique",
    )


def downgrade() -> None:
    op.create_unique_constraint(
        op.f("uq_robot_fleet_rotation_rotation_id"),
        "robot_fleet_rotation",
        ["rotation_id"],
    )
    op.drop_constraint(
        op.f("uq_robot_fleet_rotation_robot_fk_rotation_id"),
        "robot_fleet_rotation",
        type_="unique",
    )

    revocations = "robot_fleet_revocation_list"
    for column in ("withdrawal_requested_by", "withdrawn_by"):
        op.drop_constraint(
            op.f(f"fk_{revocations}_{column}_user"), revocations, type_="foreignkey"
        )
    for column in (
        "withdrawn_at",
        "withdrawn_by",
        "withdrawal_requested_at",
        "withdrawal_requested_by",
        "withdrawal_reason",
        "trust_root_key_id",
    ):
        op.drop_column(revocations, column)

    op.drop_constraint(
        op.f("ck_robot_fleet_approval_status_v2"),
        "robot_fleet_approval",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_robot_fleet_approval_status"),
        "robot_fleet_approval",
        "status IN ('pending', 'signed', 'cancelled')",
    )
    op.drop_column("robot_fleet_approval", "payload")

    op.drop_constraint(
        op.f("ck_robot_fleet_soc_key_custody"), "robot_fleet_soc_key", type_="check"
    )
    op.alter_column(
        "robot_fleet_soc_key",
        "encrypted_seed",
        existing_type=sa.LargeBinary(),
        nullable=False,
    )
    op.drop_constraint(
        op.f("fk_robot_fleet_soc_key_activated_by_user"),
        "robot_fleet_soc_key",
        type_="foreignkey",
    )
    op.drop_column("robot_fleet_soc_key", "activated_by")
    op.drop_column("robot_fleet_soc_key", "custody")

    op.drop_column("robot_key", "provenance")
    op.drop_table(_REGISTRY)
    op.execute(disable_workspace_table_rls(_TRUST_ROOT))
    op.drop_index(op.f(f"ix_{_TRUST_ROOT}_id"), table_name=_TRUST_ROOT)
    op.drop_table(_TRUST_ROOT)
