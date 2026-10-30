"""Add tenant RLS policies to link tables without tenant columns.

Revision ID: 9b4d6e2f1a37
Revises: 4c8e2a9f6b13
Create Date: 2026-10-30 21:00:00.000000

These tables reference tenant rows but carry no ``workspace_id`` or
``organization_id`` of their own, so the earlier rollouts left them without
policies. Each policy admits a row only when its parent rows belong to the
current tenant, like ``agent_tag_link``:

- case_attachment, case_dropdown_option, case_dropdown_value, case_tag_link,
  table_column and workflow_tag_link: every parent's ``workspace_id``.
- role_scope: the parent role's ``organization_id``.
- ownership: ``owner_id`` matches the current organization, workspace or user.

``robot_key_registry`` stays without a policy on purpose: it is the SOC-wide
key-id registry whose uniqueness check must see every tenant.

Expand-only: the previous app version sets the same session settings, and the
policies only bind roles subject to RLS, which the previous version never
connects as. The downgrade drops the policies.
"""

from collections.abc import Sequence

from alembic import op
from autosecops.db.tenant_rls import (
    PARENT_SCOPED_TABLES,
    disable_table_rls,
    enable_ownership_table_rls,
    enable_parent_scoped_table_rls,
)

revision: str = "9b4d6e2f1a37"
down_revision: str | None = "4c8e2a9f6b13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PARENT_SCOPED = (
    "case_attachment",
    "case_dropdown_option",
    "case_dropdown_value",
    "case_tag_link",
    "table_column",
    "workflow_tag_link",
    "role_scope",
)


def upgrade() -> None:
    assert set(_PARENT_SCOPED) == set(PARENT_SCOPED_TABLES)
    for table in _PARENT_SCOPED:
        op.execute(disable_table_rls(table))
        op.execute(enable_parent_scoped_table_rls(table))
    op.execute(disable_table_rls("ownership"))
    op.execute(enable_ownership_table_rls())


def downgrade() -> None:
    op.execute(disable_table_rls("ownership"))
    for table in reversed(_PARENT_SCOPED):
        op.execute(disable_table_rls(table))
