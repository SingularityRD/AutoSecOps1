"""Rename the case text search helper functions to the AutoSecOps prefix.

Revision ID: 07c9a895bd57
Revises: b7d41c9e2a6f
Create Date: 2026-10-26 09:30:00.000000

Renames the two SQL helper functions created by e2018a1b2c3d in place:

- public.tracecat_case_text_matches_v1 -> public.autosecops_case_text_matches_v1
- public.tracecat_case_safe_vector_v1 -> public.autosecops_case_safe_vector_v1

These are the only database objects whose names carry the pre-rename prefix.
``ALTER FUNCTION ... RENAME`` keeps each function's OID, so the expression
indexes on public.case that call the vector helper, and any EXECUTE grants,
follow the rename without a rebuild. The application only calls the new names,
so this revision ships together with the matching code. Downgrade renames the
functions back.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "07c9a895bd57"
down_revision: str | None = "b7d41c9e2a6f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (old name, new name, argument signature)
_RENAMES = (
    (
        "tracecat_case_text_matches_v1",
        "autosecops_case_text_matches_v1",
        "text,text,boolean",
    ),
    (
        "tracecat_case_safe_vector_v1",
        "autosecops_case_safe_vector_v1",
        "text",
    ),
)


def _rename(source: str, target: str, signature: str) -> None:
    op.execute(f"ALTER FUNCTION public.{source}({signature}) RENAME TO {target}")


def upgrade() -> None:
    for old_name, new_name, signature in _RENAMES:
        _rename(old_name, new_name, signature)


def downgrade() -> None:
    for old_name, new_name, signature in reversed(_RENAMES):
        _rename(new_name, old_name, signature)
