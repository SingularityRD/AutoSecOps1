"""Shared tenant RLS policy registry and SQL helpers.

Any new tenant-scoped table must be added to one of the policy registries
below and its creating Alembic migration should apply the matching helper SQL
in the same revision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

RLS_BYPASS_VAR = "app.rls_bypass"
RLS_BYPASS_ON = "on"

# Tables covered by the initial RLS rollout migration.
INITIAL_WORKSPACE_SCOPED_TABLES = (
    "workflow",
    "workflow_definition",
    "workflow_folder",
    "action",
    "webhook",
    "webhook_api_key",
    "schedule",
    "secret",
    "workspace_variable",
    "tables",
    "case",
    "case_comment",
    "case_comment_mention",
    "case_event",
    "case_task",
    "case_tag",
    "case_field",
    "case_duration_definition",
    "case_duration",
    "case_trigger",
    "case_dropdown_definition",
    "workflow_tag",
    "interaction",
    "approval",
    "agent_session",
    "agent_session_history",
    "agent_preset",
    "file",
    "chat",
    "chat_message",
    "membership",
    "oauth_integration",
    "oauth_provider",
    "mcp_integration",
)

INITIAL_ORG_SCOPED_TABLES = (
    "organization_secret",
    "organization_settings",
    "organization_domain",
    "organization_membership",
    "organization_invitation",
    "organization_tier",
    "invitation",
    "registry_repository",
    "registry_action",
    "registry_version",
    "registry_index",
    "role",
    "group",
)

INITIAL_ORG_OPTIONAL_WORKSPACE_SCOPED_TABLES = (
    "user_role_assignment",
    "group_role_assignment",
)

# Tables introduced after the initial RLS rollout. Their creating or follow-up
# revisions must apply policy SQL explicitly.
POST_RLS_WORKSPACE_SCOPED_TABLES = (
    "case_agent_session_interaction",
    "case_table_row",
    "case_version",
    "case_comment_agent_invocation",
    "agent_channel_token",
    "agent_preset_version",
    "agent_folder",
    "agent_tag",
    "skill_folder",
    "skill_tag",
    "skill",
    "skill_blob",
    "skill_upload",
    "skill_draft_file",
    "skill_version",
    "skill_version_file",
    "skill_version_tool",
    "skill_version_mcp_tool",
    "skill_library_install",
    "agent_preset_skill",
    "agent_preset_version_skill",
    "workspace_sync_resource_mapping",
    "form",
    "form_submission",
    "form_view",
    "form_file",
    "workspace_tunnel",
    "robot_evidence_export",
    "robot_action_audit",
    "robot",
    "robot_key",
    "robot_finding",
    "robot_finding_event",
    "robot_ingest_batch",
    "robot_fleet_soc_key",
    "robot_fleet_token",
    "robot_fleet_rotation",
    "robot_fleet_revocation_list",
    "robot_fleet_profile_draft",
    "robot_fleet_profile_offer",
    "robot_fleet_approval",
    "robot_fleet_ring",
    "robot_fleet_trust_root",
)

POST_RLS_ORG_SCOPED_TABLES = (
    "watchtower_agent",
    "mcp_refresh_token",
    "agent_custom_provider",
    "organization_secret_store",
    "external_user",
    "external_group",
    "external_group_mapping",
    "external_group_member",
    "scim_connection",
    "invitation_group",
)

POST_RLS_ORG_OPTIONAL_WORKSPACE_SCOPED_TABLES = (
    "invitation_grant",
    "watchtower_agent_session",
    "watchtower_agent_tool_call",
    "service_account",
    "mcp_personal_access_token",
    "agent_model_access",
    "workspace_secret_store_authorization",
)


@dataclass(frozen=True, slots=True)
class ParentScope:
    """A parent row whose tenant column scopes a table without its own."""

    table: str
    fk_column: str
    tenant_column: Literal["workspace_id", "organization_id"]


# Link and child tables without tenant columns. Each row is visible only when
# every listed parent belongs to the current tenant.
PARENT_SCOPED_TABLES: dict[str, tuple[ParentScope, ...]] = {
    "case_attachment": (
        ParentScope("case", "case_id", "workspace_id"),
        ParentScope("file", "file_id", "workspace_id"),
    ),
    "case_dropdown_option": (
        ParentScope("case_dropdown_definition", "definition_id", "workspace_id"),
    ),
    "case_dropdown_value": (
        ParentScope("case", "case_id", "workspace_id"),
        ParentScope("case_dropdown_definition", "definition_id", "workspace_id"),
    ),
    "case_tag_link": (
        ParentScope("case", "case_id", "workspace_id"),
        ParentScope("case_tag", "tag_id", "workspace_id"),
    ),
    "table_column": (ParentScope("tables", "table_id", "workspace_id"),),
    "workflow_tag_link": (
        ParentScope("workflow_tag", "tag_id", "workspace_id"),
        ParentScope("workflow", "workflow_id", "workspace_id"),
    ),
    "role_scope": (ParentScope("role", "role_id", "organization_id"),),
}

SPECIAL_TENANT_POLICY_TABLES = frozenset(
    {
        "agent_tag_link",
        "skill_tag_link",
        "service_account_api_key",
        "service_account_scope",
        "ownership",
        *PARENT_SCOPED_TABLES,
    }
)

# Public tables that deliberately carry no tenant policy. Every other public
# table must appear in a registry above; tests check the migrated catalog.
_PLATFORM_TABLE = "Platform-wide row shared by every tenant; no tenant column."
_AUTH_TABLE = (
    "Authentication state read before a tenant context exists; access is"
    " enforced by the auth layer."
)
RLS_EXEMPT_TABLES: dict[str, str] = {
    "robot_key_registry": (
        "SOC-wide registry of every robot and SOC public key ever issued. The"
        " key-id uniqueness check must see all tenants, and rows hold public key"
        " material only."
    ),
    "alembic_version": "Migration bookkeeping; the runtime role can only read it.",
    "organization": (
        "The tenant root itself. Login, org discovery and invitations resolve"
        " organizations before an org context exists."
    ),
    "user": _AUTH_TABLE,
    "access_token": _AUTH_TABLE,
    "oauth_account": _AUTH_TABLE,
    "saml_request_data": _AUTH_TABLE,
    "tier": _PLATFORM_TABLE,
    "platform_settings": _PLATFORM_TABLE,
    "platform_secret": _PLATFORM_TABLE,
    "platform_registry_repository": _PLATFORM_TABLE,
    "platform_registry_version": _PLATFORM_TABLE,
    "platform_registry_action": _PLATFORM_TABLE,
    "platform_registry_index": _PLATFORM_TABLE,
}

# Workspace and oauth_state carry custom policy SQL. scope and agent_catalog
# both have nullable organization_id and allow shared platform-owned rows.
SEARCH_POLICY_TABLES = frozenset(
    {
        "search_workspace_state",
        "search_embedding_config",
        "search_collection",
        "search_document",
        "search_chunk",
    }
)
# group_member.organization_id is a nullable denormalization for the membership
# foreign key; the table is governed by its parent group's policy.
SPECIAL_WORKSPACE_POLICY_TABLES = frozenset({"oauth_state"}) | SEARCH_POLICY_TABLES
SPECIAL_ORG_POLICY_TABLES = (
    frozenset({"workspace", "scope", "agent_catalog", "group_member"})
    | SEARCH_POLICY_TABLES
)

CURRENT_WORKSPACE_SCOPED_TABLES = (
    *INITIAL_WORKSPACE_SCOPED_TABLES,
    *POST_RLS_WORKSPACE_SCOPED_TABLES,
)
CURRENT_ORG_SCOPED_TABLES = (
    *INITIAL_ORG_SCOPED_TABLES,
    *POST_RLS_ORG_SCOPED_TABLES,
)
CURRENT_ORG_OPTIONAL_WORKSPACE_SCOPED_TABLES = (
    *INITIAL_ORG_OPTIONAL_WORKSPACE_SCOPED_TABLES,
    *POST_RLS_ORG_OPTIONAL_WORKSPACE_SCOPED_TABLES,
)

WORKSPACE_POLICY_TABLES = frozenset(CURRENT_WORKSPACE_SCOPED_TABLES)
ORG_POLICY_TABLES = frozenset(CURRENT_ORG_SCOPED_TABLES)
ORG_OPTIONAL_WORKSPACE_POLICY_TABLES = frozenset(
    CURRENT_ORG_OPTIONAL_WORKSPACE_SCOPED_TABLES
)
ALL_TENANT_RLS_TABLES = (
    WORKSPACE_POLICY_TABLES
    | ORG_POLICY_TABLES
    | ORG_OPTIONAL_WORKSPACE_POLICY_TABLES
    | SPECIAL_WORKSPACE_POLICY_TABLES
    | SPECIAL_ORG_POLICY_TABLES
    | SPECIAL_TENANT_POLICY_TABLES
)


def policy_name(table: str) -> str:
    return f"rls_policy_{table}"


def enable_workspace_table_rls(table: str) -> str:
    return f"""
        ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name(table)} ON "{table}"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
            );
    """


def disable_workspace_table_rls(table: str) -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name(table)} ON "{table}";
        ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY;
    """


def enable_oauth_state_special_rls() -> str:
    return f"""
        ALTER TABLE "oauth_state" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name("oauth_state")} ON "oauth_state"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
                OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR (
                    user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
                    AND workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                )
            );
    """


def disable_oauth_state_special_rls() -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name("oauth_state")} ON "oauth_state";
        ALTER TABLE "oauth_state" DISABLE ROW LEVEL SECURITY;
    """


def enable_group_member_table_rls() -> str:
    """Scope legacy nullable membership rows through their owning group."""
    return f"""
        ALTER TABLE group_member ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {policy_name("group_member")} ON group_member
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR EXISTS (
                    SELECT 1 FROM "group" AS parent_group
                    WHERE parent_group.id = group_member.group_id
                      AND parent_group.organization_id = NULLIF(
                          current_setting('app.current_org_id', true), ''
                      )::uuid
                )
            );
    """


def enable_org_table_rls(table: str) -> str:
    return f"""
        ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name(table)} ON "{table}"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
    """


def disable_org_table_rls(table: str) -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name(table)} ON "{table}";
        ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY;
    """


def enable_org_optional_workspace_table_rls(table: str) -> str:
    return f"""
        ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name(table)} ON "{table}"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR (
                    organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
                    AND (
                        workspace_id IS NULL
                        OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                        OR NULLIF(current_setting('app.current_workspace_id', true), '')::uuid IS NULL
                    )
                )
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR (
                    organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
                    AND (
                        workspace_id IS NULL
                        OR workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                        OR NULLIF(current_setting('app.current_workspace_id', true), '')::uuid IS NULL
                    )
                )
            );
    """


def disable_org_optional_workspace_table_rls(table: str) -> str:
    return disable_org_table_rls(table)


def enable_scope_table_rls() -> str:
    return f"""
        ALTER TABLE "scope" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name("scope")} ON "scope"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR organization_id IS NULL
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
    """


def disable_scope_table_rls() -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name("scope")} ON "scope";
        ALTER TABLE "scope" DISABLE ROW LEVEL SECURITY;
    """


def enable_service_account_child_table_rls(table: str) -> str:
    return f"""
        ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name(table)} ON "{table}"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR EXISTS (
                    SELECT 1
                    FROM service_account
                    WHERE service_account.id = "{table}".service_account_id
                      AND service_account.organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
                      AND (
                          service_account.workspace_id IS NULL
                          OR service_account.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                          OR NULLIF(current_setting('app.current_workspace_id', true), '')::uuid IS NULL
                      )
                )
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR EXISTS (
                    SELECT 1
                    FROM service_account
                    WHERE service_account.id = "{table}".service_account_id
                      AND service_account.organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
                      AND (
                          service_account.workspace_id IS NULL
                          OR service_account.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                          OR NULLIF(current_setting('app.current_workspace_id', true), '')::uuid IS NULL
                      )
                )
            );
    """


def _agent_catalog_platform_read_policy() -> str:
    return f"{policy_name('agent_catalog')}_platform_read"


def enable_agent_catalog_table_rls() -> str:
    # Split policy so platform rows (organization_id IS NULL) are readable by
    # every org but cannot be written or deleted by an org-scoped session.
    # Writes/deletes are gated by the FOR ALL policy, which only matches
    # rows owned by the current org; platform-row read access is granted
    # additively via a FOR SELECT policy (permissive policies OR together).
    return f"""
        ALTER TABLE "agent_catalog" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name("agent_catalog")} ON "agent_catalog"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );

        CREATE POLICY {_agent_catalog_platform_read_policy()} ON "agent_catalog"
            FOR SELECT
            USING (
                organization_id IS NULL
            );
    """


def disable_service_account_child_table_rls(table: str) -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name(table)} ON "{table}";
        ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY;
    """


def _agent_tag_link_workspace_condition() -> str:
    return """
                EXISTS (
                    SELECT 1
                    FROM agent_tag
                    WHERE agent_tag.id = agent_tag_link.tag_id
                      AND agent_tag.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                )
                AND EXISTS (
                    SELECT 1
                    FROM agent_preset
                    WHERE agent_preset.id = agent_tag_link.preset_id
                      AND agent_preset.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                )
    """


def enable_agent_tag_link_table_rls() -> str:
    workspace_condition = _agent_tag_link_workspace_condition()
    return f"""
        ALTER TABLE "agent_tag_link" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name("agent_tag_link")} ON "agent_tag_link"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR (
{workspace_condition}
                )
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR (
{workspace_condition}
                )
            );
    """


def disable_agent_tag_link_table_rls() -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name("agent_tag_link")} ON "agent_tag_link";
        ALTER TABLE "agent_tag_link" DISABLE ROW LEVEL SECURITY;
    """


def _skill_tag_link_workspace_condition() -> str:
    return """
                EXISTS (
                    SELECT 1
                    FROM skill_tag
                    WHERE skill_tag.id = skill_tag_link.tag_id
                      AND skill_tag.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                )
                AND EXISTS (
                    SELECT 1
                    FROM skill
                    WHERE skill.id = skill_tag_link.skill_id
                      AND skill.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                )
    """


def enable_skill_tag_link_table_rls() -> str:
    workspace_condition = _skill_tag_link_workspace_condition()
    return f"""
        ALTER TABLE "skill_tag_link" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name("skill_tag_link")} ON "skill_tag_link"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR (
{workspace_condition}
                )
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR (
{workspace_condition}
                )
            );
    """


def disable_skill_tag_link_table_rls() -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name("skill_tag_link")} ON "skill_tag_link";
        ALTER TABLE "skill_tag_link" DISABLE ROW LEVEL SECURITY;
    """


_TENANT_SETTINGS = {
    "workspace_id": "app.current_workspace_id",
    "organization_id": "app.current_org_id",
}


def _parent_scope_condition(table: str, parent: ParentScope) -> str:
    setting = _TENANT_SETTINGS[parent.tenant_column]
    return f"""
                EXISTS (
                    SELECT 1
                    FROM "{parent.table}" AS parent
                    WHERE parent.id = "{table}".{parent.fk_column}
                      AND parent.{parent.tenant_column} = NULLIF(current_setting('{setting}', true), '')::uuid
                )"""


def enable_parent_scoped_table_rls(table: str) -> str:
    """Scope a table without tenant columns through its parent rows."""
    if (parents := PARENT_SCOPED_TABLES.get(table)) is None:
        raise ValueError("Unknown parent-scoped table")
    condition = "\n                AND".join(
        _parent_scope_condition(table, parent) for parent in parents
    )
    return f"""
        ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name(table)} ON "{table}"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR ({condition}
                )
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR ({condition}
                )
            );
    """


def enable_ownership_table_rls() -> str:
    """Scope ownership rows to the tenant or user that owns the resource.

    Rows have no tenant column; ``owner_id`` holds an organization, workspace
    or user id depending on the row.
    """
    predicate = f"""
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR owner_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
                OR owner_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                OR owner_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    """
    return f"""
        ALTER TABLE "ownership" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name("ownership")} ON "ownership"
            FOR ALL
            USING ({predicate})
            WITH CHECK ({predicate});
    """


def disable_table_rls(table: str) -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name(table)} ON "{table}";
        ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY;
    """


def disable_agent_catalog_table_rls() -> str:
    return f"""
        DROP POLICY IF EXISTS {_agent_catalog_platform_read_policy()} ON "agent_catalog";
        DROP POLICY IF EXISTS {policy_name("agent_catalog")} ON "agent_catalog";
        ALTER TABLE "agent_catalog" DISABLE ROW LEVEL SECURITY;
    """


def enable_workspace_special_rls() -> str:
    return f"""
        ALTER TABLE "workspace" ENABLE ROW LEVEL SECURITY;

        CREATE POLICY {policy_name("workspace")} ON "workspace"
            FOR ALL
            USING (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('{RLS_BYPASS_VAR}', true) = '{RLS_BYPASS_ON}'
                OR id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
                OR organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
    """


def disable_workspace_special_rls() -> str:
    return f"""
        DROP POLICY IF EXISTS {policy_name("workspace")} ON "workspace";
        ALTER TABLE "workspace" DISABLE ROW LEVEL SECURITY;
    """


def enable_search_table_rls(table: str) -> str:
    """Enforce both tenant identities and hide data after workspace deletion."""
    if table not in SEARCH_POLICY_TABLES:
        raise ValueError("Unknown search table")
    predicate = f"""
        current_setting('app.rls_bypass', true) = 'on'
        OR (
            workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
            AND organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            AND EXISTS (SELECT 1 FROM workspace w
                        WHERE w.id = "{table}".workspace_id
                          AND w.organization_id = "{table}".organization_id)
        )
    """
    return f"""
        ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {policy_name(table)} ON "{table}"
        FOR ALL USING ({predicate}) WITH CHECK ({predicate});
    """
