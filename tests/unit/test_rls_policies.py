"""Tenant isolation tests for the PostgreSQL row-level security policies.

The policies come from Alembic migrations, not from ``Base.metadata.create_all``,
and PostgreSQL skips RLS for superusers and table owners. Phase 1 enables RLS
without ``FORCE``, so the policies only bind a separate, non-owner runtime role.
These tests therefore migrate a dedicated database to head, let the migrations
step provision the runtime role as deployments do, and query as that non-owner
login role.

The tests set ``AUTOSECOPS__RLS_MODE`` themselves, so they run in every CI job.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import uuid
from collections.abc import AsyncGenerator, Iterator
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import NullPool

from autosecops import config
from autosecops.auth.types import Role
from autosecops.contexts import ctx_role
from autosecops.db.engine import get_async_engine, get_async_session
from autosecops.db.engine import reset_async_engine as reset_engines
from autosecops.db.rls import (
    RLS_BYPASS_OFF,
    RLS_BYPASS_ON,
    RLS_UNSET_VALUE,
    RLS_VAR_BYPASS,
    RLS_VAR_ORG_ID,
    RLS_VAR_WORKSPACE_ID,
    set_rls_context,
)
from autosecops.db.runtime_role import RuntimeRoleCredentials, provision_runtime_role
from autosecops.db.tenant_rls import (
    ALL_TENANT_RLS_TABLES,
    RLS_EXEMPT_TABLES,
    policy_name,
)
from tests.database import TEST_DB_CONFIG

REPO_ROOT = Path(__file__).resolve().parents[2]
TENANT_COLUMNS = ("organization_id", "workspace_id")


def _libpq_url(sqlalchemy_url: str) -> str:
    """Strip the SQLAlchemy driver suffix so psycopg can connect directly."""
    return sqlalchemy_url.replace("+psycopg", "").replace("+asyncpg", "")


@dataclass(frozen=True, slots=True)
class Tenant:
    """One organization with one workflow and secret per workspace."""

    org_id: uuid.UUID
    workspace_ids: tuple[uuid.UUID, ...]
    workflow_ids: tuple[uuid.UUID, ...]
    secret_ids: tuple[uuid.UUID, ...]
    org_secret_id: uuid.UUID
    tag_ids: tuple[uuid.UUID, ...]
    column_ids: tuple[uuid.UUID, ...]
    role_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class MigratedTenantDB:
    """A database migrated to head and seeded with two organizations."""

    owner_url: str
    app_url: str
    app_role: str
    app_password: str
    org_a: Tenant
    org_b: Tenant

    @property
    def all_workflow_ids(self) -> set[uuid.UUID]:
        return {*self.org_a.workflow_ids, *self.org_b.workflow_ids}


def _seed_tenant(conn: psycopg.Connection, *, label: str, workspaces: int) -> Tenant:
    org_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO organization (id, name, slug, is_active) VALUES (%s, %s, %s, true)",
        (org_id, f"RLS {label}", f"rls-{label}-{org_id.hex[:8]}"),
    )
    workspace_ids: list[uuid.UUID] = []
    workflow_ids: list[uuid.UUID] = []
    secret_ids: list[uuid.UUID] = []
    tag_ids: list[uuid.UUID] = []
    column_ids: list[uuid.UUID] = []
    for index in range(workspaces):
        workspace_id, workflow_id, secret_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        conn.execute(
            "INSERT INTO workspace (id, organization_id, name) VALUES (%s, %s, %s)",
            (workspace_id, org_id, f"{label}-{index}"),
        )
        conn.execute(
            "INSERT INTO workflow (id, workspace_id, title, description, status)"
            " VALUES (%s, %s, %s, '', 'offline')",
            (workflow_id, workspace_id, f"{label}-{index}"),
        )
        conn.execute(
            "INSERT INTO secret (id, workspace_id, type, name, encrypted_keys)"
            " VALUES (%s, %s, 'custom', %s, %s)",
            (secret_id, workspace_id, f"{label}_{index}", b"ciphertext"),
        )
        workspace_ids.append(workspace_id)
        workflow_ids.append(workflow_id)
        secret_ids.append(secret_id)
        tag_ids.append(_seed_workspace_links(conn, workspace_id, workflow_id))
        column_ids.append(_seed_table_column(conn, workspace_id))
    org_secret_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO organization_secret"
        " (id, organization_id, type, name, encrypted_keys, environment)"
        " VALUES (%s, %s, 'custom', %s, %s, 'default')",
        (org_secret_id, org_id, f"{label}_org", b"ciphertext"),
    )
    return Tenant(
        org_id=org_id,
        workspace_ids=tuple(workspace_ids),
        workflow_ids=tuple(workflow_ids),
        secret_ids=tuple(secret_ids),
        org_secret_id=org_secret_id,
        tag_ids=tuple(tag_ids),
        column_ids=tuple(column_ids),
        role_id=_seed_role_scope(conn, org_id),
    )


def _seed_workspace_links(
    conn: psycopg.Connection, workspace_id: uuid.UUID, workflow_id: uuid.UUID
) -> uuid.UUID:
    """Tag the workflow and record the workspace's ownership row."""
    tag_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO workflow_tag (id, workspace_id, name, ref) VALUES (%s, %s, %s, %s)",
        (tag_id, workspace_id, f"tag-{tag_id.hex[:8]}", f"tag-{tag_id.hex[:8]}"),
    )
    conn.execute(
        "INSERT INTO workflow_tag_link (tag_id, workflow_id) VALUES (%s, %s)",
        (tag_id, workflow_id),
    )
    conn.execute(
        "INSERT INTO ownership (resource_id, resource_type, owner_id, owner_type)"
        " SELECT %s, 'workspace', organization_id, 'user' FROM workspace"
        " WHERE id = %s",
        (str(workspace_id), workspace_id),
    )
    return tag_id


def _seed_table_column(conn: psycopg.Connection, workspace_id: uuid.UUID) -> uuid.UUID:
    table_id, column_id = uuid.uuid4(), uuid.uuid4()
    conn.execute(
        "INSERT INTO tables (id, workspace_id, name) VALUES (%s, %s, %s)",
        (table_id, workspace_id, f"t_{table_id.hex[:8]}"),
    )
    conn.execute(
        "INSERT INTO table_column (id, table_id, name, type, nullable)"
        " VALUES (%s, %s, 'value', 'TEXT', true)",
        (column_id, table_id),
    )
    return column_id


def _seed_role_scope(conn: psycopg.Connection, org_id: uuid.UUID) -> uuid.UUID:
    role_id, scope_id = uuid.uuid4(), uuid.uuid4()
    conn.execute(
        "INSERT INTO role (id, organization_id, name) VALUES (%s, %s, %s)",
        (role_id, org_id, f"role-{role_id.hex[:8]}"),
    )
    conn.execute(
        "INSERT INTO scope (id, organization_id, name, resource, action, source)"
        " VALUES (%s, %s, %s, 'workflow', 'read', 'CUSTOM')",
        (scope_id, org_id, f"custom:{scope_id.hex[:8]}"),
    )
    conn.execute(
        "INSERT INTO role_scope (role_id, scope_id) VALUES (%s, %s)",
        (role_id, scope_id),
    )
    return role_id


def _run_alembic_upgrade_head(
    db_url: str, *, runtime_user: str, runtime_password: str
) -> None:
    """Migrate to head; env.py then provisions the runtime role."""
    env = os.environ.copy()
    env["AUTOSECOPS__DB_URI"] = db_url
    env["AUTOSECOPS__DB_RUNTIME_USER"] = runtime_user
    env["AUTOSECOPS__DB_RUNTIME_PASSWORD"] = runtime_password
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Alembic upgrade failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


@pytest.fixture(scope="module")
def tenant_db() -> Iterator[MigratedTenantDB]:
    """Migrate a dedicated database and expose it through the runtime role.

    The migrations step provisions the role exactly as deployments do, so these
    tests also cover its grants.
    """
    db_name = f"rls_{uuid.uuid4().hex}"
    app_role = f"rls_app_{uuid.uuid4().hex[:12]}"
    # Characters that need quoting in SQL and URLs.
    app_password = f"{secrets.token_hex(8)}%'@:/{secrets.token_hex(8)}"
    owner_url = TEST_DB_CONFIG.sys_url_sync.removesuffix("postgres") + db_name
    app_url = (
        make_url(owner_url)
        .set(username=app_role, password=app_password)
        .render_as_string(hide_password=False)
    )

    with psycopg.connect(
        _libpq_url(TEST_DB_CONFIG.sys_url_sync), autocommit=True
    ) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
    try:
        _run_alembic_upgrade_head(
            owner_url, runtime_user=app_role, runtime_password=app_password
        )
        with psycopg.connect(_libpq_url(owner_url)) as owner:
            org_a = _seed_tenant(owner, label="a", workspaces=2)
            org_b = _seed_tenant(owner, label="b", workspaces=1)
        yield MigratedTenantDB(
            owner_url=owner_url,
            app_url=app_url,
            app_role=app_role,
            app_password=app_password,
            org_a=org_a,
            org_b=org_b,
        )
    finally:
        with psycopg.connect(
            _libpq_url(TEST_DB_CONFIG.sys_url_sync), autocommit=True
        ) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                    sql.Identifier(db_name)
                )
            )
            admin.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(app_role))
            )


@pytest.fixture
def app_conn(tenant_db: MigratedTenantDB) -> Iterator[psycopg.Connection]:
    """A connection as the non-owner runtime role, rolled back after each test."""
    with psycopg.connect(_libpq_url(tenant_db.app_url)) as conn:
        try:
            yield conn
        finally:
            conn.rollback()


def _set_context(
    conn: psycopg.Connection,
    *,
    org_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
    bypass: bool = False,
) -> None:
    conn.execute(
        """
        SELECT
            set_config('app.rls_bypass', %s, true),
            set_config('app.current_org_id', %s, true),
            set_config('app.current_workspace_id', %s, true)
        """,
        (
            RLS_BYPASS_ON if bypass else RLS_BYPASS_OFF,
            str(org_id) if org_id else RLS_UNSET_VALUE,
            str(workspace_id) if workspace_id else RLS_UNSET_VALUE,
        ),
    )


def _ids(conn: psycopg.Connection, table: str) -> set[uuid.UUID]:
    query = sql.SQL("SELECT id FROM {}").format(sql.Identifier(table))
    return {row[0] for row in conn.execute(query).fetchall()}


class TestRlsContextVariables:
    """Tests for RLS PostgreSQL session variables."""

    @pytest.fixture
    async def rls_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with AsyncSession(get_async_engine(), expire_on_commit=False) as session:
            yield session

    @pytest.mark.anyio
    async def test_context_variables_are_set_correctly(
        self, rls_session: AsyncSession
    ) -> None:
        org_id, workspace_id = uuid.uuid4(), uuid.uuid4()
        await set_rls_context(rls_session, org_id, workspace_id)

        settings = (
            await rls_session.execute(
                text(
                    f"SELECT current_setting('{RLS_VAR_ORG_ID}', true),"
                    f" current_setting('{RLS_VAR_WORKSPACE_ID}', true),"
                    f" current_setting('{RLS_VAR_BYPASS}', true)"
                )
            )
        ).one()
        assert tuple(settings) == (str(org_id), str(workspace_id), RLS_BYPASS_OFF)

    @pytest.mark.anyio
    async def test_none_context_resets_tenant_scope(
        self, rls_session: AsyncSession
    ) -> None:
        """Unset tenant IDs must not imply bypass access."""
        await set_rls_context(rls_session, org_id=None, workspace_id=None)

        settings = (
            await rls_session.execute(
                text(
                    f"SELECT current_setting('{RLS_VAR_ORG_ID}', true),"
                    f" current_setting('{RLS_VAR_WORKSPACE_ID}', true),"
                    f" current_setting('{RLS_VAR_BYPASS}', true)"
                )
            )
        ).one()
        assert tuple(settings) == (RLS_UNSET_VALUE, RLS_UNSET_VALUE, RLS_BYPASS_OFF)

    @pytest.mark.anyio
    async def test_context_reapplies_after_commit(
        self, rls_session: AsyncSession
    ) -> None:
        org_id, workspace_id = uuid.uuid4(), uuid.uuid4()
        await set_rls_context(rls_session, org_id=org_id, workspace_id=workspace_id)
        await rls_session.commit()

        settings = (
            await rls_session.execute(
                text(
                    f"SELECT current_setting('{RLS_VAR_ORG_ID}', true),"
                    f" current_setting('{RLS_VAR_WORKSPACE_ID}', true)"
                )
            )
        ).one()
        assert tuple(settings) == (str(org_id), str(workspace_id))


class TestMigratedPolicyCatalog:
    """The migrated schema carries a policy for every tenant-scoped table."""

    def test_runtime_role_is_subject_to_rls(self, app_conn: psycopg.Connection) -> None:
        row = app_conn.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
        assert row == (False, False)
        owned = app_conn.execute(
            "SELECT count(*) FROM pg_class WHERE relowner ="
            " (SELECT oid FROM pg_roles WHERE rolname = current_user)"
        ).fetchone()
        assert owned == (0,)

    def test_registry_tables_have_rls_and_policy(
        self, tenant_db: MigratedTenantDB
    ) -> None:
        with psycopg.connect(_libpq_url(tenant_db.owner_url)) as conn:
            rows = conn.execute(
                """
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                       array_remove(array_agg(p.policyname), NULL)
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
                LEFT JOIN pg_policies p
                  ON p.schemaname = 'public' AND p.tablename = c.relname
                WHERE c.relkind IN ('r', 'p') AND c.relname = ANY(%s)
                GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
                """,
                (sorted(ALL_TENANT_RLS_TABLES),),
            ).fetchall()
        found = {
            name: (enabled, forced, set(policies))
            for name, enabled, forced, policies in rows
        }

        assert set(found) == ALL_TENANT_RLS_TABLES
        for table, (enabled, forced, policies) in sorted(found.items()):
            assert enabled, f"{table} does not enable row-level security"
            # Phase 1 rollout: RLS is enabled but not forced on the owner.
            assert not forced, f"{table} unexpectedly forces row-level security"
            assert policy_name(table) in policies, f"{table} has no tenant policy"

    def test_tables_with_tenant_columns_enable_rls(
        self, tenant_db: MigratedTenantDB
    ) -> None:
        with psycopg.connect(_libpq_url(tenant_db.owner_url)) as conn:
            unprotected = conn.execute(
                """
                SELECT DISTINCT c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
                JOIN pg_attribute a
                  ON a.attrelid = c.oid AND a.attname = ANY(%s) AND NOT a.attisdropped
                WHERE c.relkind IN ('r', 'p') AND NOT c.relrowsecurity
                ORDER BY c.relname
                """,
                (list(TENANT_COLUMNS),),
            ).fetchall()
        assert unprotected == []

    def test_every_public_table_is_registered_or_exempt(
        self, tenant_db: MigratedTenantDB
    ) -> None:
        assert not ALL_TENANT_RLS_TABLES & set(RLS_EXEMPT_TABLES)
        with psycopg.connect(_libpq_url(tenant_db.owner_url)) as conn:
            rows = conn.execute(
                """
                SELECT c.relname, c.relrowsecurity
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
                WHERE c.relkind IN ('r', 'p')
                """
            ).fetchall()
        without_rls = {name for name, enabled in rows if not enabled}
        assert without_rls == set(RLS_EXEMPT_TABLES)
        assert {name for name, _ in rows} == ALL_TENANT_RLS_TABLES | set(
            RLS_EXEMPT_TABLES
        )


class TestRuntimeRoleProvisioning:
    """The migrations step leaves the runtime role with DML and nothing more."""

    def test_runtime_role_cannot_change_schema_or_version(
        self, app_conn: psycopg.Connection
    ) -> None:
        for statement in (
            "CREATE TABLE public.rls_probe (id int)",
            "ALTER TABLE workflow ADD COLUMN rls_probe int",
            "ALTER TABLE workflow DISABLE ROW LEVEL SECURITY",
            "DELETE FROM alembic_version",
            "TRUNCATE workflow",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with app_conn.transaction():
                    app_conn.execute(statement.encode())
        assert app_conn.execute("SELECT count(*) FROM alembic_version").fetchone() == (
            1,
        )

    def test_provisioning_is_idempotent_and_reassigns_workspace_schemas(
        self, tenant_db: MigratedTenantDB
    ) -> None:
        org_a = tenant_db.org_a
        own_ws, other_ws = org_a.workspace_ids
        schema = f"tables_ws_{uuid.uuid4().hex[:22]}"
        tenant_col = "__tc_workspace_id"
        policy = (
            "current_setting('app.rls_bypass', true) = 'on'"
            f" OR {tenant_col} = NULLIF(current_setting('app.current_workspace_id',"
            " true), '')::uuid"
        )
        with psycopg.connect(_libpq_url(tenant_db.owner_url)) as owner:
            # A workspace table the owner created before the runtime role existed.
            owner.execute(f'CREATE SCHEMA "{schema}"'.encode())
            owner.execute(
                f'CREATE TABLE "{schema}".rows (id serial PRIMARY KEY,'
                f" {tenant_col} uuid NOT NULL)".encode()
            )
            owner.execute(
                f'ALTER TABLE "{schema}".rows ENABLE ROW LEVEL SECURITY'.encode()
            )
            owner.execute(
                f'CREATE POLICY p ON "{schema}".rows USING ({policy})'
                f" WITH CHECK ({policy})".encode()
            )
            owner.execute(
                f'INSERT INTO "{schema}".rows ({tenant_col}) VALUES (%s), (%s)'.encode(),
                (own_ws, other_ws),
            )

        credentials = RuntimeRoleCredentials(
            username=tenant_db.app_role, password=tenant_db.app_password
        )
        engine = create_engine(tenant_db.owner_url, poolclass=NullPool)
        try:
            for _ in range(2):
                with engine.begin() as conn:
                    report = provision_runtime_role(conn, credentials)
                assert not report.created
                assert report.warnings == []
        finally:
            engine.dispose()

        with psycopg.connect(_libpq_url(tenant_db.owner_url)) as owner:
            owners = owner.execute(
                "SELECT n.nspowner::regrole::text, c.relowner::regrole::text,"
                " c.relforcerowsecurity FROM pg_class c"
                " JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname = %s AND c.relname = 'rows'",
                (schema,),
            ).fetchone()
        assert owners == (tenant_db.app_role, tenant_db.app_role, True)

        with psycopg.connect(_libpq_url(tenant_db.app_url)) as app:
            _set_context(app, org_id=org_a.org_id, workspace_id=own_ws)
            visible = app.execute(
                f'SELECT {tenant_col} FROM "{schema}".rows'.encode()
            ).fetchall()
            assert visible == [(own_ws,)]
            # The runtime role owns workspace schemas, so it can run the DDL
            # the tables feature needs.
            app.execute(f'ALTER TABLE "{schema}".rows ADD COLUMN note text'.encode())
            app.rollback()


class TestRlsIsolation:
    """Policies isolate tenants for the non-owner runtime role."""

    def test_deny_by_default_without_context(
        self, app_conn: psycopg.Connection
    ) -> None:
        _set_context(app_conn)
        for table in ("workspace", "workflow", "secret", "organization_secret"):
            assert _ids(app_conn, table) == set(), table

    def test_bypass_sees_every_tenant(
        self, app_conn: psycopg.Connection, tenant_db: MigratedTenantDB
    ) -> None:
        _set_context(app_conn, bypass=True)
        assert _ids(app_conn, "workflow") >= tenant_db.all_workflow_ids

    def test_workspace_scope_hides_other_workspaces(
        self, app_conn: psycopg.Connection, tenant_db: MigratedTenantDB
    ) -> None:
        org_a = tenant_db.org_a
        for workspace_id, workflow_id, secret_id in zip(
            org_a.workspace_ids, org_a.workflow_ids, org_a.secret_ids, strict=True
        ):
            _set_context(app_conn, org_id=org_a.org_id, workspace_id=workspace_id)
            assert _ids(app_conn, "workflow") == {workflow_id}
            assert _ids(app_conn, "secret") == {secret_id}

    def test_workspace_scope_rejects_cross_tenant_writes(
        self, app_conn: psycopg.Connection, tenant_db: MigratedTenantDB
    ) -> None:
        org_a, org_b = tenant_db.org_a, tenant_db.org_b
        own_workspace, sibling_workspace = org_a.workspace_ids
        own_workflow = org_a.workflow_ids[0]
        foreign_workflow = org_b.workflow_ids[0]
        _set_context(app_conn, org_id=org_a.org_id, workspace_id=own_workspace)

        for statement, params in [
            (
                "INSERT INTO workflow (id, workspace_id, title, description, status)"
                " VALUES (%s, %s, 'x', '', 'offline')",
                (uuid.uuid4(), sibling_workspace),
            ),
            (
                "INSERT INTO workflow (id, workspace_id, title, description, status)"
                " VALUES (%s, %s, 'x', '', 'offline')",
                (uuid.uuid4(), org_b.workspace_ids[0]),
            ),
            (
                "UPDATE workflow SET workspace_id = %s WHERE id = %s",
                (org_b.workspace_ids[0], own_workflow),
            ),
        ]:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with app_conn.transaction():
                    app_conn.execute(statement.encode(), params)

        for statement, target in [
            ("UPDATE workflow SET title = 'hijacked' WHERE id = %s", foreign_workflow),
            ("DELETE FROM workflow WHERE id = %s", foreign_workflow),
            ("DELETE FROM secret WHERE workspace_id = %s", org_b.workspace_ids[0]),
        ]:
            assert app_conn.execute(statement.encode(), (target,)).rowcount == 0

        _set_context(app_conn, bypass=True)
        title = app_conn.execute(
            "SELECT title FROM workflow WHERE id = %s", (foreign_workflow,)
        ).fetchone()
        assert title == ("b-0",)
        assert _ids(app_conn, "secret") >= set(org_b.secret_ids)

    def test_org_scope_hides_other_organizations(
        self, app_conn: psycopg.Connection, tenant_db: MigratedTenantDB
    ) -> None:
        org_a, org_b = tenant_db.org_a, tenant_db.org_b
        _set_context(app_conn, org_id=org_a.org_id)
        assert _ids(app_conn, "workspace") == set(org_a.workspace_ids)
        assert _ids(app_conn, "organization_secret") == {org_a.org_secret_id}
        # Workspace-scoped tables need a workspace in context.
        assert _ids(app_conn, "workflow") == set()

        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with app_conn.transaction():
                app_conn.execute(
                    "INSERT INTO organization_secret"
                    " (id, organization_id, type, name, encrypted_keys, environment)"
                    " VALUES (%s, %s, 'custom', 'x', %s, 'default')",
                    (uuid.uuid4(), org_b.org_id, b"ciphertext"),
                )
        assert (
            app_conn.execute(
                "DELETE FROM organization_secret WHERE id = %s", (org_b.org_secret_id,)
            ).rowcount
            == 0
        )

    def test_link_tables_follow_their_parents(
        self, app_conn: psycopg.Connection, tenant_db: MigratedTenantDB
    ) -> None:
        org_a, org_b = tenant_db.org_a, tenant_db.org_b
        _set_context(app_conn, org_id=org_a.org_id, workspace_id=org_a.workspace_ids[0])
        tag_links = app_conn.execute("SELECT tag_id FROM workflow_tag_link").fetchall()
        assert tag_links == [(org_a.tag_ids[0],)]
        assert _ids(app_conn, "table_column") == {org_a.column_ids[0]}

        # A link may not point at another workspace's parent.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with app_conn.transaction():
                app_conn.execute(
                    "INSERT INTO workflow_tag_link (tag_id, workflow_id)"
                    " VALUES (%s, %s)",
                    (org_a.tag_ids[0], org_b.workflow_ids[0]),
                )
        assert (
            app_conn.execute(
                "DELETE FROM table_column WHERE id = %s", (org_b.column_ids[0],)
            ).rowcount
            == 0
        )

        _set_context(app_conn, org_id=org_a.org_id)
        role_ids = app_conn.execute("SELECT role_id FROM role_scope").fetchall()
        assert role_ids == [(org_a.role_id,)]
        owned = app_conn.execute("SELECT resource_id FROM ownership").fetchall()
        assert {row[0] for row in owned} == {str(ws) for ws in org_a.workspace_ids}

        _set_context(app_conn)
        for table in ("workflow_tag_link", "role_scope", "ownership"):
            query = sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))
            assert app_conn.execute(query).fetchone() == (0,), table


class TestRlsWithRuntimeMode:
    """The application session applies tenant context according to the mode."""

    @pytest.fixture
    async def app_engine(
        self, monkeypatch: pytest.MonkeyPatch, tenant_db: MigratedTenantDB
    ) -> AsyncGenerator[None, None]:
        """Point the application engine at the migrated DB as the runtime role.

        The engine gets the owner URI plus runtime credentials, as deployed
        services do, and swaps the credentials itself.
        """
        monkeypatch.setattr(config, "AUTOSECOPS__DB_URI", tenant_db.owner_url)
        monkeypatch.setattr(config, "AUTOSECOPS__DB_RUNTIME_USER", tenant_db.app_role)
        monkeypatch.setattr(
            config, "AUTOSECOPS__DB_RUNTIME_PASSWORD", tenant_db.app_password
        )
        reset_engines()
        engine = get_async_engine()
        try:
            yield
        finally:
            await engine.dispose()
            reset_engines()

    async def _visible_workflows(self, role: Role | None) -> set[uuid.UUID]:
        ctx_role.set(role)
        try:
            async for session in get_async_session():
                rows = await session.execute(text("SELECT id FROM workflow"))
                return set(rows.scalars().all())
        finally:
            ctx_role.set(None)
        raise AssertionError("get_async_session yielded no session")

    @pytest.mark.anyio
    @pytest.mark.usefixtures("app_engine")
    async def test_enforce_mode_scopes_sessions_to_the_role(
        self, monkeypatch: pytest.MonkeyPatch, tenant_db: MigratedTenantDB
    ) -> None:
        monkeypatch.setattr(config, "AUTOSECOPS__RLS_MODE", config.RLSMode.ENFORCE)
        org_a = tenant_db.org_a
        workspace_role = Role(
            type="user",
            workspace_id=org_a.workspace_ids[0],
            organization_id=org_a.org_id,
            user_id=uuid.uuid4(),
            service_id="autosecops-api",
        )
        superuser_role = Role(
            type="user",
            user_id=uuid.uuid4(),
            service_id="autosecops-api",
            is_platform_superuser=True,
        )

        assert await self._visible_workflows(workspace_role) == {org_a.workflow_ids[0]}
        assert await self._visible_workflows(None) == set()
        assert (
            await self._visible_workflows(superuser_role) >= tenant_db.all_workflow_ids
        )

    @pytest.mark.anyio
    @pytest.mark.usefixtures("app_engine")
    @pytest.mark.parametrize("mode", ["off", "shadow"])
    async def test_off_and_shadow_modes_bypass_policies(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tenant_db: MigratedTenantDB,
        mode: str,
    ) -> None:
        """Only enforce mode isolates tenants; off and shadow set the bypass."""
        monkeypatch.setattr(config, "AUTOSECOPS__RLS_MODE", config.RLSMode(mode))
        org_a = tenant_db.org_a
        role = Role(
            type="user",
            workspace_id=org_a.workspace_ids[0],
            organization_id=org_a.org_id,
            user_id=uuid.uuid4(),
            service_id="autosecops-api",
        )
        assert await self._visible_workflows(role) >= tenant_db.all_workflow_ids

    @pytest.mark.anyio
    async def test_ctx_role_is_used_by_enforced_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(config, "AUTOSECOPS__RLS_MODE", config.RLSMode.ENFORCE)
        role = Role(
            type="user",
            workspace_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            service_id="autosecops-api",
        )
        ctx_role.set(role)
        try:
            async for session in get_async_session():
                result = await session.execute(
                    text(f"SELECT current_setting('{RLS_VAR_WORKSPACE_ID}', true)")
                )
                assert result.scalar() == str(role.workspace_id)
                break
        finally:
            ctx_role.set(None)
