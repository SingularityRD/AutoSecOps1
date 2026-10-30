"""Provision the non-owner database role the services connect as.

PostgreSQL never applies row-level security to superusers, to roles with
BYPASSRLS, or to a table's owner unless the table forces it. Tenant RLS
therefore only isolates tenants when the API, workers, executors and agent
services connect as a separate login role that owns nothing in ``public``.

The migrations step connects as the owner, so after ``alembic upgrade head``
it calls :func:`provision_runtime_role` to create that role (or update its
password) and to re-apply its grants. Every statement is idempotent, so each
deployment's migrations run converges the role to the expected state.

Workspace schemas (``tables_*`` and ``custom_fields_*``) are the exception to
"owns nothing": the services create and alter them at runtime, which requires
ownership. The runtime role therefore owns them, and their tables force RLS so
the owner is still subject to the workspace policy.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

import psycopg
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from autosecops import config
from autosecops.logger import logger

_ROLE_NAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
WORKSPACE_SCHEMA_PATTERN = r"^(tables|custom_fields)_ws_[0-9A-Za-z]+$"
"""Schemas the services create per workspace and must own to run DDL in."""

RUNTIME_TABLE_PRIVILEGES = "SELECT, INSERT, UPDATE, DELETE"
RUNTIME_SEQUENCE_PRIVILEGES = "USAGE, SELECT"
RUNTIME_REFERENCED_TABLES = ("case",)
"""Public tables that runtime-created workspace tables reference by foreign key.

The per-workspace ``custom_fields_*.case_fields`` table references ``case``.
"""


class RuntimeRoleError(RuntimeError):
    """The runtime role cannot be made safe for tenant RLS."""


@dataclass(frozen=True, slots=True)
class RuntimeRoleCredentials:
    """Login credentials for the runtime role."""

    username: str
    password: str = field(repr=False)


@dataclass(slots=True)
class RuntimeRoleReport:
    """What a provisioning run changed or could not change."""

    owner: str
    runtime_role: str
    created: bool = False
    workspace_objects_reassigned: int = 0
    warnings: list[str] = field(default_factory=list)


def runtime_role_credentials_from_config() -> RuntimeRoleCredentials | None:
    """Return the configured runtime credentials, or None when unset."""
    password = config.AUTOSECOPS__DB_RUNTIME_PASSWORD
    if password is None:
        return None
    return RuntimeRoleCredentials(
        username=config.AUTOSECOPS__DB_RUNTIME_USER, password=password
    )


def _ident(name: str) -> sql.Identifier:
    return sql.Identifier(name)


class _Provisioner:
    """Runs provisioning statements on one owner connection."""

    def __init__(
        self, connection: Connection, credentials: RuntimeRoleCredentials
    ) -> None:
        self._conn = connection
        self._creds = credentials
        self._role = _ident(credentials.username)
        owner = connection.execute(text("SELECT current_user")).scalar_one()
        self.report = RuntimeRoleReport(owner=owner, runtime_role=credentials.username)

    def _exec(self, statement: sql.Composed) -> None:
        # Run on the driver cursor without parameters, so a password with `%`
        # is never parsed as a placeholder. It shares the SQLAlchemy
        # connection's transaction and savepoints.
        driver_connection = self._conn.connection.driver_connection
        if not isinstance(driver_connection, psycopg.Connection):
            raise RuntimeRoleError("Runtime role provisioning requires psycopg")
        with driver_connection.cursor() as cursor:
            cursor.execute(statement)

    def _try(self, description: str, action: Callable[[], None]) -> bool:
        """Run ``action`` in a savepoint; record a warning if it is refused."""
        savepoint = self._conn.begin_nested()
        try:
            action()
        except (DBAPIError, psycopg.Error) as exc:
            savepoint.rollback()
            reason = exc.orig if isinstance(exc, DBAPIError) else exc
            message = f"Could not {description}: {reason}"
            self.report.warnings.append(message)
            logger.warning("Runtime role provisioning step skipped", detail=message)
            return False
        savepoint.commit()
        return True

    def _scalar(self, query: str, **params: object) -> object:
        return self._conn.execute(text(query), params).scalar()

    def validate_name(self) -> None:
        name = self._creds.username
        if not _ROLE_NAME_PATTERN.fullmatch(name):
            raise RuntimeRoleError(
                "AUTOSECOPS__DB_RUNTIME_USER must be a lowercase PostgreSQL"
                " identifier of letters, digits and underscores"
            )
        if name == self.report.owner:
            raise RuntimeRoleError(
                "AUTOSECOPS__DB_RUNTIME_USER must differ from the owner role that"
                " runs migrations; PostgreSQL exempts table owners from RLS"
            )

    def ensure_role(self) -> None:
        exists = self._scalar(
            "SELECT 1 FROM pg_roles WHERE rolname = :name",
            name=self._creds.username,
        )
        password = sql.Literal(self._creds.password)
        if exists is None:
            self._exec(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {}"
                    " NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
                ).format(self._role, password)
            )
            self.report.created = True
            return
        self._try(
            "set the runtime role password (a DBA must set it to"
            " AUTOSECOPS__DB_RUNTIME_PASSWORD)",
            lambda: self._exec(
                sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
                    self._role, password
                )
            ),
        )

    def check_role_is_subject_to_rls(self) -> None:
        row = self._conn.execute(
            text(
                "SELECT rolsuper, rolbypassrls,"
                " pg_has_role(rolname, current_user, 'USAGE')"
                " FROM pg_roles WHERE rolname = :name"
            ),
            {"name": self._creds.username},
        ).one()
        is_super, bypasses_rls, acts_as_owner = row
        if is_super or bypasses_rls:
            raise RuntimeRoleError(
                f"Runtime role {self._creds.username!r} is a superuser or has"
                " BYPASSRLS; recreate it as NOSUPERUSER NOBYPASSRLS"
            )
        if acts_as_owner:
            raise RuntimeRoleError(
                f"Runtime role {self._creds.username!r} is a member of the owner"
                f" role {self.report.owner!r} and would bypass RLS; revoke the"
                " membership"
            )

    def grant_public_schema(self) -> None:
        database = self._conn.execute(text("SELECT current_database()")).scalar_one()
        self._try(
            "grant CONNECT on the database",
            lambda: self._exec(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    _ident(database), self._role
                )
            ),
        )
        self._exec(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(self._role))
        table_privs = sql.SQL(RUNTIME_TABLE_PRIVILEGES)
        sequence_privs = sql.SQL(RUNTIME_SEQUENCE_PRIVILEGES)
        self._exec(
            sql.SQL("GRANT {} ON ALL TABLES IN SCHEMA public TO {}").format(
                table_privs, self._role
            )
        )
        self._exec(
            sql.SQL("GRANT {} ON ALL SEQUENCES IN SCHEMA public TO {}").format(
                sequence_privs, self._role
            )
        )
        # Workspace tables the services create point foreign keys at these.
        for table in RUNTIME_REFERENCED_TABLES:
            self._exec(
                sql.SQL("GRANT REFERENCES ON TABLE public.{} TO {}").format(
                    _ident(table), self._role
                )
            )
        # Only migrations may record the schema version.
        self._exec(
            sql.SQL(
                "REVOKE INSERT, UPDATE, DELETE ON TABLE public.alembic_version FROM {}"
            ).format(self._role)
        )
        # Tables a later migration creates get the same grants before the next
        # provisioning run re-applies them.
        self._exec(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT {} ON TABLES TO {}"
            ).format(table_privs, self._role)
        )
        self._exec(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT {} ON SEQUENCES TO {}"
            ).format(sequence_privs, self._role)
        )

    def prepare_workspace_schemas(self) -> None:
        database = self._conn.execute(text("SELECT current_database()")).scalar_one()
        # The services create a schema per workspace for tables and case fields.
        self._try(
            "grant CREATE on the database (workspace tables and case fields need"
            " it to create workspace schemas)",
            lambda: self._exec(
                sql.SQL("GRANT CREATE ON DATABASE {} TO {}").format(
                    _ident(database), self._role
                )
            ),
        )
        owner_is_superuser = self._scalar(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        )
        if not owner_is_superuser:
            # Migrations alter workspace schemas the runtime role owns, and
            # reassigning ownership requires membership in the new owner.
            self._try(
                "grant the runtime role to the owner role",
                lambda: self._exec(
                    sql.SQL("GRANT {} TO {}").format(
                        self._role, _ident(self.report.owner)
                    )
                ),
            )
        self._try("reassign workspace schemas", self._reassign_workspace_schemas)

    def _reassign_workspace_schemas(self) -> None:
        params = {"name": self._creds.username, "pattern": WORKSPACE_SCHEMA_PATTERN}
        schemas = self._conn.execute(
            text(
                "SELECT n.nspname FROM pg_namespace n"
                " WHERE n.nspname ~ :pattern"
                " AND n.nspowner <> (SELECT oid FROM pg_roles WHERE rolname = :name)"
            ),
            params,
        ).scalars()
        for schema in schemas.all():
            self._exec(
                sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(
                    _ident(schema), self._role
                )
            )
            self.report.workspace_objects_reassigned += 1
        relations = self._conn.execute(
            text(
                "SELECT n.nspname, c.relname, c.relkind"
                " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname ~ :pattern AND c.relkind IN ('r', 'p', 'S')"
                " AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :name)"
                # Sequences owned by a column follow their table.
                " AND NOT EXISTS (SELECT 1 FROM pg_depend d"
                "   WHERE d.objid = c.oid AND d.classid = 'pg_class'::regclass"
                "   AND d.deptype IN ('a', 'i') AND c.relkind = 'S')"
            ),
            params,
        ).tuples()
        for schema, relation, kind in relations.all():
            keyword = sql.SQL("SEQUENCE" if kind == "S" else "TABLE")
            self._exec(
                sql.SQL("ALTER {} {}.{} OWNER TO {}").format(
                    keyword, _ident(schema), _ident(relation), self._role
                )
            )
            self.report.workspace_objects_reassigned += 1
        # The runtime role owns these tables, so only FORCE makes their
        # workspace policy apply to it.
        unforced = self._conn.execute(
            text(
                "SELECT n.nspname, c.relname"
                " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname ~ :pattern AND c.relkind IN ('r', 'p')"
                " AND c.relrowsecurity AND NOT c.relforcerowsecurity"
            ),
            params,
        ).tuples()
        for schema, relation in unforced.all():
            self._exec(
                sql.SQL("ALTER TABLE {}.{} FORCE ROW LEVEL SECURITY").format(
                    _ident(schema), _ident(relation)
                )
            )


def provision_runtime_role(
    connection: Connection, credentials: RuntimeRoleCredentials
) -> RuntimeRoleReport:
    """Create or update the runtime role and re-apply its grants.

    Run this as the owner role, inside a transaction, after migrations. It is
    idempotent. It raises :class:`RuntimeRoleError` when the role would bypass
    RLS, and records a warning for each optional step the owner lacks the
    privilege to run, such as a managed database where a DBA owns the role.

    Args:
        connection: A psycopg-backed SQLAlchemy connection as the owner role.
        credentials: The runtime role's name and password.

    Returns:
        A report of what changed and which steps were skipped.
    """
    provisioner = _Provisioner(connection, credentials)
    provisioner.validate_name()
    provisioner.ensure_role()
    provisioner.check_role_is_subject_to_rls()
    provisioner.grant_public_schema()
    provisioner.prepare_workspace_schemas()
    report = provisioner.report
    logger.info(
        "Provisioned database runtime role",
        runtime_role=report.runtime_role,
        owner=report.owner,
        created=report.created,
        workspace_objects_reassigned=report.workspace_objects_reassigned,
        warnings=len(report.warnings),
    )
    return report
