import base64
import contextlib
import json
from collections.abc import AsyncGenerator
from contextvars import ContextVar
from typing import Any, Literal, Protocol

import boto3
from botocore.exceptions import ClientError
from loguru import logger
from sqlalchemy import event, text
from sqlalchemy.engine import Result, make_url
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy.sql.selectable import TypedReturnsRows

from autosecops import config
from autosecops.contexts import ctx_role
from autosecops.db import (
    session_events,  # noqa: F401  # pyright: ignore[reportUnusedImport] - side effect import to register listeners
    soft_delete,  # noqa: F401  # pyright: ignore[reportUnusedImport] - side effect import to register listeners
)
from autosecops.db.exceptions import (
    AuthPoolExhaustedError,
    DatabasePoolAcquisitionOrderError,
)
from autosecops.db.locks import (
    hold_pg_advisory_xact_lock,
    require_lock_holder_on_commit,
)
from autosecops.db.rls import set_rls_context, set_rls_context_from_role
from autosecops.db.types import DbPoolName, DbPoolUsage

# Global so we don't create more than one engine per process.
# Outside of being best practice, this is needed so we can properly pool
# connections and not create a new pool on every request
_async_engine: AsyncEngine | None = None

# Dedicated operational bulkhead for short authentication/bootstrap lookups.
# It uses the same database URI, role, and RLS mechanism as the main engine; a
# separate database role is a distinct follow-up and is required for a true
# privilege boundary.
#
# INVARIANT: the dependency between pools is one-directional. Main-pool code may
# acquire an auth-pool connection, but auth-pool code must never wait on the main
# pool or acquire a second auth connection. Without a cycle there is no
# hold-and-wait deadlock.
_async_auth_engine: AsyncEngine | None = None
_ctx_auth_pool_session: ContextVar[AsyncSession | None] = ContextVar(
    "auth_pool_session",
    default=None,
)
_owner_connection_warned = False


class SupportsExecute(Protocol):
    """Read surface shared by request sessions and auth handles.

    Helpers that legitimately serve both pools (e.g. entitlement lookups) take
    this instead of a concrete session type, so neither caller has to widen.
    """

    async def execute[T: tuple[Any, ...]](
        self, statement: TypedReturnsRows[T]
    ) -> Result[T]: ...


class AuthSession:
    """Capability-narrowed handle over an authentication-bulkhead session.

    Deliberately does NOT subclass `AsyncSession`: any subclass or `NewType`
    stays assignable to `AsyncSession`, so a future caller could take an
    auth-pool handle and use it for general or background work — the exact
    misuse the bulkhead exists to prevent. Composition makes that a type error.

    The surface below is the union of what today's authentication callsites
    need, and nothing more. Notably absent: `begin`, `flush`, `delete`,
    `merge`, `refresh`, `get`, and access to the wrapped session — long-lived
    or transactional work does not belong on this pool. `add`/`commit` exist
    only for the API-key `last_used_at` write.

    The `_ctx_auth_pool_session` guard remains the runtime backstop for
    checkouts that static analysis cannot see.
    """

    __slots__ = ("_session",)

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def execute[T: tuple[Any, ...]](
        self, statement: TypedReturnsRows[T]
    ) -> Result[T]:
        return await self._session.execute(statement)

    def add(self, instance: object) -> None:
        self._session.add(instance)

    async def commit(self) -> None:
        await self._session.commit()


def _assert_main_pool_checkout_allowed() -> None:
    """Reject a main-pool checkout while the current task holds the auth pool.

    This raises in every environment because logging and continuing would allow
    the exact cross-pool cycle that the auth bulkhead exists to prevent.
    """
    if _ctx_auth_pool_session.get() is not None:
        raise DatabasePoolAcquisitionOrderError(
            "Cannot acquire a main-pool connection while an auth-pool session is held"
        )


def _guard_main_pool_checkout(
    _dbapi_connection: object,
    _connection_record: object,
    _connection_proxy: object,
) -> None:
    """SQLAlchemy checkout listener enforcing auth-to-main acquisition order."""
    _assert_main_pool_checkout_allowed()


async def _initialize_session_rls_context(session: AsyncSession) -> None:
    """Initialize RLS context for a newly opened request session."""
    rls_mode = config.AUTOSECOPS__RLS_MODE

    if rls_mode == config.RLSMode.ENFORCE:
        # Enforce mode applies role-based context with deny-default fallback.
        await set_rls_context_from_role(session)
        return

    role = ctx_role.get()
    user_id = role.user_id if role is not None else None

    if rls_mode == config.RLSMode.SHADOW:
        logger.trace(
            "RLS shadow mode active (bypass context with telemetry)",
            has_role=role is not None,
            role_type=role.type if role is not None else None,
            has_org_context=bool(role and role.organization_id),
            has_workspace_context=bool(role and role.workspace_id),
            is_platform_superuser=bool(role and role.is_platform_superuser),
        )

    # Off/shadow modes use bypass by default so rollout is app-controlled.
    await set_rls_context(
        session,
        org_id=None,
        workspace_id=None,
        user_id=user_id,
        bypass=True,
    )


def get_connection_string(
    *,
    username: str,
    password: str,
    host: str = "postgres_db",
    port: int | str = 5432,
    database: str = "postgres",
    scheme: str = "postgresql",
    driver: Literal["asyncpg", "psycopg"] = "asyncpg",
    sslmode: str | None = None,
) -> str:
    base = f"{scheme}+{driver}://{username}:{password}@{host}:{port!s}/{database}"
    if sslmode:
        # asyncpg uses 'ssl' parameter, psycopg uses 'sslmode'
        if driver == "asyncpg":
            # Map PostgreSQL sslmode to asyncpg ssl parameter
            # asyncpg accepts: 'disable', 'prefer', 'require', 'verify-ca', 'verify-full'
            return f"{base}?ssl={sslmode}"
        return f"{base}?sslmode={sslmode}"
    return base


def runtime_role_configured() -> bool:
    """Whether services connect as the non-owner runtime role."""
    return config.AUTOSECOPS__DB_RUNTIME_PASSWORD is not None


def _with_runtime_role_credentials(uri: str) -> str:
    """Swap the owner credentials in ``uri`` for the runtime role's.

    The host, port, database and TLS options stay those of the owner URI, so
    every way of configuring the owner connection also locates the database for
    the runtime role.
    """
    url = make_url(uri).set(
        username=config.AUTOSECOPS__DB_RUNTIME_USER,
        password=config.AUTOSECOPS__DB_RUNTIME_PASSWORD,
    )
    return url.render_as_string(hide_password=False)


def _warn_once_if_owner_connection() -> None:
    """Log once per process when tenant RLS cannot bind the service role."""
    global _owner_connection_warned
    if _owner_connection_warned or runtime_role_configured():
        return
    _owner_connection_warned = True
    logger.warning(
        "AUTOSECOPS__DB_RUNTIME_PASSWORD is not set, so this service connects as"
        " the database owner. PostgreSQL exempts table owners from row-level"
        " security, so tenant RLS isolation is inactive. Set"
        " AUTOSECOPS__DB_RUNTIME_PASSWORD and rerun migrations to enable it.",
        rls_mode=config.AUTOSECOPS__RLS_MODE.value,
    )


def _get_db_uri(
    driver: Literal["psycopg", "asyncpg"] = "psycopg",
    *,
    as_owner: bool = False,
) -> str:
    """Resolve the database URI for this process.

    Args:
        driver: SQLAlchemy driver to render into the URI.
        as_owner: Return the owner (migration) credentials even when runtime
            role credentials are configured.
    """
    uri = _get_owner_db_uri(driver)
    if as_owner or not runtime_role_configured():
        return uri
    return _with_runtime_role_credentials(uri)


def _get_owner_db_uri(driver: Literal["psycopg", "asyncpg"]) -> str:
    # Check if AWS environment
    if config.AUTOSECOPS__DB_PASS__ARN:
        logger.info("Retrieving database password from AWS Secrets Manager...")
        try:
            session = boto3.session.Session()
            client = session.client(service_name="secretsmanager")
            response = client.get_secret_value(SecretId=config.AUTOSECOPS__DB_PASS__ARN)
            secret_string = response.get("SecretString")
            if not secret_string and response.get("SecretBinary"):
                try:
                    secret_string = base64.b64decode(response["SecretBinary"]).decode(
                        "utf-8"
                    )
                except UnicodeDecodeError as e:
                    logger.error(
                        "Error decoding secret from AWS Secrets Manager."
                        " SecretBinary must be UTF-8 encoded text or JSON."
                        " Use SecretString for plain text credentials.",
                        error=e,
                    )
                    raise e
            if not secret_string:
                raise KeyError("SecretString")

            parsed_json = True
            try:
                secret_payload = json.loads(secret_string)
            except json.JSONDecodeError:
                parsed_json = False
                secret_payload = {}

            username = config.AUTOSECOPS__DB_USER
            password = None
            if isinstance(secret_payload, dict):
                username = username or secret_payload.get("username")
                password = secret_payload.get("password")

            if not password:
                if not parsed_json and config.AUTOSECOPS__DB_USER:
                    password = secret_string
                else:
                    raise KeyError("password")

            if not username:
                raise KeyError("username")
        except ClientError as e:
            logger.error(
                "Error retrieving secret from AWS secrets manager."
                " Please check that the ECS task has sufficient permissions to read the secret and that the secret exists.",
                error=e,
            )
            raise e
        except KeyError as e:
            logger.error(
                "Error retrieving secret from AWS secrets manager."
                " Please check that the database secret in AWS Secrets Manager is a valid JSON object"
                " with `username` and `password` (or set AUTOSECOPS__DB_USER and store the password as the secret string)."
            )
            raise e

        # Get the password from AWS Secrets Manager
        if not config.AUTOSECOPS__DB_ENDPOINT:
            raise ValueError(
                "AUTOSECOPS__DB_ENDPOINT is required when using AWS Secrets Manager"
            )
        if not config.AUTOSECOPS__DB_PORT:
            raise ValueError(
                "AUTOSECOPS__DB_PORT is required when using AWS Secrets Manager"
            )
        if not config.AUTOSECOPS__DB_NAME:
            raise ValueError(
                "AUTOSECOPS__DB_NAME is required when using AWS Secrets Manager"
            )
        uri = get_connection_string(
            username=username,
            password=password,
            host=config.AUTOSECOPS__DB_ENDPOINT,
            port=config.AUTOSECOPS__DB_PORT,
            database=config.AUTOSECOPS__DB_NAME,
            driver=driver,
            sslmode=config.AUTOSECOPS__DB_SSLMODE,
        )
        logger.info("Successfully retrieved database password from AWS Secrets Manager")
    # Else check if the password is in the local environment
    elif config.AUTOSECOPS__DB_USER and config.AUTOSECOPS__DB_PASS:
        if not config.AUTOSECOPS__DB_ENDPOINT:
            raise ValueError(
                "AUTOSECOPS__DB_ENDPOINT is required when using DB credentials"
            )
        if not config.AUTOSECOPS__DB_PORT:
            raise ValueError(
                "AUTOSECOPS__DB_PORT is required when using DB credentials"
            )
        if not config.AUTOSECOPS__DB_NAME:
            raise ValueError(
                "AUTOSECOPS__DB_NAME is required when using DB credentials"
            )
        uri = get_connection_string(
            username=config.AUTOSECOPS__DB_USER,
            password=config.AUTOSECOPS__DB_PASS,
            host=config.AUTOSECOPS__DB_ENDPOINT,
            port=config.AUTOSECOPS__DB_PORT,
            database=config.AUTOSECOPS__DB_NAME,
            driver=driver,
            sslmode=config.AUTOSECOPS__DB_SSLMODE,
        )
    # Else use the default URI
    else:
        uri = config.AUTOSECOPS__DB_URI
        if driver == "asyncpg":
            uri = uri.replace("psycopg", "asyncpg")
    return uri


def _create_async_db_engine() -> AsyncEngine:
    # Postgres as default
    _warn_once_if_owner_connection()
    uri = _get_db_uri(driver="asyncpg")
    engine = create_async_engine(
        uri,
        max_overflow=config.AUTOSECOPS__DB_MAX_OVERFLOW,
        pool_recycle=config.AUTOSECOPS__DB_POOL_RECYCLE,
        pool_size=config.AUTOSECOPS__DB_POOL_SIZE,
        pool_timeout=config.AUTOSECOPS__DB_POOL_TIMEOUT,
        pool_pre_ping=True,
        pool_use_lifo=True,  # Better for burst workloads
        # Keep statement parameters (encrypted secrets, tokens, user input) out
        # of exception messages, logs and error reports.
        hide_parameters=True,
        # Attribute pooled connections to the originating service in
        # pg_stat_activity.
        connect_args={
            "server_settings": {"application_name": config.AUTOSECOPS__SERVICE_NAME}
        },
    )
    event.listen(engine.sync_engine, "checkout", _guard_main_pool_checkout)
    return engine


def _create_async_auth_db_engine() -> AsyncEngine:
    """Create the operational bulkhead for short authentication lookups.

    Same connection settings as the main engine, but a separate (small) pool and
    a distinct `application_name` so `pg_stat_activity` attributes authentication
    lookups separately from request-scoped work. This is not a privilege
    boundary: both engines use the same database role and RLS session settings.
    """
    uri = _get_db_uri(driver="asyncpg")
    return create_async_engine(
        uri,
        max_overflow=config.AUTOSECOPS__DB_AUTH_MAX_OVERFLOW,
        pool_recycle=config.AUTOSECOPS__DB_POOL_RECYCLE,
        pool_size=config.AUTOSECOPS__DB_AUTH_POOL_SIZE,
        pool_timeout=config.AUTOSECOPS__DB_POOL_TIMEOUT,
        pool_pre_ping=True,
        pool_use_lifo=True,  # Better for burst workloads
        # Keep statement parameters (encrypted secrets, tokens, user input) out
        # of exception messages, logs and error reports.
        hide_parameters=True,
        connect_args={
            "server_settings": {
                "application_name": f"{config.AUTOSECOPS__SERVICE_NAME}-auth"
            }
        },
    )


def get_async_engine() -> AsyncEngine:
    """Get the db async connection pool."""
    global _async_engine
    if _async_engine is None:
        _async_engine = _create_async_db_engine()
    return _async_engine


def get_async_auth_engine() -> AsyncEngine:
    """Get the async connection pool for short authentication lookups.

    This operational bulkhead isolates auth admission capacity from the main
    request pool. It does not provide additional database privileges.
    """
    global _async_auth_engine
    if _async_auth_engine is None:
        _async_auth_engine = _create_async_auth_db_engine()
    return _async_auth_engine


def get_pool_usage() -> list[DbPoolUsage]:
    """Report usage of the connection pools this process has created.

    Pools are created lazily, so an engine that has not been used yet is
    omitted rather than created here.
    """
    pools: tuple[tuple[DbPoolName, AsyncEngine | None, int], ...] = (
        (
            "main",
            _async_engine,
            config.AUTOSECOPS__DB_POOL_SIZE + config.AUTOSECOPS__DB_MAX_OVERFLOW,
        ),
        (
            "auth",
            _async_auth_engine,
            config.AUTOSECOPS__DB_AUTH_POOL_SIZE
            + config.AUTOSECOPS__DB_AUTH_MAX_OVERFLOW,
        ),
    )
    usage: list[DbPoolUsage] = []
    for name, engine, max_connections in pools:
        if engine is None or not isinstance(pool := engine.pool, QueuePool):
            continue
        usage.append(
            DbPoolUsage(
                pool=name,
                in_use=pool.checkedout(),
                idle=pool.checkedin(),
                max_connections=max_connections,
            )
        )
    return usage


def reset_async_engine() -> None:
    """Reset the global async engines.

    This should only be used in tests to ensure clean state between tests.
    """
    global _async_engine, _async_auth_engine
    _async_engine = None
    _async_auth_engine = None


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async SQLAlchemy database session with RLS context.

    Behavior depends on AUTOSECOPS__RLS_MODE:
    - off: bypass context by default
    - shadow: bypass context + rollout telemetry
    - enforce: role-derived context with deny-default fallback
    """
    _assert_main_pool_checkout_allowed()
    async with AsyncSession(get_async_engine(), expire_on_commit=False) as session:
        await _initialize_session_rls_context(session)
        yield session


async def get_async_session_bypass_rls() -> AsyncGenerator[AsyncSession, None]:
    """Get an async SQLAlchemy database session with explicit RLS bypass context.

    Use this only for system operations that need unrestricted access:
    - Database migrations
    - Background jobs without user context
    - Administrative operations

    WARNING: Use sparingly and only when necessary. Prefer get_async_session()
    with proper role context for most operations.
    """
    _assert_main_pool_checkout_allowed()
    async with AsyncSession(get_async_engine(), expire_on_commit=False) as session:
        await set_rls_context(
            session,
            org_id=None,
            workspace_id=None,
            user_id=None,
            bypass=True,
        )
        yield session


async def get_async_session_auth() -> AsyncGenerator[AuthSession, None]:
    """Get an RLS-bypass session from the authentication bulkhead.

    Only short authentication/bootstrap lookups may use this accessor. It is an
    operational isolation measure, not a database privilege boundary.
    """
    if _ctx_auth_pool_session.get() is not None:
        raise DatabasePoolAcquisitionOrderError(
            "Cannot acquire a nested auth-pool session"
        )

    async with AsyncSession(get_async_auth_engine(), expire_on_commit=False) as session:
        token = _ctx_auth_pool_session.set(session)
        try:
            try:
                await set_rls_context(
                    session,
                    org_id=None,
                    workspace_id=None,
                    user_id=None,
                    bypass=True,
                )
            except SQLAlchemyTimeoutError as exc:
                raise AuthPoolExhaustedError(
                    "Authentication database pool checkout timed out"
                ) from exc
            yield AuthSession(session)
        finally:
            _ctx_auth_pool_session.reset(token)


def get_async_session_context_manager() -> contextlib.AbstractAsyncContextManager[
    AsyncSession
]:
    """Get a context manager for an async SQLAlchemy database session with RLS context."""
    return contextlib.asynccontextmanager(get_async_session)()


@contextlib.asynccontextmanager
async def get_serialized_session(lock_key: int) -> AsyncGenerator[AsyncSession, None]:
    """Start a tenant-scoped serializable snapshot only after acquiring the lock.

    Uses two main-pool connections: one holds the lock, one runs the snapshot.
    """
    if not (-(2**63) <= lock_key < 2**63):
        raise ValueError(
            f"Lock key {lock_key} out of range for PostgreSQL advisory locks"
        )
    _assert_main_pool_checkout_allowed()
    engine = get_async_engine()
    # The lock lives on its own connection so the snapshot transaction begins
    # after the previous holder committed, and may commit more than once.
    async with hold_pg_advisory_xact_lock(engine, lock_key) as holder:
        assert holder is not None
        async with engine.connect() as connection:
            await connection.execution_options(isolation_level="SERIALIZABLE")
            async with AsyncSession(connection, expire_on_commit=False) as session:
                require_lock_holder_on_commit(session, holder, lock_key)
                await _initialize_session_rls_context(session)
                yield session


def get_async_session_bypass_rls_context_manager() -> (
    contextlib.AbstractAsyncContextManager[AsyncSession]
):
    """Get a context manager for an async session with explicit RLS bypass.

    Use this for system operations that need unrestricted database access.
    """
    return contextlib.asynccontextmanager(get_async_session_bypass_rls)()


def get_async_session_auth_context_manager() -> contextlib.AbstractAsyncContextManager[
    AuthSession
]:
    """Get a context manager for a short authentication bulkhead session."""
    return contextlib.asynccontextmanager(get_async_session_auth)()


async def log_rls_posture() -> bool:
    """Log whether tenant RLS isolates this service's sessions.

    Isolation needs `enforce` mode and a connection role that PostgreSQL
    subjects to row-level security: not a superuser, not BYPASSRLS, and not the
    owner role that migrations run as.

    Returns:
        True when tenant RLS isolation is active.
    """
    async with get_async_session_bypass_rls_context_manager() as session:
        row = (
            await session.execute(
                text(
                    "SELECT current_user, rolsuper, rolbypassrls"
                    " FROM pg_roles WHERE rolname = current_user"
                )
            )
        ).one()
    db_role, is_superuser, bypasses_rls = row
    active = (
        config.AUTOSECOPS__RLS_MODE == config.RLSMode.ENFORCE
        and runtime_role_configured()
        and not is_superuser
        and not bypasses_rls
    )
    log = logger.info if active else logger.warning
    log(
        "RLS posture",
        rls_mode=config.AUTOSECOPS__RLS_MODE.value,
        db_role=db_role,
        rls_isolation_active=active,
    )
    return active
