import base64
import binascii
import logging
import os
import re
import uuid
from collections.abc import Mapping
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Literal, cast
from urllib.parse import urlsplit

from autosecops import __version__
from autosecops.agent.constants import (
    AGENT_SANDBOX_TIMEOUT_SECONDS_DEFAULT,
    AGENT_TIMEOUT_CLEANUP_BUFFER_SECONDS,
)
from autosecops.auth.enums import AuthType
from autosecops.executor.enums import ExecutorBackendType
from autosecops.feature_flags.enums import FeatureFlag
from autosecops.licensing.evaluation import license_permits_multi_tenant_mode

# === Logger === #
logger = logging.getLogger(__name__)


def _coerce_env_numeric[T: int | float](*, var: str, value: str, default: T) -> T:
    if isinstance(default, int):
        try:
            return cast(T, int(value))
        except ValueError as e:
            raise ValueError(f"{var} must be an integer (got {value!r})") from e
    try:
        return cast(T, float(value))
    except ValueError as e:
        raise ValueError(f"{var} must be a float (got {value!r})") from e


def bound_env[T: int | float](
    var: str,
    default: T,
    *,
    lower: T | None = None,
    upper: T | None = None,
) -> T:
    """Read a numeric env var with default and optional clamped bounds."""
    if lower is not None and upper is not None and lower > upper:
        raise ValueError(
            f"Invalid bounds for {var}: lower ({lower}) cannot be greater than upper ({upper})"
        )

    env_value = os.environ.get(var)
    if env_value is None or env_value == "":
        bounded = default
    else:
        bounded = _coerce_env_numeric(var=var, value=env_value, default=default)

    if lower is not None and bounded < lower:
        bounded = lower
    if upper is not None and bounded > upper:
        bounded = upper
    return bounded


def env_bool(var: str, *, default: bool) -> bool:
    """Read a boolean env var with explicit tokens and code-defined defaults.

    Missing, empty, or whitespace-only values return default. Non-empty values
    must be one of 1, true, yes, on, 0, false, no, or off.

    Deployment files must not pass boolean env vars through as blank/defaultless
    values. Keep Compose entries as `${VAR:-default}` so `.env` overrides still
    work; keep `.env.example` entries explicit, never blank.
    `tests/unit/test_config.py` enforces this.
    """
    raw_value = os.environ.get(var)
    if raw_value is None or not raw_value.strip():
        return default

    value = raw_value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False

    raise ValueError(f"{var} must be a boolean value (got {raw_value!r})")


# Pre-rename environment variable prefix. Values under it are never read.
_LEGACY_ENV_PREFIX = "TRACECAT_"
_ENV_PREFIX = "AUTOSECOPS_"


def legacy_env_var_replacements(environ: Mapping[str, str]) -> dict[str, str]:
    """Map each pre-rename environment variable present to its replacement name.

    Args:
        environ: The environment to inspect.

    Returns:
        Legacy variable names, such as `TRACECAT__DB_URI`, mapped to the
        `AUTOSECOPS__DB_URI`-style names that AutoSecOps reads instead.
    """
    return {
        name: _ENV_PREFIX + name.removeprefix(_LEGACY_ENV_PREFIX)
        for name in sorted(environ)
        if name.startswith(_LEGACY_ENV_PREFIX)
    }


def report_legacy_env_vars(environ: Mapping[str, str]) -> dict[str, str]:
    """Log an error for every pre-rename environment variable that is set.

    AutoSecOps ignores these variables. The error names the replacement so an
    operator can rename the setting.

    Args:
        environ: The environment to inspect.

    Returns:
        The legacy-to-replacement name mapping that was reported.
    """
    replacements = legacy_env_var_replacements(environ)
    for legacy_name, replacement in replacements.items():
        logger.error(
            "Ignoring environment variable %s: AutoSecOps no longer reads it. "
            "Rename it to %s.",
            legacy_name,
            replacement,
        )
    return replacements


report_legacy_env_vars(os.environ)


class RLSMode(StrEnum):
    """Runtime mode for application-level RLS session behavior."""

    OFF = "off"
    SHADOW = "shadow"
    ENFORCE = "enforce"


class DBEncryptionAlgorithm(StrEnum):
    """Cipher used to encrypt new database values."""

    FERNET = "fernet"
    AES256GCM = "aes256gcm"


# === Internal Services === #
AUTOSECOPS__APP_ENV: Literal["development", "staging", "production"] = cast(
    Literal["development", "staging", "production"],
    os.environ.get("AUTOSECOPS__APP_ENV", "development"),
)
AUTOSECOPS__SERVICE_NAME = os.environ.get("AUTOSECOPS__SERVICE_NAME") or "autosecops"
"""Name of the AutoSecOps service running in this process.

Used to attribute database connections in `pg_stat_activity` via the PostgreSQL
`application_name` session setting.
"""

AUTOSECOPS__API_URL = os.environ.get("AUTOSECOPS__API_URL", "http://localhost:8000")
AUTOSECOPS__API_ROOT_PATH = os.environ.get("AUTOSECOPS__API_ROOT_PATH", "/api")
AUTOSECOPS__PUBLIC_API_URL = os.environ.get(
    "AUTOSECOPS__PUBLIC_API_URL", "http://localhost/api"
)
AUTOSECOPS__PUBLIC_APP_URL = os.environ.get(
    "AUTOSECOPS__PUBLIC_APP_URL", "http://localhost"
)

# Email (SMTP relay). Invitation email delivery is enabled only when every
# required value is configured.
AUTOSECOPS__SMTP_HOST = (os.environ.get("AUTOSECOPS__SMTP_HOST") or "").strip() or None
AUTOSECOPS__SMTP_PORT = int(os.environ.get("AUTOSECOPS__SMTP_PORT") or 587)
if not 1 <= AUTOSECOPS__SMTP_PORT <= 65535:
    raise ValueError(
        f"AUTOSECOPS__SMTP_PORT is an invalid port: {AUTOSECOPS__SMTP_PORT}"
    )
AUTOSECOPS__SMTP_USER = (os.environ.get("AUTOSECOPS__SMTP_USER") or "").strip() or None
# Whitespace is preserved: a stripped password is a different credential.
_smtp_password = os.environ.get("AUTOSECOPS__SMTP_PASSWORD") or ""
AUTOSECOPS__SMTP_PASSWORD = _smtp_password if _smtp_password.strip() else None
AUTOSECOPS__EMAIL_FROM = (
    os.environ.get("AUTOSECOPS__EMAIL_FROM") or ""
).strip() or None

AUTOSECOPS__PLATFORM_OTEL_ENABLED = env_bool(
    "AUTOSECOPS__PLATFORM_OTEL_ENABLED", default=False
)
"""Enable AutoSecOps-operated platform tracing, separate from agent OTel export."""

AUTOSECOPS__LOOP_MAX_BATCH_SIZE = int(
    os.environ.get("AUTOSECOPS__LOOP_MAX_BATCH_SIZE") or 64
)
"""Maximum number of parallel requests to the worker service."""

AUTOSECOPS__DSL_SCHEDULER_MAX_PENDING_TASKS = int(
    os.environ.get("AUTOSECOPS__DSL_SCHEDULER_MAX_PENDING_TASKS") or 64
)
"""Maximum number of scheduler task coroutines allowed in-flight."""

AUTOSECOPS__CHILD_WORKFLOW_DISPATCH_WINDOW = bound_env(
    "AUTOSECOPS__CHILD_WORKFLOW_DISPATCH_WINDOW",
    16,
    lower=8,
    upper=128,
)
"""Hard cap on concurrent child workflow dispatches for looped subflow execution."""

AUTOSECOPS__WORKFLOW_PERMIT_MAX_WAIT_SECONDS = int(
    os.environ.get("AUTOSECOPS__WORKFLOW_PERMIT_MAX_WAIT_SECONDS") or 300
)
"""Maximum seconds to wait for a workflow concurrency permit before failing."""

AUTOSECOPS__WORKFLOW_PERMIT_BACKOFF_BASE_SECONDS = float(
    os.environ.get("AUTOSECOPS__WORKFLOW_PERMIT_BACKOFF_BASE_SECONDS") or 1
)
"""Base backoff in seconds when retrying workflow permit acquisition."""

AUTOSECOPS__WORKFLOW_PERMIT_BACKOFF_MAX_SECONDS = float(
    os.environ.get("AUTOSECOPS__WORKFLOW_PERMIT_BACKOFF_MAX_SECONDS") or 30
)
"""Maximum backoff in seconds when retrying workflow permit acquisition."""

AUTOSECOPS__WORKFLOW_PERMIT_HEARTBEAT_SECONDS = float(
    os.environ.get("AUTOSECOPS__WORKFLOW_PERMIT_HEARTBEAT_SECONDS") or 60
)
"""Interval in seconds between workflow permit heartbeat refreshes."""

AUTOSECOPS__EXPRESSION_REGEX_TIMEOUT_SECONDS = float(
    os.environ.get("AUTOSECOPS__EXPRESSION_REGEX_TIMEOUT_SECONDS") or 1
)
"""Maximum seconds one user-supplied regex in an expression may run.

``FN.regex_*`` patterns run on the ``regex`` engine, which enforces this
timeout and releases the GIL while matching, so a catastrophically
backtracking pattern fails with an expression error instead of stalling the
shared worker.
"""

AUTOSECOPS__PERMIT_TTL_SECONDS = int(
    os.environ.get("AUTOSECOPS__PERMIT_TTL_SECONDS") or 300
)
"""TTL in seconds for workflow/action concurrency permits before stale pruning."""

AUTOSECOPS__ACTION_PERMIT_MAX_WAIT_SECONDS = int(
    os.environ.get("AUTOSECOPS__ACTION_PERMIT_MAX_WAIT_SECONDS") or 120
)
"""Maximum seconds to wait for an action concurrency permit before failing."""

AUTOSECOPS__TIER_LIMITS_CACHE_TTL_SECONDS = int(
    os.environ.get("AUTOSECOPS__TIER_LIMITS_CACHE_TTL_SECONDS") or 30
)
"""TTL in seconds for cached per-organization effective tier limits."""

AUTOSECOPS__EXECUTOR_QUEUE = os.environ.get(
    "AUTOSECOPS__EXECUTOR_QUEUE", "shared-action-queue"
)
"""Task queue for the ExecutorWorker (Temporal activity queue)."""

AUTOSECOPS__EXECUTOR_FOR_EACH_MAX_CONCURRENCY = int(
    os.environ.get("AUTOSECOPS__EXECUTOR_FOR_EACH_MAX_CONCURRENCY") or 4
)
"""Maximum concurrent iterations for a single executor-side action for_each loop."""

AUTOSECOPS__EXECUTOR_MAX_CONCURRENT_ACTIVITIES = int(
    os.environ.get("AUTOSECOPS__EXECUTOR_MAX_CONCURRENT_ACTIVITIES") or 16
)
"""Maximum concurrent activities for the ExecutorWorker Temporal worker."""

AUTOSECOPS__EXECUTOR_THREADPOOL_MAX_WORKERS = int(
    os.environ.get("AUTOSECOPS__EXECUTOR_THREADPOOL_MAX_WORKERS") or 16
)
"""Activity thread-pool size for the ExecutorWorker; bounds concurrent CPU-bound sync activities competing for the GIL."""

AUTOSECOPS__ACTIVITY_HEARTBEAT_TIMEOUT = int(
    os.environ.get("AUTOSECOPS__ACTIVITY_HEARTBEAT_TIMEOUT") or 60
)
"""Heartbeat timeout in seconds for executor activities.

If Temporal does not receive a heartbeat within this window, the activity
is considered failed and can be retried on a healthy worker. Set to 0 to disable."""

AUTOSECOPS__ACTIVITY_HEARTBEAT_INTERVAL = int(
    os.environ.get("AUTOSECOPS__ACTIVITY_HEARTBEAT_INTERVAL") or 30
)
"""Interval in seconds between heartbeat signals sent by executor activities.

Should be less than AUTOSECOPS__ACTIVITY_HEARTBEAT_TIMEOUT (recommended: half)."""

AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_DIR = os.environ.get(
    "AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_DIR", "/tmp/autosecops/registry-cache"
)
"""Directory for caching extracted registry tarballs in subprocess mode. Uses /tmp for ephemeral storage."""

AUTOSECOPS__EXECUTOR_REGISTRY_SQUASHFS_ENABLED = env_bool(
    "AUTOSECOPS__EXECUTOR_REGISTRY_SQUASHFS_ENABLED", default=True
)
"""Prefer SquashFS registry artifacts when sidecars and mount support are available."""

AUTOSECOPS__EXECUTOR_SQUASHFS_MOUNT_MAX_ATTEMPTS = bound_env(
    "AUTOSECOPS__EXECUTOR_SQUASHFS_MOUNT_MAX_ATTEMPTS",
    3,
    lower=1,
)
"""Mount attempts per SquashFS artifact before falling back to extraction.

Losers of a node-wide loop-device race retry; raise this before raising
in-pod mount concurrency."""

AUTOSECOPS__EXECUTOR_REGISTRY_DOWNLOAD_SLOTS = bound_env(
    "AUTOSECOPS__EXECUTOR_REGISTRY_DOWNLOAD_SLOTS", 2, lower=1
)
"""Concurrent cold registry artifact downloads per executor process.

Each download reserves its bytes against the cache cap before writing."""

AUTOSECOPS__EXECUTOR_REGISTRY_EXTRACT_SLOTS = bound_env(
    "AUTOSECOPS__EXECUTOR_REGISTRY_EXTRACT_SLOTS", 1, lower=1
)
"""Concurrent registry artifact extractions per executor process.

unsquashfs already uses every visible core, so one is the default."""

AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_ENTRIES = int(
    os.environ.get("AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_ENTRIES") or 64
)
"""Maximum number of registry artifacts kept in the executor-local cache.

Set to 0 to disable entry-count eviction."""

AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_BYTES = int(
    os.environ.get("AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_BYTES") or 10 * 1024**3
)
"""Maximum on-disk size of the executor-local registry artifact cache, in bytes.

Cold downloads and extraction scratch are admitted within this bound. Mounted
artifacts only account for their backing image file. Set to 0 to disable
size-based eviction and materialization limits."""

AUTOSECOPS__AGENT_SKILL_CACHE_DIR = os.environ.get(
    "AUTOSECOPS__AGENT_SKILL_CACHE_DIR", "/tmp/autosecops/agent-skill-cache"
)
"""Directory for caching extracted published skills on executor workers."""

AUTOSECOPS__COPILOT_SKILLS_DIR = (
    os.environ.get("AUTOSECOPS__COPILOT_SKILLS_DIR")
    or "/var/lib/autosecops/copilot-skills"
)
"""Directory holding the built-in workspace-chat skills vendored from the public
`autosecops-plugins` repository at image build time.

Deliberately outside the Python package tree. These are markdown the agent reads,
not code that gets imported, and keeping them out of `packages/` means neither the
wheel build nor a development bind mount can serve a stale copy."""

AUTOSECOPS__AGENT_SKILL_CACHE_MAX_CONCURRENT_DOWNLOADS = int(
    os.environ.get("AUTOSECOPS__AGENT_SKILL_CACHE_MAX_CONCURRENT_DOWNLOADS") or 8
)
"""Maximum concurrent file downloads while populating a cached published skill."""

# TODO: Set this as an environment variable
AUTOSECOPS__SERVICE_ROLES_WHITELIST = [
    "autosecops-api",
    "autosecops-cli",
    "autosecops-llm-gateway",
    "autosecops-runner",
    "autosecops-schedule-runner",
    "autosecops-case-triggers",
    "autosecops-case-duration-sync",
    "autosecops-ui",
]
AUTOSECOPS__DEFAULT_USER_ID = uuid.UUID(int=0)

# === DB Config === #
AUTOSECOPS__DB_URI = os.environ.get(
    "AUTOSECOPS__DB_URI",
    "postgresql+psycopg://postgres:postgres@postgres_db:5432/postgres",
)
AUTOSECOPS__DB_NAME = os.environ.get("AUTOSECOPS__DB_NAME")
"""The name of the database to connect to."""
AUTOSECOPS__DB_USER = os.environ.get("AUTOSECOPS__DB_USER")
"""The user to connect to the database with."""
AUTOSECOPS__DB_PASS = os.environ.get("AUTOSECOPS__DB_PASS")
"""The password to connect to the database with."""
AUTOSECOPS__DB_ENDPOINT = os.environ.get("AUTOSECOPS__DB_ENDPOINT")
"""The endpoint to connect to the database on."""
AUTOSECOPS__DB_PORT = os.environ.get("AUTOSECOPS__DB_PORT")
"""The port to connect to the database on."""
AUTOSECOPS__DB_SSLMODE = os.environ.get("AUTOSECOPS__DB_SSLMODE", "require")
"""The SSL mode to connect to the database with."""

AUTOSECOPS__DB_PASS__ARN = os.environ.get("AUTOSECOPS__DB_PASS__ARN")
"""(AWS only) ARN of the secret to connect to the database with."""

DEFAULT_DB_RUNTIME_USER = "autosecops_app"
AUTOSECOPS__DB_RUNTIME_USER = (
    os.environ.get("AUTOSECOPS__DB_RUNTIME_USER") or DEFAULT_DB_RUNTIME_USER
)
"""Non-owner login role the services connect as so tenant RLS policies apply.

The migrations step creates it as NOSUPERUSER NOBYPASSRLS and grants it DML on
the application tables. The owner credentials above stay in use for migrations.
"""
AUTOSECOPS__DB_RUNTIME_PASSWORD = (
    os.environ.get("AUTOSECOPS__DB_RUNTIME_PASSWORD") or None
)
"""Password of the runtime role. Unset keeps every service on the owner role.

When unset, services connect with the owner credentials, which PostgreSQL
exempts from row-level security, so tenant isolation relies on application
filters alone.
"""

AUTOSECOPS__DB_MAX_OVERFLOW = int(os.environ.get("AUTOSECOPS__DB_MAX_OVERFLOW") or 60)
"""The maximum number of connections to allow in the pool."""
AUTOSECOPS__DB_POOL_SIZE = int(os.environ.get("AUTOSECOPS__DB_POOL_SIZE") or 10)
"""The size of the connection pool."""
AUTOSECOPS__DB_POOL_TIMEOUT = int(os.environ.get("AUTOSECOPS__DB_POOL_TIMEOUT") or 30)
"""The timeout for the connection pool."""
AUTOSECOPS__DB_POOL_RECYCLE = int(os.environ.get("AUTOSECOPS__DB_POOL_RECYCLE") or 600)
"""The time to recycle the connection pool."""
AUTOSECOPS__DB_AUTH_POOL_SIZE = int(
    os.environ.get("AUTOSECOPS__DB_AUTH_POOL_SIZE") or 5
)
"""The size of the dedicated connection pool for short authentication lookups.

This pool is an operational bulkhead, not a database privilege boundary. It
uses the same database role and URI as the main pool.
"""
AUTOSECOPS__DB_AUTH_MAX_OVERFLOW = int(
    os.environ.get("AUTOSECOPS__DB_AUTH_MAX_OVERFLOW") or 5
)
"""The maximum number of overflow connections for the authentication pool."""


# === Auth config === #
# Infrastructure config
def _parse_auth_types() -> set[AuthType]:
    auth_types: set[AuthType] = set()
    raw_auth_types = os.environ.get("AUTOSECOPS__AUTH_TYPES", "").strip()
    if not raw_auth_types:
        return {AuthType.BASIC}

    for auth_type in raw_auth_types.split(","):
        if not (t := auth_type.strip().lower()):
            continue
        if t == "google_oauth":
            logger.warning(
                "Ignoring removed auth type 'google_oauth' in AUTOSECOPS__AUTH_TYPES; use 'oidc' instead."
            )
            continue
        try:
            auth_types.add(AuthType(t))
        except ValueError:
            logger.warning(
                "Invalid auth type %r in AUTOSECOPS__AUTH_TYPES, skipping", t
            )

    if not auth_types:
        raise ValueError(
            "AUTOSECOPS__AUTH_TYPES must include at least one supported auth type"
        )
    return auth_types


AUTOSECOPS__AUTH_TYPES = _parse_auth_types()
"""The set of allowed auth types on the platform. If an auth type is not in this set,
it cannot be enabled."""

AUTOSECOPS__AUTH_REQUIRE_EMAIL_VERIFICATION = env_bool(
    "AUTOSECOPS__AUTH_REQUIRE_EMAIL_VERIFICATION", default=False
)
SESSION_EXPIRE_TIME_SECONDS = int(
    os.environ.get("SESSION_EXPIRE_TIME_SECONDS") or 86400 * 7
)  # 7 days
SESSION_LAST_SEEN_UPDATE_INTERVAL_SECONDS = int(
    os.environ.get("SESSION_LAST_SEEN_UPDATE_INTERVAL_SECONDS") or 300
)
"""Minimum interval between ``last_seen_at`` writes for an active session."""
AUTOSECOPS__AUTH_ALLOWED_DOMAINS = {
    domain.strip().lower()
    for domain in os.getenv("AUTOSECOPS__AUTH_ALLOWED_DOMAINS", "").split(",")
    if domain.strip()
}
"""Deprecated: This config has been moved into the settings service"""

AUTOSECOPS__AUTH_MIN_PASSWORD_LENGTH = int(
    os.environ.get("AUTOSECOPS__AUTH_MIN_PASSWORD_LENGTH") or 12
)

# Auth endpoint rate limits. Counters live in Redis and use fixed windows; a
# limit of 0 disables that rule. Clients are keyed by the address resolved with
# AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS.
AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED = env_bool(
    "AUTOSECOPS__AUTH_RATE_LIMIT_ENABLED", default=True
)
"""Rate limit login, registration, password reset, invitation tokens, and API-key failures."""
AUTOSECOPS__AUTH_RATE_LIMIT_LOGIN_PER_IP = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_LOGIN_PER_IP", 50, lower=0
)
"""Password login attempts per client IP per minute."""
AUTOSECOPS__AUTH_RATE_LIMIT_LOGIN_PER_ACCOUNT = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_LOGIN_PER_ACCOUNT", 10, lower=0
)
"""Password login attempts per client IP and email per minute."""
AUTOSECOPS__AUTH_RATE_LIMIT_FORGOT_PASSWORD_PER_IP = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_FORGOT_PASSWORD_PER_IP", 20, lower=0
)
"""Forgot-password requests per client IP per hour."""
AUTOSECOPS__AUTH_RATE_LIMIT_FORGOT_PASSWORD_PER_ACCOUNT = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_FORGOT_PASSWORD_PER_ACCOUNT", 5, lower=0
)
"""Forgot-password requests per email per hour, across all clients."""
AUTOSECOPS__AUTH_RATE_LIMIT_RESET_PASSWORD_PER_IP = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_RESET_PASSWORD_PER_IP", 10, lower=0
)
"""Reset-password submissions per client IP per minute."""
AUTOSECOPS__AUTH_RATE_LIMIT_REGISTER_PER_IP = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_REGISTER_PER_IP", 10, lower=0
)
"""Registration attempts per client IP per hour."""
AUTOSECOPS__AUTH_RATE_LIMIT_INVITATION_PER_IP = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_INVITATION_PER_IP", 30, lower=0
)
"""Invitation lookups and acceptances by token per client IP per minute."""
AUTOSECOPS__AUTH_RATE_LIMIT_API_KEY_FAILURES_PER_IP = bound_env(
    "AUTOSECOPS__AUTH_RATE_LIMIT_API_KEY_FAILURES_PER_IP", 20, lower=0
)
"""Failed service-account API-key authentications per client IP per minute
before further API-key attempts from that IP are refused."""

AUTOSECOPS__AUTH_SUPERADMIN_EMAIL = os.environ.get("AUTOSECOPS__AUTH_SUPERADMIN_EMAIL")
"""Email address that is allowed to become the first superuser. If not set, the first user logic is disabled for security."""

# OIDC Login Flow
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").strip().rstrip("/")
"""OIDC issuer URL (without trailing slash). Required when oidc auth is enabled."""

if AUTOSECOPS__AUTH_TYPES == {AuthType.OIDC} and not OIDC_ISSUER:
    raise ValueError(
        "OIDC_ISSUER must be set when AUTOSECOPS__AUTH_TYPES includes 'oidc'"
    )

OIDC_CLIENT_ID = (
    os.environ.get("OIDC_CLIENT_ID") or os.environ.get("OAUTH_CLIENT_ID") or ""
)
OIDC_CLIENT_SECRET = (
    os.environ.get("OIDC_CLIENT_SECRET") or os.environ.get("OAUTH_CLIENT_SECRET") or ""
)
OIDC_SCOPES = tuple(
    scope
    for scope in (
        os.environ.get("OIDC_SCOPES", "openid profile email").replace(",", " ").split()
    )
    if scope
)

# Backward-compatible aliases for legacy config names.
OAUTH_CLIENT_ID = OIDC_CLIENT_ID
OAUTH_CLIENT_SECRET = OIDC_CLIENT_SECRET
USER_AUTH_SECRET = os.environ.get("USER_AUTH_SECRET")
AUTOSECOPS__DB_ENCRYPTION_KEY = os.environ.get("AUTOSECOPS__DB_ENCRYPTION_KEY")
_db_encryption_algorithm_raw = (
    os.environ.get("AUTOSECOPS__DB_ENCRYPTION_ALGORITHM")
    or DBEncryptionAlgorithm.FERNET
)
try:
    AUTOSECOPS__DB_ENCRYPTION_ALGORITHM = DBEncryptionAlgorithm(
        _db_encryption_algorithm_raw.strip().lower()
    )
except ValueError as e:
    raise ValueError(
        "AUTOSECOPS__DB_ENCRYPTION_ALGORITHM must be one of "
        f"{', '.join(DBEncryptionAlgorithm)} (got {_db_encryption_algorithm_raw!r})"
    ) from e
"""Cipher for new database writes (fernet|aes256gcm). Reads accept both."""


def _parse_db_encryption_previous_keys() -> tuple[str, ...]:
    raw = os.environ.get("AUTOSECOPS__DB_ENCRYPTION_PREVIOUS_KEYS") or ""
    keys = tuple(key for part in raw.split(",") if (key := part.strip()))
    for index, key in enumerate(keys):
        try:
            decoded = base64.urlsafe_b64decode(key)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) != 32:
            # Never echo the key itself; name its position instead.
            raise ValueError(
                f"AUTOSECOPS__DB_ENCRYPTION_PREVIOUS_KEYS entry {index} is not "
                "32 url-safe base64-encoded bytes"
            )
    return keys


AUTOSECOPS__DB_ENCRYPTION_PREVIOUS_KEYS = _parse_db_encryption_previous_keys()
"""Comma-separated retired DB encryption keys, used for reads only during rotation."""
AUTOSECOPS__SIGNING_SECRET = os.environ.get("AUTOSECOPS__SIGNING_SECRET")
AUTOSECOPS__AWS_ASSUME_ROLE_ACCOUNT_ID = os.environ.get(
    "AUTOSECOPS__AWS_ASSUME_ROLE_ACCOUNT_ID"
)
"""AWS account ID for AutoSecOps workloads that assume customer roles."""

AUTOSECOPS__AWS_ASSUME_ROLE_PRINCIPAL_ARN = os.environ.get(
    "AUTOSECOPS__AWS_ASSUME_ROLE_PRINCIPAL_ARN"
)
"""Dedicated AWS principal ARN used by AutoSecOps executors for customer AssumeRole."""

# SAML SSO


SAML_PUBLIC_ACS_URL = f"{AUTOSECOPS__PUBLIC_APP_URL}/auth/saml/acs"

SAML_IDP_METADATA_URL = os.environ.get("SAML_IDP_METADATA_URL")
"""Sets the default SAML metadata URL for cold start."""

SAML_ALLOW_UNSOLICITED = env_bool("SAML_ALLOW_UNSOLICITED", default=False)
"""Whether to allow unsolicited SAML responses (default false)
Do not set to true if authn requests are signed are false
"""

SAML_AUTHN_REQUESTS_SIGNED = env_bool("SAML_AUTHN_REQUESTS_SIGNED", default=False)
"""Whether to require signed SAML authentication requests. (default false)
Do not set to true if authn requests are signed are false
"""

SAML_ACCEPTED_TIME_DIFF = int(os.environ.get("SAML_ACCEPTED_TIME_DIFF") or 3)
"""The time difference in seconds for SAML authentication."""

XMLSEC_BINARY_PATH = os.environ.get("XMLSEC_BINARY_PATH", "/usr/bin/xmlsec1")

SAML_CA_CERTS = os.environ.get("SAML_CA_CERTS")
"""Base64 encoded CA certificates for validating self-signed certificates."""

SAML_VERIFY_SSL_ENTITY = env_bool("SAML_VERIFY_SSL_ENTITY", default=True)
"""Whether to verify SSL certificates for general SAML entity operations."""

SAML_VERIFY_SSL_METADATA = env_bool("SAML_VERIFY_SSL_METADATA", default=True)
"""Whether to verify SSL certificates for SAML metadata operations."""

# === CORS config === #
# NOTE: If you are self-hosting AutoSecOps, please replace with your
# own domain by setting the comma separated AUTOSECOPS__ALLOW_ORIGINS env var.
AUTOSECOPS__ALLOW_ORIGINS = os.environ.get("AUTOSECOPS__ALLOW_ORIGINS") or None

# === Temporal config === #
TEMPORAL__CONNECT_RETRIES = int(os.environ.get("TEMPORAL__CONNECT_RETRIES") or 10)
TEMPORAL__CLUSTER_URL = os.environ.get(
    "TEMPORAL__CLUSTER_URL", "http://localhost:7233"
)  # AKA TEMPORAL_HOST_URL
TEMPORAL__CLUSTER_NAMESPACE = os.environ.get(
    "TEMPORAL__CLUSTER_NAMESPACE", "default"
)  # AKA TEMPORAL_NAMESPACE
TEMPORAL__CLUSTER_QUEUE = os.environ.get(
    "TEMPORAL__CLUSTER_QUEUE", "autosecops-task-queue"
)
AUTOSECOPS__BACKGROUND_QUEUE = (
    os.environ.get("AUTOSECOPS__BACKGROUND_QUEUE") or "shared-background-queue"
)
AUTOSECOPS__BACKGROUND_MAX_CONCURRENT_ACTIVITIES = int(
    os.environ.get("AUTOSECOPS__BACKGROUND_MAX_CONCURRENT_ACTIVITIES") or 4
)
if AUTOSECOPS__BACKGROUND_MAX_CONCURRENT_ACTIVITIES < 1:
    raise ValueError(
        "AUTOSECOPS__BACKGROUND_MAX_CONCURRENT_ACTIVITIES must be at least 1"
    )
TEMPORAL__API_KEY__ARN = os.environ.get("TEMPORAL__API_KEY__ARN")
TEMPORAL__API_KEY = os.environ.get("TEMPORAL__API_KEY")
TEMPORAL__CLIENT_RPC_TIMEOUT = os.environ.get("TEMPORAL__CLIENT_RPC_TIMEOUT") or "900"
"""RPC timeout for Temporal workflows in seconds (default 900 seconds)."""

TEMPORAL__TASK_TIMEOUT = os.environ.get("TEMPORAL__TASK_TIMEOUT") or "900"
"""Temporal workflow task timeout in seconds (default 900 seconds)."""

TEMPORAL__METRICS_PORT = os.environ.get("TEMPORAL__METRICS_PORT")
"""Port for the Temporal metrics server."""


TEMPORAL__DISABLE_EAGER_ACTIVITY_EXECUTION = env_bool(
    "TEMPORAL__DISABLE_EAGER_ACTIVITY_EXECUTION", default=True
)
"""Disable eager activity execution for Temporal workflows."""
TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED = env_bool(
    "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED", default=False
)
"""Enable application-layer encryption for Temporal payloads."""

TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING = os.environ.get(
    "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING"
)
"""JSON keyring used to derive workspace-scoped Temporal payload keys."""

TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING_ARN = os.environ.get(
    "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING_ARN"
)
"""AWS Secrets Manager ARN containing the Temporal payload encryption keyring."""

TEMPORAL__PAYLOAD_ENCRYPTION_CACHE_TTL_SECONDS = int(
    os.environ.get("TEMPORAL__PAYLOAD_ENCRYPTION_CACHE_TTL_SECONDS") or 3600
)
"""TTL for cached derived Temporal payload keys."""

TEMPORAL__PAYLOAD_ENCRYPTION_CACHE_MAX_ITEMS = int(
    os.environ.get("TEMPORAL__PAYLOAD_ENCRYPTION_CACHE_MAX_ITEMS") or 4096
)
"""Maximum number of cached derived Temporal payload keys."""

# === Sentry config === #
SENTRY_ENVIRONMENT_OVERRIDE = os.environ.get("SENTRY_ENVIRONMENT_OVERRIDE")
"""Override the Sentry environment. If not set, defaults to '{app_env}-{temporal_namespace}'."""

# === Secrets manager config === #
AUTOSECOPS__UNSAFE_DISABLE_SM_MASKING = env_bool(
    "AUTOSECOPS__UNSAFE_DISABLE_SM_MASKING", default=False
)
"""Disable masking of secrets in the secrets manager.
    WARNING: This is only be used for testing and debugging purposes during
    development and should never be enabled in production.
"""

AUTOSECOPS__UNSAFE_DISABLE_SECRET_ERROR_WITHHOLDING = env_bool(
    "AUTOSECOPS__UNSAFE_DISABLE_SECRET_ERROR_WITHHOLDING", default=False
)
"""Legacy setting accepted by existing deployments; no longer changes behavior.
Action and expression errors always use selective masking of known secrets and
observed secret-derived values.
"""

# === M2M config === #
AUTOSECOPS__SERVICE_KEY = os.environ.get("AUTOSECOPS__SERVICE_KEY")
AUTOSECOPS__EXECUTOR_TOKEN_TTL_SECONDS = int(
    os.environ.get("AUTOSECOPS__EXECUTOR_TOKEN_TTL_SECONDS") or 900
)
"""Executor JWT TTL in seconds (default: 900 seconds)."""

# === Remote registry === #
AUTOSECOPS__ALLOWED_GIT_DOMAINS = set(
    os.environ.get(
        "AUTOSECOPS__ALLOWED_GIT_DOMAINS", "github.com,gitlab.com,bitbucket.org"
    ).split(",")
)

# === Blob Storage Config === #

AUTOSECOPS__BLOB_STORAGE_BUCKET_ATTACHMENTS = os.environ.get(
    "AUTOSECOPS__BLOB_STORAGE_BUCKET_ATTACHMENTS", "autosecops-attachments"
)
"""Bucket for case attachments."""

AUTOSECOPS__BLOB_STORAGE_BUCKET_REGISTRY = os.environ.get(
    "AUTOSECOPS__BLOB_STORAGE_BUCKET_REGISTRY", "autosecops-registry"
)
"""Bucket for registry tarball files and versioned artifacts."""

AUTOSECOPS__BLOB_STORAGE_BUCKET_SKILLS = os.environ.get(
    "AUTOSECOPS__BLOB_STORAGE_BUCKET_SKILLS", "autosecops-skills"
)
"""Bucket for workspace skill blobs."""

AUTOSECOPS__BLOB_STORAGE_ENDPOINT = os.environ.get(
    "AUTOSECOPS__BLOB_STORAGE_ENDPOINT", ""
)
"""Endpoint URL for blob storage."""

AUTOSECOPS__BLOB_STORAGE_SSL_VERIFY = env_bool(
    "AUTOSECOPS__BLOB_STORAGE_SSL_VERIFY", default=True
)
"""Verify TLS certificates when connecting to blob storage (S3/MinIO).

Set to false for self-hosted S3-compatible storage that terminates TLS with a
self-signed or otherwise unverifiable certificate. Defaults to true."""

AUTOSECOPS__BLOB_STORAGE_MAX_ATTEMPTS = int(
    os.environ.get("AUTOSECOPS__BLOB_STORAGE_MAX_ATTEMPTS") or 5
)
"""Total blob storage request attempts (initial try + retries) for transient
S3/MinIO failures. Uses botocore's "standard" retry mode with backoff."""

AUTOSECOPS__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT = os.environ.get(
    "AUTOSECOPS__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT", None
)
"""Public endpoint URL to use for presigned URLs."""

AUTOSECOPS__BLOB_STORAGE_PRESIGNED_URL_EXPIRY = int(
    os.environ.get("AUTOSECOPS__BLOB_STORAGE_PRESIGNED_URL_EXPIRY") or 10
)
"""Default expiry time for presigned URLs in seconds (default: 10 seconds for immediate use)."""

AUTOSECOPS__DISABLE_PRESIGNED_URL_IP_CHECKING = env_bool(
    "AUTOSECOPS__DISABLE_PRESIGNED_URL_IP_CHECKING", default=True
)
"""Disable client IP checking for presigned URLs. Set to false for production with public S3, true for local MinIO (default: true)."""

# Bucket for workflow data (externalized results, triggers, etc.)
AUTOSECOPS__BLOB_STORAGE_BUCKET_WORKFLOW = os.environ.get(
    "AUTOSECOPS__BLOB_STORAGE_BUCKET_WORKFLOW", "autosecops-workflow"
)
"""Bucket for externalized workflow data (action results, triggers, etc.)."""

AUTOSECOPS__BLOB_STORAGE_BUCKET_AGENT = os.environ.get(
    "AUTOSECOPS__BLOB_STORAGE_BUCKET_AGENT", "autosecops-agent"
)
"""Bucket for durable agent filesystem snapshots."""

AUTOSECOPS__WORKFLOW_ARTIFACT_RETENTION_DAYS = int(
    os.environ.get("AUTOSECOPS__WORKFLOW_ARTIFACT_RETENTION_DAYS") or 30
)
"""Retention period in days for workflow artifacts in blob storage.

Objects older than this will be automatically deleted via S3 lifecycle rules.
Set to 0 to disable automatic expiration.
Default: 30 days (matches Temporal Cloud workflow history retention).
"""

# === Result Externalization Config === #
AUTOSECOPS__RESULT_EXTERNALIZATION_ENABLED = env_bool(
    "AUTOSECOPS__RESULT_EXTERNALIZATION_ENABLED", default=True
)
"""Enable externalization of large action results and triggers to S3/MinIO.

When enabled, payloads exceeding the threshold are stored in blob storage with
only a small reference kept in Temporal workflow history. This prevents history
bloat for workflows with large payloads.

Default: true.
"""

AUTOSECOPS__RESULT_EXTERNALIZATION_THRESHOLD_BYTES = int(
    os.environ.get("AUTOSECOPS__RESULT_EXTERNALIZATION_THRESHOLD_BYTES") or 128 * 1024
)
"""Threshold in bytes above which payloads are externalized to blob storage.

Payloads smaller than this are kept inline in workflow history.
Default: 128 KB.
"""

# === Collection Manifests Config === #
AUTOSECOPS__COLLECTION_MANIFESTS_ENABLED = env_bool(
    "AUTOSECOPS__COLLECTION_MANIFESTS_ENABLED", default=False
)
"""Feature gate for CollectionObject emission.

When enabled, large collections (above thresholds) are stored as chunked manifests
in blob storage, with only a small handle kept in Temporal workflow history.
When disabled (default), large collections use legacy InlineObject/ExternalObject.
"""

AUTOSECOPS__COLLECTION_CHUNK_SIZE = int(
    os.environ.get("AUTOSECOPS__COLLECTION_CHUNK_SIZE") or 256
)
"""Number of items per chunk in collection manifests. Default: 256."""

AUTOSECOPS__COLLECTION_INLINE_MAX_ITEMS = int(
    os.environ.get("AUTOSECOPS__COLLECTION_INLINE_MAX_ITEMS") or 100
)
"""Maximum items before using CollectionObject. Below this, use InlineObject/ExternalObject."""

AUTOSECOPS__COLLECTION_INLINE_MAX_BYTES = int(
    os.environ.get("AUTOSECOPS__COLLECTION_INLINE_MAX_BYTES") or 256 * 1024
)
"""Maximum bytes before using CollectionObject. Default: 256 KB."""

# === Local registry === #
AUTOSECOPS__LOCAL_REPOSITORY_ENABLED = env_bool(
    "AUTOSECOPS__LOCAL_REPOSITORY_ENABLED", default=False
)
AUTOSECOPS__LOCAL_REPOSITORY_PATH = os.getenv("AUTOSECOPS__LOCAL_REPOSITORY_PATH")
AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH = "/app/local_registry"

# === Python Script Execution (nsjail Sandbox) === #
AUTOSECOPS__SANDBOX_NSJAIL_PATH = os.environ.get(
    "AUTOSECOPS__SANDBOX_NSJAIL_PATH", "/usr/local/bin/nsjail"
)
"""Path to the nsjail binary for sandbox execution."""

AUTOSECOPS__SANDBOX_ROOTFS_PATH = os.environ.get(
    "AUTOSECOPS__SANDBOX_ROOTFS_PATH", "/var/lib/autosecops/sandbox-rootfs"
)
"""Path to the sandbox rootfs directory containing Python 3.12 + uv.

Used by both action sandbox and agent sandbox. Runtime code is copied
to job directory at spawn time, site-packages mounted read-only.
"""

AUTOSECOPS__SANDBOX_CACHE_DIR = os.environ.get(
    "AUTOSECOPS__SANDBOX_CACHE_DIR", "/var/lib/autosecops/sandbox-cache"
)
"""Base directory for sandbox caching (packages, uv cache)."""

AUTOSECOPS__AGENT_FS_CACHE_DIR = os.environ.get(
    "AUTOSECOPS__AGENT_FS_CACHE_DIR",
    f"{AUTOSECOPS__SANDBOX_CACHE_DIR}/agent-fs",
)
"""Worker-local staging directory for agent filesystem snapshot archives."""

AUTOSECOPS__AGENT_FS_MAX_UNCOMPRESSED_BYTES = int(
    os.environ.get("AUTOSECOPS__AGENT_FS_MAX_UNCOMPRESSED_BYTES") or 1024 * 1024 * 1024
)
"""Maximum uncompressed bytes allowed in one agent filesystem snapshot."""

AUTOSECOPS__AGENT_FS_MAX_FILE_COUNT = int(
    os.environ.get("AUTOSECOPS__AGENT_FS_MAX_FILE_COUNT") or 50_000
)
"""Maximum number of regular files allowed in one agent filesystem snapshot."""

AUTOSECOPS__SANDBOX_DEFAULT_TIMEOUT = int(
    os.environ.get("AUTOSECOPS__SANDBOX_DEFAULT_TIMEOUT") or 300
)
"""Default timeout for sandbox script execution in seconds."""

AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB = int(
    os.environ.get("AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB") or 2048
)
"""Aggregate cgroup memory budget for action and Python sandboxes in MiB."""
if AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB <= 0:
    raise ValueError("AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB must be positive")

_sandbox_address_space_mb = os.environ.get(
    "AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB", ""
).strip()
AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB = (
    int(_sandbox_address_space_mb) if _sandbox_address_space_mb else None
)
"""Per-process address-space cap in MiB.

Unset means uncapped under the sandbox cgroup memory limit, which bounds RAM;
without that cgroup it defaults to twice the memory budget.
"""
if (
    AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB is not None
    and AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB <= 0
):
    raise ValueError("AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB must be positive")

AUTOSECOPS__SANDBOX_PYPI_INDEX_URL = (
    os.environ.get("AUTOSECOPS__SANDBOX_PYPI_INDEX_URL", "").strip()
    or "https://pypi.org/simple"
)
"""Primary PyPI index URL for package installation. Supports private mirrors and air-gapped deployments.

Blank means unset, so deployments can forward an empty override and keep PyPI.
"""

AUTOSECOPS__SANDBOX_PYPI_EXTRA_INDEX_URLS = [
    url.strip()
    for url in os.environ.get("AUTOSECOPS__SANDBOX_PYPI_EXTRA_INDEX_URLS", "").split(
        ","
    )
    if url.strip()
]
"""Additional PyPI index URLs (comma-separated). Used as fallback sources for package installation."""


def env_networks(
    name: str, *, default: tuple[IPv4Network | IPv6Network, ...] = ()
) -> tuple[IPv4Network | IPv6Network, ...]:
    """Parse a comma-separated environment variable into validated IP networks.

    Args:
        name: Environment variable name.
        default: Networks returned when the variable is unset or blank.

    Returns:
        Parsed IPv4 and IPv6 networks in configured order.

    Raises:
        ValueError: If any configured value is not a valid CIDR or IP address.
    """
    raw_value = os.environ.get(name, "")
    if not raw_value.strip():
        return default
    networks: list[IPv4Network | IPv6Network] = []
    for value in raw_value.split(","):
        stripped = value.strip()
        if not stripped:
            continue
        try:
            networks.append(ip_network(stripped))
        except ValueError as exc:
            raise ValueError(f"{name} contains an invalid CIDR: {stripped!r}") from exc
    return tuple(networks)


def env_ports(name: str, *, default: tuple[int, ...]) -> tuple[int, ...]:
    """Parse unique TCP/UDP ports from a comma-separated environment variable."""
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default

    ports: list[int] = []
    for value in raw_value.split(","):
        stripped = value.strip()
        if not stripped:
            continue
        try:
            port = int(stripped)
        except ValueError as exc:
            raise ValueError(f"{name} contains an invalid port: {stripped!r}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"{name} contains an invalid port: {stripped!r}")
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def env_proxy_url(name: str) -> str | None:
    """Parse an optional HTTP(S) forward proxy URL from an environment variable.

    Args:
        name: Environment variable name.

    Returns:
        The stripped proxy URL, or None when the variable is unset or blank.

    Raises:
        ValueError: If the value is not an ``http`` or ``https`` URL with a host
            and no path, query, or fragment. The message omits the value
            because proxy URLs can carry credentials.
    """
    raw_value = (os.environ.get(name) or "").strip()
    if not raw_value:
        return None
    try:
        parsed = urlsplit(raw_value)
        # Accessing the port validates it; urlsplit parses lazily.
        _ = parsed.port
    except ValueError:
        # Suppress the cause: parser messages can echo parts of the value.
        raise ValueError(f"{name} must be a valid proxy URL") from None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"{name} must be an http:// or https:// proxy URL without a path"
        )
    return raw_value


_NO_PROXY_LABEL = r"[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?"
_NO_PROXY_HOSTNAME = re.compile(rf"{_NO_PROXY_LABEL}(\.{_NO_PROXY_LABEL})*")


def env_no_proxy(name: str) -> tuple[str | IPv4Network | IPv6Network, ...]:
    """Parse comma-separated proxy bypass entries from an environment variable.

    Entries are hostnames, which also match their subdomains, or IP addresses
    and CIDRs, which match literal IP hosts. A leading ``.`` or ``*.`` on a
    hostname is accepted and ignored.

    Args:
        name: Environment variable name.

    Returns:
        Lowercase hostnames and parsed networks in configured order.

    Raises:
        ValueError: If an entry is neither a hostname nor an IP address or CIDR.
    """
    raw_value = os.environ.get(name, "")
    entries: list[str | IPv4Network | IPv6Network] = []
    for value in raw_value.split(","):
        stripped = value.strip().lower()
        if not stripped:
            continue
        try:
            entries.append(ip_network(stripped.removeprefix("[").removesuffix("]")))
            continue
        except ValueError:
            pass
        hostname = stripped.removeprefix("*.").removeprefix(".").removesuffix(".")
        if not _NO_PROXY_HOSTNAME.fullmatch(hostname):
            raise ValueError(f"{name} contains an invalid entry: {stripped!r}")
        entries.append(hostname)
    return tuple(entries)


AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS = env_networks(
    "AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS"
)
"""Operator-only exceptions for caller-controlled HTTP destinations.

Covers MCP and LLM endpoints, audit webhook delivery and tests, workspace sync
GitLab and Bitbucket Data Center instance URLs, and OAuth discovery and dynamic
client registration. Empty by default. Configure exact IPs or narrow CIDRs only for intentional private
integrations. Every workspace using these clients can reach an allowed address.
Set this in the process/container environment, not workspace or action inputs.
"""

AUTOSECOPS__OUTBOUND_PROXY_URL = env_proxy_url("AUTOSECOPS__OUTBOUND_PROXY_URL")
"""Operator-configured HTTP(S) forward proxy for caller-controlled destinations.

Unset by default, so outbound clients connect directly. When set, the shared
outbound client still validates each target URL and resolves the target host
locally against the outbound policy, then sends the request through this proxy.
The proxy's own address is dialed without that policy, so it may be private.
Generic ``HTTP_PROXY``/``HTTPS_PROXY`` variables are never honored implicitly.
Tunneled requests keep using their tunnel gateway instead.
"""

AUTOSECOPS__OUTBOUND_NO_PROXY = env_no_proxy("AUTOSECOPS__OUTBOUND_NO_PROXY")
"""Destinations that bypass ``AUTOSECOPS__OUTBOUND_PROXY_URL``.

Hostnames match themselves and their subdomains; IPs and CIDRs match literal IP
hosts. Bypassed requests connect directly under the same outbound policy.
"""

AUTOSECOPS__PLATFORM_ADMIN_IP_ALLOWLIST_BYPASS = env_bool(
    "AUTOSECOPS__PLATFORM_ADMIN_IP_ALLOWLIST_BYPASS", default=False
)
"""Break-glass override that skips the platform admin IP allowlist.

Lets operators recover platform admin access after a lockout. Organization IP
allowlists are unaffected.
"""

AUTOSECOPS__PLATFORM_ADMIN_MFA_BYPASS = env_bool(
    "AUTOSECOPS__PLATFORM_ADMIN_MFA_BYPASS", default=False
)
"""Break-glass override that skips security key (MFA) checks for platform admins.

Skips both the sign-in challenge and step-up verification for platform
superusers so operators can recover access after losing every security key.
Organization members are unaffected.
"""

AUTOSECOPS__MFA_STEP_UP_MAX_AGE_SECONDS = bound_env(
    "AUTOSECOPS__MFA_STEP_UP_MAX_AGE_SECONDS", 300, lower=30, upper=3600
)
"""How long a security key verification satisfies step-up checks (30 s to 1 h)."""

AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS = env_networks(
    "AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS",
    default=(
        ip_network("127.0.0.0/8"),
        ip_network("::1/128"),
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("169.254.0.0/16"),
        ip_network("fc00::/7"),
    ),
)
"""CIDRs of proxies behind which the API runs (Caddy, the UI container, a load
balancer). X-Forwarded-For entries from these hops are skipped when resolving
the client IP for audit attribution."""

AUTOSECOPS__SANDBOX_INSTALL_ALLOWED_EGRESS_CIDRS = env_networks(
    "AUTOSECOPS__SANDBOX_INSTALL_ALLOWED_EGRESS_CIDRS"
)
"""Private CIDRs reachable only while installing sandbox dependencies."""

AUTOSECOPS__SANDBOX_INSTALL_ALLOWED_EGRESS_TCP_PORTS = env_ports(
    "AUTOSECOPS__SANDBOX_INSTALL_ALLOWED_EGRESS_TCP_PORTS",
    default=(80, 443),
)
"""TCP ports allowed to install-only private CIDRs."""

AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_CIDRS = env_networks(
    "AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_CIDRS"
)
"""Private CIDRs reachable only while acquiring custom registry sources."""

AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_TCP_PORTS = env_ports(
    "AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_TCP_PORTS",
    default=(22,),
)
"""TCP ports allowed to registry-only private CIDRs."""

AUTOSECOPS__SANDBOX_SCRIPT_ALLOWED_EGRESS_CIDRS = env_networks(
    "AUTOSECOPS__SANDBOX_SCRIPT_ALLOWED_EGRESS_CIDRS"
)
"""Private CIDRs reachable by network-enabled Python script sandboxes."""

AUTOSECOPS__SANDBOX_SCRIPT_ALLOWED_EGRESS_TCP_PORTS = env_ports(
    "AUTOSECOPS__SANDBOX_SCRIPT_ALLOWED_EGRESS_TCP_PORTS",
    default=(443,),
)
"""TCP ports allowed to script-only private CIDRs."""

AUTOSECOPS__SANDBOX_ACTION_ALLOWED_EGRESS_CIDRS = env_networks(
    "AUTOSECOPS__SANDBOX_ACTION_ALLOWED_EGRESS_CIDRS"
)
"""Private CIDRs reachable by action sandboxes."""

AUTOSECOPS__SANDBOX_ACTION_ALLOWED_EGRESS_TCP_PORTS = env_ports(
    "AUTOSECOPS__SANDBOX_ACTION_ALLOWED_EGRESS_TCP_PORTS",
    default=(443,),
)
"""TCP ports allowed to action-only private CIDRs."""

AUTOSECOPS__SANDBOX_AGENT_ALLOWED_EGRESS_CIDRS = env_networks(
    "AUTOSECOPS__SANDBOX_AGENT_ALLOWED_EGRESS_CIDRS"
)
"""Private CIDRs reachable by internet-enabled agent sandboxes."""

AUTOSECOPS__SANDBOX_AGENT_ALLOWED_EGRESS_TCP_PORTS = env_ports(
    "AUTOSECOPS__SANDBOX_AGENT_ALLOWED_EGRESS_TCP_PORTS",
    default=(443,),
)
"""TCP ports allowed to agent-only private CIDRs."""

AUTOSECOPS__SANDBOX_BLOCKED_EGRESS_CIDRS = env_networks(
    "AUTOSECOPS__SANDBOX_BLOCKED_EGRESS_CIDRS"
)
"""Deployment-specific CIDRs blocked in addition to the filtered baseline."""

AUTOSECOPS__SANDBOX_DNS_ALLOWED_EGRESS_CIDRS = env_networks(
    "AUTOSECOPS__SANDBOX_DNS_ALLOWED_EGRESS_CIDRS"
)
"""Additional CIDRs reachable from sandboxes on TCP/UDP port 53 only.

CNIs with socket-level load balancing (for example Cilium with socket LB)
rewrite the resolver ClusterIP to a backend pod IP before the packet reaches
NSTUN. List the backend CIDR here so DNS to those addresses is allowed."""

AUTOSECOPS__SANDBOX_ALLOW_PUBLIC_IPV6_EGRESS = env_bool(
    "AUTOSECOPS__SANDBOX_ALLOW_PUBLIC_IPV6_EGRESS", default=False
)
"""Allow filtered sandboxes to reach public IPv6 destinations."""

# === Execution isolation === #
AUTOSECOPS__EXECUTOR_BACKEND = ExecutorBackendType.from_config(
    os.environ.get("AUTOSECOPS__EXECUTOR_BACKEND")
)
"""Execution mode for actions, agents, registry sync, and Python scripts.

- 'direct' (default): Run subprocesses without nsjail.
- 'nsjail': Require nsjail isolation. Requires Linux, the nsjail binary,
  sandbox rootfs, and the required container capabilities.
- 'ephemeral': Compatibility alias for 'nsjail'.
"""

AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT = float(
    os.environ.get("AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT") or 300
)
"""Maximum seconds one action function call may run (default: 300s).

The executor caps each UDF subprocess call at this value and uses it as the
action timeout when the timeout is 0. Template totals and run_python follow the
action's own timeout. Agent services also use it to bound executor tool calls."""

AUTOSECOPS__EXECUTOR_ACTIVITY_PLATFORM_TIMEOUT = float(
    os.environ.get("AUTOSECOPS__EXECUTOR_ACTIVITY_PLATFORM_TIMEOUT") or 600
)
"""Seconds added to an action's timeout for the executor activity's start-to-close timeout.

The action timeout budgets only the action function call. This allowance covers
platform work in the same activity (context materialization, secret resolution,
registry artifacts, sandbox startup, and result storage)."""

AUTOSECOPS__EXECUTOR_SUBPROCESS_STARTUP_GRACE = float(
    os.environ.get("AUTOSECOPS__EXECUTOR_SUBPROCESS_STARTUP_GRACE") or 60
)
"""Seconds an action subprocess may run beyond the action timeout before it is killed.

Covers sandbox startup, imports, and result serialization around the timed
function call, which the action runner enforces itself."""

# === Action Gateway === #
AUTOSECOPS__ACTION_GATEWAY_SOCKET = (
    os.environ.get("AUTOSECOPS__ACTION_GATEWAY_SOCKET")
    or "/var/run/autosecops/action-gateway.sock"
)
"""Unix socket path for the executor-local action gateway."""

# === Action Executor Sandbox === #
AUTOSECOPS__EXECUTOR_AUTOSECOPS_APP_DIR = os.environ.get(
    "AUTOSECOPS__EXECUTOR_AUTOSECOPS_APP_DIR", ""
)
"""Path to the autosecops package directory for sandbox mounting.
If not set, will be auto-detected from the installed autosecops package location.
"""

AUTOSECOPS__EXECUTOR_SITE_PACKAGES_DIR = os.environ.get(
    "AUTOSECOPS__EXECUTOR_SITE_PACKAGES_DIR", ""
)
"""Path to the Python site-packages directory containing autosecops dependencies.
If not set, will be auto-detected from a known dependency's location.
"""

# === Agent Sandbox (NSJail for ClaudeAgentRuntime) === #
AUTOSECOPS__AGENT_SANDBOX_TIMEOUT = int(
    os.environ.get("AUTOSECOPS__AGENT_SANDBOX_TIMEOUT")
    or AGENT_SANDBOX_TIMEOUT_SECONDS_DEFAULT
)
"""Ceiling for agent execution timeouts in seconds.

Per-action agent timeouts clamp to [min(AGENT_TIMEOUT_SECONDS_FLOOR, this), this].
"""

AUTOSECOPS__AGENT_EXECUTOR_GRACEFUL_SHUTDOWN_TIMEOUT = int(
    os.environ.get("AUTOSECOPS__AGENT_EXECUTOR_GRACEFUL_SHUTDOWN_TIMEOUT")
    or (AUTOSECOPS__AGENT_SANDBOX_TIMEOUT + AGENT_TIMEOUT_CLEANUP_BUFFER_SECONDS)
)
"""Agent executor worker drain timeout in seconds.

Defaults to the agent timeout ceiling plus the cleanup buffer so planned
worker shutdowns can let active agent activities finish.
"""

AUTOSECOPS__AGENT_SANDBOX_MEMORY_MB = int(
    os.environ.get("AUTOSECOPS__AGENT_SANDBOX_MEMORY_MB") or 4096
)
"""Default memory limit for agent sandbox execution in megabytes (4 GiB)."""

AUTOSECOPS__LITELLM_PORT = int(os.environ.get("AUTOSECOPS__LITELLM_PORT") or 4000)
"""Bind port for the managed LiteLLM service."""

AUTOSECOPS__LITELLM_NUM_WORKERS = int(
    os.environ.get("AUTOSECOPS__LITELLM_NUM_WORKERS") or 2
)
"""Number of uvicorn workers for the managed LiteLLM service."""

AUTOSECOPS__LITELLM_BASE_URL = os.environ.get(
    "AUTOSECOPS__LITELLM_BASE_URL", f"http://127.0.0.1:{AUTOSECOPS__LITELLM_PORT}"
)
"""Internal base URL for the managed LiteLLM service."""

AUTOSECOPS__LLM_PROXY_READ_TIMEOUT = float(
    os.environ.get("AUTOSECOPS__LLM_PROXY_READ_TIMEOUT") or 600.0
)
"""Read timeout for the LLM socket proxy in seconds (default: 10 minutes)."""


AUTOSECOPS__LLM_GATEWAY_CREDENTIAL_CACHE_TTL_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_CREDENTIAL_CACHE_TTL_SECONDS") or 60.0
)
"""TTL for process-local LLM gateway credential cache entries in seconds."""

AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_INTERVAL_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_INTERVAL_SECONDS") or 30.0
)
"""Interval between LLM gateway readiness checks in seconds."""

AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS") or 2.0
)
"""Default timeout for LLM gateway readiness checks in seconds."""

AUTOSECOPS__LLM_GATEWAY_CONNECT_TIMEOUT_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_CONNECT_TIMEOUT_SECONDS")
    or AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS
)
"""Connect timeout for LLM gateway requests in seconds."""

AUTOSECOPS__LLM_GATEWAY_READ_TIMEOUT_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_READ_TIMEOUT_SECONDS")
    or AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS
)
"""Read timeout for LLM gateway requests in seconds."""

AUTOSECOPS__LLM_GATEWAY_WRITE_TIMEOUT_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_WRITE_TIMEOUT_SECONDS")
    or AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS
)
"""Write timeout for LLM gateway requests in seconds."""

AUTOSECOPS__LLM_GATEWAY_POOL_TIMEOUT_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_POOL_TIMEOUT_SECONDS")
    or AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS
)
"""Pool timeout for LLM gateway requests in seconds."""

AUTOSECOPS__LLM_GATEWAY_FAILURE_THRESHOLD = int(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_FAILURE_THRESHOLD") or 3
)
"""Number of consecutive LLM gateway failures before failing the worker."""

AUTOSECOPS__LLM_GATEWAY_STATUS_LOG_INTERVAL_SECONDS = float(
    os.environ.get("AUTOSECOPS__LLM_GATEWAY_STATUS_LOG_INTERVAL_SECONDS") or 30.0
)
"""Interval between periodic LLM gateway status heartbeat logs in seconds."""

AUTOSECOPS__AGENT_QUEUE = os.environ.get(
    "AUTOSECOPS__AGENT_QUEUE", "shared-agent-queue"
)
"""Task queue for the AgentWorker (Temporal workflow queue).

This is the dedicated queue for agent workflow execution, separate from the main
autosecops-task-queue used by DSLWorkflow."""

AUTOSECOPS__AGENT_EXECUTOR_QUEUE = os.environ.get(
    "AUTOSECOPS__AGENT_EXECUTOR_QUEUE", "shared-agent-executor-queue"
)
"""Task queue for the AgentExecutorWorker.

This queue is reserved for `run_agent_activity` so agent runtime capacity can be
provisioned independently from agent workflow/control-plane work."""

AUTOSECOPS__AGENT_CHAT_BACKEND = (
    os.environ.get("AUTOSECOPS__AGENT_CHAT_BACKEND") or "oss"
)
"""Agent backend for new sessions whose caller does not choose one.

Applies to workspace, agent preset, case and external channel (Slack) sessions,
including case-comment and MCP preset runs, for organizations entitled to
non-default backends. Workflow runs and the preset builder keep the built-in
backend."""

# === Rate Limiting === #
AUTOSECOPS__RATE_LIMIT_ENABLED = env_bool(
    "AUTOSECOPS__RATE_LIMIT_ENABLED", default=True
)
"""Whether rate limiting is enabled for the executor service."""

AUTOSECOPS__RATE_LIMIT_RATE = float(
    os.environ.get("AUTOSECOPS__RATE_LIMIT_RATE") or 40.0
)
"""The rate at which tokens are added to the bucket (tokens per second)."""

AUTOSECOPS__RATE_LIMIT_CAPACITY = float(
    os.environ.get("AUTOSECOPS__RATE_LIMIT_CAPACITY") or 80.0
)
"""The maximum number of tokens the bucket can hold."""

AUTOSECOPS__RATE_LIMIT_WINDOW_SIZE = int(
    os.environ.get("AUTOSECOPS__RATE_LIMIT_WINDOW_SIZE") or 60
)
"""The time window in seconds for rate limiting."""

AUTOSECOPS__RATE_LIMIT_BY_IP = env_bool("AUTOSECOPS__RATE_LIMIT_BY_IP", default=True)
"""Whether to rate limit by client IP."""

AUTOSECOPS__RATE_LIMIT_BY_ENDPOINT = env_bool(
    "AUTOSECOPS__RATE_LIMIT_BY_ENDPOINT", default=True
)
"""Whether to rate limit by endpoint."""

AUTOSECOPS__EXECUTOR_PAYLOAD_MAX_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__EXECUTOR_PAYLOAD_MAX_SIZE_BYTES") or 5 * 1024**3
)
"""The maximum size of a payload in bytes the executor can return.

Defaults to 5 GiB, the largest single-object upload S3 and MinIO accept.
Results above ``AUTOSECOPS__RESULT_EXTERNALIZATION_THRESHOLD_BYTES`` are
externalized to blob storage with a single PUT, so the object store's
single-upload cap is the effective ceiling on an action's result.
"""

AUTOSECOPS__SANDBOX_PACKAGE_CACHE_MAX_BYTES = int(
    os.environ.get("AUTOSECOPS__SANDBOX_PACKAGE_CACHE_MAX_BYTES") or 5 * 1024**3
)
"""Maximum aggregate bytes promoted from a sandbox package cache."""

AUTOSECOPS__SANDBOX_PACKAGE_CACHE_MAX_ENTRIES = int(
    os.environ.get("AUTOSECOPS__SANDBOX_PACKAGE_CACHE_MAX_ENTRIES") or 200_000
)
"""Maximum entries promoted from a sandbox package cache."""

AUTOSECOPS__MAX_FILE_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_FILE_SIZE_BYTES")
    or 20 * 1024 * 1024  # Default 20MB
)
"""The maximum size for file handling (e.g., uploads, downloads) in bytes. Defaults to 20MB."""

AUTOSECOPS__MAX_TABLE_IMPORT_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_TABLE_IMPORT_SIZE_BYTES") or 5 * 1024 * 1024
)
"""Maximum CSV upload size for table imports in bytes. Defaults to 5MB."""

AUTOSECOPS__MAX_UPLOAD_FILES_COUNT = int(
    os.environ.get("AUTOSECOPS__MAX_UPLOAD_FILES_COUNT") or 5
)
"""The maximum number of files that can be uploaded at once. Defaults to 5."""

AUTOSECOPS__MAX_AGGREGATE_UPLOAD_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_AGGREGATE_UPLOAD_SIZE_BYTES") or 100 * 1024 * 1024
)
"""The maximum size of the aggregate upload size in bytes. Defaults to 100MB."""

AUTOSECOPS__MAX_SKILL_FILE_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_SKILL_FILE_SIZE_BYTES") or 20 * 1024 * 1024
)
"""Maximum size of one skill file in bytes. Defaults to 20 MiB."""

AUTOSECOPS__MAX_SKILL_FILES_COUNT = int(
    os.environ.get("AUTOSECOPS__MAX_SKILL_FILES_COUNT") or 1_000
)
"""Maximum number of files in one skill draft. Defaults to 1,000."""

AUTOSECOPS__MAX_SKILL_TRANSFER_FILES_COUNT = int(
    os.environ.get("AUTOSECOPS__MAX_SKILL_TRANSFER_FILES_COUNT") or 64
)
"""Maximum number of files in one staged skill transfer. Defaults to 64."""

AUTOSECOPS__MAX_SKILL_TOTAL_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_SKILL_TOTAL_SIZE_BYTES") or 100 * 1024 * 1024
)
"""Maximum aggregate size of one skill draft in bytes. Defaults to 100 MiB."""

AUTOSECOPS__MAX_SKILL_MANIFEST_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_SKILL_MANIFEST_SIZE_BYTES") or 256 * 1024
)
"""Maximum size of a root skill SKILL.md manifest. Defaults to 256 KiB."""

# === System PATH config === #
AUTOSECOPS__SYSTEM_PATH = os.environ.get(
    "AUTOSECOPS__SYSTEM_PATH", "/usr/local/bin:/usr/bin:/bin"
)
"""System PATH for subprocess execution. Includes common binary locations."""

# === Concurrency Limits === #
AUTOSECOPS__S3_CONCURRENCY_LIMIT = int(
    os.environ.get("AUTOSECOPS__S3_CONCURRENCY_LIMIT") or 50
)
"""Maximum number of concurrent S3 operations to prevent resource exhaustion. Defaults to 50."""

# === API List/Search Limits === #
AUTOSECOPS__LIMIT_MIN = 1
"""Minimum list/search page size."""

AUTOSECOPS__LIMIT_AGG_GROUPS_MAX = bound_env(
    "AUTOSECOPS__LIMIT_AGG_GROUPS_MAX",
    1000,
    lower=1,
)
"""Maximum number of groups returned by an aggregation query."""

AUTOSECOPS__LIMIT_AGG_GROUPS_DEFAULT = bound_env(
    "AUTOSECOPS__LIMIT_AGG_GROUPS_DEFAULT",
    100,
    lower=1,
    upper=AUTOSECOPS__LIMIT_AGG_GROUPS_MAX,
)
"""Default number of groups returned by an aggregation query."""

POSTGRES_STATEMENT_TIMEOUT_MAX_MS = 2_147_483_647
"""Largest PostgreSQL statement timeout accepted in milliseconds."""

AUTOSECOPS__AGG_STATEMENT_TIMEOUT_MS = bound_env(
    "AUTOSECOPS__AGG_STATEMENT_TIMEOUT_MS",
    30_000,
    lower=1,
    upper=POSTGRES_STATEMENT_TIMEOUT_MAX_MS,
)
"""PostgreSQL statement timeout for aggregation queries, in milliseconds."""

AUTOSECOPS__CASE_SEARCH_STATEMENT_TIMEOUT_MS = bound_env(
    "AUTOSECOPS__CASE_SEARCH_STATEMENT_TIMEOUT_MS",
    30_000,
    lower=1,
    upper=POSTGRES_STATEMENT_TIMEOUT_MAX_MS,
)
"""PostgreSQL statement timeout for case text search, in milliseconds.

A slow search holds a pooled database connection for up to this long.
"""

AUTOSECOPS__LIMIT_DEFAULT = 20
"""Default list/search page size."""

AUTOSECOPS__LIMIT_CURSOR_MAX = 200
"""Maximum page size for cursor-pagination and case list/search endpoints."""

AUTOSECOPS__LIMIT_WORKFLOW_LIST_MIN = 0
"""Minimum workflow list limit (0 means unpaginated/all)."""

AUTOSECOPS__LIMIT_AGENT_SESSIONS_DEFAULT = 50
"""Default page size for agent session listing."""

AUTOSECOPS__LIMIT_REGISTRY_VERSIONS_DEFAULT = 50
"""Default page size for registry version listing."""

AUTOSECOPS__LIMIT_COMMITS_DEFAULT = 10
"""Default page size for commit listing endpoints."""

AUTOSECOPS__LIMIT_WORKFLOW_EXECUTIONS_DEFAULT = 100
"""Default page size for workflow execution listing."""

AUTOSECOPS__LIMIT_WORKFLOW_EXECUTIONS_MAX = 1000
"""Maximum page size for workflow execution listing."""

AUTOSECOPS__LIMIT_TABLE_SEARCH_DEFAULT = min(100, AUTOSECOPS__LIMIT_CURSOR_MAX)
"""Default page size for internal table search."""

AUTOSECOPS__LIMIT_TABLE_DOWNLOAD_MAX = 1000
"""Maximum row count for internal table downloads."""

AUTOSECOPS__LIMIT_TABLE_DOWNLOAD_DEFAULT = AUTOSECOPS__LIMIT_TABLE_DOWNLOAD_MAX
"""Default row count for internal table download."""

# === API Lifecycle === #
AUTOSECOPS__API_TASK_DRAIN_TIMEOUT = float(
    os.environ.get("AUTOSECOPS__API_TASK_DRAIN_TIMEOUT") or 10.0
)
"""Seconds to let finite in-process API tasks finish during shutdown.

Stoppable consumers (e.g. case triggers) are signalled to finish in-flight
work and are awaited alongside finite startup tasks (e.g. registry sync) for
this duration. Stragglers are then cancelled and get the same duration again
for cleanup; non-stoppable long-running tasks are cancelled immediately. The
deployment's termination grace period must exceed twice this value for full
coverage.
"""

# === Context Compression === #
AUTOSECOPS__CONTEXT_COMPRESSION_ENABLED = env_bool(
    "AUTOSECOPS__CONTEXT_COMPRESSION_ENABLED", default=False
)
"""Enable compression of large action results in workflow contexts. Defaults to False."""

AUTOSECOPS__CONTEXT_COMPRESSION_THRESHOLD_KB = int(
    os.environ.get("AUTOSECOPS__CONTEXT_COMPRESSION_THRESHOLD_KB") or 16
)
"""Threshold in KB above which action results are compressed. Defaults to 16KB."""

AUTOSECOPS__CONTEXT_COMPRESSION_ALGORITHM = os.environ.get(
    "AUTOSECOPS__CONTEXT_COMPRESSION_ALGORITHM", "zstd"
)
"""Compression algorithm to use. Supported: zstd, gzip, brotli. Defaults to zstd."""

AUTOSECOPS__WORKFLOW_RETURN_STRATEGY: Literal["context", "minimal"] = cast(
    Literal["context", "minimal"],
    os.environ.get("AUTOSECOPS__WORKFLOW_RETURN_STRATEGY", "minimal").lower(),
)
"""Strategy to use when returning a value from a workflow. Supported: context, minimal. Defaults to minimal."""

# === Redis config === #
REDIS_CHAT_TTL_SECONDS = int(
    os.environ.get("REDIS_CHAT_TTL_SECONDS") or 3 * 24 * 60 * 60  # 3 days
)
"""TTL for Redis chat history streams in seconds. Defaults to 3 days."""

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
"""URL for the Redis instance. Required for Redis chat history."""

REDIS_URL__ARN = os.environ.get("REDIS_URL__ARN")
"""(AWS only) ARN of the secret containing the Redis URL."""

AUTOSECOPS__CASE_TRIGGERS_ENABLED = env_bool(
    "AUTOSECOPS__CASE_TRIGGERS_ENABLED", default=True
)
"""Enable case event workflow triggers. Defaults to true."""

AUTOSECOPS__CASE_TRIGGERS_STREAM_KEY = os.environ.get(
    "AUTOSECOPS__CASE_TRIGGERS_STREAM_KEY", "case-events"
)
"""Redis stream key for case events."""

AUTOSECOPS__CASE_TRIGGERS_GROUP = os.environ.get(
    "AUTOSECOPS__CASE_TRIGGERS_GROUP", "case-triggers"
)
"""Redis consumer group for case trigger processing."""

AUTOSECOPS__CASE_TRIGGERS_BLOCK_MS = int(
    os.environ.get("AUTOSECOPS__CASE_TRIGGERS_BLOCK_MS") or 2000
)
"""XREADGROUP block timeout in milliseconds."""

AUTOSECOPS__CASE_TRIGGERS_BATCH = int(
    os.environ.get("AUTOSECOPS__CASE_TRIGGERS_BATCH") or 100
)
"""Maximum number of events to read per batch."""

AUTOSECOPS__CASE_TRIGGERS_CLAIM_IDLE_MS = int(
    os.environ.get("AUTOSECOPS__CASE_TRIGGERS_CLAIM_IDLE_MS") or 300000
)
"""Idle time before claiming pending messages (milliseconds)."""

AUTOSECOPS__CASE_TRIGGERS_MAXLEN = int(
    os.environ.get("AUTOSECOPS__CASE_TRIGGERS_MAXLEN") or 30000
)
"""Approximate max length for the case events stream."""

AUTOSECOPS__CASE_TRIGGERS_DEDUP_TTL_SECONDS = int(
    os.environ.get("AUTOSECOPS__CASE_TRIGGERS_DEDUP_TTL_SECONDS") or 21600
)
"""TTL for case trigger dedup keys in seconds."""

AUTOSECOPS__CASE_TRIGGERS_LOCK_TTL_SECONDS = int(
    os.environ.get("AUTOSECOPS__CASE_TRIGGERS_LOCK_TTL_SECONDS") or 300
)
"""TTL for case trigger lock keys in seconds."""

AUTOSECOPS__CASE_DURATION_SYNC_STREAM_KEY = os.environ.get(
    "AUTOSECOPS__CASE_DURATION_SYNC_STREAM_KEY", "case-duration-sync"
)
"""Redis stream key for case duration sync jobs."""

AUTOSECOPS__CASE_DURATION_SYNC_GROUP = os.environ.get(
    "AUTOSECOPS__CASE_DURATION_SYNC_GROUP", "case-duration-sync"
)
"""Redis consumer group for case duration sync processing."""

AUTOSECOPS__CASE_DURATION_SYNC_BLOCK_MS = int(
    os.environ.get("AUTOSECOPS__CASE_DURATION_SYNC_BLOCK_MS") or 2000
)
"""XREADGROUP block timeout in milliseconds for duration sync jobs."""

AUTOSECOPS__CASE_DURATION_SYNC_BATCH = int(
    os.environ.get("AUTOSECOPS__CASE_DURATION_SYNC_BATCH") or 100
)
"""Maximum number of duration sync jobs to read per batch."""

AUTOSECOPS__CASE_DURATION_SYNC_CLAIM_IDLE_MS = int(
    os.environ.get("AUTOSECOPS__CASE_DURATION_SYNC_CLAIM_IDLE_MS") or 300000
)
"""Idle time before claiming pending duration sync jobs."""

AUTOSECOPS__CASE_DURATION_SYNC_BACKFILL_BATCH = int(
    os.environ.get("AUTOSECOPS__CASE_DURATION_SYNC_BACKFILL_BATCH") or 250
)
"""Number of cases to enqueue per duration definition backfill job."""

# === File limits === #
AUTOSECOPS__MAX_ATTACHMENT_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_ATTACHMENT_SIZE_BYTES") or 20 * 1024 * 1024
)
"""The maximum size for case attachment files in bytes. Defaults to 20MB."""

AUTOSECOPS__MAX_ATTACHMENT_FILENAME_LENGTH = int(
    os.environ.get("AUTOSECOPS__MAX_ATTACHMENT_FILENAME_LENGTH") or 255
)
"""The maximum length for attachment filenames. Defaults to 255 (Django FileField standard)."""

AUTOSECOPS__MAX_CASE_STORAGE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_CASE_STORAGE_BYTES") or 200 * 1024 * 1024
)
"""The maximum total storage per case in bytes. Defaults to 200MB."""

AUTOSECOPS__MAX_ATTACHMENTS_PER_CASE = int(
    os.environ.get("AUTOSECOPS__MAX_ATTACHMENTS_PER_CASE") or 10
)
"""The maximum number of attachments allowed per case. Defaults to 10."""

AUTOSECOPS__MAX_RECORDS_PER_CASE = int(
    os.environ.get("AUTOSECOPS__MAX_RECORDS_PER_CASE") or 50
)
"""The maximum number of entity records allowed per case. Defaults to 50."""

# === File security === #

ALLOWED_ATTACHMENT_EXTENSIONS = ",".join(
    [
        ".pdf",
        ".docx",
        ".xlsx",
        ".pptx",
        ".txt",
        ".csv",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
    ]
)
AUTOSECOPS__ALLOWED_ATTACHMENT_EXTENSIONS = {
    ext.strip()
    for ext in os.environ.get(
        "AUTOSECOPS__ALLOWED_ATTACHMENT_EXTENSIONS", ALLOWED_ATTACHMENT_EXTENSIONS
    ).split(",")
    if ext.strip()
}
"""The allowed extensions for case attachment files."""

ALLOWED_ATTACHMENT_MIME_TYPES = ",".join(
    [
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "text/plain",
        "text/csv",
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
    ]
)
AUTOSECOPS__ALLOWED_ATTACHMENT_MIME_TYPES = {
    mime_type.strip()
    for mime_type in os.environ.get(
        "AUTOSECOPS__ALLOWED_ATTACHMENT_MIME_TYPES", ALLOWED_ATTACHMENT_MIME_TYPES
    ).split(",")
    if mime_type.strip()
}
"""The allowed MIME types for case attachment files."""

# === Enterprise features === #
ENTERPRISE_EDITION = env_bool("ENTERPRISE_EDITION", default=False)
"""Whether enterprise features (the bundled `autosecops_ee` package) are enabled."""

AUTOSECOPS__LICENSE_KEY = (
    os.environ.get("AUTOSECOPS__LICENSE_KEY") or ""
).strip() or None
"""Signed license key that unlocks paid entitlements on single-tenant installs.

In multi-tenant mode it only has to grant ``multi_tenant``; entitlements then
come from database tiers.
"""

AUTOSECOPS__EE_MULTI_TENANT_REQUESTED = env_bool(
    "AUTOSECOPS__EE_MULTI_TENANT", default=False
)
"""Whether ``AUTOSECOPS__EE_MULTI_TENANT`` is set to true.

Read ``AUTOSECOPS__EE_MULTI_TENANT`` to know whether multi-tenant mode is on.
"""

AUTOSECOPS__EE_MULTI_TENANT = (
    AUTOSECOPS__EE_MULTI_TENANT_REQUESTED
    and license_permits_multi_tenant_mode(AUTOSECOPS__LICENSE_KEY)
)
"""Whether multi-tenant enterprise features are enabled.

Requires ``AUTOSECOPS__EE_MULTI_TENANT=true`` and a verified license key that
grants ``multi_tenant``, evaluated at process start. A license that expired
past its grace period keeps multi-tenant mode on in a degraded state
(``MultiTenantMode.LAPSED``) so existing tenants are never dropped; see
``autosecops.licensing.multi_tenant``. Otherwise the process runs single-tenant
with license-based entitlements, and the API refuses to start if the database
already holds more than one organization.
"""

# === Managed tunnels (Pangolin) === #
AUTOSECOPS__PANGOLIN_ENDPOINT = os.environ.get("AUTOSECOPS__PANGOLIN_ENDPOINT")
"""Pangolin server URL that sites and machine clients connect to, e.g. Pangolin Cloud."""

AUTOSECOPS__PANGOLIN_API_URL = os.environ.get("AUTOSECOPS__PANGOLIN_API_URL")
"""Pangolin Integration API base URL (ending in /v1) used to provision managed tunnels."""

AUTOSECOPS__PANGOLIN_ORG_ID = os.environ.get("AUTOSECOPS__PANGOLIN_ORG_ID")
"""Pangolin organization that holds every managed tunnel's site, client, and resources."""

AUTOSECOPS__PANGOLIN_API_KEY = os.environ.get("AUTOSECOPS__PANGOLIN_API_KEY")
"""Pangolin organization API key. Managed tunnels are disabled when unset."""

AUTOSECOPS__PANGOLIN_API_KEY__ARN = os.environ.get("AUTOSECOPS__PANGOLIN_API_KEY__ARN")
"""AWS Secrets Manager ARN holding the Pangolin API key. Takes precedence over
``AUTOSECOPS__PANGOLIN_API_KEY``. Only the API service reads it."""

# === Tunnel gateways === #
AUTOSECOPS__TUNNEL_GATEWAY_BACKEND = (
    os.environ.get("AUTOSECOPS__TUNNEL_GATEWAY_BACKEND", "none").strip().lower()
)
"""Who runs tunnel gateways: ``kubernetes`` (the API creates one per tunnel) or
``none`` (gateways are run by hand, e.g. Docker Compose and most self-hosted installs)."""

AUTOSECOPS__TUNNEL_GATEWAY_NAMESPACE = os.environ.get(
    "AUTOSECOPS__TUNNEL_GATEWAY_NAMESPACE", "autosecops-tunnels"
)
"""Kubernetes namespace that holds tunnel gateway objects."""

AUTOSECOPS__TUNNEL_GATEWAY_IMAGE = os.environ.get(
    "AUTOSECOPS__TUNNEL_GATEWAY_IMAGE",
    f"ghcr.io/singularityrd/autosecops-tunnel-gateway:{__version__}",
)
"""Container image for tunnel gateways created by the ``kubernetes`` backend.

Defaults to this release's version tag. Pin a digest for an immutable image.
"""

AUTOSECOPS__TUNNEL_GATEWAY_IMAGE_PULL_SECRETS: tuple[str, ...] = tuple(
    name.strip()
    for name in os.environ.get(
        "AUTOSECOPS__TUNNEL_GATEWAY_IMAGE_PULL_SECRETS", ""
    ).split(",")
    if name.strip()
)
"""Comma-separated names of image pull Secrets in the gateway namespace, for a
private gateway image registry such as GHCR."""

AUTOSECOPS__TUNNEL_GATEWAY_BLOCKED_CIDRS = env_networks(
    "AUTOSECOPS__TUNNEL_GATEWAY_BLOCKED_CIDRS"
)
"""Extra CIDRs, such as cluster pod and service ranges, that gateways never dial."""

AUTOSECOPS__TUNNEL_GATEWAY_API_URL = os.environ.get(
    "AUTOSECOPS__TUNNEL_GATEWAY_API_URL", AUTOSECOPS__API_URL
)
"""AutoSecOps API URL that gateways poll for their policy."""

AUTOSECOPS__TUNNEL_GATEWAY_TUN_RESOURCE = os.environ.get(
    "AUTOSECOPS__TUNNEL_GATEWAY_TUN_RESOURCE", "squat.ai/tun"
)
"""Extended resource that grants a gateway pod ``/dev/net/tun``. Empty disables the request."""

AUTOSECOPS__TUNNEL_GATEWAY_RECONCILE_INTERVAL = float(
    os.environ.get("AUTOSECOPS__TUNNEL_GATEWAY_RECONCILE_INTERVAL") or 60
)
"""Seconds between reconciles of gateway objects against tunnels."""

AUTOSECOPS__TUNNEL_GATEWAY_HOST_TEMPLATE = (
    os.environ.get("AUTOSECOPS__TUNNEL_GATEWAY_HOST_TEMPLATE")
    or f"tunnel-{{tunnel_id}}.{AUTOSECOPS__TUNNEL_GATEWAY_NAMESPACE}.svc.cluster.local"
)
"""Host executors use to reach a tunnel's gateway. ``{tunnel_id}`` is replaced."""

AUTOSECOPS__TUNNEL_GATEWAY_PORT = int(
    os.environ.get("AUTOSECOPS__TUNNEL_GATEWAY_PORT") or 8080
)
"""Port tunnel gateways listen on."""

# === Feature Flags === #
AUTOSECOPS__FEATURE_FLAGS: set[FeatureFlag] = set()
for _flag in os.environ.get("AUTOSECOPS__FEATURE_FLAGS", "").split(","):
    if not (_flag_value := _flag.strip()):
        continue
    try:
        AUTOSECOPS__FEATURE_FLAGS.add(FeatureFlag(_flag_value))
    except ValueError:
        logger.warning(
            "Ignoring unknown feature flag '%s' from AUTOSECOPS__FEATURE_FLAGS",
            _flag_value,
        )
"""Set of enabled feature flags."""

_rls_mode_raw = (
    os.environ.get("AUTOSECOPS__RLS_MODE", RLSMode.OFF.value).strip().lower()
)
try:
    AUTOSECOPS__RLS_MODE: RLSMode = RLSMode(_rls_mode_raw)
except ValueError:
    logger.warning(
        "Invalid AUTOSECOPS__RLS_MODE '%s'; defaulting to '%s'",
        _rls_mode_raw,
        RLSMode.OFF.value,
    )
    AUTOSECOPS__RLS_MODE = RLSMode.OFF
"""Runtime RLS enforcement mode (off|shadow|enforce).

The code default stays `off` so tests and ad hoc scripts that connect as the
table owner keep bypass semantics. The shipped Compose, Helm and Fargate
deployments set `enforce`, which only isolates tenants when the services
connect as the runtime role (`AUTOSECOPS__DB_RUNTIME_PASSWORD`).
"""


# === Agent config === #
AUTOSECOPS__UNIFIED_AGENT_STREAMING_ENABLED = env_bool(
    "AUTOSECOPS__UNIFIED_AGENT_STREAMING_ENABLED", default=False
)
"""Whether to enable unified streaming for agent execution."""

AUTOSECOPS__AGENT_MAX_TOOLS = int(os.environ.get("AUTOSECOPS__AGENT_MAX_TOOLS") or 128)
"""The maximum number of tools that can be used in an agent."""

AUTOSECOPS__AGENT_MAX_TOOL_CALLS = int(
    os.environ.get("AUTOSECOPS__AGENT_MAX_TOOL_CALLS") or 40
)
"""The maximum number of tool calls that can be made per agent run."""

AUTOSECOPS__AGENT_MAX_REQUESTS = int(
    os.environ.get("AUTOSECOPS__AGENT_MAX_REQUESTS") or 120
)
"""The maximum number of requests that can be made per agent run."""

AUTOSECOPS__AGENT_MAX_RETRIES = int(
    os.environ.get("AUTOSECOPS__AGENT_MAX_RETRIES") or 20
)
"""The maximum number of retries that can be made per agent run."""

AUTOSECOPS__AGENT_DEFAULT_CONTEXT_LIMIT = int(
    os.environ.get("AUTOSECOPS__AGENT_DEFAULT_CONTEXT_LIMIT") or 128_000
)
"""Default character limit for agent message history when truncating context."""

AUTOSECOPS__AGENT_TOOL_OUTPUT_LIMIT = int(
    os.environ.get("AUTOSECOPS__AGENT_TOOL_OUTPUT_LIMIT") or 80_000
)
"""Default character limit for individual tool outputs when truncating context."""

AUTOSECOPS__MODEL_CONTEXT_LIMITS = {
    "gpt-4o-mini": 100_000,
    "gpt-5-mini": 350_000,
    "gpt-5-nano": 350_000,
    "gpt-5": 350_000,
    "claude-sonnet-4-5-20250929": 180_000,
    "claude-haiku-4-5-20251001": 180_000,
    "claude-opus-4-5-20251101": 180_000,
    "anthropic.claude-sonnet-4-5-20250929-v1:0": 180_000,
    "anthropic.claude-haiku-4-5-20251001-v1:0": 180_000,
}
"""Model-specific character limits for agent message history truncation."""

# === Registry Sync === #
AUTOSECOPS__REGISTRY_SYNC_SANDBOX_ENABLED = env_bool(
    "AUTOSECOPS__REGISTRY_SYNC_SANDBOX_ENABLED", default=True
)
"""Enable executor-hosted registry sync via Temporal.

When True (default), registry sync operations run on the ExecutorWorker.
NsJail isolation on that worker is controlled separately by
AUTOSECOPS__EXECUTOR_BACKEND.

When False, uses the existing subprocess approach from the API service.
"""

AUTOSECOPS__REGISTRY_SYNC_CLONE_TIMEOUT = int(
    os.environ.get("AUTOSECOPS__REGISTRY_SYNC_CLONE_TIMEOUT") or 120
)
"""Timeout for Git clone/fetch/checkout during registry sync in seconds."""

AUTOSECOPS__REGISTRY_SYNC_INSTALL_TIMEOUT = int(
    os.environ.get("AUTOSECOPS__REGISTRY_SYNC_INSTALL_TIMEOUT") or 600
)
"""Timeout for package installation during registry sync in seconds. Defaults to 600 (10 min)."""

AUTOSECOPS__REGISTRY_SYNC_DISCOVER_TIMEOUT = int(
    os.environ.get("AUTOSECOPS__REGISTRY_SYNC_DISCOVER_TIMEOUT") or 300
)
"""Timeout for action discovery during registry sync in seconds. Defaults to 300 (5 min)."""

AUTOSECOPS__REGISTRY_SYNC_BUILTIN_USE_INSTALLED_SITE_PACKAGES = env_bool(
    "AUTOSECOPS__REGISTRY_SYNC_BUILTIN_USE_INSTALLED_SITE_PACKAGES", default=True
)
"""Use installed site-packages for builtin registry tarball builds.

When True (default), builtin autosecops_registry sync packages the current
interpreter's installed site-packages into a tarball. This avoids creating
a fresh venv and re-installing dependencies from package indexes at runtime.
"""

AUTOSECOPS__REGISTRY_SYNC_SQUASHFS_ENABLED = env_bool(
    "AUTOSECOPS__REGISTRY_SYNC_SQUASHFS_ENABLED", default=True
)
"""Build SquashFS sidecars for registry tarball venvs when mksquashfs is available."""

AUTOSECOPS__REGISTRY_SYNC_SQUASHFS_PROCESSORS = int(
    os.environ.get("AUTOSECOPS__REGISTRY_SYNC_SQUASHFS_PROCESSORS") or 1
)
"""Number of processors mksquashfs may use for registry SquashFS sidecar builds."""

AUTOSECOPS__REGISTRY_SYNC_SQUASHFS_MEM = (
    os.environ.get("AUTOSECOPS__REGISTRY_SYNC_SQUASHFS_MEM") or "200M"
)
"""Memory budget passed to mksquashfs for registry SquashFS sidecar builds."""

AUTOSECOPS__REGISTRY_SYNC_PREBUILT_ARTIFACTS_DIR = (
    os.environ.get("AUTOSECOPS__REGISTRY_SYNC_PREBUILT_ARTIFACTS_DIR")
    or "/app/.registry-artifacts"
)
"""Root directory for release-built registry artifacts.

Artifacts use the same relative layout as blob storage keys, for example:
platform/tarball-venvs/autosecops_registry/<version>/site-packages.tar.gz
"""

AUTOSECOPS__BUILTIN_REGISTRY_SOURCE_PATH = os.environ.get(
    "AUTOSECOPS__BUILTIN_REGISTRY_SOURCE_PATH", "/app/packages/autosecops-registry"
)
"""Path to the builtin autosecops_registry package source.

In Docker, packages are copied to /app/packages/autosecops-registry.
In development with editable install, falls back to checking relative to the installed package.
"""

# === Robot EDR (RoboDR ingest) === #
AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES = int(
    os.environ.get("AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES") or 64 * 1024 * 1024
)
"""Largest verified RoboDR evidence bundle stored for a case (bytes).

Defaults to 64 MiB, robodr-agentd's default `max_export_bytes`. Bundles are
stored in the attachments bucket, outside the per-case attachment limits; the
case gets a small verification report attachment that names them.
"""

AUTOSECOPS__ROBOT_EDR_EVIDENCE_QUOTA_BYTES = int(
    os.environ.get("AUTOSECOPS__ROBOT_EDR_EVIDENCE_QUOTA_BYTES") or 10 * 1024**3
)
"""Total verified RoboDR evidence bundle bytes one workspace may store.

Defaults to 10 GiB. Counted over the bundles of every stored export
(`robot_evidence_export`); deleting a case releases its share.
"""

AUTOSECOPS__ROBOT_EDR_FLEET_MAX_DRAFTS = int(
    os.environ.get("AUTOSECOPS__ROBOT_EDR_FLEET_MAX_DRAFTS") or 16
)
"""Draft profiles kept per robot (`robodr.fleet` §6.1, each up to 8 MiB).

A new draft beyond the limit removes that robot's oldest draft, so a robot
cannot fill the database with drafts; review drafts before the robot
publishes more.
"""

AUTOSECOPS__ROBOT_EDR_REQUIRE_TLS = env_bool(
    "AUTOSECOPS__ROBOT_EDR_REQUIRE_TLS", default=True
)
"""Refuse RoboDR ingest requests that did not arrive over TLS.

A request counts as TLS when the API itself serves HTTPS, or when a proxy in
AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS forwards `X-Forwarded-Proto: https` (the
stock Caddy front end does). Plain HTTP from a loopback client is always
accepted. Turn this off only for a closed lab network.
"""
