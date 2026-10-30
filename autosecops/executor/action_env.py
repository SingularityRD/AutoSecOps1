"""Environment for direct-mode action subprocesses.

Direct-mode actions run as executor subprocesses. The executor's own environment
holds platform credentials (database URI, encryption and service keys, signing
secrets, cloud credentials), so actions never inherit it wholesale. They start
from an allowlist of process plumbing and non-secret runtime settings instead.
The action runner then adds the run's SDK context and executor token.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from functools import cache

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from autosecops import config
from autosecops.logger import logger

ACTION_ENV_ALLOWED_NAMES = frozenset(
    {
        # Process plumbing.
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LANGUAGE",
        "TZ",
        "TMPDIR",
        "TEMP",
        "TMP",
        # Python import roots. Custom registries installed for local-repository
        # mode live in the user site that PYTHONUSERBASE/PYTHONPATH point at.
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "PYTHONUNBUFFERED",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "VIRTUAL_ENV",
        # TLS trust stores for outbound action requests.
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        # Operator egress proxy. Tunneled actions replace these with their route.
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        # Non-secret settings that autosecops_registry reads at import time.
        "AUTOSECOPS__MAX_FILE_SIZE_BYTES",
        "AUTOSECOPS__MAX_UPLOAD_FILES_COUNT",
        "AUTOSECOPS__MAX_AGGREGATE_UPLOAD_SIZE_BYTES",
        "AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES",
        "AUTOSECOPS__LAMBDA_MAX_STEPS",
        "AUTOSECOPS__LAMBDA_MAX_ALLOCATION_BYTES",
        "AUTOSECOPS__LAMBDA_TIMEOUT_SECONDS",
        "AUTOSECOPS__S3_CONCURRENCY_LIMIT",
        "AUTOSECOPS__DUCKDB_EXTENSION_DIRECTORY",
        "AUTOSECOPS__AGENT_MAX_RETRIES",
        "AUTOSECOPS__AGENT_MAX_TOOL_CALLS",
        "AUTOSECOPS__AGENT_MAX_REQUESTS",
        "AUTOSECOPS__EXECUTOR_URL",
        # Process cap the trusted minimal runner applies before action code.
        "AUTOSECOPS__SANDBOX_RLIMIT_NPROC",
    }
)
"""Executor environment variables copied into every direct-mode action."""

ACTION_ENV_ALLOWED_PREFIXES = ("LC_",)
"""Name prefixes copied into every direct-mode action (locale categories)."""

PASSTHROUGH_DENIED_PREFIXES = (
    "AUTOSECOPS__",
    "TRACECAT__",
    "TEMPORAL__",
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "GCP_",
    "GCLOUD_",
    "CLOUDSDK_",
    "SENTRY_",
    "MINIO_",
    "REDIS_",
    "OTEL_",
    "POSTGRES",
    "PG",
    "DATABASE_",
    "DB_",
    "ECS_",
    "KUBERNETES_",
)
"""Platform namespaces that ``AUTOSECOPS__EXECUTOR_ENV_PASSTHROUGH`` refuses."""

_CREDENTIAL_NAME_PATTERN = re.compile(
    r"(KEY|KEYS|KEYRING|SECRET|SECRETS|PASSWORD|PASSWD|PASS|PWD|TOKEN|TOKENS|"
    r"CREDENTIAL|CREDENTIALS|CREDS|DSN|URI|URL|ARN|CERT|AUTH|COOKIE|SESSION)"
    r"(_|$)",
)
"""Name segments that mark a variable as a credential or connection string."""

_ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_passthrough_denied(name: str) -> bool:
    """Return whether an operator may not pass this variable to actions.

    Args:
        name: Environment variable name from the passthrough setting.

    Returns:
        True for invalid names, platform namespaces, and credential-like names.
    """
    if not _ENV_NAME_PATTERN.fullmatch(name):
        return True
    upper = name.upper()
    if upper.startswith(PASSTHROUGH_DENIED_PREFIXES):
        return True
    segments = upper.split("_")
    return any(
        _CREDENTIAL_NAME_PATTERN.fullmatch(segment) for segment in segments if segment
    )


@cache
def _allowed_passthrough(names: tuple[str, ...]) -> tuple[str, ...]:
    """Drop refused passthrough names, logging each refusal once."""
    allowed: list[str] = []
    for name in names:
        if is_passthrough_denied(name):
            logger.warning(
                "Ignoring AUTOSECOPS__EXECUTOR_ENV_PASSTHROUGH entry: platform and "
                "credential variables are never passed to actions. Store secrets "
                "as workspace secrets instead.",
                name=name,
            )
            continue
        allowed.append(name)
    return tuple(allowed)


def _internal_db_endpoint_env() -> dict[str, str]:
    """Return the internal database host and port without its credentials.

    ``core.sql`` refuses connections to the platform database by comparing the
    target against this endpoint, so actions need the host and port, never the
    URI that carries the owner credentials.
    """
    host = config.AUTOSECOPS__DB_ENDPOINT
    port = config.AUTOSECOPS__DB_PORT
    try:
        url = make_url(config.AUTOSECOPS__DB_URI)
    except ArgumentError:
        url = None
    if url is not None:
        host = host or url.host
        port = port or (str(url.port) if url.port is not None else None)

    env: dict[str, str] = {}
    if host:
        env["AUTOSECOPS__DB_ENDPOINT"] = host
    if port:
        env["AUTOSECOPS__DB_PORT"] = str(port)
    return env


def build_direct_action_env(
    environ: Mapping[str, str],
    *,
    passthrough: Iterable[str] = (),
) -> dict[str, str]:
    """Build the base environment for a direct-mode action subprocess.

    Args:
        environ: The executor process environment to select from.
        passthrough: Operator-requested extra variable names. Platform and
            credential-like names are refused.

    Returns:
        The allowlisted variables present in ``environ``, the requested
        passthrough variables, and the internal database endpoint.
    """
    env = {
        name: value
        for name, value in environ.items()
        if name in ACTION_ENV_ALLOWED_NAMES
        or name.startswith(ACTION_ENV_ALLOWED_PREFIXES)
    }
    for name in _allowed_passthrough(tuple(passthrough)):
        if (value := environ.get(name)) is not None:
            env[name] = value
    env.update(_internal_db_endpoint_env())
    return env
