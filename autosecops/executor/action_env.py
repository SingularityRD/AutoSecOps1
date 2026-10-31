"""Environment for direct-mode action subprocesses.

Direct-mode actions run as executor subprocesses. The executor's own environment
holds platform credentials (database URI, encryption and service keys, signing
secrets, cloud credentials), so actions never inherit it wholesale. They start
from an allowlist of process plumbing and non-secret runtime settings instead.
The action runner then adds the run's SDK context and executor token.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from functools import cache
from pathlib import Path

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from autosecops import config
from autosecops.logger import logger
from autosecops.process_env import BASE_ENV_NAMES, select_env

AWS_NON_SECRET_ENV_NAMES = frozenset(
    {
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_CA_BUNDLE",
        "AWS_USE_FIPS_ENDPOINT",
        "AWS_STS_REGIONAL_ENDPOINTS",
    }
)
"""AWS client settings that hold no credentials, so actions may inherit them."""

ACTION_ENV_ALLOWED_NAMES = (
    BASE_ENV_NAMES
    | AWS_NON_SECRET_ENV_NAMES
    | frozenset(
        {
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
)
"""Executor environment variables copied into every direct-mode action.

Process plumbing, Python import roots, CA bundles and the operator egress proxy
come from ``BASE_ENV_NAMES``; tunneled actions replace the proxy with their
route."""

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
    if name in AWS_NON_SECRET_ENV_NAMES:
        return False
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


def local_registry_import_paths() -> list[str]:
    """Return import roots for custom actions in local-repository mode.

    Local-repository mode installs the mounted repository into
    ``PYTHONUSERBASE`` and imports it from there and from the mount. Only
    action subprocesses get these paths: privileged processes never import
    from directories that action code can write.

    Returns:
        The import roots, or an empty list when local-repository mode is off.
    """
    if not config.AUTOSECOPS__LOCAL_REPOSITORY_ENABLED:
        return []
    user_base = os.environ.get("PYTHONUSERBASE") or str(Path.home() / ".local")
    return [user_base, config.AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH]


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
    env = select_env(environ, names=ACTION_ENV_ALLOWED_NAMES)
    for name in _allowed_passthrough(tuple(passthrough)):
        if (value := environ.get(name)) is not None:
            env[name] = value
    env.update(_internal_db_endpoint_env())
    return env
