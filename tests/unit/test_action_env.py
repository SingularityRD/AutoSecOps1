"""Direct-mode actions see an allowlisted environment, not the executor's."""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from autosecops import config
from autosecops.auth.types import Role
from autosecops.authz.scopes import SERVICE_PRINCIPAL_SCOPES
from autosecops.dsl.common import create_default_execution_context
from autosecops.dsl.schemas import ActionStatement, RunActionInput, RunContext
from autosecops.executor import action_env
from autosecops.executor.action_env import (
    build_direct_action_env,
    is_passthrough_denied,
)
from autosecops.executor.action_runner import ActionRunner
from autosecops.executor.schemas import ActionImplementation, ResolvedContext
from autosecops.executor.secret_preprocessors import SecretEnvProjection
from autosecops.identifiers.workflow import WorkflowUUID
from autosecops.registry.lock.types import RegistryLock

# Synthetic stand-ins for the platform credentials the executor container holds.
PLATFORM_SECRETS = {
    "AUTOSECOPS__DB_ENCRYPTION_KEY": "synthetic-encryption-key",
    "AUTOSECOPS__SERVICE_KEY": "synthetic-service-key",
    "AUTOSECOPS__DB_URI": (
        "postgresql+psycopg://owner:synthetic-db-pass@db.internal.test:6543/app"
    ),
    "AUTOSECOPS__DB_PASS": "synthetic-db-pass",
    "AUTOSECOPS__SIGNING_SECRET": "synthetic-signing-secret",
    "AUTOSECOPS__LICENSE_KEY": "synthetic-license-key",
    "AUTOSECOPS__TUNNEL_PROXY_URL": "http://tunnel:synthetic@gateway.test:8080",
    "AWS_ACCESS_KEY_ID": "AKIASYNTHETIC0000000",
    "AWS_SECRET_ACCESS_KEY": "synthetic-aws-secret",
    "AWS_SESSION_TOKEN": "synthetic-aws-session",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/synthetic",
    "TEMPORAL__API_KEY": "synthetic-temporal-key",
    "MINIO_ROOT_PASSWORD": "synthetic-minio-password",
    "REDIS_URL": "redis://:synthetic@redis.test:6379",
    "SENTRY_DSN": "https://synthetic@sentry.test/1",
}

REQUIRED_BASE = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/home/apiuser",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONUSERBASE": "/home/apiuser/.local",
    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    "HTTPS_PROXY": "http://egress.test:3128",
    "NO_PROXY": "localhost",
    "AUTOSECOPS__DUCKDB_EXTENSION_DIRECTORY": "/usr/local/lib/duckdb/extensions",
}


@pytest.fixture
def executor_environ(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Return an executor-like environment with platform credentials set."""
    monkeypatch.setattr(
        config, "AUTOSECOPS__DB_URI", PLATFORM_SECRETS["AUTOSECOPS__DB_URI"]
    )
    monkeypatch.setattr(config, "AUTOSECOPS__DB_ENDPOINT", None)
    monkeypatch.setattr(config, "AUTOSECOPS__DB_PORT", None)
    return {**PLATFORM_SECRETS, **REQUIRED_BASE}


def test_build_env_drops_platform_secrets(executor_environ: dict[str, str]) -> None:
    env = build_direct_action_env(executor_environ)

    for name in PLATFORM_SECRETS:
        assert name not in env
    secret_values = set(PLATFORM_SECRETS.values())
    assert not secret_values & set(env.values())
    assert not any("synthetic-db-pass" in value for value in env.values())
    for name, value in REQUIRED_BASE.items():
        assert env[name] == value


def test_build_env_keeps_non_secret_aws_settings(
    executor_environ: dict[str, str],
) -> None:
    environ = {
        **executor_environ,
        "AWS_REGION": "eu-west-1",
        "AWS_DEFAULT_REGION": "eu-west-1",
        "AWS_USE_FIPS_ENDPOINT": "true",
    }

    env = build_direct_action_env(environ)

    assert env["AWS_REGION"] == "eu-west-1"
    assert env["AWS_DEFAULT_REGION"] == "eu-west-1"
    assert env["AWS_USE_FIPS_ENDPOINT"] == "true"
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_build_env_strips_proxy_credentials(
    executor_environ: dict[str, str],
) -> None:
    environ = {
        **executor_environ,
        "HTTPS_PROXY": "http://user:synthetic-proxy-pass@egress.test:3128",
    }

    env = build_direct_action_env(environ)

    assert env["HTTPS_PROXY"] == "http://egress.test:3128"


def test_build_env_passes_internal_db_endpoint_without_credentials(
    executor_environ: dict[str, str],
) -> None:
    env = build_direct_action_env(executor_environ)

    assert env["AUTOSECOPS__DB_ENDPOINT"] == "db.internal.test"
    assert env["AUTOSECOPS__DB_PORT"] == "6543"


def test_build_env_prefers_explicit_db_endpoint(
    executor_environ: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__DB_ENDPOINT", "rds.internal.test")
    monkeypatch.setattr(config, "AUTOSECOPS__DB_PORT", "5433")

    env = build_direct_action_env(executor_environ)

    assert env["AUTOSECOPS__DB_ENDPOINT"] == "rds.internal.test"
    assert env["AUTOSECOPS__DB_PORT"] == "5433"


def test_passthrough_adds_allowed_names_and_refuses_secrets(
    executor_environ: dict[str, str],
) -> None:
    environ = {
        **executor_environ,
        "CUSTOMER_REGION": "eu-west",
        "VENDOR_API_KEY": "synthetic-vendor-key",
    }
    passthrough = (
        "CUSTOMER_REGION",
        "VENDOR_API_KEY",
        *PLATFORM_SECRETS,
        "MISSING_SETTING",
    )

    env = build_direct_action_env(environ, passthrough=passthrough)

    assert env["CUSTOMER_REGION"] == "eu-west"
    assert "VENDOR_API_KEY" not in env
    assert "MISSING_SETTING" not in env
    for name in PLATFORM_SECRETS:
        assert name not in env


@pytest.mark.parametrize(
    "name",
    [
        "AUTOSECOPS__DB_ENCRYPTION_KEY",
        "AUTOSECOPS__SERVICE_KEY",
        "AUTOSECOPS__DB_URI",
        "AUTOSECOPS__API_URL",
        "TRACECAT__DB_URI",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_PROFILE",
        "TEMPORAL__API_KEY",
        "SENTRY_DSN",
        "REDIS_URL",
        "PGPASSWORD",
        "GITHUB_TOKEN",
        "MY_CLIENT_SECRET",
        "SMTP_PASSWORD",
        "SERVICE_CREDENTIALS",
        "lower_api_key",
        "BAD-NAME",
        "",
    ],
)
def test_passthrough_denies_platform_and_credential_names(name: str) -> None:
    assert is_passthrough_denied(name)


@pytest.mark.parametrize(
    "name",
    ["CUSTOMER_REGION", "LOG_LEVEL", "KEYBOARD_LAYOUT", "AWS_REGION", "AWS_CA_BUNDLE"],
)
def test_passthrough_allows_plain_settings(name: str) -> None:
    assert not is_passthrough_denied(name)


ENV_PROBE_MODULE = """
import os


def probe(names):
    return {name: os.environ.get(name) for name in names}
"""


@pytest.fixture
def probe_registry(tmp_path: Path) -> Path:
    """Create a registry import root holding an env-reading action."""
    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "env_probe_action.py").write_text(ENV_PROBE_MODULE)
    return registry


@pytest.fixture
def run_input() -> RunActionInput:
    wf_id = WorkflowUUID.new_uuid4()
    return RunActionInput(
        task=ActionStatement(action="test.env_probe", args={}, ref="probe"),
        exec_context=create_default_execution_context(),
        run_context=RunContext(
            wf_id=wf_id,
            wf_exec_id=f"{wf_id.short()}/exec_test",
            wf_run_id=uuid.uuid4(),
            environment="default",
            logical_time=datetime.now(UTC),
        ),
        registry_lock=RegistryLock(
            origins={"autosecops_registry": "test-version"},
            actions={"test.env_probe": "autosecops_registry"},
        ),
    )


@pytest.fixture
def executor_role() -> Role:
    return Role(
        type="service",
        service_id="autosecops-executor",
        workspace_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        scopes=SERVICE_PRINCIPAL_SCOPES["autosecops-executor"],
    )


@pytest.fixture
def leaky_process_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Put synthetic platform credentials in the executor process environment."""
    for name, value in PLATFORM_SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("CUSTOMER_REGION", "eu-west")
    monkeypatch.setattr(
        config, "AUTOSECOPS__DB_URI", PLATFORM_SECRETS["AUTOSECOPS__DB_URI"]
    )
    monkeypatch.setattr(config, "AUTOSECOPS__DB_ENDPOINT", None)
    monkeypatch.setattr(config, "AUTOSECOPS__DB_PORT", None)
    monkeypatch.setattr(
        config,
        "AUTOSECOPS__EXECUTOR_ENV_PASSTHROUGH",
        ("CUSTOMER_REGION", "AUTOSECOPS__SERVICE_KEY", "AWS_SECRET_ACCESS_KEY"),
    )
    action_env._allowed_passthrough.cache_clear()
    yield
    action_env._allowed_passthrough.cache_clear()


def _resolved_context(
    role: Role,
    run_input: RunActionInput,
    *,
    module: str,
    name: str,
    args: dict[str, object],
) -> ResolvedContext:
    return ResolvedContext(
        action_impl=ActionImplementation(
            type="udf",
            action_name=run_input.task.action,
            module=module,
            name=name,
        ),
        evaluated_args=args,
        workspace_id=str(role.workspace_id),
        workflow_id=str(run_input.run_context.wf_id),
        run_id=str(run_input.run_context.wf_run_id),
        executor_token="synthetic-executor-token",
    )


requires_direct_subprocess = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("setpriv") is None,
    reason="direct action subprocesses need Linux and setpriv",
)


@requires_direct_subprocess
@pytest.mark.anyio
@pytest.mark.usefixtures("leaky_process_env")
async def test_direct_action_cannot_read_platform_secrets(
    tmp_path: Path,
    probe_registry: Path,
    run_input: RunActionInput,
    executor_role: Role,
) -> None:
    names = [
        *PLATFORM_SECRETS,
        "PATH",
        "HOME",
        "PYTHONPATH",
        "CUSTOMER_REGION",
        "AUTOSECOPS__API_URL",
        "AUTOSECOPS__WORKSPACE_ID",
        "AUTOSECOPS__EXECUTOR_TOKEN",
        "AUTOSECOPS__ACTION_GATEWAY_SOCKET",
        "AUTOSECOPS__DB_ENDPOINT",
        "AUTOSECOPS__DB_PORT",
    ]
    runner = ActionRunner(cache_dir=tmp_path / "cache")

    result = await runner._execute_direct(
        input=run_input,
        role=executor_role,
        registry_paths=[probe_registry],
        secret_projection=SecretEnvProjection(env={}, mask_values=set()),
        timeout=30.0,
        resolved_context=_resolved_context(
            executor_role,
            run_input,
            module="env_probe_action",
            name="probe",
            args={"names": names},
        ),
    )

    assert isinstance(result, dict), result
    for name in PLATFORM_SECRETS:
        assert result[name] is None, name
    assert result["PATH"] == os.environ["PATH"]
    assert result["HOME"] == os.environ["HOME"]
    assert result["PYTHONPATH"].split(":")[0] == str(probe_registry)
    assert result["CUSTOMER_REGION"] == "eu-west"
    assert result["AUTOSECOPS__API_URL"] == config.AUTOSECOPS__API_URL
    assert result["AUTOSECOPS__WORKSPACE_ID"] == str(executor_role.workspace_id)
    assert result["AUTOSECOPS__EXECUTOR_TOKEN"] == "synthetic-executor-token"
    assert result["AUTOSECOPS__ACTION_GATEWAY_SOCKET"]
    assert result["AUTOSECOPS__DB_ENDPOINT"] == "db.internal.test"
    assert result["AUTOSECOPS__DB_PORT"] == "6543"


@requires_direct_subprocess
@pytest.mark.anyio
@pytest.mark.usefixtures("leaky_process_env")
async def test_direct_registry_action_still_runs(
    tmp_path: Path,
    run_input: RunActionInput,
    executor_role: Role,
) -> None:
    runner = ActionRunner(cache_dir=tmp_path / "cache")

    result = await runner._execute_direct(
        input=run_input,
        role=executor_role,
        registry_paths=[],
        secret_projection=SecretEnvProjection(env={}, mask_values=set()),
        timeout=30.0,
        resolved_context=_resolved_context(
            executor_role,
            run_input,
            module="autosecops_registry.core.transform",
            name="reshape",
            args={"value": {"answer": 42}},
        ),
    )

    assert result == {"answer": 42}
