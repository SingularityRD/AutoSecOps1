from __future__ import annotations

import ast
import importlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

import autosecops.config as autosecops_config
from autosecops.config import (
    bound_env,
    env_bind_host,
    env_bool,
    env_networks,
    env_no_proxy,
    env_port,
    env_ports,
    env_proxy_url,
    format_bind_address,
)
from autosecops.feature_flags.enums import FeatureFlag

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "autosecops" / "config.py"
SANDBOX_POLICY_COMPOSE_ENV_FILES = (
    REPO_ROOT / "docker-compose.yml",
    REPO_ROOT / "docker-compose.dev.yml",
    REPO_ROOT / "docker-compose.local.yml",
)
# The sandbox Compose file is an override and inherits policy variables from a base.
COMPOSE_ENV_FILES = (
    *SANDBOX_POLICY_COMPOSE_ENV_FILES,
    REPO_ROOT / "docker-compose.sandbox.yml",
    REPO_ROOT / "deployments" / "lab" / "docker-compose.lab.yml",
)
ENV_EXAMPLE_FILES = (
    REPO_ROOT / ".env.example",
    REPO_ROOT / "deployments" / "lab" / ".env.lab.example",
)
DEPLOYMENT_ENV_FILES = (*COMPOSE_ENV_FILES, *ENV_EXAMPLE_FILES)
TRACED_COMPOSE_ENV_FILES = SANDBOX_POLICY_COMPOSE_ENV_FILES
TRACED_COMPOSE_SERVICES = (
    "api",
    "worker",
    "executor",
    "agent-worker",
    "agent-executor",
)
PLATFORM_OTEL_COMPOSE_ENV = (
    "AUTOSECOPS__PLATFORM_OTEL_ENABLED: ${AUTOSECOPS__PLATFORM_OTEL_ENABLED:-false}",
    "OTEL_EXPORTER_OTLP_ENDPOINT: ${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4318}",
    "OTEL_TRACES_SAMPLER: ${OTEL_TRACES_SAMPLER:-parentbased_traceidratio}",
    "OTEL_TRACES_SAMPLER_ARG: ${OTEL_TRACES_SAMPLER_ARG:-1.0}",
)
PLATFORM_OTEL_HEADERS_COMPOSE_ENV = (
    "OTEL_EXPORTER_OTLP_HEADERS: ${OTEL_EXPORTER_OTLP_HEADERS:-}"
)
SANDBOX_POLICY_ENV_VARS = {
    "AUTOSECOPS__SANDBOX_INSTALL_ALLOWED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_INSTALL_ALLOWED_EGRESS_TCP_PORTS",
    "AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_TCP_PORTS",
    "AUTOSECOPS__SANDBOX_SCRIPT_ALLOWED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_SCRIPT_ALLOWED_EGRESS_TCP_PORTS",
    "AUTOSECOPS__SANDBOX_ACTION_ALLOWED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_ACTION_ALLOWED_EGRESS_TCP_PORTS",
    "AUTOSECOPS__SANDBOX_AGENT_ALLOWED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_AGENT_ALLOWED_EGRESS_TCP_PORTS",
    "AUTOSECOPS__SANDBOX_BLOCKED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_DNS_ALLOWED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_ALLOW_PUBLIC_IPV6_EGRESS",
}
REGISTRY_POLICY_ENV_VARS = {
    "AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_CIDRS",
    "AUTOSECOPS__SANDBOX_REGISTRY_ALLOWED_EGRESS_TCP_PORTS",
}
SENTRY_PLATFORM_COMPOSE_SERVICES = (
    "api",
    "worker",
    "agent-worker",
    "executor",
    "agent-executor",
)
SMTP_COMPOSE_ENV = (
    "AUTOSECOPS__SMTP_HOST: ${AUTOSECOPS__SMTP_HOST:-}",
    "AUTOSECOPS__SMTP_PORT: ${AUTOSECOPS__SMTP_PORT:-587}",
    "AUTOSECOPS__SMTP_USER: ${AUTOSECOPS__SMTP_USER:-}",
    "AUTOSECOPS__SMTP_PASSWORD: ${AUTOSECOPS__SMTP_PASSWORD:-}",
    "AUTOSECOPS__EMAIL_FROM: ${AUTOSECOPS__EMAIL_FROM:-}",
)


def _config_bool_env_vars() -> set[str]:
    tree = ast.parse(CONFIG_PATH.read_text())
    env_vars: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "env_bool"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            env_vars.add(node.args[0].value)
    return env_vars


def test_bound_env_returns_default_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_BOUND_ENV", raising=False)

    result = bound_env("TEST_BOUND_ENV", 16, lower=8)

    assert result == 16


@pytest.mark.parametrize("default", [False, True])
def test_env_bool_returns_default_when_unset(
    monkeypatch: pytest.MonkeyPatch, default: bool
) -> None:
    monkeypatch.delenv("TEST_BOOL_ENV", raising=False)

    result = env_bool("TEST_BOOL_ENV", default=default)

    assert result is default


@pytest.mark.parametrize("raw_value", ["", "   "])
@pytest.mark.parametrize("default", [False, True])
def test_env_bool_returns_default_for_blank_values(
    monkeypatch: pytest.MonkeyPatch, raw_value: str, default: bool
) -> None:
    monkeypatch.setenv("TEST_BOOL_ENV", raw_value)

    result = env_bool("TEST_BOOL_ENV", default=default)

    assert result is default


@pytest.mark.parametrize("raw_value", ["1", "true", "TRUE", "yes", "on"])
def test_env_bool_parses_true_tokens(
    monkeypatch: pytest.MonkeyPatch, raw_value: str
) -> None:
    monkeypatch.setenv("TEST_BOOL_ENV", raw_value)

    result = env_bool("TEST_BOOL_ENV", default=False)

    assert result is True


@pytest.mark.parametrize("raw_value", ["0", "false", "FALSE", "no", "off"])
def test_env_bool_parses_false_tokens(
    monkeypatch: pytest.MonkeyPatch, raw_value: str
) -> None:
    monkeypatch.setenv("TEST_BOOL_ENV", raw_value)

    result = env_bool("TEST_BOOL_ENV", default=True)

    assert result is False


def test_env_bool_rejects_invalid_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_BOOL_ENV", "not-a-bool")

    with pytest.raises(ValueError, match="TEST_BOOL_ENV must be a boolean"):
        env_bool("TEST_BOOL_ENV", default=True)


def test_env_networks_parses_ipv4_and_ipv6_cidrs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TEST_NETWORKS_ENV",
        "10.42.0.0/16, 203.0.113.10, 2001:db8::/48",
    )

    networks = env_networks("TEST_NETWORKS_ENV")

    assert tuple(str(network) for network in networks) == (
        "10.42.0.0/16",
        "203.0.113.10/32",
        "2001:db8::/48",
    )


def test_env_networks_rejects_invalid_cidr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_NETWORKS_ENV", "10.42.0.0/16,not-a-cidr")

    with pytest.raises(ValueError, match="TEST_NETWORKS_ENV contains an invalid CIDR"):
        env_networks("TEST_NETWORKS_ENV")


def test_env_ports_parses_and_deduplicates_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_PORTS_ENV", "443, 8443,443")

    assert env_ports("TEST_PORTS_ENV", default=(80,)) == (443, 8443)


@pytest.mark.parametrize("raw_value", ["not-a-port", "0", "65536"])
def test_env_ports_rejects_invalid_ports(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str,
) -> None:
    monkeypatch.setenv("TEST_PORTS_ENV", raw_value)

    with pytest.raises(ValueError, match="TEST_PORTS_ENV contains an invalid port"):
        env_ports("TEST_PORTS_ENV", default=(443,))


@pytest.mark.parametrize("raw_value", [None, "", "   "])
def test_env_ports_uses_default_when_unset_or_blank(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str | None,
) -> None:
    if raw_value is None:
        monkeypatch.delenv("TEST_PORTS_ENV", raising=False)
    else:
        monkeypatch.setenv("TEST_PORTS_ENV", raw_value)

    assert env_ports("TEST_PORTS_ENV", default=(80, 443)) == (80, 443)


@pytest.mark.parametrize("raw_value", [None, "", "  "])
def test_env_networks_uses_default_when_unset_or_blank(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str | None,
) -> None:
    if raw_value is None:
        monkeypatch.delenv("TEST_NETWORKS_ENV", raising=False)
    else:
        monkeypatch.setenv("TEST_NETWORKS_ENV", raw_value)
    default = env_networks(
        "TEST_NETWORKS_ENV",
        default=autosecops_config.AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS,
    )

    assert default == autosecops_config.AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS


@pytest.mark.parametrize("raw_value", [None, "", "   "])
def test_env_proxy_url_is_none_when_unset_or_blank(
    monkeypatch: pytest.MonkeyPatch, raw_value: str | None
) -> None:
    if raw_value is None:
        monkeypatch.delenv("TEST_PROXY_ENV", raising=False)
    else:
        monkeypatch.setenv("TEST_PROXY_ENV", raw_value)

    assert env_proxy_url("TEST_PROXY_ENV") is None


@pytest.mark.parametrize(
    "raw_value",
    [
        "http://proxy.example.internal:3128",
        " https://user:p%40ss@10.0.0.8:8443/ ",
        "HTTP://[fd00::8]:3128",
    ],
)
def test_env_proxy_url_accepts_http_proxies(
    monkeypatch: pytest.MonkeyPatch, raw_value: str
) -> None:
    monkeypatch.setenv("TEST_PROXY_ENV", raw_value)

    assert env_proxy_url("TEST_PROXY_ENV") == raw_value.strip()


@pytest.mark.parametrize(
    "raw_value",
    [
        "socks5://user:synthetic-secret@proxy:1080",
        "proxy.example.internal:3128",
        "http://user:synthetic-secret@proxy:3128/path",
        "http://user:synthetic-secret@proxy:3128/?q=1",
        "http://user:synthetic-secret@proxy:notaport",
        "http://user:synthetic-secret@:3128",
    ],
)
def test_env_proxy_url_rejects_invalid_values_without_echoing_them(
    monkeypatch: pytest.MonkeyPatch, raw_value: str
) -> None:
    monkeypatch.setenv("TEST_PROXY_ENV", raw_value)

    with pytest.raises(ValueError, match="TEST_PROXY_ENV must be") as exc_info:
        env_proxy_url("TEST_PROXY_ENV")
    assert "synthetic-secret" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_env_no_proxy_parses_hosts_and_networks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TEST_NO_PROXY_ENV",
        " Internal.Example.com, .corp.example, *.svc.cluster.local,10.0.0.0/8,"
        "203.0.113.7,[fd00::1],, host_with_underscore ",
    )

    entries = env_no_proxy("TEST_NO_PROXY_ENV")

    assert tuple(str(entry) for entry in entries) == (
        "internal.example.com",
        "corp.example",
        "svc.cluster.local",
        "10.0.0.0/8",
        "203.0.113.7/32",
        "fd00::1/128",
        "host_with_underscore",
    )


@pytest.mark.parametrize("raw_value", [None, "", " , "])
def test_env_no_proxy_is_empty_when_unset_or_blank(
    monkeypatch: pytest.MonkeyPatch, raw_value: str | None
) -> None:
    if raw_value is None:
        monkeypatch.delenv("TEST_NO_PROXY_ENV", raising=False)
    else:
        monkeypatch.setenv("TEST_NO_PROXY_ENV", raw_value)

    assert env_no_proxy("TEST_NO_PROXY_ENV") == ()


@pytest.mark.parametrize(
    "raw_value", ["*", "example.com:443", "http://example.com", "bad host", "a..b"]
)
def test_env_no_proxy_rejects_invalid_entries(
    monkeypatch: pytest.MonkeyPatch, raw_value: str
) -> None:
    monkeypatch.setenv("TEST_NO_PROXY_ENV", raw_value)

    with pytest.raises(ValueError, match="TEST_NO_PROXY_ENV contains an invalid"):
        env_no_proxy("TEST_NO_PROXY_ENV")


def test_outbound_proxy_is_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        with monkeypatch.context() as env:
            env.delenv("AUTOSECOPS__OUTBOUND_PROXY_URL", raising=False)
            env.delenv("AUTOSECOPS__OUTBOUND_NO_PROXY", raising=False)
            # Generic proxy variables must not enable the proxy implicitly.
            env.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
            env.setenv("HTTP_PROXY", "http://127.0.0.1:9999")
            env.setenv("NO_PROXY", "example.com")
            reloaded = importlib.reload(autosecops_config)
            assert reloaded.AUTOSECOPS__OUTBOUND_PROXY_URL is None
            assert reloaded.AUTOSECOPS__OUTBOUND_NO_PROXY == ()
    finally:
        importlib.reload(autosecops_config)


def test_audit_trusted_proxy_env_is_wired_to_deployments() -> None:
    """Both audit consumers (api, mcp) must receive the override in every target."""
    name = "AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS"
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        source = path.read_text()
        for service in ("api", "mcp"):
            match = re.search(
                rf"(?ms)^  {service}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
                source,
            )
            assert match is not None, f"{path.name}: no {service} service block"
            assert name in match.group("body"), f"{path.name}: {service}"
    fargate = REPO_ROOT / "deployments/fargate"
    assert name in (fargate / "modules/ecs/locals.tf").read_text()
    for tf in ("variables.tf", "main.tf", "modules/ecs/variables.tf"):
        assert "audit_trusted_proxy_cidrs" in (fargate / tf).read_text(), tf


@pytest.mark.parametrize(
    "name,tf_var",
    [
        (
            "AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS",
            "outbound_allowed_private_cidrs",
        ),
        ("AUTOSECOPS__OUTBOUND_PROXY_URL", "outbound_proxy_url"),
        ("AUTOSECOPS__OUTBOUND_NO_PROXY", "outbound_no_proxy"),
    ],
)
def test_outbound_policy_env_is_wired_to_deployments(name: str, tf_var: str) -> None:
    """Validation, gateway, and agent processes share the operator's policy."""
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        for service in ("api", "litellm", "agent-executor", "agent-worker"):
            match = re.search(
                rf"(?ms)^  {service}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
                path.read_text(),
            )
            assert match is not None, f"{path.name}: no {service} service block"
            body = match.group("body").replace(" # Sensitive", "")
            assert f"{name}: ${{{name}:-}}" in body, (
                f"{path.name}: {service} must forward the override and default to empty"
            )
    fargate = REPO_ROOT / "deployments/fargate"
    if name in FARGATE_SECRET_SETTINGS:
        assert (
            f'name      = "{name}"' in (fargate / "modules/ecs/secrets.tf").read_text()
        )
    else:
        assert re.search(
            rf"{name}\s*=\s*var\.{tf_var}\n",
            (fargate / "modules/ecs/locals.tf").read_text(),
        )
    assert re.search(
        rf"{tf_var}\s*=\s*var\.{tf_var}\n",
        (fargate / "main.tf").read_text(),
    )
    for tf in ("variables.tf", "modules/ecs/variables.tf"):
        assert re.search(
            rf'variable "{tf_var}" \{{[^}}]*default\s*=\s*""',
            (fargate / tf).read_text(),
        ), tf


FARGATE_SECRET_SETTINGS = {
    "AUTOSECOPS__LICENSE_KEY": "license_key",
    "AUTOSECOPS__OUTBOUND_PROXY_URL": "outbound_proxy_url",
}


@pytest.mark.parametrize("name,tf_var", sorted(FARGATE_SECRET_SETTINGS.items()))
def test_fargate_sensitive_settings_are_ecs_secrets(name: str, tf_var: str) -> None:
    """Task-definition env is plaintext to anyone with ecs:DescribeTaskDefinition."""
    ecs = REPO_ROOT / "deployments/fargate/modules/ecs"
    assert not re.search(
        rf"^\s*{name}\s*=", (ecs / "locals.tf").read_text(), re.MULTILINE
    ), f"{name} must not be in a task-definition environment map"
    secrets = (ecs / "secrets.tf").read_text()
    assert f'name      = "{name}"' in secrets
    assert f"secret_string = var.{tf_var}" in secrets
    iam = (ecs / "iam.tf").read_text()
    assert f"aws_secretsmanager_secret.{tf_var}[*].arn" in iam


DB_RUNTIME_ROLE_COMPOSE_SERVICES = (
    "api",
    "worker",
    "background-worker",
    "executor",
    "agent-worker",
    "litellm",
    "agent-executor",
    "mcp",
)


def _compose_service_body(source: str, service: str) -> str | None:
    match = re.search(
        rf"(?ms)^  {service}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)", source
    )
    return match.group("body") if match else None


def test_db_runtime_role_env_is_wired_to_compose() -> None:
    """Every Compose service with a DB URI gets the runtime role and RLS mode."""
    user = "AUTOSECOPS__DB_RUNTIME_USER: ${AUTOSECOPS__DB_RUNTIME_USER:-autosecops_app}"
    password = "AUTOSECOPS__DB_RUNTIME_PASSWORD: ${AUTOSECOPS__DB_RUNTIME_PASSWORD:-}"
    rls_mode = "AUTOSECOPS__RLS_MODE: ${AUTOSECOPS__RLS_MODE:-enforce}"
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        source = path.read_text().replace(" # Sensitive", "")
        services_with_db = {
            name
            for name in re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):\n", source)
            if "AUTOSECOPS__DB_URI:" in (_compose_service_body(source, name) or "")
        }
        assert services_with_db == {*DB_RUNTIME_ROLE_COMPOSE_SERVICES, "migrations"}
        for service in services_with_db:
            body = _compose_service_body(source, service) or ""
            assert user in body, f"{path.name}: {service}"
            assert password in body, f"{path.name}: {service}"
            # Migrations run as the owner; the mode only matters to services.
            assert (rls_mode in body) == (service != "migrations"), (
                f"{path.name}: {service}"
            )


def test_db_runtime_role_is_wired_to_fargate() -> None:
    fargate = REPO_ROOT / "deployments/fargate"
    ecs = fargate / "modules/ecs"
    locals_tf = (ecs / "locals.tf").read_text()
    assert re.search(r'AUTOSECOPS__DB_RUNTIME_USER\s*=\s*"autosecops_app"', locals_tf)
    assert re.search(r"AUTOSECOPS__RLS_MODE\s*=\s*var\.rls_mode\n", locals_tf)
    # The password is an ECS secret, never task-definition environment.
    assert not re.search(r"^\s*AUTOSECOPS__DB_RUNTIME_PASSWORD\s*=", locals_tf, re.M)
    secrets_tf = (ecs / "secrets.tf").read_text()
    assert 'name      = "AUTOSECOPS__DB_RUNTIME_PASSWORD"' in secrets_tf
    assert "local.db_runtime_password_secret,\n  ]" in secrets_tf
    assert "secrets     = local.migrations_secrets" in (ecs / "ecs-api.tf").read_text()
    assert (
        "aws_secretsmanager_secret.db_runtime_password.arn"
        in (ecs / "iam.tf").read_text()
    )
    assert re.search(
        r"rls_mode\s*=\s*var\.rls_mode\n", (fargate / "main.tf").read_text()
    )
    for tf in ("variables.tf", "modules/ecs/variables.tf"):
        assert re.search(
            r'variable "rls_mode" \{[^}]*default\s*=\s*"enforce"',
            (fargate / tf).read_text(),
        ), tf


def test_db_runtime_password_is_generated_by_env_sh() -> None:
    assert (
        'dotenv_replace "AUTOSECOPS__DB_RUNTIME_PASSWORD"'
        in (REPO_ROOT / "env.sh").read_text()
    )


def test_rls_and_runtime_role_code_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Code stays on `off` and the owner role unless deployments opt in."""
    try:
        with monkeypatch.context() as env:
            env.delenv("AUTOSECOPS__RLS_MODE", raising=False)
            env.setenv("AUTOSECOPS__DB_RUNTIME_USER", "")
            env.setenv("AUTOSECOPS__DB_RUNTIME_PASSWORD", "")
            reloaded = importlib.reload(autosecops_config)
            assert reloaded.AUTOSECOPS__RLS_MODE == reloaded.RLSMode.OFF
            assert reloaded.AUTOSECOPS__DB_RUNTIME_USER == "autosecops_app"
            assert reloaded.AUTOSECOPS__DB_RUNTIME_PASSWORD is None
    finally:
        importlib.reload(autosecops_config)


def test_fargate_autosecops_containers_use_registry_credentials() -> None:
    ecs = REPO_ROOT / "deployments/fargate/modules/ecs"
    checked = 0
    for tf in sorted(ecs.glob("ecs-*.tf")):
        source = tf.read_text()
        for block in re.split(r"\n    (?:merge\()?\{\n", source)[1:]:
            image = re.search(r"^      image\s*=\s*(.+)$", block, re.MULTILINE)
            if image is None or "autosecops" not in image.group(1):
                continue
            checked += 1
            assert re.search(
                r"\n    \}, local\.autosecops_repository_credentials\)", block
            ), f"{tf.name}: {image.group(1)} has no repositoryCredentials"
    assert checked >= 9
    fargate = REPO_ROOT / "deployments/fargate"
    for tf in ("variables.tf", "main.tf", "modules/ecs/variables.tf"):
        assert "autosecops_registry_credentials_arn" in (fargate / tf).read_text()


def test_smtp_env_is_wired_to_api_deployments() -> None:
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        source = path.read_text().replace(" # Sensitive", "")
        api_match = re.search(
            r"(?ms)^  api:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
            source,
        )
        assert api_match is not None
        for env_line in SMTP_COMPOSE_ENV:
            assert env_line in api_match.group("body"), f"{path.name}: {env_line}"

    fargate = REPO_ROOT / "deployments/fargate"
    for name in (
        "smtp_host",
        "smtp_port",
        "smtp_user",
        "smtp_password",
        "email_from",
    ):
        assert (
            name in (fargate / "modules/ecs/locals.tf").read_text()
            or name in (fargate / "modules/ecs/secrets.tf").read_text()
        )
    for tf in ("variables.tf", "main.tf", "modules/ecs/variables.tf"):
        source = (fargate / tf).read_text()
        for name in (
            "smtp_password_arn",
            "smtp_host",
            "smtp_port",
            "smtp_user",
            "email_from",
        ):
            assert name in source, f"{tf}: {name}"


def test_sandbox_policy_env_vars_are_wired_to_compose_files() -> None:
    missing_by_file = {
        str(path.relative_to(REPO_ROOT)): sorted(
            name for name in SANDBOX_POLICY_ENV_VARS if name not in path.read_text()
        )
        for path in SANDBOX_POLICY_COMPOSE_ENV_FILES
    }
    missing_by_file = {
        path: missing for path, missing in missing_by_file.items() if missing
    }

    assert not missing_by_file


def test_registry_policy_env_vars_are_regular_executor_only() -> None:
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        source = path.read_text()
        executor_match = re.search(
            r"(?ms)^  executor:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
            source,
        )
        agent_executor_match = re.search(
            r"(?ms)^  agent-executor:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
            source,
        )
        assert executor_match is not None
        assert agent_executor_match is not None

        executor_source = executor_match.group("body")
        agent_executor_source = agent_executor_match.group("body")
        for name in REGISTRY_POLICY_ENV_VARS:
            assert name in executor_source
            assert name not in agent_executor_source


@pytest.mark.parametrize(
    "name,tf_var",
    [
        ("AUTOSECOPS__SANDBOX_PYPI_INDEX_URL", "sandbox_pypi_index_url"),
        ("AUTOSECOPS__SANDBOX_PYPI_EXTRA_INDEX_URLS", "sandbox_pypi_extra_index_urls"),
    ],
)
def test_sandbox_pypi_index_env_is_wired_to_deployments(name: str, tf_var: str) -> None:
    """Air-gapped installs point sandbox package installs at an internal mirror."""
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        match = re.search(
            r"(?ms)^  executor:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
            path.read_text(),
        )
        assert match is not None, f"{path.name}: no executor service block"
        assert f"{name}: ${{{name}:-}}" in match.group("body"), path.name
    executor_template = (
        REPO_ROOT / "deployments/helm/autosecops/templates/executor.yaml"
    ).read_text()
    assert f"name: {name}" in executor_template
    fargate = REPO_ROOT / "deployments/fargate"
    assert re.search(
        rf"{name}\s*=\s*var\.{tf_var}\n",
        (fargate / "modules/ecs/locals.tf").read_text(),
    )
    for tf in ("variables.tf", "modules/ecs/variables.tf"):
        assert re.search(
            rf'variable "{tf_var}" \{{[^}}]*default\s*=\s*""',
            (fargate / tf).read_text(),
        ), tf


def test_sandbox_pypi_index_url_treats_blank_as_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOSECOPS__SANDBOX_PYPI_INDEX_URL", "")
    try:
        reloaded = importlib.reload(autosecops_config)
        assert reloaded.AUTOSECOPS__SANDBOX_PYPI_INDEX_URL == "https://pypi.org/simple"
        monkeypatch.setenv(
            "AUTOSECOPS__SANDBOX_PYPI_INDEX_URL", "https://pypi.example.internal/simple"
        )
        reloaded = importlib.reload(autosecops_config)
        assert (
            reloaded.AUTOSECOPS__SANDBOX_PYPI_INDEX_URL
            == "https://pypi.example.internal/simple"
        )
    finally:
        monkeypatch.delenv("AUTOSECOPS__SANDBOX_PYPI_INDEX_URL")
        importlib.reload(autosecops_config)


def test_config_boolean_env_values_use_env_bool() -> None:
    source = CONFIG_PATH.read_text()
    forbidden_patterns = {
        r"\.lower\(\)\s*==\s*['\"]true['\"]": "inline true comparison",
        r"\.lower\(\)\s+in\s+\(": "inline truthy token tuple",
        r"bool\(\s*(?:os\.environ\.get|os\.getenv)\(": "bool(os.environ.get(...))",
    }

    violations = [
        f"{description}: {pattern}"
        for pattern, description in forbidden_patterns.items()
        if re.search(pattern, source)
    ]

    assert not violations, (
        "Boolean environment variables in autosecops/config.py must use env_bool(): "
        + ", ".join(violations)
    )


def test_boolean_env_values_preserve_defaults_and_compose_overrides() -> None:
    bool_env_vars = _config_bool_env_vars()
    assert bool_env_vars

    violations: list[str] = []
    for path in DEPLOYMENT_ENV_FILES:
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for env_var in bool_env_vars:
                if re.fullmatch(rf"{re.escape(env_var)}=", stripped):
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: {stripped}"
                    )
                if re.fullmatch(
                    rf"{re.escape(env_var)}:\s*\$\{{{re.escape(env_var)}\}}",
                    stripped,
                ):
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: {stripped}"
                    )
                if re.fullmatch(
                    rf"-\s*{re.escape(env_var)}=\$\{{{re.escape(env_var)}\}}",
                    stripped,
                ):
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: {stripped}"
                    )
                if path in COMPOSE_ENV_FILES and (
                    re.fullmatch(
                        rf"{re.escape(env_var)}:\s*['\"]?(?:true|false)['\"]?",
                        stripped,
                        flags=re.IGNORECASE,
                    )
                    or re.fullmatch(
                        rf"-\s*{re.escape(env_var)}=['\"]?(?:true|false)['\"]?",
                        stripped,
                        flags=re.IGNORECASE,
                    )
                ):
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: {stripped}"
                    )

    assert not violations, (
        "Boolean env vars must not be blank/defaultless. Compose files must use "
        "`${VAR:-default}` instead of hardcoded literals so .env overrides still "
        "work: " + ", ".join(violations)
    )


@pytest.mark.parametrize("path", TRACED_COMPOSE_ENV_FILES, ids=lambda path: path.name)
@pytest.mark.parametrize("service", TRACED_COMPOSE_SERVICES)
def test_platform_otel_env_is_forwarded_to_traced_compose_services(
    path: Path, service: str
) -> None:
    source = path.read_text()
    service_match = re.search(
        rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert service_match is not None

    service_body = service_match.group("body")
    for env_line in PLATFORM_OTEL_COMPOSE_ENV:
        assert env_line in service_body
    if service in {"executor", "agent-executor"}:
        assert PLATFORM_OTEL_HEADERS_COMPOSE_ENV not in service_body
    else:
        assert PLATFORM_OTEL_HEADERS_COMPOSE_ENV in service_body


@pytest.mark.parametrize("path", TRACED_COMPOSE_ENV_FILES, ids=lambda path: path.name)
@pytest.mark.parametrize("service", SENTRY_PLATFORM_COMPOSE_SERVICES)
def test_sentry_dsn_is_forwarded_to_platform_compose_services(
    path: Path, service: str
) -> None:
    source = path.read_text()
    service_match = re.search(
        rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert service_match is not None

    assert "SENTRY_DSN: ${SENTRY_DSN:-}" in service_match.group("body")


def test_bound_env_clamps_below_lower(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_BOUND_ENV", "4")

    result = bound_env("TEST_BOUND_ENV", 16, lower=8)

    assert result == 8


def test_bound_env_clamps_above_upper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_BOUND_ENV", "99")

    result = bound_env("TEST_BOUND_ENV", 16, upper=32)

    assert result == 32


def test_bound_env_parses_float(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_BOUND_ENV", "1.5")

    result = bound_env("TEST_BOUND_ENV", 0.5, lower=0.0, upper=2.0)

    assert result == 1.5


def test_bound_env_uses_default_for_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_BOUND_ENV", "")

    result = bound_env("TEST_BOUND_ENV", 10, lower=8)

    assert result == 10


def test_removed_agent_runtime_feature_flag_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deployments that still set the removed flag keep starting."""
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__FEATURE_FLAGS", "agent-runtime,forms")
            reloaded_config = importlib.reload(autosecops_config)
            assert reloaded_config.AUTOSECOPS__FEATURE_FLAGS == {FeatureFlag.FORMS}
    finally:
        importlib.reload(autosecops_config)


def test_action_gateway_socket_uses_default_for_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__ACTION_GATEWAY_SOCKET", "")

            reloaded_config = importlib.reload(autosecops_config)

            assert (
                reloaded_config.AUTOSECOPS__ACTION_GATEWAY_SOCKET
                == "/var/run/autosecops/action-gateway.sock"
            )
    finally:
        importlib.reload(autosecops_config)


@pytest.mark.parametrize("port", ["0", "65536", "-1"])
def test_smtp_port_rejects_out_of_range(
    monkeypatch: pytest.MonkeyPatch, port: str
) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__SMTP_PORT", port)

            with pytest.raises(ValueError, match="AUTOSECOPS__SMTP_PORT"):
                importlib.reload(autosecops_config)
    finally:
        importlib.reload(autosecops_config)


def test_smtp_password_preserves_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__SMTP_PASSWORD", " secret ")

            reloaded_config = importlib.reload(autosecops_config)

            assert reloaded_config.AUTOSECOPS__SMTP_PASSWORD == " secret "

        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__SMTP_PASSWORD", "   ")

            reloaded_config = importlib.reload(autosecops_config)

            assert reloaded_config.AUTOSECOPS__SMTP_PASSWORD is None
    finally:
        importlib.reload(autosecops_config)


def test_copilot_skills_dir_uses_default_for_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__COPILOT_SKILLS_DIR", "")

            reloaded_config = importlib.reload(autosecops_config)

            assert (
                reloaded_config.AUTOSECOPS__COPILOT_SKILLS_DIR
                == "/var/lib/autosecops/copilot-skills"
            )
    finally:
        importlib.reload(autosecops_config)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com,example.org", {"example.com", "example.org"}),
        # The OIDC check compared raw entries, so a space or capital made the
        # listed domain reject every sign-in while SAML admitted it.
        (" Example.com, example.org ,,", {"example.com", "example.org"}),
        ("", set()),
    ],
)
def test_auth_allowed_domains_are_normalized(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: set[str]
) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__AUTH_ALLOWED_DOMAINS", raw)

            reloaded_config = importlib.reload(autosecops_config)

            assert reloaded_config.AUTOSECOPS__AUTH_ALLOWED_DOMAINS == expected
    finally:
        importlib.reload(autosecops_config)


@pytest.mark.parametrize(
    ("sandbox_timeout", "expected_drain_timeout"),
    [(None, 10860), (900, 960), (7200, 7260)],
)
def test_agent_executor_drain_default_covers_all_supported_timeouts(
    monkeypatch: pytest.MonkeyPatch,
    sandbox_timeout: int | None,
    expected_drain_timeout: int,
) -> None:
    try:
        with monkeypatch.context() as env:
            if sandbox_timeout is None:
                env.delenv("AUTOSECOPS__AGENT_SANDBOX_TIMEOUT", raising=False)
            else:
                env.setenv("AUTOSECOPS__AGENT_SANDBOX_TIMEOUT", str(sandbox_timeout))
            env.delenv(
                "AUTOSECOPS__AGENT_EXECUTOR_GRACEFUL_SHUTDOWN_TIMEOUT",
                raising=False,
            )

            reloaded_config = importlib.reload(autosecops_config)

            assert reloaded_config.AUTOSECOPS__AGENT_SANDBOX_TIMEOUT == (
                expected_drain_timeout - 60
            )
            assert (
                reloaded_config.AUTOSECOPS__AGENT_EXECUTOR_GRACEFUL_SHUTDOWN_TIMEOUT
                == expected_drain_timeout
            )
    finally:
        importlib.reload(autosecops_config)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        pytest.param(
            {},
            (100, 1000, 30_000),
            id="defaults",
        ),
        pytest.param(
            {
                "AUTOSECOPS__LIMIT_AGG_GROUPS_DEFAULT": "250",
                "AUTOSECOPS__LIMIT_AGG_GROUPS_MAX": "2000",
                "AUTOSECOPS__AGG_STATEMENT_TIMEOUT_MS": "15000",
            },
            (250, 2000, 15_000),
            id="operator-overrides",
        ),
        pytest.param(
            {
                "AUTOSECOPS__AGG_STATEMENT_TIMEOUT_MS": "2147483648",
            },
            (100, 1000, 2_147_483_647),
            id="timeout-clamped-to-postgres-maximum",
        ),
    ],
)
def test_aggregation_query_config(
    monkeypatch: pytest.MonkeyPatch,
    values: dict[str, str],
    expected: tuple[int, int, int],
) -> None:
    names = (
        "AUTOSECOPS__LIMIT_AGG_GROUPS_DEFAULT",
        "AUTOSECOPS__LIMIT_AGG_GROUPS_MAX",
        "AUTOSECOPS__AGG_STATEMENT_TIMEOUT_MS",
    )
    try:
        with monkeypatch.context() as env:
            for name in names:
                env.delenv(name, raising=False)
            for name, value in values.items():
                env.setenv(name, value)

            reloaded_config = importlib.reload(autosecops_config)

            assert (
                reloaded_config.AUTOSECOPS__LIMIT_AGG_GROUPS_DEFAULT,
                reloaded_config.AUTOSECOPS__LIMIT_AGG_GROUPS_MAX,
                reloaded_config.AUTOSECOPS__AGG_STATEMENT_TIMEOUT_MS,
            ) == expected
    finally:
        importlib.reload(autosecops_config)


def test_executor_concurrency_uses_bounded_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        with monkeypatch.context() as env:
            env.delenv("AUTOSECOPS__EXECUTOR_MAX_CONCURRENT_ACTIVITIES", raising=False)
            env.delenv("AUTOSECOPS__EXECUTOR_THREADPOOL_MAX_WORKERS", raising=False)

            reloaded_config = importlib.reload(autosecops_config)

            assert reloaded_config.AUTOSECOPS__EXECUTOR_MAX_CONCURRENT_ACTIVITIES == 16
            assert reloaded_config.AUTOSECOPS__EXECUTOR_THREADPOOL_MAX_WORKERS == 16
    finally:
        importlib.reload(autosecops_config)


def test_bound_env_rejects_invalid_numeric_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_BOUND_ENV", "not-a-number")

    with pytest.raises(ValueError, match="TEST_BOUND_ENV must be an integer"):
        bound_env("TEST_BOUND_ENV", 16, lower=8)


def test_bound_env_rejects_invalid_bounds() -> None:
    with pytest.raises(
        ValueError, match="lower \\(10\\) cannot be greater than upper \\(8\\)"
    ):
        bound_env("TEST_BOUND_ENV", 16, lower=10, upper=8)


@pytest.mark.parametrize(
    "name",
    [
        # Read by no code.
        "AUTOSECOPS__AGENT_FS_ARCHIVE_CACHE_MAX_BYTES",
        # Tuning knobs that Compose never passes to a container.
        "AUTOSECOPS__EXECUTOR_TOKEN_TTL_SECONDS",
        "AUTOSECOPS__BLOB_STORAGE_MAX_ATTEMPTS",
        "SAML_ACCEPTED_TIME_DIFF",
    ],
)
def test_env_example_does_not_advertise_ineffective_settings(name: str) -> None:
    source = (REPO_ROOT / ".env.example").read_text()
    assert f"{name}=" not in source


def test_ui_deployments_do_not_set_unread_auth_types() -> None:
    """The frontend never reads NEXT_PUBLIC_AUTH_TYPES; auth discovery is an API."""
    paths = [
        *COMPOSE_ENV_FILES,
        REPO_ROOT / "deployments" / "helm" / "autosecops" / "templates" / "ui.yaml",
        REPO_ROOT / "deployments" / "fargate" / "modules" / "ecs" / "locals.tf",
    ]
    for path in paths:
        assert "NEXT_PUBLIC_AUTH_TYPES" not in path.read_text(), path.name


def test_platform_otel_operator_settings_are_not_advertised_in_env_example() -> None:
    source = (REPO_ROOT / ".env.example").read_text()
    assert "AUTOSECOPS__PLATFORM_OTEL_ENABLED" not in source
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in source
    assert "OTEL_EXPORTER_OTLP_HEADERS" not in source


@pytest.mark.parametrize(
    "raw,expected", [("", None), ("  \t", None), ("8192", 8192), (" 8192 ", 8192)]
)
def test_sandbox_address_space_override(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: int | None
) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB", raw)
            reloaded_config = importlib.reload(autosecops_config)
            assert reloaded_config.AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB == expected
    finally:
        importlib.reload(autosecops_config)


@pytest.mark.parametrize(
    "name",
    ["AUTOSECOPS__SANDBOX_DEFAULT_MEMORY_MB", "AUTOSECOPS__SANDBOX_ADDRESS_SPACE_MB"],
)
@pytest.mark.parametrize("value", ["0", "-1"])
def test_sandbox_memory_limits_must_be_positive(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv(name, value)
            with pytest.raises(ValueError, match=name):
                importlib.reload(autosecops_config)
    finally:
        importlib.reload(autosecops_config)


def test_legacy_env_var_replacements_maps_pre_rename_names() -> None:
    environ = {
        "TRACECAT__DB_URI": "postgresql://synthetic",
        "TRACECAT_MCP__PORT": "8099",
        "AUTOSECOPS__APP_ENV": "development",
        "PATH": "/usr/bin",
    }

    assert autosecops_config.legacy_env_var_replacements(environ) == {
        "TRACECAT_MCP__PORT": "AUTOSECOPS_MCP__PORT",
        "TRACECAT__DB_URI": "AUTOSECOPS__DB_URI",
    }


def test_report_legacy_env_vars_logs_error_naming_replacement(
    caplog: pytest.LogCaptureFixture,
) -> None:
    environ = {"TRACECAT__SERVICE_KEY": "synthetic-service-key"}

    with caplog.at_level("ERROR", logger=autosecops_config.logger.name):
        reported = autosecops_config.report_legacy_env_vars(environ)

    assert reported == {"TRACECAT__SERVICE_KEY": "AUTOSECOPS__SERVICE_KEY"}
    messages = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert len(messages) == 1
    assert "TRACECAT__SERVICE_KEY" in messages[0]
    assert "AUTOSECOPS__SERVICE_KEY" in messages[0]
    assert "synthetic-service-key" not in messages[0]


def test_report_legacy_env_vars_is_silent_without_legacy_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("ERROR", logger=autosecops_config.logger.name):
        reported = autosecops_config.report_legacy_env_vars(
            {"AUTOSECOPS__SERVICE_KEY": "synthetic-service-key"}
        )

    assert reported == {}
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


def test_legacy_env_vars_are_ignored_on_import(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("AUTOSECOPS__SERVICE_NAME", raising=False)
    monkeypatch.setenv("TRACECAT__SERVICE_NAME", "legacy-service-name")

    try:
        with caplog.at_level("ERROR", logger=autosecops_config.logger.name):
            reloaded = importlib.reload(autosecops_config)
        assert reloaded.AUTOSECOPS__SERVICE_NAME == "autosecops"
        assert any("AUTOSECOPS__SERVICE_NAME" in r.getMessage() for r in caplog.records)
    finally:
        monkeypatch.undo()
        importlib.reload(autosecops_config)


ENV_EXAMPLE_GENERATED_SECRETS = (
    "AUTOSECOPS__DB_ENCRYPTION_KEY",
    "AUTOSECOPS__SERVICE_KEY",
    "AUTOSECOPS__SIGNING_SECRET",
    "USER_AUTH_SECRET",
    "AUTOSECOPS__POSTGRES_PASSWORD",
    "TEMPORAL__POSTGRES_PASSWORD",
    "MINIO_ROOT_PASSWORD",
    "AUTOSECOPS__DB_RUNTIME_PASSWORD",
    "REDIS_PASSWORD",
)
WEAK_DEFAULT_CREDENTIALS = {
    "AUTOSECOPS__POSTGRES_PASSWORD": {"postgres"},
    "TEMPORAL__POSTGRES_PASSWORD": {"temporal"},
    "MINIO_ROOT_PASSWORD": {"password", "minioadmin"},
}


def _env_example_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (REPO_ROOT / ".env.example").read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        values[name] = value
    return values


def test_env_example_ships_placeholders_instead_of_weak_secrets() -> None:
    values = _env_example_values()
    for name in ENV_EXAMPLE_GENERATED_SECRETS:
        assert values[name].startswith("change-me-"), (
            f"{name} must ship a `change-me-` placeholder that env.sh replaces"
        )
    for name, weak_values in WEAK_DEFAULT_CREDENTIALS.items():
        assert values[name] not in weak_values


def test_env_example_defaults_to_production_mode() -> None:
    values = _env_example_values()
    assert values["AUTOSECOPS__APP_ENV"] == "production"
    assert values["NODE_ENV"] == "production"
    assert values["NEXT_PUBLIC_APP_ENV"] == "production"


def test_temporal_ui_image_is_pinned() -> None:
    assert _env_example_values()["TEMPORAL__UI_VERSION"] not in {"", "latest"}
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        images = re.findall(
            r"image:\s*(?:temporalio/ui|\$\{TEMPORAL__UI_IMAGE_REPOSITORY:-temporalio/ui\}):(\S+)",
            path.read_text(),
        )
        assert images, f"{path.name} has no Temporal UI service"
        for image in images:
            assert "latest" not in image, f"{path.name} pins temporalio/ui to latest"
            assert re.fullmatch(r"\$\{TEMPORAL__UI_VERSION:-\d+\.\d+\.\d+\}", image)


def _temporal_postgres_service(text: str) -> str:
    match = re.search(
        r"^  temporal_postgres_db:\n((?:    .*\n|\n)+)", text, re.MULTILINE
    )
    assert match, "no temporal_postgres_db service"
    return match.group(1)


def test_temporal_postgres_matches_core_postgres_base() -> None:
    """The Temporal DB runs the same digest-pinned PostgreSQL 16 base as the core DB."""
    images = json.loads((REPO_ROOT / "deployments/postgres/images.json").read_text())
    base = images["trixie"]["base"]
    assert re.fullmatch(r"postgres:16\.\d+-trixie@sha256:[0-9a-f]{64}", base)
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        service = _temporal_postgres_service(path.read_text())
        assert f"    image: ${{TEMPORAL__POSTGRES_IMAGE:-{base}}}\n" in service, (
            f"{path.name}: temporal_postgres_db must default to {base}"
        )
        # Existing PostgreSQL 13 volumes stop with upgrade steps, not a FATAL.
        assert "PG_VERSION" in service
        assert "updating#upgrade-the-temporal-database" in service
        assert "exec docker-entrypoint.sh postgres" in service
        assert "temporal-db:/var/lib/postgresql/data" in service


def test_temporal_server_version_matches_across_targets() -> None:
    versions: dict[str, str] = {}
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        matches = re.findall(
            r"temporalio/auto-setup\}?:\$\{TEMPORAL__VERSION:-([\d.]+)\}",
            path.read_text(),
        )
        assert len(matches) == 1, f"{path.name} has no pinned Temporal server"
        versions[path.name] = matches[0]
    for tf in ("variables.tf", "modules/ecs/variables.tf"):
        text = (REPO_ROOT / "deployments/fargate" / tf).read_text()
        match = re.search(
            r'variable "temporal_server_image_tag" \{[^}]*default\s*=\s*"([^"]+)"',
            text,
        )
        assert match, f"{tf} has no temporal_server_image_tag default"
        versions[f"fargate/{tf}"] = match.group(1)
    assert len(set(versions.values())) == 1, f"Temporal versions drifted: {versions}"


def _run_env_migration(tmp_path: Path, old_env: str) -> str:
    for name in ("env-migration.sh", ".env.example"):
        (tmp_path / name).write_text((REPO_ROOT / name).read_text())
    (tmp_path / ".env").write_text(old_env)
    subprocess.run(
        ["bash", "env-migration.sh"],
        cwd=tmp_path,
        input="n\ny\n",
        capture_output=True,
        text=True,
        check=True,
    )
    return (tmp_path / ".env").read_text()


def test_env_migration_keeps_temporal_postgres_image_pin(tmp_path: Path) -> None:
    pinned = _run_env_migration(
        tmp_path,
        "AUTOSECOPS__APP_ENV=production\nTEMPORAL__POSTGRES_IMAGE=postgres:13\n",
    )
    assert re.search(r"^TEMPORAL__POSTGRES_IMAGE=postgres:13$", pinned, re.MULTILINE)
    assert re.search(r"^AUTOSECOPS__APP_ENV=production$", pinned, re.MULTILINE)

    unpinned = _run_env_migration(tmp_path, "AUTOSECOPS__APP_ENV=production\n")
    assert "TEMPORAL__POSTGRES_IMAGE" not in unpinned


def test_redis_service_runs_pinned_valkey() -> None:
    """Redis 7.4 and later are RSALv2/SSPLv1, so the stacks ship Valkey instead."""
    pins: dict[str, str] = {}
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        text = path.read_text()
        match = re.search(
            r"^  redis:\n    image: (?:\$\{AUTOSECOPS__REDIS_IMAGE:-)?([^}\s]+)\}?$",
            text,
            re.MULTILINE,
        )
        assert match, f"{path.name} has no redis service image"
        image = match.group(1)
        assert re.fullmatch(
            r"valkey/valkey:\d+\.\d+\.\d+-alpine@sha256:[0-9a-f]{64}", image
        ), f"{path.name}: pin redis to valkey/valkey:<x.y.z>-alpine@sha256:<digest>"
        assert not re.search(r"^\s*-?\s*redis-data:", text, re.MULTILINE), (
            f"{path.name}: Valkey 8 cannot load Redis 7.4+ data; keep valkey-data"
        )
        pins[path.name] = image
    assert len(set(pins.values())) == 1, f"Valkey pins drifted: {pins}"


def test_env_sh_check_refuses_placeholder_secrets(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text((REPO_ROOT / ".env.example").read_text())
    refused = subprocess.run(
        ["bash", str(REPO_ROOT / "env.sh"), "--check", str(env_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode == 1
    for name in ENV_EXAMPLE_GENERATED_SECRETS:
        assert name in refused.stdout

    generated = env_file.read_text()
    for name in ENV_EXAMPLE_GENERATED_SECRETS:
        generated = re.sub(
            rf"^{name}=.*$", f"{name}=generated-value", generated, flags=re.MULTILINE
        )
    env_file.write_text(generated)
    accepted = subprocess.run(
        ["bash", str(REPO_ROOT / "env.sh"), "--check", str(env_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert accepted.returncode == 0, accepted.stdout


@pytest.mark.parametrize("value", ["0", "-1", "1.5"])
def test_background_activity_capacity_rejects_invalid_values(monkeypatch, value):
    try:
        with monkeypatch.context() as env:
            env.setenv("AUTOSECOPS__BACKGROUND_MAX_CONCURRENT_ACTIVITIES", value)
            with pytest.raises(ValueError):
                importlib.reload(autosecops_config)
    finally:
        importlib.reload(autosecops_config)


@pytest.mark.parametrize("path", SANDBOX_POLICY_COMPOSE_ENV_FILES, ids=lambda p: p.name)
@pytest.mark.parametrize(
    "setting",
    [
        "AUTOSECOPS__AGENT_SANDBOX_TIMEOUT",
        "AUTOSECOPS__CONTEXT_COMPRESSION_ENABLED",
        "AUTOSECOPS__CONTEXT_COMPRESSION_THRESHOLD_KB",
    ],
)
def test_background_worker_shared_settings_match_other_services(
    path: Path, setting: str
) -> None:
    """Background activities use the same validation and payload codec settings."""
    source = path.read_text()
    values = []
    for service in ("api", "worker", "background-worker", "executor", "agent-executor"):
        block = re.search(
            rf"(?ms)^  {service}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
            source,
        )
        assert block is not None
        value = re.search(rf"{setting}:\s*(\S+)", block["body"])
        assert value is not None, service
        values.append(value[1])
    assert len(set(values)) == 1, values


# === Compose operations: log rotation, resource limits, Redis auth === #

# One-shot containers exit after their task, so they need no memory limit or
# restart policy.
COMPOSE_ONE_SHOT_SERVICES = {"migrations", "minio-init"}
COMPOSE_LOGGING_ANCHOR = """x-logging: &default-logging
  driver: ${AUTOSECOPS__DOCKER_LOG_DRIVER:-json-file}
  options:
    max-size: ${AUTOSECOPS__DOCKER_LOG_MAX_SIZE:-50m}
    max-file: "${AUTOSECOPS__DOCKER_LOG_MAX_FILE:-5}"
"""


def _compose_services(path: Path) -> dict[str, dict[str, Any]]:
    services = yaml.safe_load(path.read_text())["services"]
    assert isinstance(services, dict)
    return services


def _compose_limit_env(service: str, kind: str) -> str:
    return f"AUTOSECOPS__{service.upper().replace('-', '_')}_{kind}_LIMIT"


@pytest.mark.parametrize(
    "path", SANDBOX_POLICY_COMPOSE_ENV_FILES, ids=lambda path: path.name
)
def test_compose_services_rotate_logs(path: Path) -> None:
    """Unbounded json-file logs fill the Docker host's disk."""
    source = path.read_text()
    assert COMPOSE_LOGGING_ANCHOR in source
    for name in _compose_services(path):
        body = _compose_service_body(source, name) or ""
        assert re.search(r"(?m)^ +logging: \*default-logging$", body), (
            f"{path.name}: {name} must use the bounded x-logging anchor"
        )


@pytest.mark.parametrize(
    "path", SANDBOX_POLICY_COMPOSE_ENV_FILES, ids=lambda path: path.name
)
def test_compose_long_running_services_have_limits(path: Path) -> None:
    """A runaway container must not take the host's memory from the database."""
    services = _compose_services(path)
    assert COMPOSE_ONE_SHOT_SERVICES <= set(services)
    for name, service in services.items():
        if name in COMPOSE_ONE_SHOT_SERVICES:
            assert service.get("restart") == "no", f"{path.name}: {name}"
            continue
        assert service.get("restart") in {"unless-stopped", "on-failure:3"}, (
            f"{path.name}: {name} needs a restart policy"
        )
        # deploy.resources.limits, not mem_limit/cpus/pids_limit: Compose
        # merges an operator's deploy.resources override over it, but refuses
        # a service that sets both forms with different values.
        for key in ("mem_limit", "memswap_limit", "cpus", "pids_limit"):
            assert key not in service, f"{path.name}: {name} sets {key}"
        limits = service.get("deploy", {}).get("resources", {}).get("limits", {})
        memory = _compose_limit_env(name, "MEMORY")
        assert re.fullmatch(rf"\$\{{{memory}:-\d+[mg]\}}", limits.get("memory", "")), (
            f"{path.name}: {name} needs a deploy memory limit from {memory}"
        )
        # A CPU limit above the host's core count stops `docker compose up`, so
        # CPU limits stay opt-in.
        cpus = _compose_limit_env(name, "CPU")
        assert limits.get("cpus") == f"${{{cpus}:-0}}", (
            f"{path.name}: {name} needs an overridable cpus limit from {cpus}"
        )


def test_compose_limit_defaults_match_across_files() -> None:
    defaults: dict[str, dict[str, str]] = {}
    for path in SANDBOX_POLICY_COMPOSE_ENV_FILES:
        defaults[path.name] = dict(
            re.findall(
                r"memory: \$\{(AUTOSECOPS__[A-Z_]+_MEMORY_LIMIT):-(\w+)\}",
                path.read_text(),
            )
        )
    assert len({tuple(sorted(d.items())) for d in defaults.values()}) == 1, defaults


def _redis_service_body(path: Path) -> str:
    body = _compose_service_body(path.read_text(), "redis")
    assert body, f"{path.name} has no redis service"
    return body


@pytest.mark.parametrize(
    "path",
    (REPO_ROOT / "docker-compose.yml", REPO_ROOT / "docker-compose.local.yml"),
    ids=lambda path: path.name,
)
def test_compose_redis_requires_password(path: Path) -> None:
    body = _redis_service_body(path)
    # Compose refuses to start without REDIS_PASSWORD, with the upgrade step.
    assert re.search(
        r"(?m)^      REDIS_PASSWORD: \$\{REDIS_PASSWORD:\?[^}]*env\.sh --upgrade[^}]*\}",
        body,
    )
    # The container refuses an empty value or the .env.example placeholder.
    assert '"" | change-me-*)' in body
    assert (
        'exec docker-entrypoint.sh --appendonly yes --maxmemory "$$maxmemory" --maxmemory-policy noeviction --requirepass "$$REDIS_PASSWORD"'
        in body
    )
    assert "command:" not in body
    # The health check authenticates; an unauthenticated PING answers NOAUTH.
    assert 'REDISCLI_AUTH=\\"$$REDIS_PASSWORD\\"' in body
    assert "| grep -q PONG" in body


def test_dev_compose_redis_uses_password_when_set() -> None:
    body = _redis_service_body(REPO_ROOT / "docker-compose.dev.yml")
    assert "REDIS_PASSWORD: ${REDIS_PASSWORD:-}" in body
    assert "change-me-*)" in body
    assert (
        'exec docker-entrypoint.sh --appendonly yes --maxmemory "$$maxmemory" --maxmemory-policy noeviction --requirepass "$$REDIS_PASSWORD"'
        in body
    )


@pytest.mark.parametrize(
    "path", SANDBOX_POLICY_COMPOSE_ENV_FILES, ids=lambda path: path.name
)
def test_compose_redis_clients_get_password(path: Path) -> None:
    source = path.read_text()
    clients = [
        name
        for name in _compose_services(path)
        if "REDIS_URL:" in (_compose_service_body(source, name) or "")
    ]
    assert clients
    for name in clients:
        body = _compose_service_body(source, name) or ""
        assert (
            "REDIS_PASSWORD: ${REDIS_CLIENT_PASSWORD-${REDIS_PASSWORD:-}} # Sensitive"
            in body
        ), f"{path.name}: {name}"


def test_compose_redis_is_not_published() -> None:
    """Production Compose keeps Redis on the internal network only."""
    prod = _compose_services(REPO_ROOT / "docker-compose.yml")["redis"]
    assert "ports" not in prod
    assert not re.search(
        r"(?m)^ +#? *ports:", _redis_service_body(REPO_ROOT / "docker-compose.yml")
    )
    # Development stacks publish it for host tests, on loopback only.
    for name in ("docker-compose.dev.yml", "docker-compose.local.yml"):
        ports = _compose_services(REPO_ROOT / name)["redis"].get("ports", [])
        assert ports, name
        for port in ports:
            assert str(port).startswith("127.0.0.1:"), f"{name}: {port}"


def test_redis_password_is_generated_by_env_sh() -> None:
    assert 'dotenv_replace "REDIS_PASSWORD"' in (REPO_ROOT / "env.sh").read_text()


def _run_env_sh_upgrade(tmp_path: Path, env: str) -> tuple[str, str]:
    env_file = tmp_path / ".env"
    env_file.write_text(env)
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "env.sh"), "--upgrade", str(env_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return env_file.read_text(), result.stdout


def test_env_sh_upgrade_adds_redis_password(tmp_path: Path) -> None:
    upgraded, out = _run_env_sh_upgrade(
        tmp_path, "REDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}\n"
    )
    assert re.search(r"(?m)^REDIS_PASSWORD=[0-9a-f]{48}$", upgraded)
    assert "generated" in out
    assert list(tmp_path.glob(".env.backup_*"))
    # Idempotent: a second run keeps the password.
    again, out = _run_env_sh_upgrade(tmp_path, upgraded)
    assert again == upgraded
    assert "up to date" in out


def test_env_sh_upgrade_reuses_redis_url_password(tmp_path: Path) -> None:
    # Installs that followed the earlier hardening steps keep their password.
    upgraded, _ = _run_env_sh_upgrade(
        tmp_path,
        "REDIS_URL=redis://:synthetic%24pass@redis:6379\n"
        "REDIS_PASSWORD=change-me-redis-password\n",
    )
    assert "REDIS_PASSWORD='synthetic$pass'\n" in upgraded
    assert "change-me-" not in upgraded


def test_env_sh_check_requires_redis_password(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("AUTOSECOPS__APP_ENV=development\n")
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "env.sh"), "--check", str(env_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "REDIS_PASSWORD" in result.stdout
    assert "--upgrade" in result.stdout


def test_env_migration_sets_redis_password(tmp_path: Path) -> None:
    generated = _run_env_migration(
        tmp_path, "REDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}\n"
    )
    assert re.search(r"(?m)^REDIS_PASSWORD=[0-9a-f]{48}$", generated)

    reused = _run_env_migration(tmp_path, "REDIS_URL=redis://:synthetic@redis:6379\n")
    assert re.search(r"(?m)^REDIS_PASSWORD=synthetic$", reused)

    kept = _run_env_migration(
        tmp_path, "REDIS_PASSWORD=existing\nREDIS_URL=redis://redis:6379\n"
    )
    assert re.search(r"(?m)^REDIS_PASSWORD=existing$", kept)


def test_redis_password_treats_blank_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    try:
        with monkeypatch.context() as env:
            env.setenv("REDIS_PASSWORD", "")
            assert importlib.reload(autosecops_config).REDIS_PASSWORD is None
            env.setenv("REDIS_PASSWORD", "synthetic")
            assert importlib.reload(autosecops_config).REDIS_PASSWORD == "synthetic"
    finally:
        importlib.reload(autosecops_config)


def test_redis_clients_send_redis_password() -> None:
    """Every Redis client passes REDIS_PASSWORD; URL credentials still win."""
    clients = (
        "autosecops/redis/client.py",
        "autosecops/mcp/auth.py",
        "autosecops/mcp/oidc/storage.py",
        "autosecops/mcp/server.py",
    )
    for relative in clients:
        source = (REPO_ROOT / relative).read_text()
        calls = re.findall(r"from_url\((.*?)\)\n", source, re.S)
        assert calls, relative
        for call in calls:
            assert "REDIS_PASSWORD" in call, f"{relative}: {call}"
    for path in (REPO_ROOT / "autosecops").rglob("*.py"):
        source = path.read_text()
        if re.search(r"Redis\w*\.from_url\(|redis\.from_url\(", source):
            assert "REDIS_PASSWORD" in source, path.relative_to(REPO_ROOT)


@pytest.mark.parametrize(
    "path", SANDBOX_POLICY_COMPOSE_ENV_FILES, ids=lambda path: path.name
)
def test_compose_redis_caps_memory_below_its_limit(path: Path) -> None:
    """Valkey must refuse writes before the cgroup OOM-kills it.

    An OOM-killed Valkey replays the same AOF into the same limit on restart and
    crash-loops, taking every Redis client down with it.
    """
    body = _redis_service_body(path)
    assert "REDIS_MAXMEMORY: ${AUTOSECOPS__REDIS_MAXMEMORY:-}" in body
    assert "/sys/fs/cgroup/memory.max" in body
    assert "maxmemory=$$((limit / 4 * 3))" in body
    execs = re.findall(r"exec docker-entrypoint\.sh [^\n]*", body)
    assert execs
    for line in execs:
        assert '--maxmemory "$$maxmemory" --maxmemory-policy noeviction' in line


def _docs_yaml_blocks() -> list[tuple[Path, str]]:
    blocks: list[tuple[Path, str]] = []
    for path in sorted((REPO_ROOT / "docs").rglob("*.mdx")):
        for block in re.findall(r"```ya?ml[^\n]*\n(.*?)```", path.read_text(), re.S):
            blocks.append((path, block))
    return blocks


def test_docs_do_not_mix_compose_limit_forms() -> None:
    """The Compose files set deploy.resources.limits. Compose refuses a service
    that also sets mem_limit, cpus or pids_limit to a different value, so the
    docs must only show deploy.resources overrides."""
    for path, block in _docs_yaml_blocks():
        for key in ("mem_limit", "memswap_limit", "pids_limit"):
            assert not re.search(rf"(?m)^\s+{key}:", block), (
                f"{path.relative_to(REPO_ROOT)} shows {key}"
            )
        assert not re.search(r"(?m)^ {4}cpus:", block), path.relative_to(REPO_ROOT)


def test_docs_daemon_log_driver_override_covers_every_service() -> None:
    """The override that hands logging back to the Docker daemon's driver must
    list every service, or that service keeps writing local json-file logs."""
    page = (REPO_ROOT / "docs/self-hosting/docker-compose.mdx").read_text()
    reset = set(re.findall(r"(?m)^  ([\w-]+):\n    logging: !reset null$", page))
    expected = set(_compose_services(REPO_ROOT / "docker-compose.yml"))
    expected |= set(_compose_services(REPO_ROOT / "docker-compose.sandbox.yml"))
    assert reset == expected


def _env_from_env_sh(tmp_path: Path) -> str:
    """A complete production .env as env.sh writes it."""
    work = tmp_path / "env-sh"
    work.mkdir()
    for name in ("env.sh", ".env.example"):
        (work / name).write_text((REPO_ROOT / name).read_text())
    subprocess.run(
        ["bash", "env.sh"],
        cwd=work,
        input="y\nautosecops.example.test\nn\nadmin@example.com\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return (work / ".env").read_text()


def _run_env_migration_output(tmp_path: Path, old_env: str) -> tuple[str, str]:
    for name in ("env-migration.sh", ".env.example"):
        (tmp_path / name).write_text((REPO_ROOT / name).read_text())
    (tmp_path / ".env").write_text(old_env)
    result = subprocess.run(
        ["bash", "env-migration.sh"],
        cwd=tmp_path,
        input="n\ny\n",
        capture_output=True,
        text=True,
        check=True,
    )
    return (tmp_path / ".env").read_text(), result.stdout


def _drop_keys(env: str, *keys: str) -> str:
    return "".join(
        line
        for line in env.splitlines(keepends=True)
        if not any(line.startswith(f"{key}=") for key in keys)
    )


def test_env_migration_output_passes_env_sh_check(tmp_path: Path) -> None:
    """The documented upgrade runs env-migration.sh, then env.sh --check."""
    old_env = _drop_keys(
        _env_from_env_sh(tmp_path), "AUTOSECOPS__DB_RUNTIME_PASSWORD", "REDIS_PASSWORD"
    )
    migrated, out = _run_env_migration_output(tmp_path, old_env)
    assert re.search(r"(?m)^AUTOSECOPS__DB_RUNTIME_PASSWORD=[0-9a-f]{48}$", migrated)
    assert re.search(r"(?m)^REDIS_PASSWORD=[0-9a-f]{48}$", migrated)
    assert "REDIS_CLIENT_PASSWORD" not in migrated
    assert "WARNING" not in out
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "env.sh"), "--check", str(tmp_path / ".env")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


def test_env_migration_keeps_an_explicitly_empty_runtime_password(
    tmp_path: Path,
) -> None:
    migrated, _ = _run_env_migration_output(
        tmp_path, "AUTOSECOPS__DB_RUNTIME_PASSWORD=\n"
    )
    assert re.search(r"(?m)^AUTOSECOPS__DB_RUNTIME_PASSWORD=$", migrated)
    kept, _ = _run_env_migration_output(
        tmp_path, "AUTOSECOPS__DB_RUNTIME_PASSWORD=synthetic-runtime\n"
    )
    assert re.search(r"(?m)^AUTOSECOPS__DB_RUNTIME_PASSWORD=synthetic-runtime$", kept)


@pytest.mark.parametrize(
    "redis_env",
    [
        "REDIS_URL=redis://cache.internal.example.test:6379\n",
        "REDIS_HOST=cache.internal.example.test\n"
        "REDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}\n",
        "REDIS_URL=rediss://cache.internal.example.test:6380/0\n",
    ],
)
def test_env_migration_keeps_external_unauthenticated_redis_working(
    tmp_path: Path, redis_env: str
) -> None:
    migrated, out = _run_env_migration_output(tmp_path, redis_env)
    # The bundled Redis still gets a password; the clients send none.
    assert re.search(r"(?m)^REDIS_PASSWORD=[0-9a-f]{48}$", migrated)
    assert re.search(r"(?m)^REDIS_CLIENT_PASSWORD=$", migrated)
    assert "WARNING: REDIS_URL points to an external Redis" in out
    assert "cache.internal.example.test" in out
    # A later migration keeps the opt-out although .env.example omits it.
    again, out = _run_env_migration_output(tmp_path, migrated)
    assert re.search(r"(?m)^REDIS_CLIENT_PASSWORD=$", again)
    assert "WARNING" not in out


def test_env_migration_sends_bundled_or_url_passwords(tmp_path: Path) -> None:
    for redis_env in (
        "REDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}\n",
        "REDIS_HOST=redis\nREDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}\n",
        "REDIS_URL=rediss://:synthetic@cache.internal.example.test:6380\n",
    ):
        migrated, out = _run_env_migration_output(tmp_path, redis_env)
        assert "REDIS_CLIENT_PASSWORD" not in migrated, redis_env
        assert "WARNING" not in out, redis_env


def test_env_sh_upgrade_generates_runtime_password(tmp_path: Path) -> None:
    upgraded, _ = _run_env_sh_upgrade(
        tmp_path,
        "AUTOSECOPS__DB_RUNTIME_PASSWORD=change-me-runtime-password\n"
        "REDIS_PASSWORD=synthetic\n",
    )
    assert re.search(r"(?m)^AUTOSECOPS__DB_RUNTIME_PASSWORD=[0-9a-f]{48}$", upgraded)
    assert "REDIS_PASSWORD=synthetic\n" in upgraded
    # An explicitly empty value is the operator's choice.
    kept, out = _run_env_sh_upgrade(
        tmp_path, "AUTOSECOPS__DB_RUNTIME_PASSWORD=\nREDIS_PASSWORD=synthetic\n"
    )
    assert "up to date" in out
    assert "AUTOSECOPS__DB_RUNTIME_PASSWORD=\n" in kept


def test_env_sh_upgrade_keeps_external_unauthenticated_redis_working(
    tmp_path: Path,
) -> None:
    upgraded, out = _run_env_sh_upgrade(
        tmp_path,
        "AUTOSECOPS__DB_RUNTIME_PASSWORD=synthetic\n"
        "REDIS_HOST=cache.internal.example.test\n"
        "REDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}\n",
    )
    assert re.search(r"(?m)^REDIS_PASSWORD=[0-9a-f]{48}$", upgraded)
    assert re.search(r"(?m)^REDIS_CLIENT_PASSWORD=$", upgraded)
    assert "external Redis (cache.internal.example.test)" in out
    again, out = _run_env_sh_upgrade(tmp_path, upgraded)
    assert again == upgraded
    assert "up to date" in out


# === Fargate operations: log retention, Redis auth, HA profile === #

FARGATE_DIR = REPO_ROOT / "deployments" / "fargate"


def test_fargate_log_group_has_retention() -> None:
    """CloudWatch Logs rotates ECS task logs; the group must still expire them."""
    log_group = (FARGATE_DIR / "modules/ecs/cloudwatch.tf").read_text()
    assert "retention_in_days = var.log_retention_in_days" in log_group
    for tf in ("variables.tf", "modules/ecs/variables.tf"):
        assert re.search(
            r'variable "log_retention_in_days" \{[^}]*default\s*=\s*30\n',
            (FARGATE_DIR / tf).read_text(),
        ), tf
    assert re.search(
        r"log_retention_in_days\s*=\s*var\.log_retention_in_days\n",
        (FARGATE_DIR / "main.tf").read_text(),
    )


def test_fargate_redis_requires_tls_and_auth() -> None:
    redis_tf = (FARGATE_DIR / "modules/ecs/redis.tf").read_text()
    assert re.search(r"transit_encryption_enabled\s*=\s*true", redis_tf)
    assert re.search(r"at_rest_encryption_enabled\s*=\s*true", redis_tf)
    # The default user is disabled; the app user needs a password.
    assert 'access_string = "off ~* -@all"' in redis_tf
    assert re.search(r'type\s*=\s*"password"', redis_tf)
    assert re.search(
        r"user_group_ids\s*=\s*\[aws_elasticache_user_group\.redis\.id\]", redis_tf
    )
    assert '"rediss://%s:%s@%s:%d"' in redis_tf
    # Multi-node groups fail over automatically.
    assert re.search(
        r"automatic_failover_enabled\s*=\s*var\.redis_num_cache_clusters > 1",
        redis_tf,
    )


def _tfvars(path: Path) -> dict[str, str]:
    return dict(re.findall(r"(?m)^([a-z_]+)\s*=\s*(\S+)\s*$", path.read_text()))


def test_fargate_ha_example_is_valid_and_redundant() -> None:
    example = _tfvars(FARGATE_DIR / "examples/ha.tfvars.example")
    root_variables = (FARGATE_DIR / "variables.tf").read_text()
    main_tf = (FARGATE_DIR / "main.tf").read_text()
    for name in example:
        assert f'variable "{name}" {{' in root_variables, name
        assert re.search(rf"\b{name}\s*=\s*var\.{name}\n", main_tf), name
    for service in (
        "api",
        "worker",
        "executor",
        "agent_worker",
        "agent_executor",
        "background_worker",
        "mcp",
        "litellm",
        "ui",
        "caddy",
    ):
        assert int(example[f"{service}_desired_count"]) >= 2, service
    # Every ECS service the stack always runs takes its count from a variable,
    # so no single task sits outside the profile. The bundled Temporal server
    # and UI are the documented exception.
    ecs_dir = FARGATE_DIR / "modules/ecs"
    for tf in sorted(ecs_dir.glob("ecs-*.tf")):
        for count in re.findall(r"(?m)^\s+desired_count\s*=\s*(\S+)$", tf.read_text()):
            if tf.name in {"ecs-temporal.tf", "ecs-temporal-ui.tf"}:
                continue
            assert count.startswith("var."), f"{tf.name}: desired_count = {count}"
    assert "Temporal" in (FARGATE_DIR / "examples/ha.tfvars.example").read_text()
    # New counts default to one task, so existing bills do not change.
    for name in ("ui_desired_count", "caddy_desired_count"):
        assert re.search(
            rf'variable "{name}" \{{[^}}]*default\s*=\s*1\n', root_variables
        ), name
    assert example["rds_multi_az"] == "true"
    assert int(example["redis_num_cache_clusters"]) >= 2
    # The HA profile is opt-in: defaults do not add standby databases.
    assert re.search(
        r'variable "rds_multi_az" \{[^}]*default\s*=\s*false', root_variables
    )
    assert re.search(
        r'variable "redis_num_cache_clusters" \{[^}]*default\s*=\s*1\n',
        root_variables,
    )


@pytest.mark.parametrize("value", [None, "", "  "])
def test_env_port_uses_default_when_unset_or_blank(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("TEST_PORT", raising=False)
    else:
        monkeypatch.setenv("TEST_PORT", value)
    assert env_port("TEST_PORT", default=9100) == 9100


@pytest.mark.parametrize("value", ["0", "65536", "-1", "http", "80,81"])
def test_env_port_rejects_invalid_ports(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("TEST_PORT", value)
    with pytest.raises(ValueError, match="TEST_PORT must be a port number"):
        env_port("TEST_PORT", default=9100)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "0.0.0.0"),
        ("", "0.0.0.0"),
        (" 127.0.0.1 ", "127.0.0.1"),
        ("::", "::"),
        ("[::1]", "::1"),
    ],
)
def test_env_bind_host_parses_ip_literals(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: str
) -> None:
    if value is None:
        monkeypatch.delenv("TEST_HOST", raising=False)
    else:
        monkeypatch.setenv("TEST_HOST", value)
    assert env_bind_host("TEST_HOST", default="0.0.0.0") == expected


@pytest.mark.parametrize("value", ["localhost", "metrics.example.com", "0.0.0.0:9100"])
def test_env_bind_host_rejects_hostnames(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("TEST_HOST", value)
    with pytest.raises(ValueError, match="TEST_HOST must be an IP address"):
        env_bind_host("TEST_HOST", default="0.0.0.0")


def test_format_bind_address_brackets_ipv6() -> None:
    assert format_bind_address("0.0.0.0", 9090) == "0.0.0.0:9090"
    assert format_bind_address("::", 9090) == "[::]:9090"


def test_metrics_are_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    try:
        with monkeypatch.context() as env:
            for name in (
                "AUTOSECOPS__API_METRICS_ENABLED",
                "AUTOSECOPS__API_METRICS_HOST",
                "AUTOSECOPS__API_METRICS_PORT",
                "TEMPORAL__METRICS_HOST",
                "TEMPORAL__METRICS_PORT",
            ):
                env.delenv(name, raising=False)
            reloaded = importlib.reload(autosecops_config)
            assert reloaded.AUTOSECOPS__API_METRICS_ENABLED is False
            assert reloaded.AUTOSECOPS__API_METRICS_PORT == 9100
            assert reloaded.TEMPORAL__METRICS_PORT is None
    finally:
        importlib.reload(autosecops_config)


TEMPORAL_WORKER_COMPOSE_SERVICES = (
    "worker",
    "background-worker",
    "executor",
    "agent-worker",
    "agent-executor",
)


@pytest.mark.parametrize(
    "path", SANDBOX_POLICY_COMPOSE_ENV_FILES, ids=lambda path: path.name
)
def test_temporal_workers_have_readiness_healthchecks(path: Path) -> None:
    services = yaml.safe_load(path.read_text())["services"]
    for name in TEMPORAL_WORKER_COMPOSE_SERVICES:
        service = services[name]
        assert service["healthcheck"]["test"] == [
            "CMD",
            "python",
            "-m",
            "autosecops.temporal.healthcheck",
            "ready",
        ], name
        assert service["environment"]["TEMPORAL__METRICS_PORT"] == (
            "${TEMPORAL__METRICS_PORT:-}"
        ), name
        # Without the passthrough, a loopback bind set in .env would be ignored.
        assert service["environment"]["TEMPORAL__METRICS_HOST"] == (
            "${TEMPORAL__METRICS_HOST:-0.0.0.0}"
        ), name
        assert "9090" not in str(service.get("ports", [])), name
    api = services["api"]
    assert api["environment"]["AUTOSECOPS__API_METRICS_ENABLED"] == (
        "${AUTOSECOPS__API_METRICS_ENABLED:-false}"
    )
    assert api["environment"]["AUTOSECOPS__API_METRICS_HOST"] == (
        "${AUTOSECOPS__API_METRICS_HOST:-0.0.0.0}"
    )
    assert "9100" not in str(api.get("ports", []))


@pytest.mark.parametrize(
    "task_file",
    [
        "ecs-worker.tf",
        "ecs-background-worker.tf",
        "ecs-executor.tf",
        "ecs-agent-worker.tf",
        "ecs-agent-executor.tf",
    ],
)
def test_fargate_temporal_workers_have_health_checks(task_file: str) -> None:
    ecs_dir = REPO_ROOT / "deployments" / "fargate" / "modules" / "ecs"
    assert (
        "healthCheck = local.worker_health_check" in (ecs_dir / task_file).read_text()
    )
    locals_source = (ecs_dir / "locals.tf").read_text()
    assert (
        'command     = ["CMD", "python", "-m", "autosecops.temporal.healthcheck", "live"]'
        in locals_source
    )


def test_fargate_metrics_are_opt_in_and_scoped_to_scrapers() -> None:
    fargate = REPO_ROOT / "deployments" / "fargate"
    ecs_dir = fargate / "modules" / "ecs"
    locals_source = (ecs_dir / "locals.tf").read_text()
    for name in (
        "TEMPORAL__METRICS_PORT",
        "TEMPORAL__METRICS_HOST",
        "AUTOSECOPS__API_METRICS_ENABLED",
        "AUTOSECOPS__API_METRICS_PORT",
        "AUTOSECOPS__API_METRICS_HOST",
    ):
        assert name in locals_source, name
    # Every Temporal worker env merges the metrics env; the background worker
    # derives from worker_env.
    assert locals_source.count("local.autosecops_worker_metrics_env,") == 4
    assert locals_source.count("local.autosecops_api_metrics_env,") == 1
    # No scraper security group: loopback only, for a sidecar in the task.
    assert (
        'length(var.metrics_scraper_security_group_ids) > 0 ? "0.0.0.0" : "127.0.0.1"'
        in locals_source
    )
    for tf in ("variables.tf", "modules/ecs/variables.tf"):
        source = (fargate / tf).read_text()
        assert 'variable "metrics_enabled"' in source, tf
        assert 'variable "metrics_scraper_security_group_ids"' in source, tf
    main = (fargate / "main.tf").read_text()
    assert "metrics_enabled                               = var.metrics_enabled" in main
    security_groups = (ecs_dir / "security_groups.tf").read_text()
    assert "security_groups = var.metrics_scraper_security_group_ids" in security_groups
