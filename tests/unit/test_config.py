from __future__ import annotations

import ast
import importlib
import re
import subprocess
from pathlib import Path

import pytest

import autosecops.config as autosecops_config
from autosecops.config import (
    bound_env,
    env_bool,
    env_networks,
    env_no_proxy,
    env_ports,
    env_proxy_url,
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
