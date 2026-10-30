"""The local evaluation lab and its sample workflows validate offline.

`deployments/lab/docker-compose.lab.yml` must stay a self-contained, pinned,
localhost-only Compose file, and every workflow in
`examples/005-local-evaluation-lab/workflows/` must load in the import format
(`ExternalWorkflowDefinition`) and pass the DSL validators that need no
database, with every action argument known to the registry.
"""

import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from autosecops.dsl.common import DSLInput
from autosecops.expressions.common import ExprType
from autosecops.registry.repository import Repository
from autosecops.validation.service import (
    validate_dsl_acyclic,
    validate_dsl_entrypoint,
    validate_dsl_expressions,
)
from autosecops.workflow.management.schemas import ExternalWorkflowDefinition

REPO_ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = REPO_ROOT / "deployments" / "lab"
LAB_COMPOSE = LAB_DIR / "docker-compose.lab.yml"
LAB_GPU_COMPOSE = LAB_DIR / "docker-compose.lab.gpu.yml"
LAB_ENV_EXAMPLE = LAB_DIR / ".env.lab.example"
LAB_SCRIPT = LAB_DIR / "lab.sh"
WORKFLOWS_DIR = REPO_ROOT / "examples" / "005-local-evaluation-lab" / "workflows"
WORKFLOW_FILES = sorted(WORKFLOWS_DIR.glob("*.yml"))
PROFILES = {"misp", "opensearch", "wazuh", "wazuh-init", "fleet", "mailpit", "ollama"}
REGISTRY_PACKAGE = "autosecops_registry"
# ${VAR:-default} or ${VAR:?message}; a bare ${VAR} would silently be blank.
INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-?][^}]*)?\}")


def _compose() -> dict[str, Any]:
    return yaml.safe_load(LAB_COMPOSE.read_text())


def _compose_code() -> str:
    """The Compose file without comment lines, which quote example syntax."""
    return "\n".join(
        line
        for line in LAB_COMPOSE.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


def _services() -> dict[str, dict[str, Any]]:
    return _compose()["services"]


def _env_example() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in LAB_ENV_EXAMPLE.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition("=")
        values[key] = value
    return values


def test_every_service_sits_behind_a_known_profile() -> None:
    for name, service in _services().items():
        profiles = set(service.get("profiles", []))
        assert profiles, f"{name} has no profile, so a bare `up` would start it"
        assert profiles <= PROFILES, f"{name}: unknown profiles {profiles - PROFILES}"


def test_images_are_pinned_by_tag_and_digest() -> None:
    for name, service in _services().items():
        image = service["image"]
        assert re.fullmatch(r"[^:@\s]+:[^:@\s]+@sha256:[0-9a-f]{64}", image), (
            f"{name}: pin `{image}` as name:tag@sha256:<digest>"
        )


def test_published_ports_bind_to_localhost_only() -> None:
    for name, service in _services().items():
        for port in service.get("ports", []):
            assert isinstance(port, str) and port.startswith("127.0.0.1:"), (
                f"{name}: publish {port!r} on 127.0.0.1 only"
            )


def test_main_stack_network_is_external_and_overridable() -> None:
    network = _compose()["networks"]["autosecops"]
    assert network["external"] is True
    assert network["name"] == "${AUTOSECOPS_CORE_NETWORK:-autosecops_core}"


def test_interpolations_have_a_default_or_fail_fast() -> None:
    bare = [
        match.group(0)
        for match in INTERPOLATION.finditer(_compose_code())
        if match.group(2) is None
    ]
    assert bare == [], f"use ${{VAR:-default}} or ${{VAR:?msg}}, not {bare}"


def test_required_secrets_have_placeholders_and_no_defaults() -> None:
    text = _compose_code()
    required = {
        match.group(1)
        for match in INTERPOLATION.finditer(text)
        if (match.group(2) or "").startswith(":?")
    }
    assert required, "lab passwords must be required variables"
    example = _env_example()
    for var in sorted(required):
        assert example.get(var, "").startswith("change-me-"), (
            f"{var} needs a change-me- placeholder in .env.lab.example"
        )
        assert f"${{{var}:-" not in text, f"{var} must not also have a default"


def test_env_example_values_are_explicit() -> None:
    for key, value in _env_example().items():
        assert value, f"{key} is blank in .env.lab.example"
        if value.lower() in {"true", "false"}:
            assert value in {"true", "false"}, f"{key}: write booleans in lower case"


def test_env_example_covers_every_compose_variable() -> None:
    used = {match.group(1) for match in INTERPOLATION.finditer(_compose_code())}
    # Optional knobs with safe defaults may stay out of the example.
    optional = {
        "LAB_MISP_DB_BUFFER_POOL",
        "LAB_MISP_ENABLE_REDIS_EMPTY_PASSWORD",
        "LAB_MISP_SMTP_FQDN",
        "LAB_MISP_SMTP_PORT",
        "LAB_WAZUH_INDEXER_PASSWORD",
        "LAB_WAZUH_DASHBOARD_PASSWORD",
        "LAB_FLEET_LOGGING_JSON",
        "LAB_MAILPIT_MAX_MESSAGES",
        "LAB_OLLAMA_FLASH_ATTENTION",
        "LAB_OLLAMA_KV_CACHE_TYPE",
        "LAB_OLLAMA_KEEP_ALIVE",
    }
    missing = used - optional - set(_env_example())
    assert not missing, f"add to .env.lab.example: {sorted(missing)}"


def test_lab_script_uses_lf_and_never_deletes_volumes() -> None:
    raw = LAB_SCRIPT.read_bytes()
    assert b"\r\n" not in raw
    code = [
        line for line in raw.decode().splitlines() if not line.lstrip().startswith("#")
    ]
    assert not any(re.search(r"\bdown\b.*\s-v\b", line) for line in code)
    assert not any("volume rm" in line for line in code)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_compose_config_renders(profile: str) -> None:
    files = ["-f", str(LAB_COMPOSE)]
    if profile == "ollama":
        files += ["-f", str(LAB_GPU_COMPOSE)]
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(LAB_ENV_EXAMPLE),
            *files,
            "--profile",
            profile,
            "config",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0 and "is not a docker command" in result.stderr:
        pytest.skip("docker compose plugin not installed")
    assert result.returncode == 0, result.stderr


def _registry_modules() -> dict[str, dict[str, object]]:
    return {
        name: dict(vars(module))
        for name, module in list(sys.modules.items())
        if module is not None
        and (name == REGISTRY_PACKAGE or name.startswith(f"{REGISTRY_PACKAGE}."))
    }


@pytest.fixture(scope="module")
def repo() -> Iterator[Repository]:
    """A fully initialised registry that does not leak into other test modules.

    ``Repository.init`` reloads every ``autosecops_registry`` module in place,
    so module namespaces are restored afterwards and modules first imported
    here are dropped.
    """
    before = _registry_modules()
    repository = Repository()
    repository.init(include_base=True, include_templates=True)
    try:
        yield repository
    finally:
        for name in set(_registry_modules()) - set(before):
            del sys.modules[name]
        for name, namespace in before.items():
            module = sys.modules.get(name)
            if module is None:
                continue
            current = vars(module)
            current.clear()
            current.update(namespace)


def _load(path: Path) -> ExternalWorkflowDefinition:
    return ExternalWorkflowDefinition.model_validate(yaml.safe_load(path.read_text()))


def _arg_errors(dsl: DSLInput, repo: Repository) -> list[str]:
    errors: list[str] = []
    for stmt in dsl.actions:
        bound = repo.store.get(stmt.action)
        if bound is None:
            errors.append(f"{stmt.ref}: unknown action {stmt.action}")
            continue
        expects = bound.get_interface()["expects"]
        properties = set(expects.get("properties", {}))
        required = set(expects.get("required", []))
        if unknown := set(stmt.args) - properties:
            errors.append(f"{stmt.ref}: unknown args {sorted(unknown)}")
        if missing := required - set(stmt.args):
            errors.append(f"{stmt.ref}: missing args {sorted(missing)}")
    return errors


def test_all_workflows_ship() -> None:
    titles = {_load(path).definition.title for path in WORKFLOW_FILES}
    assert titles == {
        "Lab: IOC enrichment",
        "Lab: Alert triage",
        "Lab: MISP lookup and sighting",
        "Lab: LLM tool-calling check",
    }


@pytest.mark.anyio
@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
async def test_workflow_validates(path: Path, repo: Repository) -> None:
    dsl = _load(path).definition
    errors: list[object] = [*validate_dsl_acyclic(dsl), *validate_dsl_entrypoint(dsl)]
    # Secrets and variables live in the importing workspace, not in the repo.
    errors += await validate_dsl_expressions(
        dsl, exclude={ExprType.SECRET, ExprType.VARIABLE}
    )
    errors += _arg_errors(dsl, repo)
    assert errors == []


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_model_calls_take_the_model_from_trigger_inputs(path: Path) -> None:
    dsl = _load(path).definition
    expects = dsl.entrypoint.expects or {}
    for stmt in dsl.actions:
        if not stmt.action.startswith("ai."):
            continue
        assert stmt.args["model"] == {
            "model_name": "${{ TRIGGER.model_name }}",
            "model_provider": "${{ TRIGGER.model_provider }}",
        }
        assert expects["model_provider"].default == "ollama"
        assert stmt.args["enable_thinking"] is False


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_lab_endpoints_skip_tls_verification(path: Path) -> None:
    """Lab services use self-signed certificates."""
    dsl = _load(path).definition
    for stmt in dsl.actions:
        namespace = stmt.action.rsplit(".", 1)[0]
        if namespace in {"tools.misp", "tools.opensearch", "tools.wazuh"}:
            assert stmt.args.get("verify_ssl") is False, stmt.ref


@pytest.mark.anyio
async def test_validators_catch_a_broken_workflow(repo: Repository) -> None:
    raw = yaml.safe_load((WORKFLOWS_DIR / "misp-lookup-sighting.yml").read_text())
    raw["definition"]["actions"][0]["args"]["unexpected"] = 1
    raw["definition"]["actions"][1]["args"]["inputs"]["search"] = (
        "${{ FN.no_such_function(1) }}"
    )
    dsl = ExternalWorkflowDefinition.model_validate(raw).definition
    assert _arg_errors(dsl, repo)
    assert await validate_dsl_expressions(
        dsl, exclude={ExprType.SECRET, ExprType.VARIABLE}
    )
