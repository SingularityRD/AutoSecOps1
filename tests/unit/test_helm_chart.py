"""Consistency checks for the AutoSecOps Helm chart in deployments/helm/autosecops.

The static checks need no Kubernetes tooling or live services, so CI runs this
module with ``--noconftest``. The rendering checks run only when the ``helm``
binary is on PATH.
"""

import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from autosecops import __version__

REPO_ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = REPO_ROOT / "deployments" / "helm" / "autosecops"
TEMPLATES_DIR = CHART_DIR / "templates"
CI_VALUES = sorted((CHART_DIR / "ci").glob("*-values.yaml"))
# Backend settings are read by Python code; the UI reads a few in its middleware.
SOURCE_GLOBS = (
    (REPO_ROOT / "autosecops", "*.py"),
    (REPO_ROOT / "packages" / "autosecops-ee", "*.py"),
    (REPO_ROOT / "packages" / "autosecops-registry", "*.py"),
    (REPO_ROOT / "frontend" / "src", "*.ts"),
)
ENV_NAME_PATTERN = re.compile(
    r"\b((?:AUTOSECOPS_MCP|AUTOSECOPS|TEMPORAL)__[A-Z0-9_]+)\b"
)


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def _application_source() -> str:
    return "\n".join(
        path.read_text()
        for source_dir, pattern in SOURCE_GLOBS
        for path in source_dir.rglob(pattern)
    )


def _chart_env_names() -> set[str]:
    names: set[str] = set()
    for template in TEMPLATES_DIR.iterdir():
        names.update(ENV_NAME_PATTERN.findall(template.read_text()))
    return names


def _value_paths(node: Any, prefix: tuple[str, ...] = ()) -> Iterator[tuple[str, ...]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield (*prefix, key)
            yield from _value_paths(value, (*prefix, key))


def _schema_allows(schema: dict[str, Any], path: tuple[str, ...]) -> bool:
    node = schema
    for key in path:
        properties = node.get("properties")
        if properties is None:
            # Free-form objects (resources, annotations, probes) accept any key.
            return node.get("type") in ("object", ["object", "null"])
        if key not in properties:
            return False
        node = properties[key]
    return True


def test_chart_app_version_matches_release() -> None:
    chart = _load_yaml(CHART_DIR / "Chart.yaml")
    assert chart["name"] == "autosecops"
    assert chart["appVersion"] == __version__


def test_chart_version_matches_release() -> None:
    # publish-helm-chart.yml publishes the chart under the release tag.
    chart = _load_yaml(CHART_DIR / "Chart.yaml")
    assert chart["version"] == __version__


def test_chart_env_vars_exist_in_application_config() -> None:
    source = _application_source()
    missing = sorted(name for name in _chart_env_names() if name not in source)
    assert not missing, f"Chart sets env vars the application never reads: {missing}"


def test_chart_has_no_upstream_names() -> None:
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in CHART_DIR.rglob("*")
        if path.is_file() and "tracecat" in path.read_text().lower()
    ]
    assert not offenders


def test_values_are_described_by_schema() -> None:
    schema = json.loads((CHART_DIR / "values.schema.json").read_text())
    values = _load_yaml(CHART_DIR / "values.yaml")
    undocumented = [
        ".".join(path)
        for path in _value_paths(values)
        if not _schema_allows(schema, path)
    ]
    assert not undocumented, f"values.yaml keys missing from the schema: {undocumented}"
    jsonschema.validate(values, schema)


@pytest.mark.parametrize("values_file", CI_VALUES, ids=lambda path: path.name)
def test_ci_values_match_schema(values_file: Path) -> None:
    schema = json.loads((CHART_DIR / "values.schema.json").read_text())
    jsonschema.validate(_load_yaml(values_file), schema)


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
@pytest.mark.parametrize("values_file", CI_VALUES, ids=lambda path: path.name)
def test_rendered_env_values_are_strings(values_file: Path) -> None:
    rendered = subprocess.run(
        ["helm", "template", "autosecops", str(CHART_DIR), "-f", str(values_file)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    documents = [doc for doc in yaml.safe_load_all(rendered) if doc]
    for doc in documents:
        if doc["kind"] == "ConfigMap":
            for key, value in doc["data"].items():
                assert isinstance(value, str), f"ConfigMap {key} is not a string"
        pod_spec = (
            doc.get("spec", {}).get("template", {}).get("spec")
            if doc["kind"] in ("Deployment", "Job")
            else None
        )
        if pod_spec is None:
            continue
        for container in pod_spec["containers"]:
            for env in container.get("env", []):
                if "value" in env:
                    assert isinstance(env["value"], str), (
                        f"{doc['metadata']['name']}: {env['name']} is not a string"
                    )


def _helm_template(*args: str, chart_dir: Path = CHART_DIR) -> str:
    return subprocess.run(
        ["helm", "template", *args, str(chart_dir)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
@pytest.mark.parametrize("length", [44, 45, 50, 53])
def test_long_release_names_keep_resource_names_unique(length: int) -> None:
    # Helm allows release names of up to 53 characters.
    release = "r" * length
    rendered = _helm_template(release, "-f", str(CHART_DIR / "ci/minimal-values.yaml"))
    documents = [doc for doc in yaml.safe_load_all(rendered) if doc]
    names = [(doc["kind"], doc["metadata"]["name"]) for doc in documents]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    assert not duplicates, f"Resource names collide: {duplicates}"
    for doc in documents:
        if doc["kind"] not in ("Deployment", "Service", "Job"):
            continue
        name = doc["metadata"]["name"]
        assert len(name) <= 63, f"{doc['kind']} {name} is longer than 63 characters"
        component = doc["metadata"]["labels"].get("app.kubernetes.io/component")
        if doc["kind"] != "Job" and component:
            assert name.endswith(f"-{component}")


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
@pytest.mark.parametrize("use_hooks", [True, False])
def test_notes_name_the_rendered_migrations_job(
    tmp_path: Path, use_hooks: bool
) -> None:
    # `helm template` skips NOTES.txt, so render it through a ConfigMap.
    chart = tmp_path / "autosecops"
    shutil.copytree(CHART_DIR, chart)
    shutil.copy(chart / "templates/NOTES.txt", chart / "notes-source.txt")
    (chart / "templates/notes-copy.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes\ndata:\n"
        '  notes: {{ tpl (.Files.Get "notes-source.txt") . | quote }}\n'
    )
    args = [
        "autosecops",
        "-f",
        str(chart / "ci/minimal-values.yaml"),
        "--set",
        f"migrations.useHelmHooks={str(use_hooks).lower()}",
    ]
    notes = yaml.safe_load(
        _helm_template(*args, "-s", "templates/notes-copy.yaml", chart_dir=chart)
    )["data"]["notes"]
    job = yaml.safe_load(
        _helm_template(*args, "-s", "templates/migrations-job.yaml", chart_dir=chart)
    )
    assert f"logs job/{job['metadata']['name']}\n" in notes


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_tunnels_namespace_must_differ_from_release_namespace() -> None:
    result = subprocess.run(
        [
            "helm",
            "template",
            "autosecops",
            str(CHART_DIR),
            "-n",
            "autosecops-tunnels",
            "-f",
            str(CHART_DIR / "ci/full-values.yaml"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "tunnels.namespace must differ from the release namespace" in result.stderr


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_tunnel_gateway_pull_secrets_reach_the_api() -> None:
    rendered = _helm_template(
        "autosecops", "-f", str(CHART_DIR / "ci/full-values.yaml")
    )
    api = next(
        doc
        for doc in yaml.safe_load_all(rendered)
        if doc
        and doc["kind"] == "Deployment"
        and doc["metadata"]["name"] == "autosecops-api"
    )
    env = {
        item["name"]: item.get("value")
        for item in api["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["AUTOSECOPS__TUNNEL_GATEWAY_IMAGE_PULL_SECRETS"] == "ghcr-pull"


def test_rls_is_enforced_by_default() -> None:
    values = _load_yaml(CHART_DIR / "values.yaml")
    assert values["autosecops"]["rlsMode"] == "enforce"
    assert values["externalPostgres"]["auth"]["runtimeUsername"] == "autosecops_app"


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
@pytest.mark.parametrize("values_file", CI_VALUES, ids=lambda path: path.name)
def test_backend_pods_and_migrations_receive_the_runtime_role(
    values_file: Path,
) -> None:
    """Every pod that reaches PostgreSQL gets the runtime role credentials."""
    rendered = _helm_template("autosecops", "-f", str(values_file))
    documents = [doc for doc in yaml.safe_load_all(rendered) if doc]
    configmap = next(
        doc
        for doc in documents
        if doc["kind"] == "ConfigMap" and doc["metadata"]["name"] == "autosecops-env"
    )
    assert configmap["data"]["AUTOSECOPS__RLS_MODE"] == "enforce"
    assert configmap["data"]["AUTOSECOPS__DB_RUNTIME_USER"] == "autosecops_app"

    checked = 0
    for doc in documents:
        if doc["kind"] not in ("Deployment", "Job"):
            continue
        for container in doc["spec"]["template"]["spec"]["containers"]:
            env = {item["name"]: item for item in container.get("env", [])}
            if "AUTOSECOPS__DB_PASS" not in env:
                continue
            checked += 1
            ref = env["AUTOSECOPS__DB_RUNTIME_PASSWORD"]["valueFrom"]["secretKeyRef"]
            assert ref["key"] == "runtime-password"
            # Optional: a Secret without the key keeps the owner connection.
            assert ref["optional"] is True
            if doc["kind"] == "Job":
                assert env["AUTOSECOPS__DB_RUNTIME_USER"]["value"] == "autosecops_app"
    assert checked >= 7


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_chart_managed_postgres_secret_holds_the_runtime_password() -> None:
    rendered = _helm_template(
        "autosecops",
        "-f",
        str(CHART_DIR / "ci/minimal-values.yaml"),
        "-s",
        "templates/secrets.yaml",
    )
    secret = next(
        doc
        for doc in yaml.safe_load_all(rendered)
        if doc and doc["metadata"]["name"] == "autosecops-postgres-credentials"
    )
    assert secret["stringData"]["runtime-password"] == "placeholder-runtime-password"


WORKER_COMPONENTS = (
    "worker",
    "background-worker",
    "executor",
    "agent-worker",
    "agent-executor",
)


def _rendered_documents(*args: str) -> list[dict[str, Any]]:
    rendered = _helm_template("autosecops", *args)
    return [doc for doc in yaml.safe_load_all(rendered) if doc]


def _deployment(documents: list[dict[str, Any]], component: str) -> dict[str, Any]:
    return next(
        doc
        for doc in documents
        if doc["kind"] == "Deployment"
        and doc["metadata"]["labels"]["app.kubernetes.io/component"] == component
    )


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
@pytest.mark.parametrize("values_file", CI_VALUES, ids=lambda path: path.name)
def test_temporal_workers_have_exec_health_probes(values_file: Path) -> None:
    documents = _rendered_documents("-f", str(values_file))
    probe = ["python", "-m", "autosecops.temporal.healthcheck"]
    for component in WORKER_COMPONENTS:
        container = _deployment(documents, component)["spec"]["template"]["spec"][
            "containers"
        ][0]
        assert container["startupProbe"]["exec"]["command"] == [*probe, "live"]
        assert container["livenessProbe"]["exec"]["command"] == [*probe, "live"]
        assert container["readinessProbe"]["exec"]["command"] == [*probe, "ready"]


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_operator_worker_probe_replaces_the_default() -> None:
    """A component probe replaces the default; merging would render two handlers."""
    documents = _rendered_documents(
        "-f",
        str(CHART_DIR / "ci/full-values.yaml"),
        "--set",
        "worker.readinessProbe.tcpSocket.port=9090",
        "--set",
        "worker.readinessProbe.periodSeconds=5",
        "--set",
        "workerProbes.livenessProbe=null",
    )
    container = _deployment(documents, "worker")["spec"]["template"]["spec"][
        "containers"
    ][0]
    assert container["readinessProbe"] == {
        "tcpSocket": {"port": 9090},
        "periodSeconds": 5,
    }
    assert "exec" in container["startupProbe"]
    for component in WORKER_COMPONENTS:
        worker = _deployment(documents, component)["spec"]["template"]["spec"][
            "containers"
        ][0]
        assert "livenessProbe" not in worker
    other = _deployment(documents, "executor")["spec"]["template"]["spec"][
        "containers"
    ][0]
    assert other["readinessProbe"]["exec"]["command"][-1] == "ready"
    assert "tcpSocket" not in other["readinessProbe"]


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_worker_health_dir_is_writable_with_read_only_root_filesystem() -> None:
    documents = _rendered_documents(
        "-f",
        str(CHART_DIR / "ci/full-values.yaml"),
        "--set",
        "containerSecurityContext.readOnlyRootFilesystem=true",
    )
    for component in WORKER_COMPONENTS:
        pod = _deployment(documents, component)["spec"]["template"]["spec"]
        mounts = {
            mount["name"]: mount for mount in pod["containers"][0]["volumeMounts"]
        }
        assert mounts["worker-health"]["mountPath"] == "/var/run/autosecops"
        assert not mounts["worker-health"].get("readOnly", False)
        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        assert volumes["worker-health"]["emptyDir"]["medium"] == "Memory"
    api = _deployment(documents, "api")["spec"]["template"]["spec"]
    assert "worker-health" not in {volume["name"] for volume in api.get("volumes", [])}


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_metrics_are_off_by_default() -> None:
    documents = _rendered_documents("-f", str(CHART_DIR / "ci/minimal-values.yaml"))
    for doc in documents:
        assert doc["kind"] not in ("PodMonitor", "ServiceMonitor")
        if doc["kind"] != "Deployment":
            continue
        pod = doc["spec"]["template"]
        assert "prometheus.io/scrape" not in pod["metadata"].get("annotations", {})
        for container in pod["spec"]["containers"]:
            ports = {port["name"] for port in container.get("ports", [])}
            env = {item["name"] for item in container.get("env", [])}
            assert "metrics" not in ports
            assert not env & {
                "AUTOSECOPS__API_METRICS_ENABLED",
                "TEMPORAL__METRICS_PORT",
            }


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_api_metrics_port_is_never_exposed_by_service_or_ingress() -> None:
    documents = _rendered_documents(
        "-f",
        str(CHART_DIR / "ci/full-values.yaml"),
        "--set",
        "metrics.podMonitor.enabled=true",
        "--set",
        "metrics.serviceMonitor.enabled=true",
    )
    api = _deployment(documents, "api")
    container = api["spec"]["template"]["spec"]["containers"][0]
    assert {"name": "metrics", "containerPort": 9100, "protocol": "TCP"} in container[
        "ports"
    ]
    env = {item["name"]: item.get("value") for item in container["env"]}
    assert env["AUTOSECOPS__API_METRICS_ENABLED"] == "true"
    assert env["AUTOSECOPS__API_METRICS_PORT"] == "9100"

    api_service = next(
        doc
        for doc in documents
        if doc["kind"] == "Service" and doc["metadata"]["name"] == "autosecops-api"
    )
    assert [port["targetPort"] for port in api_service["spec"]["ports"]] == ["http"]
    for ingress in (doc for doc in documents if doc["kind"] == "Ingress"):
        for rule in ingress["spec"]["rules"]:
            for path in rule["http"]["paths"]:
                assert not path["backend"]["service"]["name"].endswith("-metrics")
                assert path["backend"]["service"]["port"] == {"name": "http"}

    metrics_services = {
        doc["metadata"]["name"]: doc
        for doc in documents
        if doc["kind"] == "Service" and doc["metadata"]["name"].endswith("-metrics")
    }
    assert set(metrics_services) == {
        f"autosecops-{component}-metrics" for component in ("api", *WORKER_COMPONENTS)
    }
    for service in metrics_services.values():
        assert service["spec"]["clusterIP"] == "None"
        assert service["spec"]["ports"][0]["targetPort"] == "metrics"

    pod_monitor = next(doc for doc in documents if doc["kind"] == "PodMonitor")
    selected = pod_monitor["spec"]["selector"]["matchExpressions"][0]["values"]
    assert selected == ["api", *WORKER_COMPONENTS]
    assert any(doc["kind"] == "ServiceMonitor" for doc in documents)


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_monitors_require_a_metrics_source() -> None:
    result = subprocess.run(
        [
            "helm",
            "template",
            "autosecops",
            str(CHART_DIR),
            "-f",
            str(CHART_DIR / "ci/minimal-values.yaml"),
            "--set",
            "metrics.podMonitor.enabled=true",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "metrics.podMonitor/serviceMonitor need" in result.stderr
