"""scripts/support_bundle.sh collects diagnostics without leaking secrets.

The script runs against a fake `docker` that answers the Compose commands it
issues, so these tests need neither Docker nor a running deployment.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "support_bundle.sh"

SECRET_LOG_LINES = [
    "connecting to postgresql+psycopg://autosecops:hunter2-db-pass@postgres_db:5432/postgres",
    "AUTOSECOPS__DB_ENCRYPTION_KEY=fernet-secret-value-123",
    '{"password": "pw-in-json-456", "user": "alice"}',
    "Authorization: Bearer abcdefghijklmnop.qrstuvwx",
    "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl",
    "aws key AKIAABCDEFGHIJKLMNOP leaked",
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC-private-body",
    "-----END PRIVATE KEY-----",
    "api_key: sk-live-abcdefghijklmnop",
    "workflow run completed status=success",
]
SECRET_VALUES = [
    "hunter2-db-pass",
    "fernet-secret-value-123",
    "pw-in-json-456",
    "abcdefghijklmnop.qrstuvwx",
    "eyJhbGciOiJIUzI1NiJ9",
    "AKIAABCDEFGHIJKLMNOP",
    "private-body",
    "sk-live-abcdefghijklmnop",
    "license-token-value",
    "smtp-pass-value",
]

FAKE_DOCKER = r"""#!/bin/bash
args="$*"
case "$args" in
  "compose version") echo "Docker Compose version v2.29.0" ;;
  "compose version --short") echo "2.29.0" ;;
  "version --format "*) echo "27.3.1" ;;
  "compose ps -aq") echo "cid-api" ;;
  "compose ps -a --services") printf 'api\npostgres_db\n' ;;
  "compose ps -a") echo "NAME STATUS"; echo "autosecops-api-1 running (healthy)" ;;
  "inspect --format {{.Image}} cid-api") echo "sha256:1111" ;;
  "inspect --format "*) echo "/autosecops-api-1 ghcr.io/singularityrd/autosecops:1.0.0 sha256:1111" ;;
  "image inspect "*) echo "  repo_digests=ghcr.io/singularityrd/autosecops@sha256:2222" ;;
  "compose exec -T api python -")
    cat >/dev/null
    echo "WARNING service log line password=from-stderr-789" >&2
    printf '{"autosecops_version": "1.0.0", "alembic_revisions": ["abc123"],'
    printf ' "license": {"status": "valid", "entitlements": ["rbac"]}}\n'
    ;;
  "compose logs "*" api") cat "$FAKE_LOG_FILE" ;;
  "compose logs "*" postgres_db") exit 3 ;;
  *) echo "unexpected docker call: $args" >&2; exit 64 ;;
esac
"""


@pytest.fixture
def bundle(tmp_path: Path) -> tuple[Path, subprocess.CompletedProcess[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    log_file = tmp_path / "api.log"
    log_file.write_text("\n".join(SECRET_LOG_LINES) + "\n")
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "docker-compose.yml").write_text("services: {}\n")
    (deploy / ".env").write_text(
        "AUTOSECOPS__IMAGE_TAG=1.0.0\n"
        "AUTOSECOPS__EXECUTOR_BACKEND=nsjail\n"
        "AUTOSECOPS__LICENSE_KEY=license-token-value\n"
        "SMTP_PASSWORD=smtp-pass-value\n"
        "AUTOSECOPS__DB_RUNTIME_PASSWORD=\n"
        "# a comment\n"
    )
    out = tmp_path / "out"
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "FAKE_LOG_FILE": str(log_file),
    }
    result = subprocess.run(
        ["bash", str(SCRIPT), "-o", str(out), "--since", "2h", "--tail", "100"],
        cwd=deploy,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return out, result


def _members(out: Path) -> dict[str, str]:
    (archive,) = out.glob("autosecops-support-*.tar.gz")
    assert archive.stat().st_mode & 0o077 == 0, "archive must be private"
    with tarfile.open(archive) as tar:
        return {
            member.name.split("/", 1)[1]: tar.extractfile(member).read().decode()  # type: ignore[union-attr]
            for member in tar.getmembers()
            if member.isfile()
        }


def test_bundle_collects_every_section(
    bundle: tuple[Path, subprocess.CompletedProcess[str]],
) -> None:
    out, result = bundle
    assert result.returncode == 0, result.stderr
    files = _members(out)
    assert {
        "summary.txt",
        "settings.txt",
        "services.txt",
        "images.txt",
        "probe.json",
        "logs/api.log",
        "logs/postgres_db.log",
    } <= set(files)
    assert "docker_compose=2.29.0" in files["summary.txt"]
    assert "log_since=2h" in files["summary.txt"]
    assert "sha256:2222" in files["images.txt"]
    probe = json.loads(files["probe.json"])
    assert probe["alembic_revisions"] == ["abc123"]
    assert probe["license"]["status"] == "valid"
    # A failing collector is recorded, not fatal.
    assert "[collection failed: exit 3]" in files["logs/postgres_db.log"]
    assert "workflow run completed status=success" in files["logs/api.log"]


def test_bundle_never_contains_secret_values(
    bundle: tuple[Path, subprocess.CompletedProcess[str]],
) -> None:
    out, result = bundle
    assert result.returncode == 0, result.stderr
    files = _members(out)
    blob = "\n".join(files.values())
    for secret in SECRET_VALUES:
        assert secret not in blob, secret
    assert "from-stderr-789" not in blob
    settings = files["settings.txt"].splitlines()
    assert "AUTOSECOPS__IMAGE_TAG=1.0.0" in settings
    assert "AUTOSECOPS__EXECUTOR_BACKEND=nsjail" in settings
    assert "AUTOSECOPS__LICENSE_KEY=<set>" in settings
    assert "SMTP_PASSWORD=<set>" in settings
    assert "AUTOSECOPS__DB_RUNTIME_PASSWORD=<empty>" in settings
    # The redactor keeps the user name in a URL and the shape of the line.
    assert re.search(r"autosecops:\[REDACTED\]@postgres_db", files["logs/api.log"])


def test_probe_reads_no_key_material() -> None:
    text = SCRIPT.read_text()
    probe = text[text.index("<<'PY'") : text.index("\nPY\n")]
    assert "LICENSE_KEY" not in probe
    assert "customer" not in probe
    assert "get_license_state(log=False)" in probe


@pytest.mark.parametrize("args", [["--since", "1d"], ["--tail", "0"], ["--bogus"]])
def test_bundle_rejects_bad_options(tmp_path: Path, args: list[str]) -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode != 0


def test_image_ships_the_support_bundle_script() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    block = dockerfile[: dockerfile.index("/opt/autosecops/install/")]
    assert "./scripts/support_bundle.sh" in block.rsplit("COPY", 1)[1]


def test_redact_mode_filters_stdin() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--redact"],
        input="\n".join(SECRET_LOG_LINES) + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    for secret in SECRET_VALUES[:8]:
        assert secret not in result.stdout, secret
    assert "workflow run completed status=success" in result.stdout


def _redact(text: str) -> str:
    return subprocess.run(
        ["bash", str(SCRIPT), "--redact"],
        input=text + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout


# Lines AutoSecOps, uvicorn, PostgreSQL, or integrations write to logs, each
# with the synthetic secret it carries and what the redacted line keeps.
@pytest.mark.parametrize(
    ("line", "secret", "kept"),
    [
        (
            'INFO: 10.0.0.5:5123 - "POST /webhooks/wf_abc123/whsecretvalue1 HTTP/1.1" 200',
            "whsecretvalue1",
            "/webhooks/wf_abc123/[REDACTED] HTTP/1.1",
        ),
        (
            '"POST /api/webhooks/wf_abc123/whsecretvalue2/wait?x=1 HTTP/1.1"',
            "whsecretvalue2",
            "/api/webhooks/wf_abc123/[REDACTED]/wait",
        ),
        (
            "STATEMENT:  CREATE ROLE autosecops_app LOGIN PASSWORD 'pg-role-pass-1'",
            "pg-role-pass-1",
            "LOGIN PASSWORD '[REDACTED]'",
        ),
        (
            "STATEMENT:  ALTER ROLE autosecops_app WITH LOGIN PASSWORD 'it''s-pass-2'",
            "s-pass-2",
            "PASSWORD '[REDACTED]'",
        ),
        (
            r"{\"password\": \"escaped-json-pass\", \"user\": \"bob\"}",
            "escaped-json-pass",
            r"\"user\": \"bob\"",
        ),
        (
            '"password": "correct horse battery staple", "user": "alice"',
            "horse battery staple",
            '"user": "alice"',
        ),
        (
            "{'api_key': 'repr value with spaces'}",
            "value with spaces",
            "{'api_key': '[REDACTED]'}",
        ),
        (
            '"token": "quote\\"inside-token"',
            "inside-token",
            '"token": "[REDACTED]"',
        ),
        (
            "posting to https://hooks.slack.com/services/T0000/B0000/slackcapsecret",
            "slackcapsecret",
            "https://hooks.slack.com/services/[REDACTED]",
        ),
        (
            "https://example.webhook.office.com/webhookb2/teamscapsecret",
            "teamscapsecret",
            "webhook.office.com/[REDACTED]",
        ),
        (
            "https://bucket.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4"
            "&X-Amz-Signature=deadbeefsig0&X-Amz-Date=20260101",
            "deadbeefsig0",
            "X-Amz-Signature=[REDACTED]&X-Amz-Date=20260101",
        ),
        (
            "charge failed with key sk_live_abcdefghijklmnop0123",
            "abcdefghijklmnop0123",
            "[REDACTED_TOKEN]",
        ),
    ],
)
def test_redactor_covers_known_secret_shapes(line: str, secret: str, kept: str) -> None:
    redacted = _redact(line)
    assert secret not in redacted
    assert kept in redacted


FAKE_KUBECTL = r"""#!/bin/bash
args="$*"
case "$args" in
  "get deployments -n autosecops -l app.kubernetes.io/instance=prod,app.kubernetes.io/component=api -o "*)
    printf '%s' "$FAKE_API_DEPLOYMENT" ;;
  "exec -i -n autosecops deploy/prod-autosecops-api -c api -- python -")
    cat >/dev/null
    echo '{"autosecops_version": "1.0.0"}' ;;
  "exec "*) echo "Error from server (NotFound): $args" >&2; exit 1 ;;
  "get pods -n autosecops -l app.kubernetes.io/instance=prod -o name") echo "pod/prod-autosecops-api-1" ;;
  *) echo "ok" ;;
esac
"""


@pytest.mark.parametrize("deployment", ["prod-autosecops-api", ""])
def test_kubernetes_finds_the_api_deployment_by_label(
    tmp_path: Path, deployment: str
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kubectl = bin_dir / "kubectl"
    kubectl.write_text(FAKE_KUBECTL)
    kubectl.chmod(0o755)
    out = tmp_path / "out"
    result = subprocess.run(
        ["bash", str(SCRIPT), "--kubernetes", "--release", "prod", "-o", str(out)],
        cwd=tmp_path,
        env={
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(tmp_path),
            "TMPDIR": str(tmp_path),
            "FAKE_API_DEPLOYMENT": deployment,
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    probe = json.loads(_members(out)["probe.json"])
    if deployment:
        # The chart's fullname is <release>-autosecops, not <release>.
        assert probe == {"autosecops_version": "1.0.0"}
    else:
        assert "rerun with --api-deployment" in probe["probe_error"]


@pytest.mark.parametrize(
    "page",
    ["updating.mdx", "docker-compose.mdx", "air-gapped.mdx"],
)
def test_upgrade_steps_copy_the_support_bundle_script(page: str) -> None:
    """Every documented Compose upgrade path refreshes support_bundle.sh."""
    text = (ROOT / "docs" / "self-hosting" / page).read_text()
    copy_lines = [
        line
        for line in text.splitlines()
        if "restore_compose.sh" in line and ("cp " in line or "Replace" in line)
    ]
    assert copy_lines, page
    for line in copy_lines:
        assert "support_bundle.sh" in line, line
