"""The offline bundle must carry every image the Compose stack and Helm chart run.

The bundler (scripts/offline_bundle.py) derives its image list from
docker-compose.yml and the chart values. These checks resolve the same files
independently, so a new service or image cannot silently miss the bundle, and
run the bundler and its customer-side helper in dry-run mode, which never
calls Docker.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from autosecops import __version__
from autosecops.config import AUTOSECOPS__TUNNEL_GATEWAY_IMAGE

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "docker-compose.yml"
CHART_VALUES = ROOT / "deployments" / "helm" / "autosecops" / "values.yaml"
BUNDLER = ROOT / "scripts" / "offline_bundle.py"
COMPOSE_DEFAULT = re.compile(r"\$\{([A-Za-z0-9_]+):-([^}]*)\}")


def _load_bundler() -> ModuleType:
    spec = importlib.util.spec_from_file_location("offline_bundle", BUNDLER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the defining module up in sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bundler = _load_bundler()


def _compose_services() -> dict[str, dict[str, Any]]:
    return yaml.safe_load(COMPOSE_FILE.read_text())["services"]


def _compose_image_defaults() -> set[str]:
    """Each Compose image with its variables at their defaults."""
    images: set[str] = set()
    for service in _compose_services().values():
        raw = service["image"]
        resolved = COMPOSE_DEFAULT.sub(
            lambda m: (
                __version__ if m.group(1) == "AUTOSECOPS__IMAGE_TAG" else m.group(2)
            ),
            raw,
        )
        assert "$" not in resolved, f"{raw} has a variable without a default"
        images.add(resolved)
    return images


def _helm_repositories(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every non-empty `repository` in the chart values (empty ones inherit)."""
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else key
            if key == "repository" and isinstance(value, str) and value:
                yield child, value
            else:
                yield from _helm_repositories(value, child)


def _bundle_refs() -> set[str]:
    return {str(image.source) for image in bundler.bundle_images(__version__)}


def test_every_compose_image_is_bundled() -> None:
    missing = _compose_image_defaults() - _bundle_refs()
    assert not missing, f"Compose images missing from the offline bundle: {missing}"


def test_every_helm_image_is_bundled() -> None:
    refs = _bundle_refs()
    repositories = dict(_helm_repositories(yaml.safe_load(CHART_VALUES.read_text())))
    assert repositories, "found no image repositories in the chart values"
    for path, repository in repositories.items():
        assert f"{repository}:{__version__}" in refs, f"{path}: {repository}"


def test_tunnel_gateway_default_image_is_bundled() -> None:
    assert AUTOSECOPS__TUNNEL_GATEWAY_IMAGE in _bundle_refs()


def test_bundle_has_no_extra_images() -> None:
    expected = _compose_image_defaults() | {
        f"{repository}:{__version__}"
        for _, repository in _helm_repositories(
            yaml.safe_load(CHART_VALUES.read_text())
        )
    }
    assert _bundle_refs() == expected


@pytest.mark.parametrize("service", sorted(_compose_services()))
def test_compose_images_can_point_at_an_internal_registry(service: str) -> None:
    """The customer-side helper retargets images through these variables."""
    raw = _compose_services()[service]["image"]
    assert re.fullmatch(r"\$\{[A-Z0-9_]+:-[^}]+\}(:\$\{[A-Z0-9_]+:-[^}]+\})?", raw), (
        f"{service}: image {raw} is not selectable through a ${{VAR:-default}}"
    )


def test_bundle_images_records_compose_and_helm_settings() -> None:
    by_name = {image.source.name: image for image in bundler.bundle_images(__version__)}
    api = by_name["ghcr.io/singularityrd/autosecops"]
    assert (api.compose_var, api.compose_kind, api.helm_value) == (
        "AUTOSECOPS__IMAGE_REPOSITORY",
        "repository",
        "image.repository",
    )
    minio = by_name["cgr.dev/chainguard/minio"]
    assert (minio.compose_var, minio.compose_kind) == (
        "AUTOSECOPS__MINIO_IMAGE",
        "full",
    )
    assert minio.source.digest is not None
    assert minio.bundle_ref.startswith("cgr.dev/chainguard/minio:latest-")
    gateway = by_name["ghcr.io/singularityrd/autosecops-tunnel-gateway"]
    assert gateway.compose_var is None
    assert gateway.helm_value == "tunnels.gateway.image.repository"


def test_bundle_images_follow_compose_overrides() -> None:
    refs = {
        str(image.source)
        for image in bundler.bundle_images(
            __version__,
            env={
                "AUTOSECOPS__REDIS_IMAGE": "mirror.example.internal/valkey/valkey:8.1"
            },
        )
    }
    assert "mirror.example.internal/valkey/valkey:8.1" in refs
    assert not any(ref.startswith("valkey/valkey:") for ref in refs)


def test_bundle_ships_valkey_under_the_redis_settings() -> None:
    """The `redis` service runs Valkey (BSD-3-Clause), pinned by digest."""
    by_name = {image.source.name: image for image in bundler.bundle_images(__version__)}
    valkey = by_name["valkey/valkey"]
    assert (valkey.compose_var, valkey.compose_kind) == (
        "AUTOSECOPS__REDIS_IMAGE",
        "full",
    )
    assert valkey.source.tag is not None and valkey.source.digest is not None
    license_entry = bundler.upstream_license(valkey.source)
    assert license_entry is not None
    assert license_entry.license == "BSD-3-Clause"


@pytest.mark.parametrize(
    "image", ["redis:7-alpine", "mirror.example.internal/redis:7.4"]
)
def test_bundler_refuses_redis_images(image: str) -> None:
    """Redis 7.4 and later are RSALv2/SSPLv1; the bundle must not carry them."""
    with pytest.raises(bundler.BundleError, match="No license entry"):
        bundler.bundle_images(__version__, env={"AUTOSECOPS__REDIS_IMAGE": image})


def test_third_party_images_need_a_license_entry(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  extra:\n    image: example.org/unknown:1\n")
    with pytest.raises(bundler.BundleError, match="No license entry"):
        bundler.bundle_images(__version__, compose_file=compose)


@pytest.mark.parametrize(
    "ref,name,tag,digest,path",
    [
        ("redis:7-alpine", "redis", "7-alpine", None, "redis"),
        ("temporalio/ui:2.43.3", "temporalio/ui", "2.43.3", None, "temporalio/ui"),
        (
            "localhost:5000/team/app",
            "localhost:5000/team/app",
            None,
            None,
            "team/app",
        ),
        (
            "cgr.dev/chainguard/minio:latest@sha256:" + "a" * 64,
            "cgr.dev/chainguard/minio",
            "latest",
            "sha256:" + "a" * 64,
            "chainguard/minio",
        ),
    ],
)
def test_image_ref_parse(
    ref: str, name: str, tag: str | None, digest: str | None, path: str
) -> None:
    parsed = bundler.ImageRef.parse(ref)
    assert (parsed.name, parsed.tag, parsed.digest, parsed.path) == (
        name,
        tag,
        digest,
        path,
    )
    assert str(parsed) == ref


@pytest.fixture
def staged_bundle(tmp_path: Path) -> Path:
    """Run the bundler in dry-run mode with a `docker` that fails if called."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "docker-called"
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(f"#!/bin/sh\ntouch {marker}\nexit 99\n")
    fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IEXEC)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AUTOSECOPS__", "TEMPORAL__", "OFFLINE_BUNDLE_"))
    }
    env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
    output = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            str(BUNDLER),
            "--version",
            __version__,
            "--dry-run",
            "--keep-staging",
            "--output-dir",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists(), "dry run called docker"
    assert not list(output.glob("*.tar.*")), "dry run wrote an archive"
    (staging,) = output.glob(f"*/autosecops-offline-{__version__}")
    return staging


def test_dry_run_stages_the_bundle(staged_bundle: Path) -> None:
    for name in bundler.INSTALL_FILES:
        assert (staged_bundle / "install" / name).is_file(), name
        if name.endswith(".sh"):
            assert os.access(staged_bundle / "install" / name, os.X_OK), name
    assert (staged_bundle / "charts" / f"autosecops-{__version__}.tgz").is_file()
    assert os.access(staged_bundle / "load-images.sh", os.X_OK)
    for name in ("README.md", "images.txt", "SHA256SUMS"):
        assert (staged_bundle / name).is_file(), name
    for name in ("autosecops.md", "autosecops-ui.md", "IMAGES.md"):
        assert (staged_bundle / "THIRD_PARTY_NOTICES" / name).is_file(), name

    rows = [
        line.split("\t")
        for line in (staged_bundle / "images.txt").read_text().splitlines()
        if not line.startswith("#")
    ]
    assert {f"{row[0]}:{row[1]}" for row in rows} == {
        f"{image.source.name}:{image.source.tag}"
        for image in bundler.bundle_images(__version__)
    }
    assert all(len(row) == 8 and "" not in row for row in rows)

    for line in (staged_bundle / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((staged_bundle / name).read_bytes()).hexdigest() == digest


def test_image_ships_every_bundle_install_file() -> None:
    """The image's /opt/autosecops/install and the bundle's install/ match."""
    dockerfile = (ROOT / "Dockerfile").read_text()
    copies = re.findall(
        r"^COPY [^\n]*(?:\\\n[^\n]*)*/opt/autosecops/install/$", dockerfile, re.M
    )
    shipped = {
        Path(token).name
        for block in copies
        for token in block.replace("\\\n", " ").split()
        if token.startswith("./")
    }
    assert shipped == set(bundler.INSTALL_FILES)


def test_load_helper_verifies_and_plans_a_push(staged_bundle: Path) -> None:
    helper = staged_bundle / "load-images.sh"
    verify = subprocess.run(
        [str(helper), "verify"], capture_output=True, text=True, check=False
    )
    assert verify.returncode == 0, verify.stderr

    push = subprocess.run(
        [str(helper), "push", "registry.example.internal/autosecops", "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert push.returncode == 0, push.stderr
    overrides = dict(
        line.split("=", 1)
        for line in push.stdout.splitlines()
        if re.match(r"^[A-Z0-9_]+=", line)
    )
    compose_vars = {
        match.group(1)
        for service in _compose_services().values()
        if (match := re.match(r"\$\{([A-Z0-9_]+):-", service["image"]))
    }
    assert set(overrides) == compose_vars
    assert all(
        value.startswith("registry.example.internal/autosecops/")
        for value in overrides.values()
    )
    assert (
        overrides["AUTOSECOPS__IMAGE_REPOSITORY"]
        == "registry.example.internal/autosecops/singularityrd/autosecops"
    )
    assert (
        "repository: registry.example.internal/autosecops/singularityrd/autosecops-ui"
        in (push.stdout)
    )


def test_load_helper_rejects_a_tampered_bundle(staged_bundle: Path) -> None:
    (staged_bundle / "install" / "docker-compose.yml").write_text("tampered\n")
    verify = subprocess.run(
        [str(staged_bundle / "load-images.sh"), "verify"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify.returncode != 0


BUNDLE_WORKFLOW = ROOT / ".github" / "workflows" / "build-offline-bundle.yml"


@pytest.mark.parametrize(
    ("ref_type", "ref", "tag", "accepted"),
    [
        ("tag", "1.2.3", "1.2.3", True),
        ("tag", "1.3.0-rc.1", "1.3.0-rc.1", True),
        ("tag", "1.2.3", "1.2.4", False),
        ("branch", "main", "main", False),
        ("tag", "v1.2.3", "v1.2.3", False),
        ("tag", "1.2.3;id", "1.2.3;id", False),
    ],
)
def test_bundle_workflow_only_builds_the_dispatched_release_tag(
    tmp_path: Path, ref_type: str, ref: str, tag: str, accepted: bool
) -> None:
    workflow = yaml.safe_load(BUNDLE_WORKFLOW.read_text())
    job = workflow["jobs"]["bundle"]
    assert "TRUSTED_CI_ACTORS_JSON" in job["if"]
    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"] == {
        "contents": "read",
        "packages": "read",
        "id-token": "write",
    }
    script = job["steps"][0]["run"]
    output = tmp_path / "output"
    output.write_text("")
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        env={
            **os.environ,
            "REF_TYPE": ref_type,
            "REF_NAME": ref,
            "INPUT_TAG": tag,
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted, result.stdout
    assert (output.read_text() == f"version={tag}\n") is accepted


def _bundle_step(name: str) -> dict[str, Any]:
    workflow = yaml.safe_load(BUNDLE_WORKFLOW.read_text())
    return next(s for s in workflow["jobs"]["bundle"]["steps"] if s["name"] == name)


def test_bundle_workflow_never_uploads_images_as_an_artifact() -> None:
    workflow = yaml.safe_load(BUNDLE_WORKFLOW.read_text())
    job = workflow["jobs"]["bundle"]
    # Secrets and the OIDC role are scoped to a protected environment.
    assert job["environment"] == "offline-bundle"
    uploads = [
        step
        for step in job["steps"]
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    paths = uploads[0]["with"]["path"].splitlines()
    assert paths, "no artifact paths"
    for path in paths:
        assert path.endswith((".sha256", ".sig", ".SHA256SUMS", ".cosign.pub")), path
    build = _bundle_step("Build and sign bundle")
    assert "--require-signature" in build["run"]
    for step in job["steps"]:
        if uses := step.get("uses"):
            action, _, ref = uses.partition("@")
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), action
        # Signing material and secrets are never echoed or uploaded.
        assert "set -x" not in step.get("run", "")


VALID_BUNDLE_CONFIG = {
    "S3_URI": "s3://example-bundles/autosecops",
    "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/offline-bundle",
    "AWS_REGION": "eu-central-1",
    "KMS_KEY": "",
    "HAS_PRIVATE_KEY": "true",
    "HAS_PASSWORD": "true",
}


@pytest.mark.parametrize(
    ("overrides", "signer"),
    [
        ({}, "key"),
        ({"KMS_KEY": "awskms:///alias/autosecops-bundle"}, "kms"),
        ({"S3_URI": "s3://example-bundles/"}, "key"),
        ({"S3_URI": ""}, None),
        ({"S3_URI": "https://example-bundles.s3.amazonaws.com"}, None),
        ({"S3_URI": "s3://example-bundles/$(id)"}, None),
        ({"AWS_ROLE_ARN": ""}, None),
        ({"AWS_REGION": ""}, None),
        ({"HAS_PRIVATE_KEY": "false"}, None),
        ({"HAS_PASSWORD": "false"}, None),
        ({"KMS_KEY": "gcpkms://projects/x"}, None),
    ],
)
def test_bundle_workflow_requires_signing_and_a_private_destination(
    tmp_path: Path, overrides: dict[str, str], signer: str | None
) -> None:
    step = _bundle_step("Require signing and a private destination")
    output = tmp_path / "output"
    output.write_text("")
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        env={
            **os.environ,
            **VALID_BUNDLE_CONFIG,
            **overrides,
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is (signer is not None), result.stdout
    if signer is not None:
        assert output.read_text() == f"signer={signer}\n"


def test_require_signature_refuses_an_unsigned_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OFFLINE_BUNDLE_COSIGN_KEY", raising=False)
    monkeypatch.delenv("OFFLINE_BUNDLE_MINISIGN_KEY", raising=False)
    monkeypatch.setattr(
        bundler,
        "bundle_images",
        lambda *_a, **_k: pytest.fail("checked the key after resolving images"),
    )
    code = bundler.main(
        [
            "--version",
            __version__,
            "--require-signature",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 1


def _fake_tool(directory: Path, name: str, body: str) -> None:
    directory.mkdir(exist_ok=True)
    tool = directory / name
    tool.write_text(f"#!/bin/bash\n{body}\n")
    tool.chmod(0o755)


def test_cosign_signs_detached_without_a_transparency_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    args_file = tmp_path / "args"
    # Write the file named after --output-signature, as cosign does.
    _fake_tool(
        bin_dir,
        "cosign",
        f'printf "%s\\n" "$@" > {args_file}\n'
        "while [[ $# -gt 0 ]]; do\n"
        '  if [[ $1 == --output-signature ]]; then echo sig > "$2"; fi\n'
        "  shift\n"
        "done",
    )
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("OFFLINE_BUNDLE_COSIGN_KEY", "awskms:///alias/example")
    monkeypatch.delenv("OFFLINE_BUNDLE_MINISIGN_KEY", raising=False)
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("x\n")

    signature = bundler.sign_file(sums)

    assert signature == tmp_path / "SHA256SUMS.sig"
    args = args_file.read_text().splitlines()
    for flag in (
        "--new-bundle-format=false",
        "--use-signing-config=false",
        "--tlog-upload=false",
    ):
        assert flag in args

    (tmp_path / "out").mkdir()
    exported = bundler.export_checksums(sums, signature, tmp_path / "out", "1.2.3")
    assert [p.name for p in exported] == [
        "autosecops-offline-1.2.3.SHA256SUMS",
        "autosecops-offline-1.2.3.SHA256SUMS.sig",
    ]


def test_signer_that_writes_no_signature_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    # cosign 3 exits 0 and ignores --output-signature in its default mode.
    _fake_tool(bin_dir, "cosign", "exit 0")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("OFFLINE_BUNDLE_COSIGN_KEY", "cosign.key")
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("x\n")
    with pytest.raises(bundler.BundleError, match="wrote no SHA256SUMS.sig"):
        bundler.sign_file(sums)


def test_load_helper_verifies_cosign_signatures_offline() -> None:
    helper = (ROOT / "scripts" / "offline_bundle_load.sh").read_text()
    verify = helper[helper.index("cosign verify-blob") :].split("||", 1)[0]
    assert "--insecure-ignore-tlog=true" in verify
