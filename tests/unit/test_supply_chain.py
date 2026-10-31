"""Supply-chain guards: pinned base images and automated dependency updates."""

import re
from pathlib import Path

import pytest
import yaml
from check_pr_title import check_title
from commit_conventions import load_conventions

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILES = [
    "Dockerfile",
    "Dockerfile.tunnel-gateway",
    "frontend/Dockerfile",
    "frontend/Dockerfile.prod",
    ".devcontainer/claude.Dockerfile",
    "deployments/postgres/Dockerfile",
]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def _external_images(dockerfile: Path) -> list[str]:
    """Images a Dockerfile pulls: FROM and COPY --from that are not stages."""
    stages: set[str] = set()
    images: list[str] = []
    for raw in dockerfile.read_text().splitlines():
        line = raw.strip()
        if match := re.match(
            r"FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I
        ):
            image, stage = match.groups()
            if image not in stages:
                images.append(image)
            if stage:
                stages.add(stage)
        elif match := re.match(r"COPY\s+(?:--\S+\s+)*?--from=(\S+)", line):
            source = match.group(1)
            if source not in stages and not source.isdigit():
                images.append(source)
    return images


def test_every_dockerfile_is_listed() -> None:
    found = {
        str(path.relative_to(ROOT))
        for pattern in (
            "Dockerfile*",
            "*.Dockerfile",
            "*/Dockerfile*",
            "*/*.Dockerfile",
            "*/*/Dockerfile*",
        )
        for path in ROOT.glob(pattern)
        if "node_modules" not in path.parts
    }
    assert found <= set(DOCKERFILES), sorted(found - set(DOCKERFILES))


@pytest.mark.parametrize("name", DOCKERFILES)
def test_base_images_are_pinned_by_digest(name: str) -> None:
    images = _external_images(ROOT / name)
    assert images, name
    for image in images:
        # deployments/postgres takes BASE_IMAGE from images.json, which pins a
        # digest and is checked by its own workflow.
        if image == "${BASE_IMAGE}":
            continue
        assert ":" in image.split("@")[0], f"{name}: {image} keeps no readable tag"
        assert DIGEST.search(image), f"{name}: {image} is not pinned by digest"


def test_dependabot_covers_every_ecosystem_with_a_cooldown() -> None:
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    assert config["version"] == 2
    updates = {u["package-ecosystem"]: u for u in config["updates"]}
    assert set(updates) == {"uv", "npm", "docker", "github-actions"}
    assert updates["npm"]["directory"] == "/frontend"
    docker_dirs = set(updates["docker"]["directories"])
    for name in DOCKERFILES:
        if name.startswith("deployments/"):
            # Its base comes from images.json, not a FROM line.
            continue
        parent = Path(name).parent.as_posix()
        assert ("/" if parent == "." else f"/{parent}") in docker_dirs, name
    for ecosystem, update in updates.items():
        assert update["schedule"]["interval"] == "weekly", ecosystem
        # Matches `exclude-newer = "7 days"` and `minimum-release-age`.
        assert update["cooldown"]["default-days"] >= 7, ecosystem
        assert update["groups"], ecosystem
        prefix = update["commit-message"]["prefix"]
        # GitHub Actions work is a bare `ci:` title; the rest are build(deps).
        assert prefix == ("ci" if ecosystem == "github-actions" else "build(deps)")


def _dependabot_titles(update: dict[str, object]) -> list[str]:
    """Titles Dependabot writes for an update entry, production and dev.

    Dependabot appends `: ` to a prefix ending in a letter or `)`. With
    `include: scope` it inserts `(deps)` or `(deps-dev)`, and
    `prefix-development` replaces the prefix for development dependencies.
    """
    message = update["commit-message"]
    assert isinstance(message, dict)
    titles = []
    for dev in (False, True):
        prefix = str(message.get("prefix-development", "") if dev else "")
        prefix = prefix or str(message["prefix"])
        if message.get("include") == "scope":
            prefix = f"{prefix}({'deps-dev' if dev else 'deps'})"
        titles += [
            f"{prefix}: bump example-package from 1.2.3 to 1.2.4",
            f"{prefix}: bump the example group with 3 updates",
        ]
    return titles


@pytest.mark.parametrize("ecosystem", ["uv", "npm", "docker", "github-actions"])
def test_dependabot_titles_pass_the_pr_title_check(ecosystem: str) -> None:
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    (update,) = [u for u in config["updates"] if u["package-ecosystem"] == ecosystem]
    conventions = load_conventions()
    for title in _dependabot_titles(update):
        report = check_title(title, conventions)
        assert report.ok, (title, [v.code for v in report.violations])


@pytest.mark.parametrize("ecosystem", ["uv", "npm", "docker"])
def test_dependabot_version_updates_skip_majors(ecosystem: str) -> None:
    """Majors move in deliberate migration PRs, not in bot bumps.

    Every ignore rule must also carry `update-types`: a rule that ignores a
    dependency outright can suppress its security updates too.
    """
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    (update,) = [u for u in config["updates"] if u["package-ecosystem"] == ecosystem]
    rules = update["ignore"]
    assert {
        "dependency-name": "*",
        "update-types": ["version-update:semver-major"],
    } in rules
    for rule in rules:
        assert rule.get("update-types"), rule


def test_dependabot_keeps_github_actions_majors_in_the_grouped_pr() -> None:
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    (actions,) = [
        u for u in config["updates"] if u["package-ecosystem"] == "github-actions"
    ]
    assert "ignore" not in actions


def test_dependabot_ignores_runtime_changing_base_image_tags() -> None:
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    (docker,) = [u for u in config["updates"] if u["package-ecosystem"] == "docker"]
    ignored = {
        (rule["dependency-name"], update_type)
        for rule in docker["ignore"]
        for update_type in rule["update-types"]
    }
    assert ("*", "version-update:semver-major") in ignored
    # python:3.12 -> 3.13 and uv 0.13 -> 0.14 are minor tag bumps that change
    # the interpreter or resolver; the grouped PR must carry only digest and
    # patch refreshes.
    assert ("python", "version-update:semver-minor") in ignored
    assert ("ghcr.io/astral-sh/uv", "version-update:semver-minor") in ignored
    images = {
        image.split(":")[0]
        for name in DOCKERFILES
        for image in _external_images(ROOT / name)
    }
    assert {"python", "ghcr.io/astral-sh/uv"} <= images
