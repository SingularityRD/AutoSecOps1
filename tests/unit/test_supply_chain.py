"""Supply-chain guards: pinned base images and automated dependency updates."""

import re
from pathlib import Path

import pytest
import yaml

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
        if ecosystem == "github-actions":
            # GitHub Actions work is a bare `ci:` title.
            assert prefix == "ci" and "include" not in update["commit-message"]
        else:
            assert prefix == "build"
            assert update["commit-message"]["include"] == "scope"
