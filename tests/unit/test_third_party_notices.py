"""The third-party notices shipped in the images must cover every dependency.

Regenerate with `just gen-notices` after changing dependencies.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PYTHON_NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
FRONTEND_NOTICES = ROOT / "frontend" / "THIRD_PARTY_NOTICES.md"
REGENERATE = "run `just gen-notices` to regenerate the third-party notices"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "third_party_notices", ROOT / "scripts" / "third_party_notices.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the defining module up in sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _table(path: Path) -> dict[str, set[str]]:
    rows: dict[str, set[str]] = {}
    for match in re.finditer(r"^\| (\S+) \| (\S+) \| .* \|$", path.read_text(), re.M):
        name, version = match.groups()
        if name != "Package":
            rows.setdefault(_norm(name), set()).add(version)
    return rows


@pytest.mark.parametrize("path", [PYTHON_NOTICES, FRONTEND_NOTICES])
def test_notices_exist_and_say_what_they_cover(path: Path) -> None:
    assert path.exists(), REGENERATE
    text = path.read_text()
    assert text.startswith("# Third-party notices\n")
    assert "proprietary software of SingularityRD" in text
    assert "## License texts" in text


def test_python_notices_match_locked_production_dependencies() -> None:
    generator = _load_generator()
    table = _table(PYTHON_NOTICES)
    missing = [
        f"{name}=={version}"
        for name, version in generator.python_requirements()
        if version not in table.get(_norm(name), set())
    ]
    assert not missing, f"{REGENERATE}; missing: {missing}"


def test_frontend_notices_cover_direct_dependencies() -> None:
    dependencies = json.loads((ROOT / "frontend" / "package.json").read_text())[
        "dependencies"
    ]
    table = _table(FRONTEND_NOTICES)
    missing = [
        f"{name}@{version}"
        for name, version in dependencies.items()
        if version not in table.get(_norm(name), set())
    ]
    assert not missing, f"{REGENERATE}; missing: {missing}"


@pytest.mark.parametrize(
    ("dockerfile", "needle"),
    [
        ("Dockerfile", "./THIRD_PARTY_NOTICES.md"),
        ("Dockerfile.tunnel-gateway", "THIRD_PARTY_NOTICES.md"),
        ("frontend/Dockerfile.prod", "/app/THIRD_PARTY_NOTICES.md"),
    ],
)
def test_images_ship_the_notices(dockerfile: str, needle: str) -> None:
    copies = [
        line
        for line in (ROOT / dockerfile).read_text().splitlines()
        if line.startswith("COPY") and needle in line
    ]
    assert copies, f"{dockerfile} must COPY {needle}"
