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


def test_frontend_notices_list_ui_target_native_packages() -> None:
    """The UI image ships Linux musl x64/arm64 binaries, not the host's."""
    generator = _load_generator()
    platforms = generator._lockfile_platforms()
    table = _table(FRONTEND_NOTICES)
    wrong_platform = sorted(
        f"{name}@{version}"
        for (name, version), constraints in platforms.items()
        if constraints
        and version in table.get(_norm(name), set())
        and not generator._matches_ui_targets(constraints)
    )
    assert not wrong_platform, f"{REGENERATE}; not in the UI image: {wrong_platform}"
    for name in (
        "@img/sharp-linuxmusl-x64",
        "@img/sharp-linuxmusl-arm64",
        "@img/sharp-libvips-linuxmusl-x64",
        "@img/sharp-libvips-linuxmusl-arm64",
    ):
        assert _norm(name) in table, f"{REGENERATE}; missing {name}"


def test_target_variants_replace_host_variants() -> None:
    generator = _load_generator()
    host = generator.Component(
        ecosystem="frontend",
        name="@img/sharp-libvips-darwin-arm64",
        version="1.0.0",
        license="LGPL-3.0-or-later",
        homepage="",
        texts=(("LICENSE", "license text"),),
    )
    portable = generator.Component(
        ecosystem="frontend",
        name="left-pad",
        version="1.0.0",
        license="MIT",
        homepage="",
    )
    platforms = {
        ("@img/sharp-libvips-darwin-arm64", "1.0.0"): {
            "os": ["darwin"],
            "cpu": ["arm64"],
        },
        ("@img/sharp-libvips-linuxmusl-x64", "1.0.0"): {
            "os": ["linux"],
            "cpu": ["x64"],
            "libc": ["musl"],
        },
        ("@img/sharp-libvips-linux-x64", "1.0.0"): {
            "os": ["linux"],
            "cpu": ["x64"],
            "libc": ["glibc"],
        },
        ("@img/sharp-libvips-win32-x64", "1.0.0"): {"os": ["win32"], "cpu": ["x64"]},
        ("left-pad", "1.0.0"): {},
    }

    result = generator._for_ui_targets([host, portable], platforms)

    assert sorted(c.name for c in result) == [
        "@img/sharp-libvips-linuxmusl-x64",
        "left-pad",
    ]
    musl = next(c for c in result if c.name.endswith("linuxmusl-x64"))
    assert musl.license == "LGPL-3.0-or-later"
    assert musl.texts == host.texts


def test_python_notices_list_bundled_programs() -> None:
    generator = _load_generator()
    text = PYTHON_NOTICES.read_text()
    programs = generator.api_programs()
    names = {program.name for program in programs}
    assert {"nsjail", "Pangolin CLI", "Node.js", "npm", "uv and uvx"} <= names
    for program in programs:
        row = f"| {program.name} | {program.version} | {program.license} |"
        assert row in text, f"{REGENERATE}; missing {program.name} {program.version}"
    for program in generator.ui_programs():
        row = f"| {program.name} | {program.version} | {program.license} |"
        assert row in FRONTEND_NOTICES.read_text(), REGENERATE
