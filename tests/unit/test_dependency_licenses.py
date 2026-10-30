"""Runtime dependencies must not carry proprietary, non-redistributable licenses.

The API image ships every locked production dependency to customers, so a
package whose license forbids redistribution must never enter `uv.lock`.
"""

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LOCKFILE = ROOT / "uv.lock"
PYTHON_NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"

# Packages under licenses that forbid redistribution without a vendor
# subscription. litellm[proxy] requires litellm-enterprise; pyproject.toml
# drops it with `[tool.uv] exclude-dependencies`.
FORBIDDEN_PACKAGES = frozenset({"litellm-enterprise"})

# License strings that mark a package as not open source.
PROPRIETARY_LICENSE = re.compile(
    r"proprietary|licenseref-|commercial|\bunlicensed\b", re.IGNORECASE
)


def _locked_package_names() -> set[str]:
    lock = tomllib.loads(LOCKFILE.read_text())
    return {
        re.sub(r"[-_.]+", "-", package["name"]).lower() for package in lock["package"]
    }


def test_lockfile_has_no_forbidden_packages() -> None:
    found = FORBIDDEN_PACKAGES & _locked_package_names()
    assert not found, (
        f"{sorted(found)} in uv.lock: proprietary license, must not ship. "
        "Exclude it in [tool.uv] exclude-dependencies and run `uv lock`."
    )


def test_pyproject_excludes_forbidden_packages() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    excluded = set(pyproject["tool"]["uv"].get("exclude-dependencies", []))
    assert FORBIDDEN_PACKAGES <= excluded


@pytest.mark.parametrize(
    "license_",
    ["MIT", "Apache-2.0", "The Unlicense (Unlicense)", "See license text"],
)
def test_proprietary_marker_allows_open_source(license_: str) -> None:
    assert not PROPRIETARY_LICENSE.search(license_)


@pytest.mark.parametrize(
    "license_",
    ["LicenseRef-Proprietary", "Other/Proprietary License", "UNLICENSED"],
)
def test_proprietary_marker_flags_proprietary(license_: str) -> None:
    assert PROPRIETARY_LICENSE.search(license_)


def test_python_notices_have_no_proprietary_licenses() -> None:
    rows = re.findall(
        r"^\| (\S+) \| (\S+) \| (.*) \|$", PYTHON_NOTICES.read_text(), re.M
    )
    flagged = [
        f"{name} {version}: {license_}"
        for name, version, license_ in rows
        if name != "Package" and PROPRIETARY_LICENSE.search(license_)
    ]
    assert not flagged, f"proprietary runtime dependencies: {flagged}"
