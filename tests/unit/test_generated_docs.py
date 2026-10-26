"""Checked-in generated docs must match what their generators produce."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import orjson
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS_SPEC = REPO_ROOT / "docs" / "api-reference" / "openapi.json"


def test_docs_openapi_spec_is_current(tmp_path: Path) -> None:
    generated_path = tmp_path / "openapi.json"
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "openapi" / "generate_openapi.py"),
            str(generated_path),
        ],
        check=True,
        capture_output=True,
        cwd=REPO_ROOT,
    )
    generated = orjson.loads(generated_path.read_bytes())
    published = orjson.loads(DOCS_SPEC.read_bytes())
    # The docs spec only swaps in a templated server URL for the docs site.
    generated["servers"] = published["servers"]
    missing = sorted(
        f"{method.upper()} {path}"
        for path, methods in generated["paths"].items()
        for method in methods
        if method not in published["paths"].get(path, {})
    )
    assert not missing, (
        f"docs/api-reference/openapi.json is missing {missing}; regenerate it "
        "with scripts/openapi/generate_openapi.py"
    )
    assert generated == published, (
        "docs/api-reference/openapi.json is stale; regenerate it with "
        "scripts/openapi/generate_openapi.py and keep the docs servers entry"
    )


@pytest.mark.parametrize(
    "script", ["generate_core_action_docs.py", "generate_tool_docs.py"]
)
def test_generated_docs_are_current(script: str) -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / script), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, (
        f"{script} --check failed; rerun it without --check:\n"
        f"{result.stdout[-2000:]}{result.stderr[-2000:]}"
    )
