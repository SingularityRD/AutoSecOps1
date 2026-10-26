"""Run env.sh non-interactively and check the .env it writes."""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


@pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("openssl") is None,
    reason="env.sh needs bash and openssl",
)
@pytest.mark.parametrize(
    ("public_host", "expected_origins"),
    [
        ("localhost", "http://localhost,http://localhost:3000"),
        (
            "autosecops.example.test:8080",
            "http://autosecops.example.test:8080,http://localhost:3000",
        ),
    ],
)
def test_env_sh_sets_allow_origins(
    tmp_path: Path, public_host: str, expected_origins: str
) -> None:
    shutil.copy(REPO_ROOT / "env.sh", tmp_path / "env.sh")
    shutil.copy(REPO_ROOT / ".env.example", tmp_path / ".env.example")
    # Answers: production mode, public host, no PostgreSQL SSL, superadmin email.
    answers = f"y\n{public_host}\nn\nadmin@example.com\n"

    subprocess.run(
        ["bash", "env.sh"],
        cwd=tmp_path,
        input=answers,
        text=True,
        capture_output=True,
        check=True,
        timeout=60,
    )

    env = _read_env(tmp_path / ".env")
    assert env["AUTOSECOPS__ALLOW_ORIGINS"] == expected_origins
