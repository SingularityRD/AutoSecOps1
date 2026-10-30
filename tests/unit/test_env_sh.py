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


requires_env_sh = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("openssl") is None,
    reason="env.sh needs bash and openssl",
)


def _run_env_sh(
    tmp_path: Path, *, production: bool, public_host: str
) -> dict[str, str]:
    shutil.copy(REPO_ROOT / "env.sh", tmp_path / "env.sh")
    shutil.copy(REPO_ROOT / ".env.example", tmp_path / ".env.example")
    # Answers: production mode, public host, no PostgreSQL SSL, superadmin email.
    answers = f"{'y' if production else 'n'}\n{public_host}\nn\nadmin@example.com\n"

    subprocess.run(
        ["bash", "env.sh"],
        cwd=tmp_path,
        input=answers,
        text=True,
        capture_output=True,
        check=True,
        timeout=60,
    )
    return _read_env(tmp_path / ".env")


@requires_env_sh
@pytest.mark.parametrize(
    ("production", "public_host", "app_url", "origins", "app_port"),
    [
        # The non-interactive CI answers: production mode on localhost.
        (True, "localhost", "http://localhost", "http://localhost", "80"),
        (True, "", "http://localhost", "http://localhost", "80"),
        (
            True,
            "127.0.0.1:8080",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080",
            "8080",
        ),
        # Production defaults a public host to HTTPS, so cookies are Secure.
        (
            True,
            "autosecops.example.test",
            "https://autosecops.example.test",
            "https://autosecops.example.test",
            "80",
        ),
        # A typed scheme is kept, not stripped.
        (
            True,
            "https://autosecops.example.test/",
            "https://autosecops.example.test",
            "https://autosecops.example.test",
            "80",
        ),
        (
            True,
            "HTTP://autosecops.example.test:8080",
            "http://autosecops.example.test:8080",
            "http://autosecops.example.test:8080",
            "8080",
        ),
        # With HTTPS, the port belongs to the TLS endpoint in front of Caddy.
        (
            True,
            "https://autosecops.example.test:8443",
            "https://autosecops.example.test:8443",
            "https://autosecops.example.test:8443",
            "80",
        ),
        # Development mode keeps HTTP and allows the frontend dev server.
        (False, "", "http://localhost", "http://localhost,http://localhost:3000", "80"),
        (
            False,
            "autosecops.example.test:8080",
            "http://autosecops.example.test:8080",
            "http://autosecops.example.test:8080,http://localhost:3000",
            "8080",
        ),
        (
            False,
            "https://autosecops.example.test",
            "https://autosecops.example.test",
            "http://localhost:3000,https://autosecops.example.test",
            "80",
        ),
    ],
)
def test_env_sh_sets_public_urls_and_allow_origins(
    tmp_path: Path,
    production: bool,
    public_host: str,
    app_url: str,
    origins: str,
    app_port: str,
) -> None:
    env = _run_env_sh(tmp_path, production=production, public_host=public_host)
    assert env["PUBLIC_APP_URL"] == app_url
    assert env["PUBLIC_API_URL"] == f"{app_url}/api"
    assert env["AUTOSECOPS__ALLOW_ORIGINS"] == origins
    assert env["PUBLIC_APP_PORT"] == app_port
    assert env["AUTOSECOPS__APP_ENV"] == ("production" if production else "development")


@requires_env_sh
def test_env_sh_reprompts_for_unsupported_scheme(tmp_path: Path) -> None:
    shutil.copy(REPO_ROOT / "env.sh", tmp_path / "env.sh")
    shutil.copy(REPO_ROOT / ".env.example", tmp_path / ".env.example")
    result = subprocess.run(
        ["bash", "env.sh"],
        cwd=tmp_path,
        input="y\nftp://autosecops.example.test\nautosecops.example.test\nn\nadmin@example.com\n",
        text=True,
        capture_output=True,
        check=True,
        timeout=60,
    )
    assert "Use an http:// or https:// address" in result.stdout
    assert (
        _read_env(tmp_path / ".env")["PUBLIC_APP_URL"]
        == "https://autosecops.example.test"
    )
