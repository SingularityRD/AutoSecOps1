"""Run env.sh non-interactively and check the .env it writes."""

import shutil
import subprocess
from pathlib import Path

import pytest

from autosecops.temporal.codec import TemporalPayloadKeyring

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
    tmp_path: Path, *, production: bool, public_host: str = "localhost"
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


@requires_env_sh
@pytest.mark.parametrize("production", [True, False])
def test_env_sh_generates_a_temporal_payload_keyring(
    tmp_path: Path, production: bool
) -> None:
    env = _run_env_sh(tmp_path, production=production)

    assert env["TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED"] == "true"
    raw = env["TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING"]
    # Single-quoted so Docker Compose and python-dotenv read the JSON literally.
    assert raw.startswith("'") and raw.endswith("'")
    keyring = TemporalPayloadKeyring.model_validate_json(raw[1:-1])
    assert keyring.current_key_id == "v1"
    root_secret = keyring.keys["v1"].get_secret_value()
    assert len(root_secret) == 64
    int(root_secret, 16)  # 32 random bytes, hex encoded


@requires_env_sh
def test_env_sh_generates_a_different_keyring_per_install(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    first_keyring = _run_env_sh(first, production=True)[
        "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING"
    ]
    second_keyring = _run_env_sh(second, production=True)[
        "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING"
    ]

    assert first_keyring != second_keyring


@requires_env_sh
def test_env_sh_check_warns_when_production_payloads_are_plaintext(
    tmp_path: Path,
) -> None:
    _run_env_sh(tmp_path, production=True)
    env_file = tmp_path / ".env"
    env_file.write_text(
        env_file.read_text().replace(
            "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED=true",
            "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED=false",
        )
    )

    result = subprocess.run(
        ["bash", "env.sh", "--check", ".env"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )

    assert result.returncode == 0, result.stdout
    assert "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED is not true" in result.stdout


@requires_env_sh
@pytest.mark.parametrize("production", [True, False])
def test_env_sh_generates_redis_password(tmp_path: Path, production: bool) -> None:
    # Development mode too: the development Compose Redis requires it when set.
    env = _run_env_sh(tmp_path, production=production, public_host="")
    assert len(env["REDIS_PASSWORD"]) == 48
    assert not env["REDIS_PASSWORD"].startswith("change-me-")
    # Compose clients send it separately, so REDIS_URL keeps no credentials.
    assert env["REDIS_URL"] == "redis://${REDIS_HOST}:${REDIS_PORT}"
