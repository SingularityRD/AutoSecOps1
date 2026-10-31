"""Registry installs run uv and git without platform credentials."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from autosecops import config
from autosecops.auth.types import Role
from autosecops.authz.scopes import SERVICE_PRINCIPAL_SCOPES
from autosecops.registry import repository as registry_repository
from autosecops.registry.constants import DEFAULT_LOCAL_REGISTRY_ORIGIN
from autosecops.registry.repository import Repository, install_remote_repository
from autosecops.ssh import SshEnv

PLATFORM_SECRETS = {
    "AUTOSECOPS__DB_ENCRYPTION_KEY": "synthetic-encryption-key",
    "AUTOSECOPS__SERVICE_KEY": "synthetic-service-key",
    "AWS_SECRET_ACCESS_KEY": "synthetic-aws-secret",
    "UV_INDEX_CORP_PASSWORD": "synthetic-index-password",
}


class _Spawned:
    """Records each subprocess the code under test starts."""

    def __init__(self, returncodes: dict[str, int] | None = None) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
        self.returncodes = returncodes or {}

    async def create(self, *args: str, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return SimpleNamespace(returncode=self.returncodes.get(args[0], 0))

    def by_program(self, program: str) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
        return [call for call in self.calls if call[0][0] == program]


@pytest.fixture
def spawned(monkeypatch: pytest.MonkeyPatch) -> _Spawned:
    for name, value in PLATFORM_SECRETS.items():
        monkeypatch.setenv(name, value)
    recorder = _Spawned()

    async def communicate(process: Any, **_kwargs: Any) -> tuple[bytes, bytes]:
        del process
        return b"0123456789abcdef0123456789abcdef01234567\n", b""

    monkeypatch.setattr(
        registry_repository.asyncio, "create_subprocess_exec", recorder.create
    )
    monkeypatch.setattr(registry_repository, "communicate_process_group", communicate)
    return recorder


@pytest.fixture
def local_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "local_registry"
    (repo / ".git").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname = 'local_registry'\n")
    monkeypatch.setattr(config, "AUTOSECOPS__LOCAL_REPOSITORY_ENABLED", True)
    monkeypatch.setattr(
        config, "AUTOSECOPS__LOCAL_REPOSITORY_CONTAINER_PATH", str(repo)
    )
    monkeypatch.setenv("PYTHONUSERBASE", str(tmp_path / "userbase"))
    return repo


def _role() -> Role:
    return Role(
        type="service",
        service_id="autosecops-service",
        scopes=SERVICE_PRINCIPAL_SCOPES["autosecops-service"],
    )


def _assert_no_platform_secrets(env: dict[str, str]) -> None:
    for name in PLATFORM_SECRETS:
        assert name not in env, name
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"


@pytest.mark.anyio
async def test_local_install_runs_git_and_uv_without_credentials(
    spawned: _Spawned, local_repo: Path, tmp_path: Path
) -> None:
    installation = await Repository(
        origin=DEFAULT_LOCAL_REGISTRY_ORIGIN, role=_role()
    ).install_from_origin()

    assert installation.package_name == "local_registry"
    assert installation.commit_sha is None
    assert installation.site_dir == tmp_path / "userbase"

    [(git_args, git_kwargs)] = spawned.by_program("git")
    assert git_args == ("git", "rev-parse", "HEAD")
    git_env = git_kwargs["env"]
    _assert_no_platform_secrets(git_env)
    assert git_env["GIT_DIR"] == str(local_repo / ".git")
    assert git_env["GIT_CONFIG_KEY_0"] == "safe.directory"
    assert git_env["GIT_CONFIG_VALUE_0"] == str(local_repo)
    assert git_kwargs["start_new_session"] is True

    [(uv_args, uv_kwargs)] = spawned.by_program("uv")
    assert uv_args == (
        "uv",
        "pip",
        "install",
        "--refresh",
        "--editable",
        str(local_repo),
        "--python",
        sys.executable,
        "--target",
        str(tmp_path / "userbase"),
    )
    uv_env = uv_kwargs["env"]
    _assert_no_platform_secrets(uv_env)
    assert uv_env["UV_NO_CONFIG"] == "1"
    # A private cache that is gone once the install returns.
    assert Path(uv_env["UV_CACHE_DIR"]).name.startswith("autosecops-uv-cache-")
    assert not Path(uv_env["UV_CACHE_DIR"]).exists()
    assert uv_kwargs["start_new_session"] is True


@pytest.mark.anyio
async def test_local_install_skips_rev_parse_when_commit_is_given(
    spawned: _Spawned, local_repo: Path
) -> None:
    del local_repo
    await Repository(
        origin=DEFAULT_LOCAL_REGISTRY_ORIGIN, role=_role()
    ).install_from_origin(commit_sha="a" * 40)

    assert spawned.by_program("git") == []
    assert len(spawned.by_program("uv")) == 1


@pytest.mark.anyio
async def test_local_install_tolerates_rev_parse_failure(
    spawned: _Spawned, local_repo: Path
) -> None:
    del local_repo
    spawned.returncodes["git"] = 128

    installation = await Repository(
        origin=DEFAULT_LOCAL_REGISTRY_ORIGIN, role=_role()
    ).install_from_origin()

    assert installation.package_name == "local_registry"
    assert len(spawned.by_program("uv")) == 1


@pytest.mark.anyio
async def test_remote_install_targets_given_directory_without_credentials(
    spawned: _Spawned, tmp_path: Path
) -> None:
    target = tmp_path / "per-sync-target"
    ssh_env = SshEnv(ssh_auth_sock="/tmp/agent.sock", ssh_agent_pid="1")

    await install_remote_repository(
        "git+ssh://git@github.com/example-org/registry.git",
        commit_sha="b" * 40,
        env=ssh_env,
        target_dir=target,
    )

    [(uv_args, uv_kwargs)] = spawned.by_program("uv")
    assert uv_args == (
        "uv",
        "pip",
        "install",
        "--python",
        sys.executable,
        "--target",
        str(target),
        "--refresh",
        f"git+ssh://git@github.com/example-org/registry.git@{'b' * 40}",
    )
    uv_env = uv_kwargs["env"]
    _assert_no_platform_secrets(uv_env)
    assert uv_env["SSH_AUTH_SOCK"] == "/tmp/agent.sock"
    assert uv_kwargs["start_new_session"] is True


@pytest.mark.anyio
async def test_remote_install_needs_a_caller_owned_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[Path | None] = []

    async def install(self: Repository, **kwargs: Any) -> str:
        del self
        seen.append(kwargs.get("target_dir"))
        return "c" * 40

    async def no_setting(*_args: Any, **kwargs: Any) -> Any:
        return kwargs.get("default")

    monkeypatch.setattr(Repository, "_install_remote_repository", install)
    monkeypatch.setattr(registry_repository, "get_setting", no_setting)
    repo = Repository(
        origin="git+ssh://git@github.com/example-org/registry.git", role=_role()
    )

    # No silent temporary directory that nobody removes.
    with pytest.raises(ValueError, match="target_dir"):
        await repo.install_from_origin()

    installation = await repo.install_from_origin(target_dir=tmp_path)

    assert installation.commit_sha == "c" * 40
    assert seen == [tmp_path]
    assert installation.site_dir == tmp_path
