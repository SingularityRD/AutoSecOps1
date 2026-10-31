"""Every registry git fetch verifies the host against pinned or per-sync keys."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from autosecops import config
from autosecops.exceptions import RegistryError
from autosecops.registry.sync.runner import GitCloneError, RegistrySyncRunner
from autosecops.registry.sync.sandbox import RegistrySyncSandbox
from autosecops.ssh import (
    SshEnv,
    UnknownGitHostError,
    add_host_to_known_hosts_sync,
    known_hosts_lists,
)

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="needs OpenSSH ssh-keygen"
)

GIT_URL = "git+ssh://git@git.example.test:2222/acme/registry.git"


def _host_key(tmp_path: Path) -> str:
    key = tmp_path / "host_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    return " ".join(key.with_suffix(".pub").read_text().split()[:2])


def _hashed_known_hosts(tmp_path: Path, host_token: str) -> Path:
    path = tmp_path / "pinned_known_hosts"
    path.write_text(f"{host_token} {_host_key(tmp_path)}\n")
    subprocess.run(
        ["ssh-keygen", "-H", "-f", str(path)], check=True, capture_output=True
    )
    path.with_name(path.name + ".old").unlink()
    assert path.read_text().startswith("|1|")
    return path


@pytest.fixture
def no_keyscan(monkeypatch: pytest.MonkeyPatch) -> None:
    real_run = subprocess.run

    def run(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        assert Path(cmd[0]).name != "ssh-keyscan", "a pinned host was rescanned"
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr("autosecops.ssh.subprocess.run", run)


def test_known_hosts_lists_understands_hashed_ca_and_port_entries(
    tmp_path: Path,
) -> None:
    hashed = _hashed_known_hosts(tmp_path, "[git.example.test]:2222")
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    ca = tmp_path / "ca_known_hosts"
    ca.write_text(f"@cert-authority *.example.org {_host_key(ca_dir)}\n")

    assert known_hosts_lists(hashed, "git.example.test", "2222")
    assert not known_hosts_lists(hashed, "git.example.test", None)
    assert known_hosts_lists(ca, "git.example.org", None)
    assert not known_hosts_lists(ca, "other.test", None)


@pytest.mark.usefixtures("no_keyscan")
def test_pinned_hashed_entry_is_recognised_and_not_scanned(tmp_path: Path) -> None:
    known_hosts = _hashed_known_hosts(tmp_path, "[git.example.test]:2222")
    before = known_hosts.read_text()
    env = SshEnv(ssh_auth_sock="", ssh_agent_pid="", known_hosts_path=str(known_hosts))

    add_host_to_known_hosts_sync("git.example.test:2222", env)

    # Nothing appended next to the pin, so ssh can only accept the pinned key.
    assert known_hosts.read_text() == before


@pytest.mark.usefixtures("no_keyscan")
def test_strict_mode_refuses_an_unlisted_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__GIT_SSH_STRICT_KNOWN_HOSTS", True)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    env = SshEnv(ssh_auth_sock="", ssh_agent_pid="", known_hosts_path=str(known_hosts))

    with pytest.raises(UnknownGitHostError, match="git.example.test"):
        add_host_to_known_hosts_sync("git.example.test:2222", env)

    assert known_hosts.read_text() == ""


@pytest.mark.anyio
@pytest.mark.usefixtures("no_keyscan")
async def test_artifact_clone_verifies_the_pinned_host_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocker
) -> None:
    pinned = _hashed_known_hosts(tmp_path, "[git.example.test]:2222")
    monkeypatch.setattr(config, "AUTOSECOPS__GIT_SSH_KNOWN_HOSTS_FILE", str(pinned))
    work_dir = tmp_path / "sync"
    work_dir.mkdir()
    runner = RegistrySyncRunner()
    commands: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    async def fake_exec(*args: str, **kwargs: Any) -> Any:
        commands.append((args, kwargs))
        process = mocker.Mock(returncode=0)
        process.communicate = mocker.AsyncMock(return_value=(b"c" * 40, b""))
        return process

    mocker.patch(
        "autosecops.registry.sync.runner.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    )

    known_hosts = await runner._prepare_known_hosts(GIT_URL, work_dir)
    await runner._clone_repository(
        git_url=GIT_URL,
        commit_sha=None,
        ssh_key="synthetic-key",
        work_dir=work_dir,
        known_hosts=known_hosts,
    )

    assert known_hosts.read_text() == pinned.read_text()
    ssh_command = shlex.split(commands[0][1]["env"]["GIT_SSH_COMMAND"])
    assert ssh_command[:3] == ["ssh", "-F", "/dev/null"]
    assert f"UserKnownHostsFile={known_hosts}" in ssh_command
    assert "GlobalKnownHostsFile=/dev/null" in ssh_command
    assert "StrictHostKeyChecking=yes" in ssh_command
    assert "StrictHostKeyChecking=no" not in ssh_command


@pytest.mark.anyio
async def test_artifact_clone_requires_verified_host_keys(tmp_path: Path) -> None:
    with pytest.raises(GitCloneError, match="known_hosts"):
        await RegistrySyncRunner()._clone_repository(
            git_url=GIT_URL,
            commit_sha=None,
            ssh_key="synthetic-key",
            work_dir=tmp_path,
            known_hosts=None,
        )


@pytest.mark.anyio
async def test_artifact_clone_refuses_unlisted_host_in_strict_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__GIT_SSH_STRICT_KNOWN_HOSTS", True)

    with pytest.raises(GitCloneError, match="git.example.test"):
        await RegistrySyncRunner()._prepare_known_hosts(GIT_URL, tmp_path)


@pytest.mark.anyio
async def test_sandboxed_clone_uses_the_pin_without_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocker
) -> None:
    pinned = _hashed_known_hosts(tmp_path, "[git.example.test]:2222")
    monkeypatch.setattr(config, "AUTOSECOPS__GIT_SSH_KNOWN_HOSTS_FILE", str(pinned))
    executor = mocker.patch("autosecops.registry.sync.sandbox.NsjailExecutor")
    target = mocker.Mock(host="git.example.test", port=2222)

    known_hosts = await RegistrySyncSandbox()._scan_host_keys(
        target=target, work_dir=tmp_path / "sync"
    )

    executor.assert_not_called()
    assert known_hosts.read_text() == pinned.read_text()


@pytest.mark.anyio
async def test_sandboxed_clone_refuses_unlisted_host_in_strict_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocker
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__GIT_SSH_STRICT_KNOWN_HOSTS", True)
    executor = mocker.patch("autosecops.registry.sync.sandbox.NsjailExecutor")
    target = mocker.Mock(host="git.example.test", port=2222)

    with pytest.raises(RegistryError, match="git.example.test"):
        await RegistrySyncSandbox()._scan_host_keys(
            target=target, work_dir=tmp_path / "sync"
        )

    executor.assert_not_called()
