"""Tests for SSH base functionality."""

import asyncio
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import SecretStr

from autosecops import config
from autosecops.git.types import GitUrl
from autosecops.process_env import tool_subprocess_env
from autosecops.ssh import (
    SshEnv,
    add_host_to_known_hosts_sync,
    add_ssh_key_to_agent_sync,
    ssh_context,
    temporary_ssh_agent,
)


class TestAddHostToKnownHosts:
    """Tests for add_host_to_known_hosts_sync."""

    def test_add_host_with_custom_port(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        env = SshEnv(ssh_auth_sock="/tmp/sock", ssh_agent_pid="123")
        captured_cmd: list[list[str]] = []

        def fake_run(cmd, capture_output, text, env, check, timeout=None):  # noqa: ANN001
            captured_cmd.append(cmd)
            return SimpleNamespace(
                returncode=0,
                stdout="[gitlab.example.com]:2222 ssh-rsa AAAA\n",
                stderr="",
            )

        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setattr("subprocess.run", fake_run)

        add_host_to_known_hosts_sync("gitlab.example.com:2222", env)

        assert captured_cmd == [["ssh-keyscan", "-p", "2222", "gitlab.example.com"]]
        known_hosts = tmp_path / ".ssh" / "known_hosts"
        assert known_hosts.read_text() == "[gitlab.example.com]:2222 ssh-rsa AAAA\n"

    def test_add_host_skips_existing_entry(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        env = SshEnv(ssh_auth_sock="/tmp/sock", ssh_agent_pid="123")
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        known_hosts = ssh_dir / "known_hosts"
        known_hosts.write_text("[gitlab.example.com]:2222 ssh-rsa AAAA\n")

        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        def fake_run(*args, **kwargs):  # noqa: ANN001, ANN002
            raise AssertionError("ssh-keyscan should not run for existing hosts")

        monkeypatch.setattr("subprocess.run", fake_run)

        add_host_to_known_hosts_sync("gitlab.example.com:2222", env)

    @pytest.mark.parametrize(
        ("url", "expected_host", "expected_port"),
        (
            ("gitlab.example.com:2222", "gitlab.example.com", "2222"),
            ("[gitlab.example.com]:2222", "gitlab.example.com", "2222"),
            ("gitlab.example.com", "gitlab.example.com", None),
            ("[2001:db8::1]:2222", "2001:db8::1", "2222"),
        ),
    )
    def test_split_host_port(
        self, url: str, expected_host: str, expected_port: str | None
    ) -> None:
        from autosecops.ssh import _split_host_port

        host, port = _split_host_port(url)

        assert host == expected_host
        assert port == expected_port


requires_ssh_agent = pytest.mark.skipif(
    shutil.which("ssh-agent") is None or shutil.which("ssh-add") is None,
    reason="needs OpenSSH ssh-agent and ssh-add",
)


@requires_ssh_agent
@pytest.mark.anyio
async def test_temporary_ssh_agent_is_a_reaped_foreground_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUTOSECOPS__SERVICE_KEY", "synthetic-service-key")
    socket_dir = tmp_path / "agent"
    real_exec = asyncio.create_subprocess_exec
    agent_envs: list[dict[str, str]] = []

    async def spy_exec(*args: Any, **kwargs: Any) -> Any:
        agent_envs.append(kwargs["env"])
        return await real_exec(*args, **kwargs)

    monkeypatch.setattr("autosecops.ssh.asyncio.create_subprocess_exec", spy_exec)

    async with temporary_ssh_agent(socket_dir=socket_dir) as env:
        assert env.ssh_auth_sock == str(socket_dir / "agent.sock")
        assert Path(env.ssh_auth_sock).is_socket()
        assert socket_dir.stat().st_mode & 0o777 == 0o700
        pid = int(env.ssh_agent_pid)
        # A child of this process, not a daemon reparented to PID 1.
        stat = Path(f"/proc/{pid}/stat").read_text()
        assert int(stat[stat.rfind(")") + 2 :].split()[1]) == os.getpid()
        # The agent lives for the whole sync without platform credentials. It
        # marks itself non-dumpable, so check what it was started with.
        assert agent_envs == [tool_subprocess_env()]
        assert "AUTOSECOPS__SERVICE_KEY" not in agent_envs[0]

    # Stopped and reaped: no zombie remains.
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def _ed25519_private_key() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@requires_ssh_agent
@pytest.mark.anyio
async def test_ssh_context_pins_git_ssh_to_a_private_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocker
) -> None:
    """git never reads ~/.ssh, which direct-mode action code can rewrite."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    secrets_service = mocker.patch("autosecops.ssh.SecretsService")
    secrets_service.return_value.get_ssh_key = mocker.AsyncMock(
        return_value=SecretStr(_ed25519_private_key())
    )

    async def fake_keyscan(host: str, *, env: SshEnv) -> None:
        assert env.known_hosts_path is not None
        Path(env.known_hosts_path).write_text(f"{host} ssh-ed25519 AAAAsynthetic\n")

    mocker.patch("autosecops.ssh.add_host_to_known_hosts", side_effect=fake_keyscan)
    git_url = GitUrl(host="git.example.test", org="example-org", repo="registry")

    async with ssh_context(git_url=git_url, session=mocker.Mock(), role=None) as env:
        assert env is not None
        env_vars = env.to_dict()
        command = shlex.split(env_vars["GIT_SSH_COMMAND"])
        known_hosts = Path(env.known_hosts_path or "")
        identity = Path(env.identity_path or "")
        context_dir = known_hosts.parent
        assert command[:3] == ["ssh", "-F", os.devnull]
        assert f"UserKnownHostsFile={known_hosts}" in command
        assert f"GlobalKnownHostsFile={os.devnull}" in command
        assert "StrictHostKeyChecking=yes" in command
        assert "IdentitiesOnly=yes" in command
        assert f"IdentityFile={identity}" in command
        assert identity.read_text().startswith("ssh-ed25519 ")
        assert "git.example.test" in known_hosts.read_text()
        assert context_dir.stat().st_mode & 0o777 == 0o700
        assert Path(env.ssh_auth_sock).parent.parent == context_dir
        # The sync's tools see the pinned command through their environment.
        assert (
            tool_subprocess_env(env_vars)["GIT_SSH_COMMAND"]
            == env_vars["GIT_SSH_COMMAND"]
        )

    assert not context_dir.exists()
    assert not (home / ".ssh").exists()


def test_add_ssh_key_applies_lifetime_and_destination_constraint(
    tmp_path: Path,
    mocker,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("git.example.test ssh-ed25519 synthetic\n")
    env = SshEnv(ssh_auth_sock="/tmp/agent.sock", ssh_agent_pid="123")
    validate_key = mocker.patch("autosecops.ssh.paramiko.Ed25519Key.from_private_key")
    run = mocker.patch(
        "autosecops.ssh.subprocess.run",
        return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    add_ssh_key_to_agent_sync(
        "fake-private-key",
        env,
        lifetime_seconds=150,
        destination="git@git.example.test",
        known_hosts_path=known_hosts,
    )

    validate_key.assert_called_once()
    run.assert_called_once_with(
        [
            "ssh-add",
            "-t",
            "150",
            "-H",
            str(known_hosts),
            "-h",
            "git@git.example.test",
            "-",
        ],
        input="fake-private-key\n",
        capture_output=True,
        text=True,
        env=tool_subprocess_env(env.to_dict()),
        check=False,
        timeout=30.0,
    )


def test_add_ssh_key_rejects_non_ed25519_key_with_credentials_error(mocker) -> None:
    """An RSA key surfaces as a clear credentials error, never reaching ssh-add."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from autosecops.exceptions import AutoSecOpsCredentialsError
    from autosecops.ssh import INVALID_SSH_KEY_MESSAGE

    rsa_key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )
    run = mocker.patch("autosecops.ssh.subprocess.run")

    with pytest.raises(AutoSecOpsCredentialsError) as exc_info:
        add_ssh_key_to_agent_sync(
            rsa_key, SshEnv(ssh_auth_sock="/tmp/agent.sock", ssh_agent_pid="1")
        )

    assert str(exc_info.value) == INVALID_SSH_KEY_MESSAGE
    run.assert_not_called()


@requires_ssh_agent
@pytest.mark.anyio
async def test_ssh_context_trusts_operator_pinned_host_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocker
) -> None:
    """A pinned host is verified against the operator's key, never rescanned."""
    pinned = tmp_path / "known_hosts"
    pinned.write_text("git.example.test ssh-ed25519 AAAApinnedsynthetic\n")
    monkeypatch.setattr(config, "AUTOSECOPS__GIT_SSH_KNOWN_HOSTS_FILE", str(pinned))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    secrets_service = mocker.patch("autosecops.ssh.SecretsService")
    secrets_service.return_value.get_ssh_key = mocker.AsyncMock(
        return_value=SecretStr(_ed25519_private_key())
    )
    real_run = subprocess.run

    def run(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        assert cmd[0] != "ssh-keyscan", "pinned host was rescanned"
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr("autosecops.ssh.subprocess.run", run)
    git_url = GitUrl(host="git.example.test", org="example-org", repo="registry")

    async with ssh_context(git_url=git_url, session=mocker.Mock(), role=None) as env:
        assert env is not None
        known_hosts = Path(env.known_hosts_path or "")
        assert known_hosts.read_text() == pinned.read_text()


@requires_ssh_agent
@pytest.mark.anyio
async def test_temporary_ssh_agent_shortens_overlong_socket_paths(
    tmp_path: Path,
) -> None:
    deep = tmp_path / ("d" * 60) / ("e" * 60)

    async with temporary_ssh_agent(socket_dir=deep) as env:
        assert len(os.fsencode(env.ssh_auth_sock)) < 108
        assert Path(env.ssh_auth_sock).is_socket()
