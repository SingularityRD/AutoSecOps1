"""Least-privilege subprocess environments."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from autosecops import process_env
from autosecops.process_env import (
    strip_url_credentials,
    tool_subprocess_env,
    trusted_path,
)


def test_trusted_path_drops_directories_the_user_can_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writable = tmp_path / "bin"
    writable.mkdir()
    system = tmp_path / "system" / "bin"
    system.mkdir(parents=True)
    monkeypatch.setattr(process_env.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(
        process_env.os,
        "access",
        lambda path, _mode: Path(path) == writable,
    )

    path = trusted_path(os.pathsep.join([str(writable), str(system), "relative"]))

    assert path == str(system)


def test_trusted_path_falls_back_to_trusted_system_directories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = "/home/apiuser"
    monkeypatch.setattr(process_env.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(
        process_env.os, "access", lambda path, _mode: str(path).startswith(home)
    )
    monkeypatch.setattr(process_env.Path, "resolve", lambda self, strict=False: self)

    assert trusted_path(f"{home}/.local/bin") == process_env.DEFAULT_TRUSTED_PATH


def test_trusted_path_is_empty_when_even_system_directories_are_writable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_env.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(process_env.os, "access", lambda _path, _mode: True)

    assert trusted_path("/home/apiuser/.local/bin") == ""
    # A restricted environment never gets an empty PATH, which would make
    # exec search the working directory.
    monkeypatch.setenv("PATH", "/home/apiuser/.local/bin")
    assert tool_subprocess_env()["PATH"] == os.devnull


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://user:pass@proxy.test:3128", "http://proxy.test:3128"),
        ("http://proxy.test:3128", "http://proxy.test:3128"),
        ("socks5://token@proxy.test", "socks5://proxy.test"),
    ],
)
def test_strip_url_credentials(url: str, expected: str) -> None:
    assert strip_url_credentials(url) == expected


def test_tool_env_drops_uv_credentials_and_user_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("UV_INDEX_URL", "https://pypi.example.test/simple")
    monkeypatch.setenv("UV_INDEX_CORP_PASSWORD", "synthetic-password")
    monkeypatch.setenv("UV_INDEX_CORP_USERNAME", "synthetic-user")
    monkeypatch.setenv("AUTOSECOPS__SERVICE_KEY", "synthetic-service-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://user:synthetic@proxy.test:3128")

    env = tool_subprocess_env({"GIT_DIR": "/repo/.git"})

    assert env["UV_INDEX_URL"] == "https://pypi.example.test/simple"
    assert "UV_INDEX_CORP_PASSWORD" not in env
    assert "UV_INDEX_CORP_USERNAME" not in env
    assert "AUTOSECOPS__SERVICE_KEY" not in env
    assert env["HTTPS_PROXY"] == "http://proxy.test:3128"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["UV_NO_CONFIG"] == "1"
    assert env["GIT_DIR"] == "/repo/.git"
