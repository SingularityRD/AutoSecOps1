"""Custom registry Git URLs with an ``@ref`` suffix and SSH key errors.

The ``@ref`` suffix on a custom registry URL selects a branch (or commit) and is
not part of the remote path, so Git must never receive it. Unsupported SSH keys
must surface as a clear 400 instead of an internal server error.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from inspect import unwrap
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from autosecops.auth.types import Role
from autosecops.exceptions import AutoSecOpsCredentialsError
from autosecops.git.types import GitUrl
from autosecops.registry import repository as registry_repository
from autosecops.registry.repositories import router as registry_repos_router
from autosecops.registry.repositories.schemas import RegistryRepositorySync
from autosecops.registry.repository import Repository
from autosecops.registry.sync import artifact as registry_artifact
from autosecops.ssh import INVALID_SSH_KEY_MESSAGE, SshEnv

ORIGIN = "git+ssh://git@git.example.test:2222/acme/registry.git@release/v1"
REMOTE = "git+ssh://git@git.example.test:2222/acme/registry.git"
SSH_ENV = SshEnv(ssh_auth_sock="/tmp/agent.sock", ssh_agent_pid="1")
COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"


def _role() -> Role:
    return Role(
        type="user",
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        service_id="autosecops-api",
    )


@asynccontextmanager
async def _fake_session_cm() -> AsyncIterator[MagicMock]:
    yield MagicMock()


def _ssh_context_factory(
    *, env: SshEnv | None = SSH_ENV, error: Exception | None = None
) -> Any:
    @asynccontextmanager
    async def fake_ssh_context(**_kwargs: Any) -> AsyncIterator[SshEnv | None]:
        if error is not None:
            raise error
        yield env

    return fake_ssh_context


def _patch_router_repo(monkeypatch: pytest.MonkeyPatch, origin: str) -> None:
    repo = MagicMock(id=uuid.uuid4(), origin=origin)
    service = MagicMock()
    service.get_repository_by_id = AsyncMock(return_value=repo)
    service.sync_repository = AsyncMock()
    monkeypatch.setattr(
        registry_repos_router, "RegistryReposService", MagicMock(return_value=service)
    )
    monkeypatch.setattr(
        registry_repos_router,
        "get_setting",
        AsyncMock(return_value=["git.example.test:2222"]),
    )
    monkeypatch.setattr(
        registry_repos_router, "get_async_session_context_manager", _fake_session_cm
    )


def test_git_url_remote_url_drops_ref() -> None:
    git_url = GitUrl(host="git.example.test", org="acme", repo="registry", ref="dev")
    assert git_url.remote_url() == "git+ssh://git@git.example.test/acme/registry.git"
    assert git_url.to_url() == "git+ssh://git@git.example.test/acme/registry.git@dev"


@pytest.mark.anyio
async def test_list_commits_fetches_remote_without_ref_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_router_repo(monkeypatch, ORIGIN)
    monkeypatch.setattr(registry_repos_router, "ssh_context", _ssh_context_factory())
    list_git_commits = AsyncMock(return_value=[])
    monkeypatch.setattr(registry_repos_router, "list_git_commits", list_git_commits)

    list_commits = unwrap(registry_repos_router.list_repository_commits)
    result = await list_commits(
        role=_role(),
        session=MagicMock(),
        repository_id=uuid.uuid4(),
        branch="release/v1",
        limit=10,
    )

    assert result == []
    list_git_commits.assert_awaited_once_with(
        REMOTE, env=SSH_ENV, branch="release/v1", limit=10
    )


@pytest.mark.anyio
async def test_list_commits_reports_unsupported_ssh_key_as_bad_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_router_repo(monkeypatch, ORIGIN)
    monkeypatch.setattr(
        registry_repos_router,
        "ssh_context",
        _ssh_context_factory(error=AutoSecOpsCredentialsError(INVALID_SSH_KEY_MESSAGE)),
    )

    list_commits = unwrap(registry_repos_router.list_repository_commits)
    with pytest.raises(HTTPException) as exc_info:
        await list_commits(
            role=_role(),
            session=MagicMock(),
            repository_id=uuid.uuid4(),
            branch="main",
            limit=10,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == INVALID_SSH_KEY_MESSAGE


@pytest.mark.anyio
async def test_sync_reports_unsupported_ssh_key_as_bad_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = MagicMock(id=uuid.uuid4(), origin=ORIGIN)
    service = MagicMock()
    service.get_repository_by_id = AsyncMock(return_value=repo)
    service.sync_repository = AsyncMock(
        side_effect=AutoSecOpsCredentialsError(INVALID_SSH_KEY_MESSAGE)
    )
    monkeypatch.setattr(
        registry_repos_router, "RegistryReposService", MagicMock(return_value=service)
    )

    sync = unwrap(registry_repos_router.sync_registry_repository)
    with pytest.raises(HTTPException) as exc_info:
        await sync(
            role=_role(),
            session=MagicMock(),
            repository_id=repo.id,
            sync_params=RegistryRepositorySync(),
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == INVALID_SSH_KEY_MESSAGE


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("ref", "resolved_ref", "expected_sha"),
    [
        pytest.param("release/v1", "release/v1", "f" * 40, id="branch"),
        pytest.param(None, None, "e" * 40, id="default-head"),
        pytest.param(COMMIT_SHA, None, COMMIT_SHA, id="pinned-commit"),
    ],
)
async def test_install_remote_repository_uses_ref_free_url(
    monkeypatch: pytest.MonkeyPatch,
    ref: str | None,
    resolved_ref: str | None,
    expected_sha: str,
) -> None:
    monkeypatch.setattr(
        registry_repository, "get_async_session_context_manager", _fake_session_cm
    )
    monkeypatch.setattr(registry_repository, "ssh_context", _ssh_context_factory())
    resolve = AsyncMock(return_value=expected_sha)
    install = AsyncMock()
    monkeypatch.setattr(registry_repository, "resolve_git_ref", resolve)
    monkeypatch.setattr(registry_repository, "install_remote_repository", install)

    git_url = GitUrl(host="git.example.test:2222", org="acme", repo="registry", ref=ref)
    repo = Repository(origin=git_url.to_url(), role=_role())
    sha = await repo._install_remote_repository(git_url=git_url)

    assert sha == expected_sha
    if ref == COMMIT_SHA:
        resolve.assert_not_awaited()
    else:
        resolve.assert_awaited_once_with(REMOTE, ref=resolved_ref, env=SSH_ENV)
    install.assert_awaited_once_with(REMOTE, commit_sha=expected_sha, env=SSH_ENV)


@pytest.mark.anyio
async def test_build_artifact_from_git_clones_without_ref_suffix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    commands: list[tuple[str, ...]] = []

    async def fake_exec(*cmd: str, **_kwargs: Any) -> MagicMock:
        commands.append(cmd)
        process = MagicMock(returncode=0)
        process.communicate = AsyncMock(return_value=(b"", b""))
        return process

    monkeypatch.setattr(registry_artifact.asyncio, "create_subprocess_exec", fake_exec)
    build_from_path = AsyncMock(return_value=MagicMock())
    monkeypatch.setattr(registry_artifact, "build_artifact_from_path", build_from_path)

    await registry_artifact.build_artifact_from_git(
        git_url=ORIGIN,
        commit_sha=COMMIT_SHA,
        env=SSH_ENV,
        output_dir=tmp_path,
    )

    clone_cmd = commands[0]
    assert clone_cmd[:4] == ("git", "clone", "--depth", "1")
    assert clone_cmd[4] == "ssh://git@git.example.test:2222/acme/registry.git"
    assert ("git", "fetch", "origin", COMMIT_SHA) in commands
