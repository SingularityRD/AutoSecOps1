"""Tests for the unsandboxed registry sync subprocess wrapper."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from autosecops.exceptions import RegistryError, RegistrySyncContentError
from autosecops.registry.repository import Repository, RepositoryInstallation
from autosecops.registry.sync.schemas import SyncErrorCode, SyncResultError
from autosecops.registry.sync.subprocess import (
    fetch_actions_from_subprocess,
    registry_discovery_env,
)


def _mock_subprocess(mocker, *, stdout: str, returncode: int) -> None:
    process = mocker.Mock(returncode=returncode)
    process.communicate = mocker.AsyncMock(return_value=(stdout.encode(), b""))
    mocker.patch(
        "autosecops.registry.sync.subprocess.asyncio.create_subprocess_exec",
        mocker.AsyncMock(return_value=process),
    )


@pytest.mark.anyio
async def test_fetch_actions_raises_typed_error_for_error_code(mocker) -> None:
    _mock_subprocess(
        mocker,
        stdout=SyncResultError(
            error="No module named 'internal_registry'",
            error_code=SyncErrorCode.PACKAGE_NOT_FOUND,
        ).model_dump_json(),
        returncode=1,
    )

    with pytest.raises(RegistrySyncContentError) as exc_info:
        await fetch_actions_from_subprocess(
            origin="autosecops_registry", repository_id=uuid4()
        )

    assert exc_info.value.code == SyncErrorCode.PACKAGE_NOT_FOUND
    assert str(exc_info.value) == "No module named 'internal_registry'"


@pytest.mark.anyio
async def test_fetch_actions_raises_plain_error_without_error_code(mocker) -> None:
    _mock_subprocess(
        mocker,
        stdout=SyncResultError(error="git clone failed").model_dump_json(),
        returncode=1,
    )

    with pytest.raises(RegistryError) as exc_info:
        await fetch_actions_from_subprocess(
            origin="autosecops_registry", repository_id=uuid4()
        )

    assert type(exc_info.value) is RegistryError
    assert str(exc_info.value) == "git clone failed"


@pytest.mark.anyio
async def test_fetch_actions_reports_exit_code_for_unparseable_output(mocker) -> None:
    _mock_subprocess(mocker, stdout="not json", returncode=2)

    with pytest.raises(RegistryError, match="exited with code 2"):
        await fetch_actions_from_subprocess(
            origin="autosecops_registry", repository_id=uuid4()
        )


@pytest.mark.anyio
async def test_fetch_actions_maps_zero_exit_error_result(mocker) -> None:
    _mock_subprocess(
        mocker,
        stdout=json.dumps(
            {
                "error": "Failed to load template action from a.yml: bad",
                "error_code": "template_load_failed",
            }
        ),
        returncode=0,
    )

    with pytest.raises(RegistrySyncContentError) as exc_info:
        await fetch_actions_from_subprocess(
            origin="autosecops_registry", repository_id=uuid4()
        )

    assert exc_info.value.code == SyncErrorCode.TEMPLATE_LOAD_FAILED


SYNC_PLATFORM_SECRETS = {
    "AUTOSECOPS__DB_ENCRYPTION_KEY": "synthetic-encryption-key",
    "AUTOSECOPS__SERVICE_KEY": "synthetic-service-key",
    "AUTOSECOPS__SIGNING_SECRET": "synthetic-signing-secret",
    "AUTOSECOPS__DB_URI": "postgresql+psycopg://owner:synthetic-pass@db.test:5432/app",
    "AWS_SECRET_ACCESS_KEY": "synthetic-aws-secret",
    "TEMPORAL__API_KEY": "synthetic-temporal-key",
}

GIT_ORIGIN = "git+ssh://git@github.com/example-org/leak_probe.git"

LEAK_PROBE_MODULE = """
import json
import os
from pathlib import Path

from autosecops import config

Path({out!r}).write_text(
    json.dumps(
        {{
            "environ": dict(os.environ),
            "config": {{
                "encryption_key": config.AUTOSECOPS__DB_ENCRYPTION_KEY,
                "service_key": config.AUTOSECOPS__SERVICE_KEY,
                "signing_secret": config.AUTOSECOPS__SIGNING_SECRET,
                "db_uri": config.AUTOSECOPS__DB_URI,
            }},
        }}
    )
)
"""


@pytest.fixture
def platform_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in SYNC_PLATFORM_SECRETS.items():
        monkeypatch.setenv(name, value)


def _installed(mocker, *, package_name: str, commit_sha: str | None) -> None:
    mocker.patch.object(
        Repository,
        "install_from_origin",
        mocker.AsyncMock(
            return_value=RepositoryInstallation(
                package_name=package_name, commit_sha=commit_sha
            )
        ),
    )


@pytest.mark.usefixtures("platform_secrets")
def test_discovery_env_drops_platform_secrets() -> None:
    env = registry_discovery_env()

    for name in SYNC_PLATFORM_SECRETS:
        assert name not in env
    assert env["PATH"] == os.environ["PATH"]


@pytest.mark.anyio
@pytest.mark.usefixtures("platform_secrets")
async def test_fetch_actions_installs_in_caller_and_imports_without_secrets(
    mocker,
) -> None:
    commit_sha = "a" * 40
    _installed(mocker, package_name="leak_probe", commit_sha=commit_sha)
    process = mocker.Mock(returncode=0)
    process.communicate = mocker.AsyncMock(
        return_value=(
            json.dumps(
                {"actions": [], "commit_sha": commit_sha, "validation_errors": {}}
            ).encode(),
            b"",
        )
    )
    spawn = mocker.patch(
        "autosecops.registry.sync.subprocess.asyncio.create_subprocess_exec",
        mocker.AsyncMock(return_value=process),
    )

    result = await fetch_actions_from_subprocess(
        origin=GIT_ORIGIN, repository_id=uuid4(), validate=True
    )

    assert result.commit_sha == commit_sha
    args = list(spawn.await_args.args)
    assert args[args.index("--package-name") + 1] == "leak_probe"
    assert args[args.index("--commit-sha") + 1] == commit_sha
    assert "--validate" in args
    env = spawn.await_args.kwargs["env"]
    for name in SYNC_PLATFORM_SECRETS:
        assert name not in env


@pytest.mark.anyio
async def test_fetch_actions_reports_install_errors_before_spawning(mocker) -> None:
    mocker.patch.object(
        Repository,
        "install_from_origin",
        mocker.AsyncMock(side_effect=RegistryError("No SSH key found")),
    )
    spawn = mocker.patch(
        "autosecops.registry.sync.subprocess.asyncio.create_subprocess_exec"
    )

    with pytest.raises(RegistryError, match="No SSH key found"):
        await fetch_actions_from_subprocess(origin=GIT_ORIGIN, repository_id=uuid4())

    spawn.assert_not_called()


@pytest.mark.anyio
@pytest.mark.usefixtures("platform_secrets")
async def test_repository_code_cannot_read_platform_secrets(
    mocker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Import real repository code in the real discovery subprocess."""
    packages = tmp_path / "packages"
    package = packages / "leak_probe"
    package.mkdir(parents=True)
    out = tmp_path / "leak.json"
    (package / "__init__.py").write_text(LEAK_PROBE_MODULE.format(out=str(out)))
    monkeypatch.setenv(
        "PYTHONPATH", f"{packages}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"
    )
    commit_sha = "b" * 40
    _installed(mocker, package_name="leak_probe", commit_sha=commit_sha)

    result = await fetch_actions_from_subprocess(
        origin=GIT_ORIGIN, repository_id=uuid4(), timeout=120.0
    )

    assert result.commit_sha == commit_sha
    seen = json.loads(out.read_text())
    for name in SYNC_PLATFORM_SECRETS:
        assert name not in seen["environ"], name
    leaked = json.dumps(seen)
    for value in SYNC_PLATFORM_SECRETS.values():
        assert value not in leaked
    assert not seen["config"]["encryption_key"]
    assert not seen["config"]["service_key"]
    assert not seen["config"]["signing_secret"]
