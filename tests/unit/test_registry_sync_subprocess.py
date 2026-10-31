"""Tests for the unsandboxed registry sync subprocess wrapper."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from autosecops.exceptions import RegistryError, RegistrySyncContentError
from autosecops.registry.dependencies import RegistryDependencyConflictError
from autosecops.registry.repository import Repository, RepositoryInstallation
from autosecops.registry.sync.schemas import SyncErrorCode, SyncResultError
from autosecops.registry.sync.subprocess import (
    MIN_DISCOVERY_TIMEOUT_SECONDS,
    fetch_actions_from_subprocess,
    registry_discovery_env,
)


def _mock_subprocess(mocker, *, stdout: str, returncode: int):
    process = mocker.Mock(returncode=returncode)
    mocker.patch(
        "autosecops.registry.sync.subprocess.communicate_process_group",
        mocker.AsyncMock(return_value=(stdout.encode(), b"")),
    )
    return mocker.patch(
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
import sys
from pathlib import Path

from autosecops import config


def _read(path):
    try:
        return Path(path).read_bytes().decode(errors="replace")
    except OSError as exc:
        return "denied:" + type(exc).__name__


Path({out!r}).write_text(
    json.dumps(
        {{
            "environ": dict(os.environ),
            "parent_environ": _read(f"/proc/{{os.getppid()}}/environ"),
            "sys_path": sys.path,
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


@pytest.fixture(autouse=True)
def validation_setting(mocker):
    """Keep the org setting lookup off the database."""
    return mocker.patch(
        "autosecops.registry.sync.subprocess.get_setting",
        mocker.AsyncMock(return_value=False),
    )


@pytest.fixture
def platform_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in SYNC_PLATFORM_SECRETS.items():
        monkeypatch.setenv(name, value)


def _installed(
    mocker,
    *,
    package_name: str,
    commit_sha: str | None,
    module_source: str | None = None,
):
    """Stand in for the trusted install, writing the package into the target."""

    async def install(*, commit_sha: str | None = None, target_dir: Path):
        del commit_sha
        if module_source is not None:
            package = target_dir / package_name
            package.mkdir()
            (package / "__init__.py").write_text(module_source)
        return RepositoryInstallation(
            package_name=package_name, commit_sha=resolved, site_dir=target_dir
        )

    resolved = commit_sha
    return mocker.patch.object(
        Repository, "install_from_origin", mocker.AsyncMock(side_effect=install)
    )


@pytest.mark.usefixtures("platform_secrets")
def test_discovery_env_drops_platform_secrets() -> None:
    env = registry_discovery_env()

    for name in SYNC_PLATFORM_SECRETS:
        assert name not in env
    assert "PATH" in env


@pytest.mark.anyio
@pytest.mark.usefixtures("platform_secrets")
async def test_fetch_actions_installs_in_caller_and_imports_without_secrets(
    mocker,
) -> None:
    commit_sha = "a" * 40
    install = _installed(mocker, package_name="leak_probe", commit_sha=commit_sha)
    spawn = _mock_subprocess(
        mocker,
        stdout=json.dumps(
            {"actions": [], "commit_sha": commit_sha, "validation_errors": {}}
        ),
        returncode=0,
    )

    result = await fetch_actions_from_subprocess(
        origin=GIT_ORIGIN, repository_id=uuid4(), validate=True
    )

    assert result.commit_sha == commit_sha
    target_dir = install.await_args.kwargs["target_dir"]
    # Each sync gets its own install target, removed afterwards.
    assert target_dir.name.startswith("autosecops-registry-")
    assert not target_dir.exists()
    args = list(spawn.await_args.args)
    assert args[1:3] == ["-s", "-P"]
    assert args[args.index("--package-name") + 1] == "leak_probe"
    assert args[args.index("--site-dir") + 1] == str(target_dir)
    assert args[args.index("--commit-sha") + 1] == commit_sha
    assert "--validate" in args
    assert spawn.await_args.kwargs["start_new_session"] is True
    env = spawn.await_args.kwargs["env"]
    for name in SYNC_PLATFORM_SECRETS:
        assert name not in env


@pytest.mark.anyio
async def test_fetch_actions_reads_registry_validation_setting(
    mocker, validation_setting
) -> None:
    validation_setting.return_value = True
    _installed(mocker, package_name="leak_probe", commit_sha=None)
    spawn = _mock_subprocess(
        mocker,
        stdout=json.dumps({"actions": [], "commit_sha": None, "validation_errors": {}}),
        returncode=0,
    )

    await fetch_actions_from_subprocess(origin=GIT_ORIGIN, repository_id=uuid4())

    assert "--validate" in spawn.await_args.args
    assert validation_setting.await_args.args == ("app_registry_validation_enabled",)


@pytest.mark.anyio
async def test_fetch_actions_keeps_typed_install_errors(mocker) -> None:
    conflict = RegistryDependencyConflictError("Failed to install: conflict")
    mocker.patch.object(
        Repository, "install_from_origin", mocker.AsyncMock(side_effect=conflict)
    )
    spawn = mocker.patch(
        "autosecops.registry.sync.subprocess.asyncio.create_subprocess_exec"
    )

    with pytest.raises(RegistryDependencyConflictError) as exc_info:
        await fetch_actions_from_subprocess(origin=GIT_ORIGIN, repository_id=uuid4())

    assert exc_info.value is conflict
    spawn.assert_not_called()


@pytest.mark.anyio
async def test_fetch_actions_does_not_relabel_inner_timeouts(mocker) -> None:
    mocker.patch.object(
        Repository,
        "install_from_origin",
        mocker.AsyncMock(side_effect=TimeoutError("git ls-remote timed out")),
    )

    with pytest.raises(RegistryError) as exc_info:
        await fetch_actions_from_subprocess(origin=GIT_ORIGIN, repository_id=uuid4())

    assert "git ls-remote timed out" in str(exc_info.value)
    assert "Registry install timed out" not in str(exc_info.value)


@pytest.mark.anyio
async def test_fetch_actions_reports_untyped_install_errors_as_registry_errors(
    mocker,
) -> None:
    failure = RuntimeError("Failed to install repository: fatal: bad ref")
    mocker.patch.object(
        Repository, "install_from_origin", mocker.AsyncMock(side_effect=failure)
    )

    with pytest.raises(RegistryError, match="fatal: bad ref") as exc_info:
        await fetch_actions_from_subprocess(origin=GIT_ORIGIN, repository_id=uuid4())

    assert exc_info.value.__cause__ is failure


@pytest.mark.anyio
async def test_fetch_actions_reports_install_deadline(mocker) -> None:
    async def slow_install(**_kwargs):
        await asyncio.sleep(10)

    mocker.patch.object(
        Repository, "install_from_origin", mocker.AsyncMock(side_effect=slow_install)
    )

    with pytest.raises(RegistryError, match="Registry install timed out"):
        await fetch_actions_from_subprocess(
            origin=GIT_ORIGIN, repository_id=uuid4(), timeout=0.05
        )


@pytest.mark.anyio
async def test_discovery_keeps_a_minimum_budget(mocker) -> None:
    _installed(mocker, package_name="leak_probe", commit_sha=None)
    _mock_subprocess(
        mocker,
        stdout=json.dumps({"actions": [], "commit_sha": None, "validation_errors": {}}),
        returncode=0,
    )
    communicate = mocker.patch(
        "autosecops.registry.sync.subprocess.communicate_process_group",
        mocker.AsyncMock(
            return_value=(
                json.dumps(
                    {"actions": [], "commit_sha": None, "validation_errors": {}}
                ).encode(),
                b"",
            )
        ),
    )

    await fetch_actions_from_subprocess(
        origin=GIT_ORIGIN, repository_id=uuid4(), timeout=0.001
    )

    assert communicate.await_args.kwargs["timeout"] == MIN_DISCOVERY_TIMEOUT_SECONDS


@pytest.mark.anyio
@pytest.mark.usefixtures("platform_secrets")
async def test_repository_code_cannot_read_platform_secrets(
    mocker, tmp_path: Path
) -> None:
    """Import real repository code in the real discovery subprocess."""
    out = tmp_path / "leak.json"
    commit_sha = "b" * 40
    install = _installed(
        mocker,
        package_name="leak_probe",
        commit_sha=commit_sha,
        module_source=LEAK_PROBE_MODULE.format(out=str(out)),
    )

    result = await fetch_actions_from_subprocess(
        origin=GIT_ORIGIN, repository_id=uuid4(), timeout=120.0
    )

    assert result.commit_sha == commit_sha
    seen = json.loads(out.read_text())
    for name in SYNC_PLATFORM_SECRETS:
        assert name not in seen["environ"], name
    leaked = json.dumps(
        {key: value for key, value in seen.items() if key != "parent_environ"}
    )
    for value in SYNC_PLATFORM_SECRETS.values():
        assert value not in leaked
    assert not seen["config"]["encryption_key"]
    assert not seen["config"]["service_key"]
    assert not seen["config"]["signing_secret"]
    # The package was imported from this sync's own install target only.
    assert str(install.await_args.kwargs["target_dir"]) in seen["sys_path"]
    if os.geteuid() != 0:
        # Root keeps CAP_SYS_PTRACE; tests/unit/test_process_isolation.py
        # covers this as an unprivileged user.
        assert seen["parent_environ"].startswith("denied:")
