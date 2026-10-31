"""Validate execution prerequisites before a worker accepts tasks."""

import os
from collections.abc import Iterator
from contextlib import AbstractAsyncContextManager, contextmanager
from pathlib import Path
from typing import Protocol

from autosecops import config
from autosecops.temporal.worker_lifecycle import (
    WORKER_READY_FILE,
    ReadinessCheck,
    worker_readiness,
)


class WorkerReadiness(Protocol):
    """``worker_readiness`` bound to the executor's ready file."""

    def __call__(
        self, *, check: ReadinessCheck | None = None
    ) -> AbstractAsyncContextManager[None]: ...


def validate_execution_backend() -> None:
    """Reject missing nsjail prerequisites for explicitly sandboxed workers."""
    if not config.AUTOSECOPS__EXECUTOR_BACKEND.uses_nsjail:
        return

    nsjail = Path(config.AUTOSECOPS__SANDBOX_NSJAIL_PATH)
    if not nsjail.is_file() or not os.access(nsjail, os.X_OK):
        raise RuntimeError(
            "AUTOSECOPS__EXECUTOR_BACKEND=nsjail requires an executable nsjail "
            f"binary at {nsjail}. Check AUTOSECOPS__SANDBOX_NSJAIL_PATH."
        )

    rootfs = Path(config.AUTOSECOPS__SANDBOX_ROOTFS_PATH)
    if not rootfs.is_dir():
        raise RuntimeError(
            "AUTOSECOPS__EXECUTOR_BACKEND=nsjail requires a sandbox rootfs "
            f"directory at {rootfs}. Check AUTOSECOPS__SANDBOX_ROOTFS_PATH."
        )

    for directory in ("usr", "lib", "bin", "etc"):
        mount_source = rootfs / directory
        if not mount_source.is_dir():
            raise RuntimeError(
                "AUTOSECOPS__EXECUTOR_BACKEND=nsjail requires a sandbox rootfs "
                f"mount directory at {mount_source}. "
                "Check AUTOSECOPS__SANDBOX_ROOTFS_PATH."
            )

    python = rootfs / "usr/local/bin/python3"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeError(
            "AUTOSECOPS__EXECUTOR_BACKEND=nsjail requires an executable Python "
            f"binary at {python}. Check AUTOSECOPS__SANDBOX_ROOTFS_PATH."
        )


@contextmanager
def executor_lifecycle() -> Iterator[WorkerReadiness]:
    """Validate startup and provide readiness for the initialized worker.

    Call the yielded factory with the worker's ``ReadinessCheck`` and enter the
    resulting context after the Temporal worker, so readiness is removed before
    Temporal drains. The outer context also cleans up on startup failure.
    """
    path = WORKER_READY_FILE
    path.unlink(missing_ok=True)
    validate_execution_backend()
    try:

        def readiness(
            *, check: ReadinessCheck | None = None
        ) -> AbstractAsyncContextManager[None]:
            return worker_readiness(path, check=check)

        yield readiness
    finally:
        path.unlink(missing_ok=True)
