"""Protect a platform process from inspection by its own children.

Direct-mode actions run as the same Linux user as the executor worker. Linux
lets a process read ``/proc/<pid>/environ`` and ``/proc/<pid>/mem`` of, or
ptrace, any dumpable process with the same user ID, so action code could read
the worker's environment and memory, which hold every platform credential.
Clearing the dumpable flag makes those ``/proc`` files root-owned and refuses
same-user ptrace access without ``CAP_SYS_PTRACE``. It also disables core dumps
of the worker. The flag is per process and resets on ``execve``, so it does not
change how children such as action subprocesses behave.

This module uses only the standard library so it can run first in an
entrypoint, before anything else starts.
"""

from __future__ import annotations

import ctypes
import os
import sys

_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4


def _prctl(option: int, arg: int = 0) -> int:
    """Call ``prctl(2)`` and raise ``OSError`` when it fails."""
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    result = prctl(option, arg, 0, 0, 0)
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return result


def is_process_dumpable() -> bool:
    """Return whether this process is dumpable (Linux only).

    Returns:
        True when same-user processes may inspect this one through ``/proc``.
        Always True outside Linux, where the flag does not exist.
    """
    if not sys.platform.startswith("linux"):
        return True
    return _prctl(_PR_GET_DUMPABLE) != 0


def protect_process_from_inspection() -> bool:
    """Make this process non-dumpable so same-user code cannot inspect it.

    Call it once at the start of a worker that runs untrusted code as its own
    user, before it reads secrets or starts children.

    Returns:
        True when the protection is in place, False outside Linux.

    Raises:
        RuntimeError: If Linux refuses to clear the dumpable flag.
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        _prctl(_PR_SET_DUMPABLE, 0)
    except OSError as exc:
        raise RuntimeError(
            "Could not protect the worker process from same-user inspection"
        ) from exc
    if is_process_dumpable():
        raise RuntimeError("The worker process is still dumpable after PR_SET_DUMPABLE")
    return True
