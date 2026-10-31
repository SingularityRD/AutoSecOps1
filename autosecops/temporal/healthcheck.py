"""Container probe for Temporal worker liveness and readiness.

Temporal workers serve no HTTP, so they report health through two marker files
that their event loop keeps fresh (see ``autosecops.temporal.worker_lifecycle``):

- ``worker-alive`` is touched every ``HEALTH_REFRESH_INTERVAL_SECONDS`` while the
  worker's event loop runs. A stale file means the loop is blocked or the
  process is wedged, so the container should be restarted (liveness).
- ``worker-ready`` exists while the Temporal worker is running, and is touched
  each interval only when the worker is still polling and the Temporal frontend
  answers a health check. A missing or stale file means the worker is not
  taking tasks (readiness).

Run ``python -m autosecops.temporal.healthcheck live`` or ``... ready`` from a
Compose healthcheck, Kubernetes exec probe, or ECS container health check. The
probe imports only the standard library so it stays cheap to run every few
seconds, and exits 0 when healthy and 1 otherwise.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal

# Keep these paths off persistent volumes: container replacement must clear them.
# The Helm chart mounts an in-memory emptyDir here so the markers stay writable
# with a read-only root filesystem; a stale mtime guards against a marker left
# by a previous container in the same pod.
HEALTH_DIR: Final = Path("/var/run/autosecops")
WORKER_ALIVE_FILE: Final = HEALTH_DIR / "worker-alive"
WORKER_READY_FILE: Final = HEALTH_DIR / "worker-ready"

HEALTH_REFRESH_INTERVAL_SECONDS: Final = 10.0
"""How often a worker refreshes its marker files."""

DEFAULT_LIVE_MAX_AGE_SECONDS: Final = 120.0
"""Liveness tolerates a long stall before reporting a wedged loop.

A failed liveness probe restarts the container and aborts every activity on
it, so a slow synchronous call in an async activity must not trip it. Kubernetes
adds ``failureThreshold x periodSeconds`` on top of this limit.
"""

DEFAULT_READY_MAX_AGE_SECONDS: Final = 30.0
"""Readiness drops after a couple of missed refreshes."""

type ProbeKind = Literal["live", "ready"]


def file_age_seconds(path: Path, *, now: float | None = None) -> float | None:
    """Return seconds since ``path`` was last touched, or ``None`` if unreadable."""
    try:
        modified = path.stat().st_mtime
    except OSError:
        return None
    current = time.time() if now is None else now
    # A clock step backwards can put the mtime in the future; treat it as fresh.
    return max(0.0, current - modified)


def probe_failure(
    kind: ProbeKind,
    *,
    max_age_seconds: float,
    alive_path: Path = WORKER_ALIVE_FILE,
    ready_path: Path = WORKER_READY_FILE,
    now: float | None = None,
) -> str | None:
    """Return why the probe fails, or ``None`` when the worker is healthy."""
    path = alive_path if kind == "live" else ready_path
    age = file_age_seconds(path, now=now)
    if age is None:
        return f"{path} is missing"
    if age > max_age_seconds:
        return f"{path} is stale ({age:.0f}s old, limit {max_age_seconds:.0f}s)"
    return None


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m autosecops.temporal.healthcheck",
        description="Check Temporal worker liveness or readiness.",
    )
    parser.add_argument("kind", choices=("live", "ready"))
    parser.add_argument(
        "--max-age",
        type=float,
        default=None,
        help=(
            "Maximum marker file age in seconds (default "
            f"{DEFAULT_LIVE_MAX_AGE_SECONDS:.0f} for live, "
            f"{DEFAULT_READY_MAX_AGE_SECONDS:.0f} for ready)."
        ),
    )
    args = parser.parse_args(argv)
    if args.max_age is not None and args.max_age <= HEALTH_REFRESH_INTERVAL_SECONDS:
        parser.error(
            "--max-age must be greater than the "
            f"{HEALTH_REFRESH_INTERVAL_SECONDS:.0f}s refresh interval"
        )
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Run the probe and return its process exit code."""
    args = _parse_args(argv)
    kind: ProbeKind = args.kind
    max_age = args.max_age
    if max_age is None:
        max_age = (
            DEFAULT_LIVE_MAX_AGE_SECONDS
            if kind == "live"
            else DEFAULT_READY_MAX_AGE_SECONDS
        )
    if failure := probe_failure(kind, max_age_seconds=max_age):
        print(f"worker not {kind}: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
