"""Per-line framing, validation and case rendering (ingest steps 5.1-5.2).

These checks are pure CPU work: about 0.85 ms per 4 KiB finding, so a
1000-line batch spends most of a second here. :func:`check_lines` runs them
before the batch transaction and, for large batches, spreads them over a
small pool of worker processes so they run in parallel and the API event
loop stays responsive. The module imports only what the checks need, which
keeps worker start-up short.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
from collections.abc import Callable, Sequence
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, replace
from typing import Final

from autosecops.logger import logger
from autosecops.robot_edr import rendering
from autosecops.robot_edr.crypto import verify_strict
from autosecops.robot_edr.ndjson import FindingSignature, parse_line
from autosecops.robot_edr.types import LineErrorCode, LineRejection
from autosecops.robot_edr.validator import (
    FindingValidationError,
    UnsupportedContractError,
    ValidatedFinding,
    parse_and_validate,
)

MAX_VALUE_BYTES: Final = 256 * 1024
DETAIL_MAX: Final = 300

# Worker processes for large batches; 0 checks every batch in the API process.
# The API process only waits while the workers run, so they may use every CPU.
CHECK_WORKERS: Final = int(
    os.environ.get("AUTOSECOPS__ROBOT_EDR_CHECK_WORKERS")
    or (min(4, os.cpu_count() or 1) if (os.cpu_count() or 1) > 1 else 0)
)
# Below this many lines a batch is checked in the API process: shipping the
# lines to the workers would cost more than it saves.
POOL_MIN_LINES: Final = 200
_YIELD_EVERY: Final = 64

_pool: ProcessPoolExecutor | None = None


@dataclass(frozen=True, slots=True)
class CheckedLine:
    """A line that passed framing, validation and rendering.

    ``finding`` omits the validator's typed ``document`` projection, which
    ingest does not use, so results from worker processes stay small.
    """

    number: int
    sig: FindingSignature | None
    value: bytes
    finding: ValidatedFinding
    inputs: rendering.CaseInputs


type LineCheck = LineRejection | CheckedLine


@dataclass(frozen=True, slots=True)
class SignatureJob:
    """One per-finding signature to verify (step 5.4)."""

    public_key: bytes
    message: bytes
    signature: bytes


def reject(number: int, code: LineErrorCode, detail: str) -> LineRejection:
    """A line rejection with its detail cut to the contract's length."""
    return LineRejection(line=number, code=code, detail=detail[:DETAIL_MAX])


def check_line(number: int, raw: bytes) -> LineCheck:
    """Steps 5.1-5.2 for one line: framing, size, validation and rendering."""
    parsed = parse_line(number, raw)
    if isinstance(parsed, LineRejection):
        return parsed
    value = parsed.value.encode("utf-8")
    if len(value) > MAX_VALUE_BYTES:
        return reject(
            number,
            LineErrorCode.TOO_LARGE,
            f"decoded value is {len(value)} bytes; at most {MAX_VALUE_BYTES}",
        )
    try:
        finding = parse_and_validate(value)
        inputs = rendering.case_inputs(parsed.value)
    except UnsupportedContractError as exc:
        return reject(
            number,
            LineErrorCode.UNSUPPORTED_CONTRACT,
            f"contract version {exc.contract_version[:32]!r} is not 2.x",
        )
    except FindingValidationError as exc:
        return reject(
            number, LineErrorCode.INVALID_FINDING, "; ".join(exc.problems[:3])
        )
    except rendering.CaseRenderError as exc:
        return reject(number, LineErrorCode.INVALID_FINDING, str(exc))
    return CheckedLine(
        number=number,
        sig=parsed.sig,
        value=value,
        finding=replace(finding, document={}),
        inputs=inputs,
    )


def _get_pool() -> ProcessPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ProcessPoolExecutor(
            max_workers=CHECK_WORKERS,
            mp_context=multiprocessing.get_context("spawn"),
        )
    return _pool


def _discard_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.shutdown(wait=False, cancel_futures=True)
    _pool = None


async def _check_inline(lines: Sequence[bytes]) -> list[LineCheck]:
    checked: list[LineCheck] = []
    for index, raw in enumerate(lines):
        checked.append(check_line(index + 1, raw))
        if index % _YIELD_EVERY == _YIELD_EVERY - 1:
            await asyncio.sleep(0)  # Let other requests run.
    return checked


async def _in_pool[T, R](
    items: Sequence[T], task: Callable[[int, Sequence[T]], list[R]]
) -> list[R] | None:
    """Run ``task`` over one chunk of ``items`` per worker; ``None`` on failure.

    ``task`` receives each chunk's 0-based offset and the chunk.
    """
    size = -(-len(items) // CHECK_WORKERS)
    loop = asyncio.get_running_loop()
    try:
        pool = _get_pool()
        chunks = await asyncio.gather(
            *(
                loop.run_in_executor(pool, task, start, items[start : start + size])
                for start in range(0, len(items), size)
            )
        )
    except (BrokenProcessPool, OSError, RuntimeError) as exc:
        logger.warning(
            "Robot EDR ingest workers failed; continuing in process",
            error_type=type(exc).__name__,
        )
        _discard_pool()
        return None
    return [result for chunk in chunks for result in chunk]


def _use_pool(count: int) -> bool:
    return CHECK_WORKERS >= 1 and count >= POOL_MIN_LINES


async def verify_signatures(jobs: Sequence[SignatureJob]) -> list[bool]:
    """Verify per-finding signatures, in order (in the pool when many)."""
    if _use_pool(len(jobs)):
        verified = await _in_pool(jobs, verify_chunk)
        if verified is not None:
            return verified
    results: list[bool] = []
    for index, job in enumerate(jobs):
        results.append(verify_strict(job.public_key, job.message, job.signature))
        if index % _YIELD_EVERY == _YIELD_EVERY - 1:
            await asyncio.sleep(0)  # Let other requests run.
    return results


def verify_chunk(_offset: int, jobs: Sequence[SignatureJob]) -> list[bool]:
    """``verify_strict`` for each job (a worker-process task)."""
    return [verify_strict(j.public_key, j.message, j.signature) for j in jobs]


def check_chunk(offset: int, lines: Sequence[bytes]) -> list[LineCheck]:
    """:func:`check_line` for the lines after the first ``offset`` (a task)."""
    return [check_line(offset + i + 1, raw) for i, raw in enumerate(lines)]


async def check_lines(lines: Sequence[bytes]) -> list[LineCheck]:
    """Steps 5.1-5.2 for every line of a batch, in line order.

    Batches of at least ``POOL_MIN_LINES`` lines are split into one chunk per
    worker process; if the pool fails, the batch is checked in process.
    """
    if _use_pool(len(lines)):
        checked = await _in_pool(lines, check_chunk)
        if checked is not None:
            return checked
    return await _check_inline(lines)


def warm_pool() -> None:
    """Start the worker processes ahead of the first large batch."""
    if CHECK_WORKERS < 1 or _pool is not None:
        return
    pool = _get_pool()
    for _ in range(CHECK_WORKERS):
        pool.submit(check_chunk, 0, ())
