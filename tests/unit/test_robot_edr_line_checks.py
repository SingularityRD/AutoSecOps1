"""The ingest line checks give the same results in worker processes as inline."""

from __future__ import annotations

from concurrent.futures.process import BrokenProcessPool

import pytest

from autosecops.robot_edr import line_checks
from autosecops.robot_edr.crypto import finding_signing_message
from tests._robot_edr_utils import finding_sig, key, line, synth_finding

pytestmark = pytest.mark.anyio

SIZE = line_checks.POOL_MIN_LINES + 37


def _lines() -> list[bytes]:
    signer = key("line-checks")
    lines = []
    for n in range(SIZE):
        value = synth_finding(label=f"lc-{n}", compact=n % 2 == 0)
        lines.append(line(value, finding_sig(signer, value) if n % 3 else None))
    lines[7] = b"{not json"
    lines[11] = line(synth_finding(label="lc-v1").replace('"2.1.0"', '"1.0.0"', 1))
    lines[12] = line("{}")
    return lines


def _jobs(checked: list[line_checks.LineCheck]) -> list[line_checks.SignatureJob]:
    signer = key("line-checks")
    jobs = [
        line_checks.SignatureJob(
            public_key=signer.public,
            message=finding_signing_message(
                alg=c.sig.alg, key_id=c.sig.key_id, value=c.value
            ),
            signature=c.sig.sig,
        )
        for c in checked
        if isinstance(c, line_checks.CheckedLine) and c.sig is not None
    ]
    tampered = jobs[5]
    jobs[5] = line_checks.SignatureJob(
        public_key=tampered.public_key,
        message=tampered.message + b" ",
        signature=tampered.signature,
    )
    return jobs


@pytest.fixture
def two_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(line_checks, "CHECK_WORKERS", 2)


@pytest.mark.usefixtures("two_workers")
async def test_pool_results_equal_inline_results() -> None:
    lines = _lines()
    pooled = await line_checks.check_lines(lines)
    assert pooled == await line_checks._check_inline(lines)
    assert [c.line for c in pooled if not isinstance(c, line_checks.CheckedLine)] == [
        8,
        12,
        13,
    ]

    jobs = _jobs(pooled)
    assert len(jobs) >= line_checks.POOL_MIN_LINES // 2
    jobs = jobs * 2  # Enough signatures for the pool.
    verified = await line_checks.verify_signatures(jobs)
    assert verified == [
        line_checks.verify_strict(j.public_key, j.message, j.signature) for j in jobs
    ]
    assert verified.count(False) == 2


@pytest.mark.usefixtures("two_workers")
async def test_a_broken_pool_falls_back_to_inline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _broken() -> None:
        raise BrokenProcessPool("worker died")

    monkeypatch.setattr(line_checks, "_get_pool", _broken)
    lines = _lines()
    assert await line_checks.check_lines(lines) == await line_checks._check_inline(
        lines
    )
