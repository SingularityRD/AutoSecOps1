"""Differential test: the Python bundle verifier against `robodr-blackbox verify`.

`tests/data/robot_edr/blackbox_verdicts/` holds crafted `RBBXBND1` bundles and
the verdict the reference Rust verifier reached on each (`craft.py` there
regenerates them). The Python verifier must be a strict subset: it may call a
bundle intact only where the reference verifier does, and it reports what it
refuses although the reference accepts it as not verifiable by AutoSecOps.

Set ``ROBODR_BLACKBOX_CLI`` to a built ``robodr-blackbox`` binary to re-run the
reference verifier on every fixture as well.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from autosecops_registry.integrations import robodr_evidence as ev

DATA = Path(__file__).parents[1] / "data" / "robot_edr" / "blackbox_verdicts"
VERDICTS: dict[str, dict[str, object]] = json.loads(
    (DATA / "verdicts.json").read_text()
)
KEY_FILES = sorted(DATA.glob("*.pub"))


def _python_report(name: str) -> ev.BundleReport:
    keyring = ev.parse_blackbox_keyring([p.read_text() for p in KEY_FILES])
    return ev.verify_bundle(
        (DATA / f"{name}.rbbx").read_bytes(),
        keyring,
        robot_id="ugv-x",
        signing_key_id="bb:ugv-x:1",
    )


def test_fixtures_cover_every_reviewed_case() -> None:
    assert {
        "segment_dropped_missing",
        "segment_dropped_unparseable",
        "recovery_quarantined_segment",
        "genesis_nonzero_seq",
        "key_rotation_without_reason",
    } <= set(VERDICTS)
    assert all((DATA / f"{name}.rbbx").is_file() for name in VERDICTS)


@pytest.mark.parametrize("name", sorted(VERDICTS))
def test_python_verifier_is_a_strict_subset_of_the_reference(name: str) -> None:
    expected = VERDICTS[name]
    report = _python_report(name)
    assert report.intact is expected["python_intact"], report.problems
    if report.intact:
        assert expected["rust"] == "intact"
        assert report.problems == []
    else:
        assert report.problems
    if not report.intact and expected["rust"] == "intact":
        # Legitimate to the reference verifier: not called tampering here.
        assert any("not verifiable by AutoSecOps" in p for p in report.problems)


@pytest.mark.skipif(
    not os.environ.get("ROBODR_BLACKBOX_CLI"),
    reason="set ROBODR_BLACKBOX_CLI to cross-check against the Rust verifier",
)
@pytest.mark.parametrize("name", sorted(VERDICTS))
def test_reference_verdicts_are_current(name: str) -> None:
    args = [
        os.environ["ROBODR_BLACKBOX_CLI"],
        "verify",
        str(DATA / f"{name}.rbbx"),
        "--device",
        "ugv-x",
        "--signing-key",
        "bb:ugv-x:1",
    ]
    for path in KEY_FILES:
        args += ["--keyring", str(path)]
    res = subprocess.run(args, capture_output=True, text=True, check=False)
    rust = {0: "intact", 1: "tamper"}.get(res.returncode, "error")
    assert rust == VERDICTS[name]["rust"], res.stdout + res.stderr
