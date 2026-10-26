"""Regenerate the RBBXBND1 differential fixtures and their Rust verdicts.

Usage (from the repository root, with a built ``robodr-blackbox`` CLI):

    uv run python tests/data/robot_edr/blackbox_verdicts/craft.py \
        tests/data/robot_edr/blackbox_verdicts /path/to/robodr-blackbox

Every bundle is signed with fixed test-only Ed25519 keys (private bytes
0..31 and 32..63), so the output is deterministic. ``verdicts.json`` records
what the reference verifier (``robodr-blackbox verify BUNDLE``) said about
each bundle, and the verdict AutoSecOps must reach: ``python_intact`` may
be ``true`` only where ``rust`` is ``intact`` (the Python verifier is a
strict subset of the reference one).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from autosecops_registry.integrations import robodr_evidence as ev
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DEVICE = "ugv-x"
KEYS = {
    "bb:ugv-x:1": Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
    "bb:ugv-x:2": Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))),
}
K1, K2 = "bb:ugv-x:1", "bb:ugv-x:2"
IDENTITY = {
    "device_id": DEVICE,
    "boot_id": "boot-1",
    "key_id": K1,
    "algorithm": "ed25519",
    "created_wall_ns": 1_000,
}
_ident = ev._identity_from(IDENTITY)  # pyright: ignore[reportPrivateUsage]
assert _ident is not None
CHAIN = _ident.chain_id()


def key_file(key_id: str) -> str:
    public = KEYS[key_id].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return json.dumps(
        {
            "format": "robodr-blackbox-key/v2",
            "kind": "public",
            "algorithm": "ed25519",
            "key_id": key_id,
            "public_hex": public.hex(),
        }
    )


def compact(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


def record(
    seq: int, kind: int, payload: bytes, prev: bytes, signer: str
) -> tuple[bytes, bytes]:
    body = bytes([1]) + CHAIN + seq.to_bytes(8, "big")
    body += (1_000 + seq).to_bytes(8, "big") + (1_000 + seq).to_bytes(8, "big")
    body += bytes([0, kind, 0])
    body += len(payload).to_bytes(4, "big") + payload + prev
    digest = hashlib.sha256(ev._RECORD_DOMAIN + body).digest()  # pyright: ignore[reportPrivateUsage]
    sig = KEYS[signer].sign(ev._SIG_DOMAIN + digest)  # pyright: ignore[reportPrivateUsage]
    body += digest + len(sig).to_bytes(2, "big") + sig
    return b"RBF1" + len(body).to_bytes(4, "big") + body, digest


Rec = tuple[int, int, bytes] | tuple[int, int, bytes, str]


def bundle(recs: list[Rec], identity_json: bytes | None = None) -> bytes:
    frames, prev = b"", bytes(32)
    for item in recs:
        seq, kind, payload = item[0], item[1], item[2]
        signer = item[3] if len(item) == 4 else K1
        frame, prev = record(seq, kind, payload, prev, signer)
        frames += frame
    idj = compact(IDENTITY) if identity_json is None else identity_json
    return (
        b"RBBXBND1"
        + len(idj).to_bytes(4, "big")
        + idj
        + b"\x00"
        + len(frames).to_bytes(8, "big")
        + frames
    )


GENESIS = compact({"identity": IDENTITY, "recorder_version": "t", "format_version": 1})
NOTE = compact({"text": "x"})


def dropped(*, missing: bool) -> bytes:
    return compact(
        {
            "segment_index": 3,
            "reason": "missing" if missing else "exported",
            "first_seq": None,
            "last_seq": None,
            "last_hash": None,
            "records": 0,
            "exported": not missing,
            "missing": missing,
        }
    )


def recovery(**extra: Any) -> bytes:
    return compact(
        {
            "segment_index": 0,
            "offset": 0,
            "discarded_bytes": 10,
            "discarded_sha256": "00" * 32,
            "reason": "torn tail",
            "quarantine_file": None,
            **extra,
        }
    )


def rotation(*, reason: bool) -> bytes:
    payload: dict[str, Any] = {
        "from": {"key_id": K1, "algorithm": "ed25519"},
        "to": {"key_id": K2, "algorithm": "ed25519"},
    }
    if reason:
        payload["reason"] = "scheduled"
    return compact(payload)


def segment_start(signing_key: str) -> bytes:
    return compact(
        {
            "identity": IDENTITY,
            "segment_index": 1,
            "boot_id": "boot-1",
            "signing_key": {"key_id": signing_key, "algorithm": "ed25519"},
        }
    )


_dup_recovery = (
    recovery(quarantined_segment=True)[:-1] + b',"quarantined_segment":false}'
)
_dup_identity = b'{"device_id":"ugv-y",' + compact(IDENTITY)[1:]
_other_identity = compact(
    {
        "identity": {**IDENTITY, "boot_id": "boot-2"},
        "recorder_version": "t",
        "format_version": 1,
    }
)

# name: (records, identity JSON override, AutoSecOps verdict)
CASES: dict[str, tuple[list[Rec], bytes | None, bool]] = {
    "baseline": ([(0, 0, GENESIS), (1, 18, NOTE)], None, True),
    "segment_dropped_exported": (
        [(0, 0, GENESIS), (1, 5, dropped(missing=False))],
        None,
        True,
    ),
    "segment_dropped_missing": (
        [(0, 0, GENESIS), (1, 5, dropped(missing=True))],
        None,
        False,
    ),
    "segment_dropped_unparseable": (
        [(0, 0, GENESIS), (1, 5, b"not json")],
        None,
        False,
    ),
    "recovery_crash_plausible": ([(0, 0, GENESIS), (1, 4, recovery())], None, True),
    "recovery_not_crash_plausible": (
        [(0, 0, GENESIS), (1, 4, recovery(crash_plausible=False))],
        None,
        False,
    ),
    "recovery_quarantined_segment": (
        [(0, 0, GENESIS), (1, 4, recovery(quarantined_segment=True))],
        None,
        False,
    ),
    "recovery_duplicate_keys": ([(0, 0, GENESIS), (1, 4, _dup_recovery)], None, False),
    "genesis_nonzero_seq": ([(0, 0, GENESIS), (1, 0, GENESIS)], None, False),
    "genesis_identity_mismatch": ([(0, 0, _other_identity)], None, False),
    "truncation_detected": (
        [(0, 0, GENESIS), (1, 8, compact({"head_seq": 0, "skipped_seqs": [1, 4]}))],
        None,
        False,
    ),
    "key_rotation": (
        [(0, 0, GENESIS), (1, 9, rotation(reason=True)), (2, 18, NOTE, K2)],
        None,
        True,
    ),
    "key_rotation_without_reason": (
        [(0, 0, GENESIS), (1, 9, rotation(reason=False)), (2, 18, NOTE, K2)],
        None,
        False,
    ),
    "segment_start_key_switch": (
        [(0, 0, GENESIS), (1, 1, segment_start(K2), K2)],
        None,
        False,
    ),
    "identity_utf16": (
        [(0, 0, GENESIS), (1, 18, NOTE)],
        json.dumps(IDENTITY).encode("utf-16"),
        False,
    ),
    "identity_duplicate_keys": ([(0, 0, GENESIS), (1, 18, NOTE)], _dup_identity, False),
    "empty": ([], None, False),
}


def rust_verdict(cli: str, out: Path, path: Path) -> str:
    args = [cli, "verify", str(path), "--device", DEVICE, "--signing-key", K1]
    for key_id in KEYS:
        args += ["--keyring", str(out / f"{key_id.replace(':', '_')}.pub")]
    res = subprocess.run(args, capture_output=True, text=True, check=False)
    return {0: "intact", 1: "tamper"}.get(res.returncode, "error")


def main() -> None:
    out, cli = Path(sys.argv[1]), sys.argv[2]
    for key_id in KEYS:
        (out / f"{key_id.replace(':', '_')}.pub").write_text(key_file(key_id))
    verdicts: dict[str, dict[str, Any]] = {}
    for name, (recs, identity_json, python_intact) in CASES.items():
        path = out / f"{name}.rbbx"
        path.write_bytes(bundle(recs, identity_json))
        rust = rust_verdict(cli, out, path)
        assert rust == "intact" or not python_intact, name
        verdicts[name] = {"rust": rust, "python_intact": python_intact}
    (out / "verdicts.json").write_text(json.dumps(verdicts, indent=2) + "\n")


if __name__ == "__main__":
    main()
