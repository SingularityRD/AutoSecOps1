"""Helpers for RoboDR ingest tests: keys, signed batches, synthetic findings.

`tests/data/robot_edr/producer_findings.json` holds record values produced by
the RoboDR reference producer (`robodr_ocsf::FindingBuilder` + `to_json`,
findings contract 2.1.0), byte for byte, including the hostile-name corpus of
`crates/robodr-ocsf/tests/findings.rs` (`INJECTIONS`). Synthetic findings are
derived from those values by rewriting identity fields consistently; the
validator does not recompute the producer's id hashes, so they stay valid.

`robodr-finding.example.json` is a verbatim copy of the RoboDR contract's
golden example (`docs/contracts/robodr-finding.example.json`, contract 2.1.0).
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from autosecops.robot_edr.crypto import (
    batch_signing_message,
    derive_key_id,
    finding_signing_message,
)

DATA_DIR = Path(__file__).parent / "data" / "robot_edr"
NDJSON = "application/x-ndjson"


@cache
def producer_values() -> dict[str, str]:
    """Producer-emitted record values by vector name."""
    entries = json.loads((DATA_DIR / "producer_findings.json").read_text())
    return {e["name"]: e["value"] for e in entries}


@cache
def producer_entries() -> list[dict[str, Any]]:
    return json.loads((DATA_DIR / "producer_findings.json").read_text())


@dataclass(frozen=True)
class RoboKey:
    """An Ed25519 key pair from a fixed seed."""

    seed: bytes

    @property
    def private(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.seed)

    @property
    def public(self) -> bytes:
        return self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        return derive_key_id(self.public)

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)


def key(label: str) -> RoboKey:
    """A deterministic test key per label."""
    return RoboKey(hashlib.sha256(label.encode()).digest())


def line(value: str, sig: dict[str, str] | None = None) -> bytes:
    """One NDJSON line object (value carried verbatim as a JSON string)."""
    return json.dumps({"value": value, "sig": sig}, separators=(",", ":")).encode()


def finding_sig(
    signer: RoboKey, value: str, key_id: str | None = None
) -> dict[str, str]:
    """The per-finding `sig` object over the exact value bytes."""
    kid = key_id or signer.key_id
    message = finding_signing_message(alg="ed25519", key_id=kid, value=value.encode())
    return {"alg": "ed25519", "key_id": kid, "sig": signer.sign(message).hex()}


def body_of(lines: list[bytes], *, final_lf: bool = True) -> bytes:
    return b"\n".join(lines) + (b"\n" if final_lf and lines else b"")


def signed_headers(
    signer: RoboKey,
    batch_id: str,
    body: bytes,
    *,
    timestamp_ms: int | None = None,
    key_id: str | None = None,
) -> dict[str, str]:
    """`X-RoboDR-*` headers for a batch signed by ``signer``."""
    ts = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    kid = key_id or signer.key_id
    message = batch_signing_message(
        key_id=kid, batch_id=batch_id, timestamp_ms=ts, body=body
    )
    return {
        "Content-Type": NDJSON,
        "X-RoboDR-Key-Id": kid,
        "X-RoboDR-Batch-Id": batch_id,
        "X-RoboDR-Timestamp": str(ts),
        "X-RoboDR-Signature": signer.sign(message).hex(),
    }


_SEVERITIES = {
    "low": (2, "Low"),
    "medium": (3, "Medium"),
    "high": (4, "High"),
    "critical": (5, "Critical"),
}


def _rfc3339_ms(ms: int) -> str:
    secs, millis = divmod(ms, 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(secs)) + f".{millis:03d}Z"


def synth_finding(
    *,
    robot_id: str = "ugv-001",
    finding_hex: str | None = None,
    count: int = 1,
    severity: str | None = None,
    template: str = "r1_critical_c1",
    label: str = "",
) -> str:
    """A valid 2.x value derived from a producer vector.

    Args:
        robot_id: Robot named by the finding.
        finding_hex: 32 hex digits of the finding id (default: from ``label``).
        count: Occurrence count (1 = Create, otherwise Update).
        severity: Override the producer severity.
        template: Producer vector to start from.
        label: Seed for a deterministic finding id.
    """
    doc = json.loads(producer_values()[template])
    finding_hex = (
        finding_hex or hashlib.sha256(f"{robot_id}|{label}".encode()).hexdigest()[:32]
    )
    finding_id = f"rf1-{finding_hex}"
    first = doc["ocsf"]["finding_info"]["first_seen_time"]
    last = first + (count - 1) * 1000
    event = hashlib.sha256(f"{finding_id}|{last}|{count}".encode()).hexdigest()[:32]
    activity = (1, "Create") if count == 1 else (2, "Update")

    doc["finding_id"] = finding_id
    doc["external_id"] = f"{robot_id}:{finding_id}"
    doc["timestamp"] = _rfc3339_ms(last)
    ocsf = doc["ocsf"]
    ocsf["activity_id"], ocsf["activity_name"] = activity
    ocsf["type_uid"] = 200400 + activity[0]
    ocsf["type_name"] = f"Detection Finding: {activity[1]}"
    ocsf["time"] = last
    ocsf["count"] = count
    ocsf["metadata"]["uid"] = f"re1-{event}"
    ocsf["finding_info"]["uid"] = finding_id
    ocsf["finding_info"]["last_seen_time"] = last
    ocsf["device"]["uid"] = robot_id
    ocsf["device"]["name"] = robot_id
    for ctx in (doc["entity_context"], ocsf["unmapped"]["robodr"]):
        ctx["robot"]["id"] = robot_id
        ctx["occurrence_count"] = count
    if severity is not None:
        doc["severity"] = severity
        ocsf["severity_id"], ocsf["severity"] = _SEVERITIES[severity]
    return json.dumps(copy.deepcopy(doc), separators=(",", ":"))
