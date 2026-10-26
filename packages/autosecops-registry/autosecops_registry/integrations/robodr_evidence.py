"""RoboDR black-box evidence: manifest signatures and bundle verification.

Pure functions for the evidence API of `robodr.control-plane` v2 (§11): no
I/O, no platform context. `robodr_control_plane` downloads exports with them,
and the AutoSecOps API re-checks a manifest with them before it stores one.

Verification (§11.6)
--------------------

1. Answer signatures are checked by the transport (`robodr_control_plane`).
2. `verify_manifest_signature`: `X-RoboDR-Manifest-Signature` over
   ``robodr-evidence-manifest/v1 LF <hex SHA-256 of the manifest bytes>``
   with the robot's finding key; `parse_manifest` then checks `kind`,
   `version`, `api`, `robot_id`, `export_id` and the bundle layout, and
   `selector_matches` that the selection is the one asked for.
3. `check_chunk` / `assemble_bundle`: every chunk's length and SHA-256, then
   the whole bundle's.
4. `verify_bundle`: the `RBBXBND1` bundle under the robot's black-box
   keyring, as `robodr_blackbox::Bundle::verify_with_key(keyring, None,
   Some(robot_id), Some(&manifest.chain.signing_key))` does.
5. `check_report_against_manifest`: seqs, count, last hash, chain id, anchor
   and every referenced record.

`verify_bundle` is a strict subset of `robodr_blackbox::verify`: it accepts
only a bundle that the reference verifier reports intact *and* that has no
malformed frame, no gap, no foreign or reordered record, no recorded
truncation, segment loss or quarantine, no unexplained recovery, and no key
it cannot prove (a key switch is followed only through a signed
`KeyRotation` from the current key). Every control record (genesis, segment
start, recovery, segment drop, key rotation) must carry a payload it parses
as strictly as the reference does (UTF-8, no duplicate keys, the fields the
reference reads present and well-typed); where the reference would merely
skip a payload it cannot parse, AutoSecOps refuses the bundle as "not
verifiable by AutoSecOps" rather than guess. Anything else is reported as
not verified, never as verified: a "verified" result means steps 2-5 passed
(step 1 is the transport's). `tests/data/robot_edr/blackbox_verdicts` holds
the differential fixtures that pin this against the reference CLI.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from autosecops_registry.integrations.robodr import (
    ed25519_verify_strict,
    parse_public_key_hex,
)

API_VERSION = "robodr-control-plane/v2"
MANIFEST_KIND = "robodr.evidence_manifest"
MANIFEST_VERSION = 1
MANIFEST_DOMAIN = "robodr-evidence-manifest/v1"
BUNDLE_FORMAT = "RBBXBND1"
MAX_CHUNKS = 4096
MAX_CHUNK_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONTEXT_RECORDS = 1024
DEFAULT_CONTEXT_RECORDS = 16
MAX_EVIDENCE_LINKS = 64
MAX_TIME_RANGE_MS = 7 * 24 * 3600 * 1000

# robodr_blackbox::record / export wire constants.
_BUNDLE_MAGIC = b"RBBXBND1"
_MAX_IDENTITY_JSON = 64 * 1024
_FRAME_MAGIC = b"RBF1"
_FRAME_HEADER_LEN = 8
_MAX_FRAME_BODY = 16 * 1024 * 1024
_MAX_SIG_LEN = 1024
_FORMAT_VERSION = 1
_FLAG_CRITICAL = 0x01
_RECORD_DOMAIN = b"robodr-blackbox/record/v1\x00"
_SIG_DOMAIN = b"robodr-blackbox/sig/v1\x00"
_CHAIN_DOMAIN = b"robodr-blackbox/chain/v1\x00"
_ZERO_HASH = bytes(32)

# RecordKind (robodr_blackbox::record::RecordKind::to_u8).
_KIND_NAMES = {
    0: "genesis",
    1: "segment_start",
    2: "seal",
    3: "resume",
    4: "recovery",
    5: "segment_dropped",
    6: "saturation",
    7: "saturation_cleared",
    8: "truncation_detected",
    9: "key_rotation",
    16: "event",
    17: "deviation",
    18: "note",
}
_TIME_SOURCES = frozenset({0, 1, 2, 3})
_KIND_GENESIS = 0
_KIND_SEGMENT_START = 1
_KIND_RECOVERY = 4
_KIND_SEGMENT_DROPPED = 5
_KIND_TRUNCATION = 8
_KIND_KEY_ROTATION = 9
_CONTROL_KINDS = frozenset(
    {
        _KIND_GENESIS,
        _KIND_SEGMENT_START,
        _KIND_RECOVERY,
        _KIND_SEGMENT_DROPPED,
        _KIND_KEY_ROTATION,
    }
)
UNVERIFIABLE = "not verifiable by AutoSecOps"
"""Suffix of a refusal the reference verifier would not call tampering."""

_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_KEY_ID_RE = re.compile(r"[!-:<-~]{1,128}")  # printable ASCII except ';'
_EXPORT_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_ROBOT_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_LINK_RE = re.compile(
    r"robodr-blackbox://([A-Za-z0-9._-]{1,64})/([0-9]{1,20})/([0-9]{1,20})"
    r"\?sha256=([0-9a-f]{64})"
)


class EvidenceError(ValueError):
    """Evidence that does not verify, or a malformed evidence input."""


def _full(pattern: re.Pattern[str], text: object) -> bool:
    return isinstance(text, str) and pattern.fullmatch(text) is not None


def _is_uint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


# --------------------------------------------------------------------------- #
# Signature headers (§2, §11.4)
# --------------------------------------------------------------------------- #


def parse_signature_header(header: str) -> tuple[str, bytes] | None:
    """`ed25519;key_id=<id>;sig=<128 lower-case hex>` to (key id, signature)."""
    fields = header.split(";")
    if len(fields) != 3 or fields[0] != "ed25519":
        return None
    if not fields[1].startswith("key_id=") or not fields[2].startswith("sig="):
        return None
    key_id = fields[1].removeprefix("key_id=")
    if not _full(_KEY_ID_RE, key_id):
        return None
    sig_hex = fields[2].removeprefix("sig=")
    if len(sig_hex) != 128 or any(c not in "0123456789abcdef" for c in sig_hex):
        return None
    return key_id, bytes.fromhex(sig_hex)


def manifest_message(manifest_bytes: bytes) -> bytes:
    """The bytes the robot's finding key signs for a manifest (§11.4)."""
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    return f"{MANIFEST_DOMAIN}\n{digest}".encode()


def verify_manifest_signature(
    manifest_bytes: bytes,
    header: str | None,
    public_key: bytes,
    expected_key_id: str | None = None,
) -> str:
    """Check `X-RoboDR-Manifest-Signature`; return the key id it names.

    Raises:
        EvidenceError: The header is missing or malformed, names another key
            id than ``expected_key_id``, or does not verify.
    """
    parsed = parse_signature_header(header) if header else None
    if parsed is None:
        raise EvidenceError("the manifest carries no valid manifest signature")
    key_id, signature = parsed
    if expected_key_id is not None and key_id != expected_key_id:
        raise EvidenceError("the manifest is signed by an unexpected key id")
    if not ed25519_verify_strict(
        public_key, manifest_message(manifest_bytes), signature
    ):
        raise EvidenceError("the manifest signature does not verify")
    return key_id


# --------------------------------------------------------------------------- #
# Manifest (§11.4)
# --------------------------------------------------------------------------- #


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise EvidenceError(f"duplicate key {key[:32]!r} in the manifest")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise EvidenceError(f"non-JSON number {name} in the manifest")


class _NotStrictJSON(ValueError):
    pass


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _NotStrictJSON("duplicate key")
        out[key] = value
    return out


def _strict_constant(name: str) -> Any:
    raise _NotStrictJSON(name)


def _utf8_clean(value: object) -> bool:
    """No lone surrogate anywhere (`serde_json` refuses them in a `String`)."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return False
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return True


_INVALID: Any = object()


def _strict_json(raw: bytes) -> Any:
    """JSON as `serde_json::from_slice` would take it, or `_INVALID`.

    UTF-8 only (`json.loads` would also sniff UTF-16/32), no duplicate keys,
    no NaN/Infinity, no lone surrogates, and no nesting deep enough to
    exhaust the interpreter's stack.
    """
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_strict_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _INVALID
    return value if _utf8_clean(value) else _INVALID


@dataclass(frozen=True, slots=True)
class ChunkSpec:
    index: int
    offset: int
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Manifest:
    """The fields of a manifest the SOC checks; `raw` is the parsed object."""

    raw: dict[str, Any]
    robot_id: str
    export_id: str
    signing_key_id: str
    signing_key_algorithm: str
    chain_id: str
    bundle_bytes: int
    bundle_sha256: str
    chunk_bytes: int
    chunks: tuple[ChunkSpec, ...]


def _require(obj: object, key: str, where: str) -> Any:
    if not isinstance(obj, dict) or key not in obj:
        raise EvidenceError(f"manifest {where} has no {key}")
    return obj[key]


def parse_manifest(manifest_bytes: bytes, *, robot_id: str, export_id: str) -> Manifest:
    """Parse and check a manifest (§11.4, §11.6 step 2 without the selector).

    Raises:
        EvidenceError: The manifest is malformed or for another robot,
            export or API.
    """
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise EvidenceError("the manifest exceeds 1 MiB")
    try:
        raw = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("the manifest is not JSON") from exc
    if not isinstance(raw, dict):
        raise EvidenceError("the manifest is not a JSON object")
    if raw.get("kind") != MANIFEST_KIND or raw.get("version") != MANIFEST_VERSION:
        raise EvidenceError("not a robodr.evidence_manifest version 1")
    if raw.get("api") != API_VERSION:
        raise EvidenceError(f"the manifest is not for {API_VERSION}")
    if raw.get("robot_id") != robot_id:
        raise EvidenceError("the manifest is for another robot_id")
    if raw.get("export_id") != export_id:
        raise EvidenceError("the manifest is for another export_id")

    chain = _require(raw, "chain", "")
    chain_id = _require(chain, "chain_id", "chain")
    if not _full(_HEX64_RE, chain_id):
        raise EvidenceError("manifest chain.chain_id is not 64 hex")
    signing_key = _require(chain, "signing_key", "chain")
    key_id = _require(signing_key, "key_id", "chain.signing_key")
    algorithm = _require(signing_key, "algorithm", "chain.signing_key")
    if not _full(_KEY_ID_RE, key_id) or algorithm != "ed25519":
        raise EvidenceError("manifest chain.signing_key is not an ed25519 key id")

    bundle = _require(raw, "bundle", "")
    if _require(bundle, "format", "bundle") != BUNDLE_FORMAT:
        raise EvidenceError("manifest bundle.format is not RBBXBND1")
    total = _require(bundle, "bytes", "bundle")
    digest = _require(bundle, "sha256", "bundle")
    chunk_bytes = _require(bundle, "chunk_bytes", "bundle")
    raw_chunks = _require(bundle, "chunks", "bundle")
    if not _is_uint(total) or total == 0 or not _full(_HEX64_RE, digest):
        raise EvidenceError("manifest bundle.bytes / bundle.sha256 are invalid")
    if not _is_uint(chunk_bytes) or not 0 < chunk_bytes <= MAX_CHUNK_BYTES:
        raise EvidenceError("manifest bundle.chunk_bytes is out of range")
    if not isinstance(raw_chunks, list) or not 0 < len(raw_chunks) <= MAX_CHUNKS:
        raise EvidenceError("manifest bundle.chunks must list 1..4096 chunks")
    chunks: list[ChunkSpec] = []
    offset = 0
    for index, item in enumerate(raw_chunks):
        spec = ChunkSpec(
            index=_require(item, "index", "bundle.chunks[]"),
            offset=_require(item, "offset", "bundle.chunks[]"),
            size=_require(item, "bytes", "bundle.chunks[]"),
            sha256=_require(item, "sha256", "bundle.chunks[]"),
        )
        if (
            spec.index != index
            or spec.offset != offset
            or not _is_uint(spec.size)
            or not 0 < spec.size <= chunk_bytes
            or not _full(_HEX64_RE, spec.sha256)
        ):
            raise EvidenceError(f"manifest bundle.chunks[{index}] is inconsistent")
        chunks.append(spec)
        offset += spec.size
    if offset != total:
        raise EvidenceError("manifest chunks do not add up to bundle.bytes")
    return Manifest(
        raw=raw,
        robot_id=robot_id,
        export_id=export_id,
        signing_key_id=key_id,
        signing_key_algorithm=algorithm,
        chain_id=chain_id,
        bundle_bytes=total,
        bundle_sha256=digest,
        chunk_bytes=chunk_bytes,
        chunks=tuple(chunks),
    )


# --------------------------------------------------------------------------- #
# Selectors (§11.3)
# --------------------------------------------------------------------------- #


def parse_evidence_link(link: object, robot_id: str) -> dict[str, Any]:
    """A `robodr-blackbox://<robot>/<segment>/<seq>?sha256=<hex>` link of this robot."""
    if not isinstance(link, str) or (m := _LINK_RE.fullmatch(link)) is None:
        raise EvidenceError("evidence links must be robodr-blackbox:// links")
    if m.group(1) != robot_id:
        raise EvidenceError("an evidence link names another robot")
    segment, seq = int(m.group(2)), int(m.group(3))
    if segment >= 2**64 or seq >= 2**64:
        raise EvidenceError("an evidence link's segment or seq exceeds u64")
    return {"segment": segment, "seq": seq, "sha256": m.group(4)}


def build_selector(
    *,
    robot_id: str,
    finding_id: str | None = None,
    evidence_links: list[str] | None = None,
    context_records: int | None = None,
    from_seq: int | None = None,
    to_seq: int | None = None,
    from_ms: int | None = None,
    to_ms: int | None = None,
) -> dict[str, Any]:
    """The export request's `selector`: exactly one of the three (§11.3).

    Raises:
        EvidenceError: None or more than one selector is given, or a
            selector is incomplete.
    """
    finding = finding_id is not None or evidence_links is not None
    seq_range = from_seq is not None or to_seq is not None
    time_range = from_ms is not None or to_ms is not None
    if context_records is not None and not finding:
        raise EvidenceError("context_records belongs to the finding selector")
    if sum((finding, seq_range, time_range)) != 1:
        raise EvidenceError(
            "give exactly one selector: finding_id + evidence_links, "
            "from_seq + to_seq, or from_ms + to_ms"
        )
    if finding:
        if not isinstance(finding_id, str) or not 1 <= len(finding_id.encode()) <= 256:
            raise EvidenceError("finding_id must be 1..256 bytes")
        if not isinstance(evidence_links, list) or not (
            1 <= len(evidence_links) <= MAX_EVIDENCE_LINKS
        ):
            raise EvidenceError("evidence_links must list 1..64 links")
        for link in evidence_links:
            parse_evidence_link(link, robot_id)
        inner: dict[str, Any] = {"finding_id": finding_id, "evidence": evidence_links}
        if context_records is not None:
            if not _is_uint(context_records) or context_records > MAX_CONTEXT_RECORDS:
                raise EvidenceError("context_records must be 0..1024")
            inner["context_records"] = context_records
        return {"finding": inner}
    if seq_range:
        if (seqs := _ordered_pair(from_seq, to_seq)) is None:
            raise EvidenceError(
                "from_seq and to_seq must be integers, from_seq <= to_seq"
            )
        return {"seq_range": {"from_seq": seqs[0], "to_seq": seqs[1]}}
    if (times := _ordered_pair(from_ms, to_ms)) is None:
        raise EvidenceError("from_ms and to_ms must be integers, from_ms <= to_ms")
    if times[1] - times[0] > MAX_TIME_RANGE_MS:
        raise EvidenceError("from_ms and to_ms are at most 7 days apart")
    return {"time_range": {"from_ms": times[0], "to_ms": times[1]}}


def _ordered_pair(low: object, high: object) -> tuple[int, int] | None:
    """``(low, high)`` when both are non-negative integers and low <= high."""
    if not (isinstance(low, int) and isinstance(high, int)):
        return None
    if not (_is_uint(low) and _is_uint(high)) or low > high:
        return None
    return low, high


def _link_key(item: dict[str, Any]) -> tuple[int, int, str]:
    return (item["segment"], item["seq"], item["sha256"])


def normalized_selector(selector: dict[str, Any], robot_id: str) -> dict[str, Any]:
    """The selection as the robot normalizes it in the manifest (§11.4).

    Finding links are parsed, sorted and deduplicated, and the default
    `context_records` is filled in; range selectors are unchanged.
    """
    match selector:
        case {"finding": {"finding_id": finding_id, "evidence": links} as inner}:
            parsed = {
                _link_key(p): p
                for p in (parse_evidence_link(link, robot_id) for link in links)
            }
            return {
                "finding": {
                    "finding_id": finding_id,
                    "evidence": [parsed[k] for k in sorted(parsed)],
                    "context_records": inner.get(
                        "context_records", DEFAULT_CONTEXT_RECORDS
                    ),
                }
            }
        case _:
            return selector


def selector_matches(
    manifest: Manifest, selector: dict[str, Any], robot_id: str
) -> bool:
    """Whether the manifest's `selector` is the selection that was asked for."""
    expected = normalized_selector(selector, robot_id)
    actual = manifest.raw.get("selector")
    match actual:
        case {"finding": {"evidence": list() as evidence} as inner} if all(
            isinstance(e, dict) and set(e) == {"segment", "seq", "sha256"}
            for e in evidence
        ):
            actual = {
                "finding": {
                    **inner,
                    "evidence": sorted(evidence, key=_link_key),
                }
            }
        case _:
            pass
    return actual == expected


# --------------------------------------------------------------------------- #
# Chunks (§11.5, §11.6 step 3)
# --------------------------------------------------------------------------- #


def check_chunk(spec: ChunkSpec, data: bytes) -> None:
    """Raise unless ``data`` is exactly the chunk the manifest describes."""
    if len(data) != spec.size:
        raise EvidenceError(
            f"chunk {spec.index} has {len(data)} bytes, not {spec.size}"
        )
    if hashlib.sha256(data).hexdigest() != spec.sha256:
        raise EvidenceError(f"chunk {spec.index} does not match its SHA-256")


def assemble_bundle(manifest: Manifest, chunks: dict[int, bytes]) -> bytes:
    """Concatenate verified chunks in index order and check the whole bundle."""
    parts: list[bytes] = []
    for spec in manifest.chunks:
        if spec.index not in chunks:
            raise EvidenceError(f"chunk {spec.index} is missing")
        check_chunk(spec, chunks[spec.index])
        parts.append(chunks[spec.index])
    bundle = b"".join(parts)
    if len(bundle) != manifest.bundle_bytes:
        raise EvidenceError("the bundle's length differs from bundle.bytes")
    if hashlib.sha256(bundle).hexdigest() != manifest.bundle_sha256:
        raise EvidenceError("the bundle does not match bundle.sha256")
    return bundle


# --------------------------------------------------------------------------- #
# Black-box keyring
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class KeyringEntry:
    key_id: str
    public_key: bytes
    device_id: str | None


def parse_blackbox_keyring(key_files: list[str]) -> dict[str, KeyringEntry]:
    """Public key files of `robodr-blackbox keygen` to a keyring by key id.

    Only public key files are accepted: a file with `"kind": "secret"` or a
    `secret_hex` field is refused, so a secret key never enters a workflow.

    Raises:
        EvidenceError: A file is not an ed25519 public key file, or two files
            name the same key id.
    """
    if not isinstance(key_files, list) or not 1 <= len(key_files) <= 16:
        raise EvidenceError("give 1..16 black-box public key files")
    keyring: dict[str, KeyringEntry] = {}
    for text in key_files:
        try:
            doc = json.loads(text) if isinstance(text, str) else None
        except json.JSONDecodeError:
            doc = None
        if not isinstance(doc, dict):
            raise EvidenceError("a black-box key file is not a JSON object")
        if doc.get("kind") != "public" or "secret_hex" in doc:
            raise EvidenceError(
                "black-box key files must be public key files (.pub); never "
                "pass a secret key file"
            )
        if not str(doc.get("format", "")).startswith("robodr-blackbox-key/"):
            raise EvidenceError("a black-box key file has an unknown format")
        key_id = doc.get("key_id")
        public = parse_public_key_hex(doc.get("public_hex", ""))
        device_id = doc.get("device_id")
        if (
            doc.get("algorithm") != "ed25519"
            or not isinstance(key_id, str)
            or not _full(_KEY_ID_RE, key_id)
            or public is None
            or (device_id is not None and not isinstance(device_id, str))
        ):
            raise EvidenceError("a black-box key file is not a valid ed25519 key")
        if key_id in keyring:
            raise EvidenceError("two black-box key files name the same key id")
        keyring[key_id] = KeyringEntry(key_id, public, device_id)
    return keyring


# --------------------------------------------------------------------------- #
# Bundle (robodr_blackbox::export::Bundle, record::Record)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _Record:
    chain_id: bytes
    seq: int
    wall_ns: int
    kind: int
    payload: bytes
    prev_hash: bytes
    hash: bytes
    sig: bytes
    computed_hash: bytes


@dataclass(frozen=True, slots=True)
class _Identity:
    device_id: str
    boot_id: str
    key_id: str
    algorithm: str
    created_wall_ns: int

    def chain_id(self) -> bytes:
        h = hashlib.sha256(_CHAIN_DOMAIN)
        for text in (self.device_id, self.boot_id, self.key_id, self.algorithm):
            raw = text.encode()
            h.update(len(raw).to_bytes(4, "big"))
            h.update(raw)
        h.update(self.created_wall_ns.to_bytes(8, "big"))
        return h.digest()


def _identity_from(obj: object) -> _Identity | None:
    match obj:
        case {
            "device_id": str(device_id),
            "boot_id": str(boot_id),
            "key_id": str(key_id),
            "algorithm": str(algorithm),
            "created_wall_ns": int(created),
        } if not isinstance(created, bool) and 0 <= created < 2**64:
            return _Identity(device_id, boot_id, key_id, algorithm, created)
        case _:
            return None


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        end = self.pos + n
        if n < 0 or end > len(self.data):
            raise EvidenceError("the bundle is truncated")
        out = self.data[self.pos : end]
        self.pos = end
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")


def _decode_record(body: bytes) -> _Record:
    r = _Reader(body)
    if r.uint(1) != _FORMAT_VERSION:
        raise EvidenceError("a record has an unsupported format version")
    chain_id = r.take(32)
    seq = r.uint(8)
    wall_ns = r.uint(8)
    r.uint(8)  # mono_ns
    if r.uint(1) not in _TIME_SOURCES:
        raise EvidenceError("a record has an unknown time source")
    kind = r.uint(1)
    if kind not in _KIND_NAMES:
        raise EvidenceError("a record has an unknown kind")
    if r.uint(1) & ~_FLAG_CRITICAL:
        raise EvidenceError("a record has unknown flag bits")
    payload = r.take(r.uint(4))
    prev_hash = r.take(32)
    hashed_end = r.pos
    stored_hash = r.take(32)
    sig_len = r.uint(2)
    if sig_len > _MAX_SIG_LEN:
        raise EvidenceError("a record signature is too long")
    sig = r.take(sig_len)
    if r.pos != len(body):
        raise EvidenceError("a record frame has trailing bytes")
    computed = hashlib.sha256(_RECORD_DOMAIN + body[:hashed_end]).digest()
    return _Record(
        chain_id, seq, wall_ns, kind, payload, prev_hash, stored_hash, sig, computed
    )


def _frames(frames: bytes) -> list[_Record]:
    records: list[_Record] = []
    pos = 0
    while pos < len(frames):
        if (
            len(frames) - pos < _FRAME_HEADER_LEN
            or frames[pos : pos + 4] != _FRAME_MAGIC
        ):
            raise EvidenceError("the bundle holds a malformed frame")
        body_len = int.from_bytes(frames[pos + 4 : pos + 8], "big")
        end = pos + _FRAME_HEADER_LEN + body_len
        if body_len > _MAX_FRAME_BODY or end > len(frames):
            raise EvidenceError("the bundle holds a malformed frame")
        records.append(_decode_record(frames[pos + _FRAME_HEADER_LEN : end]))
        pos = end
    return records


def _key_ref(obj: object) -> tuple[str, str] | None:
    match obj:
        case {"key_id": str(key_id), "algorithm": str(algorithm)}:
            return (key_id, algorithm)
        case _:
            return None


def _unverifiable(what: str, seq: int) -> EvidenceError:
    return EvidenceError(f"{what} at seq {seq} ({UNVERIFIABLE})")


def _control_payload(record: _Record) -> dict[str, Any]:
    """A control record's payload object, parsed as strictly as the reference."""
    payload = _strict_json(record.payload)
    if not isinstance(payload, dict):
        name = _KIND_NAMES[record.kind]
        raise _unverifiable(f"unparseable {name} payload", record.seq)
    return payload


def _flag(payload: dict[str, Any], key: str, default: bool | None) -> bool | None:
    """A boolean payload field (``default`` when absent, None when ill-typed)."""
    value = payload.get(key, default)
    return value if isinstance(value, bool) else None


def _check_signature(
    record: _Record,
    keyring: dict[str, KeyringEntry],
    current: tuple[str, str],
    device_id: str,
) -> None:
    key_id, algorithm = current
    entry = keyring.get(key_id)
    if entry is None or algorithm != "ed25519":
        raise EvidenceError(f"no ed25519 key {key_id[:64]!r} for seq {record.seq}")
    if entry.device_id is not None and entry.device_id != device_id:
        raise EvidenceError(f"key {key_id[:64]!r} is bound to another device")
    if not ed25519_verify_strict(
        entry.public_key, _SIG_DOMAIN + record.hash, record.sig
    ):
        raise EvidenceError(f"bad signature at seq {record.seq}")


def _check_control_record(
    record: _Record, payload: dict[str, Any], current: tuple[str, str]
) -> tuple[str, str]:
    """Refuse what the reference reports as tampering for a control record.

    Returns the key in effect after the record (changed only by a
    `KeyRotation` from the current key, whose signature is already checked).
    """
    seq = record.seq
    match record.kind:
        case 4:  # Recovery: SegmentQuarantined / DamageQuarantined are Tamper.
            quarantined = _flag(payload, "quarantined_segment", False)
            plausible = _flag(payload, "crash_plausible", True)
            if quarantined is None or plausible is None:
                raise _unverifiable("malformed recovery record", seq)
            if quarantined:
                raise EvidenceError(f"recorded segment quarantine at seq {seq}")
            if not plausible:
                raise EvidenceError(f"recorded damage at seq {seq}")
        case 5:  # SegmentDropped: SegmentMissingReported is Tamper.
            missing = _flag(payload, "missing", None)
            if missing is None or not _is_uint(payload.get("segment_index")):
                raise _unverifiable("malformed segment_dropped record", seq)
            if missing:
                raise EvidenceError(f"recorded missing segment at seq {seq}")
        case 9:  # KeyRotation: followed only when fully parseable, as Rust does.
            from_key = _key_ref(payload.get("from"))
            to_key = _key_ref(payload.get("to"))
            if from_key is None or to_key is None:
                raise _unverifiable("malformed key_rotation record", seq)
            if not isinstance(payload.get("reason"), str):
                raise _unverifiable("key_rotation record without a reason", seq)
            if from_key == current:
                return to_key
        case _:
            pass
    return current


@dataclass(slots=True)
class BundleReport:
    """What `verify_bundle` established; `intact` only if nothing failed."""

    intact: bool
    problems: list[str] = field(default_factory=list)
    device_id: str | None = None
    chain_id: str | None = None
    first_seq: int | None = None
    last_seq: int | None = None
    verified_records: int = 0
    last_hash: str | None = None
    anchor_seq: int | None = None
    anchor_hash: str | None = None
    signing_key_id: str | None = None
    record_hashes: dict[int, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "problems": self.problems,
            "device_id": self.device_id,
            "chain_id": self.chain_id,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "verified_records": self.verified_records,
            "last_hash": self.last_hash,
            "anchor": (
                None
                if self.anchor_seq is None
                else {"seq": self.anchor_seq, "sha256": self.anchor_hash}
            ),
            "anchor_verified": False,
            "signing_key_id": self.signing_key_id,
        }


def verify_bundle(
    bundle: bytes,
    keyring: dict[str, KeyringEntry] | None,
    *,
    robot_id: str,
    signing_key_id: str,
) -> BundleReport:
    """Verify an `RBBXBND1` bundle (§11.6 step 4); never raises on bad input.

    Every record must decode, hash to its stored hash, carry a valid
    signature under the key in effect (``signing_key_id`` at the start,
    switched only by a signed `KeyRotation` from it), belong to the
    identity's chain, follow the previous record (seq + 1, `prev_hash`) from
    the bundle's anchor (or start at genesis), and the identity must name
    ``robot_id``. The anchor itself is unverified (first contact).

    ``keyring=None`` checks everything except the record signatures (the
    platform's re-check of a bundle a workflow verified with the keyring).
    """
    report = BundleReport(intact=False)
    try:
        _verify_bundle(bundle, keyring, robot_id, signing_key_id, report)
    except EvidenceError as exc:
        report.problems.append(str(exc))
    report.intact = not report.problems
    return report


def _verify_bundle(
    bundle: bytes,
    keyring: dict[str, KeyringEntry] | None,
    robot_id: str,
    signing_key_id: str,
    report: BundleReport,
) -> None:
    r = _Reader(bundle)
    if r.take(8) != _BUNDLE_MAGIC:
        raise EvidenceError("the bundle has a bad magic")
    id_len = r.uint(4)
    if id_len > _MAX_IDENTITY_JSON:
        raise EvidenceError("the bundle identity is too large")
    identity = _identity_from(_strict_json(r.take(id_len)))
    if identity is None:
        raise EvidenceError("the bundle identity is not a chain identity")
    chain_id = identity.chain_id()
    report.device_id = identity.device_id
    report.chain_id = chain_id.hex()
    anchor: tuple[bytes, int, bytes] | None = None
    match r.uint(1):
        case 0:
            pass
        case 1:
            anchor = (r.take(32), r.uint(8), r.take(32))
        case _:
            raise EvidenceError("the bundle has a bad anchor flag")
    frames = r.take(r.uint(8))
    if r.pos != len(bundle):
        raise EvidenceError("the bundle has trailing bytes")
    if identity.device_id != robot_id:
        raise EvidenceError("the bundle is from another device")
    records = _frames(frames)
    if not records:
        raise EvidenceError(f"the bundle holds no records ({UNVERIFIABLE})")

    if anchor is not None:
        anchor_chain, anchor_seq, anchor_hash = anchor
        report.anchor_seq, report.anchor_hash = anchor_seq, anchor_hash.hex()
        if anchor_chain != chain_id:
            raise EvidenceError("the bundle anchor names another chain")
        expected_seq, expected_prev = anchor_seq + 1, anchor_hash
    else:
        if records[0].kind != _KIND_GENESIS:
            raise EvidenceError("an unanchored bundle must start at genesis")
        expected_seq, expected_prev = 0, _ZERO_HASH

    current: tuple[str, str] = (signing_key_id, "ed25519")
    for record in records:
        seq = record.seq
        if record.chain_id != chain_id:
            raise EvidenceError(f"record {seq} belongs to another chain")
        if record.computed_hash != record.hash:
            raise EvidenceError(f"hash mismatch at seq {seq}")
        if seq != expected_seq:
            raise EvidenceError(f"seq {seq} where {expected_seq} was expected")
        if record.prev_hash != expected_prev:
            raise EvidenceError(f"chain break at seq {seq}")
        if record.kind == _KIND_GENESIS and seq != 0:
            raise EvidenceError(f"genesis record at non-zero seq {seq}")
        payload = _control_payload(record) if record.kind in _CONTROL_KINDS else None
        if record.kind in (_KIND_GENESIS, _KIND_SEGMENT_START):
            assert payload is not None
            named_identity = _identity_from(payload.get("identity"))
            if named_identity is None:
                raise _unverifiable(f"unparseable {_KIND_NAMES[record.kind]}", seq)
            if named_identity.chain_id() != chain_id:
                raise EvidenceError(f"identity mismatch at seq {seq}")
            named = (named_identity.key_id, named_identity.algorithm)
            if (
                record.kind == _KIND_SEGMENT_START
                and payload.get("signing_key") is not None
            ):
                signing_key = _key_ref(payload.get("signing_key"))
                if signing_key is None:
                    raise _unverifiable("malformed segment_start signing_key", seq)
                named = signing_key
            if named != current:
                raise EvidenceError(f"key switch refused at seq {seq}")
        if keyring is not None:
            _check_signature(record, keyring, current, identity.device_id)
        if record.kind == _KIND_TRUNCATION:
            raise EvidenceError(f"recorded truncation at seq {seq}")
        if payload is not None:
            current = _check_control_record(record, payload, current)
        report.record_hashes[seq] = record.hash.hex()
        report.verified_records += 1
        if report.first_seq is None:
            report.first_seq = seq
        report.last_seq = seq
        report.last_hash = record.hash.hex()
        expected_seq, expected_prev = seq + 1, record.hash
    report.signing_key_id = current[0]


# --------------------------------------------------------------------------- #
# Report against manifest (§11.6 step 5)
# --------------------------------------------------------------------------- #


def check_report_against_manifest(
    report: BundleReport, manifest: Manifest
) -> list[str]:
    """Differences between the verified bundle and its manifest (empty = none)."""
    problems: list[str] = []
    records = manifest.raw.get("records")
    if not isinstance(records, dict):
        return ["the manifest has no records"]
    expected = {
        "first_seq": (report.first_seq, records.get("first_seq")),
        "last_seq": (report.last_seq, records.get("last_seq")),
        "count": (report.verified_records, records.get("count")),
        "last_sha256": (report.last_hash, records.get("last_sha256")),
        "chain_id": (report.chain_id, manifest.chain_id),
    }
    for name, (seen, stated) in expected.items():
        if seen != stated:
            problems.append(f"the bundle's {name} differs from the manifest")
    anchor = manifest.raw.get("anchor")
    stated_anchor = (
        (anchor.get("seq"), anchor.get("sha256")) if isinstance(anchor, dict) else None
    )
    seen_anchor = (
        None if report.anchor_seq is None else (report.anchor_seq, report.anchor_hash)
    )
    if stated_anchor != seen_anchor:
        problems.append("the bundle's anchor differs from the manifest")
    referenced = manifest.raw.get("referenced", [])
    if not isinstance(referenced, list):
        return [*problems, "the manifest's referenced list is invalid"]
    for item in referenced:
        seq = item.get("seq") if isinstance(item, dict) else None
        digest = item.get("sha256") if isinstance(item, dict) else None
        if not isinstance(seq, int) or report.record_hashes.get(seq) != digest:
            problems.append(f"referenced record {seq!r} is not in the bundle")
    return problems
