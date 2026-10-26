"""Strict validator for `robodr.findings` 2.x record values.

A port of ``robodr_ocsf::validate::parse_and_validate`` restricted to
contract major 2 (the ingest API carries 2.x only; any other well-formed major
is ``unsupported_contract``). The rules are applied in the same order and with
the same semantics:

* the value is at most 64 KiB and must be UTF-8 JSON without duplicate object
  keys at any depth (escape-equivalent spellings count as duplicates);
* every string anywhere in the raw document, keys included, is at most
  4096 bytes of printable ASCII without ``<``, ``>`` or a backtick, so the
  SR-TAINT string rules also cover fields this release does not know;
* the document is projected onto the contract's typed model. Unknown fields
  are ignored (contract §5: a minor release may add optional fields) but
  every known field must have its declared type;
* the typed checks of ``validate()``: constants, enum captions, identity
  (``external_id == robot_id:finding_id``), times, rule-catalog constants of
  the message's own contract minor, ATT&CK lists, evidence URIs, resources,
  ``unmapped.robodr == entity_context``, canonical tainted values, and the
  sorted ``adversary_controlled_fields`` list.

Two heuristics are checked less strictly than the reference, never more:
``mixed_script`` is recomputed only for ASCII input (Python's Unicode tables
differ from Rust's ``char::is_alphabetic``), and for a non-ASCII original the
producer's value is accepted as long as it implies ``non_ascii``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any, Final

import orjson

from autosecops.robot_edr.taint import (
    TAINT_LABEL,
    Charset,
    TaintCap,
    escaped_cap,
    is_encoded,
    looks_like_injection,
    render,
    unescape,
)

MAX_FINDING_BYTES: Final = 64 * 1024
MAX_STRING_BYTES: Final = 4096
MAX_EVIDENCE: Final = 64
MAX_TECHNIQUES: Final = 16
MAX_RESOURCES: Final = 8
MAX_TITLE: Final = 256
MAX_DESCRIPTION: Final = 2048
MAX_LABEL: Final = 128
MAX_ROBOT_ID: Final = 64
MAX_RULE_ID: Final = 128
MIN_TIME_MS: Final = 946_684_800_000
MAX_TIME_MS: Final = 4_102_444_800_000
MAX_JSON_DEPTH: Final = 128
CONTRACT_MAJOR: Final = 2

OCSF_VERSION: Final = "1.1.0"
PRODUCT_NAME: Final = "RoboDR"
VENDOR_NAME: Final = "Singularity RD"

SEVERITY_IDS: Final[Mapping[str, int]] = {
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
SEVERITY_NAMES: Final[Mapping[str, str]] = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
_ACTIVITY_NAMES: Final = {1: "Create", 2: "Update", 3: "Close"}
_STATUS_NAMES: Final = {
    0: "Unknown",
    1: "New",
    2: "In Progress",
    3: "Suppressed",
    4: "Resolved",
    99: "Other",
}
_RESOURCE_CAPS: Final = {
    "ros2.participant": TaintCap.GUID,
    "ros2.node": TaintCap.NODE,
    "ros2.topic": TaintCap.TOPIC,
    "ip_address": TaintCap.IP,
}
_ROS_FIELDS: Final = (
    ("participant_guid", TaintCap.GUID),
    ("node", TaintCap.NODE),
    ("topic", TaintCap.TOPIC),
    ("type_name", TaintCap.TYPE_NAME),
    ("src_ip", TaintCap.IP),
)
_HEX = frozenset("0123456789abcdef")
# `robodr_ocsf::validate::contract_major`: 1-9 ASCII digits per part,
# leading zeros allowed.
_VERSION_PART: Final = r"([0-9]{1,9})"
_VERSION_RE: Final = re.compile(rf"{_VERSION_PART}\.{_VERSION_PART}\.{_VERSION_PART}")


class FindingValidationError(Exception):
    """The value is not a valid `robodr.findings` 2.x record."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


class UnsupportedContractError(Exception):
    """The value is well formed but names a contract major other than 2."""

    def __init__(self, contract_version: str) -> None:
        super().__init__(f"unsupported contract version {contract_version!r}")
        self.contract_version = contract_version


@dataclass(frozen=True, slots=True)
class ValidatedFinding:
    """The fields the ingest pipeline needs from a validated value.

    ``document`` is the typed projection (known fields only) of the parsed
    value; it is data for storage and rendering, never re-serialised for
    signature checks.
    """

    contract_version: str
    finding_id: str
    external_id: str
    data_source: str
    robot_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    severity_id: int
    event_uid: str
    first_seen_ms: int
    last_seen_ms: int
    occurrence_count: int
    robot_model: str
    robot_site: str
    platform_family: str
    mode: str
    motion: str
    human_proximity: str
    attestation: str
    techniques: tuple[str, ...]
    evidence_links: tuple[str, ...]
    adversary_controlled_fields: tuple[str, ...]
    document: dict[str, Any]


# --- typed projection --------------------------------------------------------
#
# A spec mirrors the serde model of `robodr_ocsf::model`. Projection keeps
# known keys only, applies serde defaults, and drops `null` optional values,
# so equality and the tainted-pointer walk see what the Rust validator sees.


class _Missing:
    pass


_MISSING: Final = _Missing()
type _Spec = Callable[[Any, str, list[str]], Any]


def _str() -> _Spec:
    def check(value: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(value, str):
            errs.append(f"{path}: expected a string")
            return _MISSING
        return value

    return check


def _uint(bits: int) -> _Spec:
    limit = 2**bits

    def check(value: Any, path: str, errs: list[str]) -> Any:
        if isinstance(value, bool) or not isinstance(value, int):
            errs.append(f"{path}: expected an unsigned integer")
            return _MISSING
        if not 0 <= value < limit:
            errs.append(f"{path}: integer out of range")
            return _MISSING
        return value

    return check


def _f64() -> _Spec:
    def check(value: Any, path: str, errs: list[str]) -> Any:
        if isinstance(value, bool) or not isinstance(value, int | float):
            errs.append(f"{path}: expected a number")
            return _MISSING
        return float(value)

    return check


def _bool() -> _Spec:
    def check(value: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(value, bool):
            errs.append(f"{path}: expected a boolean")
            return _MISSING
        return value

    return check


def _enum(*values: str) -> _Spec:
    allowed = frozenset(values)

    def check(value: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(value, str) or value not in allowed:
            errs.append(f"{path}: unknown variant")
            return _MISSING
        return value

    return check


def _list(item: _Spec) -> _Spec:
    def check(value: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(value, list):
            errs.append(f"{path}: expected an array")
            return _MISSING
        out = [item(v, f"{path}/{i}", errs) for i, v in enumerate(value)]
        return _MISSING if any(v is _MISSING for v in out) else out

    return check


@dataclass(frozen=True, slots=True)
class _Field:
    spec: _Spec
    optional: bool = False
    default: Any = _MISSING


def _obj(fields: dict[str, _Field]) -> _Spec:
    def check(value: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(value, dict):
            errs.append(f"{path}: expected an object")
            return _MISSING
        out: dict[str, Any] = {}
        failed = False
        for key, field in fields.items():
            raw = value.get(key, _MISSING)
            if raw is _MISSING or (field.optional and raw is None):
                if field.default is not _MISSING:
                    out[key] = field.default
                elif not field.optional:
                    errs.append(f"{path}/{key}: missing field")
                    failed = True
                continue
            projected = field.spec(raw, f"{path}/{key}", errs)
            if projected is _MISSING:
                failed = True
            else:
                out[key] = projected
        return _MISSING if failed else out

    return check


_TAINTED = _obj(
    {
        "value": _Field(_str()),
        "display": _Field(_str(), default=""),
        "taint": _Field(_enum("sensor", "adversary", "third_party")),
        "escaped": _Field(_bool()),
        "truncated": _Field(_bool()),
        "non_ascii": _Field(_bool(), default=False),
        "mixed_script": _Field(_bool(), default=False),
        "injection_hint": _Field(_bool(), default=False),
        "suspicious": _Field(_bool(), default=False),
        "original_len": _Field(_uint(64)),
        "original_sha256": _Field(_str()),
    }
)
_OPT_TAINTED = _Field(_TAINTED, optional=True)
_OPT_F64 = _Field(_f64(), optional=True)
_ENTITY_CONTEXT = _obj(
    {
        "robot": _Field(
            _obj(
                {
                    "id": _Field(_str()),
                    "model": _Field(_str()),
                    "platform_family": _Field(
                        _enum(
                            "linux_ros2",
                            "rtos",
                            "closed_controller",
                            "fieldbus",
                            "other",
                        )
                    ),
                    "site": _Field(_str()),
                    "firmware": _Field(
                        _obj({"version": _Field(_str()), "sha256": _Field(_str())}),
                        optional=True,
                    ),
                }
            )
        ),
        "profile": _Field(_obj({"version": _Field(_str()), "sha256": _Field(_str())})),
        "rule_id": _Field(_str()),
        "mode": _Field(_enum("observe", "enforce")),
        "safety_state": _Field(
            _obj(
                {
                    "motion": _Field(_enum("moving", "stationary", "unknown")),
                    "human_proximity": _Field(
                        _enum("detected", "not_detected", "unknown")
                    ),
                }
            )
        ),
        "attestation": _Field(_enum("verified", "deviation", "unknown")),
        "ros": _Field(
            _obj(
                {
                    "participant_guid": _OPT_TAINTED,
                    "node": _OPT_TAINTED,
                    "topic": _OPT_TAINTED,
                    "type_name": _OPT_TAINTED,
                    "src_ip": _OPT_TAINTED,
                }
            )
        ),
        "command": _Field(
            _obj(
                {
                    "channel": _Field(_TAINTED),
                    "linear_speed": _OPT_F64,
                    "joint_speed": _OPT_F64,
                    "envelope_max_linear_speed": _OPT_F64,
                    "envelope_max_joint_speed": _OPT_F64,
                }
            ),
            optional=True,
        ),
        "bus_message_id": _Field(_uint(32), optional=True),
        "occurrence_count": _Field(_uint(64)),
        "detail": _Field(_TAINTED),
    }
)
_DETECTION_FINDING = _obj(
    {
        "activity_id": _Field(_uint(8)),
        "activity_name": _Field(_str()),
        "category_uid": _Field(_uint(32)),
        "category_name": _Field(_str()),
        "class_uid": _Field(_uint(32)),
        "class_name": _Field(_str()),
        "type_uid": _Field(_uint(32)),
        "type_name": _Field(_str()),
        "severity_id": _Field(_uint(8)),
        "severity": _Field(_str()),
        "status_id": _Field(_uint(8)),
        "status": _Field(_str()),
        "time": _Field(_uint(64)),
        "message": _Field(_str()),
        "count": _Field(_uint(64)),
        "metadata": _Field(
            _obj(
                {
                    "version": _Field(_str()),
                    "product": _Field(
                        _obj(
                            {
                                "name": _Field(_str()),
                                "vendor_name": _Field(_str()),
                                "version": _Field(_str()),
                            }
                        )
                    ),
                    "uid": _Field(_str()),
                    "log_name": _Field(_str()),
                }
            )
        ),
        "finding_info": _Field(
            _obj(
                {
                    "uid": _Field(_str()),
                    "title": _Field(_str()),
                    "desc": _Field(_str()),
                    "types": _Field(_list(_str())),
                    "first_seen_time": _Field(_uint(64)),
                    "last_seen_time": _Field(_uint(64)),
                    "analytic": _Field(
                        _obj(
                            {
                                "uid": _Field(_str()),
                                "name": _Field(_str()),
                                "type_id": _Field(_uint(8)),
                                "type": _Field(_str()),
                            }
                        )
                    ),
                    "attacks": _Field(
                        _list(
                            _obj(
                                {
                                    "technique": _Field(
                                        _obj(
                                            {
                                                "uid": _Field(_str()),
                                                "name": _Field(_str()),
                                            }
                                        )
                                    )
                                }
                            )
                        )
                    ),
                    "data_sources": _Field(_list(_str())),
                }
            )
        ),
        "device": _Field(
            _obj(
                {
                    "uid": _Field(_str()),
                    "name": _Field(_str()),
                    "type_id": _Field(_uint(8)),
                    "type": _Field(_str()),
                    "model": _Field(_str()),
                }
            )
        ),
        "evidences": _Field(
            _list(
                _obj(
                    {
                        "data": _Field(
                            _obj(
                                {
                                    "kind": _Field(_str()),
                                    "segment": _Field(_uint(64)),
                                    "seq": _Field(_uint(64)),
                                    "sha256": _Field(_str()),
                                    "uri": _Field(_str()),
                                }
                            )
                        )
                    }
                )
            )
        ),
        "resources": _Field(
            _list(
                _obj(
                    {
                        "type": _Field(_str()),
                        "uid": _Field(_str(), optional=True),
                        "name": _Field(_str(), optional=True),
                        "labels": _Field(_list(_str())),
                    }
                )
            )
        ),
        "unmapped": _Field(_obj({"robodr": _Field(_ENTITY_CONTEXT)})),
    }
)
_ENVELOPE = _obj(
    {
        "contract_version": _Field(_str()),
        "finding_id": _Field(_str()),
        "external_id": _Field(_str()),
        "data_source": _Field(_str()),
        "title": _Field(_str()),
        "description": _Field(_str()),
        "severity": _Field(_enum("low", "medium", "high", "critical")),
        "timestamp": _Field(_str()),
        "entity_context": _Field(_ENTITY_CONTEXT),
        "mitre_predictions": _Field(
            _list(
                _obj(
                    {
                        "technique_id": _Field(_str()),
                        "technique_name": _Field(_str()),
                        "framework": _Field(_str()),
                        "provenance": _Field(
                            _enum("sensor", "adversary", "third_party")
                        ),
                    }
                )
            )
        ),
        "evidence_links": _Field(_list(_str())),
        "anomaly_score": _OPT_F64,
        "adversary_controlled_fields": _Field(_list(_str())),
        "ocsf": _Field(_DETECTION_FINDING),
    }
)


# --- rule catalog ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Trusted catalog entry for a rule id."""

    title: str
    desc: str
    data_source: str
    techniques: tuple[tuple[str, str], ...]


def _rule_info(entry: dict[str, Any]) -> RuleInfo:
    return RuleInfo(
        title=entry["title"],
        desc=entry["desc"],
        data_source=entry["data_source"],
        techniques=tuple((t[0], t[1]) for t in entry["techniques"]),
    )


@cache
def _catalog() -> dict[str, Any]:
    data = (
        resources.files("autosecops.robot_edr")
        .joinpath("data/rule_catalog.json")
        .read_bytes()
    )
    return orjson.loads(data)


def rule_info_for_contract(rule_id: str, contract_version: str) -> RuleInfo:
    """Port of ``robodr_ocsf::rule_info_for_contract`` for contract 2.x."""
    catalog = _catalog()
    parts = contract_version.split(".")
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    with_2_1 = minor is None or minor >= 1
    if (entry := catalog["catalog_1_0"].get(rule_id)) is not None:
        return _rule_info(entry)
    if (entry := catalog["catalog_1_3"].get(rule_id)) is not None:
        return _rule_info(entry)
    if rule_id.startswith("robot.correlate."):
        return _rule_info(catalog["correlate_generic"])
    if with_2_1 and (entry := catalog["catalog_2_1"].get(rule_id)) is not None:
        return _rule_info(entry)
    return _rule_info(catalog["generic"])


# --- format helpers ----------------------------------------------------------


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(c in _HEX for c in value)


def _is_prefixed_uid(value: str, prefix: str) -> bool:
    tail = value.removeprefix(prefix)
    return value.startswith(prefix) and len(tail) == 32 and all(c in _HEX for c in tail)


def _is_ascii_alnum(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9")


def is_valid_robot_id(value: str) -> bool:
    """``[A-Za-z0-9._-]{1,64}``."""
    return 0 < len(value) <= MAX_ROBOT_ID and all(
        _is_ascii_alnum(c) or c in "._-" for c in value
    )


def is_valid_rule_id(value: str) -> bool:
    """``[a-z0-9._]{1,128}`` starting with a lower-case letter."""
    return (
        0 < len(value) <= MAX_RULE_ID
        and "a" <= value[0] <= "z"
        and all(("a" <= c <= "z") or ("0" <= c <= "9") or c in "._" for c in value)
    )


def is_valid_data_source(value: str) -> bool:
    """``[a-z0-9][a-z0-9._-]{0,63}``."""
    return (
        0 < len(value) <= 64
        and (("a" <= value[0] <= "z") or ("0" <= value[0] <= "9"))
        and all(("a" <= c <= "z") or ("0" <= c <= "9") or c in "._-" for c in value)
    )


def _is_valid_topic(value: str) -> bool:
    return (
        0 < len(value) <= 249
        and value not in {".", ".."}
        and all(_is_ascii_alnum(c) or c in "._-" for c in value)
    )


def _is_technique_id(value: str) -> bool:
    base = len(value) >= 5 and value[0] == "T" and value[1:5].isdigit()
    if not base or not value[1:5].isascii():
        return False
    if len(value) == 5:
        return True
    return (
        len(value) == 9
        and value[5] == "."
        and value[6:9].isascii()
        and value[6:9].isdigit()
    )


def contract_major(version: str) -> int | None:
    """The major of a well-formed ``X.Y.Z`` version, read as a number.

    ``robodr_ocsf::validate::contract_major``: exactly three parts, each 1-9
    ASCII decimal digits, leading zeros allowed (``02.1.0`` is major 2);
    anything else is malformed.
    """
    if (match := _VERSION_RE.fullmatch(version)) is None:
        return None
    return int(match.group(1))


def rfc3339_ms(ms: int) -> str:
    """``robodr_ocsf::rfc3339_ms``: UTC, millisecond precision, ``Z`` suffix."""
    secs, millis = divmod(ms, 1000)
    days, sod = divmod(secs, 86_400)
    z = days + 719_468
    era = z // 146_097
    doe = z % 146_097
    yoe = (doe - doe // 1460 + doe // 36_524 - doe // 146_096) // 365
    year = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    if month <= 2:
        year += 1
    return (
        f"{year:04}-{month:02}-{day:02}T{sod // 3600:02}:{(sod % 3600) // 60:02}:"
        f"{sod % 60:02}.{millis:03}Z"
    )


# --- raw document checks ------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-JSON number {name}")


def _parse_float(literal: str) -> float:
    value = float(literal)
    if value in (float("inf"), float("-inf")):
        raise ValueError("number out of range")
    return value


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON object key {key!r}")
        out[key] = value
    return out


def loads_strict(text: str) -> Any:
    """Parse JSON refusing duplicate keys and NaN/Infinity.

    Raises:
        ValueError: The text is not strict JSON (``json.JSONDecodeError`` is a
            subclass), or it nests deeper than serde_json allows.
    """
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting too deep") from exc


def _escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


# Printable ASCII U+0020-U+007E minus `<`, `>` and the backtick.
_UNSAFE_CHAR_RE: Final = re.compile(r"[^ -;=?-_a-~]")


def _check_str(path: str, value: str, errs: list[str]) -> None:
    if len(value) > MAX_STRING_BYTES or (
        not value.isascii()
        and len(value.encode("utf-8", "surrogatepass")) > MAX_STRING_BYTES
    ):
        errs.append(f"{path}: string longer than {MAX_STRING_BYTES} bytes")
    if bad := _UNSAFE_CHAR_RE.search(value):
        errs.append(f"{path}: forbidden character U+{ord(bad.group()):04X}")


def _walk_strings(value: Any, path: str, errs: list[str], depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        errs.append(f"{path}: nesting deeper than {MAX_JSON_DEPTH}")
        return
    match value:
        case str():
            _check_str(path, value, errs)
        case list():
            for i, item in enumerate(value):
                _walk_strings(item, f"{path}/{i}", errs, depth + 1)
        case dict():
            for key, item in value.items():
                child = f"{path}/{_escape_pointer_token(key)}"
                _check_str(child, key, errs)
                _walk_strings(item, child, errs, depth + 1)
        case _:
            pass


def _collect_tainted(value: Any, path: str, out: list[str]) -> None:
    match value:
        case list():
            for i, item in enumerate(value):
                _collect_tainted(item, f"{path}/{i}", out)
        case dict():
            labels = value.get("labels")
            tainted_value = value.get("taint") == "adversary"
            tainted_resource = isinstance(labels, list) and TAINT_LABEL in labels
            if tainted_value or tainted_resource:
                out.append(path)
            for key, item in value.items():
                _collect_tainted(item, f"{path}/{_escape_pointer_token(key)}", out)
        case _:
            pass


# --- typed checks --------------------------------------------------------------


class _Checker:
    def __init__(self) -> None:
        self.errs: list[str] = []

    def push(self, problem: str) -> None:
        self.errs.append(problem)

    def eq(self, a: object, b: object, what: str) -> None:
        if a != b:
            self.push(f"inconsistent: {what}")

    def fmt(self, ok: bool, path: str, reason: str) -> None:
        if not ok:
            self.push(f"{path}: {reason}")

    def length(self, path: str, value: str, lo: int, hi: int) -> None:
        if len(value) < lo:
            self.push(f"{path}: empty")
        if len(value) > hi:
            self.push(f"{path}: {len(value)} bytes > {hi}")

    def sha(self, path: str, value: str) -> None:
        self.fmt(_is_sha256_hex(value), path, "expected 64 lower-case hex chars")

    def float_value(self, path: str, value: float | None, hi: float | None) -> None:
        if value is None:
            return
        finite = value == value and value not in (float("inf"), float("-inf"))
        if not (finite and value >= 0.0 and (hi is None or value <= hi)):
            self.push(f"{path}: out of range ({value})")

    def tainted(
        self, path: str, tainted: dict[str, Any], cap: int, charset: Charset
    ) -> None:
        value: str = tainted["value"]
        self.eq(
            tainted["taint"], "adversary", "tainted value must carry taint=adversary"
        )
        if len(value) > escaped_cap(cap):
            self.push(f"{path}: {len(value)} bytes > {escaped_cap(cap)}")
        self.sha(f"{path}/original_sha256", tainted["original_sha256"])
        raw = unescape(value) if is_encoded(value, charset) else None
        if raw is None:
            self.push(f"{path}: tainted value not neutralised")
            return
        self.fmt(
            tainted["escaped"] == ("\\" in value),
            f"{path}/escaped",
            "escaped flag does not match the value",
        )
        n_chars = len(raw)
        if n_chars > cap:
            self.push(f"{path}: {n_chars} characters > {cap}")
        raw_bytes = raw.encode("utf-8")
        non_ascii = not raw.isascii()
        hint = looks_like_injection(raw)
        truncated: bool = tainted["truncated"]
        self.fmt(
            tainted["non_ascii"] or not non_ascii,
            f"{path}/non_ascii",
            "value escapes a non-ASCII character but non_ascii is false",
        )
        self.fmt(
            tainted["non_ascii"] or not tainted["mixed_script"],
            f"{path}/mixed_script",
            "mixed_script requires non_ascii",
        )
        if not truncated:
            digest = hashlib.sha256(raw_bytes).hexdigest()
            self.fmt(
                tainted["original_len"] == len(raw_bytes)
                and tainted["original_sha256"] == digest,
                f"{path}/original_sha256",
                "untruncated value does not decode to the hashed original",
            )
            self.fmt(
                tainted["non_ascii"] == non_ascii,
                f"{path}/non_ascii",
                "non_ascii does not match the value",
            )
            self.fmt(
                tainted["injection_hint"] == hint,
                f"{path}/injection_hint",
                "injection_hint does not match the value",
            )
        else:
            self.fmt(
                n_chars == cap and tainted["original_len"] > len(raw_bytes),
                f"{path}/truncated",
                "truncated value must keep exactly cap characters of a longer original",
            )
            self.fmt(
                tainted["injection_hint"] or not hint,
                path,
                "hint flags weaker than the kept prefix",
            )
        self.fmt(
            tainted["display"] == render(raw, charset),
            f"{path}/display",
            "display is not the ASCII-safe rendering of the value",
        )
        flags_or = (
            tainted["escaped"]
            or truncated
            or tainted["non_ascii"]
            or tainted["mixed_script"]
            or tainted["injection_hint"]
        )
        self.fmt(
            tainted["suspicious"] == flags_or,
            f"{path}/suspicious",
            "suspicious must be the OR of the other flags",
        )


def _validate_typed(env: dict[str, Any]) -> None:
    """Port of ``robodr_ocsf::validate::validate`` for contract 2.x."""
    c = _Checker()
    o = env["ocsf"]
    ec = env["entity_context"]
    fi = o["finding_info"]
    robot = ec["robot"]

    c.fmt(
        is_valid_data_source(env["data_source"]),
        "/data_source",
        "expected [a-z0-9][a-z0-9._-]{0,63}",
    )
    c.fmt(
        _is_prefixed_uid(env["finding_id"], "rf1-"),
        "/finding_id",
        "expected rf1-<32 hex>",
    )
    c.eq(env["finding_id"], fi["uid"], "finding_id == ocsf.finding_info.uid")
    c.eq(
        env["external_id"],
        f"{robot['id']}:{env['finding_id']}",
        "external_id == <robot_id>:<finding_id>",
    )
    c.fmt(
        is_valid_robot_id(robot["id"]),
        "/entity_context/robot/id",
        "robot id charset/length",
    )
    c.fmt(
        is_valid_rule_id(ec["rule_id"]),
        "/entity_context/rule_id",
        "rule id charset/length",
    )

    c.length("/title", env["title"], 1, MAX_TITLE)
    c.length("/description", env["description"], 1, MAX_DESCRIPTION)
    c.eq(env["title"], fi["title"], "title == finding_info.title")
    c.eq(env["title"], o["message"], "title == ocsf.message")
    c.eq(env["description"], fi["desc"], "description == finding_info.desc")
    c.length("/entity_context/robot/model", robot["model"], 1, MAX_LABEL)
    c.length("/entity_context/robot/site", robot["site"], 1, MAX_LABEL)
    c.length("/entity_context/profile/version", ec["profile"]["version"], 1, MAX_LABEL)
    c.sha("/entity_context/profile/sha256", ec["profile"]["sha256"])
    if (firmware := robot.get("firmware")) is not None:
        c.length(
            "/entity_context/robot/firmware/version", firmware["version"], 1, MAX_LABEL
        )
        c.sha("/entity_context/robot/firmware/sha256", firmware["sha256"])

    c.eq(o["severity_id"], SEVERITY_IDS[env["severity"]], "severity_id <-> severity")
    c.eq(o["severity"], SEVERITY_NAMES[env["severity"]], "ocsf.severity caption")

    c.eq(o["class_uid"], 2004, "class_uid == 2004")
    c.eq(o["class_name"], "Detection Finding", "class_name")
    c.eq(o["category_uid"], 2, "category_uid == 2")
    c.eq(o["category_name"], "Findings", "category_name")
    if (activity := _ACTIVITY_NAMES.get(o["activity_id"])) is None:
        c.push(f"/ocsf/activity_id: out of range ({o['activity_id']})")
    else:
        c.eq(o["activity_name"], activity, "activity_name caption")
        c.eq(o["type_name"], f"Detection Finding: {activity}", "type_name")
    c.eq(
        o["type_uid"],
        2004 * 100 + o["activity_id"],
        "type_uid == class_uid*100 + activity_id",
    )
    if (status := _STATUS_NAMES.get(o["status_id"])) is None:
        c.push(f"/ocsf/status_id: out of range ({o['status_id']})")
    else:
        c.eq(o["status"], status, "status caption")

    if o["count"] == 0:
        c.push("/ocsf/count: out of range (0)")
    c.eq(o["count"], ec["occurrence_count"], "ocsf.count == occurrence_count")
    if o["activity_id"] == 1 and o["count"] != 1:
        c.push("inconsistent: activity Create requires count == 1")
    if o["activity_id"] == 2 and o["count"] < 2:
        c.push("inconsistent: activity Update requires count >= 2")

    for path, t in (
        ("/ocsf/time", o["time"]),
        ("/ocsf/finding_info/first_seen_time", fi["first_seen_time"]),
        ("/ocsf/finding_info/last_seen_time", fi["last_seen_time"]),
    ):
        if not MIN_TIME_MS <= t < MAX_TIME_MS:
            c.push(f"{path}: out of range ({t})")
    if fi["first_seen_time"] > fi["last_seen_time"]:
        c.push("inconsistent: first_seen_time <= last_seen_time")
    c.eq(o["time"], fi["last_seen_time"], "time == last_seen_time")
    c.eq(env["timestamp"], rfc3339_ms(o["time"]), "timestamp == rfc3339(time)")

    meta = o["metadata"]
    c.eq(meta["version"], OCSF_VERSION, "metadata.version")
    c.eq(meta["product"]["name"], PRODUCT_NAME, "metadata.product.name")
    c.eq(meta["product"]["vendor_name"], VENDOR_NAME, "metadata.product.vendor_name")
    c.length("/ocsf/metadata/product/version", meta["product"]["version"], 1, MAX_LABEL)
    c.fmt(
        _is_prefixed_uid(meta["uid"], "re1-"),
        "/ocsf/metadata/uid",
        "expected re1-<32 hex>",
    )
    c.fmt(
        _is_valid_topic(meta["log_name"]),
        "/ocsf/metadata/log_name",
        "expected a topic name [A-Za-z0-9._-]{1,249}",
    )

    analytic = fi["analytic"]
    c.eq(analytic["uid"], ec["rule_id"], "analytic.uid == rule_id")
    c.eq(analytic["name"], ec["rule_id"], "analytic.name == rule_id")
    c.eq(analytic["type_id"], 1, "analytic.type_id == 1 (Rule)")
    c.eq(analytic["type"], "Rule", "analytic.type")
    info = rule_info_for_contract(ec["rule_id"], env["contract_version"])
    c.eq(env["title"], info.title, "title == catalog title of rule_id")
    c.fmt(
        env["description"].startswith(info.desc),
        "/description",
        "description must start with the catalog description of rule_id",
    )
    c.fmt(
        fi["types"] == ["robot_deviation", info.data_source],
        "/ocsf/finding_info/types",
        'expected ["robot_deviation", <catalog data source of rule_id>]',
    )
    c.fmt(
        fi["data_sources"] == [info.data_source],
        "/ocsf/finding_info/data_sources",
        "expected [<catalog data source of rule_id>]",
    )

    predictions = env["mitre_predictions"]
    attacks = fi["attacks"]
    if len(predictions) > MAX_TECHNIQUES:
        c.push(f"/mitre_predictions: {len(predictions)} items > {MAX_TECHNIQUES}")
    c.eq(len(predictions), len(attacks), "mitre_predictions <-> attacks")
    catalog_ok = [
        (mp["technique_id"], mp["technique_name"]) for mp in predictions
    ] == list(info.techniques)
    c.fmt(
        catalog_ok,
        "/mitre_predictions",
        "ATT&CK techniques must be exactly the catalog entries of rule_id",
    )
    for i, (mp, attack) in enumerate(zip(predictions, attacks, strict=False)):
        path = f"/mitre_predictions/{i}"
        c.fmt(
            _is_technique_id(mp["technique_id"]),
            path,
            "technique id must be Tnnnn[.nnn]",
        )
        c.length(f"{path}/technique_name", mp["technique_name"], 1, MAX_LABEL)
        c.eq(mp["framework"], "attack_ics", "mitre framework")
        c.eq(mp["provenance"], "sensor", "mitre provenance == sensor")
        c.eq(mp["technique_id"], attack["technique"]["uid"], "attacks[].technique.uid")
        c.eq(
            mp["technique_name"],
            attack["technique"]["name"],
            "attacks[].technique.name",
        )

    device = o["device"]
    c.eq(device["uid"], robot["id"], "device.uid == robot id")
    c.eq(device["name"], robot["id"], "device.name == robot id")
    c.eq(device["model"], robot["model"], "device.model == robot model")
    c.eq(device["type_id"], 99, "device.type_id == 99 (Other)")
    c.eq(device["type"], "Robot", "device.type")

    evidences = o["evidences"]
    links = env["evidence_links"]
    if len(evidences) > MAX_EVIDENCE:
        c.push(f"/ocsf/evidences: {len(evidences)} items > {MAX_EVIDENCE}")
    c.eq(len(evidences), len(links), "evidences <-> evidence_links")
    for i, (evidence, link) in enumerate(zip(evidences, links, strict=False)):
        data = evidence["data"]
        c.eq(data["kind"], "robodr.blackbox", "evidence kind")
        c.sha(f"/ocsf/evidences/{i}/data/sha256", data["sha256"])
        uri = (
            f"robodr-blackbox://{robot['id']}/{data['segment']}/{data['seq']}"
            f"?sha256={data['sha256']}"
        )
        c.eq(data["uri"], uri, "evidence uri")
        c.eq(link, uri, "evidence_links[i] == evidences[i].data.uri")

    resources_list = o["resources"]
    if len(resources_list) > MAX_RESOURCES:
        c.push(f"/ocsf/resources: {len(resources_list)} items > {MAX_RESOURCES}")
    for i, resource in enumerate(resources_list):
        path = f"/ocsf/resources/{i}"
        if (cap := _RESOURCE_CAPS.get(resource["type"])) is None:
            c.push(f"{path}/type: out of range ({resource['type']})")
            continue
        if TAINT_LABEL not in resource["labels"]:
            c.push("missing: resources[].labels taint:adversary")
        c.fmt(
            resource["labels"] == [TAINT_LABEL],
            f"{path}/labels",
            'labels must be exactly ["taint:adversary"]',
        )
        if "uid" not in resource and "name" not in resource:
            c.push("missing: resources[].uid or name")
        for key in ("uid", "name"):
            if (value := resource.get(key)) is None:
                continue
            c.fmt(
                is_encoded(value, Charset.ROS_NAME),
                f"{path}/{key}",
                "tainted value not neutralised",
            )
            if len(value) > escaped_cap(cap):
                c.push(f"{path}/{key}: {len(value)} bytes > {escaped_cap(cap)}")

    c.eq(o["unmapped"]["robodr"], ec, "ocsf.unmapped.robodr == entity_context")
    ros = ec["ros"]
    for key, cap in _ROS_FIELDS:
        if (tainted := ros.get(key)) is not None:
            c.tainted(f"/entity_context/ros/{key}", tainted, cap, Charset.ROS_NAME)
    c.tainted("/entity_context/detail", ec["detail"], TaintCap.DETAIL, Charset.TEXT)
    if (command := ec.get("command")) is not None:
        c.tainted(
            "/entity_context/command/channel",
            command["channel"],
            TaintCap.TOPIC,
            Charset.ROS_NAME,
        )
        for key in (
            "linear_speed",
            "joint_speed",
            "envelope_max_linear_speed",
            "envelope_max_joint_speed",
        ):
            c.float_value(f"/entity_context/command/{key}", command.get(key), None)
    c.float_value("/anomaly_score", env.get("anomaly_score"), 1.0)

    # The raw document's strings were checked before projection; the typed
    # projection holds a subset of them (plus empty serde defaults).
    expected: list[str] = []
    _collect_tainted(env, "", expected)
    expected.sort()
    if env["adversary_controlled_fields"] != expected:
        c.push(
            "inconsistent: adversary_controlled_fields must list every tainted "
            "value (sorted)"
        )
    if len(orjson.dumps(env)) > MAX_FINDING_BYTES:
        c.push(f"finding is larger than {MAX_FINDING_BYTES} bytes")

    if c.errs:
        raise FindingValidationError(c.errs)


def check_contract_major(raw: bytes) -> None:
    """Refuse a value that names another contract major (ingest §4 step 5.2).

    Runs before validation: a JSON object whose ``contract_version`` is a
    well-formed version (:func:`contract_major`) with ``MAJOR != 2``. The
    object is read as the reference consumer reads it (``serde_json``):
    integers beyond 64 bits are numbers, NaN, infinite numbers, lone
    surrogate escapes and nesting deeper than 127 make it unreadable. An
    unreadable value or a malformed version is left to the validator
    (``invalid_finding``).

    Raises:
        UnsupportedContractError: The value names another major.
    """
    document = _loads_like_serde(raw)
    if not isinstance(document, dict):
        return
    version = document.get("contract_version")
    if not isinstance(version, str):
        return
    major = contract_major(version)
    if major is None or major == CONTRACT_MAJOR:
        return
    if _nests_deeper_than(document, _SERDE_MAX_NESTING):
        return
    raise UnsupportedContractError(version)


# serde_json's recursion limit: at most 127 nested arrays and objects.
_SERDE_MAX_NESTING: Final = 127


def _loads_like_serde(raw: bytes) -> Any:
    """Parse JSON like ``serde_json::from_slice``; ``None`` if it would fail."""
    try:
        return orjson.loads(raw)
    except orjson.JSONDecodeError:
        pass
    # orjson refuses some JSON that serde_json reads (integers beyond 64
    # bits); the standard library reads those, and refuses what serde does.
    try:
        document = json.loads(
            raw, parse_constant=_reject_constant, parse_float=_parse_float
        )
    except (ValueError, RecursionError):
        return None
    if _nests_deeper_than(document, _SERDE_MAX_NESTING) or _has_lone_surrogate(
        document
    ):
        return None
    return document


def _has_lone_surrogate(value: Any) -> bool:
    """Whether any string (key or value) holds a lone surrogate code point."""
    stack: list[Any] = [value]
    while stack:
        match stack.pop():
            case str() as text if not text.isascii():
                if any("\ud800" <= ch <= "\udfff" for ch in text):
                    return True
            case list() as items:
                stack.extend(items)
            case dict() as mapping:
                stack.extend(mapping.keys())
                stack.extend(mapping.values())
            case _:
                pass
    return False


def _nests_deeper_than(value: Any, limit: int) -> bool:
    """Whether ``value`` nests more than ``limit`` arrays and objects deep."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        match item:
            case dict():
                children: Iterable[Any] = item.values()
            case list():
                children = item
            case _:
                continue
        if depth + 1 > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def parse_and_validate(raw: bytes) -> ValidatedFinding:
    """Validate one record value exactly as received.

    Args:
        raw: The decoded ``value`` bytes from an ingest line.

    Returns:
        The validated finding.

    Raises:
        UnsupportedContractError: A well-formed contract version whose major
            is not 2.
        FindingValidationError: Anything else that is not a valid 2.x value.
    """
    check_contract_major(raw)
    if len(raw) > MAX_FINDING_BYTES:
        raise FindingValidationError(
            [f"finding is {len(raw)} bytes > {MAX_FINDING_BYTES}"]
        )
    try:
        text = raw.decode("utf-8")
        document = loads_strict(text)
    except ValueError as exc:
        raise FindingValidationError([f"parse error: {exc}"]) from None

    errs: list[str] = []
    _walk_strings(document, "", errs)
    if errs:
        raise FindingValidationError(errs)
    if not isinstance(document, dict):
        raise FindingValidationError(["parse error: expected a JSON object"])

    version = document.get("contract_version")
    if isinstance(version, str) and contract_major(version) != CONTRACT_MAJOR:
        raise FindingValidationError(
            ["/contract_version: unsupported contract major version"]
        )

    env = _ENVELOPE(document, "", errs)
    if errs or env is _MISSING:
        raise FindingValidationError(errs or ["parse error"])
    _validate_typed(env)

    ec = env["entity_context"]
    o = env["ocsf"]
    return ValidatedFinding(
        contract_version=env["contract_version"],
        finding_id=env["finding_id"],
        external_id=env["external_id"],
        data_source=env["data_source"],
        robot_id=ec["robot"]["id"],
        rule_id=ec["rule_id"],
        title=env["title"],
        description=env["description"],
        severity=env["severity"],
        severity_id=o["severity_id"],
        event_uid=o["metadata"]["uid"],
        first_seen_ms=o["finding_info"]["first_seen_time"],
        last_seen_ms=o["finding_info"]["last_seen_time"],
        occurrence_count=o["count"],
        robot_model=ec["robot"]["model"],
        robot_site=ec["robot"]["site"],
        platform_family=ec["robot"]["platform_family"],
        mode=ec["mode"],
        motion=ec["safety_state"]["motion"],
        human_proximity=ec["safety_state"]["human_proximity"],
        attestation=ec["attestation"],
        techniques=tuple(mp["technique_id"] for mp in env["mitre_predictions"]),
        evidence_links=tuple(env["evidence_links"]),
        adversary_controlled_fields=tuple(env["adversary_controlled_fields"]),
        document=env,
    )
