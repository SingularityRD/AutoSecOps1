"""Strict NDJSON framing of the ingest body (ingest contract §2.3)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from autosecops.robot_edr.crypto import FINDING_SIG_ALG
from autosecops.robot_edr.types import LineErrorCode, LineRejection
from autosecops.robot_edr.validator import loads_strict

_LINE_KEYS = frozenset({"value", "sig"})
_SIG_KEYS = ("alg", "key_id", "sig")
_KEY_ID_RE = re.compile(r"[!-~]{1,128}")
_SIG_HEX_RE = re.compile(r"[0-9a-f]{128}")


@dataclass(frozen=True, slots=True)
class FindingSignature:
    """A well-formed per-finding signature object."""

    alg: str
    key_id: str
    sig: bytes


@dataclass(frozen=True, slots=True)
class ParsedLine:
    """A line whose framing is valid; the value is not validated yet."""

    number: int
    value: str
    sig: FindingSignature | None


def split_lines(body: bytes) -> list[bytes]:
    """Split a body into lines: LF separators, optional final LF.

    An empty body has no lines. Empty lines are kept (and later refused) so
    line numbers always match the producer's.
    """
    if not body:
        return []
    if body.endswith(b"\n"):
        body = body[:-1]
    return body.split(b"\n")


def parse_line(number: int, raw: bytes) -> ParsedLine | LineRejection:
    """Parse one line object ``{"value": "...", "sig": null | {...}}``.

    Args:
        number: The 1-based line number.
        raw: The line bytes without the LF.

    Returns:
        The parsed line, or an ``invalid_line`` rejection.
    """
    if not raw:
        return _invalid(number, "empty line")
    if b"\r" in raw:
        return _invalid(number, "line contains CR")
    try:
        text = raw.decode("utf-8")
        obj = loads_strict(text)
    except ValueError as exc:
        return _invalid(number, f"not a strict JSON object: {exc}")
    if not isinstance(obj, dict):
        return _invalid(number, "line is not a JSON object")
    if set(obj) != _LINE_KEYS:
        return _invalid(number, 'line must have exactly the keys "value" and "sig"')
    value = obj["value"]
    sig = obj["sig"]
    if not isinstance(value, str):
        return _invalid(number, '"value" must be a JSON string')
    if not _is_utf8_encodable(value):
        return _invalid(number, '"value" decodes to a lone surrogate (not UTF-8)')
    if sig is None:
        return ParsedLine(number=number, value=value, sig=None)
    if (signature := _signature(sig)) is None:
        return _invalid(
            number,
            '"sig" must be null or {"alg":"ed25519","key_id":<1-128 printable '
            'ASCII>,"sig":<128 lower-case hex>}',
        )
    return ParsedLine(number=number, value=value, sig=signature)


def _signature(sig: Any) -> FindingSignature | None:
    """A well-formed `robodr-finding-sig` object (contract §2.3), else ``None``."""
    if not isinstance(sig, dict) or set(sig) != set(_SIG_KEYS):
        return None
    alg, key_id, sig_hex = (sig[k] for k in _SIG_KEYS)
    if not all(isinstance(v, str) for v in (alg, key_id, sig_hex)):
        return None
    if alg != FINDING_SIG_ALG or not _KEY_ID_RE.fullmatch(key_id):
        return None
    if not _SIG_HEX_RE.fullmatch(sig_hex):
        return None
    return FindingSignature(alg=alg, key_id=key_id, sig=bytes.fromhex(sig_hex))


def _is_utf8_encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _invalid(number: int, detail: str) -> LineRejection:
    return LineRejection(line=number, code=LineErrorCode.INVALID_LINE, detail=detail)
