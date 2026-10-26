"""SR-TAINT helpers ported from ``robodr_ocsf::taint`` (findings contract §3).

Only the consumer-side helpers are ported: charset tests, canonical escape
decoding, the ASCII-safe ``display`` rendering, and the ASCII parts of the
flag heuristics. The validator uses them to prove that a tainted value is the
canonical, lossless encoding its producer claims.
"""

from __future__ import annotations

from enum import StrEnum

TAINT_LABEL = "taint:adversary"
MAX_ESCAPE_LEN = 10
DISPLAY_PLACEHOLDER = "?"


class Charset(StrEnum):
    """Allow-list a tainted value is encoded with."""

    ROS_NAME = "ros_name"
    TEXT = "text"


class TaintCap:
    """Caps in characters of the raw input (``robodr_ocsf::taint::caps``)."""

    TOPIC = 256
    NODE = 256
    TYPE_NAME = 256
    GUID = 64
    IP = 64
    DETAIL = 400


_TEXT_EXCLUDED = frozenset("!\"#&'()*<>[\\]`{|}~")
_ROS_PUNCT = frozenset("_/.:-")

# Case-insensitive ASCII needles of ``looks_like_injection``.
_INJECTION_NEEDLES = (
    "system:",
    "system=",
    "assistant:",
    "user:",
    "developer:",
    "[inst]",
    "<|",
    "ignore",
    "disregard",
    "instruction",
    "prompt",
    "jailbreak",
    "benign",
    "false positive",
    "false_positive",
    "severity",
    "status=",
    "status:",
    "resolved",
    "verdict",
    "://",
    "www.",
    "](",
    "![",
    "&#",
    "&lt",
    "&gt",
    "&amp",
    "&quot",
    "</",
    "{{",
    "}}",
    '":',
    '","',
    '{"',
)


def escaped_cap(cap: int) -> int:
    """Byte cap of an encoded value whose raw input was capped at ``cap``."""
    return cap * MAX_ESCAPE_LEN


def _is_ascii_alnum(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9")


def is_raw(ch: str, charset: Charset) -> bool:
    """Return whether ``ch`` is copied unchanged under ``charset``."""
    if charset is Charset.ROS_NAME:
        return _is_ascii_alnum(ch) or ch in _ROS_PUNCT
    return " " <= ch <= "~" and ch not in _TEXT_EXCLUDED


def is_safe_char(ch: str) -> bool:
    """The rule for every string in a finding: printable ASCII minus ``< > \\```."""
    return " " <= ch <= "~" and ch not in "<>`"


def render(raw: str, charset: Charset) -> str:
    """ASCII-safe lossy rendering: raw-set characters kept, others ``?``."""
    return "".join(
        ch if ch != "\\" and is_raw(ch, charset) else DISPLAY_PLACEHOLDER for ch in raw
    )


def is_display(value: str, charset: Charset) -> bool:
    """Return whether ``value`` could be a :func:`render` output."""
    return all(
        ch == DISPLAY_PLACEHOLDER or (ch != "\\" and is_raw(ch, charset))
        for ch in value
    )


def _decode_escape(rest: str) -> tuple[str, int] | None:
    """Decode one escape after a backslash; ``(char, consumed)`` or ``None``."""
    if rest.startswith("\\"):
        return ("\\", 1)
    if not rest.startswith("u{"):
        return None
    body = rest[2:]
    end = body.find("}")
    if end < 0:
        return None
    digits = body[:end]
    canonical_len = 4 <= len(digits) <= 6 and (
        len(digits) == 4 or not digits.startswith("0")
    )
    if not canonical_len or any(c not in "0123456789ABCDEF" for c in digits):
        return None
    codepoint = int(digits, 16)
    if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
        return None
    return (chr(codepoint), 2 + end + 1)


def unescape(value: str) -> str | None:
    """Decode an encoded value; ``None`` on a malformed or non-canonical escape."""
    out: list[str] = []
    i = 0
    while (off := value.find("\\", i)) >= 0:
        out.append(value[i:off])
        decoded = _decode_escape(value[off + 1 :])
        if decoded is None:
            return None
        ch, consumed = decoded
        out.append(ch)
        i = off + 1 + consumed
    out.append(value[i:])
    return "".join(out)


def is_encoded(value: str, charset: Charset) -> bool:
    """Return whether ``value`` is exactly what the producer's escaping emits."""
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\":
            decoded = _decode_escape(value[i + 1 :])
            if decoded is None:
                return False
            raw_ch, consumed = decoded
            canonical = consumed == 1 if raw_ch == "\\" else not is_raw(raw_ch, charset)
            if not canonical:
                return False
            i += 1 + consumed
            continue
        if not is_raw(ch, charset):
            return False
        i += 1
    return True


def looks_like_injection(raw: str) -> bool:
    """Port of ``looks_like_injection`` (ASCII-only heuristic, exact)."""
    if "\n" in raw or "\r" in raw:
        return True
    folded = "".join(
        ch.lower()
        for ch in raw
        if ch.isascii() and not (ord(ch) < 32 or ord(ch) == 127)
    )
    return any(needle in folded for needle in _INJECTION_NEEDLES)
