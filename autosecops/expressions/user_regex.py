"""Bounded evaluation of user-supplied regular expressions.

Expressions run inside API and worker processes shared by every workspace.
Python's ``re`` backtracks without limit and holds the GIL while it does, so a
pattern such as ``(a+)+$`` against ``"aaaa...!"`` can stall a whole process.

User patterns therefore run on the ``regex`` package, whose default
``VERSION0`` mode matches ``re`` semantics, and which adds:

* a ``timeout`` that aborts a match that runs too long, and
* ``concurrent=True``, which releases the GIL while matching so other work in
  the process keeps running until the timeout fires.

Each pattern is still compiled with ``re`` first, so the accepted syntax and
the ``re.error`` messages for invalid patterns are unchanged. Two corner cases
match differently: ``[[:alpha:]]`` is a POSIX class in ``regex`` but a plain
character set in ``re``, and ``\\s`` does not match the ASCII separators
``\\x1c``-``\\x1f``.

``regex`` expands counted repeats such as ``x{1000}`` when it compiles a
pattern, and compiling is not covered by the timeout: ``(?:x{65535}){65535}``
would try to build billions of nodes. Patterns are screened first, and those
whose counted repeats would expand beyond :data:`MAX_PATTERN_EXPANSION` are
rejected with a clear error.

``google-re2`` was considered and rejected: it is linear-time, but it silently
changes results for common patterns (``\\w``, ``\\d``, ``\\s`` and ``\\b`` are
ASCII-only, ``$`` does not match before a trailing newline, and ``a{,3}`` is a
literal), and it cannot compile backreferences or lookaround at all.
"""

from __future__ import annotations

import re

import regex

from autosecops import config

MAX_PATTERN_EXPANSION = 100_000
"""Largest number of pattern nodes counted repeats may expand to."""

# Escapes whose argument is written in braces, such as \p{L}, \N{name} or
# \x{41}. Their braces are not a repeat count.
_BRACED_ESCAPES = frozenset("pPNxgu")


class _Frame:
    """Running pattern weight of one group while scanning a pattern."""

    __slots__ = ("alternatives", "current", "last_atom")

    def __init__(self) -> None:
        self.alternatives: list[int] = []
        self.current = 0
        self.last_atom = 0

    def add_atom(self, weight: int) -> None:
        self.current += weight
        self.last_atom = weight

    def repeat_last(self, count: int) -> None:
        extra = self.last_atom * (max(count, 1) - 1)
        self.current += extra
        self.last_atom += extra

    def total(self) -> int:
        return max([*self.alternatives, self.current])


def _skip_class(pattern: str, index: int) -> int:
    """Return the index just past the character class starting at ``index``."""
    index += 1
    if index < len(pattern) and pattern[index] == "^":
        index += 1
    if index < len(pattern) and pattern[index] == "]":
        index += 1
    while index < len(pattern) and pattern[index] != "]":
        index += 2 if pattern[index] == "\\" else 1
    return index + 1


def _read_repeat(pattern: str, index: int) -> tuple[int, int] | None:
    """Parse ``{m}``, ``{m,}``, ``{m,n}`` or ``{,n}`` at ``index``.

    Returns:
        The minimum count and the index just past the closing brace, or
        ``None`` when the brace is a literal.
    """
    end = pattern.find("}", index)
    if end == -1:
        return None
    low, _, high = pattern[index + 1 : end].partition(",")
    if not (low.isdigit() or (low == "" and high.isdigit())):
        return None
    if high and not high.isdigit():
        return None
    # A minimum count longer than seven digits is larger than any limit here;
    # avoid converting arbitrarily long digit strings.
    minimum = int(low[:7]) if low else 0
    if len(low) > 7:
        minimum = MAX_PATTERN_EXPANSION + 1
    return minimum, end + 1


def pattern_expansion(pattern: str | bytes) -> int:
    """Estimate how many nodes ``regex`` builds when it compiles ``pattern``.

    Counted repeats multiply the weight of the atom they follow, and nested
    groups multiply again, so ``(?:x{300}){300}`` weighs 90,000. Alternatives
    weigh as much as their largest branch.

    Args:
        pattern: The user-supplied pattern.

    Returns:
        The estimated expansion, saturated just above the limit.
    """
    if isinstance(pattern, bytes):
        pattern = pattern.decode("latin-1")
    stack = [_Frame()]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        frame = stack[-1]
        if char == "\\":
            index += 2
            if (
                index - 1 < len(pattern)
                and pattern[index - 1] in _BRACED_ESCAPES
                and index < len(pattern)
                and pattern[index] == "{"
            ):
                closing = pattern.find("}", index)
                index = len(pattern) if closing == -1 else closing + 1
            frame.add_atom(1)
            continue
        if char == "[":
            index = _skip_class(pattern, index)
            frame.add_atom(1)
            continue
        if char == "(":
            stack.append(_Frame())
            index += 1
            continue
        if char == ")" and len(stack) > 1:
            group = stack.pop()
            stack[-1].add_atom(group.total())
            index += 1
            continue
        if char == "|":
            frame.alternatives.append(frame.current)
            frame.current = 0
            frame.last_atom = 0
            index += 1
            continue
        if char == "{" and (repeat := _read_repeat(pattern, index)) is not None:
            minimum, index = repeat
            frame.repeat_last(minimum)
        else:
            if char not in "*+?":
                frame.add_atom(1)
            index += 1
        if frame.current > MAX_PATTERN_EXPANSION:
            return MAX_PATTERN_EXPANSION + 1
    while len(stack) > 1:
        group = stack.pop()
        stack[-1].add_atom(group.total())
    return stack[0].total()


def compile_user_pattern(pattern: str) -> regex.Pattern[str]:
    """Compile a user-supplied pattern after checking its compiled size.

    The pattern is first compiled with ``re``, which does not expand repeats,
    so exactly the patterns ``re`` accepted before are accepted now, with the
    same ``re.error`` messages for invalid ones.

    Args:
        pattern: The pattern from the expression.

    Returns:
        The compiled pattern.

    Raises:
        re.error: If the pattern is not a valid ``re`` pattern.
        ValueError: If the pattern would expand too far when compiled.
    """
    re.compile(pattern)
    if pattern_expansion(pattern) > MAX_PATTERN_EXPANSION:
        raise ValueError(
            "Regex pattern is too large: its counted repeats such as {1000}"
            f" would expand beyond {MAX_PATTERN_EXPANSION:,} nodes"
        )
    try:
        return regex.compile(pattern)
    except regex.error as e:
        raise ValueError(f"Invalid regex pattern: {e}") from e


def search(pattern: str, text: str) -> regex.Match[str] | None:
    """Search ``text`` for ``pattern`` within the configured timeout."""
    compiled = compile_user_pattern(pattern)
    return _bounded("regex search", compiled, text, anchored=False)


def match(pattern: str, text: str) -> regex.Match[str] | None:
    """Match ``pattern`` at the start of ``text`` within the configured timeout."""
    compiled = compile_user_pattern(pattern)
    return _bounded("regex match", compiled, text, anchored=True)


def _bounded(
    operation: str, compiled: regex.Pattern[str], text: str, *, anchored: bool
) -> regex.Match[str] | None:
    timeout = config.AUTOSECOPS__EXPRESSION_REGEX_TIMEOUT_SECONDS
    try:
        if anchored:
            return compiled.match(text, timeout=timeout, concurrent=True)
        return compiled.search(text, timeout=timeout, concurrent=True)
    except TimeoutError as e:
        raise ValueError(
            f"{operation} took longer than {timeout:g}s and was stopped. The"
            " pattern probably backtracks catastrophically; avoid nested"
            " quantifiers such as (a+)+ or overlapping alternatives such as"
            " (a|a)*"
        ) from e
