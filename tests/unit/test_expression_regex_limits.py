"""User regexes in expressions must not stall a shared worker.

``FN.regex_*`` used to run user patterns on ``re``, which backtracks without
limit while holding the GIL: ``FN.regex_match('(a|a)*$', 'aaaa...!')`` with 40
characters would run for days and block every other workflow in the process.
"""

import re
import threading
import time

import pytest

from autosecops import config
from autosecops.exceptions import AutoSecOpsExpressionError
from autosecops.expressions import functions, user_regex
from autosecops.expressions.eval import eval_templated_object

EVIL_TEXT = "a" * 40 + "!"


@pytest.fixture(autouse=True)
def short_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EXPRESSION_REGEX_TIMEOUT_SECONDS", 0.1)


@pytest.mark.parametrize(
    "function", ["regex_match", "regex_not_match", "regex_extract"]
)
@pytest.mark.parametrize("pattern", [r"(a|a)*$", r"(?:a|a)+$", r"((a|a)|a)*$"])
def test_catastrophic_backtracking_times_out(function: str, pattern: str) -> None:
    started = time.monotonic()
    with pytest.raises(AutoSecOpsExpressionError, match="took longer than 0.1s"):
        eval_templated_object(
            f"${{{{ FN.{function}(TRIGGER.pattern, TRIGGER.text) }}}}",
            operand={"TRIGGER": {"pattern": pattern, "text": EVIL_TEXT}},
        )
    assert time.monotonic() - started < 1


def test_backtracking_releases_the_gil() -> None:
    """Other threads keep running while a pathological pattern is matched."""
    ticks = 0
    stop = threading.Event()

    def spin() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1

    thread = threading.Thread(target=spin)
    thread.start()
    try:
        with pytest.raises(ValueError, match="took longer"):
            functions.regex_match(r"(a|a)*$", EVIL_TEXT)
    finally:
        stop.set()
        thread.join()
    assert ticks > 1000


@pytest.mark.parametrize(
    "pattern",
    [
        r"(?:x{65535}){65535}",
        r"(?:x{1000}){1000}",
        r"((x{100}){100}){100}",
        r"x{100001}",
    ],
)
def test_patterns_that_expand_too_far_are_rejected(pattern: str) -> None:
    started = time.monotonic()
    with pytest.raises(ValueError, match="Regex pattern is too large"):
        functions.regex_match(pattern, "x")
    assert time.monotonic() - started < 1


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"x{65535}", 65535),
        (r"(?:x{300}){300}", 90_300),
        (r"(a|b{100}){10}", 1000),
        (r"\d{1,3}(?:\.\d{1,3}){3}", 10),
        (r"\p{L}{5}[a{9}]{3}", 8),
        (rb"x{10}", 10),
    ],
)
def test_pattern_expansion_estimate(pattern: str | bytes, expected: int) -> None:
    assert user_regex.pattern_expansion(pattern) == expected


@pytest.mark.parametrize(
    ("function", "pattern", "text", "expected"),
    [
        ("regex_extract", r"(\w+)@(\w+)", "joé@example", "joé"),
        ("regex_extract", r"\d+", "order ٣٤ and 12", "٣٤"),
        ("regex_extract", r"(?<=id=)\w+", "id=abc", "abc"),
        ("regex_extract", r"(?P<word>a+)b", "xaab", "aa"),
        ("regex_extract", r"x", "abc", None),
        ("regex_match", r"(a)\1", "aa", True),
        ("regex_match", r"(?i)HELLO", "hello world", True),
        ("regex_match", r"^\d{4}-\d{2}-\d{2}$", "2024-01-31", True),
        ("regex_match", r"a$", "a\n", True),
        ("regex_match", r"(?=.*\d)(?=.*[a-z]).{8,}", "passw0rdx", True),
        ("regex_match", r"world", "hello world", False),
        ("regex_not_match", r"world", "hello world", True),
    ],
)
def test_normal_patterns_keep_their_results(
    function: str, pattern: str, text: str, expected: object
) -> None:
    assert getattr(functions, function)(pattern, text) == expected
    reference = {
        "regex_extract": _re_extract,
        "regex_match": lambda p, t: bool(re.match(p, t)),
        "regex_not_match": lambda p, t: not re.match(p, t),
    }[function]
    assert reference(pattern, text) == expected


def _re_extract(pattern: str, text: str) -> str | None:
    if not (match := re.search(pattern, text)):
        return None
    groups = [group for group in match.groups() if group is not None]
    return groups[0] if groups else match.group(0)


def test_invalid_patterns_keep_the_re_error() -> None:
    with pytest.raises(re.error, match="missing \\)"):
        functions.regex_match("(", "x")
