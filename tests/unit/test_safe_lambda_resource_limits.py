"""A safe lambda must fail fast instead of exhausting a shared worker.

Lambdas (``python_lambda`` in ``core.transform`` and the HTTP polling and
pagination actions) run inside executor processes shared by every workspace.
Before these limits ``lambda x: 9**9**9`` held the GIL indefinitely,
``[i for i in range(10**6) for j in range(10**6)]`` ran for hours and
``['a' * 10**6] * 10**6`` built a result that serialized to a terabyte.
"""

import time
from collections.abc import Callable
from typing import Any

import pytest
from autosecops_registry import config as registry_config
from autosecops_registry._internal.lambda_guards import (
    LambdaResourceError,
    expanded_size,
)
from autosecops_registry._internal.safe_lambda import (
    build_safe_lambda as registry_build_safe_lambda,
)

from autosecops.sandbox.safe_lambda import build_safe_lambda

BUILDERS: list[Callable[[str], Callable[[Any], Any]]] = [
    build_safe_lambda,
    registry_build_safe_lambda,
]
FAST_SECONDS = 0.5


@pytest.fixture(params=BUILDERS, ids=["autosecops", "registry"])
def builder(request: pytest.FixtureRequest) -> Callable[[str], Callable[[Any], Any]]:
    return request.param


def _fails_fast(
    builder: Callable[[str], Callable[[Any], Any]],
    lambda_str: str,
    argument: object = None,
    match: str | None = None,
) -> None:
    started = time.monotonic()
    with pytest.raises(ValueError, match=match):
        builder(lambda_str)(argument)
    assert time.monotonic() - started < FAST_SECONDS


@pytest.mark.parametrize(
    "lambda_str",
    [
        "lambda x: 9**9**9",
        "lambda x: 2 ** (2**40)",
        "lambda x: (10**5000) * (10**5000)",
        "lambda x: 1 << 10**10",
        "lambda x: x ** x ** x",
    ],
)
def test_nested_exponents_are_rejected(
    builder: Callable[[str], Callable[[Any], Any]], lambda_str: str
) -> None:
    _fails_fast(builder, lambda_str, 9, match="exceed 16,384 bits")


@pytest.mark.parametrize(
    ("lambda_str", "match"),
    [
        ("lambda x: range(10**12)", "maximum is 1,000,000"),
        ("lambda x: list(range(10**12))", "maximum is 1,000,000"),
        ("lambda x: [i for i in range(10**6) for j in range(10**6)]", "steps"),
        ("lambda x: sum(1 for i in range(10**5) for j in range(10**5))", "steps"),
        (
            "lambda x: [a for a in zip(range(10**6), range(10**6))"
            " for b in zip(range(10**6), range(10**6))]",
            "steps",
        ),
        ("lambda x: [list(range(10**6)) for i in range(1000)]", "allocation"),
        ("lambda x: {i: str(i) * 1000 for i in range(10**5)}", "allocation"),
        # Appending to the list being iterated would never end.
        ("lambda x: [x.append(i) for i in x]", None),
    ],
)
def test_huge_ranges_and_comprehensions_are_rejected(
    builder: Callable[[str], Callable[[Any], Any]], lambda_str: str, match: str | None
) -> None:
    if match is None:
        assert builder(lambda_str)([1, 2, 3]) == [None, None, None]
        return
    _fails_fast(builder, lambda_str, [1], match=match)


@pytest.mark.parametrize(
    ("lambda_str", "match"),
    [
        ("lambda x: 'a' * 10**10", "maximum is 1,000,000"),
        ("lambda x: 10**10 * 'ab'", "maximum is 1,000,000"),
        ("lambda x: [0] * 10**10", "maximum is 1,000,000"),
        ("lambda x: ['a' * 10**6] * 10**6", "allocation"),
        ("lambda x: [['a' * 10**6] * 1000] * 1000", "allocation"),
        ("lambda x: ''.join(['a' * 10**5] * 10**5)", "allocation"),
        ("lambda x: str.join('', ['a' * 10**5] * 10**5)", "allocation"),
        ("lambda x: str([['a' * 10**5] * 10**4] * 10**3)", "allocation"),
        ("lambda x: f'{[\"a\" * 10**5] * 10**4}'", "allocation"),
        ("lambda x: '{}'.format(['a' * 10**5] * 10**4)", "allocation"),
        ("lambda x: '%s' % (['a' * 10**5] * 10**4,)", "allocation"),
        ("lambda x: 'a'.ljust(10**10)", "maximum is 1,000,000"),
        ("lambda x: 'a'.center(10**10)", "maximum is 1,000,000"),
        ("lambda x: '1'.zfill(10**10)", "maximum is 1,000,000"),
        ("lambda x: ('\\t' * 10**6).expandtabs(10**6)", "maximum is 1,000,000"),
        (
            "lambda x: ('\\t' * 10**6).expandtabs(tabsize=10**6)",
            "maximum is 1,000,000",
        ),
        ("lambda x: ('a' * 10**6).replace('a', 'b' * 10**6)", "allocation"),
        ("lambda x: ('a' * 10**6).translate({97: 'b' * 10**6})", "allocation"),
        ("lambda x: '{:>9999999999}'.format(1)", "Format width"),
        ("lambda x: '{0:>{1}}'.format(1, 10**10)", "Format width"),
        ("lambda x: f'{1:>{10**10}}'", "Format width"),
        ("lambda x: '%9999999999d' % 1", "Format width"),
        ("lambda x: sum([[0] * 1000] * 10**5, [])", "allocation"),
        ("lambda x: [x.extend(x) for i in range(64)]", "allocation"),
    ],
)
def test_string_and_sequence_multiplication_is_rejected(
    builder: Callable[[str], Callable[[Any], Any]], lambda_str: str, match: str
) -> None:
    _fails_fast(builder, lambda_str, [1], match=match)


def test_static_format_width_is_rejected_at_build_time(
    builder: Callable[[str], Callable[[Any], Any]],
) -> None:
    with pytest.raises(ValueError, match="Format width"):
        builder("lambda x: f'{x:>9999999999}'")


@pytest.mark.parametrize(
    "lambda_str",
    [
        "lambda x: (lambda f: f(f))(lambda f: f(f))",
        "lambda x: (lambda f: f(f, x))(lambda f, n: f(f, n + 1))",
    ],
)
def test_deep_recursion_is_rejected(
    builder: Callable[[str], Callable[[Any], Any]], lambda_str: str
) -> None:
    _fails_fast(builder, lambda_str, 0, match="maximum recursion depth")


def test_amplified_results_are_rejected(
    builder: Callable[[str], Callable[[Any], Any]],
) -> None:
    """A result made of shared references would serialize to terabytes."""
    _fails_fast(
        builder, "lambda x: [x for i in range(10**5)]", ["a" * 10**4], "too large"
    )


def test_wall_clock_limit(
    builder: Callable[[str], Callable[[Any], Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(registry_config, "AUTOSECOPS__LAMBDA_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(registry_config, "AUTOSECOPS__LAMBDA_MAX_STEPS", 10**9)
    _fails_fast(
        builder,
        "lambda x: [sorted(range(10**5)) for i in zip(range(10**6))]",
        None,
        "time limit of 0.05s",
    )


def test_limits_are_configurable(
    builder: Callable[[str], Callable[[Any], Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    fn = builder("lambda x: [i for i in range(x)]")
    assert len(fn(1000)) == 1000
    monkeypatch.setattr(registry_config, "AUTOSECOPS__LAMBDA_MAX_STEPS", 100)
    with pytest.raises(LambdaResourceError, match="budget of 100 steps"):
        fn(1000)
    monkeypatch.setattr(registry_config, "AUTOSECOPS__LAMBDA_MAX_STEPS", 10**6)
    monkeypatch.setattr(
        registry_config, "AUTOSECOPS__LAMBDA_MAX_ALLOCATION_BYTES", 1000
    )
    with pytest.raises(LambdaResourceError, match="allocation budget of 1,000"):
        fn(1000)


def test_budget_is_fresh_for_every_call(
    builder: Callable[[str], Callable[[Any], Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(registry_config, "AUTOSECOPS__LAMBDA_MAX_STEPS", 1000)
    fn = builder("lambda x: sum(i for i in range(x))")
    for _ in range(50):
        assert fn(900) == sum(range(900))


@pytest.mark.parametrize(
    "lambda_str",
    [
        "lambda x: _guard_iter",
        "lambda _guard_iter: [i for i in range(10)]",
        "lambda x: (lambda _guard_binop: 9**9**9)(None)",
        "lambda x: [_guard_alloc for _guard_alloc in x]",
    ],
)
def test_guard_helpers_cannot_be_referenced_or_shadowed(
    builder: Callable[[str], Callable[[Any], Any]], lambda_str: str
) -> None:
    with pytest.raises(ValueError, match="reserved"):
        builder(lambda_str)


@pytest.mark.parametrize(
    ("lambda_str", "argument", "expected"),
    [
        ("lambda x: 2**64", None, 2**64),
        ("lambda x: 2**-1", None, 0.5),
        ("lambda x: 'ab' * 3", None, "ababab"),
        ("lambda x: [0] * 3", None, [0, 0, 0]),
        ("lambda x: 1 << 10", None, 1024),
        ("lambda x: x % 3", 10, 1),
        ("lambda x: '%05.1f|%s' % (x, 'a')", 2.25, "002.2|a"),
        ("lambda x: x + [4]", [1, 2, 3], [1, 2, 3, 4]),
        ("lambda x: ', '.join(str(i) for i in x)", [1, 2], "1, 2"),
        ("lambda x: str.join('-', x)", ["a", "b"], "a-b"),
        ("lambda x: x.ljust(5, '.')", "ab", "ab..."),
        ("lambda x: x.replace('a', 'bb')", "aXa", "bbXbb"),
        ("lambda x: x.translate({97: 'A'})", "banana", "bAnAnA"),
        ("lambda x: '{0:>{1}}|{name}'.format(x, 4, name='n')", "a", "   a|n"),
        ("lambda x: '{a}'.format_map(x)", {"a": 1}, "1"),
        ("lambda x: f'{x:>6.2f}|{x!r}'", 3.14159, "  3.14|3.14159"),
        ("lambda x: [i * 2 for i in x if i > 1]", [1, 2, 3], [4, 6]),
        ("lambda x: {k: v for k, v in x.items() if v}", {"a": 1, "b": 0}, {"a": 1}),
        ("lambda x: sorted(x, key=lambda i: -i)", [1, 3, 2], [3, 2, 1]),
        ("lambda x: sum(x)", [1, 2, 3], 6),
        ("lambda x: sum([[1], [2]], [])", None, [1, 2]),
        ("lambda x: x[::-1]", [1, 2, 3], [3, 2, 1]),
        ("lambda x: len([i for i in range(10**5)])", None, 10**5),
        ("lambda x: x", ["a" * 10**6] * 5, ["a" * 10**6] * 5),
        ("lambda x: [1, 2] + list(range(3))", None, [1, 2, 0, 1, 2]),
    ],
)
def test_normal_lambdas_still_work(
    builder: Callable[[str], Callable[[Any], Any]],
    lambda_str: str,
    argument: object,
    expected: object,
) -> None:
    assert builder(lambda_str)(argument) == expected


def test_expanded_size_counts_shared_references() -> None:
    shared = "a" * 100
    assert expanded_size([shared] * 10, 10**6) > 10 * 100
    # The walk stops soon after passing the limit instead of visiting 10**6
    # references.
    assert 1000 < expanded_size([[shared] * 1000] * 1000, 1000) < 10_000
