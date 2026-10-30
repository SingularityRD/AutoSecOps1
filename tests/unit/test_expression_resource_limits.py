"""Expressions must fail cleanly instead of exhausting a shared worker.

Expressions are evaluated inside worker processes shared by every workspace.
Before these limits, ``FN.pow(9, FN.pow(9, 9))`` held the GIL for hours,
``'a' * 10**10`` tried to allocate gigabytes, a 400-term ``1 + 1 + ...`` raised
RecursionError instead of an expression error, and ``FN.format`` could walk
Python object attributes with ``{0.__class__}``.
"""

import time

import pytest

from autosecops.exceptions import AutoSecOpsExpressionError
from autosecops.expressions import functions
from autosecops.expressions.eval import eval_templated_object
from autosecops.expressions.parser.core import MAX_EXPRESSION_DEPTH, parser


def _eval(expr: str) -> object:
    return eval_templated_object(f"${{{{ {expr} }}}}", operand={})


@pytest.mark.parametrize(
    "expr",
    [
        "FN.pow(9, FN.pow(9, 9))",
        "FN.pow(2, 100000)",
        "FN.mul(FN.pow(2, 16000), FN.pow(2, 16000))",
        "'ab' * 100000000",
        "100000000 * 'ab'",
        "[1] * 100000000",
        "FN.range(0, 100000000000)",
        "FN.iter_product(FN.range(0, 10000), FN.range(0, 10000))",
        "FN.format('{:>1000000000}', 1)",
        "'%1000000000d' % 1",
        # "*" takes the width from the arguments; FN.zip yields a tuple.
        "'%*d' % FN.zip([1000000000], [1])[0]",
        "'%.*f' % FN.zip([1000000000], [1])[0]",
    ],
)
def test_resource_heavy_expressions_are_rejected_quickly(expr: str) -> None:
    started = time.monotonic()
    with pytest.raises(AutoSecOpsExpressionError):
        _eval(expr)
    assert time.monotonic() - started < 2


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("FN.pow(2, 64)", 2**64),
        ("FN.pow(10, 18)", 10**18),
        ("FN.pow(1, 10000000)", 1),
        ("FN.pow(2.5, 2)", 6.25),
        ("FN.pow(2, -1)", 0.5),
        ("'ab' * 3", "ababab"),
        ("2 * [0]", [0, 0]),
        ("6 * 7", 42),
        ("FN.range(0, 3)", [0, 1, 2]),
        ("FN.format('{} {}', 'a', 1)", "a 1"),
        ("FN.format('{0:>4}', 'a')", "   a"),
        ("'%05d' % 42", "00042"),
        ("'100%% of %s' % 'x'", "100% of x"),
        ("'Order 50000000000 %s' % 'x'", "Order 50000000000 x"),
    ],
)
def test_ordinary_arithmetic_still_works(expr: str, expected: object) -> None:
    assert _eval(expr) == expected


@pytest.mark.parametrize(
    "template",
    [
        "{0.__class__}",
        "{0.__class__.__mro__}",
        "{0[key]}",
        "{0.real}",
        "{0:{1}}",
    ],
)
def test_format_rejects_attribute_and_index_fields(template: str) -> None:
    with pytest.raises(ValueError):
        functions.format_string(template, {"key": 1}, 1)


@pytest.mark.parametrize(
    "expr",
    [
        " + ".join(["1"] * 1000),
        "-" * 1000 + "1",
        "[" * 500 + "]" * 500,
        "FN.add(1, " * 500 + "1" + ")" * 500,
    ],
)
def test_deeply_nested_expressions_raise_expression_errors(expr: str) -> None:
    with pytest.raises(AutoSecOpsExpressionError, match="nested too deeply"):
        parser.parse(expr)
    with pytest.raises(AutoSecOpsExpressionError):
        _eval(expr)


def test_expressions_at_the_depth_limit_still_evaluate() -> None:
    terms = MAX_EXPRESSION_DEPTH - 10
    assert _eval(" + ".join(["1"] * terms)) == terms
