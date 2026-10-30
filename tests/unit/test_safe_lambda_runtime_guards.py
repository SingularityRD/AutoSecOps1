"""Runtime guards of the safe_lambda sandbox that static checks cannot cover."""

from __future__ import annotations

import ast
import sys

import pytest

from autosecops.sandbox.safe_lambda import SafeLambdaValidator, build_safe_lambda


def test_generator_results_are_refused() -> None:
    """A returned generator would expose ``gi_frame`` to the caller."""
    fn = build_safe_lambda("lambda x: (i for i in x)")
    with pytest.raises(ValueError, match="unsafe type: generator"):
        fn([1, 2])


@pytest.mark.parametrize(
    "expr",
    ["lambda x: range(3)", "lambda x: reversed(x)", "lambda x: zip(x, x)"],
)
def test_lazy_iterators_are_refused(expr: str) -> None:
    with pytest.raises(ValueError, match="unsafe type"):
        build_safe_lambda(expr)([1, 2])


def test_input_size_is_bounded() -> None:
    fn = build_safe_lambda("lambda x: len(x)")
    assert fn(list(range(10_000))) == 10_000
    with pytest.raises(ValueError, match="maximum iteration limit"):
        fn(list(range(10_001)))
    with pytest.raises(ValueError, match="maximum iteration limit"):
        fn({i: i for i in range(10_001)})


def test_recursion_limit_is_restored_when_the_lambda_raises() -> None:
    before = sys.getrecursionlimit()
    fn = build_safe_lambda("lambda x: x[0] // 0")

    with pytest.raises(ZeroDivisionError):
        fn([1])

    assert sys.getrecursionlimit() == before


def test_format_spec_nesting_is_bounded() -> None:
    build_safe_lambda('lambda x: "{0:{1}}".format(x, 5)')
    with pytest.raises(ValueError, match="nests replacement fields too deeply"):
        build_safe_lambda('lambda x: "{0:{1:{2:{3:{4}}}}}".format(x, 1, 2, 3, 4)')


@pytest.mark.parametrize(
    ("source", "mode", "message"),
    [
        pytest.param("import os", "exec", "Restricted node Import", id="import"),
        pytest.param("x.__class__", "eval", "dunder attribute", id="dunder"),
        pytest.param("x.f_globals", "eval", "restricted attribute", id="frame_attr"),
        pytest.param("x.format(1)", "eval", "only allowed on a string", id="format"),
    ],
)
def test_validator_rejects_without_the_string_prefilter(
    source: str, mode: str, message: str
) -> None:
    """The AST validator holds even when the substring pre-filter is bypassed."""
    with pytest.raises(ValueError, match=message):
        SafeLambdaValidator().visit(ast.parse(source, mode=mode))
