"""Regression tests: str.format must not let a safe lambda walk object graphs.

``"{0.attr[key]}".format(obj)`` performs getattr and getitem at runtime. A
lambda could build such a template from string pieces (``"_" * 2`` avoids the
literal ``__`` check) and read module globals, ``sys.modules`` and the process
environment through the ``jsonpath`` helper it is given.
"""

from collections.abc import Callable
from typing import Any

import pytest
from autosecops_registry._internal.safe_lambda import (
    build_safe_lambda as registry_build_safe_lambda,
)

from autosecops.sandbox.safe_lambda import build_safe_lambda

BUILDERS: list[Callable[[str], Callable[[Any], Any]]] = [
    build_safe_lambda,
    registry_build_safe_lambda,
]
DUNDER = '"_" * 2'
ENV_CANARY = "AUTOSECOPS_SAFE_LAMBDA_CANARY"


@pytest.fixture(params=BUILDERS, ids=["autosecops", "registry"])
def builder(request: pytest.FixtureRequest) -> Callable[[str], Callable[[Any], Any]]:
    return request.param


@pytest.mark.parametrize(
    "lambda_str",
    [
        # Reads os.environ through jsonpath.__globals__ -> threading -> sys.
        (
            f'lambda x: ("{{0." + {DUNDER} + "globals" + {DUNDER} + '
            f'"[threading]._sys.modules[os].environ[{ENV_CANARY}]}}").format(jsonpath)'
        ),
        f'lambda x: ("{{0." + {DUNDER} + "class" + {DUNDER} + "}}").format(x)',
        'lambda x: "{0.real}".format(x)',
        'lambda x: "{0[key]}".format(x)',
        'lambda x: "{a.b}".format_map(x)',
        'lambda x: "{0:{1.real}}".format(x, 1)',
        # Templates that come from data or are computed are never trusted.
        "lambda x: x.format(jsonpath)",
        "lambda x: str.format(x, jsonpath)",
        "lambda x: ('{' + '0}').format(x)",
        # Taking the bound method without calling it on a literal.
        "lambda x: (lambda f: f(jsonpath))(x.format)",
        "lambda x: (lambda f: f(jsonpath))('{0}'.format)",
    ],
)
def test_format_attribute_traversal_is_rejected(
    builder: Callable[[str], Callable[[Any], Any]],
    lambda_str: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_CANARY, "canary-secret-value")
    with pytest.raises(ValueError):
        builder(lambda_str)


@pytest.mark.parametrize(
    ("lambda_str", "value", "expected"),
    [
        ('lambda x: "{} items".format(len(x))', [1, 2], "2 items"),
        ('lambda x: "{0}-{1}".format(x, x)', "a", "a-a"),
        ('lambda x: "{name}".format(name=x)', "n", "n"),
        ('lambda x: "{a}".format_map(x)', {"a": 1}, "1"),
        ('lambda x: "{0:>{1}}".format(x, 4)', "a", "   a"),
        ('lambda x: "{0!r:.3}".format(x)', "abcdef", "'ab"),
        ('lambda x: "{{literal}} {0}".format(x)', 1, "{literal} 1"),
    ],
)
def test_format_with_simple_fields_still_works(
    builder: Callable[[str], Callable[[Any], Any]],
    lambda_str: str,
    value: Any,
    expected: str,
) -> None:
    assert builder(lambda_str)(value) == expected
