"""Property-based fuzzing of parsers that take untrusted input.

Each property states what must hold for every input, not just the examples
we thought of: parsers fail only with their documented error type, finish
quickly, keep their sandbox and secret policies, and round-trip where they
claim to. Example counts are bounded so the module stays fast in CI; set
``AUTOSECOPS_FUZZ_EXAMPLES`` to run a deeper local campaign.
"""

from __future__ import annotations

import os
import re
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from autosecops_registry._internal.safe_lambda import (
    build_safe_lambda as registry_build_safe_lambda,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError
from sqlalchemy.dialects import postgresql
from starlette.requests import Request

from autosecops import config
from autosecops.exceptions import AutoSecOpsExpressionError, AutoSecOpsValidationError
from autosecops.expressions import functions
from autosecops.expressions.eval import (
    eval_templated_object,
    extract_templated_secrets,
)
from autosecops.expressions.parser.core import parser
from autosecops.licensing.token import (
    LicenseVerificationError,
    decode_license,
    encode_license,
)
from autosecops.licensing.types import LicenseClaims
from autosecops.outbound import _bypasses_egress_proxy
from autosecops.query.compiler import compile_filter
from autosecops.query.filters import Filter, FilterOp
from autosecops.query.lexical import parse_full_text_query
from autosecops.query.resolver import FieldKind, ResolvedField
from autosecops.sandbox.safe_lambda import build_safe_lambda
from autosecops.webhooks.dependencies import (
    parse_content_type,
    parse_webhook_payload,
)
from autosecops.workflow.executions.common import build_query

EXAMPLES = int(os.environ.get("AUTOSECOPS_FUZZ_EXAMPLES", "60"))
FUZZ = settings(
    max_examples=EXAMPLES,
    deadline=None,
    database=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
SLOW_SECONDS = 2.0

# Text without NUL so it can also be placed in environment variables.
env_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    max_size=80,
)
json_leaf = (
    st.none()
    | st.booleans()
    | st.integers(-(10**6), 10**6)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=8)
)
json_value = st.recursive(
    json_leaf,
    lambda children: (
        st.lists(children, max_size=3)
        | st.dictionaries(st.text(max_size=4), children, max_size=3)
    ),
    max_leaves=8,
)


# --- Expression language -------------------------------------------------

EXPR_TOKENS = [
    "ACTIONS.a.result",
    "ACTIONS.a.result[0]",
    "SECRETS.s.k",
    "VARS.v.k",
    "TRIGGER",
    "TRIGGER.x",
    "ENV.e",
    "var.x",
    "inputs.i",
    "steps.s.result",
    "FN.add(",
    "FN.pow(",
    "FN.mul(",
    "FN.format(",
    "FN.range(",
    "FN.iter_product(",
    "FN.join(",
    "FN.length(",
    "FN.flatten(",
    "FN.lookup(",
    "FN.serialize_json(",
    "FN.deserialize_json(",
    "FN.to_datetime(",
    "FN.regex_extract(",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ":",
    "+",
    "-",
    "*",
    "/",
    "%",
    "==",
    "<",
    "&&",
    "||",
    "not",
    "in",
    "is",
    "None",
    "True",
    "0",
    "1",
    "-1",
    "2.5",
    "99999999999",
    "'a'",
    "'%s'",
    "'{}'",
    "'{0.real}'",
    "''",
    "if",
    "else",
    "->",
    "int",
    "str",
    "for",
]
expression_soup = st.lists(st.sampled_from(EXPR_TOKENS), min_size=1, max_size=14).map(
    " ".join
)
operands = st.fixed_dictionaries(
    {
        "ACTIONS": st.fixed_dictionaries(
            {"a": st.fixed_dictionaries({"result": json_value})}
        ),
        "SECRETS": st.fixed_dictionaries(
            {"s": st.fixed_dictionaries({"k": st.text(max_size=5)})}
        ),
        "VARS": st.fixed_dictionaries({"v": st.fixed_dictionaries({"k": json_value})}),
        "TRIGGER": json_value,
        "ENV": st.fixed_dictionaries({"e": json_value}),
        "var": st.fixed_dictionaries({"x": json_value}),
        "inputs": st.fixed_dictionaries({"i": json_value}),
        "steps": st.fixed_dictionaries(
            {"s": st.fixed_dictionaries({"result": json_value})}
        ),
    }
)


@FUZZ
@given(st.text(max_size=120) | expression_soup)
def test_expression_parser_only_raises_expression_errors(text: str) -> None:
    try:
        parser.parse(text)
    except AutoSecOpsExpressionError:
        pass


@FUZZ
@given(expression_soup, operands)
def test_expression_evaluation_fails_cleanly_and_quickly(
    expression: str, operand: dict[str, Any]
) -> None:
    started = time.monotonic()
    try:
        eval_templated_object(f"${{{{ {expression} }}}}", operand=operand)
    except AutoSecOpsExpressionError:
        pass
    assert time.monotonic() - started < SLOW_SECONDS


@FUZZ
@given(
    st.integers(1, 1200),
    st.sampled_from(["{} + 1", "-{}", "[{}]", "FN.add(1, {})", "({})", "not {}"]),
)
def test_deep_expressions_fail_with_expression_errors(depth: int, shape: str) -> None:
    expression = "1"
    for _ in range(depth):
        expression = shape.format(expression)
    try:
        eval_templated_object(f"${{{{ {expression} }}}}", operand={})
    except AutoSecOpsExpressionError:
        pass


@st.composite
def arithmetic(draw: st.DrawFn, depth: int = 0) -> str:
    if depth > 4 or draw(st.booleans()):
        return str(draw(st.integers(0, 10**6)))
    op = draw(st.sampled_from(["+", "-", "*"]))
    return f"({draw(arithmetic(depth + 1))} {op} {draw(arithmetic(depth + 1))})"


@FUZZ
@given(arithmetic())
def test_integer_arithmetic_matches_python(expression: str) -> None:
    expected = eval(expression, {"__builtins__": {}})  # noqa: S307 - digits and + - * only
    assert eval_templated_object(f"${{{{ {expression} }}}}", operand={}) == expected


SECRET_TOKENS = [
    "SECRETS.s1.k",
    "SECRETS.s2.k",
    "SECRETS.s1.j",
    "'SECRETS.s2.k'",
    "[SECRETS.s1.k]",
    "{'k': SECRETS.s2.k}",
    "FN.concat(",
    "FN.join(",
    "FN.format(",
    "FN.to_base64(",
    "(",
    ")",
    "[",
    "]",
    ",",
    "+",
    "if",
    "else",
    "True",
    "False",
    "'a'",
    "->",
    "str",
    "==",
]
ALL_SECRETS = {"s1": {"k": "v1", "j": "vj"}, "s2": {"k": "v2"}}


@FUZZ
@given(
    st.lists(
        st.lists(st.sampled_from(SECRET_TOKENS), min_size=1, max_size=10).map(" ".join),
        min_size=1,
        max_size=2,
    )
)
def test_secret_extraction_covers_every_secret_evaluation_reads(
    parts: list[str],
) -> None:
    """Executors load only the secrets the extractor finds.

    Evaluating against just those secrets must give the same result as
    evaluating against all of them, or a template could read a secret that
    was never loaded (or that the policy never saw).
    """
    template = " ".join(f"${{{{ {part} }}}}" for part in parts)
    try:
        full = eval_templated_object(template, operand={"SECRETS": ALL_SECRETS})
    except AutoSecOpsExpressionError:
        return
    loaded: dict[str, dict[str, str]] = {}
    for path in extract_templated_secrets(template):
        name, key = path.split(".", 1)
        loaded.setdefault(name, {})[key] = ALL_SECRETS[name][key]
    assert eval_templated_object(template, operand={"SECRETS": loaded}) == full


format_field = st.one_of(
    st.just(""),
    st.integers(0, 2).map(str),
    st.from_regex(
        r"[0-9a-z_]{1,4}(\.[a-z_]{1,8}|\[[a-z0-9_]{1,4}\]){1,3}", fullmatch=True
    ),
)
format_template = st.lists(
    st.tuples(
        st.text(alphabet="ab {}", max_size=3),
        format_field,
        st.sampled_from(["", "!r", "!s"]),
        st.sampled_from(["", ":>3", ":.2", ":{0}", ":>99999999"]),
    ),
    max_size=3,
).map(
    lambda parts: "".join(
        lit + "{" + field + conv + spec + "}" for lit, field, conv, spec in parts
    )
)
OBJECT_REPRS = ("<class", "<function", "<module", "<built-in", "<bound")


@FUZZ
@given(format_template, st.lists(json_value, max_size=3))
def test_fn_format_never_exposes_python_objects(
    template: str, values: list[Any]
) -> None:
    try:
        result = functions.format_string(template, *values)
    except (ValueError, IndexError, KeyError, TypeError, AttributeError):
        return
    assert len(result) <= functions.MAX_SEQUENCE_LENGTH + 1000
    assert not any(marker in result for marker in OBJECT_REPRS)


# --- Safe lambda sandbox -------------------------------------------------

LAMBDA_BUILDERS: list[Callable[[str], Callable[[Any], Any]]] = [
    build_safe_lambda,
    registry_build_safe_lambda,
]
CANARY_ENV = "AUTOSECOPS_FUZZ_LAMBDA_CANARY"
CANARY_VALUE = "fuzz-canary-value"


@pytest.fixture(scope="module")
def lambda_canary() -> Iterator[None]:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(CANARY_ENV, CANARY_VALUE)
        yield


@FUZZ
@given(st.text(max_size=120))
def test_safe_lambda_rejects_with_value_error_only(text: str) -> None:
    for builder in LAMBDA_BUILDERS:
        try:
            builder(text)
        except ValueError:
            pass


FIELD_STEPS = [
    ".__globals__",
    "[threading]",
    "._sys",
    ".modules",
    "[os]",
    ".environ",
    f"[{CANARY_ENV}]",
    ".__class__",
    ".real",
    "[a]",
    "[0]",
]


def _as_runtime_string(text: str) -> str:
    """Spell text as a concatenation, never as one literal or with a "__"."""
    pieces = [repr(part) if part else "'_' * 2" for part in text.split("__")]
    head, tail = pieces[0], pieces[1:]
    if head.startswith("'") and len(head) > 3:
        # Split the first literal so the receiver is never a plain constant.
        head = f"{head[:2]}' + '{head[2:]}"
    return " + ".join([head, *tail])


@pytest.mark.usefixtures("lambda_canary")
@pytest.mark.parametrize(
    "lambda_builder", LAMBDA_BUILDERS, ids=["autosecops", "registry"]
)
@FUZZ
@given(
    st.lists(st.sampled_from(FIELD_STEPS), max_size=7),
    st.sampled_from(["format", "format_map"]),
    st.sampled_from(["jsonpath", "x"]),
    st.booleans(),
)
def test_safe_lambda_format_fields_cannot_walk_objects(
    lambda_builder: Callable[[str], Callable[[Any], Any]],
    steps: list[str],
    method: str,
    argument: str,
    literal: bool,
) -> None:
    """str.format resolves "{0.a[b]}" with getattr/getitem at runtime.

    Any template with attribute or index steps must be refused, whether it is
    a literal or assembled at runtime, so a lambda cannot walk from its
    arguments to module globals or os.environ.
    """
    field = "a" if method == "format_map" else "0"
    template = "{" + field + "".join(steps) + "}"
    receiver = repr(template) if literal else f"({_as_runtime_string(template)})"
    source = f"lambda x: {receiver}.{method}({argument})"
    if steps or not literal:
        with pytest.raises(ValueError):
            lambda_builder(source)
        return
    fn = lambda_builder(source)
    try:
        result = fn({"a": 1})
    except (TypeError, KeyError, IndexError):
        return
    assert CANARY_VALUE not in repr(result)


# --- License tokens --------------------------------------------------------

_LICENSE_KEY = Ed25519PrivateKey.generate()
_LICENSE_PUBLIC_KEY = _LICENSE_KEY.public_key()
license_claims = st.builds(
    lambda license_id, customer, entitlements, days: LicenseClaims(
        license_id=license_id,
        customer=customer,
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=days),
        entitlements=entitlements,
    ),
    st.text(min_size=1, max_size=20),
    st.text(min_size=1, max_size=20),
    st.lists(st.text(max_size=10), max_size=4),
    st.integers(1, 3000),
)


@FUZZ
@given(
    st.text(max_size=200)
    | st.from_regex(r"[A-Za-z0-9_-]{0,80}\.[A-Za-z0-9_-]{0,90}", fullmatch=True)
)
def test_license_decode_rejects_garbage_with_verification_error(token: str) -> None:
    try:
        decode_license(token, _LICENSE_PUBLIC_KEY)
    except LicenseVerificationError:
        return
    pytest.fail("an unsigned token was accepted")


@FUZZ
@given(license_claims, st.data())
def test_license_round_trips_and_rejects_any_single_edit(
    claims: LicenseClaims, data: st.DataObject
) -> None:
    token = encode_license(claims, _LICENSE_KEY)
    assert decode_license(token, _LICENSE_PUBLIC_KEY) == claims
    assert decode_license(f"  {token}\n", _LICENSE_PUBLIC_KEY) == claims

    index = data.draw(st.integers(0, len(token) - 1))
    replacement = data.draw(st.sampled_from("AQgw-_.Zz09"))
    edited = token[:index] + replacement + token[index + 1 :]
    assume(edited != token)
    with pytest.raises(LicenseVerificationError):
        decode_license(edited, _LICENSE_PUBLIC_KEY)


# --- Proxy configuration ---------------------------------------------------


@FUZZ
@given(env_text)
def test_no_proxy_parsing_round_trips(
    raw: str,
) -> None:
    name = "AUTOSECOPS_FUZZ_NO_PROXY"
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(name, raw)
        try:
            entries = config.env_no_proxy(name)
        except ValueError:
            return
        mp.setenv(name, ",".join(str(entry) for entry in entries))
        assert config.env_no_proxy(name) == entries


@FUZZ
@given(
    st.from_regex(r"[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?\.[a-z]{2,6}", fullmatch=True),
    st.from_regex(r"[a-z0-9]{1,8}", fullmatch=True),
    st.text(max_size=40),
)
def test_no_proxy_matches_domain_and_subdomains_only(
    domain: str, label: str, other_host: str
) -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(config, "AUTOSECOPS__OUTBOUND_NO_PROXY", (domain,))
        assert _bypasses_egress_proxy(domain)
        assert _bypasses_egress_proxy(f"{label}.{domain}".upper())
        assert not _bypasses_egress_proxy(f"{label}{domain}")
        # Arbitrary hosts never crash the bypass check.
        _bypasses_egress_proxy(other_host)


@FUZZ
@given(
    st.sampled_from(["http", "https", "HTTP", "socks5", "", "ftp"]),
    st.from_regex(r"[a-z0-9.\[\]:]{0,20}", fullmatch=True),
    st.sampled_from(["", ":0", ":8080", ":65536", ":-1", ":x"]),
    st.sampled_from(["", "/", "/path", "?q=1", "#f"]),
)
def test_proxy_url_errors_never_echo_credentials(
    scheme: str, host: str, port: str, suffix: str
) -> None:
    password = "s3cr3t-proxy-password"
    raw = f"{scheme}://user:{password}@{host}{port}{suffix}"
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AUTOSECOPS_FUZZ_PROXY", raw)
        try:
            assert config.env_proxy_url("AUTOSECOPS_FUZZ_PROXY") == raw
        except ValueError as exc:
            assert password not in str(exc)


# --- Webhook payloads ------------------------------------------------------


@FUZZ
@given(st.text(max_size=80))
def test_content_type_parsing_never_raises(raw: str) -> None:
    mime_type, params = parse_content_type(raw)
    assert isinstance(mime_type, str)
    assert all(isinstance(key, str) for key in params)


@FUZZ
@given(
    st.binary(max_size=200)
    | json_value.map(lambda value: TypeAdapter(Any).dump_json(value)),
    st.sampled_from(
        [
            None,
            "application/json",
            "application/x-ndjson",
            "application/jsonl; charset=utf-8",
            "application/x-www-form-urlencoded",
            "text/plain",
            ";",
        ]
    ),
)
@pytest.mark.anyio
async def test_webhook_payload_parsing_returns_or_rejects_with_400(
    body: bytes, content_type: str | None
) -> None:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    headers = [(b"content-type", content_type.encode())] if content_type else []
    request = Request(
        {"type": "http", "method": "POST", "path": "/", "headers": headers},
        receive,
    )
    try:
        await parse_webhook_payload(request, content_type)
    except HTTPException as exc:
        assert exc.status_code == 400


# --- Search text and filters -----------------------------------------------


@FUZZ
@given(st.text(max_size=300))
def test_full_text_query_parsing_only_raises_value_errors(text: str) -> None:
    try:
        parse_full_text_query(text)
    except ValueError:
        pass


def _filter_field(kind: FieldKind) -> ResolvedField:
    column_types: Mapping[FieldKind, sa.types.TypeEngine[Any]] = {
        FieldKind.NUMBER: sa.Numeric(),
        FieldKind.BOOLEAN: sa.Boolean(),
        FieldKind.TEMPORAL: sa.DateTime(timezone=True),
        FieldKind.UUID: sa.Uuid(),
        FieldKind.JSON_SCALAR: postgresql.JSONB(),
    }
    return ResolvedField(
        expr=sa.column(kind.value, column_types.get(kind, sa.String())),
        kind=kind,
        allowed_ops=frozenset(FilterOp),
    )


class _AllKindsResolver:
    _fields = {
        kind.value: _filter_field(kind) for kind in FieldKind if kind != FieldKind.TAG
    }

    def resolve(self, field: str) -> ResolvedField | None:
        return self._fields.get(field)


filter_scalar = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=True, allow_infinity=True)
    | st.text(max_size=12)
    | st.sampled_from(["2026-09-01T12:00:00Z", "00000000-0000-0000-0000-000000000001"])
)
filter_condition = st.fixed_dictionaries(
    {
        "field": st.sampled_from([*(k.value for k in FieldKind), "missing", ""]),
        "op": st.sampled_from([*(op.value for op in FilterOp), "bogus"]),
    },
    optional={"value": filter_scalar | st.lists(filter_scalar, max_size=3)},
)
filter_tree = st.recursive(
    filter_condition,
    lambda children: (
        st.fixed_dictionaries({"and": st.lists(children, max_size=3)})
        | st.fixed_dictionaries({"or": st.lists(children, max_size=3)})
        | st.fixed_dictionaries({"not": children})
    ),
    max_leaves=6,
)
_FILTER = TypeAdapter(Filter)


@FUZZ
@given(filter_tree | json_value)
def test_filters_validate_and_compile_or_fail_cleanly(raw: Any) -> None:
    try:
        node = _FILTER.validate_python(raw)
    except ValidationError:
        return
    try:
        compiled = compile_filter(node, _AllKindsResolver())
    except AutoSecOpsValidationError:
        return
    compiled.compile(dialect=postgresql.dialect())


# --- Workflow execution search -------------------------------------------

_TEMPORAL_TIME = re.compile(r"'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)'")


@FUZZ
@given(
    st.datetimes(timezones=st.none() | st.timezones()),
    st.datetimes(timezones=st.none() | st.timezones()),
)
def test_execution_search_times_are_valid_temporal_timestamps(
    start: datetime, end: datetime
) -> None:
    """Every time filter renders as a 4-digit-year UTC timestamp.

    Years before 1000 rendered as "784-..." and offsets near year 1 or 9999
    overflowed; Temporal rejected the first and the second raised, both 500s.
    """
    query = build_query(
        workspace_id=uuid.uuid4(),
        start_time_from=start,
        close_time_to=end,
    )
    timestamps = _TEMPORAL_TIME.findall(query)
    assert len(timestamps) == 2
    for timestamp in timestamps:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
