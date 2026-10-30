"""Resource guards for ``python_lambda`` evaluation.

Lambdas run inside executor and worker processes shared by every workspace.
The AST validator in ``safe_lambda`` stops sandbox escapes, but a valid lambda
can still pin a CPU or exhaust memory: ``9**9**9``, ``'a' * 10**10``,
``[i for i in range(10**6) for j in range(10**6)]`` or ``''.join(...)`` over a
list of shared references.

Evaluating each lambda in a subprocess with ``setrlimit`` would give hard
limits, but lambdas are evaluated per item (``core.transform.filter`` calls
one for every element), and a process start costs milliseconds. Instead the
lambda's AST is rewritten before it is compiled so that every operation that
can grow without bound goes through a guard:

* ``**``, ``*``, ``<<``, ``+`` and ``%`` check integer bit sizes, repetition
  lengths and printf widths before computing, as ``FN.pow`` and friends do.
* Comprehension iterations and nested lambda calls spend a step budget.
* Values built by calls, comprehensions and operators spend an allocation
  budget measured in approximate bytes.
* ``str()``, f-strings, ``str.format`` and ``%`` spend the expanded size of
  what they render, so shared references cannot multiply output size.
* String methods that can grow a string (``join``, ``ljust``, ``replace``,
  ``translate``...) check the size of their result before running.
* ``range`` is capped, and every budget check also enforces a wall-clock limit.

Each guarded operation is bounded by :data:`MAX_SEQUENCE_LENGTH` or
:data:`MAX_INT_BITS`, so no single C-level call runs long, and the budgets
bound the total.
"""

from __future__ import annotations

import ast
import re
import string
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sized
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from autosecops_registry import config

MAX_INT_BITS = 16_384
"""Largest integer result, in bits, that a lambda may produce."""
MAX_SEQUENCE_LENGTH = 1_000_000
"""Largest repetition, range, padding width or format width in a lambda."""

GUARD_PREFIX = "_guard_"
"""Prefix of the helper names injected into lambda globals."""

GROWING_METHODS = frozenset(
    {
        "center",
        "expandtabs",
        "extend",
        "format",
        "format_map",
        "join",
        "ljust",
        "replace",
        "rjust",
        "translate",
        "zfill",
    }
)
"""Methods whose result can be much larger than their receiver."""

_SIZED = (str, bytes, list, tuple, dict, set, frozenset)
_TEXT = (str, bytes)
_PRINTF_SIZES = re.compile(r"%(?:%|(?:\([^)]*\))?[-#0 +]*(\*|\d*)(?:\.(\*|\d*))?)")
_DIGITS = re.compile(r"\d+")


class LambdaResourceError(ValueError):
    """A lambda exceeded one of its resource limits."""


_CLOCK_CHECK_INTERVAL = 64
"""Read the clock on every Nth budget check; each guarded step is short."""


@dataclass(slots=True)
class _Budget:
    steps_left: int
    allocation_left: int
    deadline: float
    max_steps: int
    max_allocation: int
    timeout: float
    checks: int = 0

    def check(self) -> None:
        """Raise if any budget is exhausted."""
        if self.steps_left < 0:
            raise LambdaResourceError(
                f"Lambda exceeded its budget of {self.max_steps:,} steps"
                " (comprehension iterations and nested lambda calls)"
            )
        if self.allocation_left < 0:
            raise LambdaResourceError(
                f"Lambda exceeded its allocation budget of {self.max_allocation:,}"
                " bytes"
            )
        self.checks += 1
        if self.checks % _CLOCK_CHECK_INTERVAL == 0 and (
            time.monotonic() > self.deadline
        ):
            raise LambdaResourceError(
                f"Lambda exceeded its time limit of {self.timeout:g}s"
            )


_budget: ContextVar[_Budget | None] = ContextVar("lambda_budget", default=None)


def _active_budget() -> _Budget:
    if (budget := _budget.get()) is None:
        raise LambdaResourceError("Lambda guards ran outside a lambda evaluation")
    return budget


def _spend(*, steps: int = 0, allocation: int = 0) -> None:
    budget = _active_budget()
    budget.steps_left -= steps
    budget.allocation_left -= allocation
    budget.check()


def _remaining_allocation() -> int:
    return max(_active_budget().allocation_left, 0)


def _check_int_bits(bits: int) -> None:
    if bits > MAX_INT_BITS:
        raise LambdaResourceError(
            f"Integer result would exceed {MAX_INT_BITS:,} bits; use smaller operands"
        )


def _check_length(length: int) -> None:
    if length > MAX_SEQUENCE_LENGTH:
        raise LambdaResourceError(
            f"Result would have {length:,} items; the maximum is"
            f" {MAX_SEQUENCE_LENGTH:,}"
        )


def _check_spec(spec: str) -> None:
    """Reject widths or precisions in a format spec that build huge strings."""
    for number in _DIGITS.findall(spec):
        if len(number) > 7 or int(number) > MAX_SEQUENCE_LENGTH:
            raise LambdaResourceError(
                f"Format width or precision {number[:12]} exceeds the maximum"
                f" of {MAX_SEQUENCE_LENGTH:,}"
            )


CONTAINER_ITEM_BYTES = 16
"""Approximate bytes charged for each item of a list, tuple, dict or set."""


def shallow_size(value: object) -> int:
    """Approximate the bytes directly held by ``value``.

    Text is charged one byte per character and containers
    :data:`CONTAINER_ITEM_BYTES` per item. Items are charged where they are
    built, so this does not recurse.
    """
    if isinstance(value, _TEXT):
        return max(len(value), 1)
    if isinstance(value, _SIZED):
        return max(len(value), 1) * CONTAINER_ITEM_BYTES
    return 1


def expanded_size(value: object, limit: int) -> int:
    """Estimate how large ``value`` is when rendered or serialized.

    Shared references count every time they appear, because ``str()`` and JSON
    serialization repeat them. The walk stops as soon as the total exceeds
    ``limit``, so its cost is bounded by ``limit``.

    Args:
        value: The value to measure.
        limit: Stop measuring once the total exceeds this.

    Returns:
        The estimated size, or a number above ``limit``.
    """
    total = 0
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, _TEXT):
            total += 1 + len(item)
        elif isinstance(item, dict):
            total += 1 + 2 * len(item)
            stack.extend(_nested(item.keys()))
            stack.extend(_nested(item.values()))
        elif isinstance(item, list | tuple | set | frozenset):
            total += 1 + len(item)
            stack.extend(_nested(item))
        elif isinstance(item, int):
            total += 1 + item.bit_length() // 3
        else:
            total += 1
        if total > limit:
            break
    return total


_SMALL_INT_BITS = 64


def _nested(items: Iterable[object]) -> list[object]:
    """Children that weigh more than the one unit their parent counted."""
    return [
        child
        for child in items
        if not (
            child is None
            or (type(child) is int and child.bit_length() <= _SMALL_INT_BITS)
            or type(child) in (bool, float)
        )
    ]


def _spend_rendering(value: object) -> None:
    limit = _remaining_allocation()
    _spend(allocation=expanded_size(value, limit + 1))


# Operator guards


def _check_repeat(sequence: object, count: int) -> None:
    if count <= 0 or not isinstance(sequence, _SIZED):
        return
    _check_length(len(sequence) * count)
    if isinstance(sequence, list | tuple):
        per_copy = expanded_size(sequence, _remaining_allocation() // count + 1)
        _spend(allocation=per_copy * count)


def _check_printf(template: str | bytes, values: object) -> None:
    pattern = template if isinstance(template, str) else template.decode("latin-1")
    for width, precision in _PRINTF_SIZES.findall(pattern):
        for number in (width, precision):
            if number == "*":
                raise LambdaResourceError(
                    "'*' widths and precisions are not allowed in % formatting"
                )
            if number:
                _check_spec(number)
    _spend_rendering(values)


def _guard_binop(op: str, left: Any, right: Any) -> Any:
    """Apply a binary operator after checking the size of its result."""
    left_int = isinstance(left, int)
    right_int = isinstance(right, int)
    match op:
        case "pow":
            if left_int and right_int and right > 0 and abs(left) > 1:
                _check_int_bits(right * abs(left).bit_length())
            result = left**right
        case "mult":
            if left_int and right_int:
                _check_int_bits(abs(left).bit_length() + abs(right).bit_length())
            elif right_int:
                _check_repeat(left, right)
            elif left_int:
                _check_repeat(right, left)
            result = left * right
        case "lshift":
            if left_int and right_int and right > 0 and left != 0:
                _check_int_bits(abs(left).bit_length() + right)
            result = left << right
        case "mod":
            if isinstance(left, _TEXT):
                _check_printf(left, right)
            result = left % right
        case "add":
            result = left + right
        case _:
            raise LambdaResourceError(f"Unknown guarded operator {op!r}")
    _spend(allocation=shallow_size(result))
    return result


# Call guards


class _GuardedFormatter(string.Formatter):
    """``str.format`` that measures each field before rendering it."""

    def convert_field(self, value: Any, conversion: str | None) -> Any:
        _spend_rendering(value)
        return super().convert_field(value, conversion)

    def format_field(self, value: Any, format_spec: str) -> Any:
        _check_spec(format_spec)
        return super().format_field(value, format_spec)


def _occurrences(target: object, sub: object) -> int | None:
    """Count ``sub`` in ``target`` as ``str.replace`` would, or ``None``."""
    if isinstance(target, str) and isinstance(sub, str):
        return target.count(sub) if sub else len(target) + 1
    if isinstance(target, bytes) and isinstance(sub, bytes):
        return target.count(sub) if sub else len(target) + 1
    return None


def _check_growing_method(
    target: object, name: str, rest: tuple[Any, ...], kwargs: dict[str, Any]
) -> None:
    """Check the result size of a growing ``str``/``bytes``/``list`` method."""
    if name == "extend" and isinstance(target, list) and rest:
        _spend(allocation=shallow_size(rest[0]))
        return
    if not isinstance(target, _TEXT):
        return
    match name, rest:
        case ("ljust" | "rjust" | "center" | "zfill", (int() as width, *_)):
            _check_length(width)
            _spend(allocation=width)
        case ("expandtabs", _):
            tabsize = rest[0] if rest else kwargs.get("tabsize", 8)
            if not isinstance(tabsize, int):
                return
            tabs = _occurrences(target, b"\t" if isinstance(target, bytes) else "\t")
            size = len(target) + (tabs or 0) * max(tabsize, 0)
            _check_length(size)
            _spend(allocation=size)
        case ("replace", (old, new, *more)) if isinstance(new, _TEXT):
            if (occurrences := _occurrences(target, old)) is None:
                return
            if more and isinstance(more[0], int) and more[0] >= 0:
                occurrences = min(occurrences, more[0])
            size = len(target) + occurrences * max(len(new) - len(old), 0)
            _spend(allocation=size)
        case ("translate", (Mapping() as table, *_)):
            widest = max(
                (len(v) for v in table.values() if isinstance(v, _TEXT)), default=1
            )
            _spend(allocation=len(target) * max(widest, 1))


def _guard_method(receiver: Any, name: str, /, *args: Any, **kwargs: Any) -> Any:
    """Call a growing method after checking the size of its result.

    ``receiver.name(*args)`` is rewritten to this call. ``str.join(sep, parts)``
    style calls on the type pass the instance as the first argument.
    """
    if name not in GROWING_METHODS:
        raise LambdaResourceError(f"Method {name!r} is not a guarded method")
    # getattr is required: the method name is only known at runtime, and it is
    # restricted to GROWING_METHODS above.
    method = getattr(receiver, name)
    unbound = isinstance(receiver, type)
    target = args[0] if unbound and args else receiver
    rest = args[1:] if unbound else args

    if name == "join" and isinstance(target, _TEXT) and len(rest) == 1:
        parts = list(_guard_iter(rest[0]))
        separators = len(target) * max(len(parts) - 1, 0)
        _spend(allocation=separators + sum(shallow_size(part) for part in parts))
        return method(*args[:1], parts) if unbound else method(parts)
    if name in {"format", "format_map"} and isinstance(target, str):
        formatter = _GuardedFormatter()
        if name == "format":
            return formatter.vformat(target, rest, kwargs)
        if len(rest) == 1 and not kwargs:
            return formatter.vformat(target, (), rest[0])
    _check_growing_method(target, name, rest, kwargs)
    return method(*args, **kwargs)


def _guard_str(*args: Any, **kwargs: Any) -> str:
    """``str()`` that measures what it renders first."""
    if args:
        _spend_rendering(args[0])
    return str(*args, **kwargs)


def _guard_fmt(value: Any) -> Any:
    """Measure an f-string replacement field before it is rendered."""
    _spend_rendering(value)
    return value


def _guard_width(value: Any) -> Any:
    """Check a computed f-string format spec such as ``{x:>{width}}``."""
    if isinstance(value, int | str):
        _check_spec(str(value))
    return value


def _counted(iterator: Iterator[Any], budget: _Budget) -> Iterator[Any]:
    # The hot loop of every comprehension: decrement inline and only call
    # check() (which reads the clock) every few iterations or when exhausted.
    for item in iterator:
        budget.steps_left -= 1
        if budget.steps_left < 0 or budget.steps_left % _CLOCK_CHECK_INTERVAL == 0:
            budget.check()
        yield item


def _guard_iter(iterable: Iterable[Any]) -> Iterable[Any]:
    """Spend one step for every item a comprehension iterates.

    Sized iterables are charged their length up front and iterated at full
    speed. A list is snapshotted first, because a comprehension that appends
    to the list it iterates would otherwise never end. Dicts and sets raise if
    they change size during iteration, and the other sized builtins are
    immutable. Unsized iterables (generators, ``zip``, ``enumerate``...) are
    charged per item.
    """
    budget = _active_budget()
    if not isinstance(iterable, Sized):
        return _counted(iter(iterable), budget)
    budget.steps_left -= len(iterable)
    budget.check()
    return tuple(iterable) if isinstance(iterable, list) else iterable


def _guard_alloc(value: Any) -> Any:
    """Spend the size of a value a call or comprehension built."""
    _spend(allocation=shallow_size(value))
    return value


def _guard_call(value: Any) -> Any:
    """Spend one step and the result size for each nested lambda call."""
    _spend(steps=1, allocation=shallow_size(value))
    return value


def guarded_range(*args: int) -> range:
    """``range`` capped at :data:`MAX_SEQUENCE_LENGTH` items."""
    result = range(*args)
    try:
        length = len(result)
    except OverflowError:
        length = MAX_SEQUENCE_LENGTH + 1
    _check_length(length)
    return result


def guarded_sum(iterable: Iterable[Any], /, start: Any = 0) -> Any:
    """``sum`` that spends the allocation budget when concatenating sequences.

    ``sum(lists, [])`` copies the running total on every item, which is
    quadratic; each addition is charged its result size.
    """
    if isinstance(start, int | float | complex):
        return sum(iterable, start)
    total = start
    for item in _guard_iter(iterable):
        total = _guard_binop("add", total, item)
    return total


GUARD_GLOBALS: dict[str, Callable[..., Any]] = {
    "_guard_alloc": _guard_alloc,
    "_guard_binop": _guard_binop,
    "_guard_call": _guard_call,
    "_guard_fmt": _guard_fmt,
    "_guard_iter": _guard_iter,
    "_guard_method": _guard_method,
    "_guard_str": _guard_str,
    "_guard_width": _guard_width,
}
"""Helpers the rewritten lambda calls. A plain dict because it is merged
into the ``eval`` globals mapping, which must be a ``dict``."""


# AST rewriting

_GUARDED_OPERATORS: dict[type[ast.operator], str] = {
    ast.Pow: "pow",
    ast.Mult: "mult",
    ast.LShift: "lshift",
    ast.Mod: "mod",
    ast.Add: "add",
}


def _call(
    helper: str, *args: ast.expr, keywords: list[ast.keyword] | None = None
) -> ast.Call:
    return ast.Call(
        func=ast.Name(id=helper, ctx=ast.Load()),
        args=list(args),
        keywords=keywords or [],
    )


class _GuardTransformer(ast.NodeTransformer):
    """Route unbounded operations in a lambda AST through the guards."""

    def visit_BinOp(self, node: ast.BinOp) -> ast.expr:
        self.generic_visit(node)
        if (op := _GUARDED_OPERATORS.get(type(node.op))) is None:
            return node
        return _call("_guard_binop", ast.Constant(op), node.left, node.right)

    def visit_Call(self, node: ast.Call) -> ast.expr:
        self.generic_visit(node)
        call: ast.expr = node
        match node.func:
            case ast.Name(id="str"):
                call = _call("_guard_str", *node.args, keywords=node.keywords)
            case ast.Attribute(value=receiver, attr=name) if name in GROWING_METHODS:
                call = _call(
                    "_guard_method",
                    receiver,
                    ast.Constant(name),
                    *node.args,
                    keywords=node.keywords,
                )
        return _call("_guard_alloc", call)

    def visit_comprehension(self, node: ast.comprehension) -> ast.comprehension:
        self.generic_visit(node)
        node.iter = _call("_guard_iter", node.iter)
        return node

    def _visit_comprehension(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ) -> ast.expr:
        # Each iteration is charged by _guard_iter, and values built inside
        # are charged where they are built. The finished collection is
        # charged its length; a generator is charged by whatever consumes it.
        self.generic_visit(node)
        if isinstance(node, ast.GeneratorExp):
            return node
        return _call("_guard_alloc", node)

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension

    def visit_Subscript(self, node: ast.Subscript) -> ast.expr:
        # A slice copies; an index does not allocate.
        self.generic_visit(node)
        if isinstance(node.slice, ast.Slice) and isinstance(node.ctx, ast.Load):
            return _call("_guard_alloc", node)
        return node

    def visit_Lambda(self, node: ast.Lambda) -> ast.expr:
        self.generic_visit(node)
        node.body = _call("_guard_call", node.body)
        return node

    def visit_FormattedValue(self, node: ast.FormattedValue) -> ast.FormattedValue:
        node.value = _call("_guard_fmt", self.visit(node.value))
        if isinstance(node.format_spec, ast.JoinedStr):
            for part in node.format_spec.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    _check_spec(part.value)
                elif isinstance(part, ast.FormattedValue):
                    self.visit_FormattedValue(part)
                    part.value = _call("_guard_width", part.value)
        return node


def _reject_guard_names(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        match node:
            case ast.Name(id=name) | ast.arg(arg=name) if name.startswith(GUARD_PREFIX):
                raise ValueError(f"Names starting with {GUARD_PREFIX!r} are reserved")


def instrument_lambda(tree: ast.Lambda) -> ast.Lambda:
    """Rewrite a validated lambda AST so its evaluation is resource-bounded.

    Args:
        tree: A lambda that already passed ``SafeLambdaValidator``.

    Returns:
        The rewritten lambda, which must be evaluated with
        :data:`GUARD_GLOBALS` and inside :func:`evaluation_budget`.

    Raises:
        ValueError: If the lambda uses a reserved name or a static format spec
            that is too wide.
    """
    _reject_guard_names(tree)
    rewritten = _GuardTransformer().visit(tree)
    if not isinstance(rewritten, ast.Lambda):
        raise ValueError("Expression must be a lambda function")
    return ast.fix_missing_locations(rewritten)


@contextmanager
def evaluation_budget() -> Iterator[None]:
    """Give one lambda evaluation fresh step, allocation and time budgets."""
    max_steps = config.AUTOSECOPS__LAMBDA_MAX_STEPS
    max_allocation = config.AUTOSECOPS__LAMBDA_MAX_ALLOCATION_BYTES
    timeout = config.AUTOSECOPS__LAMBDA_TIMEOUT_SECONDS
    token = _budget.set(
        _Budget(
            steps_left=max_steps,
            allocation_left=max_allocation,
            deadline=time.monotonic() + timeout,
            max_steps=max_steps,
            max_allocation=max_allocation,
            timeout=timeout,
        )
    )
    try:
        yield
    finally:
        _budget.reset(token)


def check_result_size(result: object, argument: object) -> None:
    """Reject a result whose serialized form would dwarf the input.

    A result may be as large as the argument it was given plus the
    allocation budget, so ``lambda x: x`` always passes. The argument is only
    measured when the result is larger than the allocation budget.

    Args:
        result: The value the lambda returned.
        argument: The value the lambda was called with.

    Raises:
        LambdaResourceError: If the result is too large.
    """
    max_allocation = config.AUTOSECOPS__LAMBDA_MAX_ALLOCATION_BYTES
    if result is argument or expanded_size(result, max_allocation) <= max_allocation:
        return
    limit = max_allocation + expanded_size(argument, 10 * max_allocation)
    if expanded_size(result, limit) > limit:
        raise LambdaResourceError(
            "Lambda result is too large: it would serialize to more than"
            f" {limit:,} bytes"
        )
