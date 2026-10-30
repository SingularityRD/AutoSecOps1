"""Safe lambda evaluation utilities for the registry.

This module provides a sandboxed lambda execution environment that avoids
importing heavy autosecops modules during SDK-style invocation.
"""

import ast
import functools
import re
import string
import sys
from collections.abc import Callable
from typing import Any

from autosecops_registry._internal.jsonpath import eval_jsonpath


# A format field may only name a positional or keyword argument. Dotted or
# indexed fields ("{0.attr}", "{0[key]}") make str.format call getattr and
# getitem at runtime, which a lambda could use to walk from an argument to
# module globals and process state.
_SIMPLE_FORMAT_FIELD = re.compile(r"\d*|[A-Za-z_][A-Za-z0-9_]*")
_MAX_FORMAT_SPEC_DEPTH = 2


def _check_format_template(template: str, depth: int = 0) -> None:
    if depth > _MAX_FORMAT_SPEC_DEPTH:
        raise ValueError("Format string nests replacement fields too deeply")
    for _literal, field_name, format_spec, _conversion in string.Formatter().parse(
        template
    ):
        if field_name is None:
            continue
        if not _SIMPLE_FORMAT_FIELD.fullmatch(field_name):
            raise ValueError(
                "Format fields may only name an argument; attribute and index "
                "lookups are not allowed"
            )
        if format_spec:
            _check_format_template(format_spec, depth + 1)


class SafeLambdaValidator(ast.NodeVisitor):
    """AST validator for lambda expressions using allow/deny lists."""

    DENYLISTED_NODES = {
        ast.Import,
        ast.ImportFrom,
        ast.Global,
        ast.Nonlocal,
        ast.Delete,
        ast.With,
        ast.AsyncWith,
        ast.AsyncFor,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.FunctionDef,
    }
    DENYLISTED_SYMBOLS = {
        # Core dangerous functions
        "eval",
        "exec",
        "compile",
        "__import__",
        "import",
        "from",
        # File operations
        "open",
        "file",
        "input",
        "raw_input",
        "io",
        "pathlib",
        "shutil",
        "tempfile",
        "fileinput",
        "glob",
        "fnmatch",
        # OS/System operations
        "os",
        "sys",
        "subprocess",
        "multiprocessing",
        "threading",
        "signal",
        "resource",
        "sysconfig",
        "platform",
        "ctypes",
        "pickle",
        "marshal",
        "code",
        "types",
        # Network operations
        "socket",
        "socketserver",
        "urllib",
        "http",
        "ftplib",
        "telnetlib",
        "smtplib",
        "poplib",
        "imaplib",
        "ssl",
        "asyncio",
        "requests",
        "httpx",
        "aiohttp",
        # Introspection/Attribute access
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
        "dir",
        "vars",
        "locals",
        "globals",
        "object",
        "type",
        "__build_class__",
        "__builtins__",
        "help",
        "inspect",
        "traceback",
        "gc",
        # Other potentially dangerous
        "breakpoint",
        "exit",
        "quit",
        "memoryview",
        "bytearray",
        # Generator and frame introspection. A generator expression exposes
        # its frame (gi_frame); f_back walks up to the sandbox wrapper, whose
        # f_globals hold sys and so os.environ.
        "gi_frame",
        "gi_code",
        "gi_yieldfrom",
        "cr_frame",
        "cr_code",
        "cr_await",
        "ag_frame",
        "ag_code",
        "ag_await",
        "f_back",
        "f_builtins",
        "f_code",
        "f_globals",
        "f_locals",
        "f_trace",
        "tb_frame",
        "tb_next",
    }
    ALLOWLISTED_NODE_TYPES = {
        # Basic nodes
        ast.Module,
        ast.Expression,
        ast.Load,
        ast.Store,
        # Lambda and function basics
        ast.Lambda,
        ast.arguments,
        ast.arg,
        # Literals and basic types
        ast.Constant,
        ast.List,
        ast.Tuple,
        ast.Dict,
        ast.Set,
        # F-string support
        ast.JoinedStr,
        ast.FormattedValue,
        # Variables and attributes
        ast.Name,
        ast.Attribute,
        ast.Subscript,
        # ast.Index was deprecated in 3.9 and removed in 3.12; subscripts now
        # hold the index expression directly, so ast.Subscript covers indexing.
        ast.Slice,
        # Operators
        ast.BinOp,
        ast.UnaryOp,
        ast.BoolOp,
        ast.Compare,
        # Operator types
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.LShift,
        ast.RShift,
        ast.BitOr,
        ast.BitXor,
        ast.BitAnd,
        ast.MatMult,
        # Unary operators
        ast.Not,
        ast.UAdd,
        ast.USub,
        ast.Invert,
        # Boolean operators
        ast.And,
        ast.Or,
        # Comparison operators
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
        # Control flow (limited)
        ast.IfExp,
        # Comprehensions (safe)
        ast.ListComp,
        ast.DictComp,
        ast.SetComp,
        ast.GeneratorExp,
        ast.comprehension,
        # Function calls (validated separately)
        ast.Call,
        ast.keyword,
    }
    ALLOWED_FUNCTIONS = {"jsonpath"}
    # str.format and str.format_map resolve fields with getattr/getitem, so
    # they are only allowed as direct calls on a literal, vetted template.
    FORMAT_METHODS = {"format", "format_map"}

    def __init__(self) -> None:
        super().__init__()
        self._vetted_format_calls: set[int] = set()

    def visit(self, node):
        if type(node) in self.DENYLISTED_NODES:
            raise ValueError(
                f"Restricted node {type(node).__name__} detected in expression"
            )

        if type(node) not in self.ALLOWLISTED_NODE_TYPES:
            raise ValueError(
                f"Node type {type(node).__name__} is not allowed in expressions. "
                f"Only safe, simple expressions are permitted."
            )

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in self.FORMAT_METHODS
        ):
            template = node.func.value
            if not (
                isinstance(template, ast.Constant) and isinstance(template.value, str)
            ):
                raise ValueError(
                    f"'{node.func.attr}' is only allowed on a string literal"
                )
            _check_format_template(template.value)
            self._vetted_format_calls.add(id(node.func))

        if (
            isinstance(node, ast.Attribute)
            and node.attr in self.FORMAT_METHODS
            and id(node) not in self._vetted_format_calls
        ):
            raise ValueError(f"'{node.attr}' is only allowed on a string literal")

        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                raise ValueError(
                    f"Access to dunder attribute '{node.attr}' is not allowed"
                )

        # Check for denylisted function calls and symbols
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                if (
                    func_name in self.DENYLISTED_SYMBOLS
                    and func_name not in self.ALLOWED_FUNCTIONS
                ):
                    raise ValueError(
                        f"Calling restricted function '{func_name}' is not allowed"
                    )

            elif isinstance(node.func, ast.Attribute):
                attr_name = node.func.attr
                if (
                    attr_name in self.DENYLISTED_SYMBOLS
                    and attr_name not in self.ALLOWED_FUNCTIONS
                ):
                    raise ValueError(
                        f"Calling restricted method '{attr_name}' is not allowed"
                    )

                if isinstance(node.func.value, ast.Name):
                    obj_name = node.func.value.id
                    if obj_name in self.DENYLISTED_SYMBOLS:
                        raise ValueError(
                            f"Accessing restricted module '{obj_name}' is not allowed"
                        )

        elif isinstance(node, ast.Name):
            if (
                node.id in self.DENYLISTED_SYMBOLS
                and node.id not in self.ALLOWED_FUNCTIONS
            ):
                raise ValueError(
                    f"Accessing restricted symbol '{node.id}' is not allowed"
                )

        elif isinstance(node, ast.Attribute):
            if (
                node.attr in self.DENYLISTED_SYMBOLS
                and node.attr not in self.ALLOWED_FUNCTIONS
            ):
                raise ValueError(
                    f"Accessing restricted attribute '{node.attr}' is not allowed"
                )

        self.generic_visit(node)


def _sandbox_lambda(func: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """Wrap a lambda function with runtime protections (internal).

    Note: The recursion limit manipulation is not fully thread-safe since
    sys.setrecursionlimit() is process-global. However, the practical impact
    is minimal - the worst case is the limit being temporarily incorrect,
    and the AST validation already prevents recursive function definitions.
    """

    @functools.wraps(func)
    def sandboxed_wrapper(x):
        original_recursion_limit = sys.getrecursionlimit()
        MAX_RECURSION_DEPTH = 500
        sys.setrecursionlimit(MAX_RECURSION_DEPTH)

        try:
            execution_count = 0
            MAX_ITERATIONS = 10000

            def count_guard(value):
                nonlocal execution_count
                execution_count += 1
                if execution_count > MAX_ITERATIONS:
                    raise ValueError("Expression exceeded maximum iteration limit")
                return value

            if hasattr(x, "__iter__") and not isinstance(x, str | bytes):
                if isinstance(x, dict):
                    x = {k: count_guard(v) for k, v in x.items()}
                elif isinstance(x, list):
                    x = [count_guard(item) for item in x]

            result = func(x)

            if hasattr(result, "__class__"):
                result_type = type(result)
                safe_return_types = (
                    type(None),
                    bool,
                    int,
                    float,
                    str,
                    bytes,
                    list,
                    tuple,
                    dict,
                    set,
                    frozenset,
                )
                if not isinstance(result, safe_return_types):
                    raise ValueError(
                        f"Lambda returned unsafe type: {result_type.__name__}"
                    )

            return result

        except RecursionError as e:
            raise ValueError("Expression exceeded maximum recursion depth") from e
        finally:
            sys.setrecursionlimit(original_recursion_limit)

    return sandboxed_wrapper


def build_safe_lambda(lambda_expr: str) -> Callable[[Any], Any]:
    """Build a safe lambda function from a string expression."""

    MAX_EXPR_LENGTH = 1000
    if len(lambda_expr) > MAX_EXPR_LENGTH:
        raise ValueError(f"Expression too long (max {MAX_EXPR_LENGTH} characters)")

    dangerous_patterns = [
        "__",
        "\\x",
        "\\u",
        "chr(",
        "ord(",
        ".decode",
        ".encode",
        "base64",
        "codecs",
    ]

    for pattern in dangerous_patterns:
        if pattern in lambda_expr:
            raise ValueError(f"Expression contains dangerous pattern: {pattern}")

    try:
        expr_ast = ast.parse(lambda_expr, mode="eval").body
    except SyntaxError as e:
        raise ValueError(f"Invalid syntax in expression: {e}") from e

    if not isinstance(expr_ast, ast.Lambda):
        raise ValueError("Expression must be a lambda function")

    SafeLambdaValidator().visit(expr_ast)

    code = compile(ast.Expression(expr_ast), "<string>", "eval")

    safe_builtins = {
        "abs": abs,
        "min": min,
        "max": max,
        "sum": sum,
        "round": round,
        "len": len,
        "int": int,
        "float": float,
        "str": str,
        "bool": bool,
        "list": list,
        "dict": dict,
        "tuple": tuple,
        "set": set,
        "all": all,
        "any": any,
        "sorted": sorted,
        "reversed": reversed,
        "enumerate": enumerate,
        "zip": zip,
        "range": range,
        "True": True,
        "False": False,
        "None": None,
    }

    restricted_globals = {
        "__builtins__": safe_builtins,
        "jsonpath": eval_jsonpath,
    }

    lambda_func = eval(code, restricted_globals, {})
    return _sandbox_lambda(lambda_func)
