from lark import Lark, Token, Tree
from lark.exceptions import UnexpectedCharacters, UnexpectedEOF, UnexpectedInput

from autosecops.exceptions import AutoSecOpsExpressionError
from autosecops.expressions.parser.grammar import grammar
from autosecops.logger import logger

MAX_EXPRESSION_DEPTH = 200
"""Deepest parse tree an expression may produce.

Evaluators, validators and extractors walk the tree recursively. Deeper trees
(such as a long ``1 + 1 + ...`` chain or deeply nested lists) would raise
RecursionError there instead of an expression error.
"""


def _tree_depth(tree: Tree[Token]) -> int:
    deepest = 0
    stack: list[tuple[Tree[Token] | Token, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        deepest = max(deepest, depth)
        if isinstance(node, Tree):
            stack.extend((child, depth + 1) for child in node.children)
    return deepest


class ExprParser:
    def __init__(self, start_rule: str = "root") -> None:
        self.parser = Lark(grammar, start=start_rule, parser="lalr")

    def parse(self, expression: str) -> Tree[Token] | None:
        try:
            tree = self.parser.parse(expression)
        except (UnexpectedCharacters, UnexpectedEOF, UnexpectedInput) as e:
            logger.error(
                "Failed to parse expression",
                kind=e.__class__.__name__,
                detail=str(e),
            )
            if hasattr(e, "allowed"):
                # Zero out the allowed attribute to hide allowed characters
                e.allowed = None  # pyright: ignore[reportAttributeAccessIssue]
            raise AutoSecOpsExpressionError(
                f"Failed to parse expression: {e}", detail=str(e)
            ) from e
        except Exception as e:
            logger.error(e)
            raise AutoSecOpsExpressionError(
                f"Unexpected error when parsing expression: {e!r}"
            ) from e
        if _tree_depth(tree) > MAX_EXPRESSION_DEPTH:
            raise AutoSecOpsExpressionError(
                "Expression is nested too deeply"
                f" (maximum depth is {MAX_EXPRESSION_DEPTH})"
            )
        return tree


parser = ExprParser()
