"""Synthetic greeting actions."""

from typing import Annotated

from autosecops_registry import registry
from typing_extensions import Doc


@registry.register(
    default_title="Say hello",
    description="Return a greeting for the given name.",
    display_group="Greetings",
    namespace="custom_actions.greetings",
)
def say_hello(
    name: Annotated[str, Doc("Name to greet.")],
) -> str:
    return f"Hello, {name}!"
