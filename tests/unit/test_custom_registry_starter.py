"""The vendored custom registry fixture registers through the real loader."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from autosecops.registry.repository import Repository

STARTER_DIR = Path(__file__).resolve().parents[1] / "data" / "custom_registry_starter"


@pytest.fixture
def starter_on_path() -> Iterator[None]:
    sys.path.insert(0, str(STARTER_DIR))
    try:
        yield
    finally:
        sys.path.remove(str(STARTER_DIR))
        for name in [m for m in sys.modules if m.split(".")[0] == "custom_actions"]:
            del sys.modules[name]


def test_starter_actions_register(starter_on_path: None) -> None:
    package = importlib.import_module("custom_actions")
    repo = Repository(origin="custom_actions")
    repo._register_udfs_from_package(package, origin="custom_actions")

    assert repo.keys == ["custom_actions.greetings.say_hello"]
    action = repo.get("custom_actions.greetings.say_hello")
    assert action.fn(name="synthetic") == "Hello, synthetic!"
