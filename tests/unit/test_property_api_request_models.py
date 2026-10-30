"""Every API request body model rejects bad JSON with a validation error.

A ``mode="before"`` validator that calls string methods on whatever arrives
raises TypeError or AttributeError for a list or a number, and FastAPI turns
that into a 500 instead of a 422. This walks every request body model the app
serves (and the models nested inside them) and feeds each one random JSON.
"""

from __future__ import annotations

import os
import types
import typing
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.routing import APIRoute
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError

from autosecops.api.app import app
from autosecops.exceptions import AutoSecOpsValidationError

EXAMPLES = int(os.environ.get("AUTOSECOPS_FUZZ_EXAMPLES", "60")) // 6 or 1

json_leaf = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False)
    | st.text(max_size=12)
)
json_value = st.recursive(
    json_leaf,
    lambda children: (
        st.lists(children, max_size=3)
        | st.dictionaries(st.text(max_size=6), children, max_size=3)
    ),
    max_leaves=6,
)


def _routes(routes: list[Any]) -> Iterator[APIRoute]:
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif original := getattr(route, "original_router", None):
            yield from _routes(original.routes)
        elif nested := getattr(route, "routes", None):
            yield from _routes(nested)


def _models(annotation: Any, seen: set[type[BaseModel]]) -> None:
    stack = [annotation]
    while stack:
        current = stack.pop()
        if isinstance(current, type) and issubclass(current, BaseModel):
            if current in seen:
                continue
            seen.add(current)
            stack.extend(field.annotation for field in current.model_fields.values())
        elif isinstance(current, typing.TypeAliasType):
            stack.append(current.__value__)
        stack.extend(typing.get_args(current))
        if isinstance(current, types.GenericAlias):
            stack.append(typing.get_origin(current))


def _request_body_models() -> list[type[BaseModel]]:
    seen: set[type[BaseModel]] = set()
    for route in _routes(app.routes):
        for param in route.dependant.body_params:
            _models(param.field_info.annotation, seen)
    return sorted(seen, key=lambda model: f"{model.__module__}.{model.__qualname__}")


REQUEST_MODELS = _request_body_models()


def test_request_models_were_found() -> None:
    assert len(REQUEST_MODELS) > 100


@pytest.mark.parametrize(
    "model", REQUEST_MODELS, ids=lambda model: f"{model.__module__}.{model.__name__}"
)
def test_request_model_rejects_random_json_with_validation_error(
    model: type[BaseModel],
) -> None:
    fields = list(model.model_fields)

    @settings(
        max_examples=EXAMPLES,
        deadline=None,
        database=None,
        derandomize=True,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    )
    @given(
        st.fixed_dictionaries({}, optional=dict.fromkeys(fields, json_value))
        | json_value
    )
    def check(payload: Any) -> None:
        try:
            model.model_validate(payload)
        except ValidationError:
            pass
        except AutoSecOpsValidationError:
            # Answered as a 400 by the app's exception handler.
            pass

    check()
