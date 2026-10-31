from typing import Literal

import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from autosecops.api.app import app
from autosecops.api.openapi import (
    OPENAPI_COMPONENT_MODELS,
    OpenAPIComponentConflictError,
    build_component_schemas,
    install_openapi_component_schemas,
    merge_component_schemas,
)


class _Leaf(BaseModel):
    kind: Literal["leaf"] = "leaf"
    value: int | None = None


class _Wrapper(BaseModel):
    leaf: _Leaf


def _get_leaf() -> _Leaf:
    return _Leaf()


def _make_unrelated_leaf() -> type[BaseModel]:
    """Build an unrelated model that FastAPI also names `_Leaf`."""

    class _Leaf(BaseModel):
        unrelated: str

    return _Leaf


def test_api_publishes_editor_component_without_a_route() -> None:
    spec = app.openapi()
    schemas = spec["components"]["schemas"]

    # The frontend imports the generated EditorComponent type and its members.
    for name in ("EditorComponent", "Text", "Select", "Float", "WorkflowAlias"):
        assert name in schemas, name
    # The former placeholder route answered 501 without authentication.
    assert not any(path.endswith("/editor/field-schema") for path in spec["paths"])
    assert list(schemas) == sorted(schemas)


def test_api_published_components_keep_their_own_definitions() -> None:
    """Every published schema, and each schema it references, is its own."""
    schemas = app.openapi()["components"]["schemas"]

    for name, schema in build_component_schemas(OPENAPI_COMPONENT_MODELS).items():
        assert schemas[name] == schema, name


def test_component_schemas_include_nested_models() -> None:
    schemas = build_component_schemas([_Wrapper])

    assert set(schemas) == {"_Wrapper", "_Leaf"}
    assert schemas["_Wrapper"]["properties"]["leaf"] == {
        "$ref": "#/components/schemas/_Leaf"
    }


def test_identical_route_schema_is_accepted() -> None:
    scratch = FastAPI()
    scratch.add_api_route("/leaf", _get_leaf, methods=["GET"], response_model=_Leaf)

    route_schema = scratch.openapi()["components"]["schemas"]["_Leaf"]
    scratch.openapi_schema = None
    install_openapi_component_schemas(scratch, [_Wrapper])

    spec = scratch.openapi()
    assert spec["components"]["schemas"]["_Leaf"] == route_schema
    assert "_Wrapper" in spec["components"]["schemas"]
    # The document is cached like FastAPI's default implementation.
    assert scratch.openapi() is spec


def test_conflicting_route_schema_fails_generation() -> None:
    """A route model reusing a published name must not hijack its `$ref`."""
    scratch = FastAPI()
    scratch.add_api_route(
        "/leaf", _get_leaf, methods=["GET"], response_model=_make_unrelated_leaf()
    )
    install_openapi_component_schemas(scratch, [_Wrapper])

    with pytest.raises(OpenAPIComponentConflictError, match="_Leaf"):
        scratch.openapi()
    # The unmerged document is not cached and served on the next call.
    assert scratch.openapi_schema is None
    with pytest.raises(OpenAPIComponentConflictError):
        scratch.openapi()


def test_dangling_component_ref_fails_merge() -> None:
    published = {
        "_Wrapper": {"properties": {"leaf": {"$ref": "#/components/schemas/_Gone"}}}
    }

    with pytest.raises(OpenAPIComponentConflictError, match="_Gone"):
        merge_component_schemas({}, published)
