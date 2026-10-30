from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from autosecops.api.app import app
from autosecops.api.openapi import (
    build_component_schemas,
    install_openapi_component_schemas,
)


class _Leaf(BaseModel):
    kind: Literal["leaf"] = "leaf"
    value: int | None = None


class _Wrapper(BaseModel):
    leaf: _Leaf


def _get_leaf() -> _Leaf:
    return _Leaf()


def test_api_publishes_editor_component_without_a_route() -> None:
    spec = app.openapi()
    schemas = spec["components"]["schemas"]

    # The frontend imports the generated EditorComponent type and its members.
    for name in ("EditorComponent", "Text", "Select", "Float", "WorkflowAlias"):
        assert name in schemas, name
    # The former placeholder route answered 501 without authentication.
    assert not any(path.endswith("/editor/field-schema") for path in spec["paths"])
    assert list(schemas) == sorted(schemas)


def test_component_schemas_include_nested_models() -> None:
    schemas = build_component_schemas([_Wrapper])

    assert set(schemas) == {"_Wrapper", "_Leaf"}
    assert schemas["_Wrapper"]["properties"]["leaf"] == {
        "$ref": "#/components/schemas/_Leaf"
    }


def test_route_generated_schema_takes_precedence() -> None:
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
