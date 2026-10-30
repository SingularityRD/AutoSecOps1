"""OpenAPI document customizations for the AutoSecOps API."""

from collections.abc import Sequence
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from autosecops.registry.fields import EditorComponent

OPENAPI_COMPONENT_MODELS: tuple[type[BaseModel], ...] = (
    # Editor widget hints embedded in registry action JSON schemas under
    # `x-autosecops-component`. No route returns this model directly, but the
    # frontend imports the generated `EditorComponent` type to render them.
    EditorComponent,
)
"""Models published as OpenAPI components without a route that returns them."""


def _unreachable() -> None:
    """Placeholder handler for the schema-only scratch app; never served."""


def build_component_schemas(
    models: Sequence[type[BaseModel]],
) -> dict[str, Any]:
    """Build OpenAPI component schemas for models and their nested models.

    The schemas are produced by FastAPI itself, on a scratch application that
    is never served, so they are byte-for-byte what a real response model would
    generate.

    Args:
        models: Pydantic models to publish. Nested models are included as
            separate components referenced through `#/components/schemas`.

    Returns:
        A mapping of component name to JSON schema. Untyped because the values
        are arbitrary JSON Schema documents produced by FastAPI.
    """
    scratch = FastAPI()
    for index, model in enumerate(models):
        scratch.add_api_route(
            f"/component/{index}",
            _unreachable,
            methods=["GET"],
            response_model=model,
        )
    return scratch.openapi().get("components", {}).get("schemas", {})


def install_openapi_component_schemas(
    app: FastAPI,
    models: Sequence[type[BaseModel]] = OPENAPI_COMPONENT_MODELS,
) -> None:
    """Publish models as OpenAPI components without exposing a placeholder route.

    FastAPI only emits schemas reachable from a registered route. Types the
    frontend needs, but that no endpoint returns, are merged into the generated
    document here. Schemas FastAPI already produced win, so a route that later
    starts returning one of these models keeps its own definition.

    Args:
        app: The application whose OpenAPI document is extended.
        models: Pydantic models to publish as components.
    """
    generate_openapi = app.openapi

    def openapi_with_component_schemas() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        spec = generate_openapi()
        components = spec.setdefault("components", {})
        schemas = components.get("schemas", {})
        merged = build_component_schemas(models) | schemas
        # FastAPI emits components sorted by name; keep that stable ordering.
        components["schemas"] = dict(sorted(merged.items()))
        app.openapi_schema = spec
        return spec

    # FastAPI documents replacing `app.openapi` as the supported way to extend
    # the generated schema; the method assignment is intentional.
    app.openapi = openapi_with_component_schemas
