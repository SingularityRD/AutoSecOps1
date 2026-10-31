"""OpenAPI document customizations for the AutoSecOps API."""

from collections.abc import Iterator, Mapping, Sequence
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

_COMPONENT_REF_PREFIX = "#/components/schemas/"


class OpenAPIComponentConflictError(RuntimeError):
    """Published component schemas cannot be merged into the API document."""


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


def _iter_component_refs(node: object) -> Iterator[str]:
    """Yield the target name of every local component `$ref` in a JSON schema."""
    if isinstance(node, Mapping):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith(_COMPONENT_REF_PREFIX):
            yield ref.removeprefix(_COMPONENT_REF_PREFIX)
        for value in node.values():
            yield from _iter_component_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_component_refs(item)


def merge_component_schemas(
    route_schemas: Mapping[str, Any],
    component_schemas: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge published component schemas into the route-generated components.

    FastAPI resolves model-name collisions only within one application, and
    the published schemas come from a separate scratch application. A name
    that both documents define must therefore have an identical definition.
    Otherwise a `$ref` inside a published schema would silently point at an
    unrelated model, and the generated frontend types would change with no
    failing check.

    Args:
        route_schemas: Component schemas FastAPI generated for the real routes.
        component_schemas: Component schemas built by `build_component_schemas`.

    Returns:
        The merged components, sorted by name like FastAPI's own output.

    Raises:
        OpenAPIComponentConflictError: A published schema name is also defined
            by a route model with a different definition, or a published
            schema references a component missing from the merged document.
    """
    conflicts = sorted(
        name
        for name, schema in component_schemas.items()
        if name in route_schemas and route_schemas[name] != schema
    )
    if conflicts:
        raise OpenAPIComponentConflictError(
            "OpenAPI component names are defined differently by route models "
            f"and published component models: {', '.join(conflicts)}. Rename "
            "one of the models so each component name has a single definition."
        )
    merged = {**route_schemas, **component_schemas}
    dangling = sorted(
        {
            ref
            for schema in component_schemas.values()
            for ref in _iter_component_refs(schema)
            if ref not in merged
        }
    )
    if dangling:
        raise OpenAPIComponentConflictError(
            "Published OpenAPI component schemas reference missing components: "
            f"{', '.join(dangling)}"
        )
    # FastAPI emits components sorted by name; keep that stable ordering.
    return dict(sorted(merged.items()))


def install_openapi_component_schemas(
    app: FastAPI,
    models: Sequence[type[BaseModel]] = OPENAPI_COMPONENT_MODELS,
) -> None:
    """Publish models as OpenAPI components without exposing a placeholder route.

    FastAPI only emits schemas reachable from a registered route. Types the
    frontend needs, but that no endpoint returns, are merged into the generated
    document here. A route that later starts returning one of these models
    keeps working because its definition is identical, while an unrelated model
    that reuses a published component name fails schema generation (see
    `merge_component_schemas`).

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
        try:
            components["schemas"] = merge_component_schemas(
                components.get("schemas", {}), build_component_schemas(models)
            )
        except OpenAPIComponentConflictError:
            # FastAPI caches the unmerged document on the app; drop it so a
            # later call fails the same way instead of serving it silently.
            app.openapi_schema = None
            raise
        app.openapi_schema = spec
        return spec

    # FastAPI documents replacing `app.openapi` as the supported way to extend
    # the generated schema; the method assignment is intentional.
    app.openapi = openapi_with_component_schemas
