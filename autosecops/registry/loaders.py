from __future__ import annotations

import importlib
import sys
from collections.abc import Callable, Mapping
from typing import Any, Literal, NoReturn

from autosecops_registry import RegistrySecretTypeValidator
from pydantic import BaseModel, ConfigDict, TypeAdapter, create_model

from autosecops import config
from autosecops.db.models import RegistryAction
from autosecops.expressions.expectations import create_expectation_model
from autosecops.expressions.validation import TemplateValidator
from autosecops.logger import logger
from autosecops.registry.actions.bound import BoundRegistryAction
from autosecops.registry.actions.schemas import (
    RegistryActionImplValidator,
    RegistryActionUDFImpl,
)
from autosecops.registry.constants import DEFAULT_REGISTRY_ORIGIN
from autosecops.registry.repository import (
    RegisterKwargs,
    attach_validators,
    generate_model_from_function,
    get_signature_docs,
    import_and_reload,
)
from autosecops.registry.versions.schemas import RegistryVersionManifestAction

F = Callable[..., Any]

LoaderMode = Literal["validation", "execution"]


def get_bound_action_impl(
    action: RegistryAction, *, mode: LoaderMode = "validation"
) -> BoundRegistryAction:
    impl = RegistryActionImplValidator.validate_python(action.implementation)
    secrets = [
        RegistrySecretTypeValidator.validate_python(secret)
        for secret in action.secrets or []
    ]
    if impl.type == "udf":
        fn = load_udf_impl(impl)
        key = getattr(fn, "__autosecops_udf_key")
        kwargs = getattr(fn, "__autosecops_udf_kwargs")
        logger.trace("Binding UDF", key=key, name=action.name, kwargs=kwargs)
        # Add validators to the function
        validated_kwargs = RegisterKwargs.model_validate(kwargs)
        if mode == "validation":
            attach_validators(fn, TemplateValidator())
        args_docs = get_signature_docs(fn)
        # Generate the model from the function signature
        args_cls, rtype, rtype_adapter = generate_model_from_function(
            func=fn, udf_kwargs=validated_kwargs
        )
        return BoundRegistryAction(
            fn=fn,
            type=impl.type,
            name=action.name,
            namespace=action.namespace,
            description=action.description,
            secrets=secrets,
            args_cls=args_cls,
            args_docs=args_docs,
            rtype_cls=rtype,
            rtype_adapter=rtype_adapter,
            default_title=action.default_title,
            display_group=action.display_group,
            doc_url=action.doc_url,
            author=action.author,
            deprecated=action.deprecated,
            origin=action.origin,
        )
    else:
        logger.trace("Binding template action", name=action.name)
        defn = impl.template_action.definition
        return BoundRegistryAction(
            fn=_not_implemented,
            type=impl.type,
            name=action.name,
            namespace=action.namespace,
            description=action.description,
            secrets=secrets,
            args_cls=create_expectation_model(
                defn.expects, defn.action.replace(".", "__")
            )
            if defn.expects
            else BaseModel,
            args_docs={
                key: schema.description or "-" for key, schema in defn.expects.items()
            },
            rtype_cls=Any,
            rtype_adapter=TypeAdapter(Any),
            default_title=action.default_title,
            display_group=action.display_group,
            doc_url=action.doc_url,
            author=action.author,
            deprecated=action.deprecated,
            include_in_schema=True,
            template_action=impl.template_action,
            origin=action.origin,
        )


def imports_customer_code(action: RegistryAction) -> bool:
    """Return whether binding this action would import customer code.

    Template actions are data, and builtin UDFs come from the platform's own
    package. Every other UDF comes from a customer repository.
    """
    impl = RegistryActionImplValidator.validate_python(action.implementation)
    return impl.type == "udf" and action.origin != DEFAULT_REGISTRY_ORIGIN


def _args_model_from_interface(
    name: str, interface: Mapping[str, Any] | None
) -> type[BaseModel]:
    """Build an argument model from a stored ``interface.expects`` JSON schema.

    The model checks argument names only: which are required and, when the
    schema forbids extra properties, which are unknown. Value types are not
    checked, because templates pass expressions that resolve at run time.
    """
    expects = (interface or {}).get("expects") or {}
    properties: Mapping[str, Any] = expects.get("properties") or {}
    required = set(expects.get("required") or ())
    fields: dict[str, Any] = {
        field: ((Any, ...) if field in required else (Any, None))
        for field in properties
    }
    extra = "forbid" if expects.get("additionalProperties") is False else "allow"
    return create_model(
        f"{name.replace('.', '__')}__Args",
        __config__=ConfigDict(extra=extra),
        **fields,
    )


def get_bound_action_from_metadata(action: RegistryAction) -> BoundRegistryAction:
    """Bind a customer UDF from its stored metadata, without importing it.

    Platform processes hold credentials, so they never import customer
    repository code. The bound action cannot run; it validates argument names
    against the interface recorded when the repository was synced.

    Args:
        action: The registry action row.

    Returns:
        A bound action for validation only.
    """
    secrets = [
        RegistrySecretTypeValidator.validate_python(secret)
        for secret in action.secrets or []
    ]
    args_cls = _args_model_from_interface(
        f"{action.namespace}.{action.name}", action.interface
    )
    return BoundRegistryAction(
        fn=_not_implemented,
        type="udf",
        name=action.name,
        namespace=action.namespace,
        description=action.description,
        secrets=secrets,
        args_cls=args_cls,
        args_docs={},
        rtype_cls=Any,
        rtype_adapter=TypeAdapter(Any),
        default_title=action.default_title,
        display_group=action.display_group,
        doc_url=action.doc_url,
        author=action.author,
        deprecated=action.deprecated,
        origin=action.origin,
    )


def get_bound_action_from_manifest(
    manifest_action: RegistryVersionManifestAction,
    origin: str,
    *,
    mode: LoaderMode = "validation",
) -> BoundRegistryAction:
    """Build BoundRegistryAction from manifest data instead of RegistryAction.

    This function mirrors get_bound_action_impl but takes manifest data from
    RegistryVersionManifest.actions rather than querying the RegistryAction table.

    Args:
        manifest_action: The manifest action containing implementation details.
        origin: The origin URL of the repository.
        mode: Loading mode - "validation" adds template validators, "execution" does not.

    Returns:
        A BoundRegistryAction ready for execution.
    """
    impl = RegistryActionImplValidator.validate_python(manifest_action.implementation)
    secrets = manifest_action.secrets or []

    if impl.type == "udf":
        fn = load_udf_impl(impl)
        key = getattr(fn, "__autosecops_udf_key")
        kwargs = getattr(fn, "__autosecops_udf_kwargs")
        logger.trace(
            "Binding UDF from manifest",
            key=key,
            name=manifest_action.name,
            kwargs=kwargs,
        )
        # Add validators to the function
        validated_kwargs = RegisterKwargs.model_validate(kwargs)
        if mode == "validation":
            attach_validators(fn, TemplateValidator())
        args_docs = get_signature_docs(fn)
        # Generate the model from the function signature
        args_cls, rtype, rtype_adapter = generate_model_from_function(
            func=fn, udf_kwargs=validated_kwargs
        )
        return BoundRegistryAction(
            fn=fn,
            type=impl.type,
            name=manifest_action.name,
            namespace=manifest_action.namespace,
            description=manifest_action.description,
            secrets=secrets,
            args_cls=args_cls,
            args_docs=args_docs,
            rtype_cls=rtype,
            rtype_adapter=rtype_adapter,
            default_title=manifest_action.default_title,
            display_group=manifest_action.display_group,
            doc_url=manifest_action.doc_url,
            author=manifest_action.author,
            deprecated=manifest_action.deprecated,
            origin=origin,
        )
    else:
        logger.trace("Binding template action from manifest", name=manifest_action.name)
        defn = impl.template_action.definition
        return BoundRegistryAction(
            fn=_not_implemented,
            type=impl.type,
            name=manifest_action.name,
            namespace=manifest_action.namespace,
            description=manifest_action.description,
            secrets=secrets,
            args_cls=create_expectation_model(
                defn.expects, defn.action.replace(".", "__")
            )
            if defn.expects
            else BaseModel,
            args_docs={
                key: schema.description or "-" for key, schema in defn.expects.items()
            },
            rtype_cls=Any,
            rtype_adapter=TypeAdapter(Any),
            default_title=manifest_action.default_title,
            display_group=manifest_action.display_group,
            doc_url=manifest_action.doc_url,
            author=manifest_action.author,
            deprecated=manifest_action.deprecated,
            include_in_schema=True,
            template_action=impl.template_action,
            origin=origin,
        )


def load_udf_impl(impl: RegistryActionUDFImpl) -> F:
    """Load a UDF implementation."""
    module_path = impl.module
    function_name = impl.name

    if config.AUTOSECOPS__LOCAL_REPOSITORY_ENABLED:
        logger.warning(
            "Force reloading local registry. You should only use this for development and not in production. "
            "In production, you should use a remote git repository."
        )
        mod = import_and_reload(module_path)
    else:
        try:
            mod = importlib.import_module(module_path)
        except ModuleNotFoundError as e:
            # Defensive fallback: if a concurrent reload temporarily disrupted imports,
            # avoid a reload if the module is already present.
            if module_path.startswith("autosecops_registry"):
                logger.warning(
                    "Recovering from module import error; attempting safe reload",
                    module=module_path,
                    error=str(e),
                )
                mod = sys.modules.get(module_path) or import_and_reload(module_path)
            else:
                raise
    try:
        fn = getattr(mod, function_name)
    except AttributeError as e:
        # Rare race if module was mid-reload; try one safe reload before failing
        logger.warning(
            "Function not found after import; attempting safe reload",
            module=module_path,
            function=function_name,
            error=str(e),
        )
        mod = import_and_reload(module_path)
        fn = getattr(mod, function_name)
    return fn


def _not_implemented() -> NoReturn:
    raise NotImplementedError(
        "This is a template action, it must be run with concrete arguments"
    )
