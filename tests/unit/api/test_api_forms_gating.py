"""Forms routes over HTTP: the flag and entitlement gate, and the error responses."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from fastapi.testclient import TestClient

from autosecops import config
from autosecops.api.app import app as api_app
from autosecops.auth.types import Role
from autosecops.exceptions import EntitlementRequired
from autosecops.executor.action_gateway.app import create_app as create_gateway_app
from autosecops.feature_flags import FeatureFlag
from autosecops.forms.dependencies import check_forms_enabled
from autosecops.forms.enums import FormErrorCode, FormFieldErrorCode
from autosecops.forms.exceptions import FormError, form_error_handler
from autosecops.forms.schemas import FormFieldError
from autosecops.licensing import keys as license_keys
from autosecops.licensing import service as license_service
from autosecops.licensing.token import encode_license
from autosecops.licensing.types import LicenseClaims
from autosecops.tiers import defaults as tier_defaults
from tests._route_utils import EffectiveRoute, iter_effective_api_routes

GATEWAY_APP = create_gateway_app()


def _routes(app: FastAPI, *prefixes: str) -> list[EffectiveRoute]:
    return [
        route
        for route in iter_effective_api_routes(app)
        if any(route.path == p or route.path.startswith(f"{p}/") for p in prefixes)
    ]


ROUTES = [
    *(
        pytest.param("client", route, id=f"{sorted(route.methods)} {route.path}")
        for route in _routes(
            api_app, "/workspaces/{workspace_id}/forms", "/forms", "/intake"
        )
    ),
    *(
        pytest.param(
            "action_gateway_client", route, id=f"{sorted(route.methods)} {route.path}"
        )
        for route in _routes(GATEWAY_APP, "/internal/forms")
    ),
]


def test_the_gateway_serves_the_paths_core_forms_calls() -> None:
    routes = {
        (method, route.path)
        for route in _routes(GATEWAY_APP, "/internal/forms")
        for method in route.methods
    }

    assert routes == {
        ("GET", "/internal/forms"),
        ("GET", "/internal/forms/{form_id}"),
        ("PUT", "/internal/forms/workflows/{workflow_id}"),
        ("GET", "/internal/forms/{form_id}/submissions"),
        ("GET", "/internal/forms/submissions/{submission_id}"),
        ("DELETE", "/internal/forms/submissions/{submission_id}"),
        ("GET", "/internal/forms/files/{file_id}/download"),
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("flags", "entitled", "status_code"),
    [(set(), True, 404), ({FeatureFlag.FORMS}, False, 403)],
    ids=["flag_off", "entitlement_off"],
)
@pytest.mark.parametrize(("client_name", "route"), ROUTES)
async def test_every_forms_route_needs_the_flag_and_the_entitlement(
    request: pytest.FixtureRequest,
    test_admin_role: Role,
    monkeypatch: pytest.MonkeyPatch,
    client_name: str,
    route: EffectiveRoute,
    flags: set[str],
    entitled: bool,
    status_code: int,
) -> None:
    client: TestClient = request.getfixturevalue(client_name)
    monkeypatch.setattr(config, "AUTOSECOPS__FEATURE_FLAGS", flags)
    path = route.path.replace("{workspace_id}", str(test_admin_role.workspace_id))
    path = re.sub(r"\{[a-z_]+\}", str(uuid.uuid4()), path)
    [method] = route.methods
    is_org_entitled = AsyncMock(return_value=entitled)

    with patch("autosecops.tiers.access.is_org_entitled", new=is_org_entitled):
        response = client.request(
            method,
            path,
            params={"workspace_id": str(test_admin_role.workspace_id)},
            json={},
        )

    assert response.status_code == status_code
    if status_code == 404:
        assert response.json() == {"detail": "Feature not enabled"}
        is_org_entitled.assert_not_awaited()
    else:
        assert response.json()["type"] == "EntitlementRequired"


@pytest.mark.anyio
async def test_single_tenant_forms_need_the_flag_and_a_licensed_entitlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On a single-tenant deployment the ``forms`` flag alone is not enough.

    The flag still gates the feature, but the ``forms`` entitlement now comes
    only from a signed license key, never from the flag.
    """
    role = Role(type="user", organization_id=uuid.uuid4(), service_id="autosecops-api")
    monkeypatch.setattr(config, "AUTOSECOPS__FEATURE_FLAGS", {FeatureFlag.FORMS})
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(),
    )
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        license_keys,
        "LICENSE_PUBLIC_KEY_PEM",
        private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ),
    )
    license_service._decode_cached.cache_clear()
    license_service._embedded_public_key.cache_clear()
    now = datetime.now(UTC)
    licensed = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=30),
        entitlements=["forms"],
    )

    try:
        monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", None)
        with pytest.raises(EntitlementRequired):
            await check_forms_enabled(AsyncMock(), role)

        token = encode_license(licensed, private_key)
        monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", token)
        await check_forms_enabled(AsyncMock(), role)
    finally:
        license_service._decode_cached.cache_clear()
        license_service._embedded_public_key.cache_clear()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("code", "status_code"),
    [
        (FormErrorCode.NOT_FOUND, 404),
        (FormErrorCode.ALREADY_EXISTS, 409),
        (FormErrorCode.FORM_CONFIG_INVALID, 422),
        (FormErrorCode.FORM_WORKFLOW_UNPUBLISHED, 409),
        (FormErrorCode.FORM_OFFLINE, 409),
        (FormErrorCode.FORM_UNAVAILABLE, 409),
        (FormErrorCode.FORM_CHANGED, 409),
        (FormErrorCode.FORM_VALIDATION_ERROR, 422),
        (FormErrorCode.WORKFLOW_START_FAILED, 503),
        (FormErrorCode.FILE_FIELD_INVALID, 422),
        (FormErrorCode.FILE_INVALID, 400),
        (FormErrorCode.FILE_TYPE_NOT_ALLOWED, 415),
        (FormErrorCode.FILE_TOO_LARGE, 413),
        (FormErrorCode.FILE_LIMIT_REACHED, 409),
        (FormErrorCode.FILE_UPLOAD_FAILED, 503),
    ],
)
async def test_form_errors_answer_with_their_status_and_detail(
    code: FormErrorCode, status_code: int
) -> None:
    error = FormFieldError(
        field="model", code=FormFieldErrorCode.REQUIRED, message="Required"
    )

    response = await form_error_handler(
        Mock(), FormError(code, "Wrong", errors=[error])
    )

    assert response.status_code == status_code
    body: dict[str, Any] = orjson.loads(response.body)
    assert body == {
        "detail": {
            "code": code.value,
            "message": "Wrong",
            "errors": [{"field": "model", "code": "required", "message": "Required"}],
            "issues": None,
        }
    }
    for app in (api_app, GATEWAY_APP):
        assert app.exception_handlers[FormError] is form_error_handler
