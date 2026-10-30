"""Malformed request input must produce client errors, never 500s.

Each case here came from fuzzing the API with schemathesis: the request was
schema-shaped garbage (a non-UUID path ID, a non-string where a string is
expected, a 30-digit integer, a NUL byte, an explicit null on an update) and
the server answered 500 or stored data it could no longer read.
"""

import json
import uuid
from typing import Any, get_args
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, SecretStr, ValidationError
from sqlalchemy.exc import DBAPIError, IntegrityError
from starlette.requests import Request

from autosecops.agent.provider.schemas import AgentCustomProviderUpdate
from autosecops.api.app import validation_exception_handler
from autosecops.api.common import (
    BigIntSafeORJSONResponse,
    database_exception_handler,
    generic_exception_handler,
)
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.auth.schemas import UserRead, UserRole, UserUpdate
from autosecops.auth.types import Role
from autosecops.contexts import ctx_role
from autosecops.db.engine import get_async_session
from autosecops.integrations.schemas import (
    CustomOAuthProviderCreate,
    IntegrationUpdate,
    MCPHttpIntegrationCreate,
    MCPIntegrationUpdate,
)
from autosecops.registry.repositories.schemas import RegistryRepositoryCreate
from autosecops.secrets import router as secrets_router
from autosecops.secrets.dependencies import secret_id_path_dependency
from autosecops.secrets.schemas import SecretCreate, SecretKeyValue
from autosecops.settings.schemas import GitSettingsUpdate
from autosecops.variables.router import router as variables_router
from autosecops.workflow.actions.dependencies import action_id_path_dependency
from autosecops.workflow.actions.schemas import ActionControlFlow
from autosecops.workflow.executions.dependencies import unquote_dep
from autosecops.workspaces.schemas import WorkspaceSettingsUpdate

pytestmark = pytest.mark.anyio

NON_STRINGS: list[Any] = [{}, [], ["https://example.test"], 1, 1.5, True]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _request(path: str = "/") -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [],
            "query_string": b"",
        }
    )


@pytest.mark.parametrize(
    "dependency", [secret_id_path_dependency, action_id_path_dependency]
)
@pytest.mark.parametrize("raw_id", ["0", "", "not-a-uuid", "secret_!!", "act_!!"])
def test_malformed_path_ids_are_validation_errors(dependency: Any, raw_id: str) -> None:
    with pytest.raises(RequestValidationError):
        dependency(raw_id)


def test_path_ids_still_accept_uuid_and_short_forms() -> None:
    value = uuid.uuid4()
    assert secret_id_path_dependency(str(value)) == value
    assert action_id_path_dependency(str(value)) == value
    secret_short = secret_id_path_dependency(str(value)).short()
    assert secret_id_path_dependency(secret_short) == value


@pytest.mark.parametrize("value", [2**64, -(2**63) - 1, 10**30])
def test_validation_error_with_huge_integer_input_is_422(value: int) -> None:
    exc = RequestValidationError(
        [{"type": "string_type", "loc": ("body", "name"), "msg": "x", "input": value}]
    )
    response = validation_exception_handler(_request(), exc)
    assert response.status_code == 422
    body = json.loads(bytes(response.body))
    assert body["detail"][0]["input"] == str(value)


def test_validation_error_keeps_ordinary_integers() -> None:
    exc = RequestValidationError(
        [{"type": "x", "loc": ("body", "n"), "msg": "x", "input": [1, True]}]
    )
    body = json.loads(bytes(validation_exception_handler(_request(), exc).body))
    assert body["detail"][0]["input"] == [1, True]


class _PgError(Exception):
    def __init__(
        self,
        sqlstate: str,
        message: str = "statement parameters: synthetic-secret-parameter",
    ) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


@pytest.mark.parametrize(
    ("sqlstate", "expected"),
    [
        ("22021", 400),  # character not in repertoire (NUL byte)
        ("22P02", 400),  # invalid text representation
        ("23505", 409),  # unique violation
        ("23503", 409),  # foreign key violation
    ],
)
async def test_database_errors_map_to_client_errors(
    sqlstate: str, expected: int
) -> None:
    exc = DBAPIError("INSERT ...", {"p": "synthetic"}, _PgError(sqlstate))
    response = await database_exception_handler(_request(), exc)
    assert response.status_code == expected
    assert b"synthetic" not in bytes(response.body)


async def test_server_database_errors_reach_the_catch_all_without_echo() -> None:
    """A connection failure stays a server error and never echoes the database text.

    The database handler re-raises it so error reporting captures it; the
    catch-all then answers with a generic 500.
    """
    exc = DBAPIError("INSERT ...", {"p": "synthetic"}, _PgError("08006"))
    with pytest.raises(DBAPIError):
        await database_exception_handler(_request(), exc)
    response = await generic_exception_handler(_request(), exc)
    assert response.status_code == 500
    assert b"synthetic" not in bytes(response.body)


@pytest.mark.parametrize(
    ("model", "base", "field"),
    [
        (GitSettingsUpdate, {}, "git_repo_url"),
        (WorkspaceSettingsUpdate, {}, "git_repo_url"),
        (ActionControlFlow, {}, "wait_until"),
        (RegistryRepositoryCreate, {}, "origin"),
        (IntegrationUpdate, {}, "authorization_endpoint"),
        (MCPIntegrationUpdate, {}, "server_uri"),
        (MCPHttpIntegrationCreate, {"name": "n"}, "server_uri"),
        (
            CustomOAuthProviderCreate,
            {
                "name": "n",
                "client_id": "c",
                "authorization_endpoint": "https://idp.test/authorize",
                "token_endpoint": "https://idp.test/token",
            },
            "token_endpoint",
        ),
    ],
)
@pytest.mark.parametrize("value", NON_STRINGS)
def test_string_validators_reject_non_strings(
    model: type[BaseModel], base: dict[str, Any], field: str, value: Any
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate({**base, field: value})


def test_registry_origin_rejects_null() -> None:
    with pytest.raises(ValidationError):
        RegistryRepositoryCreate.model_validate({"origin": None})


def test_user_update_null_role_and_settings_leave_them_unchanged() -> None:
    update = UserUpdate.model_validate(
        {"role": None, "settings": None, "first_name": None}
    )
    assert update.create_update_dict() == {"first_name": None}
    assert UserUpdate.model_validate({"settings": {"a": 1}}).create_update_dict() == {
        "settings": {"a": 1}
    }


def test_user_read_tolerates_null_settings() -> None:
    user = UserRead.model_validate(
        {
            "id": uuid.uuid4(),
            "email": "user@example.com",
            "role": UserRole.BASIC,
            "settings": None,
        }
    )
    assert user.settings == {}


def test_custom_provider_update_null_required_columns_are_unchanged() -> None:
    update = AgentCustomProviderUpdate.model_validate(
        {"passthrough": None, "display_name": None, "base_url": None}
    )
    assert update.model_dump(exclude_unset=True) == {"base_url": None}


def _role(*scopes: str) -> Role:
    return Role(
        type="user",
        organization_id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        service_id="autosecops-api",
        scopes=frozenset(scopes),
    )


async def test_variable_search_rejects_invalid_names_with_422() -> None:
    role = _role("variable:read")
    app = FastAPI()
    app.include_router(variables_router)
    app.dependency_overrides[get_args(WorkspaceActorRouteRole)[1].dependency] = lambda: (
        role
    )

    async def session():
        yield AsyncMock()

    app.dependency_overrides[get_async_session] = session
    service = MagicMock()
    service.search_variables = AsyncMock(return_value=[])
    with patch("autosecops.variables.router.VariablesService", return_value=service):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            bad = await client.get("/variables/search", params={"name": "AAA"})
            good = await client.get("/variables/search", params={"name": "api_cfg"})
    assert bad.status_code == 422
    assert good.status_code == 200
    service.search_variables.assert_awaited_once()


@pytest.mark.parametrize(
    "route", [secrets_router.create_secret, secrets_router.create_org_secret]
)
async def test_secret_conflict_does_not_echo_database_error(route: Any) -> None:
    role = _role("secret:create", "org:secret:create")
    leaked = "synthetic-encrypted-keys"
    service = MagicMock()
    error = IntegrityError(
        "INSERT INTO secret ...", {"keys": leaked}, _PgError("23514", leaked)
    )
    service.create_secret = AsyncMock(side_effect=error)
    service.create_org_secret = AsyncMock(side_effect=error)
    token = ctx_role.set(role)
    try:
        with patch.object(secrets_router, "SecretsService", return_value=service):
            # Only the named-unique violation is the route's own 409; any other
            # integrity error falls through to the shared database handler.
            with pytest.raises(IntegrityError) as caught:
                await route(
                    role=role,
                    session=AsyncMock(),
                    params=SecretCreate(
                        name="dup",
                        keys=[SecretKeyValue(key="k", value=SecretStr("v"))],
                    ),
                )
        response = await database_exception_handler(_request(), caught.value)
    finally:
        ctx_role.reset(token)
    assert response.status_code == 409
    body = bytes(response.body)
    assert leaked.encode() not in body
    assert b"IntegrityError" not in body


@pytest.mark.parametrize("environment", ["", "x" * 101])
def test_secret_create_rejects_unusable_environment(environment: str) -> None:
    """An empty environment made every workspace sync export preview 500."""
    with pytest.raises(ValidationError):
        SecretCreate(
            name="name",
            environment=environment,
            keys=[SecretKeyValue(key="k", value=SecretStr("v"))],
        )


@pytest.mark.parametrize("raw", ["", "%20", "   "])
def test_empty_execution_id_is_not_found(raw: str) -> None:
    with pytest.raises(HTTPException) as caught:
        unquote_dep(raw)
    assert caught.value.status_code == 404


def test_execution_id_is_unquoted() -> None:
    assert unquote_dep("wf_abc%2Fexec_def") == "wf_abc/exec_def"


def test_default_response_encodes_integers_beyond_64_bits() -> None:
    """A stored 30-digit integer used to make every read of it a 500."""
    big = 123456789012345678901234567890
    response = BigIntSafeORJSONResponse({"values": {"k": big, "n": 1}})
    assert json.loads(bytes(response.body)) == {"values": {"k": big, "n": 1}}


def test_app_uses_big_int_safe_default_response() -> None:
    from autosecops.api.app import app

    assert app.router.default_response_class is BigIntSafeORJSONResponse
