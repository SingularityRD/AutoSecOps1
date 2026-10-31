import uuid

import pytest
from fastapi import HTTPException, status

from autosecops.auth import ip_allowlist_enforcement
from autosecops.auth.credentials import _require_superuser
from autosecops.auth.ip_allowlist import (
    PLATFORM_ADMIN_IP_ALLOWLIST_DENIED_DETAIL,
    OrgIPAllowlist,
    compile_allowlist,
)
from autosecops.auth.types import PlatformRole
from autosecops.contexts import RequestAuditContext, ctx_request_audit
from autosecops.db.models import User


@pytest.fixture(autouse=True)
def platform_allowlist(monkeypatch: pytest.MonkeyPatch) -> dict[str, OrgIPAllowlist]:
    state = {"allowlist": OrgIPAllowlist(enabled=False, networks=())}
    calls: list[None] = []

    async def fake_loader() -> OrgIPAllowlist:
        calls.append(None)
        return state["allowlist"]

    monkeypatch.setattr(
        ip_allowlist_enforcement, "get_platform_admin_ip_allowlist", fake_loader
    )
    state["calls"] = calls  # type: ignore[assignment]
    return state


@pytest.mark.anyio
async def test_require_superuser_allows_superuser() -> None:
    user = User(id=uuid.uuid4(), is_superuser=True)
    role = await _require_superuser(user=user)

    # Verify PlatformRole is returned
    assert isinstance(role, PlatformRole)
    assert role.type == "user"
    assert role.user_id == user.id
    assert role.service_id == "autosecops-api"
    # PlatformRole is always a platform superuser
    assert role.is_platform_superuser is True
    # Note: PlatformRole doesn't have organization_id - it's platform-scoped


@pytest.mark.anyio
async def test_require_superuser_denies_non_superuser() -> None:
    user = User(id=uuid.uuid4(), is_superuser=False)
    with pytest.raises(HTTPException) as exc:
        await _require_superuser(user=user)

    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


def _set_client_ip(ip: str | None) -> None:
    ctx_request_audit.set(
        RequestAuditContext(client_ip=ip, user_agent=None, raw_user_agent=None)
    )


@pytest.mark.anyio
async def test_require_superuser_enforces_platform_admin_allowlist(
    platform_allowlist,
) -> None:
    platform_allowlist["allowlist"] = compile_allowlist(
        enabled=True, cidrs=["203.0.113.0/24"]
    )
    user = User(id=uuid.uuid4(), is_superuser=True)

    _set_client_ip("203.0.113.9")
    assert isinstance(await _require_superuser(user=user), PlatformRole)

    _set_client_ip("198.51.100.9")
    with pytest.raises(HTTPException) as exc:
        await _require_superuser(user=user)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc.value.detail == PLATFORM_ADMIN_IP_ALLOWLIST_DENIED_DETAIL


@pytest.mark.anyio
async def test_require_superuser_checks_superuser_before_allowlist(
    platform_allowlist,
) -> None:
    platform_allowlist["allowlist"] = compile_allowlist(
        enabled=True, cidrs=["203.0.113.0/24"]
    )
    _set_client_ip("198.51.100.9")
    user = User(id=uuid.uuid4(), is_superuser=False)
    with pytest.raises(HTTPException) as exc:
        await _require_superuser(user=user)
    assert exc.value.detail == "Forbidden"
    assert platform_allowlist["calls"] == []


def test_fastapi_users_superuser_routes_require_platform_admin_access() -> None:
    from fastapi.routing import APIRoute

    from autosecops.api.app import _users_router
    from autosecops.auth.credentials import require_superuser, require_superuser_step_up

    routes = {
        route.name: route
        for route in _users_router().routes
        if isinstance(route, APIRoute)
    }
    assert any(
        dep.dependency is require_superuser for dep in routes["users:user"].dependencies
    )
    # Changing or deleting another user also needs a recent security key.
    for name in ("users:patch_user", "users:delete_user"):
        assert any(
            dep.dependency is require_superuser_step_up
            for dep in routes[name].dependencies
        )
    for name in ("users:current_user", "users:patch_current_user"):
        assert all(
            dep.dependency is not require_superuser for dep in routes[name].dependencies
        )


def _admin_cli_request(headers: dict[str, str]):
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/admin/users",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
    )


@pytest.mark.anyio
async def test_require_superuser_accepts_admin_cli_service_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The admin CLI's service-key fallback authenticates /admin routes."""
    from autosecops import config
    from autosecops.auth.credentials import _admin_cli_service_role

    monkeypatch.setattr(config, "AUTOSECOPS__SERVICE_KEY", "test-service-key")
    # Headers sent by packages/autosecops-admin/autosecops_admin/client.py
    request = _admin_cli_request(
        {
            "x-autosecops-service-key": "test-service-key",
            "x-autosecops-role-service-id": "autosecops-admin-cli",
        }
    )
    service_role = await _admin_cli_service_role(request)
    role = await _require_superuser(user=None, service_role=service_role)

    assert isinstance(role, PlatformRole)
    assert role.type == "service"
    assert role.service_id == "autosecops-admin-cli"
    assert role.user_id == config.AUTOSECOPS__DEFAULT_USER_ID


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        {
            "x-autosecops-service-key": "wrong-key",
            "x-autosecops-role-service-id": "autosecops-admin-cli",
        },
    ],
)
async def test_admin_cli_service_role_rejects_wrong_key(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
) -> None:
    from autosecops import config
    from autosecops.auth.credentials import _admin_cli_service_role

    monkeypatch.setattr(config, "AUTOSECOPS__SERVICE_KEY", "test-service-key")
    with pytest.raises(HTTPException) as exc:
        await _admin_cli_service_role(_admin_cli_request(headers))
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        {},
        # Other internal services must not get platform admin access.
        {
            "x-autosecops-service-key": "test-service-key",
            "x-autosecops-role-service-id": "autosecops-api",
        },
        {"x-autosecops-service-key": "test-service-key"},
    ],
)
async def test_require_superuser_rejects_unauthenticated(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
) -> None:
    from autosecops import config
    from autosecops.auth.credentials import _admin_cli_service_role

    monkeypatch.setattr(config, "AUTOSECOPS__SERVICE_KEY", "test-service-key")
    service_role = await _admin_cli_service_role(_admin_cli_request(headers))
    assert service_role is None
    with pytest.raises(HTTPException) as exc:
        await _require_superuser(user=None, service_role=service_role)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.anyio
async def test_require_superuser_enforces_allowlist_for_admin_cli(
    platform_allowlist,
) -> None:
    platform_allowlist["allowlist"] = compile_allowlist(
        enabled=True, cidrs=["203.0.113.0/24"]
    )
    _set_client_ip("198.51.100.9")
    service_role = PlatformRole(
        type="service", user_id=uuid.UUID(int=0), service_id="autosecops-admin-cli"
    )
    with pytest.raises(HTTPException) as exc:
        await _require_superuser(user=None, service_role=service_role)
    assert exc.value.detail == PLATFORM_ADMIN_IP_ALLOWLIST_DENIED_DETAIL
