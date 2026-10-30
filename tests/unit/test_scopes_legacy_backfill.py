"""Legacy Role scope backfill for roles replayed from Temporal histories.

Roles serialized before the RBAC migration carry ``scopes=None`` (or an empty
set) and, for users, the old ``org_role`` / ``workspace_role`` fields as extra
attributes. These tests replay that wire shape through ``Role`` itself, the
way the executor activity receives it.
"""

from __future__ import annotations

import uuid

import orjson
import pytest

from autosecops.auth.types import Role
from autosecops.authz.scopes import (
    PRESET_ROLE_SCOPES,
    SERVICE_PRINCIPAL_SCOPES,
    backfill_legacy_role_scopes,
)


def _legacy_role(**fields: object) -> Role:
    payload = {
        "type": "user",
        "workspace_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "service_id": "autosecops-api",
        **fields,
    }
    return Role.model_validate_json(orjson.dumps(payload))


def test_role_with_scopes_is_returned_unchanged() -> None:
    role = _legacy_role(scopes=["workflow:read"], org_role="owner")
    assert backfill_legacy_role_scopes(role) is role
    assert role.scopes == frozenset({"workflow:read"})


@pytest.mark.parametrize("scopes", [None, []], ids=["none", "empty"])
def test_legacy_service_role_gets_its_service_scopes(scopes: list[str] | None) -> None:
    role = _legacy_role(
        type="service", user_id=None, service_id="autosecops-runner", scopes=scopes
    )

    backfilled = backfill_legacy_role_scopes(role)

    assert backfilled.scopes == SERVICE_PRINCIPAL_SCOPES["autosecops-runner"]
    # Identity fields are preserved; only scopes change.
    assert backfilled.workspace_id == role.workspace_id
    assert backfilled.service_id == "autosecops-runner"


def test_legacy_user_role_unions_org_and_workspace_presets() -> None:
    role = _legacy_role(org_role="member", workspace_role="editor")

    backfilled = backfill_legacy_role_scopes(role)

    assert backfilled.scopes == (
        PRESET_ROLE_SCOPES["organization-member"]
        | PRESET_ROLE_SCOPES["workspace-editor"]
    )


def test_legacy_workspace_viewer_does_not_gain_editor_scopes() -> None:
    backfilled = backfill_legacy_role_scopes(_legacy_role(workspace_role="viewer"))

    editor_only = (
        PRESET_ROLE_SCOPES["workspace-editor"] - PRESET_ROLE_SCOPES["workspace-viewer"]
    )
    assert editor_only
    assert backfilled.scopes == PRESET_ROLE_SCOPES["workspace-viewer"]
    assert backfilled.scopes is not None
    assert backfilled.scopes.isdisjoint(editor_only)


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({}, id="no_legacy_fields"),
        pytest.param({"org_role": "superuser"}, id="unknown_org_role"),
        pytest.param({"workspace_role": "root"}, id="unknown_workspace_role"),
    ],
)
def test_user_role_without_recognized_legacy_fields_gets_no_scopes(
    fields: dict[str, object],
) -> None:
    """Unknown legacy values never grant anything: the role stays unresolved."""
    role = _legacy_role(**fields)
    backfilled = backfill_legacy_role_scopes(role)
    assert backfilled is role
    assert backfilled.scopes is None


def test_service_account_role_is_not_backfilled() -> None:
    """Only user and internal service roles have a legacy derivation."""
    role = Role(
        type="service_account",
        organization_id=uuid.uuid4(),
        service_account_id=uuid.uuid4(),
        service_id="autosecops-api",
    )
    assert backfill_legacy_role_scopes(role) is role
