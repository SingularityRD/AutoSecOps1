"""Tests for service account API key expiry and the organization lifetime limit."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from autosecops.auth.api_keys import is_api_key_expired
from autosecops.db.models import ServiceAccount
from autosecops.exceptions import AutoSecOpsValidationError
from autosecops.service_accounts import service as sa_service
from autosecops.service_accounts.service import (
    OrganizationServiceAccountService,
    get_service_account_api_key_counts,
    resolve_api_key_expiry,
)
from autosecops.settings.schemas import SecuritySettingsUpdate

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_key_without_expiry_never_expires() -> None:
    """Keys issued before expiry support keep authenticating."""
    assert not is_api_key_expired(None, now=NOW)


def test_key_expires_at_its_expiry_time() -> None:
    assert is_api_key_expired(NOW, now=NOW)
    assert is_api_key_expired(NOW - timedelta(seconds=1), now=NOW)
    assert not is_api_key_expired(NOW + timedelta(seconds=1), now=NOW)


def test_no_limit_and_no_request_issues_a_key_that_never_expires() -> None:
    assert resolve_api_key_expiry(None, now=NOW, max_ttl_days=None) is None


def test_limit_applies_when_no_expiry_is_requested() -> None:
    assert resolve_api_key_expiry(None, now=NOW, max_ttl_days=90) == NOW + timedelta(
        days=90
    )


def test_requested_expiry_within_limit_is_kept() -> None:
    requested = NOW + timedelta(days=30)
    assert resolve_api_key_expiry(requested, now=NOW, max_ttl_days=90) == requested
    assert resolve_api_key_expiry(requested, now=NOW, max_ttl_days=None) == requested


@pytest.mark.parametrize(
    "requested",
    [
        NOW,
        NOW - timedelta(days=1),
        NOW + timedelta(days=90, seconds=1),
        datetime(2026, 2, 1),  # no time zone
    ],
)
def test_requested_expiry_outside_policy_is_refused(requested: datetime) -> None:
    with pytest.raises(AutoSecOpsValidationError):
        resolve_api_key_expiry(requested, now=NOW, max_ttl_days=90)


def test_key_counts_separate_expired_from_active() -> None:
    def key(*, revoked: bool, expires_at: datetime | None) -> SimpleNamespace:
        return SimpleNamespace(
            revoked_at=NOW if revoked else None, expires_at=expires_at
        )

    service_account = cast(
        ServiceAccount,
        SimpleNamespace(
            api_keys=[
                key(revoked=False, expires_at=None),
                key(revoked=False, expires_at=NOW + timedelta(days=1)),
                key(revoked=False, expires_at=NOW - timedelta(days=1)),
                key(revoked=True, expires_at=NOW - timedelta(days=1)),
            ]
        ),
    )

    counts = get_service_account_api_key_counts(service_account, now=NOW)

    assert (counts.total, counts.active, counts.expired, counts.revoked) == (
        4,
        2,
        1,
        1,
    )


@pytest.mark.parametrize("days", [0, -1, 3651])
def test_max_ttl_setting_rejects_out_of_range_values(days: int) -> None:
    with pytest.raises(ValidationError):
        SecuritySettingsUpdate(service_account_api_key_max_ttl_days=days)


def test_max_ttl_setting_update_leaves_allowlist_untouched() -> None:
    """A PATCH that only sets the limit must not reset the IP allowlist."""
    params = SecuritySettingsUpdate(service_account_api_key_max_ttl_days=90)
    assert params.model_dump(exclude_unset=True) == {
        "service_account_api_key_max_ttl_days": 90
    }


def _service() -> OrganizationServiceAccountService:
    service = OrganizationServiceAccountService.__new__(
        OrganizationServiceAccountService
    )
    service.role = cast(Any, SimpleNamespace(organization_id=uuid.uuid4()))
    service.session = cast(Any, AsyncMock())
    return service


@pytest.mark.anyio
@pytest.mark.parametrize("stored", [None, 30])
async def test_max_ttl_days_reads_the_org_setting(
    monkeypatch: pytest.MonkeyPatch, stored: int | None
) -> None:
    monkeypatch.setattr(sa_service, "get_setting", AsyncMock(return_value=stored))

    assert await _service()._get_api_key_max_ttl_days() == stored


@pytest.mark.anyio
@pytest.mark.parametrize("stored", [0, 5000, "90", True])
async def test_corrupt_max_ttl_setting_refuses_to_issue(
    monkeypatch: pytest.MonkeyPatch, stored: object
) -> None:
    """A policy that cannot be read must not silently become no policy."""
    monkeypatch.setattr(sa_service, "get_setting", AsyncMock(return_value=stored))

    with pytest.raises(AutoSecOpsValidationError):
        await _service()._get_api_key_max_ttl_days()


@pytest.mark.anyio
async def test_refused_expiry_does_not_revoke_the_current_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rotation validates the new key's expiry before touching the old key."""
    monkeypatch.setattr(sa_service, "get_setting", AsyncMock(return_value=30))
    service = _service()
    get_service_account = AsyncMock()
    monkeypatch.setattr(service, "get_service_account", get_service_account)

    with pytest.raises(AutoSecOpsValidationError):
        await service._issue_api_key(
            uuid.uuid4(),
            name="Rotated",
            expires_at=datetime.now(UTC) + timedelta(days=31),
        )

    get_service_account.assert_not_awaited()
