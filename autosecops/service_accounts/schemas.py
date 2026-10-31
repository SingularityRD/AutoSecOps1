from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import AwareDatetime, Field

from autosecops.auth.schemas import UserReadMinimal
from autosecops.core.schemas import Schema
from autosecops.identifiers import OrganizationID, UserID, WorkspaceID

_EXPIRES_AT_DESCRIPTION = (
    "When the key stops authenticating, with a time zone. Must be in the "
    "future and within the organization's maximum key lifetime. Omit it for "
    "the maximum lifetime, or for a key that never expires when the "
    "organization sets no maximum."
)


class ServiceAccountScopeRead(Schema):
    id: UUID
    name: str
    resource: str
    action: str
    description: str | None = None


class ServiceAccountApiKeyRead(Schema):
    id: UUID
    name: str
    key_id: str
    preview: str
    created_by: UserID | None = None
    created_by_user: UserReadMinimal | None = None
    revoked_by: UserID | None = None
    revoked_by_user: UserReadMinimal | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    expires_at: datetime | None = Field(
        default=None,
        description="When the key stops authenticating. Null: it never expires.",
    )
    created_at: datetime
    updated_at: datetime


class ServiceAccountApiKeyCounts(Schema):
    total: int = 0
    active: int = 0
    """Unrevoked keys that have not expired."""
    expired: int = 0
    """Unrevoked keys past their expiry."""
    revoked: int = 0


class ServiceAccountRead(Schema):
    id: UUID
    organization_id: OrganizationID
    workspace_id: WorkspaceID | None = None
    owner_user_id: UserID | None = None
    owner_user: UserReadMinimal | None = None
    name: str
    description: str | None = None
    disabled_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    scopes: list[ServiceAccountScopeRead] = Field(default_factory=list)
    active_api_key: ServiceAccountApiKeyRead | None = None
    api_key_counts: ServiceAccountApiKeyCounts = Field(
        default_factory=ServiceAccountApiKeyCounts
    )


class ServiceAccountCreate(Schema):
    name: str = Field(default=..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=512)
    scope_ids: list[UUID] = Field(default_factory=list)
    initial_key_name: str = Field(default="Primary", min_length=1, max_length=255)
    initial_key_expires_at: AwareDatetime | None = Field(
        default=None,
        description=_EXPIRES_AT_DESCRIPTION,
    )


class ServiceAccountUpdate(Schema):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=512)
    scope_ids: list[UUID] | None = None


class ServiceAccountApiKeyCreate(Schema):
    name: str = Field(default="Primary", min_length=1, max_length=255)
    expires_at: AwareDatetime | None = Field(
        default=None,
        description=_EXPIRES_AT_DESCRIPTION,
    )


class IssuedServiceAccountApiKey(Schema):
    raw_key: str
    api_key: ServiceAccountApiKeyRead


class ServiceAccountApiKeyIssueResponse(Schema):
    issued_api_key: IssuedServiceAccountApiKey
    service_account: ServiceAccountRead


class ServiceAccountScopeList(Schema):
    items: list[ServiceAccountScopeRead] = Field(default_factory=list)
