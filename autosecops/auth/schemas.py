import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from fastapi_users import schemas
from pydantic import UUID4, BaseModel, EmailStr, field_validator, model_validator


# === Users ===
class UserRole(StrEnum):
    BASIC = "basic"
    ADMIN = "admin"


class UserStatus(StrEnum):
    LIVE = "live"
    INVITED = "invited"
    DEACTIVATED = "deactivated"


class UserRead(schemas.BaseUser[uuid.UUID]):
    role: UserRole
    first_name: str | None = None
    last_name: str | None = None
    settings: dict[str, Any]

    @field_validator("settings", mode="before")
    @classmethod
    def _null_settings_as_empty(cls, value: Any) -> Any:
        # The column is nullable, and older updates could store an explicit
        # null. Reading such a user must not fail.
        return {} if value is None else value

    @classmethod
    def system(cls) -> Self:
        return cls(
            id=uuid.uuid4(),
            email="system@autosecops.example",
            role=UserRole.ADMIN,
            first_name="System",
            last_name="",
            settings={},
        )


class UserReadMinimal(BaseModel):
    id: uuid.UUID
    email: EmailStr
    role: UserRole
    first_name: str | None = None
    last_name: str | None = None


class UserSearchRead(BaseModel):
    """Identity fields returned by the org-scoped user email search."""

    id: uuid.UUID
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None


class UserCreate(schemas.BaseUserCreate):
    first_name: str | None = None
    last_name: str | None = None
    invitation_token: str | None = None

    def create_update_dict(self) -> dict[str, Any]:
        # Exclude invitation_token from the dict passed to the database
        # since it's not a column on the User model
        d = super().create_update_dict()
        d.pop("invitation_token", None)
        return d


class UserUpdate(schemas.BaseUserUpdate):
    role: UserRole | None = None
    first_name: str | None = None
    last_name: str | None = None
    settings: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _null_means_unchanged(self) -> Self:
        # Updates apply only the fields that were set. role is NOT NULL and a
        # null settings breaks UserRead, so an explicit null leaves them as is.
        for name in ("role", "settings"):
            if getattr(self, name) is None:
                self.model_fields_set.discard(name)
        return self


# === Sessions ===
class SessionRead(BaseModel):
    id: UUID4
    created_at: datetime
    user_id: UUID4
    user_email: EmailStr
    ip_address: str | None = None
    user_agent: str | None = None
    last_seen_at: datetime | None = None
