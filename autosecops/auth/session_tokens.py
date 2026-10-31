"""Hashed storage for browser session tokens.

The session cookie carries a random token; ``access_token.token`` stores only
``hash_bearer_token(token)``. Rows the previous app version inserted during a
rolling upgrade still hold the raw value with ``token_hashed`` false, and match
by raw value only while that flag is false: a digest read from the database is
never accepted as a cookie.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from sqlalchemy import ColumnElement, and_, or_, select

from autosecops.auth.crypto import hash_bearer_token
from autosecops.db.models import AccessToken


def access_token_matches(token: str) -> ColumnElement[bool]:
    """Build a WHERE clause selecting the session row for a raw cookie value.

    Args:
        token: The raw session token from the cookie.

    Returns:
        A clause matching the hashed row, or a pre-hashing row stored raw.
    """
    token_column = AccessToken.__table__.c.token
    hashed_column = AccessToken.__table__.c.token_hashed
    return or_(
        and_(token_column == hash_bearer_token(token), hashed_column.is_(True)),
        and_(token_column == token, hashed_column.is_(False)),
    )


class HashedAccessTokenDatabase(SQLAlchemyAccessTokenDatabase[AccessToken]):
    """fastapi-users access token adapter that stores only token digests.

    ``create`` receives the raw token from the strategy and persists its digest;
    ``get_by_token`` accepts the raw cookie value. The returned row's ``token``
    is therefore the digest, so the strategy must hand the raw value it
    generated back to the client.
    """

    async def get_by_token(
        self, token: str, max_age: datetime | None = None
    ) -> AccessToken | None:
        statement = select(AccessToken).where(access_token_matches(token))
        if max_age is not None:
            statement = statement.where(AccessToken.__table__.c.created_at >= max_age)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def create(self, create_dict: dict[str, Any]) -> AccessToken:
        # dict[str, Any] is the fastapi-users AccessTokenDatabase contract.
        stored = {
            **create_dict,
            "token": hash_bearer_token(create_dict["token"]),
            "token_hashed": True,
        }
        return await super().create(stored)
