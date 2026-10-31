"""Domain types for the database layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

type DbPoolName = Literal["main", "auth"]


@dataclass(frozen=True, slots=True)
class DbPoolUsage:
    """Point-in-time usage of one SQLAlchemy connection pool in this process."""

    pool: DbPoolName
    in_use: int
    """Connections checked out to sessions."""
    idle: int
    """Open connections waiting in the pool."""
    max_connections: int
    """``pool_size + max_overflow``: checkouts beyond this wait, then time out."""
