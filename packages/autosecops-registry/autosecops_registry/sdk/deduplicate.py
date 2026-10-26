"""Deduplicate SDK client for AutoSecOps API."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from autosecops_registry.sdk.client import AutoSecOpsClient


class DeduplicateClient:
    """Client for workspace-scoped deduplication API."""

    def __init__(self, client: AutoSecOpsClient) -> None:
        self._client = client

    async def create_digests(
        self,
        digests: list[str],
        expire_seconds: int,
    ) -> list[bool]:
        """Create deduplication digest entries.

        Args:
            digests: SHA256 hex digests to create.
            expire_seconds: TTL for each digest key.

        Returns:
            List of booleans aligned to input order. True means the digest
            was newly created; False means it already existed.
        """
        resp = await self._client.post(
            "/deduplicate/digests",
            json={"digests": digests, "expire_seconds": expire_seconds},
        )
        return resp["created"]
