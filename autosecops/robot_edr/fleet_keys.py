"""SOC fleet and approval keys (contract §2.7).

Each workspace holds at most one **active** key of each kind: the online
fleet key (tokens, answers, ring information) and the approval key (profile
approvals only, used after the two-person sign-off). Secret seeds are
Fernet-encrypted with the database encryption key, the same way workspace
secrets are stored, and decrypted only at the point of signing.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth.secrets import get_db_encryption_key
from autosecops.db.models import RobotFleetSocKey
from autosecops.robot_edr.fleet_wire import SigningKey
from autosecops.robot_edr.types import FleetSocKeyKind, FleetSocKeyStatus
from autosecops.secrets.encryption import decrypt_value, encrypt_value


def encrypt_secret(value: bytes) -> bytes:
    """Encrypt a secret value (seed or token nonce) for storage."""
    return encrypt_value(value, key=get_db_encryption_key())


def decrypt_secret(value: bytes) -> bytes:
    """Decrypt a value stored with :func:`encrypt_secret`."""
    return decrypt_value(value, key=get_db_encryption_key())


def signing_key(row: RobotFleetSocKey) -> SigningKey:
    """The signing key of a stored SOC key row."""
    return SigningKey.from_seed(decrypt_secret(row.encrypted_seed))


async def active_soc_key(
    session: AsyncSession, workspace_id: uuid.UUID, kind: FleetSocKeyKind
) -> RobotFleetSocKey | None:
    """The workspace's active SOC key of ``kind``, if any."""
    return await session.scalar(
        select(RobotFleetSocKey).where(
            RobotFleetSocKey.workspace_id == workspace_id,
            RobotFleetSocKey.kind == kind.value,
            RobotFleetSocKey.status == FleetSocKeyStatus.ACTIVE.value,
        )
    )


async def active_signing_key(
    session: AsyncSession, workspace_id: uuid.UUID, kind: FleetSocKeyKind
) -> SigningKey | None:
    """The workspace's active SOC signing key of ``kind``, decrypted."""
    row = await active_soc_key(session, workspace_id, kind)
    return signing_key(row) if row is not None else None
