"""SOC-wide key uniqueness for every key registration path (fleet contract §4).

A key id and a public key name one key of one robot (or one SOC key) across
the whole SOC, active and retired alike. Every path that registers a key,
robot keys (fleet enrollment and rotation, the key API) and SOC fleet and
approval keys, calls :func:`claim_keys` in its own transaction. It takes a
transaction-scoped advisory lock, checks the global ``robot_key_registry``
and records the keys there; the registry's unique indexes back the check,
and rows are never deleted, so a deleted key's id stays taken (tombstone).

The registry has no tenant RLS, so the check sees every workspace from any
session; it holds public material only.

The ``robodr.fleet`` contract vectors' fixed-seed keys (``tests/data/
robot_edr/fleet_vectors/keys``) are public test material: they are refused as
SOC keys (fleet and approval keys) and as trust roots, where a robot would
trust them. Robot keys are not checked against them: the other RoboDR
contracts' vectors reuse the same seeds for robot keys, and a robot key is
trusted only for its own robot.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.db.models import RobotKeyRegistry

_REGISTRATION_LOCK: Final = "robot_edr_fleet_key_registration"

type KeyKind = Literal["robot", "soc"]

# Key ids and public keys of the robodr.fleet contract vectors (§10): "never
# register them anywhere real". Includes the trust root and profile signer.
# Checked for SOC keys and trust roots (see the module notes).
CONTRACT_TEST_KEYS: Final[dict[str, str]] = {
    "ed25519:370ede82195fa32b": "3ef08959033028c8fc6fc6d491a12548e78df6aefb2d7c2c190c3f78cef3f50b",
    "ed25519:9e208c2e60b4f0a2": "9f49439e9db095bc4111ed25d35795d831bc55a047f4b1d7f6aee3777bb41220",
    "ed25519:acdd03f52b337b5e": "2012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7",
    "ed25519:a16e3ca100fe526c": "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
    "ed25519:3d2af05f349c1712": "a7f6dfaf8f38b89ba8ce649b594f91e4d01fdc57f9c9493df43b5e50a9987367",
    "ed25519:bd1a186a203ad9e3": "2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6",
    "ed25519:caf521a404f9a7bf": "2bc2800b3316e009209ffd757dab19ccf0ae84bc7ae90654e1e81712d270f653",
    "ed25519:5229cc84fa78c5b4": "d62f016a1efd1e4fdf793eb42cd84471e1ba9f0cf04d1287b5cc71f616287cb8",
    "ed25519:7bf642b114c6afa2": "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d",
    "ed25519:9df9d6d8f83b54ba": "fec1428673f6afe89264b3807344ae8b269d125a503855202687db5a7128579f",
    "ed25519:1b3ef3f0e5c90998": "5b6489c9c7fd0dcf50545e7c164886ef40491ec06c7f1b123041797e8117535e",
    "ed25519:e316bb4369867f14": "e2fe2a39b7326642827d6d82d497622cd6c297fe78270eaa436b01f086b6f3cb",
}

denied_key_ids: frozenset[str] = frozenset(CONTRACT_TEST_KEYS)
"""Key ids refused as SOC keys and trust roots."""
denied_public_keys: frozenset[bytes] = frozenset(
    bytes.fromhex(public) for public in CONTRACT_TEST_KEYS.values()
)


@dataclass(frozen=True, slots=True)
class ClaimedKey:
    """A key to register: its id and 32-byte public key."""

    key_id: str
    public_key: bytes


class KeyConflictError(Exception):
    """A key id or public key is already registered somewhere on the SOC."""


class VectorKeyError(Exception):
    """A contract test vector key was presented as a real key."""


def is_test_key(key_id: str, public_key: bytes) -> bool:
    """Whether ``key_id`` or ``public_key`` is a contract test vector key."""
    return key_id in denied_key_ids or public_key in denied_public_keys


async def lock_registrations(session: AsyncSession) -> None:
    """Serialize key registrations until the transaction ends."""
    await session.execute(
        select(func.pg_advisory_xact_lock(func.hashtext(_REGISTRATION_LOCK)))
    )


async def is_registered(session: AsyncSession, keys: Sequence[ClaimedKey]) -> bool:
    """Whether any key id or public key of ``keys`` is registered anywhere.

    Takes the registration lock first, so a concurrent registration of the
    same key waits for this transaction.
    """
    await lock_registrations(session)
    hit = await session.scalar(
        select(RobotKeyRegistry.surrogate_id)
        .where(
            or_(
                RobotKeyRegistry.key_id.in_([k.key_id for k in keys]),
                RobotKeyRegistry.public_key.in_([k.public_key for k in keys]),
            )
        )
        .limit(1)
    )
    return hit is not None


async def claim_keys(
    session: AsyncSession, keys: Sequence[ClaimedKey], kind: KeyKind
) -> None:
    """Record ``keys`` as registered (in the caller's transaction).

    Raises:
        VectorKeyError: A SOC key is a contract test vector key.
        KeyConflictError: A key id or public key is already registered, or
            two of ``keys`` collide.
    """
    if kind == "soc" and any(is_test_key(k.key_id, k.public_key) for k in keys):
        raise VectorKeyError("contract test vector keys are never registered")
    ids = {k.key_id for k in keys}
    publics = {k.public_key for k in keys}
    if len(ids) != len(keys) or len(publics) != len(keys):
        raise KeyConflictError("a key is listed twice")
    if await is_registered(session, keys):
        raise KeyConflictError("a key id or public key is already registered")
    await session.execute(
        insert(RobotKeyRegistry),
        [{"key_id": k.key_id, "public_key": k.public_key, "kind": kind} for k in keys],
    )
