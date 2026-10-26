"""Profile and revocation-list files the fleet API carries (contract §4.1, §6).

The SOC never locks, signs or trusts a profile; it only checks structure so
that a draft queued for review is a real draft (``robodr-commission``
``parse_profile_text`` rules for an unlocked file), an offered profile is a
locked one naming its platform and version, and a revocation list is a
well-formed ``robodr-profile-revocations/v2`` file whose serial only rises.
Every robot verifies these files again with ``robodr-commission`` itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from autosecops.robot_edr.crypto import verify_strict
from autosecops.robot_edr.fleet_wire import (
    MAX_STORED_INT,
    WireError,
    digest,
    dumps_compact,
    is_digest,
    is_label,
    is_lower_hex,
    loads_strict,
)

PROFILE_KEYS: Final = (
    "model",
    "locked",
    "participants",
    "writer_topics",
    "motion_envelopes",
    "services",
    "actions",
    "reader_topics",
    "raw_dds_topics",
)
OPTIONAL_PROFILE_KEYS: Final = ("metadata", "participant_identities", "motion_types")
SEAL_KEY: Final = "seal"
SET_KEYS: Final = (
    "participants",
    "writer_topics",
    "services",
    "actions",
    "reader_topics",
    "raw_dds_topics",
)
IDENTITY_KEYS: Final = ("ips", "vendor", "enclave", "nodes", "max_instances")
METADATA_KEYS: Final = (
    "schema_version",
    "profile_version",
    "platform",
    "unit_id",
    "locked_by",
    "locked_at",
    "parent_digest",
)
ENVELOPE_KEYS: Final = ("max_linear_speed", "max_joint_speed")
OPTIONAL_ENVELOPE_LIMIT_KEYS: Final = (
    "max_lateral_speed",
    "max_vertical_speed",
    "max_roll_pitch_rate",
    "max_joint_torque",
    "max_joint_kp",
    "max_joint_position_step",
)
ENVELOPE_HOLONOMIC_KEY: Final = "holonomic"

REVOCATION_FORMAT: Final = "robodr-profile-revocations/v2"
REVOCATION_DOMAIN: Final = b"robodr-profile-revocations/v2\x00"
REVOCATION_KEYS: Final = (
    "format",
    "serial",
    "issued_at",
    "platform",
    "revoked_digests",
    "revoked_keys",
    "signature",
)
MAX_REVOCATION_BYTES: Final = 1 << 20
MAX_REVOKED_ENTRIES: Final = 4096
_MAX_U64: Final = 2**64 - 1


class ProfileFileError(ValueError):
    """A profile or revocation-list file is refused."""


def _is_number_or_null(value: Any) -> bool:
    return value is None or (
        isinstance(value, int | float) and not isinstance(value, bool)
    )


def _is_u64(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= _MAX_U64
    )


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _parse_object(data: bytes) -> dict[str, Any]:
    try:
        value = loads_strict(data)
    except WireError as exc:
        raise ProfileFileError(f"not a profile: {exc}") from exc
    if not isinstance(value, dict):
        raise ProfileFileError("not a profile: top level is not a JSON object")
    return value


def _check_envelopes(envelopes: Any) -> None:
    if not isinstance(envelopes, dict):
        raise ProfileFileError("motion_envelopes is not an object")
    allowed = (*ENVELOPE_KEYS, *OPTIONAL_ENVELOPE_LIMIT_KEYS, ENVELOPE_HOLONOMIC_KEY)
    for channel, envelope in envelopes.items():
        if not isinstance(envelope, dict):
            raise ProfileFileError(f"motion envelope {channel!r}: not an object")
        for key in envelope:
            if key not in allowed:
                raise ProfileFileError(
                    f"motion envelope {channel!r}: unknown key {key!r}"
                )
        for key in (*ENVELOPE_KEYS, *OPTIONAL_ENVELOPE_LIMIT_KEYS):
            if key in envelope and not _is_number_or_null(envelope[key]):
                raise ProfileFileError(
                    f"motion envelope {channel!r}: {key} is not a number or null"
                )
        for key in ENVELOPE_KEYS:
            if key not in envelope:
                raise ProfileFileError(
                    f"motion envelope {channel!r}: missing key {key!r}"
                )
        holonomic = envelope.get(ENVELOPE_HOLONOMIC_KEY, False)
        if not isinstance(holonomic, bool):
            raise ProfileFileError(
                f"motion envelope {channel!r}: holonomic is not a boolean"
            )


def _check_identities(identities: Any) -> None:
    if not isinstance(identities, dict):
        raise ProfileFileError("participant_identities is not an object")
    for name, identity in identities.items():
        if not isinstance(identity, dict):
            raise ProfileFileError(f"participant_identities {name!r}: not an object")
        for key in identity:
            if key not in IDENTITY_KEYS:
                raise ProfileFileError(
                    f"participant_identities {name!r}: unknown key {key!r}"
                )
        for key in ("ips", "vendor"):
            if key not in identity:
                raise ProfileFileError(
                    f"participant_identities {name!r}: missing key {key!r}"
                )
        valid = (
            _is_str_list(identity["ips"])
            and isinstance(identity["vendor"], str)
            and (
                identity.get("enclave") is None or isinstance(identity["enclave"], str)
            )
            and _is_str_list(identity.get("nodes", []))
            and (
                "max_instances" not in identity
                or (
                    _is_u64(identity["max_instances"])
                    and identity["max_instances"] < 2**32
                )
            )
        )
        if not valid:
            raise ProfileFileError(f"participant_identities {name!r}: wrong types")


def _check_profile_structure(obj: Mapping[str, Any]) -> None:
    for key in obj:
        if (
            key not in PROFILE_KEYS
            and key not in OPTIONAL_PROFILE_KEYS
            and key != SEAL_KEY
        ):
            raise ProfileFileError(f"unknown key {key!r}")
    for key in PROFILE_KEYS:
        if key not in obj:
            raise ProfileFileError(f"missing key {key!r}")
    if not isinstance(obj["model"], str) or not isinstance(obj["locked"], bool):
        raise ProfileFileError("model must be a string and locked a boolean")
    for key in SET_KEYS:
        if not _is_str_list(obj[key]):
            raise ProfileFileError(f"{key} must be a list of strings")
    _check_envelopes(obj["motion_envelopes"])
    if "motion_types" in obj:
        types = obj["motion_types"]
        if not isinstance(types, dict) or not all(
            isinstance(v, str) for v in types.values()
        ):
            raise ProfileFileError("motion_types must map channels to strings")
    if "participant_identities" in obj:
        _check_identities(obj["participant_identities"])


def check_draft_profile(body: bytes) -> str:
    """Check a draft profile file (contract §6.1); return its digest.

    A draft is ``locked: false``, without seal and without metadata (only
    ``robodr-commission lock`` writes those).

    Raises:
        ProfileFileError: Not a profile, or a locked one.
    """
    obj = _parse_object(body)
    _check_profile_structure(obj)
    if obj["locked"]:
        raise ProfileFileError("a locked profile is not a draft")
    if SEAL_KEY in obj:
        raise ProfileFileError('sealed file has "locked": false (edited after locking)')
    if "metadata" in obj:
        raise ProfileFileError('"metadata" on an unlocked profile')
    return digest(body)


@dataclass(frozen=True, slots=True)
class LockedProfile:
    """What the SOC reads from a locked profile it offers (contract §6.2)."""

    digest: str
    platform: str
    profile_version: int
    unit_id: str | None


def check_locked_profile(body: bytes) -> LockedProfile:
    """Check a locked profile file and read its platform and version.

    The seal is checked as ``robodr-commission`` writes it (the file starts
    with ``{"seal": "sha256:<hex>",`` over the rest of the text). The profile
    signature is not checked here: the robot verifies it with its own trust.

    Raises:
        ProfileFileError: Not a locked profile with metadata, or a bad seal.
    """
    obj = _parse_object(body)
    _check_profile_structure(obj)
    if not obj["locked"]:
        raise ProfileFileError("a draft profile cannot be offered: lock it first")
    _check_seal(body)
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        raise ProfileFileError("a locked profile must carry metadata")
    for key in METADATA_KEYS:
        if key not in metadata:
            raise ProfileFileError(f"metadata: missing key {key!r}")
    platform = metadata["platform"]
    version = metadata["profile_version"]
    unit_id = metadata["unit_id"]
    if not isinstance(platform, str) or not is_label(platform):
        raise ProfileFileError("metadata.platform must be [A-Za-z0-9._-]{1,64}")
    if not _is_u64(version) or version == 0:
        raise ProfileFileError("metadata.profile_version must be >= 1")
    if version > MAX_STORED_INT:
        raise ProfileFileError(
            "metadata.profile_version above 2^63-1, the largest the SOC stores"
        )
    if unit_id is not None and not isinstance(unit_id, str):
        raise ProfileFileError("metadata.unit_id must be a string or null")
    return LockedProfile(
        digest=digest(body), platform=platform, profile_version=version, unit_id=unit_id
    )


_SEAL_PREFIX: Final = b'{\n  "seal": "sha256:'
_SEAL_SUFFIX: Final = b'",\n'


def _check_seal(body: bytes) -> None:
    if not body.startswith(_SEAL_PREFIX):
        raise ProfileFileError("malformed or misplaced seal")
    hex_start = len(_SEAL_PREFIX)
    seal_hex = body[hex_start : hex_start + 64].decode("ascii", errors="replace")
    rest = body[hex_start + 64 :]
    if not is_lower_hex(seal_hex, 64) or not rest.startswith(_SEAL_SUFFIX):
        raise ProfileFileError("malformed or misplaced seal")
    sealed_body = b"{\n" + rest[len(_SEAL_SUFFIX) :]
    if hashlib.sha256(sealed_body).hexdigest() != seal_hex:
        raise ProfileFileError("seal does not match content")


@dataclass(frozen=True, slots=True)
class RevocationList:
    """A structurally checked ``robodr-profile-revocations/v2`` list."""

    platform: str
    serial: int
    signer_key_id: str
    signed_message: bytes
    signature: bytes

    @property
    def list_digest(self) -> str:
        """``sha256:`` of the signed message: the list's identity (§4.1)."""
        return digest(self.signed_message)

    def verify(self, public_key: bytes) -> bool:
        """Whether the list's signature verifies under a trust root's key."""
        return verify_strict(public_key, self.signed_message, self.signature)


def _check_entries(values: Any, what: str) -> list[str]:
    if not _is_str_list(values):
        raise ProfileFileError(f"{what} must be a list of strings")
    if len(set(values)) != len(values):
        raise ProfileFileError(f"{what}: an entry is listed twice")
    if not all(is_digest(v) for v in values):
        raise ProfileFileError(f"{what}: entries must be sha256:<64 lower-case hex>")
    return values


def parse_revocation_list(body: bytes) -> RevocationList:
    """Strictly parse a revocation list (``robodr-commission`` rules).

    Raises:
        ProfileFileError: Malformed, or more than 4096 entries.
    """
    if len(body) > MAX_REVOCATION_BYTES:
        raise ProfileFileError("revocation list larger than 1 MiB")
    obj = _parse_object(body)
    for key in obj:
        if key not in REVOCATION_KEYS:
            raise ProfileFileError(f"revocation list: unknown key {key!r}")
    for key in REVOCATION_KEYS:
        if key not in obj:
            raise ProfileFileError(f"revocation list: missing key {key!r}")
    if obj["format"] != REVOCATION_FORMAT:
        raise ProfileFileError(f"revocation list format must be {REVOCATION_FORMAT}")
    serial, issued_at, platform = obj["serial"], obj["issued_at"], obj["platform"]
    if not _is_u64(serial) or serial == 0 or not _is_u64(issued_at):
        raise ProfileFileError("revocation list: serial must be >= 1")
    if serial > MAX_STORED_INT:
        raise ProfileFileError(
            "revocation list: serial above 2^63-1, the largest the SOC stores"
        )
    if not isinstance(platform, str) or not is_label(platform):
        raise ProfileFileError("revocation list: platform must be [A-Za-z0-9._-]{1,64}")
    digests = _check_entries(obj["revoked_digests"], "revoked_digests")
    keys = _check_entries(obj["revoked_keys"], "revoked_keys")
    if len(digests) + len(keys) > MAX_REVOKED_ENTRIES:
        raise ProfileFileError(f"more than {MAX_REVOKED_ENTRIES} entries")
    signature = obj["signature"]
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm",
        "key_id",
        "signature_hex",
    }:
        raise ProfileFileError("revocation list: malformed signature object")
    key_id, sig_hex = signature["key_id"], signature["signature_hex"]
    valid_key_id = (
        isinstance(key_id, str)
        and 0 < len(key_id) <= 64
        and all("!" <= c <= "~" for c in key_id)
    )
    if signature["algorithm"] != "ed25519" or not valid_key_id:
        raise ProfileFileError(
            "revocation list: signature must be ed25519 with a key id"
        )
    if not isinstance(sig_hex, str) or len(sig_hex) != 128:
        raise ProfileFileError("revocation list: signature_hex is not 64 bytes of hex")
    try:
        raw_sig = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise ProfileFileError("revocation list: signature_hex is not hex") from exc
    signed = REVOCATION_DOMAIN + dumps_compact(
        {
            "format": REVOCATION_FORMAT,
            "serial": serial,
            "issued_at": issued_at,
            "platform": platform,
            "revoked_digests": digests,
            "revoked_keys": keys,
        }
    )
    return RevocationList(
        platform=platform,
        serial=serial,
        signer_key_id=key_id,
        signed_message=signed,
        signature=raw_sig,
    )
