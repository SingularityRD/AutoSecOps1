"""Wire formats of the `robodr.fleet` API v1 (SOC side).

A byte-exact port of RoboDR's ``robodr_fleet::wire`` and ``robodr_fleet::b64``
(contract ``robodr.fleet-api.md`` §2-§7): strict base64url, the signed
envelope, the length-framed signature, MAC and request-authentication
messages, the compact enrollment token and every payload format. Pure: no
I/O and no clock (times are parameters).

Payloads are carried as base64url of their exact bytes, so verification
always hashes the bytes that were decoded, never a re-serialisation. Writers
emit compact JSON in the contract's key order (Python dicts keep insertion
order); Ed25519 is deterministic, so a document this module signs is
byte-identical to the reference implementation's.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from autosecops.robot_edr.crypto import (
    PUBLIC_KEY_LEN,
    SIGNATURE_LEN,
    derive_key_id,
    is_strict_public_key,
    verify_strict,
)

# --- constants --------------------------------------------------------------------

ENVELOPE_FORMAT: Final = "robodr-fleet-envelope/v1"
TOKEN_PREFIX: Final = "rdet1."

TOKEN_FORMAT: Final = "robodr-fleet-enroll-token/v1"
ENROLL_REQUEST_FORMAT: Final = "robodr-fleet-enroll-request/v1"
ENROLL_ANSWER_FORMAT: Final = "robodr-fleet-enroll-answer/v1"
ROTATE_REQUEST_FORMAT: Final = "robodr-fleet-rotate-request/v1"
ROTATE_ANSWER_FORMAT: Final = "robodr-fleet-rotate-answer/v1"
RETIRE_REQUEST_FORMAT: Final = "robodr-fleet-retire-request/v1"
RETIRE_ANSWER_FORMAT: Final = "robodr-fleet-retire-answer/v1"
CANCEL_REQUEST_FORMAT: Final = "robodr-fleet-cancel-request/v1"
CANCEL_ANSWER_FORMAT: Final = "robodr-fleet-cancel-answer/v1"
APPROVAL_FORMAT: Final = "robodr-fleet-profile-approval/v1"
RING_FORMAT: Final = "robodr-fleet-ring/v1"
OFFER_FORMAT: Final = "robodr-fleet-profile-offer/v1"

T_TOKEN: Final = "enroll-token"
T_ENROLL_REQUEST: Final = "enroll-request"
T_ENROLL_ANSWER: Final = "enroll-answer"
T_ROTATE_REQUEST: Final = "rotate-request"
T_ROTATE_ANSWER: Final = "rotate-answer"
T_RETIRE_REQUEST: Final = "retire-request"
T_RETIRE_ANSWER: Final = "retire-answer"
T_CANCEL_REQUEST: Final = "cancel-request"
T_CANCEL_ANSWER: Final = "cancel-answer"
T_APPROVAL: Final = "profile-approval"
T_RING: Final = "ring-info"
TYPES: Final = frozenset(
    {
        T_TOKEN,
        T_ENROLL_REQUEST,
        T_ENROLL_ANSWER,
        T_ROTATE_REQUEST,
        T_ROTATE_ANSWER,
        T_RETIRE_REQUEST,
        T_RETIRE_ANSWER,
        T_CANCEL_REQUEST,
        T_CANCEL_ANSWER,
        T_APPROVAL,
        T_RING,
    }
)

SIG_DOMAIN: Final = b"robodr-fleet/sig/v1\x00"
MAC_DOMAIN: Final = b"robodr-fleet/token-mac/v1\x00"
MAC_KEY_DOMAIN: Final = b"robodr-fleet/token-mac-key/v1\x00"
REQUEST_DOMAIN: Final = b"robodr-fleet/request/v1\x00"

MAX_ENVELOPE_BYTES: Final = 64 * 1024
MAX_PAYLOAD_BYTES: Final = 32 * 1024
MAX_TOKEN_BYTES: Final = 4 * 1024
MAX_TOKEN_VALIDITY_MS: Final = 7 * 24 * 3600 * 1000
MAX_APPROVAL_VALIDITY_MS: Final = 7 * 24 * 3600 * 1000
MAX_SKEW_MS: Final = 300_000
MAX_SIGS: Final = 4
MAX_APPROVERS: Final = 8
MAX_DRAFT_BYTES: Final = 8 * 1024 * 1024
MAX_U64: Final = 2**64 - 1
MAX_STORED_INT: Final = 2**63 - 1
"""Largest integer the SOC stores (PostgreSQL ``bigint``); larger contract
u64 values it would have to store are refused as client errors."""

ROLES: Final = ("uplink", "finding", "blackbox")
"""Key roles a robot registers at enrollment, in request order (§3.2)."""
ROTATABLE: Final = frozenset({"uplink", "finding"})
"""Roles the rotation endpoints handle (§5)."""

_LABEL_RE: Final = re.compile(r"[A-Za-z0-9._-]{1,64}")
_IDENT_RE: Final = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_KEY_ID_RE: Final = re.compile(r"ed25519:[0-9a-f]{16}")
_DIGEST_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION_RE: Final = re.compile(r"[0-9][0-9A-Za-z.+~-]{0,63}")
_B64_ALPHABET: Final = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_B64_VALUES: Final = {c: i for i, c in enumerate(_B64_ALPHABET)}


class WireError(ValueError):
    """A token, envelope or payload is refused (pure checks)."""


# --- field rules ------------------------------------------------------------------


def is_lower_hex(value: str, length: int) -> bool:
    """Exactly ``length`` lower-case hex digits."""
    return len(value) == length and all(c in "0123456789abcdef" for c in value)


def is_label(value: str) -> bool:
    """``[A-Za-z0-9._-]{1,64}`` (robot id, site, platform)."""
    return _LABEL_RE.fullmatch(value) is not None


def is_ident(value: str) -> bool:
    """``[A-Za-z0-9._:-]{1,64}`` (workspace, token id, approval id, operator)."""
    return _IDENT_RE.fullmatch(value) is not None


def is_key_id(value: str) -> bool:
    """``ed25519:<16 lower-case hex>`` (the derived RoboDR key id)."""
    return _KEY_ID_RE.fullmatch(value) is not None


def is_digest(value: str) -> bool:
    """``sha256:<64 lower-case hex>``."""
    return _DIGEST_RE.fullmatch(value) is not None


def is_version(value: str) -> bool:
    """A release version: ``[0-9][0-9A-Za-z.+~-]{0,63}``."""
    return _VERSION_RE.fullmatch(value) is not None


def _is_prefixed_id(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and is_lower_hex(value[len(prefix) :], 32)


def is_request_id(value: str) -> bool:
    """``rfe1-<32 lower-case hex>``."""
    return _is_prefixed_id(value, "rfe1-")


def is_rotation_id(value: str) -> bool:
    """``rfr1-<32 lower-case hex>``."""
    return _is_prefixed_id(value, "rfr1-")


# --- primitives -------------------------------------------------------------------


def b64_encode(data: bytes) -> str:
    """Base64url without padding (RFC 4648 §5)."""
    out: list[str] = []
    for start in range(0, len(data), 3):
        chunk = data[start : start + 3]
        padded = chunk + b"\x00" * (3 - len(chunk))
        n = (padded[0] << 16) | (padded[1] << 8) | padded[2]
        for i in range(len(chunk) + 1):
            out.append(_B64_ALPHABET[(n >> (18 - 6 * i)) & 0x3F])
    return "".join(out)


def b64_decode(text: str) -> bytes | None:
    """Decode canonical base64url without padding; ``None`` for anything else.

    Only the URL-safe alphabet, no ``=``, no white space, a length that is not
    1 mod 4, and the unused low bits of the last character zero: every byte
    string has exactly one accepted encoding.
    """
    if len(text) % 4 == 1:
        return None
    out = bytearray()
    for start in range(0, len(text), 4):
        chunk = text[start : start + 4]
        n = 0
        for i, char in enumerate(chunk):
            value = _B64_VALUES.get(char)
            if value is None:
                return None
            n |= value << (18 - 6 * i)
        match len(chunk):
            case 4:
                out += bytes(((n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF))
            case 3:
                if n & 0xFF:
                    return None
                out += bytes(((n >> 16) & 0xFF, (n >> 8) & 0xFF))
            case 2:
                if n & 0xFFFF:
                    return None
                out.append((n >> 16) & 0xFF)
            case _:
                return None
    return bytes(out)


def digest(data: bytes) -> str:
    """``sha256:`` + lower-case hex of SHA-256(``data``)."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def fingerprint(public_key: bytes) -> str:
    """Fingerprint of an Ed25519 public key: :func:`digest` of its 32 bytes."""
    return digest(public_key)


def _framed(part: bytes) -> bytes:
    return struct.pack(">I", len(part)) + part


def sig_message(kind: str, key_id: str, payload: bytes) -> bytes:
    """The message an envelope or token signature covers (§2.3)."""
    return (
        SIG_DOMAIN
        + _framed(kind.encode("ascii"))
        + _framed(key_id.encode("ascii"))
        + hashlib.sha256(payload).digest()
    )


def mac_key(nonce: bytes) -> bytes:
    """The token MAC key: SHA-256(domain || nonce) (§3.2)."""
    return hashlib.sha256(MAC_KEY_DOMAIN + nonce).digest()


def mac_message(token_id: str, payload: bytes) -> bytes:
    """The message the token MAC covers (§3.2)."""
    return (
        MAC_DOMAIN
        + _framed(token_id.encode("ascii"))
        + hashlib.sha256(payload).digest()
    )


def token_mac(nonce: bytes, token_id: str, payload: bytes) -> bytes:
    """HMAC-SHA256 under :func:`mac_key` over :func:`mac_message`."""
    return hmac.new(
        mac_key(nonce), mac_message(token_id, payload), hashlib.sha256
    ).digest()


def request_message(
    method: str, target: str, key_id: str, timestamp_ms: int, body: bytes
) -> bytes:
    """The message a request-authentication signature covers (§2.5)."""
    return (
        REQUEST_DOMAIN
        + _framed(method.encode("ascii"))
        + _framed(target.encode("utf-8"))
        + _framed(key_id.encode("ascii"))
        + struct.pack(">Q", timestamp_ms)
        + hashlib.sha256(body).digest()
    )


def verify_hex(public_key: bytes, message: bytes, sig_hex: str) -> bool:
    """Strict Ed25519 verification of ``sig_hex`` (128 lower-case hex)."""
    if not is_lower_hex(sig_hex, SIGNATURE_LEN * 2):
        return False
    return verify_strict(public_key, message, bytes.fromhex(sig_hex))


@dataclass(frozen=True, slots=True)
class SigningKey:
    """An Ed25519 secret key with its RoboDR derived key id."""

    seed: bytes
    public_key: bytes
    key_id: str

    @classmethod
    def from_seed(cls, seed: bytes) -> SigningKey:
        """Build from the 32-byte secret seed."""
        if len(seed) != 32:
            raise WireError("an Ed25519 secret seed is 32 bytes")
        public = (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        return cls(seed=seed, public_key=public, key_id=derive_key_id(public))

    def sign(self, message: bytes) -> bytes:
        """Ed25519 signature (deterministic, RFC 8032)."""
        return Ed25519PrivateKey.from_private_bytes(self.seed).sign(message)


def check_public(public_hex: str, key_id: str, fpr: str) -> bytes:
    """Decode ``public_hex`` and check that ``key_id`` and ``fpr`` derive from it.

    Raises:
        WireError: Malformed, not a canonical large-order key, or a mismatch.
    """
    if not is_lower_hex(public_hex, PUBLIC_KEY_LEN * 2):
        raise WireError("public_hex must be 64 lower-case hex digits")
    public = bytes.fromhex(public_hex)
    if not is_strict_public_key(public):
        raise WireError("public key is not a canonical, large-order Ed25519 key")
    if derive_key_id(public) != key_id:
        raise WireError("key_id is not the id derived from public_hex")
    if fingerprint(public) != fpr:
        raise WireError("fingerprint is not SHA-256 of public_hex")
    return public


# --- strict JSON ------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WireError(f"JSON: duplicate key {key[:64]!r}")
        result[key] = value
    return result


def _refuse_constant(name: str) -> Any:
    raise WireError(f"JSON: {name} is not JSON")


def loads_strict(data: bytes | str) -> Any:
    """Parse JSON refusing duplicate keys at any depth, NaN and Infinity.

    Raises:
        WireError: Not UTF-8 or not strict JSON.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WireError("not UTF-8") from exc
    else:
        text = data
    try:
        return json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_refuse_constant
        )
    except WireError:
        raise
    except (ValueError, RecursionError) as exc:
        raise WireError("JSON: malformed") from exc


def dumps_compact(value: Any) -> bytes:
    """Compact JSON in the dict's key order (the exact bytes that are signed)."""
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


type _FieldCheck = Callable[[Any], bool]


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_opt_str(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _is_u64(value: Any) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_U64
    )


def _is_u8(value: Any) -> bool:
    return _is_u64(value) and value <= 255


def _exact_object(value: Any, keys: Sequence[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WireError(f"{what} is not a JSON object")
    for key in keys:
        if key not in value:
            raise WireError(f"{what}: missing key {key!r}")
    for key in value:
        if key not in keys:
            raise WireError(f"{what}: unknown key {key[:64]!r}")
    return value


def _typed(
    payload: bytes, fields: Sequence[tuple[str, _FieldCheck]], what: str
) -> dict[str, Any]:
    obj = _exact_object(loads_strict(payload), [name for name, _ in fields], what)
    for name, check in fields:
        if not check(obj[name]):
            raise WireError(f"{what}: {name} has the wrong type")
    return obj


# --- envelope ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EnvelopeSig:
    """One envelope signature."""

    key_id: str
    sig: str


@dataclass(frozen=True, slots=True)
class EnvelopeMac:
    """The token MAC of an enrollment request."""

    token_id: str
    mac: str


@dataclass(frozen=True, slots=True)
class Opened:
    """A structurally valid envelope with its decoded payload (not yet verified)."""

    kind: str
    payload: bytes
    sigs: tuple[EnvelopeSig, ...]
    mac: EnvelopeMac | None

    @property
    def signers(self) -> list[str]:
        """Signer key ids in order."""
        return [s.key_id for s in self.sigs]

    @property
    def payload_digest(self) -> str:
        """``sha256:`` of the payload bytes (what answers name as request_digest)."""
        return digest(self.payload)

    def verify_by(self, key_id: str, public_key: bytes) -> bool:
        """Whether the signature by ``key_id`` verifies under ``public_key``."""
        for sig in self.sigs:
            if sig.key_id == key_id:
                return verify_hex(
                    public_key, sig_message(self.kind, key_id, self.payload), sig.sig
                )
        return False

    def verify_mac(self, nonce: bytes) -> bool:
        """Constant-time check of the token MAC."""
        if self.mac is None:
            return False
        want = token_mac(nonce, self.mac.token_id, self.payload)
        return hmac.compare_digest(bytes.fromhex(self.mac.mac), want)


def parse_envelope(data: bytes, kind: str) -> Opened:
    """Strictly parse an envelope of the expected ``kind`` (§2.2).

    Raises:
        WireError: Any syntax rule is broken.
    """
    if len(data) > MAX_ENVELOPE_BYTES:
        raise WireError(f"envelope larger than {MAX_ENVELOPE_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WireError("not UTF-8") from exc
    core = text.removesuffix("\n")
    if core.strip() != core:
        raise WireError("white space around the envelope")
    value = loads_strict(core)
    want = (
        ("format", "type", "payload", "sigs", "mac")
        if kind == T_ENROLL_REQUEST
        else ("format", "type", "payload", "sigs")
    )
    if not isinstance(value, dict) or len(value) != len(want):
        raise WireError(f"envelope must have exactly the keys {list(want)}")
    obj = _exact_object(value, want, "envelope")
    raw_sigs = obj["sigs"]
    if isinstance(raw_sigs, list):
        for item in raw_sigs:
            _exact_object(item, ("alg", "key_id", "sig"), "sigs[]")
    if kind == T_ENROLL_REQUEST:
        _exact_object(obj["mac"], ("alg", "token_id", "mac"), "mac")
    fmt, env_type, payload_text = obj["format"], obj["type"], obj["payload"]
    if not (
        isinstance(fmt, str)
        and isinstance(env_type, str)
        and isinstance(payload_text, str)
        and isinstance(raw_sigs, list)
    ):
        raise WireError("envelope: wrong member types")
    if not all(
        isinstance(s[k], str) for s in raw_sigs for k in ("alg", "key_id", "sig")
    ):
        raise WireError("envelope: sigs[] members must be strings")
    if fmt != ENVELOPE_FORMAT:
        raise WireError(f"format {fmt[:64]!r}, expected {ENVELOPE_FORMAT!r}")
    if env_type not in TYPES:
        raise WireError(f"unknown type {env_type[:64]!r}")
    if env_type != kind:
        raise WireError(f"type {env_type!r}, expected {kind!r}")
    if not 1 <= len(raw_sigs) <= MAX_SIGS:
        raise WireError(f"sigs must hold 1..={MAX_SIGS} signatures")
    sigs: list[EnvelopeSig] = []
    for i, item in enumerate(raw_sigs):
        if item["alg"] != "ed25519":
            raise WireError(f'sigs[{i}].alg must be "ed25519"')
        if not is_key_id(item["key_id"]):
            raise WireError(f"sigs[{i}].key_id is not ed25519:<16 hex>")
        if not is_lower_hex(item["sig"], SIGNATURE_LEN * 2):
            raise WireError(f"sigs[{i}].sig is not 128 lower-case hex")
        if any(s.key_id == item["key_id"] for s in sigs):
            raise WireError(f"sigs[{i}]: key id signs twice")
        sigs.append(EnvelopeSig(key_id=item["key_id"], sig=item["sig"]))
    mac: EnvelopeMac | None = None
    if kind == T_ENROLL_REQUEST:
        raw_mac = obj["mac"]
        if not (
            raw_mac["alg"] == "hmac-sha256"
            and isinstance(raw_mac["token_id"], str)
            and is_ident(raw_mac["token_id"])
            and isinstance(raw_mac["mac"], str)
            and is_lower_hex(raw_mac["mac"], 64)
        ):
            raise WireError('mac must be {alg: "hmac-sha256", token_id, mac: 64 hex}')
        mac = EnvelopeMac(token_id=raw_mac["token_id"], mac=raw_mac["mac"])
    payload = b64_decode(payload_text)
    if payload is None:
        raise WireError("payload is not canonical base64url")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise WireError(f"payload larger than {MAX_PAYLOAD_BYTES} bytes")
    return Opened(kind=env_type, payload=payload, sigs=tuple(sigs), mac=mac)


def sign_envelope(kind: str, payload: bytes, signers: Sequence[SigningKey]) -> bytes:
    """An envelope over ``payload`` signed by ``signers`` in order: compact JSON + LF."""
    return assemble_envelope(
        kind,
        payload,
        [
            (key.key_id, key.sign(sig_message(kind, key.key_id, payload)).hex())
            for key in signers
        ],
    )


def assemble_envelope(
    kind: str, payload: bytes, signatures: Sequence[tuple[str, str]]
) -> bytes:
    """An envelope from detached ``(key_id, sig_hex)`` signatures, in order.

    The signatures are not verified here: verify each with
    :func:`verify_hex` over :func:`sig_message` first.
    """
    sigs = [
        {"alg": "ed25519", "key_id": key_id, "sig": sig_hex}
        for key_id, sig_hex in signatures
    ]
    envelope = {
        "format": ENVELOPE_FORMAT,
        "type": kind,
        "payload": b64_encode(payload),
        "sigs": sigs,
    }
    return dumps_compact(envelope) + b"\n"


# --- token ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """The payload of an enrollment token (§3.1)."""

    token_id: str
    workspace: str
    robot_id: str
    site: str | None
    soc_key_id: str
    issued_at_ms: int
    expires_at_ms: int
    nonce: str

    def to_bytes(self) -> bytes:
        """Compact JSON in the contract's key order."""
        return dumps_compact(
            {
                "format": TOKEN_FORMAT,
                "token_id": self.token_id,
                "workspace": self.workspace,
                "robot_id": self.robot_id,
                "site": self.site,
                "soc_key_id": self.soc_key_id,
                "issued_at_ms": self.issued_at_ms,
                "expires_at_ms": self.expires_at_ms,
                "nonce": self.nonce,
            }
        )

    def check(self) -> None:
        """Field rules of §3.1.

        Raises:
            WireError: A field is malformed.
        """
        if not is_ident(self.token_id) or not is_ident(self.workspace):
            raise WireError("token_id / workspace must be [A-Za-z0-9._:-]{1,64}")
        if not is_label(self.robot_id) or (
            self.site is not None and not is_label(self.site)
        ):
            raise WireError("robot_id / site must be [A-Za-z0-9._-]{1,64}")
        if not is_key_id(self.soc_key_id):
            raise WireError("soc_key_id must be ed25519:<16 hex>")
        validity = self.expires_at_ms - self.issued_at_ms
        if not 0 < validity <= MAX_TOKEN_VALIDITY_MS:
            raise WireError("token validity must be > 0 and <= 7 days")
        if not is_lower_hex(self.nonce, 64) or set(self.nonce) == {"0"}:
            raise WireError("nonce must be 64 lower-case hex (32 random bytes)")


_TOKEN_FIELDS: Final[tuple[tuple[str, _FieldCheck], ...]] = (
    ("format", _is_str),
    ("token_id", _is_str),
    ("workspace", _is_str),
    ("robot_id", _is_str),
    ("site", _is_opt_str),
    ("soc_key_id", _is_str),
    ("issued_at_ms", _is_u64),
    ("expires_at_ms", _is_u64),
    ("nonce", _is_str),
)


def issue_token(payload: TokenPayload, fleet_key: SigningKey) -> str:
    """The compact token ``rdet1.<payload>.<signature>`` signed by the fleet key."""
    if payload.soc_key_id != fleet_key.key_id:
        raise WireError("soc_key_id must name the signing fleet key")
    payload.check()
    data = payload.to_bytes()
    signature = fleet_key.sign(sig_message(T_TOKEN, payload.soc_key_id, data))
    return f"{TOKEN_PREFIX}{b64_encode(data)}.{b64_encode(signature)}"


@dataclass(frozen=True, slots=True)
class ParsedToken:
    """A parsed compact token (structure checked)."""

    payload: TokenPayload
    payload_bytes: bytes
    signature: bytes

    def verify(self, public_key: bytes) -> bool:
        """The signature verifies under ``public_key`` (the key ``soc_key_id`` names)."""
        message = sig_message(T_TOKEN, self.payload.soc_key_id, self.payload_bytes)
        return verify_strict(public_key, message, self.signature)


def parse_token(text: str) -> ParsedToken:
    """Strictly parse a compact token; surrounding spaces, tabs, CR and LF are trimmed.

    Raises:
        WireError: Anything but ``rdet1.<payload>.<signature>`` with a valid payload.
    """
    token = text.strip(" \t\r\n")
    if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise WireError("token too long")
    if not token.startswith(TOKEN_PREFIX):
        raise WireError(f"token must start with {TOKEN_PREFIX!r}")
    parts = token[len(TOKEN_PREFIX) :].split(".")
    if len(parts) != 2:
        raise WireError("token must be rdet1.<payload>.<signature>")
    payload_bytes = b64_decode(parts[0])
    if payload_bytes is None:
        raise WireError("token payload is not base64url")
    signature = b64_decode(parts[1])
    if signature is None or len(signature) != SIGNATURE_LEN:
        raise WireError("token signature is not 64 bytes of base64url")
    obj = _typed(payload_bytes, _TOKEN_FIELDS, "token")
    if obj["format"] != TOKEN_FORMAT:
        raise WireError("token format")
    payload = TokenPayload(
        token_id=obj["token_id"],
        workspace=obj["workspace"],
        robot_id=obj["robot_id"],
        site=obj["site"],
        soc_key_id=obj["soc_key_id"],
        issued_at_ms=obj["issued_at_ms"],
        expires_at_ms=obj["expires_at_ms"],
        nonce=obj["nonce"],
    )
    payload.check()
    return ParsedToken(
        payload=payload, payload_bytes=payload_bytes, signature=signature
    )


# --- enrollment -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestKey:
    """One key of an enrollment request."""

    role: str
    key_id: str
    public_key: bytes
    fingerprint: str


@dataclass(frozen=True, slots=True)
class EnrollRequest:
    """An enrollment request payload (§3.2)."""

    request_id: str
    token_id: str
    workspace: str
    robot_id: str
    site: str | None
    created_at_ms: int
    agentd_version: str
    profile_digest: str | None
    keys: tuple[RequestKey, ...]


_ENROLL_FIELDS: Final[tuple[tuple[str, _FieldCheck], ...]] = (
    ("format", _is_str),
    ("request_id", _is_str),
    ("token_id", _is_str),
    ("workspace", _is_str),
    ("robot_id", _is_str),
    ("site", _is_opt_str),
    ("created_at_ms", _is_u64),
    ("agentd_version", _is_str),
    ("profile_digest", _is_opt_str),
    ("keys", lambda v: isinstance(v, list)),
)


def parse_enroll_request(payload: bytes) -> EnrollRequest:
    """Strictly parse an enrollment request payload.

    Raises:
        WireError: Any rule of §3.2 is broken.
    """
    obj = _typed(payload, _ENROLL_FIELDS, "enroll request")
    raw_keys: list[Any] = obj["keys"]
    if len(raw_keys) != len(ROLES):
        raise WireError(f"keys must list exactly the roles {list(ROLES)}")
    for item in raw_keys:
        _exact_object(item, ("role", "key_id", "public_hex", "fingerprint"), "keys[]")
        if not all(isinstance(v, str) for v in item.values()):
            raise WireError("keys[] members must be strings")
    if obj["format"] != ENROLL_REQUEST_FORMAT:
        raise WireError("enroll request format")
    if not is_request_id(obj["request_id"]):
        raise WireError("request_id must be rfe1-<32 hex>")
    if not (
        is_ident(obj["token_id"])
        and is_ident(obj["workspace"])
        and is_label(obj["robot_id"])
    ):
        raise WireError("token_id / workspace / robot_id malformed")
    if obj["site"] is not None and not is_label(obj["site"]):
        raise WireError("site malformed")
    if not is_version(obj["agentd_version"]):
        raise WireError("agentd_version malformed")
    if obj["profile_digest"] is not None and not is_digest(obj["profile_digest"]):
        raise WireError("profile_digest must be sha256:<64 hex> or null")
    keys: list[RequestKey] = []
    for item, role in zip(raw_keys, ROLES, strict=True):
        if item["role"] != role:
            raise WireError(f"keys must be in the order {list(ROLES)}")
        public = check_public(item["public_hex"], item["key_id"], item["fingerprint"])
        keys.append(
            RequestKey(
                role=role,
                key_id=item["key_id"],
                public_key=public,
                fingerprint=item["fingerprint"],
            )
        )
    if len({k.fingerprint for k in keys}) != len(ROLES):
        raise WireError("the three role keys must be distinct")
    return EnrollRequest(
        request_id=obj["request_id"],
        token_id=obj["token_id"],
        workspace=obj["workspace"],
        robot_id=obj["robot_id"],
        site=obj["site"],
        created_at_ms=obj["created_at_ms"],
        agentd_version=obj["agentd_version"],
        profile_digest=obj["profile_digest"],
        keys=tuple(keys),
    )


def enroll_answer_payload(
    request: EnrollRequest, *, request_digest: str, enrolled_at_ms: int
) -> bytes:
    """The ``robodr-fleet-enroll-answer/v1`` payload bytes (§3.3)."""
    return dumps_compact(
        {
            "format": ENROLL_ANSWER_FORMAT,
            "request_id": request.request_id,
            "request_digest": request_digest,
            "token_id": request.token_id,
            "workspace": request.workspace,
            "robot_id": request.robot_id,
            "site": request.site,
            "keys": [
                {"role": k.role, "key_id": k.key_id, "fingerprint": k.fingerprint}
                for k in request.keys
            ],
            "enrolled_at_ms": enrolled_at_ms,
        }
    )


# --- rotation ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RotateRequest:
    """A rotate request payload (§5.1)."""

    rotation_id: str
    workspace: str
    robot_id: str
    role: str
    old_key_id: str
    old_fingerprint: str
    new_key_id: str
    new_public_key: bytes
    new_fingerprint: str
    created_at_ms: int


@dataclass(frozen=True, slots=True)
class RetireRequest:
    """A retire request payload (§5.3)."""

    rotation_id: str
    workspace: str
    robot_id: str
    role: str
    old_key_id: str
    new_key_id: str
    created_at_ms: int


@dataclass(frozen=True, slots=True)
class CancelRequest:
    """A cancel request payload (§5.5)."""

    rotation_id: str
    request_digest: str
    workspace: str
    robot_id: str
    role: str
    old_key_id: str
    new_key_id: str
    created_at_ms: int


def parse_rotate_request(payload: bytes) -> RotateRequest:
    """Strictly parse a rotate request payload.

    Raises:
        WireError: Any rule of §5.1 is broken.
    """
    fields: tuple[tuple[str, _FieldCheck], ...] = (
        ("format", _is_str),
        ("rotation_id", _is_str),
        ("workspace", _is_str),
        ("robot_id", _is_str),
        ("role", _is_str),
        ("old_key_id", _is_str),
        ("old_fingerprint", _is_str),
        ("new_key_id", _is_str),
        ("new_public_hex", _is_str),
        ("new_fingerprint", _is_str),
        ("created_at_ms", _is_u64),
    )
    obj = _typed(payload, fields, "rotate request")
    if not (
        obj["format"] == ROTATE_REQUEST_FORMAT
        and is_rotation_id(obj["rotation_id"])
        and is_ident(obj["workspace"])
        and is_label(obj["robot_id"])
        and obj["role"] in ROTATABLE
        and is_key_id(obj["old_key_id"])
        and is_digest(obj["old_fingerprint"])
    ):
        raise WireError("rotate request malformed")
    public = check_public(
        obj["new_public_hex"], obj["new_key_id"], obj["new_fingerprint"]
    )
    if obj["new_fingerprint"] == obj["old_fingerprint"]:
        raise WireError("the new key equals the old key")
    return RotateRequest(
        rotation_id=obj["rotation_id"],
        workspace=obj["workspace"],
        robot_id=obj["robot_id"],
        role=obj["role"],
        old_key_id=obj["old_key_id"],
        old_fingerprint=obj["old_fingerprint"],
        new_key_id=obj["new_key_id"],
        new_public_key=public,
        new_fingerprint=obj["new_fingerprint"],
        created_at_ms=obj["created_at_ms"],
    )


def parse_retire_request(payload: bytes) -> RetireRequest:
    """Strictly parse a retire request payload.

    Raises:
        WireError: Any rule of §5.3 is broken.
    """
    fields: tuple[tuple[str, _FieldCheck], ...] = (
        ("format", _is_str),
        ("rotation_id", _is_str),
        ("workspace", _is_str),
        ("robot_id", _is_str),
        ("role", _is_str),
        ("old_key_id", _is_str),
        ("new_key_id", _is_str),
        ("created_at_ms", _is_u64),
    )
    obj = _typed(payload, fields, "retire request")
    if not (
        obj["format"] == RETIRE_REQUEST_FORMAT
        and is_rotation_id(obj["rotation_id"])
        and is_ident(obj["workspace"])
        and is_label(obj["robot_id"])
        and obj["role"] in ROTATABLE
        and is_key_id(obj["old_key_id"])
        and is_key_id(obj["new_key_id"])
    ):
        raise WireError("retire request malformed")
    return RetireRequest(**{k: obj[k] for k in obj if k != "format"})


def parse_cancel_request(payload: bytes) -> CancelRequest:
    """Strictly parse a cancel request payload.

    Raises:
        WireError: Any rule of §5.5 is broken.
    """
    fields: tuple[tuple[str, _FieldCheck], ...] = (
        ("format", _is_str),
        ("rotation_id", _is_str),
        ("request_digest", _is_str),
        ("workspace", _is_str),
        ("robot_id", _is_str),
        ("role", _is_str),
        ("old_key_id", _is_str),
        ("new_key_id", _is_str),
        ("created_at_ms", _is_u64),
    )
    obj = _typed(payload, fields, "cancel request")
    if not (
        obj["format"] == CANCEL_REQUEST_FORMAT
        and is_rotation_id(obj["rotation_id"])
        and is_digest(obj["request_digest"])
        and is_ident(obj["workspace"])
        and is_label(obj["robot_id"])
        and obj["role"] in ROTATABLE
        and is_key_id(obj["old_key_id"])
        and is_key_id(obj["new_key_id"])
        and obj["old_key_id"] != obj["new_key_id"]
    ):
        raise WireError("cancel request malformed")
    return CancelRequest(**{k: obj[k] for k in obj if k != "format"})


def key_answer_payload(
    *,
    answer_format: str,
    rotation_id: str,
    request_digest: str,
    workspace: str,
    robot_id: str,
    role: str,
    old_key_id: str,
    new_key_id: str,
    status: str,
    at_ms: int,
) -> bytes:
    """A rotate / retire / cancel answer payload (§5.1, §5.3, §5.5)."""
    return dumps_compact(
        {
            "format": answer_format,
            "rotation_id": rotation_id,
            "request_digest": request_digest,
            "workspace": workspace,
            "robot_id": robot_id,
            "role": role,
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "status": status,
            "at_ms": at_ms,
        }
    )


# --- profiles and ring ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Approval:
    """A profile approval payload (§6.3)."""

    approval_id: str
    workspace: str
    robot_id: str
    platform: str
    profile_digest: str
    profile_version: int
    approved_by: tuple[str, ...]
    issued_at_ms: int
    expires_at_ms: int

    def check(self) -> None:
        """The field rules of §6.3.

        Raises:
            WireError: A field is malformed or the validity exceeds 7 days.
        """
        if not (
            is_ident(self.approval_id)
            and is_ident(self.workspace)
            and is_label(self.robot_id)
            and is_label(self.platform)
            and is_digest(self.profile_digest)
            and 0 < self.profile_version <= MAX_U64
        ):
            raise WireError("profile approval malformed")
        if not 1 <= len(self.approved_by) <= MAX_APPROVERS or not all(
            is_ident(op) for op in self.approved_by
        ):
            raise WireError("approved_by must name 1..=8 operators")
        if len(set(self.approved_by)) != len(self.approved_by):
            raise WireError("approved_by names an operator twice")
        validity = self.expires_at_ms - self.issued_at_ms
        if not 0 < validity <= MAX_APPROVAL_VALIDITY_MS:
            raise WireError("approval validity must be > 0 and <= 7 days")

    def to_bytes(self) -> bytes:
        """Compact JSON in the contract's key order."""
        return dumps_compact(
            {
                "format": APPROVAL_FORMAT,
                "approval_id": self.approval_id,
                "workspace": self.workspace,
                "robot_id": self.robot_id,
                "platform": self.platform,
                "profile_digest": self.profile_digest,
                "profile_version": self.profile_version,
                "transition": "enforce",
                "approved_by": list(self.approved_by),
                "issued_at_ms": self.issued_at_ms,
                "expires_at_ms": self.expires_at_ms,
            }
        )


def parse_approval(payload: bytes) -> Approval:
    """Strictly parse an approval payload (used to register published approvals).

    Raises:
        WireError: Any rule of §6.3 is broken.
    """
    fields: tuple[tuple[str, _FieldCheck], ...] = (
        ("format", _is_str),
        ("approval_id", _is_str),
        ("workspace", _is_str),
        ("robot_id", _is_str),
        ("platform", _is_str),
        ("profile_digest", _is_str),
        ("profile_version", _is_u64),
        ("transition", _is_str),
        ("approved_by", lambda v: isinstance(v, list) and all(_is_str(x) for x in v)),
        ("issued_at_ms", _is_u64),
        ("expires_at_ms", _is_u64),
    )
    obj = _typed(payload, fields, "profile approval")
    if obj["format"] != APPROVAL_FORMAT or obj["transition"] != "enforce":
        raise WireError("profile approval malformed")
    approval = Approval(
        approval_id=obj["approval_id"],
        workspace=obj["workspace"],
        robot_id=obj["robot_id"],
        platform=obj["platform"],
        profile_digest=obj["profile_digest"],
        profile_version=obj["profile_version"],
        approved_by=tuple(obj["approved_by"]),
        issued_at_ms=obj["issued_at_ms"],
        expires_at_ms=obj["expires_at_ms"],
    )
    approval.check()
    return approval


@dataclass(frozen=True, slots=True)
class RingInfo:
    """An update-ring document payload (§7): information only."""

    serial: int
    workspace: str
    robot_id: str
    ring: int
    target_version: str | None
    bundle_sha256: str | None
    min_version: str | None
    issued_at_ms: int
    expires_at_ms: int

    def check(self) -> None:
        """The field rules of §7.

        Raises:
            WireError: A field is malformed.
        """
        if not (
            0 < self.serial <= MAX_U64
            and is_ident(self.workspace)
            and is_label(self.robot_id)
            and 0 <= self.ring <= 2
            and (self.target_version is None or is_version(self.target_version))
            and (self.min_version is None or is_version(self.min_version))
            and (self.bundle_sha256 is None or is_lower_hex(self.bundle_sha256, 64))
            and self.expires_at_ms > self.issued_at_ms
        ):
            raise WireError("ring info malformed")

    def to_bytes(self) -> bytes:
        """Compact JSON in the contract's key order."""
        return dumps_compact(
            {
                "format": RING_FORMAT,
                "serial": self.serial,
                "workspace": self.workspace,
                "robot_id": self.robot_id,
                "ring": self.ring,
                "target_version": self.target_version,
                "bundle_sha256": self.bundle_sha256,
                "min_version": self.min_version,
                "issued_at_ms": self.issued_at_ms,
                "expires_at_ms": self.expires_at_ms,
            }
        )


def parse_ring(payload: bytes) -> RingInfo:
    """Strictly parse a ring payload (used to register published ring documents).

    Raises:
        WireError: Any rule of §7 is broken.
    """
    fields: tuple[tuple[str, _FieldCheck], ...] = (
        ("format", _is_str),
        ("serial", _is_u64),
        ("workspace", _is_str),
        ("robot_id", _is_str),
        ("ring", _is_u8),
        ("target_version", _is_opt_str),
        ("bundle_sha256", _is_opt_str),
        ("min_version", _is_opt_str),
        ("issued_at_ms", _is_u64),
        ("expires_at_ms", _is_u64),
    )
    obj = _typed(payload, fields, "ring info")
    if obj["format"] != RING_FORMAT:
        raise WireError("ring info malformed")
    ring = RingInfo(**{k: obj[k] for k in obj if k != "format"})
    ring.check()
    return ring


def offer_body(profile: bytes, sig: bytes, profile_version: int) -> bytes:
    """The profile offer (§6.2): an unsigned wrapper, compact JSON."""
    return dumps_compact(
        {
            "format": OFFER_FORMAT,
            "profile_version": profile_version,
            "digest": digest(profile),
            "profile": b64_encode(profile),
            "sig": b64_encode(sig),
        }
    )


@dataclass(frozen=True, slots=True)
class Offer:
    """A decoded profile offer."""

    profile_version: int
    digest: str
    profile: bytes
    sig: bytes


def parse_offer(body: bytes) -> Offer:
    """Strictly parse a profile offer (used to register published offers).

    Raises:
        WireError: Malformed, or ``digest`` is not the profile's digest.
    """
    fields: tuple[tuple[str, _FieldCheck], ...] = (
        ("format", _is_str),
        ("profile_version", _is_u64),
        ("digest", _is_str),
        ("profile", _is_str),
        ("sig", _is_str),
    )
    obj = _typed(body, fields, "profile offer")
    if (
        obj["format"] != OFFER_FORMAT
        or not is_digest(obj["digest"])
        or obj["profile_version"] == 0
    ):
        raise WireError("profile offer malformed")
    profile = b64_decode(obj["profile"])
    sig = b64_decode(obj["sig"])
    if profile is None or sig is None:
        raise WireError("profile offer: profile / sig are not base64url")
    if digest(profile) != obj["digest"]:
        raise WireError("offer.digest is not the digest of offer.profile")
    return Offer(
        profile_version=obj["profile_version"],
        digest=obj["digest"],
        profile=profile,
        sig=sig,
    )


# --- key files --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyFile:
    """A ``robodr-blackbox-key/v2`` Ed25519 key file (secret or public)."""

    key_id: str
    public_key: bytes
    seed: bytes | None


def parse_key_file(text: str) -> KeyFile:
    """Parse a ``robodr-blackbox-key/v2`` key file.

    Raises:
        WireError: Not such a file, or the key id / public half do not match.
    """
    obj = loads_strict(text.strip())
    if not isinstance(obj, dict):
        raise WireError("a key file is a JSON object")
    kind = obj.get("kind")
    keys = ["format", "kind", "algorithm", "key_id", "public_hex"]
    if kind == "secret":
        keys.append("secret_hex")
    obj = _exact_object(obj, keys, "key file")
    if obj["format"] != "robodr-blackbox-key/v2" or obj["algorithm"] != "ed25519":
        raise WireError("not a robodr-blackbox-key/v2 Ed25519 key file")
    if kind not in ("secret", "public"):
        raise WireError("key file kind must be secret or public")
    if not all(isinstance(obj[k], str) for k in keys):
        raise WireError("key file members must be strings")
    if not is_lower_hex(obj["public_hex"], PUBLIC_KEY_LEN * 2):
        raise WireError("public_hex must be 64 lower-case hex digits")
    public_fpr = fingerprint(bytes.fromhex(obj["public_hex"]))
    public = check_public(obj["public_hex"], obj["key_id"], public_fpr)
    seed: bytes | None = None
    if kind == "secret":
        if not is_lower_hex(obj["secret_hex"], 64):
            raise WireError("secret_hex must be 64 lower-case hex digits")
        seed = bytes.fromhex(obj["secret_hex"])
        if SigningKey.from_seed(seed).public_key != public:
            raise WireError("secret_hex does not match public_hex")
    return KeyFile(key_id=obj["key_id"], public_key=public, seed=seed)


def public_key_file(public_key: bytes) -> str:
    """The ``robodr-blackbox-key/v2`` public file of a key (what robots install)."""
    return (
        dumps_compact(
            {
                "format": "robodr-blackbox-key/v2",
                "kind": "public",
                "algorithm": "ed25519",
                "key_id": derive_key_id(public_key),
                "public_hex": public_key.hex(),
            }
        ).decode("ascii")
        + "\n"
    )
