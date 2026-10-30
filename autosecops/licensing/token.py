"""Encode and verify signed license tokens.

A token is ``base64url(payload) + "." + base64url(signature)`` without padding,
where ``payload`` is the UTF-8 JSON of ``LicenseClaims`` and ``signature`` is
the Ed25519 signature over exactly those payload bytes.
"""

from __future__ import annotations

import base64
import binascii
import re

import orjson
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from pydantic import ValidationError

from autosecops.licensing.types import LicenseClaims, LicenseErrorCode

MAX_LICENSE_TOKEN_LENGTH = 16_384
"""Upper bound on token size so a garbled value never costs real work."""

_B64URL_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


class LicenseVerificationError(Exception):
    """A license token failed verification."""

    def __init__(self, code: LicenseErrorCode) -> None:
        super().__init__(f"License verification failed: {code.value}")
        self.code = code


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Strictly decode canonical unpadded base64url.

    Rejects non-alphabet characters and non-zero unused trailing bits, so each
    byte string has exactly one accepted encoding.
    """
    if not _B64URL_SEGMENT.fullmatch(data):
        raise ValueError("Not an unpadded base64url segment")
    padding = "=" * (-len(data) % 4)
    decoded = base64.b64decode(data + padding, altchars=b"-_", validate=True)
    if _b64url_encode(decoded) != data:
        raise ValueError("Not a canonical base64url segment")
    return decoded


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    """Load a PEM-encoded Ed25519 public key.

    Raises:
        ValueError: If the PEM is not an Ed25519 public key.
    """
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("License public key must be an Ed25519 key")
    return key


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    """Load a PEM-encoded, unencrypted Ed25519 private key.

    Raises:
        ValueError: If the PEM is not an Ed25519 private key.
    """
    key = load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("License private key must be an Ed25519 key")
    return key


def encode_license(claims: LicenseClaims, private_key: Ed25519PrivateKey) -> str:
    """Sign license claims and return the compact token."""
    # Unset optional claims are omitted so a license without them encodes
    # exactly as releases before those claims existed.
    payload = orjson.dumps(
        claims.model_dump(mode="json", exclude_none=True),
        option=orjson.OPT_SORT_KEYS,
    )
    signature = private_key.sign(payload)
    return f"{_b64url_encode(payload)}.{_b64url_encode(signature)}"


def decode_license(token: str, public_key: Ed25519PublicKey) -> LicenseClaims:
    """Verify a license token's signature and return its claims.

    The signature is checked before the payload is parsed.

    Raises:
        LicenseVerificationError: If the token is malformed, the signature does
            not verify, or the claims are invalid.
    """
    token = token.strip()
    if len(token) > MAX_LICENSE_TOKEN_LENGTH or token.count(".") != 1:
        raise LicenseVerificationError(LicenseErrorCode.MALFORMED)

    payload_part, signature_part = token.split(".")
    try:
        payload = _b64url_decode(payload_part)
        signature = _b64url_decode(signature_part)
    except (binascii.Error, ValueError) as exc:
        raise LicenseVerificationError(LicenseErrorCode.MALFORMED) from exc

    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise LicenseVerificationError(LicenseErrorCode.BAD_SIGNATURE) from exc

    try:
        return LicenseClaims.model_validate_json(payload)
    except ValidationError as exc:
        raise LicenseVerificationError(LicenseErrorCode.INVALID_CLAIMS) from exc
