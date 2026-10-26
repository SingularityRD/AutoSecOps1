"""Ed25519 verification, key ids, and signing-message framing for RoboDR.

Verification is strict, matching ``robodr_blackbox::sign_ed25519::verify``
(``ed25519-dalek`` ``verify_strict`` plus a canonical public-key check):

* the signature is exactly 64 bytes and ``S`` is canonical (``S < L``), which
  rules out ``S + L`` malleability;
* the public key ``A`` and the commitment ``R`` decode to curve points and are
  canonical encodings (``y < p``; ``x = 0`` with the sign bit set is refused);
* neither ``A`` nor ``R`` has small order (order dividing 8, identity included);
* the equation is the cofactorless ``[S]B = R + [k]A``.

The pre-checks run in pure Python (exact integer arithmetic on the Edwards
curve; no secret data is involved, so timing does not matter). The equation
itself is checked by OpenSSL through ``cryptography``, which also refuses a
non-canonical ``S`` and compares the encoding of the recomputed ``R`` with the
signature bytes, so a non-canonical ``R`` cannot verify either.
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64

KEY_ID_DOMAIN = b"robodr-blackbox/ed25519-key-id/v1\x00"
BATCH_SIG_DOMAIN = b"robodr-ingest/batch/v1\x00"
FINDING_SIG_DOMAIN = b"robodr-ocsf/finding-sig/v1\x00"
FINDING_SIG_ALG = "ed25519"

# Curve25519 in twisted Edwards form (RFC 8032 §5.1).
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

type _Point = tuple[int, int, int, int]


def derive_key_id(public_key: bytes) -> str:
    """Return the RoboDR key id of an Ed25519 public key.

    Identical to ``robodr_blackbox::sign_ed25519::derive_key_id``:
    ``"ed25519:"`` + the first 8 bytes of
    ``SHA-256("robodr-blackbox/ed25519-key-id/v1\\0" || public_key)`` in
    lower-case hex.

    Args:
        public_key: The 32-byte Ed25519 public key.

    Returns:
        The key id, ``ed25519:<16 lower-case hex>``.
    """
    if len(public_key) != PUBLIC_KEY_LEN:
        raise ValueError("Ed25519 public keys are 32 bytes")
    digest = hashlib.sha256(KEY_ID_DOMAIN + public_key).digest()
    return f"ed25519:{digest[:8].hex()}"


def batch_signing_message(
    *, key_id: str, batch_id: str, timestamp_ms: int, body: bytes
) -> bytes:
    """Return the `robodr.ingest` batch signing message (contract §2.2).

    ``"robodr-ingest/batch/v1" 0x00 || u32be(len(key_id)) || key_id ||
    u32be(len(batch_id)) || batch_id || u64be(timestamp_ms) || sha256(body)``.
    """
    key = key_id.encode("ascii")
    batch = batch_id.encode("ascii")
    return b"".join(
        (
            BATCH_SIG_DOMAIN,
            struct.pack(">I", len(key)),
            key,
            struct.pack(">I", len(batch)),
            batch,
            struct.pack(">Q", timestamp_ms),
            hashlib.sha256(body).digest(),
        )
    )


def finding_signing_message(*, alg: str, key_id: str, value: bytes) -> bytes:
    """Return the per-finding signing message (``robodr_ocsf::sig``).

    ``"robodr-ocsf/finding-sig/v1" 0x00 || u32be(len(alg)) || alg ||
    u32be(len(key_id)) || key_id || u64be(len(value)) || value``.
    """
    alg_bytes = alg.encode("ascii")
    key = key_id.encode("ascii")
    return b"".join(
        (
            FINDING_SIG_DOMAIN,
            struct.pack(">I", len(alg_bytes)),
            alg_bytes,
            struct.pack(">I", len(key)),
            key,
            struct.pack(">Q", len(value)),
            value,
        )
    )


def _decode_point(encoded: bytes) -> _Point | None:
    """Decode a point in extended coordinates, refusing non-canonical forms."""
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    y2 = y * y % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        return (0, y, 1, 0)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _double(point: _Point) -> _Point:
    x1, y1, z1, _ = point
    a = x1 * x1 % _P
    b = y1 * y1 % _P
    c = 2 * z1 * z1 % _P
    h = (a + b) % _P
    e = (h - (x1 + y1) * (x1 + y1)) % _P
    g = (a - b) % _P
    f = (c + g) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _has_small_order(point: _Point) -> bool:
    """Return whether ``[8]point`` is the identity."""
    for _ in range(3):
        point = _double(point)
    x, y, z, _ = point
    return x % _P == 0 and (y - z) % _P == 0


def is_strict_public_key(public_key: bytes) -> bool:
    """Return whether bytes are a canonical, large-order Ed25519 public key."""
    point = _decode_point(public_key)
    return point is not None and not _has_small_order(point)


def verify_strict(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature with ``verify_strict`` semantics.

    Never raises on malformed input; anything malformed yields ``False``.

    Args:
        public_key: 32-byte public key.
        message: The signed message.
        signature: 64-byte signature ``R || S``.

    Returns:
        Whether the signature is valid under the strict rules in the module
        docstring.
    """
    if len(public_key) != PUBLIC_KEY_LEN or len(signature) != SIGNATURE_LEN:
        return False
    if int.from_bytes(signature[32:], "little") >= _L:
        return False
    if not is_strict_public_key(public_key):
        return False
    r_point = _decode_point(signature[:32])
    if r_point is None or _has_small_order(r_point):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
