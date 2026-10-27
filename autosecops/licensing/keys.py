"""Embedded public key that verifies license signatures.

The key below is a DEVELOPMENT key. Its private half lives outside this
repository and must never ship. Before a release, SingularityRD must generate
its own production keypair on an offline machine, keep the private key offline,
and replace ``LICENSE_PUBLIC_KEY_PEM`` with the new public key:

    uv run python scripts/license_tool.py keygen --out-dir <offline-dir>

Rotating this key invalidates every license signed with the old private key.
Release workflows run ``scripts/check_license_public_key.py``, which fails
while ``LICENSE_PUBLIC_KEY_PEM`` is still the development key, and the API
logs an error at startup when it verifies licenses with the development key.

The public key is deliberately not configurable through environment variables:
an operator who could swap it could sign their own licenses. Tests override it
by passing ``public_key`` to ``autosecops.licensing.evaluation.evaluate_license``
or by patching this module attribute.

This module must stay importable without third-party packages: the release
check reads it with only the Python standard library.
"""

from __future__ import annotations

import base64
import hashlib

LICENSE_PUBLIC_KEY_PEM: bytes = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9SNn3/ISCoRcLmzTqRyi37LOYO/boUAld+8JlK0mjyo=
-----END PUBLIC KEY-----
"""
"""PEM-encoded Ed25519 public key (SubjectPublicKeyInfo) that verifies licenses."""

DEVELOPMENT_PUBLIC_KEY_SHA256 = (
    "1370b8340d949beb40c7f5129fb0f3c6f791446e2521595b601d913adeaf9afc"
)
"""SHA-256 of the development public key's DER encoding.

Keep this value after replacing ``LICENSE_PUBLIC_KEY_PEM``: it is how release
checks and startup logs recognize a build that still trusts the development
key.
"""


def public_key_fingerprint(pem: bytes) -> str:
    """Return the SHA-256 hex digest of a single-key PEM's DER body."""
    body = b"".join(
        line.strip()
        for line in pem.strip().splitlines()
        if line.strip() and not line.startswith(b"-----")
    )
    return hashlib.sha256(base64.b64decode(body, validate=True)).hexdigest()


def is_development_public_key(pem: bytes) -> bool:
    """Whether ``pem`` is the development license public key."""
    return public_key_fingerprint(pem) == DEVELOPMENT_PUBLIC_KEY_SHA256
