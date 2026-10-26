"""Embedded public key that verifies license signatures.

The key below is a DEVELOPMENT key. Its private half lives outside this
repository and must never ship. Before a release, SingularityRD must generate
its own production keypair on an offline machine, keep the private key offline,
and replace ``LICENSE_PUBLIC_KEY_PEM`` with the new public key:

    openssl genpkey -algorithm ed25519 -out license-private.pem
    openssl pkey -in license-private.pem -pubout

Rotating this key invalidates every license signed with the old private key.

The public key is deliberately not configurable through environment variables:
an operator who could swap it could sign their own licenses. Tests override it
by passing ``public_key`` to ``autosecops.licensing.service.evaluate_license`` or
by patching this module attribute.
"""

from __future__ import annotations

LICENSE_PUBLIC_KEY_PEM: bytes = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9SNn3/ISCoRcLmzTqRyi37LOYO/boUAld+8JlK0mjyo=
-----END PUBLIC KEY-----
"""
"""PEM-encoded Ed25519 public key (SubjectPublicKeyInfo) that verifies licenses."""
