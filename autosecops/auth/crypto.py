import base64
import hashlib
import secrets

from autosecops import base62


def generate_token(prefix: str = "", length: int = 32) -> str:
    """Generate a secure token with an optional prefix.

    Args:
        prefix: String prefix for the token (e.g., "sk_", "api_")
        length: Number of random bytes to generate (default 32 bytes = 256 bits)

    Returns:
        Token string with the prefix and base62-encoded random data
    """
    # Generate cryptographically secure random bytes
    num = secrets.randbits(length * 8)
    base62_encoded = base62.b62encode(num)
    return f"{prefix}{base62_encoded}"


def hash_bearer_token(token: str) -> str:
    """Return the at-rest digest of a high-entropy bearer token.

    Session cookies and invitation links carry a random token; the database
    stores only this digest, so read access to the database (a backup, a
    replica, a DBA account, or SQL injection) does not yield a usable
    credential.

    An unsalted, fast hash is sufficient because the inputs are uniformly
    random with at least 256 bits of entropy, which rules out dictionary and
    brute-force attacks. Lookups compare digests through a unique B-tree index;
    the digest of an attacker-chosen guess reveals nothing about stored
    tokens, so a constant-time comparison adds no protection there.

    Args:
        token: The raw token presented by the client.

    Returns:
        Unpadded URL-safe base64 of the SHA-256 digest, always 43 characters,
        which fits the ``access_token.token`` primary key column.
    """
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
