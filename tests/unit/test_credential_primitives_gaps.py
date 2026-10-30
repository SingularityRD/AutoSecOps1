"""Edge cases for API key hashing/parsing and Fernet secret encryption."""

from __future__ import annotations

import base64

import pytest
from cryptography.fernet import Fernet, InvalidToken

from autosecops.auth.api_keys import (
    ORG_API_KEY_PREFIX,
    WORKSPACE_API_KEY_PREFIX,
    generate_api_key,
    generate_managed_api_key,
    make_api_key_preview,
    parse_managed_api_key,
    verify_api_key,
)
from autosecops.secrets.encryption import (
    decrypt_value,
    encrypt_value,
    is_set,
)

# --- API keys ------------------------------------------------------------------


def test_preview_requires_the_expected_prefix_and_length() -> None:
    with pytest.raises(ValueError, match="prefix"):
        make_api_key_preview("other_abcdef", prefix="tc_sk_")
    with pytest.raises(ValueError, match="shorter"):
        make_api_key_preview("tc_sk_ab", prefix="tc_sk_")
    assert make_api_key_preview("tc_sk_abcdef", prefix="tc_sk_") == "tc_sk_...cdef"


@pytest.mark.parametrize(
    "kwargs",
    [{"key_id_length": 0}, {"secret_length": 0}, {"secret_length": -1}],
)
def test_managed_key_generation_rejects_non_positive_lengths(
    kwargs: dict[str, int],
) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        generate_managed_api_key(prefix=ORG_API_KEY_PREFIX, **kwargs)


def test_managed_key_round_trips_through_parse_and_verify() -> None:
    key = generate_managed_api_key(prefix=WORKSPACE_API_KEY_PREFIX)
    parsed = parse_managed_api_key(key.raw)

    assert parsed is not None
    assert (parsed.prefix, parsed.key_id) == (WORKSPACE_API_KEY_PREFIX, key.key_id)
    assert verify_api_key(key.raw, key.salt_b64, key.hashed)
    # The hash covers the whole raw key, not just the secret part.
    assert not verify_api_key(parsed.secret, key.salt_b64, key.hashed)


@pytest.mark.parametrize(
    "raw",
    [
        "tc_sk_plainkey",  # not a managed prefix
        f"{ORG_API_KEY_PREFIX}",  # nothing after the prefix
        f"{ORG_API_KEY_PREFIX}keyidonly",  # no separator
        f"{ORG_API_KEY_PREFIX}_secret",  # empty key id
        f"{ORG_API_KEY_PREFIX}keyid_",  # empty secret
    ],
)
def test_parse_managed_key_rejects_malformed_keys(raw: str) -> None:
    assert parse_managed_api_key(raw) is None


def test_parse_managed_key_respects_the_allowed_prefixes() -> None:
    key = generate_managed_api_key(prefix=ORG_API_KEY_PREFIX)
    assert parse_managed_api_key(key.raw, prefixes=(WORKSPACE_API_KEY_PREFIX,)) is None


def test_verify_rejects_empty_inputs_and_wrong_salt() -> None:
    key = generate_api_key()
    assert not verify_api_key("", key.salt_b64, key.hashed)
    assert not verify_api_key(key.raw, "", key.hashed)
    assert not verify_api_key(key.raw, key.salt_b64, "")
    other_salt = base64.b64encode(b"\x00" * 16).decode()
    assert not verify_api_key(key.raw, other_salt, key.hashed)
    assert not verify_api_key(key.raw + "x", key.salt_b64, key.hashed)


# --- Fernet encryption ---------------------------------------------------------


def test_encrypt_value_with_invalid_key_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Encryption failed"):
        encrypt_value(b"secret", key="not-a-fernet-key")


def test_decrypt_value_distinguishes_wrong_key_from_invalid_key() -> None:
    key = Fernet.generate_key().decode()
    ciphertext = encrypt_value(b"secret", key=key)
    assert decrypt_value(ciphertext, key=key) == b"secret"

    with pytest.raises(InvalidToken):
        decrypt_value(ciphertext, key=Fernet.generate_key().decode())
    with pytest.raises(InvalidToken):
        decrypt_value(ciphertext[:-4] + b"AAAA", key=key)
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_value(ciphertext, key="not-a-fernet-key")


def test_is_set_reflects_empty_ciphertext() -> None:
    assert is_set(b"x")
    assert not is_set(b"")
