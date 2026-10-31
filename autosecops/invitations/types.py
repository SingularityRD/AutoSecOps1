"""Domain types for invitations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IssuedInvitationToken:
    """A freshly generated invitation token and its stored forms.

    Attributes:
        raw: The value placed in the invitation link. Never persisted.
        digest: ``hash_bearer_token(raw)``, stored in ``invitation.token``.
        ciphertext: ``raw`` encrypted with the database encryption key, stored
            in ``invitation.encrypted_token``.
    """

    raw: str
    digest: str
    ciphertext: bytes
