from enum import StrEnum


class AuthType(StrEnum):
    BASIC = "basic"
    OIDC = "oidc"
    SAML = "saml"


class SpecialUserID(StrEnum):
    """A sentinel user ID that represents the current user."""

    CURRENT = "current"


class AuthErrorCode(StrEnum):
    """Machine-readable codes for login failures surfaced to the sign-in UI."""

    SAML_ENFORCED = "saml_enforced"
    SELF_REGISTRATION_UNAVAILABLE = "self_registration_unavailable"
    """Self-registration needs email verification, and SMTP is not configured."""


class EmailVerificationMethod(StrEnum):
    """How an account's email came to be marked verified.

    Stored on ``user.email_verified_via``. ``NULL`` there means the account was
    created verified by an identity provider, SCIM or an administrator, or
    existed before verification shipped.
    """

    EMAIL = "email"
    """The account holder opened the emailed link and set the password."""
    INVITATION = "invitation"
    """Registered through an invitation link. The inviting organization can
    read the link, so this proves no mailbox control: an identity provider
    that later resolves to the account adopts it like an unverified one."""
    BOOTSTRAP = "bootstrap"
    """The first account, at the operator-configured superadmin email."""
    ADMIN = "admin"
    """A platform superuser vouched for the address."""
    OIDC = "oidc"
    SAML = "saml"
    SCIM = "scim"
