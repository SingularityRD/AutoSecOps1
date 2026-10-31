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
