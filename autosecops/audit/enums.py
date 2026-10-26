from enum import StrEnum


class AuditEventActor(StrEnum):
    """Valid actor types for audit logging."""

    USER = "USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    SCIM = "SCIM"
    ROBOT = "ROBOT"
    """An unauthenticated or key-authenticated RoboDR sender (robot or relay)."""


class AuditEventStatus(StrEnum):
    """Valid status values for audit events."""

    ATTEMPT = "ATTEMPT"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
