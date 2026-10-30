from enum import StrEnum


class AuditEventActor(StrEnum):
    """Valid actor types for audit logging."""

    USER = "USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    SCIM = "SCIM"
    ROBOT = "ROBOT"
    """An unauthenticated or key-authenticated RoboDR sender (robot or relay)."""
    WORKFLOW = "WORKFLOW"
    """A workflow run acting through the executor (``actor_id``: the workflow).

    Used whether or not a person started the run; the person, when there is
    one, is named in the event data as ``initiated_by_user_id``.
    """
    AGENT = "AGENT"
    """An agent session acting through the executor (``actor_id``: the session)."""


class AuditEventStatus(StrEnum):
    """Valid status values for audit events."""

    ATTEMPT = "ATTEMPT"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
