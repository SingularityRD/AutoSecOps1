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


class AuditWriteResult(StrEnum):
    """What became of one audit event write."""

    WRITTEN = "written"
    """The configured sink accepted the event (2xx). Strict writes only."""
    QUEUED = "queued"
    """Handed to background delivery; the sink has not confirmed it yet."""
    NO_SINK = "no_sink"
    """No audit sink is configured, so the event exists only in the app log."""
    FAILED = "failed"
    """Not written (best-effort writes only; a strict write raises instead)."""
