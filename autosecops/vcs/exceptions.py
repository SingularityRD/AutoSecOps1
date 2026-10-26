"""VCS provider exceptions."""

from autosecops.exceptions import AutoSecOpsException


class VcsProviderError(AutoSecOpsException):
    """User-facing VCS provider operation error."""
