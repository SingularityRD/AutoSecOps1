"""VCS provider exceptions."""

from autosecops.exceptions import TracecatException


class VcsProviderError(TracecatException):
    """User-facing VCS provider operation error."""
