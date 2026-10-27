from typing import Any


class AutoSecOpsException(Exception):
    """AutoSecOps generic user-facing exception."""

    def __init__(self, *args, detail: Any | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.detail = detail


class RegistryActionError(AutoSecOpsException):
    """Exception raised when a registry UDF error occurs."""


class SecretNotFoundError(AutoSecOpsException):
    """Exception raised when a required secret is not set."""


class ActionIsInterfaceError(RegistryActionError):
    """Exception raised when attempting to directly call an action that only defines an interface."""

    def __init__(self):
        super().__init__(
            "This UDF only defines an interface and cannot be invoked directly. "
            "If you are seeing this error, please contact your administrator."
        )


class AutoSecOpsExpressionError(AutoSecOpsException):
    """Exception raised when an expression evaluation fails."""
