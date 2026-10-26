"""AutoSecOps SDK for registry actions.

This SDK provides HTTP clients for accessing AutoSecOps platform features
from within UDF actions running in sandboxed environments.
"""

from autosecops_registry.sdk.cases import CasesClient
from autosecops_registry.sdk.client import TracecatClient
from autosecops_registry.sdk.tables import TablesClient

from autosecops_registry.sdk.exceptions import (
    TracecatAPIError,
    TracecatAuthError,
    TracecatConflictError,
    TracecatNotFoundError,
    TracecatSDKError,
    TracecatValidationError,
)
from autosecops_registry.sdk.types import (
    UNSET,
    CasePriority,
    CaseSeverity,
    CaseStatus,
    SqlType,
    Unset,
    is_set,
)

__all__ = [
    # Main client
    "TracecatClient",
    # Sub-clients
    "CasesClient",
    "TablesClient",
    # Exceptions
    "TracecatAPIError",
    "TracecatAuthError",
    "TracecatConflictError",
    "TracecatNotFoundError",
    "TracecatSDKError",
    "TracecatValidationError",
    # Sentinel types and helpers
    "UNSET",
    "Unset",
    "is_set",
    # Case types
    "CasePriority",
    "CaseSeverity",
    "CaseStatus",
    # Table types
    "SqlType",
]
