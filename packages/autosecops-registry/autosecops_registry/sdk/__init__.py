"""AutoSecOps SDK for registry actions.

This SDK provides HTTP clients for accessing AutoSecOps platform features
from within UDF actions running in sandboxed environments.
"""

from autosecops_registry.sdk.cases import CasesClient
from autosecops_registry.sdk.client import AutoSecOpsClient
from autosecops_registry.sdk.tables import TablesClient

from autosecops_registry.sdk.exceptions import (
    AutoSecOpsAPIError,
    AutoSecOpsAuthError,
    AutoSecOpsConflictError,
    AutoSecOpsNotFoundError,
    AutoSecOpsSDKError,
    AutoSecOpsValidationError,
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
    "AutoSecOpsClient",
    # Sub-clients
    "CasesClient",
    "TablesClient",
    # Exceptions
    "AutoSecOpsAPIError",
    "AutoSecOpsAuthError",
    "AutoSecOpsConflictError",
    "AutoSecOpsNotFoundError",
    "AutoSecOpsSDKError",
    "AutoSecOpsValidationError",
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
