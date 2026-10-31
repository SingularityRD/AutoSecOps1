DEFAULT_REGISTRY_ORIGIN = "autosecops_registry"
DEFAULT_REMOTE_REGISTRY_ORIGIN = "remote"
DEFAULT_LOCAL_REGISTRY_ORIGIN = "local"
REGISTRY_GIT_SSH_KEY_SECRET_NAME = "github-ssh-key"
"""Name of the SSH key secret for the registry."""


REGISTRY_REPOS_PATH: str = "/registry/repos"
"""Base path for repository-related endpoints"""

REGISTRY_ACTIONS_PATH: str = "/registry/actions"
"""Base path for action-related endpoints"""

PLATFORM_REGISTRY_NAMESPACE: str = "platform"
"""Storage namespace for platform-scoped registry artifacts (S3 prefix segment)."""

API_SIDE_CUSTOM_SYNC_REFUSED = (
    "Custom registry repositories sync only on the executor, so their code "
    "never runs in the API service. Set "
    "AUTOSECOPS__REGISTRY_SYNC_SANDBOX_ENABLED=true (the default) to sync this "
    "repository."
)
"""Error for a custom-origin sync that would run repository code in the API."""
