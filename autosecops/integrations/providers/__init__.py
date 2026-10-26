from typing import Final

from autosecops.integrations.providers.base import BaseOAuthProvider
from autosecops.integrations.providers.databricks import (
    DatabricksACProvider,
    DatabricksCCProvider,
)
from autosecops.integrations.providers.github.app import (
    GitHubAppInstallationProvider,
    GitHubAppUserProvider,
)
from autosecops.integrations.providers.github.mcp import GitHubMCPProvider
from autosecops.integrations.providers.github.oauth import GitHubOAuthProvider
from autosecops.integrations.providers.google import (
    GoogleAdminACProvider,
    GoogleAdminCCProvider,
    GoogleChronicleACProvider,
    GoogleChronicleCCProvider,
    GoogleCloudLoggingACProvider,
    GoogleCloudLoggingCCProvider,
    GoogleDocsACProvider,
    GoogleDocsCCProvider,
    GoogleDriveACProvider,
    GoogleDriveCCProvider,
    GoogleFormsACProvider,
    GoogleFormsCCProvider,
    GoogleGmailACProvider,
    GoogleGmailCCProvider,
    GoogleServiceAccountOAuthProvider,
    GoogleSheetsACProvider,
    GoogleSheetsCCProvider,
    GoogleSlidesACProvider,
    GoogleSlidesCCProvider,
)
from autosecops.integrations.providers.jamf.oauth import JamfOAuthProvider
from autosecops.integrations.providers.jira.mcp import JiraMCPProvider
from autosecops.integrations.providers.linear.mcp import LinearMCPProvider
from autosecops.integrations.providers.microsoft import (
    AzureDevOpsACProvider,
    AzureDevOpsCCProvider,
    AzureLogAnalyticsACProvider,
    AzureLogAnalyticsCCProvider,
    AzureManagementACProvider,
    AzureManagementCCProvider,
    MicrosoftDefenderEndpointACProvider,
    MicrosoftDefenderEndpointCCProvider,
    MicrosoftDefenderXDRACProvider,
    MicrosoftDefenderXDRCCProvider,
    MicrosoftEntraACProvider,
    MicrosoftEntraCCProvider,
    MicrosoftGraphACProvider,
    MicrosoftGraphCCProvider,
    MicrosoftGraphSecurityACProvider,
    MicrosoftGraphSecurityCCProvider,
    MicrosoftOutlookACProvider,
    MicrosoftOutlookCCProvider,
    MicrosoftSentinelACProvider,
    MicrosoftSentinelCCProvider,
    MicrosoftTeamsACProvider,
    MicrosoftTeamsCCProvider,
)
from autosecops.integrations.providers.notion.mcp import NotionMCPProvider
from autosecops.integrations.providers.paloalto.oauth import PaloAltoSCMOAuthProvider
from autosecops.integrations.providers.perplexity.mcp import PerplexityMCPProvider
from autosecops.integrations.providers.proofpoint.oauth import (
    ProofpointThreatProtectionOAuthProvider,
)
from autosecops.integrations.providers.runreveal.mcp import RunRevealMCPProvider
from autosecops.integrations.providers.secureannex.mcp import SecureAnnexMCPProvider
from autosecops.integrations.providers.sentry.mcp import SentryMCPProvider
from autosecops.integrations.providers.servicenow.oauth import ServiceNowOAuthProvider
from autosecops.integrations.providers.slack.oauth import SlackOAuthProvider
from autosecops.integrations.providers.snowflake import (
    SnowflakeACProvider,
    SnowflakeCCProvider,
)
from autosecops.integrations.providers.wiz.mcp import WizMCPProvider
from autosecops.integrations.schemas import ProviderKey

_PROVIDER_CLASSES: list[type[BaseOAuthProvider]] = [
    GitHubOAuthProvider,
    GitHubAppInstallationProvider,
    GitHubAppUserProvider,
    GitHubMCPProvider,
    DatabricksACProvider,
    DatabricksCCProvider,
    GoogleAdminACProvider,
    GoogleAdminCCProvider,
    GoogleChronicleACProvider,
    GoogleChronicleCCProvider,
    GoogleCloudLoggingACProvider,
    GoogleCloudLoggingCCProvider,
    GoogleDocsACProvider,
    GoogleDocsCCProvider,
    GoogleDriveACProvider,
    GoogleDriveCCProvider,
    GoogleFormsACProvider,
    GoogleFormsCCProvider,
    GoogleGmailACProvider,
    GoogleGmailCCProvider,
    GoogleServiceAccountOAuthProvider,
    GoogleSheetsACProvider,
    GoogleSheetsCCProvider,
    GoogleSlidesACProvider,
    GoogleSlidesCCProvider,
    JamfOAuthProvider,
    PaloAltoSCMOAuthProvider,
    ProofpointThreatProtectionOAuthProvider,
    JiraMCPProvider,
    LinearMCPProvider,
    NotionMCPProvider,
    PerplexityMCPProvider,
    RunRevealMCPProvider,
    SecureAnnexMCPProvider,
    SentryMCPProvider,
    WizMCPProvider,
    AzureManagementACProvider,
    AzureManagementCCProvider,
    MicrosoftSentinelACProvider,
    MicrosoftSentinelCCProvider,
    AzureLogAnalyticsACProvider,
    AzureLogAnalyticsCCProvider,
    AzureDevOpsACProvider,
    AzureDevOpsCCProvider,
    MicrosoftDefenderEndpointACProvider,
    MicrosoftDefenderEndpointCCProvider,
    MicrosoftDefenderXDRACProvider,
    MicrosoftDefenderXDRCCProvider,
    MicrosoftEntraACProvider,
    MicrosoftEntraCCProvider,
    MicrosoftGraphACProvider,
    MicrosoftGraphCCProvider,
    MicrosoftGraphSecurityACProvider,
    MicrosoftGraphSecurityCCProvider,
    MicrosoftOutlookACProvider,
    MicrosoftOutlookCCProvider,
    MicrosoftTeamsACProvider,
    MicrosoftTeamsCCProvider,
    SlackOAuthProvider,
    SnowflakeACProvider,
    SnowflakeCCProvider,
    ServiceNowOAuthProvider,
]


def _build_provider_registry() -> dict[ProviderKey, type[BaseOAuthProvider]]:
    """Build provider registry with duplicate detection."""
    registry: dict[ProviderKey, type[BaseOAuthProvider]] = {}
    for cls in _PROVIDER_CLASSES:
        if not getattr(cls, "_include_in_registry", True):
            continue
        key = ProviderKey(id=cls.id, grant_type=cls.grant_type)
        if key in registry:
            raise ValueError(
                f"Duplicate provider key {key} for {cls.__name__} "
                f"(already registered by {registry[key].__name__})"
            )
        registry[key] = cls
    return registry


PROVIDER_REGISTRY: Final[dict[ProviderKey, type[BaseOAuthProvider]]] = (
    _build_provider_registry()
)


def get_provider_class(key: ProviderKey) -> type[BaseOAuthProvider] | None:
    """Return the provider class matching *key*, or ``None``."""
    return PROVIDER_REGISTRY.get(key)


def all_providers() -> list[type[BaseOAuthProvider]]:
    """Return all registered provider classes."""
    return list(PROVIDER_REGISTRY.values())
