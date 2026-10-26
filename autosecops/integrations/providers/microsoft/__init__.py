from autosecops.integrations.providers.microsoft.azure.devops import (
    AzureDevOpsACProvider,
    AzureDevOpsCCProvider,
)
from autosecops.integrations.providers.microsoft.azure.loganalytics import (
    AzureLogAnalyticsACProvider,
    AzureLogAnalyticsCCProvider,
)
from autosecops.integrations.providers.microsoft.azure.provider import (
    AzureManagementACProvider,
    AzureManagementCCProvider,
)
from autosecops.integrations.providers.microsoft.azure.sentinel import (
    MicrosoftSentinelACProvider,
    MicrosoftSentinelCCProvider,
)
from autosecops.integrations.providers.microsoft.defender.endpoint import (
    MicrosoftDefenderEndpointACProvider,
    MicrosoftDefenderEndpointCCProvider,
)
from autosecops.integrations.providers.microsoft.defender.xdr import (
    MicrosoftDefenderXDRACProvider,
    MicrosoftDefenderXDRCCProvider,
)
from autosecops.integrations.providers.microsoft.graph.entra import (
    MicrosoftEntraACProvider,
    MicrosoftEntraCCProvider,
)
from autosecops.integrations.providers.microsoft.graph.outlook import (
    MicrosoftOutlookACProvider,
    MicrosoftOutlookCCProvider,
)
from autosecops.integrations.providers.microsoft.graph.provider import (
    MicrosoftGraphACProvider,
    MicrosoftGraphCCProvider,
)
from autosecops.integrations.providers.microsoft.graph.security import (
    MicrosoftGraphSecurityACProvider,
    MicrosoftGraphSecurityCCProvider,
)
from autosecops.integrations.providers.microsoft.graph.teams import (
    MicrosoftTeamsACProvider,
    MicrosoftTeamsCCProvider,
)

__all__ = [
    "AzureManagementACProvider",
    "AzureManagementCCProvider",
    "MicrosoftSentinelACProvider",
    "MicrosoftSentinelCCProvider",
    "AzureLogAnalyticsACProvider",
    "AzureLogAnalyticsCCProvider",
    "AzureDevOpsACProvider",
    "AzureDevOpsCCProvider",
    "MicrosoftDefenderEndpointACProvider",
    "MicrosoftDefenderEndpointCCProvider",
    "MicrosoftDefenderXDRACProvider",
    "MicrosoftDefenderXDRCCProvider",
    "MicrosoftEntraACProvider",
    "MicrosoftEntraCCProvider",
    "MicrosoftGraphACProvider",
    "MicrosoftGraphCCProvider",
    "MicrosoftGraphSecurityACProvider",
    "MicrosoftGraphSecurityCCProvider",
    "MicrosoftOutlookACProvider",
    "MicrosoftOutlookCCProvider",
    "MicrosoftTeamsACProvider",
    "MicrosoftTeamsCCProvider",
]
