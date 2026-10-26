"""Microsoft Graph OAuth providers."""

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
