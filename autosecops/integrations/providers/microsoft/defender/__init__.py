"""Microsoft Defender OAuth providers."""

from autosecops.integrations.providers.microsoft.defender.endpoint import (
    MicrosoftDefenderEndpointACProvider,
    MicrosoftDefenderEndpointCCProvider,
)
from autosecops.integrations.providers.microsoft.defender.xdr import (
    MicrosoftDefenderXDRACProvider,
    MicrosoftDefenderXDRCCProvider,
)

__all__ = [
    "MicrosoftDefenderEndpointACProvider",
    "MicrosoftDefenderEndpointCCProvider",
    "MicrosoftDefenderXDRACProvider",
    "MicrosoftDefenderXDRCCProvider",
]
