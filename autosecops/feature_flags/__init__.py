from autosecops import config
from autosecops.feature_flags.enums import FeatureFlag

type FlagLike = FeatureFlag | str


def is_feature_enabled(flag: FlagLike) -> bool:
    """Check if a feature flag is enabled."""
    return flag in config.AUTOSECOPS__FEATURE_FLAGS


__all__ = ["is_feature_enabled", "FeatureFlag"]
