"""The repository gitleaks config must keep the built-in detection rules."""

import tomllib
from pathlib import Path

GITLEAKS_CONFIG = Path(__file__).resolve().parents[2] / ".gitleaks.toml"


def test_gitleaks_config_extends_default_rules() -> None:
    # A config without [extend] replaces the default rules, so the pre-commit
    # hook would scan with no rules and never report a secret.
    config = tomllib.loads(GITLEAKS_CONFIG.read_text())
    assert config.get("extend", {}).get("useDefault") is True
