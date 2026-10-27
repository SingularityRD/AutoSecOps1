"""Defaults of the Splunk HEC template land in customer Splunk data."""

from pathlib import Path

from autosecops.registry.actions.schemas import TemplateAction

HEC_TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "packages"
    / "autosecops-registry"
    / "autosecops_registry"
    / "templates"
    / "tools"
    / "splunk"
    / "hec"
    / "submit_hec_event.yml"
)


def test_submit_hec_event_defaults_name_autosecops() -> None:
    expects = TemplateAction.from_yaml(HEC_TEMPLATE).definition.expects
    defaults = {name: field.default for name, field in expects.items()}

    assert defaults["host"] == "autosecops"
    assert defaults["source"] == "autosecops_workflow"
    assert defaults["sourcetype"] == "autosecops_log"
