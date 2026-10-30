"""Pull diagnostics for rejected resource files must not echo their content."""

from __future__ import annotations

import json

from autosecops.sync import PullDiagnostic
from autosecops.workspace_sync.resources import _parse_yaml_resource
from autosecops.workspace_sync.schemas import (
    SecretMetadataResourceSpec,
    VariableResourceSpec,
)

SYNTHETIC_VALUE = "synthetic-leaked-value-7f3a"


def _diagnostic_text(diagnostic: PullDiagnostic) -> str:
    return diagnostic.message + json.dumps(diagnostic.details, default=str)


def test_secret_file_with_value_is_rejected_without_echoing_value() -> None:
    destination: dict[str, SecretMetadataResourceSpec] = {}
    diagnostics: list[PullDiagnostic] = []
    _parse_yaml_resource(
        "secret_metadata/default/leaky.yml",
        "version: 1\n"
        "type: secret_metadata\n"
        "id: default/leaky\n"
        "name: leaky\n"
        "environment: default\n"
        "secret_type: custom\n"
        "keys:\n- API_KEY\n"
        f"value: {SYNTHETIC_VALUE}\n",
        expected_source_id="default/leaky",
        model=SecretMetadataResourceSpec,
        destination=destination,
        diagnostics=diagnostics,
    )

    assert destination == {}
    [diagnostic] = diagnostics
    assert diagnostic.error_type == "validation"
    assert "not allowed in Git" in diagnostic.message
    assert SYNTHETIC_VALUE not in _diagnostic_text(diagnostic)


def test_variable_file_with_values_is_rejected_without_echoing_values() -> None:
    destination: dict[str, VariableResourceSpec] = {}
    diagnostics: list[PullDiagnostic] = []
    _parse_yaml_resource(
        "variables/default/region.yml",
        "version: 1\n"
        "type: variable\n"
        "id: default/region\n"
        "name: region\n"
        "environment: default\n"
        "keys:\n- region\n"
        f"values:\n  region: {SYNTHETIC_VALUE}\n",
        expected_source_id="default/region",
        model=VariableResourceSpec,
        destination=destination,
        diagnostics=diagnostics,
    )

    assert destination == {}
    [diagnostic] = diagnostics
    assert diagnostic.error_type == "validation"
    assert SYNTHETIC_VALUE not in _diagnostic_text(diagnostic)
