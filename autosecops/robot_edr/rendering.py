"""Case inputs for RoboDR findings: one rendering scheme with the registry.

The case summary, description, custom-field values and ``payload.robodr``
come from ``tools.robodr.finding_to_case_fields``
(``autosecops_registry.integrations.robodr``), the same mapping workflows use,
so a case reads the same whether ingest or a workflow created it. Under that
scheme every adversary-controlled value (the finding's
``adversary_controlled_fields``) reaches case text only through
``render_untrusted``: an allow-listed character set (everything else becomes
``?``) inside an inline code span that cannot be closed early, under a label
that marks it untrusted data. Nothing adversary-controlled is ever rendered as
Markdown, a link, or HTML.

Severity and priority come from the OCSF ``severity_id`` (contract §5); the
registry's own mapping agrees for the ids RoboDR emits.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

from autosecops_registry.integrations.robodr import (
    FindingError,
    finding_to_case_fields,
)

from autosecops.cases.enums import CasePriority, CaseSeverity

ROBODR_CASE_TAG: Final = "robodr"
SUMMARY_MAX: Final = 255
DESCRIPTION_MAX: Final = 5000
_TRUNCATION_NOTE: Final = "\n\n(Description truncated; see the case payload.)"

OCSF_SEVERITY_TO_CASE: Final[dict[int, CaseSeverity]] = {
    0: CaseSeverity.UNKNOWN,
    1: CaseSeverity.INFORMATIONAL,
    2: CaseSeverity.LOW,
    3: CaseSeverity.MEDIUM,
    4: CaseSeverity.HIGH,
    5: CaseSeverity.CRITICAL,
    6: CaseSeverity.FATAL,
    99: CaseSeverity.OTHER,
}
SEVERITY_TO_PRIORITY: Final[dict[CaseSeverity, CasePriority]] = {
    CaseSeverity.UNKNOWN: CasePriority.UNKNOWN,
    CaseSeverity.INFORMATIONAL: CasePriority.LOW,
    CaseSeverity.LOW: CasePriority.LOW,
    CaseSeverity.MEDIUM: CasePriority.MEDIUM,
    CaseSeverity.HIGH: CasePriority.HIGH,
    CaseSeverity.CRITICAL: CasePriority.CRITICAL,
    CaseSeverity.FATAL: CasePriority.CRITICAL,
    CaseSeverity.OTHER: CasePriority.OTHER,
}
SEVERITY_RANK: Final[dict[CaseSeverity, int]] = {
    CaseSeverity.OTHER: 0,
    CaseSeverity.UNKNOWN: 0,
    CaseSeverity.INFORMATIONAL: 1,
    CaseSeverity.LOW: 2,
    CaseSeverity.MEDIUM: 3,
    CaseSeverity.HIGH: 4,
    CaseSeverity.CRITICAL: 5,
    CaseSeverity.FATAL: 6,
}

# Custom case fields RoboDR findings populate: name -> SQL type.
ROBOT_CASE_FIELDS: Final[dict[str, str]] = {
    "robot_id": "TEXT",
    "site": "TEXT",
    "rule_id": "TEXT",
    "mitre_ics": "TEXT",
    "profile_mode": "TEXT",
    "safety_state": "TEXT",
    "external_id": "TEXT",
    "data_source": "TEXT",
    "contract_version": "TEXT",
    "occurrence_count": "INTEGER",
}


class CaseRenderError(Exception):
    """The registry mapping refused a value the ingest validator accepted."""


@dataclass(frozen=True, slots=True)
class CaseInputs:
    """Everything a RoboDR case is created or updated from."""

    summary: str
    description: str
    fields: dict[str, Any]
    payload: dict[str, Any]


def case_severity(severity_id: int) -> CaseSeverity:
    """Map an OCSF ``severity_id`` (0-6, 99) one-to-one onto a case severity."""
    return OCSF_SEVERITY_TO_CASE.get(severity_id, CaseSeverity.OTHER)


def _fit_description(description: str) -> str:
    """Cut at a line boundary so no code span is left open."""
    if len(description) <= DESCRIPTION_MAX:
        return description
    budget = DESCRIPTION_MAX - len(_TRUNCATION_NOTE)
    cut = description.rfind("\n", 0, budget)
    return description[: cut if cut > 0 else 0] + _TRUNCATION_NOTE


def _canonical_version(version: str) -> str:
    """``02.1.0`` -> ``2.1.0``: each part of a well-formed version as a number."""
    return ".".join(str(int(part)) for part in version.split("."))


def _with_canonical_version(value: str, version: str) -> str:
    """The value with its ``contract_version`` spelled canonically.

    The ingest validator follows the Rust rule (leading zeros allowed in a
    version part, ``02.1.0`` is contract 2.1.0); the registry mapping still
    requires the canonical spelling, so it renders from this copy. Only the
    version changes; the mapping reads parsed fields, never the raw bytes.
    """
    document = json.loads(value)
    document["contract_version"] = _canonical_version(version)
    return json.dumps(document, ensure_ascii=False, separators=(",", ":"))


def case_inputs(value: str, *, contract_version: str | None = None) -> CaseInputs:
    """Build case inputs from a validated record value.

    Args:
        value: The record value exactly as received (already validated).
        contract_version: The value's validated ``contract_version``; a
            version spelled with leading zeros is shown as received.

    Raises:
        CaseRenderError: The registry mapping refused the value.
    """
    rendered = value
    if (
        contract_version is not None
        and _canonical_version(contract_version) != contract_version
    ):
        rendered = _with_canonical_version(value, contract_version)
    try:
        mapped = finding_to_case_fields(rendered)
    except (FindingError, ValueError, KeyError, TypeError) as exc:
        raise CaseRenderError(str(exc)[:200]) from exc
    if rendered is not value and contract_version is not None:
        _restore_version(mapped, contract_version)
    return CaseInputs(
        summary=str(mapped["summary"])[:SUMMARY_MAX],
        description=_fit_description(str(mapped["description"])),
        fields=dict(mapped["fields"]),
        payload=dict(mapped["payload"]),
    )


def _restore_version(mapped: dict[str, Any], version: str) -> None:
    """Show the version as received where the mapping copies it."""
    match mapped:
        case {"fields": {"contract_version": _} as fields}:
            fields["contract_version"] = version
        case _:
            pass
    match mapped:
        case {"payload": {"robodr": {"contract_version": _} as robodr}}:
            robodr["contract_version"] = version
        case _:
            pass
