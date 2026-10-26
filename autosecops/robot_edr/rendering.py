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


def case_inputs(value: str) -> CaseInputs:
    """Build case inputs from a validated record value.

    Args:
        value: The record value exactly as received (already validated).

    Raises:
        CaseRenderError: The registry mapping refused the value.
    """
    try:
        mapped = finding_to_case_fields(value)
    except (FindingError, ValueError, KeyError, TypeError) as exc:
        raise CaseRenderError(str(exc)[:200]) from exc
    return CaseInputs(
        summary=str(mapped["summary"])[:SUMMARY_MAX],
        description=_fit_description(str(mapped["description"])),
        fields=dict(mapped["fields"]),
        payload=dict(mapped["payload"]),
    )
