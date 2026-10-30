"""Model-facing context for RoboDR cases.

A RoboDR case (``payload.robodr``) carries adversary-controlled values: topic
and node names, participant GUIDs, addresses, and detail strings that anyone
on the robot network can choose. This module builds the case context an
agent sees so that every such value, and every value that fails a strict
check, reaches the model only inside a ``render_untrusted`` block
(``[untrusted-data ...]`` ... ``[/untrusted-data]``). Only values that pass a
catalog lookup or a fixed pattern appear outside a block.

The case summary and description are always rendered as untrusted data:
analysts and workflows can edit them, and RoboDR's own description quotes
untrusted values in code spans.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from autosecops_registry.integrations.robodr import (
    UNTRUSTED_PROMPT_RULES,
    render_untrusted,
)
from autosecops_registry.integrations.robodr_catalog import catalog_entry

ROBODR_PAYLOAD_KEY: Final = "robodr"
MAX_UNTRUSTED_VALUES: Final = 64
"""Untrusted entries rendered per case; the findings contract caps fewer."""
MAX_EVIDENCE_LINKS: Final = 64
VALUE_MAX_LENGTH: Final = 400
"""Characters kept per untrusted value (the contract's longest field)."""
TEXT_MAX_LENGTH: Final = 4096
"""Characters kept of the case summary or description."""

_ROBOT_ID_RE: Final = re.compile(r"[A-Za-z0-9._-]{1,64}")
_FINDING_ID_RE: Final = re.compile(r"rf1-[0-9a-f]{32}")
_DATA_SOURCE_RE: Final = re.compile(r"[a-z0-9._-]{1,64}")
_VERSION_RE: Final = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
_TECHNIQUE_RE: Final = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
_EVIDENCE_RE: Final = re.compile(
    r"robodr-blackbox://[A-Za-z0-9._-]{1,64}/[0-9]{1,12}/[0-9]{1,20}"
    r"\?sha256=[0-9a-f]{64}"
)
_SEVERITIES: Final = frozenset({"low", "medium", "high", "critical"})
_COUNT_FIELDS: Final = (
    "severity_id",
    "occurrence_count",
    "first_seen_ms",
    "last_seen_ms",
)


@dataclass(frozen=True, slots=True)
class RobodrCaseContext:
    """The case columns the RoboDR prompt reads.

    ``severity``, ``priority`` and ``status`` are the case's enum values, so
    they are trusted. ``payload`` is the case's JSONB payload, untyped because
    anyone with case write access can store any JSON shape there; every value
    read from it is checked before it is shown outside an untrusted block.
    """

    case_id: uuid.UUID
    summary: str
    description: str
    severity: str
    priority: str
    status: str
    payload: Mapping[str, Any] | None


def robodr_payload(payload: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """Return ``payload.robodr`` when the case carries a RoboDR finding."""
    if payload is None:
        return None
    match payload.get(ROBODR_PAYLOAD_KEY):
        case Mapping() as robodr:
            return robodr
        case _:
            return None


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _block(value: object, field: str, max_length: int = VALUE_MAX_LENGTH) -> str:
    return render_untrusted(value, field=field, mode="prompt", max_length=max_length)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _trusted_or_block(
    lines: list[str], name: str, value: object, trusted: bool
) -> None:
    if value is None:
        return
    if trusted:
        lines.append(f"- {name}: {value}")
    else:
        lines.append(f"- {name}: (failed validation; shown as untrusted data)")
        lines.append(_block(value, f"payload.robodr.{name}"))


def _rule_lines(lines: list[str], rule_id: object) -> None:
    info = catalog_entry(rule_id) if isinstance(rule_id, str) else None
    if info is None:
        _trusted_or_block(lines, "rule_id", rule_id, trusted=False)
        return
    lines.append(f"- rule_id: {rule_id}")
    lines.append(f"- rule_title: {info.title}")
    lines.append(f"- rule_description: {info.desc}")
    lines.append(f"- rule_data_source: {info.data_source}")
    if info.techniques:
        catalog = ", ".join(f"{tid} {name}" for tid, name in info.techniques)
        lines.append(f"- catalog_mitre_ics: {catalog}")


def _mitre_lines(lines: list[str], mitre: object) -> None:
    if mitre is None:
        return
    if isinstance(mitre, list) and all(_matches(_TECHNIQUE_RE, t) for t in mitre):
        lines.append(f"- mitre_ics: {', '.join(mitre) or '(none)'}")
        return
    _trusted_or_block(lines, "mitre_ics", mitre, trusted=False)


def _evidence_lines(lines: list[str], links: object) -> None:
    if not isinstance(links, list) or not links:
        if links not in (None, []):
            _trusted_or_block(lines, "evidence_links", links, trusted=False)
        return
    lines.append("")
    lines.append("Evidence links (black-box records; resolve through the export):")
    for index, link in enumerate(links[:MAX_EVIDENCE_LINKS]):
        if _matches(_EVIDENCE_RE, link):
            lines.append(f"- {link}")
        else:
            lines.append(_block(link, f"payload.robodr.evidence_links.{index}"))


def _untrusted_value_lines(lines: list[str], robodr: Mapping[str, Any]) -> None:
    match robodr.get("untrusted"):
        case {"values": list(values)}:
            pass
        case None:
            values = []
        case other:
            values = [other]
    lines.append("")
    lines.append(f"Adversary-controlled values ({len(values)}):")
    for index, entry in enumerate(values[:MAX_UNTRUSTED_VALUES]):
        # The pointer is attacker-adjacent too; render_untrusted sanitises
        # labels to a path-safe charset.
        pointer = entry.get("pointer") if isinstance(entry, Mapping) else None
        label = pointer if isinstance(pointer, str) and pointer else f"value.{index}"
        lines.append(_block(entry, label))
    if len(values) > MAX_UNTRUSTED_VALUES:
        lines.append(f"({len(values) - MAX_UNTRUSTED_VALUES} more values omitted)")


def build_robodr_case_prompt(case: RobodrCaseContext) -> str:
    """Build the agent context for a RoboDR case.

    Args:
        case: The case to describe; its payload must carry ``robodr``.

    Returns:
        Prompt text in which every adversary-controlled or unchecked value
        sits inside a ``render_untrusted`` block.

    Raises:
        ValueError: If the case carries no RoboDR payload.
    """
    robodr = robodr_payload(case.payload)
    if robodr is None:
        raise ValueError("case has no payload.robodr")

    lines = [
        "You are a case management assistant for security operations. Do not "
        "run actions or tools the user did not explicitly request, and ask "
        "before acting on a recommendation. Use the case id below in case "
        "tools.",
        "",
        "This case holds a RoboDR robot finding.",
        UNTRUSTED_PROMPT_RULES,
        "",
        f"Case id (use it in case tools): {case.case_id}",
        f"Case severity: {case.severity}",
        f"Case priority: {case.priority}",
        f"Case status: {case.status}",
        "",
        "Finding fields checked against the RoboDR catalog and fixed patterns:",
    ]
    _rule_lines(lines, robodr.get("rule_id"))
    severity = robodr.get("severity")
    _trusted_or_block(lines, "severity", severity, severity in _SEVERITIES)
    robot_id = robodr.get("robot_id")
    _trusted_or_block(lines, "robot_id", robot_id, _matches(_ROBOT_ID_RE, robot_id))
    _mitre_lines(lines, robodr.get("mitre_ics"))
    finding_id = robodr.get("finding_id")
    _trusted_or_block(
        lines, "finding_id", finding_id, _matches(_FINDING_ID_RE, finding_id)
    )
    source = robodr.get("data_source")
    _trusted_or_block(lines, "data_source", source, _matches(_DATA_SOURCE_RE, source))
    version = robodr.get("contract_version")
    _trusted_or_block(
        lines, "contract_version", version, _matches(_VERSION_RE, version)
    )
    for name in _COUNT_FIELDS:
        value = robodr.get(name)
        _trusted_or_block(lines, name, value, _is_count(value))
    _evidence_lines(lines, robodr.get("evidence_links"))

    lines += [
        "",
        "Case summary and description (editable text):",
        _block(case.summary, "case.summary", TEXT_MAX_LENGTH),
        _block(case.description, "case.description", TEXT_MAX_LENGTH),
    ]
    _untrusted_value_lines(lines, robodr)
    return "\n".join(lines)
