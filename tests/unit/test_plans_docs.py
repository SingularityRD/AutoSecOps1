"""Keep the plans docs page, frontend plan labels, and plans.py in sync."""

from __future__ import annotations

import re
from pathlib import Path

import generate_plans_docs
import pytest

from autosecops.licensing.plans import (
    FREE_ENTITLEMENTS,
    PLAN_ENTITLEMENTS,
    PLAN_ORDER,
    minimum_plan,
    minimum_plan_for,
    plan_label,
)
from autosecops.licensing.types import LicenseGrant, LicensePlan
from autosecops.tiers.defaults import BASELINE_ENTITLEMENTS
from autosecops.tiers.enums import Entitlement

ROOT_DIR = Path(__file__).resolve().parents[2]
FRONTEND_PLANS = ROOT_DIR / "frontend" / "src" / "lib" / "plans.ts"
DOCS_DIR = ROOT_DIR / "docs"


def test_plans_page_matches_plans_py() -> None:
    """Fails when plans.py changes without regenerating the docs page.

    Fix with ``python scripts/generate_plans_docs.py``.
    """
    assert generate_plans_docs.main(["--check"]) == 0


def test_plans_page_is_in_docs_navigation() -> None:
    assert '"self-hosting/plans"' in (DOCS_DIR / "docs.json").read_text()


def test_free_entitlements_match_the_single_tenant_baseline() -> None:
    baseline = {
        Entitlement(key)
        for key, enabled in BASELINE_ENTITLEMENTS.model_dump().items()
        if enabled
    }
    assert baseline == FREE_ENTITLEMENTS


def test_every_grant_has_a_docs_entry() -> None:
    assert set(generate_plans_docs.GRANT_DOCS) == {*Entitlement, *LicenseGrant}


def test_every_grant_has_a_minimum_plan_and_plans_nest() -> None:
    for grant in [*Entitlement, *LicenseGrant]:
        assert minimum_plan(grant) in PLAN_ORDER
    paid = PLAN_ORDER[1:]
    for smaller, larger in zip(paid, paid[1:], strict=False):
        assert PLAN_ENTITLEMENTS[smaller] <= PLAN_ENTITLEMENTS[larger]


@pytest.mark.parametrize(
    ("required", "expected"),
    [
        ([], LicensePlan.COMMUNITY),
        (["custom_registry"], LicensePlan.COMMUNITY),
        (["case_addons"], LicensePlan.TEAM),
        (["forms", "semantic_search"], LicensePlan.BUSINESS),
        (["forms", "robot_edr"], LicensePlan.ENTERPRISE),
        (["multi_tenant"], LicensePlan.MSSP),
    ],
)
def test_minimum_plan_for_action_entitlements(
    required: list[str], expected: LicensePlan
) -> None:
    assert minimum_plan_for(required) is expected


def test_minimum_plan_for_rejects_unknown_keys() -> None:
    with pytest.raises(ValueError):
        minimum_plan_for(["not_an_entitlement"])


def test_frontend_plan_labels_match_plans_py() -> None:
    source = FRONTEND_PLANS.read_text()
    block = re.search(
        r"ENTITLEMENT_MINIMUM_PLAN: Record<Entitlement, PlanName> = \{(.*?)\}",
        source,
        re.S,
    )
    assert block is not None
    frontend = dict(re.findall(r"(\w+): \"(\w+)\"", block.group(1)))

    assert frontend == {
        entitlement.value: plan_label(minimum_plan(entitlement))
        for entitlement in Entitlement
    }


def test_docs_never_use_the_legacy_enterprise_edition_badge() -> None:
    """Badges name the smallest plan, such as ``Team plan``, not "Enterprise"."""
    legacy = re.compile(r'shape="pill">Enterprise( Edition)?</Badge>')
    offenders = sorted(
        str(path.relative_to(ROOT_DIR))
        for path in DOCS_DIR.rglob("*.mdx")
        if legacy.search(path.read_text(encoding="utf-8"))
    )
    assert offenders == []
