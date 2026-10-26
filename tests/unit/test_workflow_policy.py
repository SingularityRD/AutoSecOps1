"""Repository-wide GitHub Actions rules from .github/AGENTS.md."""

from pathlib import Path

import pytest
import yaml

WORKFLOWS = sorted(
    (Path(__file__).resolve().parents[2] / ".github/workflows").glob("*.yml")
)


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_checkout_does_not_persist_credentials(workflow: Path) -> None:
    jobs = yaml.safe_load(workflow.read_text()).get("jobs") or {}
    persisted = [
        name
        for name, job in jobs.items()
        for step in job.get("steps") or []
        if str(step.get("uses", "")).startswith("actions/checkout@")
        and (step.get("with") or {}).get("persist-credentials") is not False
    ]
    assert persisted == []


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_workflow_does_not_depend_on_upstream_repositories(workflow: Path) -> None:
    assert "tracecathq/" not in workflow.read_text().lower()
