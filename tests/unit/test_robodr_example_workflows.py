"""The RoboDR example workflows load and validate offline.

Each file in `examples/004-robodr-robot-findings/workflows/` is a workflow
definition in the import format (`ExternalWorkflowDefinition`). The checks run
the DSL validators that need no database (graph, entrypoint, expressions) and
check every action's arguments against the registry's input schema.
"""

from pathlib import Path

import pytest
import yaml

from autosecops.dsl.common import DSLInput
from autosecops.registry.repository import Repository
from autosecops.validation.service import (
    validate_dsl_acyclic,
    validate_dsl_entrypoint,
    validate_dsl_expressions,
)
from autosecops.workflow.management.schemas import ExternalWorkflowDefinition

WORKFLOWS_DIR = (
    Path(__file__).resolve().parents[2]
    / "examples"
    / "004-robodr-robot-findings"
    / "workflows"
)
WORKFLOW_FILES = sorted(WORKFLOWS_DIR.glob("*.yml"))
UNTRUSTED_SOURCES = ("tainted", "detail", "ros.")


@pytest.fixture(scope="module")
def repo() -> Repository:
    repository = Repository()
    repository.init(include_base=True, include_templates=True)
    return repository


def _load(path: Path) -> ExternalWorkflowDefinition:
    return ExternalWorkflowDefinition.model_validate(yaml.safe_load(path.read_text()))


def _arg_errors(dsl: DSLInput, repo: Repository) -> list[str]:
    errors: list[str] = []
    for stmt in dsl.actions:
        bound = repo.store.get(stmt.action)
        if bound is None:
            errors.append(f"{stmt.ref}: unknown action {stmt.action}")
            continue
        expects = bound.get_interface()["expects"]
        properties = set(expects.get("properties", {}))
        required = set(expects.get("required", []))
        if unknown := set(stmt.args) - properties:
            errors.append(f"{stmt.ref}: unknown args {sorted(unknown)}")
        if missing := required - set(stmt.args):
            errors.append(f"{stmt.ref}: missing args {sorted(missing)}")
    return errors


def test_all_four_workflows_ship() -> None:
    titles = {_load(p).definition.title for p in WORKFLOW_FILES}
    assert titles == {
        "Robot finding triage",
        "Robot containment request (approval)",
        "Rogue DDS participant",
        "Motion envelope violation",
    }


@pytest.mark.anyio
@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
async def test_workflow_validates(path: Path, repo: Repository) -> None:
    dsl = _load(path).definition
    errors: list[object] = [*validate_dsl_acyclic(dsl), *validate_dsl_entrypoint(dsl)]
    errors += await validate_dsl_expressions(dsl)
    errors += _arg_errors(dsl, repo)
    assert errors == []


@pytest.mark.anyio
async def test_validators_catch_a_broken_workflow(repo: Repository) -> None:
    raw = yaml.safe_load(WORKFLOW_FILES[0].read_text())
    raw["definition"]["actions"][0]["args"]["unexpected"] = 1
    raw["definition"]["actions"][1]["args"]["value"] = "${{ FN.no_such_function(1) }}"
    dsl = ExternalWorkflowDefinition.model_validate(raw).definition
    assert _arg_errors(dsl, repo)
    assert await validate_dsl_expressions(dsl)


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_tainted_fields_reach_prompts_only_through_render_untrusted(path: Path) -> None:
    dsl = _load(path).definition
    for stmt in dsl.actions:
        if not stmt.action.startswith("ai."):
            continue
        prompt = str(stmt.args.get("user_prompt", "")) + str(
            stmt.args.get("instructions", "")
        )
        # Agents read the finding's adversary-controlled fields only through
        # the rendered blocks, never straight from the parsed finding.
        assert "parse_finding.result.tainted" not in prompt
        assert "parse_finding.result.adversary" not in prompt
        assert "untrusted.values" not in prompt
        assert ".display" not in prompt and ".value }}" not in prompt


def test_containment_request_goes_through_the_approval_gate() -> None:
    path = WORKFLOWS_DIR / "robot-containment-request.yml"
    dsl = _load(path).definition
    actions = {stmt.ref: stmt for stmt in dsl.actions}
    # The workflow never calls request_action directly ...
    assert all(stmt.action != "tools.robodr.request_action" for stmt in dsl.actions)
    # ... only through an agent whose single tool needs approval.
    gate = actions["approved_request"]
    assert gate.action == "ai.agent"
    assert gate.args["actions"] == ["tools.robodr.request_action"]
    assert gate.args["tool_approvals"] == {"tools.robodr.request_action": True}
    assert gate.args["max_tool_calls"] == 1
    # The policy check runs first and gates the request.
    assert actions["policy"].action == "tools.robodr.check_action_policy"
    assert "policy.result.allowed" in str(actions["request_arguments"].run_if)
