"""The RoboDR example workflows load and validate offline.

Each file in `examples/004-robodr-robot-findings/workflows/` is a workflow
definition in the import format (`ExternalWorkflowDefinition`). The checks run
the DSL validators that need no database (graph, entrypoint, expressions) and
check every action's arguments against the registry's input schema.
"""

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from autosecops.dsl.common import DSLInput
from autosecops.dsl.schemas import ActionStatement
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


REGISTRY_PACKAGE = "autosecops_registry"


def _registry_modules() -> dict[str, dict[str, object]]:
    return {
        name: dict(vars(module))
        for name, module in list(sys.modules.items())
        if module is not None
        and (name == REGISTRY_PACKAGE or name.startswith(f"{REGISTRY_PACKAGE}."))
    }


@pytest.fixture(scope="module")
def repo() -> Iterator[Repository]:
    """A fully initialised registry that does not leak into other test modules.

    ``Repository.init`` reloads every ``autosecops_registry`` module in place,
    which rebinds module globals such as exception classes to new objects.
    Names other test modules imported earlier would then no longer match what
    the registry raises, so the module namespaces are restored afterwards and
    modules first imported here are dropped.
    """
    before = _registry_modules()
    repository = Repository()
    repository.init(include_base=True, include_templates=True)
    try:
        yield repository
    finally:
        for name in set(_registry_modules()) - set(before):
            del sys.modules[name]
        for name, namespace in before.items():
            module = sys.modules.get(name)
            if module is None:
                continue
            current = vars(module)
            current.clear()
            current.update(namespace)


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


def test_all_workflows_ship() -> None:
    titles = {_load(p).definition.title for p in WORKFLOW_FILES}
    assert titles == {
        "Robot finding triage",
        "Robot containment request (approval)",
        "Robot action sign-off",
        "Rogue DDS participant",
        "Motion envelope violation",
        "Robot evidence export",
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


def _actions(name: str) -> dict[str, ActionStatement]:
    dsl = _load(WORKFLOWS_DIR / name).definition
    return {stmt.ref: stmt for stmt in dsl.actions}


def test_containment_request_needs_platform_signoff() -> None:
    path = WORKFLOWS_DIR / "robot-containment-request.yml"
    dsl = _load(path).definition
    actions = _actions(path.name)
    expects = dsl.entrypoint.expects or {}
    # No input names a person: approvals are form submissions the action
    # reads back from the platform.
    assert "approved_by" not in expects and "requested_by" not in expects
    assert "request_submission_id" in expects
    assert "approval_submission_ids" in expects
    # The robot answer key is required (no default) and used everywhere.
    key = expects["answer_public_key_hex"]
    assert key.type == "str" and not key.has_default()
    send = actions["send"]
    assert send.action == "tools.robodr.request_action"
    assert send.args["request_submission_id"] == "${{ TRIGGER.request_submission_id }}"
    assert (
        send.args["approval_submission_ids"] == "${{ TRIGGER.approval_submission_ids }}"
    )
    assert send.args["request_id"] == "${{ ACTIONS.prepare.result.request_id }}"
    for ref in ("snapshot", "send"):
        assert (
            actions[ref].args["answer_public_key_hex"]
            == "${{ TRIGGER.answer_public_key_hex }}"
        )
        # Mutual TLS: the robot CA is a (required) input, never a secret.
        assert actions[ref].args["robot_ca_pem"] == "${{ TRIGGER.robot_ca_pem }}"
    assert not expects["robot_ca_pem"].has_default()
    # The request is sent only when the policy allows it and sign-offs exist.
    assert "policy.result.allowed" in str(send.run_if)
    assert "request_submission_id" in str(send.run_if)
    assert actions["prepare"].action == "tools.robodr.prepare_action_request"
    assert actions["policy"].action == "tools.robodr.check_action_policy"


def test_signoff_workflow_collects_the_bound_answers() -> None:
    dsl = _load(WORKFLOWS_DIR / "robot-action-sign-off.yml").definition
    expects = dsl.entrypoint.expects or {}
    assert set(expects) >= {
        "robodr_request_id",
        "robodr_request_digest",
        "robodr_decision",
    }
    decision = expects["robodr_decision"]
    assert decision.type == "str" and decision.enum == ["request", "approve"]
    # It never contacts a robot.
    assert all(not s.action.startswith("tools.robodr.") for s in dsl.actions)


@pytest.mark.parametrize(
    ("name", "ref"),
    [
        ("robot-finding-triage.yml", "render_tainted"),
        ("rogue-dds-participant.yml", "participant"),
        ("motion-envelope-violation.yml", "channel"),
    ],
)
def test_whole_tainted_entries_reach_render_untrusted(name: str, ref: str) -> None:
    """The entry carries `suspicious`; a bare `display` would drop it."""
    stmt = _actions(name)[ref]
    assert stmt.action == "tools.robodr.render_untrusted"
    assert stmt.args["value"] == "${{ var.field }}"


def test_triage_renders_the_case_summary_as_untrusted() -> None:
    actions = _actions("robot-finding-triage.yml")
    prompt = str(actions["triage_note"].args["user_prompt"])
    slack = str(actions["notify"].args["text"])
    for text in (prompt, slack):
        assert "get_case.result.summary" not in text
        assert "get_case.result.description" not in text
    assert "ACTIONS.render_summary.result" in prompt
    assert "ACTIONS.render_summary_markdown.result" in slack
    for ref, mode in (
        ("render_summary", "prompt"),
        ("render_summary_markdown", "markdown"),
    ):
        stmt = actions[ref]
        assert stmt.action == "tools.robodr.render_untrusted"
        assert stmt.args["value"] == "${{ ACTIONS.get_case.result.summary }}"
        assert stmt.args["mode"] == mode


def test_evidence_export_verifies_before_storing() -> None:
    path = WORKFLOWS_DIR / "robot-evidence-export.yml"
    dsl = _load(path).definition
    actions = _actions(path.name)
    expects = dsl.entrypoint.expects or {}
    assert expects["blackbox_public_keys"].type == "list[str]"
    export, download = actions["export"], actions["download"]
    assert export.action == "tools.robodr.create_evidence_export"
    assert download.action == "tools.robodr.download_evidence_export"
    # One selector: the finding's own evidence links.
    for stmt in (export, download):
        assert stmt.args["finding_id"] == (
            "${{ ACTIONS.get_case.result.payload.robodr.finding_id }}"
        )
        assert "from_seq" not in stmt.args and "from_ms" not in stmt.args
    assert download.args["case_id"] == "${{ TRIGGER.case_id }}"
    assert download.args["blackbox_public_keys"] == (
        "${{ TRIGGER.blackbox_public_keys }}"
    )
