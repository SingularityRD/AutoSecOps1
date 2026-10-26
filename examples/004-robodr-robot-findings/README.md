# 004: RoboDR robot findings

Five workflows for findings from RoboDR, a robot EDR. RoboDR sends `robodr.findings` 2.x findings to the AutoSecOps ingest endpoint, which opens one case per finding. These workflows triage the case, propose containment, and send a signed-off action to the robot's control plane.

The integration page is `docs/integrations/robodr-tools.mdx`. The actions are `tools.robodr.*`.

## Files

| File | Workflow |
|---|---|
| [`workflows/robot-finding-triage.yml`](workflows/robot-finding-triage.yml) | Robot finding triage: parse, enrich (robot, rule, severity, MITRE ATT&CK for ICS), model triage in a closed schema, case comment, optional Slack post |
| [`workflows/robot-containment-request.yml`](workflows/robot-containment-request.yml) | Robot containment request (approval): first run checks the action and morphology against the robot's signed snapshot and comments the `request_id` and `request_digest` to sign off; second run, with the sign-off submission ids, sends the request |
| [`workflows/robot-action-sign-off.yml`](workflows/robot-action-sign-off.yml) | Robot action sign-off: the form the requester (`robodr_decision: request`) and each approver (`robodr_decision: approve`) submit |
| [`workflows/rogue-dds-participant.yml`](workflows/rogue-dds-participant.yml) | Rogue DDS participant: proposes evidence, participant quarantine, network isolation |
| [`workflows/motion-envelope-violation.yml`](workflows/motion-envelope-violation.yml) | Motion envelope violation: proposes evidence and a time-limited motion restriction |

Each file is a workflow definition in the import format (`definition`, plus `case_trigger` for the case-triggered ones). `tests/unit/test_robodr_example_workflows.py` validates them.

## Setup

1. Connect RoboDR to the ingest endpoint and register the robots and their keys.
2. For the containment workflow, create the secret `robodr_control_plane` with `ROBODR_SOC_KEY_ID` and `ROBODR_SOC_SECRET_HEX` (the SOC key pair from `robodr-blackbox keygen`), and install the public key on each robot. Pass each robot's finding public key as `answer_public_key_hex`: the workflow requires signed robot answers.
3. Import the five workflows, publish "Robot action sign-off", and turn its form on for the people who may request or approve robot actions.
4. The case triggers ship offline and filter on the tag `robodr`; tag RoboDR cases, run each workflow once by hand on a test case, then turn the triggers on.
5. Optional: pass `slack_channel` to the triage workflow. Slack receives sensor fields and the rendered case summary only.

The workflows read the case payload the ingest writes under `robodr` (sensor fields, and adversary-controlled values under `robodr.untrusted.values`). `tools.robodr.finding_to_case_fields` builds the same payload from the raw record value for findings that arrive another way.

## Rules these workflows keep

- Every adversary-controlled field (ROS names, DDS GUIDs, the free-text detail) reaches a model or a case only through `tools.robodr.render_untrusted`, passed as the whole entry so its `suspicious` flag is kept. The triage workflow renders the case summary the same way for the model and for Slack.
- No robot action is autonomous. The proposal workflows only comment. `tools.robodr.request_action` itself refuses to send anything unless sign-off form submissions by platform users prove the request: the requester, plus one approver other than the requester, or two different approvers for `robot_safe_pause`, `robot_request_safe_state` and `robot_rollback_config`. Identities come from the platform's submission records, never from workflow inputs.
- `robot_safe_pause`, `robot_request_safe_state` and `robot_rollback_config` are sent only to a robot whose signed snapshot reports `wheeled_mobile`, `arm`, `aerial` or `other`; a humanoid, a quadruped, and a robot with no or an unknown morphology never get them.
- The current RoboDR release records accepted requests without executing them (`recorded_not_executed`). The workflows report that as not applied.

All robot ids, hosts and names in the workflows are placeholders.
