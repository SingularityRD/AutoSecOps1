# 004: RoboDR robot findings

Four workflows for findings from RoboDR, a robot EDR. RoboDR sends `robodr.findings` 2.x findings to the AutoSecOps ingest endpoint, which opens one case per finding. These workflows triage the case, propose containment, and send an approved action to the robot's control plane.

The integration page is `docs/integrations/robodr-tools.mdx`. The actions are `tools.robodr.*`.

## Files

| File | Workflow |
|---|---|
| [`workflows/robot-finding-triage.yml`](workflows/robot-finding-triage.yml) | Robot finding triage: parse, enrich (robot, rule, severity, MITRE ATT&CK for ICS), model triage in a closed schema, case comment, optional Slack post |
| [`workflows/robot-containment-request.yml`](workflows/robot-containment-request.yml) | Robot containment request (approval): approver and morphology check against the robot snapshot, then the request through an agent whose only tool needs inbox approval |
| [`workflows/rogue-dds-participant.yml`](workflows/rogue-dds-participant.yml) | Rogue DDS participant: proposes evidence, participant quarantine, network isolation |
| [`workflows/motion-envelope-violation.yml`](workflows/motion-envelope-violation.yml) | Motion envelope violation: proposes evidence and a time-limited motion restriction |

Each file is a workflow definition in the import format (`definition` plus `case_trigger`). `tests/unit/test_robodr_example_workflows.py` validates them.

## Setup

1. Connect RoboDR to the ingest endpoint and register the robots and their keys.
2. For the containment workflow, create the secret `robodr_control_plane` with `ROBODR_SOC_KEY_ID` and `ROBODR_SOC_SECRET_HEX` (the SOC key pair from `robodr-blackbox keygen`), and install the public key on each robot.
3. Import the four workflows. Their case triggers ship offline and filter on the tag `robodr`; tag RoboDR cases, run each workflow once by hand on a test case, then turn the triggers on.
4. Optional: pass `slack_channel` to the triage workflow. Slack receives sensor fields only.

The workflows read the case payload the ingest writes under `robodr` (sensor fields, and adversary-controlled values under `robodr.untrusted.values`). `tools.robodr.finding_to_case_fields` builds the same payload for findings that arrive another way.

## Rules these workflows keep

- Every adversary-controlled field (ROS names, DDS GUIDs, the free-text detail) reaches a model or a case only through `tools.robodr.render_untrusted`.
- No robot action is autonomous. The proposal workflows only comment. The containment workflow needs one approver other than the requester, or two for `robot_safe_pause`, `robot_request_safe_state` and `robot_rollback_config`, plus the inbox approval of the request itself.
- A humanoid, or a robot that reports no morphology, never gets `robot_safe_pause`, `robot_request_safe_state` or `robot_rollback_config`; a quadruped never gets `robot_rollback_config`.
- The current RoboDR release records accepted requests without executing them (`recorded_not_executed`). The workflows report that as not applied.

All robot ids, hosts and names in the workflows are placeholders.
