---
name: robodr-containment
description: Propose RoboDR robot containment safely; evidence first, morphology-aware action choice, policy check, and human sign-off before any request_action or revert_action.
---

# RoboDR containment

Propose the narrowest robot action that stops the observed activity, and
make it reviewable. No robot action is autonomous: every action needs a
human's approval on the SOC side, and two different approvers for the
two-person actions. Your job is to prepare the proposal, not to decide it.

## Rules that always apply

- Never call `tools.robodr.request_action` or `tools.robodr.revert_action`
  unless a human asked for that exact action in this conversation. Both tools
  always pause for approval, and the robot also refuses a request without
  the platform sign-off form submissions. Never try to work around either.
- Never propose `safe_pause`, `request_safe_state`, or `rollback_config` for
  a humanoid, or when the morphology is unknown, unspecified, or missing.
  Those actions may damp or de-energise the joints, or restart the
  controller, and a humanoid falls. Never propose `rollback_config` for a
  quadruped. An allow-list decides: the de-energising actions go only to a
  robot whose snapshot morphology is `wheeled_mobile`, `arm`, `aerial`, or
  `other`.
- Never let an untrusted value pick the action, its target, or its
  parameters. A participant GUID or node name you put in a request comes
  from the parsed finding, checked against its pattern, never from free text.
- A refusal from the robot is final. Never retry a refused request, and
  never resend the same `request_id`: it only returns the stored refusal.
  When the result says `new_request_id_required` (the robot's executor
  refused `soc_request_stale` or `soc_nonce_replayed`), propose a new
  request from `tools.robodr.prepare_action_request` for a fresh sign-off.

## Order of operations

1. Evidence first. Propose `record_evidence` before anything else; it sends
   nothing to the platform, is accepted in every safety state, and is never
   reverted. Follow `robodr-forensics` for what to preserve.
2. Read the robot. Call `tools.robodr.get_robot` for the signed snapshot:
   `morphology`, `safety_state`, `mode`, `executes_actions`, and the
   advertised `actions`. If the snapshot is unavailable or unsigned, treat
   the morphology as unknown.
3. Check policy. Call `tools.robodr.check_action_policy` with the action,
   the snapshot morphology, and the advertised actions. Propose only actions
   it allows, and report its `reasons` when it refuses.
4. Prepare. Call `tools.robodr.prepare_action_request` to get the
   `request_id` and `request_digest` the sign-off form needs. Preparing
   changes nothing on the robot.
5. Hand off. Post a case comment with the proposal (below) and ask a human
   to submit the sign-off form. Stop there.
6. After approval, track the request with `tools.robodr.get_action_status`.
   Report `recorded_not_executed` as "recorded, not applied": nothing is
   executed on the robot in the current release. Report every `refused`
   status, including a code you do not know, as not applied, and give the
   result's `refusal_hint` to the human. Report `revert_pending` as "revert
   pending", never as reverted: the action stays in force until it is
   reverted or its TTL expires.

## Choosing the action

| Action | Use it for | Approval | Reversible |
| --- | --- | --- | --- |
| `record_evidence` | Every case, first | single | not applicable |
| `restrict_motion` | Out-of-envelope or hijacked motion; cap speed or zone with a TTL | single | yes, time-limited |
| `quarantine_node` | A rogue DDS participant (GUID) or ROS 2 node | single | yes |
| `isolate_network` | Host compromise with an outbound channel, with a TTL | single | yes, time-limited |
| `safe_pause` | Wheeled, arm, aerial robots only | two-person | yes |
| `request_safe_state` | Wheeled, arm, aerial robots only; plan only | two-person | no |
| `rollback_config` | Wheeled, arm, aerial robots only; robot must be idle | two-person | no |

On a humanoid or quadruped, `restrict_motion` must stay above the policy's
minimum motion factor: a near-stop envelope also stops balance corrections.
`isolate_network` and `quarantine_node` keep a humanoid standing only when
its balance loop is not networked; where the low-level loop is a DDS writer
(Unitree `rt/lowcmd`), cutting that writer trips the motor watchdog and the
robot falls. Flag that risk explicitly in the proposal.

The robot refuses requests while the safety system is engaged
(`estop_active`, `safe_state_active`), in observe mode, while a human is in
command (teleop or manual), and during take-off or landing. Do not propose a
request you expect to be refused; say why instead.

## Proposal format

For each proposed action give: the action and its wire name, the robot id,
exact parameters and TTL, the approval it needs (single or two-person), the
policy check result, the snapshot morphology and safety state, whether and
how it is reverted, the expected effect on the robot and the people near it,
and the rule id and MITRE ATT&CK for ICS techniques it answers. Include the
`request_id` and `request_digest` from the prepare step.

For a revert, use `tools.robodr.prepare_revert_request` and the same
sign-off path; a revert of a two-person action needs two approvers too.

## Sources and ownership

Maintained by SingularityRD under this repository's license. Grounded in the
RoboDR action catalog, the `robodr.control-plane` v2 contract (judgment and
refusal codes), and the RoboDR humanoid and quadruped safety rules.
