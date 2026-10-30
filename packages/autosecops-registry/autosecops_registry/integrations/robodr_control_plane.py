"""RoboDR robot control plane v2 (`robodr-control-plane/v2`).

A SOC asks a robot's on-board agent (`robodr-agentd`) for one of seven catalog
actions, and exports signed black-box evidence. The robot judges each action
request against its current safety state and may refuse it. Without executor
v1 nothing is executed: an accepted request answers `recorded_not_executed`
with `executed: false`, which these actions report as not applied. With
executor v1 a request may answer `pending`, then `verified` or `reverted`;
`refused` and `failed` are never applied. With the executor's motion
adapters (its `motion` section) `restrict_motion` and `safe_pause` also
reach `verified` / `reverted`, and `request_safe_state` / `rollback_config`
(`config: program`) the terminal `applied` (carried out by the platform's
adapter, not reversible). "In force" is taken only from the
answer's own `in_force` (true for a `verified` action the executor does not
hold): a `verified` action held after a robot reboot
(`state.executor_state: "held"`) is reported as held, not enforced, and a
`verified` action whose revert is still pending (`state.revert.result:
"pending"`, e.g. a revert the executor refused) as revert pending, never as
reverted. A `quarantine_node` in force is reported contained only with
`containment: "full"` backed by its `state.quarantine`; `partial`,
`guid_only` (GUID-prefix drop only, not IP-contained) and an absent or
`unknown` scope are reported as such, never as contained (§6a "Quarantine
scope", §10). A refusal code this module does not know is reported as not
applied. The executor's own `soc_request_stale` / `soc_nonce_replayed`
refusals are never resent: the same `request_id` only answers the stored
refusal, so trying again takes a new prepared, signed-off request.

A call the robot answers `busy` (503) or rate limited (429), or refuses
right after it created its replay store (401 `stale_timestamp`, the replay
fence), is signed afresh and sent again a few times; a submission is resent
with the same `request_id` and body, which the robot judges once (§7).
Every robot error code is reported with what it means.

Channel and authentication (contract §1-2)
------------------------------------------

Every call is one HTTP/1.1 request over **mutual TLS** (https only): the
robot's server certificate must chain to the configured robot CA and match
the host of `base_url` (optionally also its SPKI SHA-256 pin, checked before
anything is sent), and the SOC presents its client certificate and key from
the `robodr_control_plane` secret. Every request is also signed with the
SOC's Ed25519 key over

    robodr-control-plane/v2
    <METHOD>
    <request target exactly as sent>
    <robot id>
    <key id>
    <timestamp: Unix seconds>
    <nonce>
    <lower-case hex SHA-256 of the body bytes>

(lines joined by LF, no trailing newline), sent as `X-RoboDR-Key-Id`,
`X-RoboDR-Timestamp`, `X-RoboDR-Nonce` and `X-RoboDR-Signature`. Every answer
must carry a valid `X-RoboDR-Answer-Signature` from the robot's finding key,
bound to the request's signature; an answer without one is treated as not
coming from the robot and nothing is taken from it.

How "no robot action is autonomous" is enforced
-----------------------------------------------

`request_action` and `revert_action` refuse to send anything unless the
platform itself proves that people signed the exact request off. The proof is
AutoSecOps form submissions, read back through the registry SDK with the
run's executor token:

1. `prepare_action_request` (or `prepare_revert_request`) computes a
   `request_digest`: SHA-256 over the canonical JSON of everything the robot
   will be asked (robot id, request id, action, parameters, ttl, reason,
   source; for a revert: robot id, request id, reason).
2. The requester submits the sign-off form with `robodr_decision: request`;
   each approver submits it with `robodr_decision: approve`. Every
   submission carries `robodr_request_id`, `robodr_request_digest` and
   `robodr_robot_id`, and a request's also `robodr_action` (the catalog wire
   name): the `signoff_answers` the prepare action returns.
3. `request_action` / `revert_action` take the submission ids, fetch each
   submission from the platform (`ctx.forms.get_submission`) and require:
   submitted by a platform user (`submitted_by.type == "user"`, never a
   service account; workflows, agents and the executor have no
   `form:submit` scope, so they cannot create one), the same form for all, the
   same request id, digest, robot id (and action) as the request being sent,
   the right decision, and at most 24 hours old. People are identified only by the platform user
   ids on those records; no action input names a person. An approver must
   differ from the requester and from every other approver: one approval, or
   two for `safe_pause`, `request_safe_state`, `rollback_config` and the
   revert of any of them (the robot's stored request says which action a
   revert undoes). The body of a two-person request or revert names those
   approvers to the robot (`approved_by`, motion adapters revision) when the
   robot's signed snapshot says its executor carries out actions
   (`executes_actions: true`): each approver as `user-<platform user id>`
   (immutable, unlike an email), never the requester, and only names
   RoboDR's grammar `[A-Za-z0-9._%+@-]{1,100}` accepts that it counts as
   different people (case-insensitively); otherwise nothing is sent. The
   robot's executor carries out a two-person action only with two such
   approvers; a robot without one only records the request as a plan, and
   an older agentd would refuse the unknown field. The platform audit
   records the `requested_by` and `approved_by` names sent and checks them
   against the sign-off submitters.
4. Any failure (no platform context, unreadable submission, mismatch) raises
   `SignoffError` before a request is signed, and nothing reaches the robot.
5. Each request and revert is then recorded by the platform
   (`ctx.robot_edr.record_robot_action`) before it is signed: the platform
   re-checks the sign-off submissions itself (same form, age, request,
   digest, robot and action), names the run that acted (workflow or agent
   session, run, execution and trigger) and the requester and approvers, and
   stores the attempt. With an audit sink configured, the call goes ahead
   only once the sink confirmed the event (`audit_log: written`); a refusal,
   a sink error or no answer in time raises `ActionAuditError` and nothing
   reaches the robot. With no audit sink configured the platform only logs
   the event (`audit_log: no_sink`, `audit_logged: false`). The robot's
   answer, or the failure (also a cancelled call), is recorded after it
   against the stored attempt, once (best effort: the robot has acted;
   `outcome_audit_log` says what became of it).

`requires_approval=True` additionally pauses an agent's tool call in the
inbox, but that gate is not relied on: a workflow step calling the action
directly, or an agent whose tool approval was turned off, still needs the
sign-off submissions above. The morphology rules are checked against the
robot's own signed snapshot.

Evidence (contract §11)
-----------------------

`list_evidence`, `create_evidence_export` and `download_evidence_export`
read black-box evidence. Exporting changes nothing on the robot (it is
recorded in its black box), so these need no sign-off; each call is recorded
by the platform first (`attempt`: refused before anything is read when the
platform refuses it or the configured audit sink does not confirm it), and
its end after (`succeeded` or `failed`, also a cancelled call; best effort).
`delete_after_download` records the delete the same way before it is sent;
a delete the platform does not record is not sent (`deleted: false`). A download verifies the export as §11.6 requires
(`robodr_evidence`) before the bundle is stored for the case; nothing that
fails verification is stored.
"""

import asyncio
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets as pysecrets
import ssl
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import quote, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing_extensions import Doc

from autosecops_registry import RegistrySecret, registry, secrets
from autosecops_registry.config import AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES
from autosecops_registry.context import get_context
from autosecops_registry.integrations.robodr import (
    DISPLAY_GROUP,
    DOC_URL,
    ed25519_verify_strict,
    parse_public_key_hex,
)
from autosecops_registry.integrations.robodr_evidence import (
    MAX_EXPORT_BYTES,
    UNVERIFIABLE,
    EvidenceError,
    Manifest,
    assemble_bundle,
    build_selector,
    check_chunk,
    check_report_against_manifest,
    parse_blackbox_keyring,
    parse_manifest,
    parse_signature_header,
    selector_matches,
    verify_bundle,
    verify_manifest_signature,
)
from autosecops_registry.sdk.robot_edr import EvidenceOperation, RobotActionOperation

API_VERSION = "robodr-control-plane/v2"
ANSWER_DOMAIN = f"{API_VERSION} answer"
API_PREFIX = "/api/v2/robots"
REQUEST_TIMEOUT_S = 35.0
"""The robot answers within 30 s (§1); a little more for the TLS handshake."""
HANDSHAKE_TIMEOUT_S = 5.0
MAX_ANSWER_BYTES = 256 * 1024
MAX_ANSWER_HEAD_BYTES = 16 * 1024
MAX_STORED_BUNDLE_BYTES = min(
    AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES, MAX_EXPORT_BYTES
)
"""Largest export downloaded and stored: the platform's
`AUTOSECOPS__ROBOT_EDR_MAX_EVIDENCE_BYTES` (default 64 MiB, the robot's default
`max_export_bytes`), so a bundle the platform would refuse is never fetched,
and never more than 256 MiB, the robot's largest export (§11.7)."""
CHUNK_ATTEMPTS = 5
MAX_RETRY_AFTER_S = 60
CALL_ATTEMPTS = 4
"""Attempts of one call that the robot answered `busy` (503), rate limited
(429) or fenced (401 `stale_timestamp`); each attempt is signed afresh."""
FENCE_RETRY_WAIT_S = 12.0
"""Wait before signing again after `stale_timestamp`: a robot that just
created its replay store refuses requests for `max_clock_skew_s` (default
30 s, §2), which three waits cover."""

robodr_control_plane_secret = RegistrySecret(
    name="robodr_control_plane",
    keys=[
        "ROBODR_SOC_KEY_ID",
        "ROBODR_SOC_SECRET_HEX",
        "ROBODR_SOC_CLIENT_CERT_PEM",
        "ROBODR_SOC_CLIENT_KEY_PEM",
    ],
)
"""SOC credentials for the robot control plane.

`ROBODR_SOC_KEY_ID` / `ROBODR_SOC_SECRET_HEX`: the SOC signing key, from the
`robodr-blackbox keygen` secret key file whose `.pub` is installed on the
robot (`control_plane.soc_keys`); `secret_hex` is the 32-byte Ed25519 seed.
`ROBODR_SOC_CLIENT_CERT_PEM` / `ROBODR_SOC_CLIENT_KEY_PEM`: the SOC's mutual
TLS client certificate chain (end entity first) and its unencrypted private
key; the certificate must chain to a CA in the robot's `tls.client_ca`.
The robot CA and SPKI pin are not secret: they are action inputs."""


# --------------------------------------------------------------------------- #
# Action catalog (robodr_responder::actions, robodr.control-plane §4)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ActionSpec:
    name: str
    params: frozenset[str]
    ttl_required: bool
    two_person: bool
    reversible: bool
    may_de_energise: bool


CATALOG: dict[str, ActionSpec] = {
    spec.name: spec
    for spec in (
        ActionSpec(
            "restrict_motion",
            frozenset({"max_linear_speed", "max_joint_speed", "workspace_zone"}),
            ttl_required=True,
            two_person=False,
            reversible=True,
            may_de_energise=False,
        ),
        ActionSpec(
            "quarantine_node",
            frozenset({"participant_guid", "node"}),
            ttl_required=False,
            two_person=False,
            reversible=True,
            may_de_energise=False,
        ),
        ActionSpec(
            "isolate_network",
            frozenset(),
            ttl_required=True,
            two_person=False,
            reversible=True,
            may_de_energise=False,
        ),
        ActionSpec(
            "record_evidence",
            frozenset(),
            ttl_required=False,
            two_person=False,
            reversible=False,
            may_de_energise=False,
        ),
        ActionSpec(
            "safe_pause",
            frozenset(),
            ttl_required=False,
            two_person=True,
            reversible=True,
            may_de_energise=True,
        ),
        ActionSpec(
            "request_safe_state",
            frozenset(),
            ttl_required=False,
            two_person=True,
            reversible=False,
            may_de_energise=True,
        ),
        ActionSpec(
            "rollback_config",
            frozenset({"config", "to_version"}),
            ttl_required=False,
            two_person=True,
            reversible=False,
            may_de_energise=True,
        ),
    )
}
WIRE_PREFIX = "robot_"
MAX_TTL_SECONDS = 86400
MAX_SPEED_CAP = 10.0
MAX_REASON_CHARS = 500
DE_ENERGISE_MORPHOLOGIES = frozenset({"wheeled_mobile", "arm", "aerial", "other"})
"""The only snapshot morphologies a de-energising action is sent to. Anything
else (humanoid, quadruped, unspecified, missing, an unknown spelling) is
refused: an allow-list fails closed."""
QUADRUPED_REFUSED = frozenset({"rollback_config"})

# Always applied with `fullmatch`: `re.match` with `$` also accepts a
# trailing newline.
_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_ROBOT_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_NAME64_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SOURCE_RE = re.compile(r"[a-z0-9_-]{1,32}")
_GUID_RE = re.compile(r"[0-9a-f]{24}|[0-9a-f]{32}")
_ROS_SEGMENT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
_KEY_ID_RE = re.compile(r"[!-:<-~]{1,128}")  # printable ASCII except ';'
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}"
)
_MAX_IDENTITY_CHARS = 100
_APPROVER_NAME_RE = re.compile(r"[A-Za-z0-9._%+@-]{1,100}")
"""RoboDR's `approved_by` name grammar (§4; `approver_name_ok`)."""
MAX_APPROVER_NAMES = 4
"""Most names an `approved_by` list may carry (§4)."""

# Sign-off form (see the module docstring).
SIGNOFF_REQUEST_ID = "robodr_request_id"
SIGNOFF_DIGEST = "robodr_request_digest"
SIGNOFF_DECISION = "robodr_decision"
SIGNOFF_ROBOT_ID = "robodr_robot_id"
SIGNOFF_ACTION = "robodr_action"
MAX_SIGNOFF_AGE = timedelta(hours=24)
MAX_SIGNOFF_CLOCK_SKEW = timedelta(minutes=5)
MAX_APPROVAL_SUBMISSIONS = 4


class ControlPlaneError(RuntimeError):
    """The robot answered with an HTTP error or an unverifiable answer."""


class SignoffError(PermissionError):
    """The platform does not prove the sign-off this request needs."""


class ActionAuditError(PermissionError):
    """The platform did not audit-log a robot action, so it was not sent."""


def _full(pattern: re.Pattern[str], text: object) -> bool:
    return isinstance(text, str) and pattern.fullmatch(text) is not None


def wire_name(action: str) -> str:
    return f"{WIRE_PREFIX}{action}"


def resolve_action(action: str) -> ActionSpec:
    """Catalog entry for a wire name (`robot_safe_pause`) or a plain name."""
    if not isinstance(action, str):
        raise ValueError("action must be a string")
    name = action.removeprefix(WIRE_PREFIX)
    if name not in CATALOG:
        allowed = ", ".join(wire_name(n) for n in CATALOG)
        raise ValueError(f"unknown action {action!r}; allowed: {allowed}")
    return CATALOG[name]


def _ros_name_ok(name: object) -> bool:
    if not isinstance(name, str):
        return False
    body = name.removeprefix("/")
    segments = body.split("/")
    return (
        bool(body)
        and len(segments) <= 16
        and all(_full(_ROS_SEGMENT_RE, seg) for seg in segments)
    )


def _text_ok(text: object, max_chars: int) -> bool:
    return (
        isinstance(text, str)
        and len(text) <= max_chars
        and all(ch.isprintable() and ch not in "\x85  " for ch in text)
    )


def _shown(value: object) -> str:
    """A snapshot value safe to quote in a reason (it may reach a case)."""
    if value is None:
        return "missing"
    text = str(value)[:32]
    return "".join(
        c if c.isascii() and (c.isalnum() or c in "_-") else "?" for c in text
    )


def _policy_reasons(
    spec: ActionSpec,
    morphology: object,
    advertised_actions: object = None,
) -> list[str]:
    reasons: list[str] = []
    if spec.may_de_energise and morphology not in DE_ENERGISE_MORPHOLOGIES:
        reasons.append(
            f"{wire_name(spec.name)} may de-energise the robot and is sent only "
            "to a robot whose snapshot morphology is one of "
            f"{', '.join(sorted(DE_ENERGISE_MORPHOLOGIES))} "
            f"(morphology={_shown(morphology)}): a humanoid or legged robot "
            "falls, and an unknown morphology is refused"
        )
    if spec.name in QUADRUPED_REFUSED and morphology == "quadruped":
        reasons.append(
            "robot_rollback_config is never sent to a quadruped: a controller "
            "restart collapses a robot that balances actively"
        )
    if advertised_actions is not None and (
        not isinstance(advertised_actions, list) or spec.name not in advertised_actions
    ):
        reasons.append(f"the robot does not offer {spec.name} (snapshot `actions`)")
    return reasons


@registry.register(
    default_title="Check RoboDR action policy",
    description=(
        "Check a robot action against the SOC-side rules before it is "
        "prepared: catalog action, how many sign-offs it needs (single or "
        "two-person), and morphology (safe_pause, request_safe_state and "
        "rollback_config only for wheeled_mobile, arm, aerial or other; never "
        "rollback_config on a quadruped). Advisory: request_action enforces "
        "the same rules and the platform sign-off itself."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
)
def check_action_policy(
    action: Annotated[
        str,
        Doc("Catalog action, wire name (e.g. robot_restrict_motion) or plain name."),
    ],
    morphology: Annotated[
        str | None,
        Doc(
            "Robot morphology from the robot snapshot. De-energising actions "
            "need wheeled_mobile, arm, aerial or other; anything else is refused."
        ),
    ] = None,
    advertised_actions: Annotated[
        list[str] | None,
        Doc("The robot snapshot's `actions` list (plain names)."),
    ] = None,
) -> dict[str, Any]:
    try:
        spec = resolve_action(action)
    except ValueError as exc:
        return {
            "allowed": False,
            "action": action,
            "wire_name": None,
            "approval": None,
            "required_approvals": None,
            "reversible": None,
            "reasons": [str(exc)],
        }
    reasons = _policy_reasons(spec, morphology, advertised_actions)
    return {
        "allowed": not reasons,
        "action": spec.name,
        "wire_name": wire_name(spec.name),
        "approval": "two_person" if spec.two_person else "single",
        "required_approvals": 2 if spec.two_person else 1,
        "reversible": spec.reversible,
        "reasons": reasons,
    }


def _build_parameters(
    spec: ActionSpec,
    *,
    max_linear_speed: float | None,
    max_joint_speed: float | None,
    workspace_zone: str | None,
    participant_guid: str | None,
    node: str | None,
    config: str | None,
    to_version: str | None,
) -> dict[str, Any]:
    given: dict[str, Any] = {
        k: v
        for k, v in {
            "max_linear_speed": max_linear_speed,
            "max_joint_speed": max_joint_speed,
            "workspace_zone": workspace_zone,
            "participant_guid": participant_guid,
            "node": node,
            "config": config,
            "to_version": to_version,
        }.items()
        if v is not None
    }
    extra = sorted(set(given) - spec.params)
    if extra:
        raise ValueError(f"{spec.name} does not take parameter(s): {', '.join(extra)}")
    for key in ("max_linear_speed", "max_joint_speed"):
        if key in given:
            v = given[key]
            if (
                isinstance(v, bool)
                or not isinstance(v, int | float)
                or not math.isfinite(v)
                or not 0 < v <= MAX_SPEED_CAP
            ):
                raise ValueError(
                    f"{key} must be in (0, {MAX_SPEED_CAP}]; a cap of 0 is a stop, "
                    "request robot_safe_pause instead"
                )
            # One spelling for the digest and the body: 1 and 1.0 are the same cap.
            given[key] = float(v)
    if "workspace_zone" in given and not _full(_NAME64_RE, given["workspace_zone"]):
        raise ValueError("workspace_zone must match [A-Za-z0-9._-]{1,64}")
    if spec.name == "restrict_motion" and not given:
        raise ValueError(
            "restrict_motion needs max_linear_speed, max_joint_speed or workspace_zone"
        )
    if spec.name == "quarantine_node":
        if len(given) != 1:
            raise ValueError(
                "quarantine_node needs exactly one of participant_guid, node"
            )
        if "participant_guid" in given and not _full(
            _GUID_RE, given["participant_guid"]
        ):
            raise ValueError("participant_guid must be 24 or 32 lower-case hex")
        if "node" in given and not _ros_name_ok(given["node"]):
            raise ValueError("node must be a plain ROS 2 node name")
    if spec.name == "rollback_config":
        given.setdefault("config", "profile")
        if given["config"] not in ("profile", "program"):
            raise ValueError("config must be profile or program")
        if "to_version" in given and (
            not _full(_NAME64_RE, given["to_version"])
            or given["to_version"].startswith("-")
        ):
            raise ValueError(
                "to_version must match [A-Za-z0-9._-]{1,64} and not start with '-'"
            )
    return given


@dataclass(frozen=True)
class _PreparedAction:
    spec: ActionSpec
    robot_id: str
    request_id: str
    parameters: dict[str, Any]
    ttl_seconds: int | None
    reason: str
    source: str

    def digest_fields(self) -> dict[str, Any]:
        return {
            "robot_id": self.robot_id,
            "request_id": self.request_id,
            "action": self.spec.name,
            "parameters": self.parameters,
            "ttl_seconds": self.ttl_seconds,
            "reason": self.reason,
            "source": self.source,
        }


def _check_robot_id(robot_id: object) -> str:
    if not _full(_ROBOT_ID_RE, robot_id):
        raise ValueError("robot_id must match [A-Za-z0-9._-]{1,64}")
    return robot_id  # type: ignore[return-value]


def _check_request_id(request_id: object) -> str:
    if not _full(_ID_RE, request_id):
        raise ValueError("request_id must match [A-Za-z0-9._:-]{1,128}")
    return request_id  # type: ignore[return-value]


def _check_reason(reason: object) -> str:
    if not _text_ok(reason, MAX_REASON_CHARS):
        raise ValueError(
            "reason must be at most 500 characters without control characters"
        )
    return reason  # type: ignore[return-value]


def _prepare_action(
    *,
    robot_id: str,
    action: str,
    reason: str,
    source: str,
    ttl_seconds: int | None,
    request_id: str | None,
    max_linear_speed: float | None,
    max_joint_speed: float | None,
    workspace_zone: str | None,
    participant_guid: str | None,
    node: str | None,
    config: str | None,
    to_version: str | None,
) -> _PreparedAction:
    spec = resolve_action(action)
    _check_robot_id(robot_id)
    _check_reason(reason)
    if not _full(_SOURCE_RE, source):
        raise ValueError("source must match [a-z0-9_-]{1,32}")
    if ttl_seconds is not None and (
        isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int)
    ):
        raise ValueError("ttl_seconds must be an integer")
    if spec.ttl_required:
        if ttl_seconds is None or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError(f"{spec.name} needs ttl_seconds in 1..{MAX_TTL_SECONDS}")
    elif ttl_seconds is not None:
        raise ValueError(f"{spec.name} does not take ttl_seconds")
    parameters = _build_parameters(
        spec,
        max_linear_speed=max_linear_speed,
        max_joint_speed=max_joint_speed,
        workspace_zone=workspace_zone,
        participant_guid=participant_guid,
        node=node,
        config=config,
        to_version=to_version,
    )
    if request_id is None:
        request_id = f"{wire_name(spec.name)}:{robot_id}:{pysecrets.token_hex(8)}"
    _check_request_id(request_id)
    return _PreparedAction(
        spec, robot_id, request_id, parameters, ttl_seconds, reason, source
    )


def request_digest(kind: str, fields: dict[str, Any]) -> str:
    """SHA-256 (hex) of the canonical JSON of what a sign-off approves."""
    doc = {"api": API_VERSION, "kind": kind, **fields}
    canonical = json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- #
# Platform sign-off
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Person:
    """A platform user, as the platform recorded them."""

    user_id: str
    email: str | None

    @property
    def identifier(self) -> str:
        """ASCII identifier: the email when it is a plain ASCII address."""
        if (
            self.email is not None
            and len(self.email) <= _MAX_IDENTITY_CHARS
            and _full(_EMAIL_RE, self.email)
        ):
            return self.email
        return f"user:{self.user_id}"

    @property
    def approver_name(self) -> str:
        """The name the robot's `approved_by` carries for this person (§4).

        Always ``user-<user id>``: the platform user id cannot change, while
        a user can change their own email, so the robot's black box and the
        platform audit name the approver the same way for good. RoboDR's
        approver grammar ``[A-Za-z0-9._%+@-]{1,100}`` has no ``:``, hence not
        the ``user:`` spelling of :attr:`identifier`.
        """
        return f"user-{self.user_id}"

    def as_dict(self) -> dict[str, str]:
        return {"user_id": self.user_id, "id": self.identifier}


def _submission_uuid(value: object) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        return str(uuid.UUID(value))
    except ValueError:
        raise SignoffError(
            f"sign-off submission ids must be form submission UUIDs, got {_shown(value)!r}"
        ) from None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


async def _collect_signoff(
    *,
    request_id: str,
    digest: str,
    robot_id: str,
    action: str | None,
    request_submission_id: object,
    approval_submission_ids: object,
) -> tuple[Person, list[Person]]:
    """Read the sign-off submissions from the platform and check them.

    ``action`` is the catalog wire name a request's sign-off names; ``None``
    for a revert, whose sign-off names the robot only (the action it undoes
    is the robot's stored request).

    Returns the requester and the approvers (distinct platform users, none of
    them the requester). The number of approvals is checked by the caller.
    """
    if not isinstance(approval_submission_ids, list):
        raise SignoffError("approval_submission_ids must be a list of submission ids")
    if len(approval_submission_ids) > MAX_APPROVAL_SUBMISSIONS:
        raise SignoffError(
            f"at most {MAX_APPROVAL_SUBMISSIONS} approval submissions are read"
        )
    request_sid = _submission_uuid(request_submission_id)
    approval_sids = [_submission_uuid(s) for s in approval_submission_ids]
    all_sids = [request_sid, *approval_sids]
    if len(set(all_sids)) != len(all_sids):
        raise SignoffError("a sign-off submission is used more than once")
    try:
        forms = get_context().forms
    except RuntimeError as exc:
        raise SignoffError(
            "sign-off submissions are not readable: no AutoSecOps run context "
            "(request_action and revert_action only run inside a workflow or "
            "agent run)"
        ) from exc

    now = datetime.now(UTC)
    form_id: str | None = None
    people: list[Person] = []
    for sid, decision in [(request_sid, "request")] + [
        (s, "approve") for s in approval_sids
    ]:
        try:
            record = await forms.get_submission(sid)
        except Exception as exc:  # fail closed on any SDK or API error
            raise SignoffError(
                f"sign-off submission {sid} is not readable ({type(exc).__name__})"
            ) from exc
        if not isinstance(record, dict) or str(record.get("id", "")).lower() != sid:
            raise SignoffError(f"sign-off submission {sid} is not readable")
        actor = record.get("submitted_by")
        if not isinstance(actor, dict) or actor.get("type") != "user":
            raise SignoffError(f"submission {sid} was not submitted by a platform user")
        try:
            user_id = str(uuid.UUID(str(actor.get("id"))))
        except ValueError:
            raise SignoffError(
                f"submission {sid} was not submitted by a platform user"
            ) from None
        this_form = str(record.get("form_id"))
        if form_id is None:
            form_id = this_form
        elif this_form != form_id:
            raise SignoffError("all sign-off submissions must come from the same form")
        answers = record.get("answers")
        if not isinstance(answers, dict):
            raise SignoffError(f"submission {sid} carries no sign-off answers")
        if answers.get(SIGNOFF_REQUEST_ID) != request_id:
            raise SignoffError(f"submission {sid} is for another request_id")
        if answers.get(SIGNOFF_DIGEST) != digest:
            raise SignoffError(
                f"submission {sid} does not carry this request's digest: the "
                "request differs from what was signed off"
            )
        if answers.get(SIGNOFF_ROBOT_ID) != robot_id:
            raise SignoffError(f"submission {sid} does not sign off robot {robot_id}")
        if action is not None and answers.get(SIGNOFF_ACTION) != action:
            raise SignoffError(f"submission {sid} does not sign off {action}")
        if answers.get(SIGNOFF_DECISION) != decision:
            raise SignoffError(
                f"submission {sid} must have {SIGNOFF_DECISION}={decision!r}"
            )
        submitted_at = _parse_time(record.get("submitted_at"))
        if submitted_at is None:
            raise SignoffError(f"submission {sid} has no submission time")
        if submitted_at > now + MAX_SIGNOFF_CLOCK_SKEW:
            raise SignoffError(f"submission {sid} is dated in the future")
        if now - submitted_at > MAX_SIGNOFF_AGE:
            raise SignoffError(f"submission {sid} is older than 24 hours")
        email = actor.get("email")
        people.append(Person(user_id, email if isinstance(email, str) else None))

    requester, approvers = people[0], people[1:]
    if any(a.user_id == requester.user_id for a in approvers):
        raise SignoffError("the requester cannot approve their own request")
    if len({a.user_id for a in approvers}) != len(approvers):
        raise SignoffError("each approval must come from a different platform user")
    return requester, approvers


def _require_approvals(label: str, required: int, approvers: list[Person]) -> None:
    if len(approvers) < required:
        raise SignoffError(
            f"{label} needs {required} approval(s) from platform users other "
            f"than the requester; got {len(approvers)}"
        )


def approved_by_names(requester: Person, approvers: list[Person]) -> list[str]:
    """The `approved_by` names of a two-person request or revert body (§4).

    The executor carries out `safe_pause`, `request_safe_state` and
    `rollback_config` (and lifts a `safe_pause`) only when the signed body
    names at least two different people, neither the requester, comparing
    names ASCII case-insensitively (the requester's trimmed `requested_by`
    too). The names come from the sign-off submitters only. A name the robot
    would refuse, or two people the robot would count as one, refuse the
    call here, before the request or revert is signed.

    Raises:
        SignoffError: A name does not fit RoboDR's grammar, two approvers
            share a name, or an approver's name is the requester's.
    """
    if len(approvers) > MAX_APPROVER_NAMES:
        raise SignoffError(
            f"the robot takes at most {MAX_APPROVER_NAMES} approvers (approved_by)"
        )
    names = [person.approver_name for person in approvers]
    for person, name in zip(approvers, names, strict=True):
        if not _full(_APPROVER_NAME_RE, name):
            raise SignoffError(
                f"approver {person.user_id} has no name the robot accepts "
                "(approved_by: 1-100 characters of [A-Za-z0-9._%+@-])"
            )
    folded = [name.lower() for name in names]
    if requester.identifier.strip().lower() in folded:
        raise SignoffError(
            "an approver's name equals the requester's (compared "
            "case-insensitively): the robot would not count that approval"
        )
    if len(set(folded)) != len(folded):
        raise SignoffError(
            "two approvers have the same name compared case-insensitively: the "
            "robot would count them as one person"
        )
    return names


def _robot_approvers(
    spec: ActionSpec,
    snapshot: dict[str, Any],
    requester: Person,
    approvers: list[Person],
) -> list[str]:
    """The `approved_by` names this body carries; empty when it carries none.

    Only a two-person action names its approvers, and only to a robot whose
    signed snapshot says its executor carries out actions
    (`executes_actions: true`): without an executor the robot records the
    request as a plan, and an agentd older than the motion adapters
    revision refuses the field (strict bodies). Single-approval bodies are
    unchanged.
    """
    if not spec.two_person or snapshot.get("executes_actions") is not True:
        return []
    return approved_by_names(requester, approvers)


_AUDIT_OUTCOME_RE = re.compile(r"[a-z_]{1,64}")
_AUDIT_LOG_RESULTS = frozenset({"written", "no_sink", "queued", "failed"})

# Strong refs to outcome records that must outlive a cancelled call.
_RECORDS_IN_FLIGHT: set[asyncio.Task[Any]] = set()


def _audit_log(answer: object) -> str:
    """What the platform says became of an audit event.

    ``written``: the configured audit sink confirmed it. ``no_sink``: no sink
    is configured, so only the platform's own log has it. ``queued`` or
    ``failed``: a best-effort event was handed to delivery, or was not.
    ``unconfirmed``: the platform did not say (an older API version).
    """
    if isinstance(answer, dict) and answer.get("audit_log") in _AUDIT_LOG_RESULTS:
        return str(answer["audit_log"])
    return "unconfirmed"


async def _record_shielded(coro: Any) -> str:
    """Await an outcome record that a cancellation of the caller cannot stop.

    The record runs on its own task; if the caller is cancelled (again)
    while waiting, the record still completes and the cancellation goes on.
    """
    task: asyncio.Task[str] = asyncio.ensure_future(coro)
    _RECORDS_IN_FLIGHT.add(task)
    task.add_done_callback(_RECORDS_IN_FLIGHT.discard)
    return await asyncio.shield(task)


@dataclass
class _ActionAudit:
    """What the platform audit log records for one robot action call."""

    robot_id: str
    request_id: str
    operation: RobotActionOperation
    robot_action: str
    request_digest: str
    request_submission_id: str
    approval_submission_ids: list[str]
    requested_by_name: str
    """The `requested_by` the body sends; the platform checks and records it."""
    approved_by_names: list[str]
    """The `approved_by` the body sends (empty: none); checked and recorded."""
    attempt_id: str | None = None
    """The platform's stored attempt, which the outcome event cites."""

    async def attempt(self) -> str:
        """Record the call before the request is signed and sent.

        Fails closed: a robot action the platform does not record (no run
        context, the route refused, the audit sink did not confirm it) is
        not sent. The platform checks the sign-off submissions itself, names
        the run that acted and reads the requester and approvers from them.

        Returns:
            The audit log result (see :func:`_audit_log`).
        """
        try:
            answer = await self._record(
                phase="attempt",
                requested_by_name=self.requested_by_name,
                approved_by_names=self.approved_by_names,
            )
        except Exception as exc:
            raise ActionAuditError(
                f"the platform did not audit-log this {self.operation} "
                f"({type(exc).__name__}: {exc}); nothing was sent to the robot"
            ) from exc
        if isinstance(answer, dict) and isinstance(answer.get("attempt_id"), str):
            self.attempt_id = answer["attempt_id"]
        return _audit_log(answer)

    async def answered(self, outcome: dict[str, Any]) -> str:
        """Record the robot's answer; best effort, as the robot already acted."""
        status = outcome.get("status")
        applied = outcome.get("applied")
        return await self._after(
            phase="answered",
            outcome=status if _full(_AUDIT_OUTCOME_RE, status) else None,
            applied=applied if isinstance(applied, bool) else None,
        )

    async def failed(self, exc: BaseException) -> str:
        """Record that the call failed after the attempt; best effort.

        Completes even when the call was cancelled: the request may have
        reached the robot.
        """
        return await _record_shielded(
            self._after(phase="failed", failure_reason=type(exc).__name__)
        )

    async def _after(self, **fields: Any) -> str:
        try:
            return _audit_log(await self._record(**fields))
        except Exception:
            return "failed"

    async def _record(self, **fields: Any) -> Any:
        return await get_context().robot_edr.record_robot_action(
            robot_id=self.robot_id,
            request_id=self.request_id,
            operation=self.operation,
            robot_action=self.robot_action,
            request_digest=self.request_digest,
            request_submission_id=self.request_submission_id,
            approval_submission_ids=self.approval_submission_ids,
            attempt_id=self.attempt_id,
            **fields,
        )


def _audit_fields(attempt_log: str, outcome_log: str) -> dict[str, Any]:
    """The audit results a robot action reports."""
    return {
        "audit_logged": attempt_log == "written",
        "audit_log": attempt_log,
        "outcome_audit_logged": outcome_log == "written",
        "outcome_audit_log": outcome_log,
    }


# --------------------------------------------------------------------------- #
# Request signing and answer signatures (§2)
# --------------------------------------------------------------------------- #


def signing_message(
    method: str,
    target: str,
    robot_id: str,
    key_id: str,
    timestamp: int,
    nonce: str,
    body: bytes,
) -> bytes:
    """The bytes a SOC signs for one request (robodr.control-plane §2)."""
    digest = hashlib.sha256(body).hexdigest()
    return (
        f"{API_VERSION}\n{method}\n{target}\n{robot_id}\n{key_id}\n"
        f"{timestamp}\n{nonce}\n{digest}"
    ).encode()


def answer_message(request_signature_hex: str, status: int, body: bytes) -> bytes:
    """The bytes a robot signs for an answer (robodr.control-plane §2)."""
    digest = hashlib.sha256(body).hexdigest()
    return f"{ANSWER_DOMAIN}\n{request_signature_hex}\n{status}\n{digest}".encode()


def request_bytes(
    *,
    method: str,
    target: str,
    host: str,
    key_id: str,
    timestamp: int,
    nonce: str,
    signature_hex: str,
    body: bytes,
) -> bytes:
    """The exact HTTP/1.1 request bytes (§1), as the contract vectors send them."""
    head = (
        f"{method} {target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-RoboDR-Key-Id: {key_id}\r\n"
        f"X-RoboDR-Timestamp: {timestamp}\r\n"
        f"X-RoboDR-Nonce: {nonce}\r\n"
        f"X-RoboDR-Signature: {signature_hex}\r\n"
        "\r\n"
    )
    return head.encode("ascii") + body


def body_bytes(document: dict[str, Any]) -> bytes:
    """Compact JSON with sorted keys, the form the contract vectors use."""
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _signing_key() -> tuple[str, Ed25519PrivateKey]:
    key_id = secrets.get("ROBODR_SOC_KEY_ID")
    secret_hex = secrets.get("ROBODR_SOC_SECRET_HEX")
    if not _full(_KEY_ID_RE, key_id):
        raise ValueError("ROBODR_SOC_KEY_ID must be 1..128 printable ASCII without ';'")
    seed = parse_public_key_hex(secret_hex or "")
    if seed is None:
        raise ValueError("ROBODR_SOC_SECRET_HEX must be a 64-hex-digit Ed25519 seed")
    return key_id, Ed25519PrivateKey.from_private_bytes(seed)


def _client_identity() -> tuple[str, str]:
    cert_pem = secrets.get("ROBODR_SOC_CLIENT_CERT_PEM")
    key_pem = secrets.get("ROBODR_SOC_CLIENT_KEY_PEM")
    if not cert_pem or "-----BEGIN CERTIFICATE-----" not in cert_pem:
        raise ValueError("ROBODR_SOC_CLIENT_CERT_PEM must be a PEM certificate chain")
    if not key_pem or "PRIVATE KEY-----" not in key_pem:
        raise ValueError("ROBODR_SOC_CLIENT_KEY_PEM must be a PEM private key")
    return cert_pem, key_pem


def _robot_target(robot_id: str, *rest: str) -> str:
    _check_robot_id(robot_id)
    parts = [API_PREFIX, quote(robot_id, safe="")]
    parts += [quote(p, safe="") for p in rest]
    return "/".join(parts)


# --------------------------------------------------------------------------- #
# Mutual TLS transport (§1)
# --------------------------------------------------------------------------- #

_SPKI_RE = re.compile(r"[0-9a-f]{64}")
_ASCII_UINT_RE = re.compile(r"[0-9]{1,18}")


def _ascii_uint(text: str | None) -> int | None:
    """A decimal of ASCII digits only (``str.isdigit`` also takes ``²``, ``٣``)."""
    if text is None or _ASCII_UINT_RE.fullmatch(text) is None:
        return None
    return int(text)


@dataclass(frozen=True, slots=True)
class _Robot:
    """Where and how to reach one robot, checked before anything is sent."""

    robot_id: str
    host: str
    port: int
    host_header: str
    ca_pem: str
    spki_sha256: str | None
    answer_key: bytes
    answer_key_id: str | None


def _robot(
    *,
    base_url: object,
    robot_id: object,
    robot_ca_pem: object,
    robot_spki_sha256: object,
    answer_public_key_hex: object,
    answer_key_id: object,
) -> _Robot:
    """Validate the connection inputs (https only, no path; §1)."""
    rid = _check_robot_id(robot_id)
    if not isinstance(base_url, str) or any(not "!" <= c <= "~" for c in base_url):
        raise ValueError("base_url must be https://host[:port] in printable ASCII")
    try:
        parts = urlsplit(base_url)
        port = parts.port or 443
    except ValueError as exc:
        raise ValueError(f"base_url is not a valid URL: {exc}") from exc
    if parts.scheme != "https":
        raise ValueError("base_url must be https: the robot only speaks mutual TLS")
    host = parts.hostname
    if not host or parts.username is not None or parts.password is not None:
        raise ValueError("base_url must be https://host[:port] without credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(
            "base_url must not carry a path or query: robodr-agentd serves "
            "/api/v2 at the root and the signature covers the target as sent"
        )
    if not isinstance(robot_ca_pem, str) or "-----BEGIN CERTIFICATE-----" not in (
        robot_ca_pem
    ):
        raise ValueError("robot_ca_pem must be the robot CA certificate(s) in PEM")
    pin = robot_spki_sha256.lower() if isinstance(robot_spki_sha256, str) else None
    if robot_spki_sha256 is not None and not _full(_SPKI_RE, pin):
        raise ValueError("robot_spki_sha256 must be 64 hex digits")
    key = (
        parse_public_key_hex(answer_public_key_hex)
        if isinstance(answer_public_key_hex, str)
        else None
    )
    if key is None:
        raise ValueError(
            "answer_public_key_hex is required (64 hex): every answer must carry "
            "the robot's answer signature"
        )
    if answer_key_id is not None and not _full(_KEY_ID_RE, answer_key_id):
        raise ValueError("answer_key_id must be 1..128 printable ASCII without ';'")
    netloc = f"[{host}]" if ":" in host else host
    host_header = netloc if parts.port is None else f"{netloc}:{port}"
    return _Robot(
        robot_id=rid,
        host=host,
        port=port,
        host_header=host_header,
        ca_pem=robot_ca_pem,
        spki_sha256=pin,
        answer_key=key,
        answer_key_id=answer_key_id if isinstance(answer_key_id, str) else None,
    )


def _tls_context(robot: _Robot, cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """TLS 1.2+ client context: robot CA only, hostname checked, SOC client cert."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cadata=robot.ca_pem)
    except ssl.SSLError as exc:
        raise ValueError("robot_ca_pem is not a valid PEM certificate") from exc
    _load_client_identity(context, cert_pem, key_pem)
    return context


def _load_client_identity(context: ssl.SSLContext, cert_pem: str, key_pem: str) -> None:
    """Load the SOC client certificate and key without a file on disk.

    `ssl` loads a client identity only from paths. Linux: the PEMs go to
    anonymous memory files (`memfd_create`), loaded through
    ``/proc/self/fd/N``; they have no name in any file system, so nothing is
    left behind even if the process is killed. Elsewhere: a private (0700)
    temporary directory, on tmpfs (``/dev/shm``) where there is one, removed
    as soon as the identity is loaded.
    """
    try:
        _load_identity_from_memfd(context, cert_pem, key_pem)
        return
    except (AttributeError, OSError):  # no memfd_create or no /proc
        pass
    tmpfs = "/dev/shm" if os.path.isdir("/dev/shm") else None
    with tempfile.TemporaryDirectory(prefix="robodr-tls-", dir=tmpfs) as directory:
        cert_path = os.path.join(directory, "client.crt")
        key_path = os.path.join(directory, "client.key")
        for path, text in ((cert_path, cert_pem), (key_path, key_pem)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(text)
        _load_cert_chain(context, cert_path, key_path)


def _load_identity_from_memfd(
    context: ssl.SSLContext, cert_pem: str, key_pem: str
) -> None:
    fds: list[int] = []
    try:
        for name, text in (("robodr-tls-crt", cert_pem), ("robodr-tls-key", key_pem)):
            fd = os.memfd_create(name, os.MFD_CLOEXEC)
            fds.append(fd)
            data = text.encode("ascii")
            written = 0
            while written < len(data):
                written += os.write(fd, data[written:])
        paths = [f"/proc/self/fd/{fd}" for fd in fds]
        if not all(os.path.exists(path) for path in paths):
            raise OSError("no /proc/self/fd")
        _load_cert_chain(context, paths[0], paths[1])
    finally:
        for fd in fds:
            os.close(fd)


def _load_cert_chain(context: ssl.SSLContext, cert_path: str, key_path: str) -> None:
    try:
        context.load_cert_chain(cert_path, key_path)
    except ssl.SSLError as exc:
        raise ValueError(
            "the SOC client certificate and key do not load (unencrypted "
            "PEM key matching the certificate required)"
        ) from exc


def _der_element(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, start of contents, end) of the DER element at ``pos``."""
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if not 0 < count <= 4 or pos + count > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("truncated DER")
    return tag, pos, pos + length


def certificate_spki(certificate_der: bytes) -> bytes:
    """The certificate's SubjectPublicKeyInfo exactly as encoded in it.

    The bytes are cut out of the certificate, never re-encoded: re-encoding
    the public key (as `cryptography` would) can change it, e.g. an EC key
    stored as a compressed point comes back uncompressed. robodr-agentd pins
    these raw bytes too (`webpki` `subject_public_key_info`, control/tls.rs).

    Raises:
        ValueError: The DER is not an X.509 certificate.
    """
    seq = 0x30
    tag, start, end = _der_element(certificate_der, 0)
    if tag != seq or end != len(certificate_der):
        raise ValueError("not a DER certificate")
    tag, pos, tbs_end = _der_element(certificate_der, start)  # tbsCertificate
    if tag != seq:
        raise ValueError("not a DER certificate")
    if certificate_der[pos] == 0xA0:  # [0] EXPLICIT version
        pos = _der_element(certificate_der, pos)[2]
    # serialNumber, signature, issuer, validity, subject: skip five elements.
    for _ in range(5):
        pos = _der_element(certificate_der, pos)[2]
    tag, _, spki_end = _der_element(certificate_der, pos)
    if tag != seq or spki_end > tbs_end:
        raise ValueError("not a DER certificate")
    return certificate_der[pos:spki_end]


def spki_sha256(certificate_der: bytes) -> str:
    """Lower-case hex SHA-256 of a certificate's DER SubjectPublicKeyInfo."""
    return hashlib.sha256(certificate_spki(certificate_der)).hexdigest()


@dataclass(frozen=True, slots=True)
class RawAnswer:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def header(self, name: str) -> str | None:
        """The header's value; None when absent or present more than once."""
        values = [v for k, v in self.headers if k.lower() == name.lower()]
        return values[0] if len(values) == 1 else None


ERROR_EXPLANATIONS: dict[str, str] = {
    "busy": (
        "the robot is busy: every authenticated connection slot is taken, its "
        "main loop is full or stopping, or it did not answer in time (a "
        "submission may still have been recorded). Retry later with the same "
        "request_id: the robot then judges it once or answers it as a duplicate"
    ),
    "rate_limited": "too many requests for this SOC key; retry later",
    "stale_timestamp": (
        "the robot refuses the request's timestamp. Right after the robot "
        "created its replay store (first start, or a wiped state directory) or "
        "after its clock went back it refuses every request for "
        "max_clock_skew_s (default 30 s): retry later. If it persists, the SOC "
        "or robot clock is off: check NTP on both"
    ),
    "replayed_nonce": "the robot already saw this request's nonce; nothing was done",
    "bad_signature": (
        "the robot did not accept the SOC request signature; check "
        "ROBODR_SOC_KEY_ID / ROBODR_SOC_SECRET_HEX and the robot_id"
    ),
    "unknown_key": (
        "the robot does not know the SOC key id; install its .pub under the "
        "robot's control_plane.soc_keys"
    ),
    "missing_credentials": "the robot did not receive the request credentials",
    "malformed_credentials": "the robot could not parse the request credentials",
    "unknown_robot": "the robot is configured with another robot_id",
    "unknown_request": (
        "the robot does not know this request_id (never sent, or older than "
        "the newest requests it keeps)"
    ),
    "request_id_conflict": (
        "this request_id was already used for a different request; prepare a "
        "new request"
    ),
    "state_unavailable": (
        "the robot's request journal cannot take or reconcile this request "
        "(journal damage); nothing was judged. Retry after an operator "
        "restarted the robot's agent so it reconciles its journal"
    ),
    "replay_cache_full": (
        "the robot's replay store is full of live nonces; nothing was done, retry later"
    ),
    "replay_store_unavailable": (
        "the robot cannot persist the request nonce; nothing was done. An "
        "operator must check the robot's control-plane state directory"
    ),
    "clock_unavailable": "the robot cannot read its clock; nothing was done",
    "evidence_busy": "another evidence index or export runs on the robot; retry shortly",
    "evidence_timeout": (
        "the robot could not build the export within 60 s (or is stopping); "
        "nothing was kept. Select fewer records"
    ),
    "evidence_unavailable": "the robot's black box cannot be read now",
    "evidence_disabled": "the robot's evidence API is not configured",
    "storage_full": (
        "the robot's export storage is full or its state directory has less "
        "than 64 MiB free; delete downloaded exports (delete_after_download) "
        "or ask an operator to free space"
    ),
    "export_too_large": (
        "the selection exceeds the robot's max_export_bytes (at most 256 MiB); "
        "select fewer records"
    ),
    "export_limit": "the robot keeps its maximum number of exports; delete one",
    "export_id_conflict": "this export_id was used for another selection",
    "export_corrupt": (
        "the robot's stored export no longer matched its manifest and was "
        "deleted; create it again"
    ),
    "unknown_export": "the robot does not keep this export (expired or deleted)",
    "no_records": "the selection matches no black-box records",
    "evidence_not_retained": "the selected records are no longer retained",
    "evidence_gap": "the selection spans a gap in the robot's black box",
    "evidence_mismatch": "the evidence links do not match the robot's records",
    "answer_signing_failed": "the robot could not sign its answer; nothing in it is used",
    "unknown_field": (
        "the robot refused a body field it does not know; nothing was judged. "
        "An agentd older than the motion adapters revision does not take "
        "approved_by, which AutoSecOps sends for safe_pause, "
        "request_safe_state, rollback_config and their reverts: upgrade the "
        "robot's executor, then its agentd"
    ),
    "invalid_field": (
        "the robot refused a body field (reason, requested_by, source or "
        "approved_by) as malformed; nothing was judged"
    ),
}
"""What each robot error code means for the person running the action (§7)."""


class RobotHTTPError(ControlPlaneError):
    """The robot answered with an HTTP error (signed or not)."""

    def __init__(
        self,
        status: int,
        code: str | None,
        message: str,
        *,
        signed: bool,
        attempts: int = 1,
    ) -> None:
        self.status = status
        self.code = code
        self.signed = signed
        self.retry_after: int | None = None
        self.raw_message = message
        self.attempts = attempts
        self.explanation = ERROR_EXPLANATIONS.get(code or "")
        origin = "signed by the robot" if signed else "UNSIGNED: not from the robot"
        text = (
            f"robot answered HTTP {status} ({_shown(code) if code else 'no error code'}, "
            f"{origin}): {message}"
        )
        if self.explanation:
            text += f". Meaning: {self.explanation}"
        if attempts > 1:
            text += f" (after {attempts} attempts)"
        super().__init__(text)

    @property
    def fenced(self) -> bool:
        """The robot refused the timestamp (its replay fence, or clock skew)."""
        return self.status == 401 and self.code == "stale_timestamp"

    def retryable(self, busy_codes: tuple[str, ...]) -> bool:
        """A signed 429, or a signed 503 with one of ``busy_codes``."""
        return self.signed and (
            self.status == 429 or (self.status == 503 and self.code in busy_codes)
        )


def parse_answer(raw: bytes, *, max_body: int) -> RawAnswer:
    """Parse one HTTP/1.1 answer read until the robot closed the connection."""
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep or len(head) > MAX_ANSWER_HEAD_BYTES:
        raise ControlPlaneError("the robot's answer has no valid HTTP head")
    lines = head.decode("latin-1").split("\r\n")
    status_line = lines[0].split(" ", 2)
    if len(status_line) < 2 or status_line[0] not in ("HTTP/1.1", "HTTP/1.0"):
        raise ControlPlaneError("the robot's answer has no HTTP status line")
    status = _ascii_uint(status_line[1]) if len(status_line[1]) == 3 else None
    if status is None:
        raise ControlPlaneError("the robot's answer has an invalid status")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not name or name != name.strip():
            raise ControlPlaneError("the robot's answer has a malformed header")
        headers.append((name, value.strip()))
    answer = RawAnswer(status, tuple(headers), b"")
    if answer.header("Transfer-Encoding") is not None or any(
        k.lower() == "transfer-encoding" for k, _ in headers
    ):
        raise ControlPlaneError("the robot's answer uses a transfer encoding")
    lengths = [v for k, v in headers if k.lower() == "content-length"]
    length = _ascii_uint(lengths[0]) if len(lengths) == 1 else None
    if len(lengths) > 1 or (lengths and length is None):
        raise ControlPlaneError("the robot's answer has an invalid Content-Length")
    if length is not None:
        if length > max_body:
            raise ControlPlaneError(f"the robot's answer exceeds {max_body} bytes")
        if len(rest) != length:
            raise ControlPlaneError("the robot's answer is truncated")
    elif len(rest) > max_body:
        raise ControlPlaneError(f"the robot's answer exceeds {max_body} bytes")
    return RawAnswer(answer.status, answer.headers, rest)


async def _read_capped(reader: asyncio.StreamReader, limit: int) -> bytes:
    """Read until EOF, refusing as soon as more than ``limit`` bytes arrive."""
    chunks: list[bytes] = []
    size = 0
    while chunk := await reader.read(64 * 1024):
        size += len(chunk)
        if size > limit:
            raise ControlPlaneError(f"the robot's answer exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


async def _exchange(robot: _Robot, request: bytes, *, max_body: int) -> RawAnswer:
    """One request on one mutual-TLS connection (`Connection: close`, §1)."""
    cert_pem, key_pem = _client_identity()
    context = _tls_context(robot, cert_pem, key_pem)
    async with asyncio.timeout(REQUEST_TIMEOUT_S):
        reader, writer = await asyncio.open_connection(
            robot.host,
            robot.port,
            ssl=context,
            server_hostname=robot.host,
            ssl_handshake_timeout=HANDSHAKE_TIMEOUT_S,
        )
        try:
            if robot.spki_sha256 is not None:
                ssl_object = writer.get_extra_info("ssl_object")
                der = (
                    ssl_object.getpeercert(binary_form=True)
                    if isinstance(ssl_object, ssl.SSLObject)
                    else None
                )
                if der is None or spki_sha256(der) != robot.spki_sha256:
                    raise ControlPlaneError(
                        "the robot's server certificate does not match "
                        "robot_spki_sha256; nothing was sent"
                    )
            writer.write(request)
            await writer.drain()
            raw = await _read_capped(reader, max_body + MAX_ANSWER_HEAD_BYTES)
        except BaseException:
            # Drop the connection at once: a graceful TLS close would wait
            # for a robot that is still sending (or stalling).
            writer.transport.abort()
            raise
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass
    return parse_answer(raw, max_body=max_body)


@dataclass(frozen=True, slots=True)
class SignedAnswer:
    """An answer whose `X-RoboDR-Answer-Signature` verified."""

    status: int
    body: bytes
    raw: RawAnswer

    def json(self) -> dict[str, Any]:
        try:
            data = json.loads(self.body)
        except ValueError as exc:
            raise ControlPlaneError("the robot's answer is not JSON") from exc
        if not isinstance(data, dict):
            raise ControlPlaneError("the robot's answer is not a JSON object")
        return data


def verify_answer(robot: _Robot, request_signature_hex: str, raw: RawAnswer) -> bool:
    """Whether the answer carries a valid answer signature for this request."""
    header = raw.header("X-RoboDR-Answer-Signature")
    parsed = parse_signature_header(header) if header else None
    if parsed is None:
        return False
    key_id, signature = parsed
    if robot.answer_key_id is not None and key_id != robot.answer_key_id:
        return False
    message = answer_message(request_signature_hex, raw.status, raw.body)
    return ed25519_verify_strict(robot.answer_key, message, signature)


def _error_of(body: bytes) -> tuple[str | None, str]:
    try:
        data = json.loads(body) if body else None
    except ValueError:
        data = None
    match data:
        case {"error": {"code": str(code), "message": str(message)}}:
            return code, message[:300]
        case {"error": {"code": str(code)}}:
            return code, "no message"
        case _:
            return None, "no message"


async def _call(
    robot: _Robot,
    method: str,
    target: str,
    body: bytes = b"",
    *,
    ok: tuple[int, ...] = (200,),
    max_body: int = MAX_ANSWER_BYTES,
) -> SignedAnswer:
    """Sign, send and verify one request; raise unless a signed `ok` answer."""
    key_id, private_key = _signing_key()
    timestamp = int(time.time())
    nonce = pysecrets.token_urlsafe(24)
    signature_hex = private_key.sign(
        signing_message(method, target, robot.robot_id, key_id, timestamp, nonce, body)
    ).hex()
    request = request_bytes(
        method=method,
        target=target,
        host=robot.host_header,
        key_id=key_id,
        timestamp=timestamp,
        nonce=nonce,
        signature_hex=signature_hex,
        body=body,
    )
    raw = await _exchange(robot, request, max_body=max_body)
    signed = verify_answer(robot, signature_hex, raw)
    if raw.status not in ok:
        code, message = _error_of(raw.body)
        error = RobotHTTPError(raw.status, code, message, signed=signed)
        retry_after = _ascii_uint(raw.header("Retry-After"))
        if signed and retry_after is not None:
            error.retry_after = retry_after
        raise error
    if not signed:
        raise ControlPlaneError(
            "the answer carries no valid answer signature from the robot's "
            "finding key: it is not taken as the robot's answer"
        )
    return SignedAnswer(raw.status, raw.body, raw)


async def _call_retrying(
    robot: _Robot,
    method: str,
    target: str,
    body: bytes = b"",
    *,
    ok: tuple[int, ...] = (200,),
    busy_codes: tuple[str, ...] = ("busy",),
) -> SignedAnswer:
    """`_call`, signed afresh and sent again while the robot is busy or fenced.

    Retried: a signed 429, a signed 503 with one of ``busy_codes`` (§7: the
    identical request with a fresh nonce is judged once or answered as a
    duplicate) and 401 `stale_timestamp` (the replay fence after the robot
    created its replay store, §2: nothing was done). Pass ``busy_codes=()``
    for a call that must not be resent after `busy`.
    """
    delay = 1.0
    for attempt in range(1, CALL_ATTEMPTS + 1):
        try:
            return await _call(robot, method, target, body, ok=ok)
        except RobotHTTPError as exc:
            if attempt < CALL_ATTEMPTS and exc.fenced:
                wait = FENCE_RETRY_WAIT_S
            elif attempt < CALL_ATTEMPTS and exc.retryable(busy_codes):
                wait = min(exc.retry_after or delay, MAX_RETRY_AFTER_S)
            elif attempt == 1:
                raise
            else:
                final = RobotHTTPError(
                    exc.status,
                    exc.code,
                    exc.raw_message,
                    signed=exc.signed,
                    attempts=attempt,
                )
                final.retry_after = exc.retry_after
                raise final from exc
        await asyncio.sleep(wait)
        delay = min(delay * 2, MAX_RETRY_AFTER_S)
    raise ControlPlaneError("unreachable: call retries exhausted")


# --------------------------------------------------------------------------- #
# Request states (§5, §6, §6a)
# --------------------------------------------------------------------------- #

TERMINAL_STATUSES = frozenset(
    {"recorded_not_executed", "refused", "failed", "not_applied", "reverted", "applied"}
)
"""Statuses that never change again (§5, §6a): `applied` is the terminal
result of `request_safe_state` / `rollback_config` carried out by a platform
adapter (motion adapters revision)."""

REFUSAL_EXPLANATIONS: dict[str, str] = {
    # The robot's judgment (§4.1).
    "safety_system_engaged": (
        "the robot's safety system is engaged (e-stop or safe state) and has "
        "authority; it gets no competing request"
    ),
    "observe_mode": (
        "the robot is in observe mode (profile not locked and enforced, or "
        "policy not OEM-validated)"
    ),
    "morphology_mismatch": "the robot's morphology differs from its response policy's",
    "human_in_command": "a person is driving the robot (teleop or manual)",
    "transient_phase": "the robot is taking off or landing",
    "fall_hazard": (
        "the action could make the robot fall or collapse (also: a motion "
        "restriction below the policy's min_motion_factor on a robot that "
        "balances)"
    ),
    "requires_idle": (
        "the action needs the robot to be idle (rollback_config; the robot's "
        "judgment or its executor at the moment of apply)"
    ),
    "above_policy": "the robot's response policy does not allow this step now",
    "not_a_restriction": "the cap is above the robot's current envelope",
    "invariant_violation": "the plan fails the robot's response invariants",
    "not_reversible": "this action cannot be reverted; an operator restores the robot",
    # The executor's own checks (§6a).
    "not_executor_action": (
        "the robot's executor does not carry out this action: it has no motion "
        "section (safe_pause, request_safe_state, rollback_config), or it is a "
        "rollback_config of the profile, which the anti-rollback chain refuses"
    ),
    "needs_approval": "the robot's executor policy needs an approval it did not get",
    "motion_path": "the action would cut a motion path",
    "locators_required": (
        "the robot has not seen the participant's network locators yet, so it "
        "cannot quarantine it; retry once the participant was discovered"
    ),
    "no_management_channel": "the action would cut the robot's management channel",
    "unsupported_target": "the executor cannot target this (a node name or a process)",
    "safety_state_changed": "the safety state changed between judgment and apply",
    "safety_state_stale": "the executor's safety state is stale",
    "safety_state_unavailable": "the executor has no current safety state",
    "operator_disabled": (
        "an operator disabled the robot's executor; nothing is executed until "
        "it is re-armed on the robot"
    ),
    "config_unavailable": "the executor's configuration is unavailable",
    "already_active": "the same action is already active",
    "ttl_out_of_range": "the TTL is outside the executor's limits",
    "replay": "the executor already received this order",
    "invalid_order": (
        "the executor received an invalid order (also: a restrict_motion with "
        "workspace_zone, which no motion adapter enforces)"
    ),
    "id_conflict": "the executor holds another order under this id",
    "evidence_elsewhere": "the evidence is recorded elsewhere",
    # The executor's trust boundary (§6a, executor M1).
    "soc_signature_invalid": "the executor did not accept the SOC signature of the order",
    "soc_request_stale": (
        "the executor found the SOC request's timestamp outside its window or "
        "inside its replay fence"
    ),
    "soc_nonce_replayed": "the executor already saw the SOC nonce of the order",
    "soc_replay_store_unavailable": (
        "the executor's SOC replay store is full or could not record the request"
    ),
    "order_mismatch": (
        "the order does not match the request the SOC signed (request id, "
        "action, TTL, target, restriction or rollback parameters, key id or "
        "requested_by)"
    ),
    "approval_missing": (
        "the executor found no SOC approval for the order: the signed body "
        "lacks the approval evidence, or a two-person action (or the revert "
        "of a safe_pause) does not name two approvers other than the "
        "requester in approved_by"
    ),
    "soc_keys_unavailable": (
        "the executor's SOC key configuration cannot be trusted; it refuses "
        "every control-plane order until it is fixed"
    ),
    "approval_key_removed": (
        "the SOC key that approved the action is no longer configured on the "
        "robot's executor, so it was not re-armed after a reboot"
    ),
    "locator_out_of_scope": (
        "the participant's network locators lie outside the executor's quarantine scope"
    ),
    "executor_refused": "the executor refused it for a reason this agent does not know",
    # The executor's motion adapters (§6a, motion adapters revision).
    "no_adapter": "the robot's executor has no motion adapter configured for this action",
    "adapter_not_validated": (
        "the robot's motion adapter for this action is not marked OEM-validated "
        "by the site"
    ),
    "safety_state_not_allowed": (
        "the robot's safety state is not one the motion adapter allows this "
        "action in (by default safe_pause and request_safe_state not while "
        "moving_fast)"
    ),
    "behaviour_unsupported": (
        "the response policy's safe behaviour for this action is not one the "
        "robot's motion adapter can carry out"
    ),
}
"""What each refusal code means (§4.1, §6a); refusals are final."""

NEW_REQUEST_ID_CODES = frozenset({"soc_request_stale", "soc_nonce_replayed"})
"""Executor refusals of a request agentd accepted that a fresh signature can
pass (§14, executor M1). The same `request_id` only answers the stored
refusal (§5), so trying again takes a new request, never a resend."""

REFUSAL_HINTS: dict[str, str] = {
    "soc_signature_invalid": (
        "The robot's executor.json must list this SOC's public key in "
        "soc.keys (the same file as agentd's control_plane.soc_keys); fix "
        "that on the robot, then prepare a new request."
    ),
    "soc_request_stale": (
        "Resending this request_id returns this stored refusal: prepare a new "
        "request with prepare_action_request (a new request_id), have it signed "
        "off again and send that. Check NTP on the SOC and the robot if it "
        "persists."
    ),
    "soc_nonce_replayed": (
        "Resending this request_id returns this stored refusal: prepare a new "
        "request with prepare_action_request (a new request_id), have it signed "
        "off again and send that."
    ),
    "soc_replay_store_unavailable": (
        "The executor's SOC replay store needs an operator on the robot "
        "(executor state directory); then prepare a new request."
    ),
    "order_mismatch": (
        "The order agentd forwarded differs from what the SOC signed (for a "
        "restrict_motion or rollback_config also its parameters): check the "
        "robot's agentd for tampering, and that its executor was upgraded "
        "together with agentd."
    ),
    "approval_missing": (
        "safe_pause, request_safe_state and rollback_config (and the revert of "
        "a safe_pause) need two sign-off approvers other than the requester, "
        "which AutoSecOps sends as approved_by: prepare a new request and have "
        "two other platform users approve it. Otherwise the signed request "
        "lacks the approval evidence the contract requires (authority, "
        "requested_by, source, reason)."
    ),
    "not_executor_action": (
        "Without a motion section in the robot's executor.json these actions "
        "are never executed (act on site). rollback_config of the profile is "
        "never executed: the anti-rollback chain refuses an older profile; "
        "only config program is rolled back by the site's adapter."
    ),
    "invalid_order": (
        "A robot with motion adapters enforces no workspace_zone: request "
        "restrict_motion with max_linear_speed or max_joint_speed instead."
    ),
    "no_adapter": (
        "An operator configures a motion adapter for this action in the "
        "robot's executor.json (motion section), or the action is taken on "
        "site."
    ),
    "adapter_not_validated": (
        "The site sets the adapter's oem_validated flag in the robot's "
        "executor.json once the OEM validated it; until then the executor "
        "refuses the action."
    ),
    "safety_state_not_allowed": (
        "This request stays refused; once the robot is in a safety state the "
        "adapter allows, a new, newly signed-off request is judged in that "
        "state."
    ),
    "requires_idle": (
        "rollback_config runs only while the robot is idle; this request stays "
        "refused. Once it is idle, a new, newly signed-off request is judged "
        "then."
    ),
    "behaviour_unsupported": (
        "The OEM response policy's safe behaviour and the robot's adapter "
        "configuration must agree; fix them on the robot."
    ),
    "soc_keys_unavailable": (
        "An operator fixes soc.keys in the robot's executor.json (an "
        "unreadable or refused key file, or a SOC key equal to one of the "
        "robot's own keys)."
    ),
    "approval_key_removed": (
        "When rotating the SOC control-plane key, keep the old and the new SOC "
        "key listed (agentd's soc_keys and the executor's soc.keys) until the "
        "actions the old key approved have expired."
    ),
    "locator_out_of_scope": (
        "Every quarantine is refused until the robot's executor.json names "
        "network.quarantine.cidrs covering the participant's locators."
    ),
}
"""What the operator does next for a refusal code, where it is not obvious."""

FAILURE_EXPLANATIONS: dict[str, str] = {
    "evidence_unavailable": (
        "the robot's black box did not take the request; nothing was decided"
    ),
    "state_unavailable": (
        "the robot's request journal did not take the request; nothing was "
        "decided or handed to the executor"
    ),
}
"""What each `state.error.code` of a `failed` request means (§5, §6a)."""


# --------------------------------------------------------------------------- #
# Quarantine scope (§6a "Quarantine scope", §10)
# --------------------------------------------------------------------------- #

CONTAINMENT_VALUES = ("unknown", "guid_only", "partial", "full")
"""`containment` values, weakest first: the weaker of two readings wins."""

CONTAINMENT_LABELS: dict[str, str] = {
    "full": "contained",
    "partial": "partially contained",
    "guid_only": "partially contained: GUID-prefix drop only, not IP-contained",
    "unknown": "scope unknown (the robot did not report how far the quarantine reaches)",
}
"""How each `containment` is shown (§6a client requirements)."""

SCOPE_BOUNDS = {
    "addresses": 16,
    "excluded_addresses": 32,
    "locators": 16,
    "excluded": 64,
}
"""The most entries §6a allows per `state.quarantine` list."""

MAX_SCOPE_REASON = 200

SHARED_HOST_CAVEAT = (
    "Shared-host caveat: an address drop cuts every DDS participant on that "
    "host, a legitimate process that is not in the robot's profile included, "
    "and source addresses are not authenticated (a decoy that spoofs its "
    "discovery to a host's address gets that host cut); confirm that no "
    "legitimate robot process runs on {addresses}."
)

ISOLATE_NEXT_STEP = (
    "Next: consider robot_isolate_network (with a TTL; on a humanoid or "
    "quadruped only when its balance loop is not networked) or on-site action."
)


class _ScopeError(ValueError):
    """A `state.quarantine` that is not what §6a describes."""


def _scope_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or "%" in value:
        raise _ScopeError("not an IP address")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise _ScopeError("not an IP address") from exc


def _scope_locator(
    value: object,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, str]:
    """An `"ip:port"` (IPv6 `"[addr]:port"`) locator and its canonical form."""
    if not isinstance(value, str):
        raise _ScopeError("not a locator")
    host, sep, port = value.rpartition(":")
    if not sep or not port.isascii() or not port.isdigit() or len(port) > 5:
        raise _ScopeError("not a locator")
    if not 0 < int(port) <= 65535:
        raise _ScopeError("locator port out of range")
    if host.startswith("[") and host.endswith("]"):
        ip = _scope_ip(host[1:-1])
        if ip.version != 6:
            raise _ScopeError("bracketed IPv4 locator")
        return ip, f"[{ip.compressed}]:{int(port)}"
    ip = _scope_ip(host)
    if ip.version != 4:
        raise _ScopeError("unbracketed IPv6 locator")
    return ip, f"{ip.compressed}:{int(port)}"


def _scope_reason(value: object) -> str:
    """A robot-reported reason: tainted text, display only (§6a).

    Kept to printable ASCII without backticks, at most 200 characters, so it
    cannot break out of a code span or carry control sequences.
    """
    if not isinstance(value, str):
        raise _ScopeError("reason is not a string")
    clean = "".join(
        ch if ch.isascii() and ch.isprintable() and ch != "`" else "?" for ch in value
    )
    return clean[:MAX_SCOPE_REASON]


def _scope_list(raw: dict[str, Any], key: str) -> list[Any]:
    value = raw.get(key, [])
    if not isinstance(value, list) or len(value) > SCOPE_BOUNDS[key]:
        raise _ScopeError(f"{key} is not a list within its bound")
    return value


def _scope_entry(entry: object, key: str) -> tuple[str, str]:
    if not isinstance(entry, dict) or set(entry) != {key, "reason"}:
        raise _ScopeError(f"left-out entry without {key} and reason")
    return entry[key], _scope_reason(entry["reason"])


def _parse_scope(raw: object) -> dict[str, Any]:
    """`state.quarantine`, checked and canonical (§6a table).

    `addresses`, `excluded_addresses` and `evidence_truncated` are absent in a
    scope journalled before revision R3-1 and read as empty / false (§9).
    """
    if not isinstance(raw, dict):
        raise _ScopeError("state.quarantine is not an object")
    addresses = [_scope_ip(a).compressed for a in _scope_list(raw, "addresses")]
    excluded_addresses = []
    for entry in _scope_list(raw, "excluded_addresses"):
        address, reason = _scope_entry(entry, "address")
        excluded_addresses.append(
            {"address": _scope_ip(address).compressed, "reason": reason}
        )
    if "locators" not in raw:
        raise _ScopeError("state.quarantine has no locators")
    locators = [_scope_locator(loc)[1] for loc in _scope_list(raw, "locators")]
    excluded = []
    for entry in _scope_list(raw, "excluded"):
        locator, reason = _scope_entry(entry, "locator")
        excluded.append({"locator": _scope_locator(locator)[1], "reason": reason})
    truncated = raw.get("evidence_truncated", False)
    if not isinstance(truncated, bool):
        raise _ScopeError("evidence_truncated is not a boolean")
    return {
        "addresses": addresses,
        "excluded_addresses": excluded_addresses,
        "evidence_truncated": truncated,
        "locators": locators,
        "excluded": excluded,
    }


def _uncovered_locators(scope: dict[str, Any]) -> list[str]:
    """Locators cut by ip:port only: their address is not cut whole."""
    cut = {ipaddress.ip_address(a) for a in scope["addresses"]}
    return [loc for loc in scope["locators"] if _scope_locator(loc)[0] not in cut]


def containment_of(scope: dict[str, Any]) -> str:
    """RoboDR's `robodr_executor::decision::containment_of` over a checked scope.

    `full` needs a non-empty address drop that covers every announced
    locator, with nothing left out or forgotten; no address and no locator
    is `guid_only`; anything else is `partial`.
    """
    if not scope["addresses"] and not scope["locators"]:
        return "guid_only"
    left_out = bool(
        scope["excluded"] or scope["excluded_addresses"] or scope["evidence_truncated"]
    )
    if scope["addresses"] and not left_out and not _uncovered_locators(scope):
        return "full"
    return "partial"


def _weaker(a: str, b: str) -> str:
    return min(a, b, key=CONTAINMENT_VALUES.index)


def _containment_detail(containment: str, scope: dict[str, Any] | None) -> str:
    """What a quarantine cuts and leaves out, and what to do next (§6a, §10)."""
    addresses = ", ".join(scope["addresses"]) if scope else ""
    caveat = SHARED_HOST_CAVEAT.format(addresses=addresses) if addresses else ""
    if containment == "unknown" or scope is None:
        return (
            "Scope unknown, not fully contained: the robot did not report how "
            "far the quarantine reaches (an executor older than RoboDR revision "
            "R2-3, or a scope this integration cannot read). Treat the "
            "participant as not contained. " + ISOLATE_NEXT_STEP + " Upgrade "
            "robodr-executor (before robodr-agentd) to get the scope reported."
        )
    if containment == "full":
        return (
            "Contained: every source address the participant was seen sending "
            f"from is cut whole ({addresses}; any source port, to and from the "
            "robot's DDS ports), covering every locator it announced, plus its "
            f"GUID-prefix drop. {caveat}"
        )
    parts: list[str] = []
    if containment == "guid_only":
        parts.append(
            "Partially contained, not fully contained: GUID-prefix drop only, "
            "not IP-contained. No address or locator of the participant is "
            "cut; it can evade the GUID-prefix drop by re-attributing its "
            "messages (INFO_SRC) or restarting under a new GUID prefix."
        )
    else:
        parts.append(
            "Partially contained, not fully contained: "
            + (f"cut whole: {addresses}." if addresses else "no address is cut whole.")
        )
        if uncovered := _uncovered_locators(scope):
            parts.append(
                "Cut by announced ip:port only (a sender using ephemeral ports, "
                "the ROS 2 default, evades these inbound): "
                + ", ".join(uncovered)
                + "."
            )
    left_out = [
        f'{entry["address"]} (address: "{entry["reason"]}")'
        for entry in scope["excluded_addresses"]
    ] + [
        f'{entry["locator"]} (locator: "{entry["reason"]}")'
        for entry in scope["excluded"]
    ]
    if left_out:
        parts.append(
            "Left out (robot-reported reasons, display only): "
            + "; ".join(left_out)
            + "."
        )
    if scope["evidence_truncated"]:
        parts.append(
            "The robot forgot some observed source addresses or announced "
            "locators of the participant (evidence truncated): more may be uncut."
        )
    if containment == "partial":
        parts.append(
            "From a left-out address the participant still reaches the robot "
            "from any port it did not announce, and by INFO_SRC re-attribution."
        )
    parts.append(ISOLATE_NEXT_STEP)
    if scope["excluded_addresses"]:
        parts.append(
            "An address left out because a profiled participant was learned "
            "there can be pinned (participant_ips) or commissioned on the robot."
        )
    if caveat:
        parts.append(caveat)
    return " ".join(parts)


def _quarantine_outcome(
    data: dict[str, Any], state: dict[str, Any], action: str | None
) -> tuple[str | None, dict[str, Any] | None]:
    """The `containment` to report and the checked `state.quarantine`.

    `containment` applies to a `quarantine_node` request that is `verified`
    or `applied` (held or not); `None` otherwise. It is the weaker of the
    robot's own word and what `containment_of` derives from the scope: an
    absent, unknown or unreadable value, or a scope that does not back the
    robot's word, is never read as contained.
    """
    stored_action = state.get("action")
    quarantine = (
        action == "quarantine_node"
        or stored_action == "quarantine_node"
        or "containment" in data
        or "quarantine" in state
    )
    if not quarantine:
        return None, None
    scope: dict[str, Any] | None = None
    if "quarantine" in state:
        try:
            scope = _parse_scope(state["quarantine"])
        except _ScopeError:
            scope = None
    if data.get("status") not in ("verified", "applied"):
        return None, scope
    reported = data.get("containment")
    word = reported if reported in CONTAINMENT_VALUES else "unknown"
    derived = containment_of(scope) if scope is not None else "unknown"
    return _weaker(word, derived), scope


REVERT_PENDING_DEFAULT = (
    "If it stays verified, the executor refused the revert (for example its "
    "SOC signature did not verify) and the action stays until its TTL "
    "expires (state.expires_at_ms)."
)
"""Why a revert may stay pending, for an action without its own note."""

REVERT_PENDING_NOTES: dict[str, str] = {
    "safe_pause": (
        "If it stays verified, the executor refused the revert: lifting a "
        "safe_pause needs two approvers other than the requester in the signed "
        "revert (approval_missing) as well as a valid SOC signature. The pause "
        "stays until the executor's motion.safe_pause_ttl_s releases it."
    ),
}
"""Why a revert of a motion action may stay pending (§6a, motion adapters)."""

IN_FORCE_NOTES: dict[str, str] = {
    "restrict_motion": (
        "The robot's motion adapters enforce the restriction (in-path gateway "
        "or the platform's speed level)."
    ),
    "safe_pause": (
        "The robot is paused. A revert (two approvers) releases the pause and "
        "never resumes a mission; the executor also releases it after its "
        "motion.safe_pause_ttl_s."
    ),
}
"""What a `verified` motion action in force means (§6a, motion adapters)."""

REVERTED_NOTES: dict[str, str] = {
    "safe_pause": (
        "The pause was released; no mission was resumed (an operator restarts it)."
    ),
}
"""What a `reverted` motion action means (§6a, motion adapters)."""


def _explain(table: dict[str, str], code: object, fallback: str) -> str:
    return table.get(code, fallback) if isinstance(code, str) else fallback


def _outcome(
    data: dict[str, Any], *, revert: bool = False, action: str | None = None
) -> dict[str, Any]:
    """Report a request state as the contract requires (§5, §6a, §10).

    "In force" is the robot's own top-level `in_force`, never inferred from
    the status: true only for `verified` / `applied` that is not held. A
    `quarantine_node` in force is "contained" only with `containment: full`
    backed by its `state.quarantine` (§6a "Quarantine scope"). `action` is
    the catalog action when the caller knows it (a submit or a revert).
    """
    status = data.get("status")
    executed = data.get("executed") is True
    raw_refusal = data.get("refusal")
    refusal: dict[str, Any] = raw_refusal if isinstance(raw_refusal, dict) else {}
    raw_state = data.get("state")
    state: dict[str, Any] = raw_state if isinstance(raw_state, dict) else {}
    raw_error = state.get("error")
    error: dict[str, Any] = raw_error if isinstance(raw_error, dict) else {}
    executor_state = state.get("executor_state")
    held = status == "verified" and executor_state == "held"
    reported_in_force = data.get("in_force")
    in_force = (
        reported_in_force is True and status in ("verified", "applied") and not held
    )
    containment, scope = _quarantine_outcome(data, state, action)
    contained = None if containment is None else (in_force and containment == "full")
    containment_report = None
    if containment is not None:
        containment_report = _containment_detail(containment, scope)
        if not in_force:
            containment_report = (
                "Not in force now; scope reported for when it is: " + containment_report
            )
    scope_label = CONTAINMENT_LABELS[containment] if containment else None
    raw_revert = state.get("revert")
    revert_state: dict[str, Any] = raw_revert if isinstance(raw_revert, dict) else {}
    # A revert the executor has not carried out (or refused: an unsigned or
    # bad revert of a SOC-approved action, §6a) leaves the request `pending`
    # or `verified` with `state.revert.result: "pending"`: never reverted.
    revert_pending = status in ("pending", "verified") and (
        revert_state.get("result") == "pending" or (revert and status == "pending")
    )
    refusal_code = refusal.get("code")
    explained_refusal = status == "refused" or (status == "reverted" and bool(refusal))
    refusal_explanation = (
        _explain(REFUSAL_EXPLANATIONS, refusal_code, "unknown refusal code")
        if explained_refusal
        else None
    )
    refusal_hint = (
        (_explain(REFUSAL_HINTS, refusal_code, "") or None)
        if explained_refusal
        else None
    )
    new_request_id_required = (
        status == "refused"
        and isinstance(refusal_code, str)
        and refusal_code in NEW_REQUEST_ID_CODES
    )
    error_explanation = (
        _explain(
            FAILURE_EXPLANATIONS,
            error.get("code"),
            "the executor was unreachable, its queue was full, or the apply did "
            "not verify and was rolled back",
        )
        if status == "failed"
        else None
    )
    match status:
        case "recorded_not_executed":
            report = (
                "Not applied: the robot accepted the request and recorded it as a "
                "plan in its black box; it executed nothing."
            )
        case "refused":
            report = (
                f"Not applied: refused by the robot ({_shown(refusal_code)}: "
                f"{refusal_explanation}; safety state "
                f"{_shown(refusal.get('safety_state'))}): {refusal.get('reason')}. "
            ) + (
                "This request_id stays refused."
                if new_request_id_required
                else "Refusals are final; do not retry."
            )
            if refusal_hint:
                report += f" {refusal_hint}"
        case "failed":
            report = (
                f"Not applied: failed ({_shown(error.get('code'))}: "
                f"{error_explanation}); nothing is in force. A new request is "
                "judged anew."
            )
        case "not_applied":
            report = "Not applied: the request never took effect, so there was nothing to revert."
        case "pending" if revert_pending:
            report = (
                "Revert pending: the robot recorded the revert and handed it to its "
                "executor; the action may stay in force until get_action_status "
                "shows reverted."
            )
        case "pending":
            report = (
                "Pending: accepted, recorded and handed to the robot's executor; "
                "not in force yet. Poll get_action_status."
            )
        case "verified" if revert_pending:
            enforcement = (
                "still in force"
                if in_force
                else "held after a reboot, not enforced"
                if held
                else "not reported in force"
            )
            if scope_label:
                enforcement += f" ({scope_label})"
            report = (
                f"Revert pending, not reverted: the action is {enforcement}. The "
                "robot recorded the revert but its executor has not lifted the "
                "action. "
                + _explain(
                    REVERT_PENDING_NOTES,
                    action if action is not None else state.get("action"),
                    REVERT_PENDING_DEFAULT,
                )
                + " Keep polling get_action_status."
            )
        case "verified" if held:
            report = (
                "Held, not enforced: the robot rebooted and its executor holds the "
                "action until it re-validated it (it turns reverted if not re-armed "
                "before its TTL). Keep polling get_action_status."
            )
            if scope_label:
                report += f" Quarantine scope once re-armed: {scope_label}."
        case "verified" | "applied" if in_force and scope_label:
            report = (
                f"In force, {scope_label}: the robot's executor applied the "
                "quarantine; it stays until revert or its TTL expires. See "
                "containment_report for what is cut and left out."
            )
        case "verified" if in_force:
            report = (
                "In force: the robot's executor applied the action and verified it; "
                "it stays until revert or its TTL expires."
            )
        case "verified":
            report = (
                "Not in force: the robot reports verified but does not report the "
                "action in force (in_force missing or false). Keep polling "
                "get_action_status."
            )
        case "reverted":
            report = "Reverted: the action is no longer in force."
            if refusal:
                report += f" ({_shown(refusal_code)}: {refusal_explanation}.)" + (
                    f" {refusal_hint}" if refusal_hint else ""
                )
        case "applied" if in_force:
            report = (
                "Applied: the robot's executor carried out the action through its "
                "platform adapter. Final and not reversible: the platform owns the "
                "result and an operator restores the robot."
            )
        case "applied":
            report = (
                "Applied by the robot's adapter, but the robot does not report it "
                "in force (in_force missing or false); final, not reversible."
            )
        case _:
            report = f"Not applied (status {_shown(status)})."
    acted = action if action is not None else state.get("action")
    note = ""
    if status == "verified" and in_force and not revert_pending:
        note = _explain(IN_FORCE_NOTES, acted, "")
    elif status == "reverted":
        note = _explain(REVERTED_NOTES, acted, "")
    if note:
        report += f" {note}"
    return {
        "status": status,
        "executed": executed,
        "in_force": in_force,
        "applied": in_force,
        "held": held,
        "executor_state": executor_state if isinstance(executor_state, str) else None,
        "terminal": status in TERMINAL_STATUSES,
        "duplicate": data.get("duplicate") is True,
        "refusal": data.get("refusal"),
        "refusal_explanation": refusal_explanation,
        "refusal_hint": refusal_hint,
        "new_request_id_required": new_request_id_required,
        "revert_pending": revert_pending,
        "containment": containment,
        "contained": contained,
        "containment_report": containment_report,
        "quarantine_scope": scope,
        "error": state.get("error"),
        "error_explanation": error_explanation,
        "report": report,
    }


async def _verified_snapshot(robot: _Robot) -> dict[str, Any]:
    snap = (await _call_retrying(robot, "GET", _robot_target(robot.robot_id))).json()
    if snap.get("robot_id") != robot.robot_id:
        raise ControlPlaneError("the snapshot is for another robot_id")
    return snap


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #

_BASE_URL_DOC = Doc(
    "Robot control-plane URL, https://host[:port] with no path: robodr-agentd's "
    "mutual-TLS listener (or a TLS terminator in front of it that forwards the "
    "client certificate check and the request target unchanged)."
)
_ROBOT_ID_DOC = Doc("Robot id robodr-agentd is configured with.")
_ROBOT_CA_DOC = Doc(
    "PEM certificate(s) of the CA that issued the robot's server certificate "
    "(tls.cert_chain). Only this CA is trusted; the certificate must also match "
    "the host of base_url."
)
_SPKI_DOC = Doc(
    "Optional pin: SHA-256 (64 hex) of the robot server certificate's "
    "SubjectPublicKeyInfo (status.json control_plane.tls.server_spki_sha256). "
    "Checked before anything is sent."
)
_ANSWER_KEY_DOC = Doc(
    "Robot finding public key (64 hex). Required: every answer must carry a "
    "valid X-RoboDR-Answer-Signature bound to its request."
)
_ANSWER_KEY_ID_DOC = Doc("Optional expected key id of the answer signature.")
_REQUEST_SUBMISSION_DOC = Doc(
    "Form submission id of the requester's sign-off (robodr_decision=request) "
    "for this request_id and request_digest."
)
_APPROVAL_SUBMISSIONS_DOC = Doc(
    "Form submission ids of the approvers' sign-offs (robodr_decision=approve): "
    "one, or two different platform users for robot_safe_pause, "
    "robot_request_safe_state, robot_rollback_config and their reverts. "
    "Never the requester."
)


@registry.register(
    default_title="Get RoboDR robot snapshot",
    description=(
        "Read a robot's control-plane snapshot over mutual TLS: safety state, "
        "mode, morphology, executor and the actions it may be asked for. "
        "Read-only; the answer signature is verified."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
)
async def get_robot(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    robot_ca_pem: Annotated[str, _ROBOT_CA_DOC],
    answer_public_key_hex: Annotated[str, _ANSWER_KEY_DOC],
    robot_spki_sha256: Annotated[str | None, _SPKI_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    robot = _robot(
        base_url=base_url,
        robot_id=robot_id,
        robot_ca_pem=robot_ca_pem,
        robot_spki_sha256=robot_spki_sha256,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    answer = await _call_retrying(robot, "GET", _robot_target(robot.robot_id))
    return {
        "status_code": answer.status,
        "answer_signature_verified": True,
        "data": answer.json(),
    }


_ACTION_INPUT_DOCS = {
    "reason": Doc("Why the action is requested, at most 500 characters."),
    "source": Doc("SOC label, [a-z0-9_-]{1,32}."),
    "ttl_seconds": Doc(
        "Lifetime in seconds, 1..86400. Required for restrict_motion and "
        "isolate_network; not allowed for the other actions."
    ),
}


@registry.register(
    default_title="Prepare RoboDR action request",
    description=(
        "Validate a robot action request and compute the request_id and "
        "request_digest its sign-offs must carry. Sends nothing. The requester "
        "and the approvers submit the sign-off form with these values, then "
        "request_action sends the identical request."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
)
def prepare_action_request(
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    action: Annotated[
        str, Doc("Catalog action by wire name (robot_<name>) or plain name.")
    ],
    reason: Annotated[str, _ACTION_INPUT_DOCS["reason"]] = "",
    source: Annotated[str, _ACTION_INPUT_DOCS["source"]] = "autosecops",
    ttl_seconds: Annotated[int | None, _ACTION_INPUT_DOCS["ttl_seconds"]] = None,
    request_id: Annotated[
        str | None,
        Doc(
            "Idempotency key, [A-Za-z0-9._:-]{1,128}. Default: "
            "robot_<action>:<robot_id>:<random>."
        ),
    ] = None,
    max_linear_speed: Annotated[
        float | None, Doc("restrict_motion: linear speed cap in (0, 10].")
    ] = None,
    max_joint_speed: Annotated[
        float | None, Doc("restrict_motion: joint speed cap in (0, 10].")
    ] = None,
    workspace_zone: Annotated[
        str | None, Doc("restrict_motion: zone name, [A-Za-z0-9._-]{1,64}.")
    ] = None,
    participant_guid: Annotated[
        str | None,
        Doc("quarantine_node: DDS participant GUID, 24 or 32 lower-case hex."),
    ] = None,
    node: Annotated[str | None, Doc("quarantine_node: plain ROS 2 node name.")] = None,
    config: Annotated[
        str | None, Doc("rollback_config: profile (default) or program.")
    ] = None,
    to_version: Annotated[
        str | None,
        Doc(
            "rollback_config: target version, [A-Za-z0-9._-]{1,64}, not "
            "starting with '-'."
        ),
    ] = None,
) -> dict[str, Any]:
    prepared = _prepare_action(
        robot_id=robot_id,
        action=action,
        reason=reason,
        source=source,
        ttl_seconds=ttl_seconds,
        request_id=request_id,
        max_linear_speed=max_linear_speed,
        max_joint_speed=max_joint_speed,
        workspace_zone=workspace_zone,
        participant_guid=participant_guid,
        node=node,
        config=config,
        to_version=to_version,
    )
    spec = prepared.spec
    digest = request_digest("action", prepared.digest_fields())
    return {
        **prepared.digest_fields(),
        "wire_name": wire_name(spec.name),
        "request_digest": digest,
        "approval": "two_person" if spec.two_person else "single",
        "required_approvals": 2 if spec.two_person else 1,
        "signoff_answers": {
            SIGNOFF_REQUEST_ID: prepared.request_id,
            SIGNOFF_DIGEST: digest,
            SIGNOFF_ROBOT_ID: prepared.robot_id,
            SIGNOFF_ACTION: wire_name(spec.name),
        },
    }


@registry.register(
    default_title="Request RoboDR robot action",
    description=(
        "Send one signed-off catalog action request (robot_restrict_motion, "
        "robot_quarantine_node, robot_isolate_network, robot_record_evidence, "
        "robot_safe_pause, robot_request_safe_state, robot_rollback_config) to a "
        "robot's control plane over mutual TLS. Refuses unless platform form "
        "submissions prove the requester and one approver (two for the "
        "two-person actions), all different platform users, signed off this "
        "exact request; a two-person action names its two approvers to the "
        "robot (approved_by), which the robot's executor requires. The robot "
        "judges it against its safety state and may refuse it. "
        "recorded_not_executed, refused and failed are reported as not "
        "applied; pending is not yet in force; applied (request_safe_state, "
        "rollback_config through a platform adapter) is final and not "
        "reversible; in_force is the robot's own word (verified or applied, "
        "and not held after a reboot). A robot_quarantine_node in "
        "force reports containment: full (contained), partial, guid_only "
        "(GUID-prefix drop only, not IP-contained) or unknown; only full is "
        "contained. Recorded by the platform (the run, requester and approvers) "
        "before it is sent; refused if the configured audit sink does not "
        "confirm it. audit_log says written (sink confirmed) or no_sink (no "
        "audit sink configured: platform log only)."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
    requires_approval=True,
    required_entitlements=["forms"],
)
async def request_action(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    robot_ca_pem: Annotated[str, _ROBOT_CA_DOC],
    action: Annotated[
        str,
        Doc("Catalog action by wire name (robot_<name>) or plain name."),
    ],
    request_id: Annotated[
        str,
        Doc("The request_id from prepare_action_request that was signed off."),
    ],
    request_submission_id: Annotated[str, _REQUEST_SUBMISSION_DOC],
    approval_submission_ids: Annotated[list[str], _APPROVAL_SUBMISSIONS_DOC],
    answer_public_key_hex: Annotated[str, _ANSWER_KEY_DOC],
    reason: Annotated[str, _ACTION_INPUT_DOCS["reason"]] = "",
    source: Annotated[str, _ACTION_INPUT_DOCS["source"]] = "autosecops",
    ttl_seconds: Annotated[int | None, _ACTION_INPUT_DOCS["ttl_seconds"]] = None,
    max_linear_speed: Annotated[
        float | None, Doc("restrict_motion: linear speed cap in (0, 10].")
    ] = None,
    max_joint_speed: Annotated[
        float | None, Doc("restrict_motion: joint speed cap in (0, 10].")
    ] = None,
    workspace_zone: Annotated[
        str | None, Doc("restrict_motion: zone name, [A-Za-z0-9._-]{1,64}.")
    ] = None,
    participant_guid: Annotated[
        str | None,
        Doc("quarantine_node: DDS participant GUID, 24 or 32 lower-case hex."),
    ] = None,
    node: Annotated[str | None, Doc("quarantine_node: plain ROS 2 node name.")] = None,
    config: Annotated[
        str | None, Doc("rollback_config: profile (default) or program.")
    ] = None,
    to_version: Annotated[
        str | None,
        Doc(
            "rollback_config: target version, [A-Za-z0-9._-]{1,64}, not "
            "starting with '-'."
        ),
    ] = None,
    robot_spki_sha256: Annotated[str | None, _SPKI_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    # 1. Inputs, before anything is read or sent.
    prepared = _prepare_action(
        robot_id=robot_id,
        action=action,
        reason=reason,
        source=source,
        ttl_seconds=ttl_seconds,
        request_id=_check_request_id(request_id),
        max_linear_speed=max_linear_speed,
        max_joint_speed=max_joint_speed,
        workspace_zone=workspace_zone,
        participant_guid=participant_guid,
        node=node,
        config=config,
        to_version=to_version,
    )
    spec = prepared.spec
    robot = _robot(
        base_url=base_url,
        robot_id=robot_id,
        robot_ca_pem=robot_ca_pem,
        robot_spki_sha256=robot_spki_sha256,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )

    # 2. The platform sign-off for exactly this request.
    required = 2 if spec.two_person else 1
    digest = request_digest("action", prepared.digest_fields())
    requester, approvers = await _collect_signoff(
        request_id=prepared.request_id,
        digest=digest,
        robot_id=robot.robot_id,
        action=wire_name(spec.name),
        request_submission_id=request_submission_id,
        approval_submission_ids=approval_submission_ids,
    )
    _require_approvals(wire_name(spec.name), required, approvers)

    # 3. The policy against the robot's own signed snapshot.
    snap = await _verified_snapshot(robot)
    reasons = _policy_reasons(spec, snap.get("morphology"), snap.get("actions"))
    if reasons:
        raise ValueError("request refused by the SOC policy: " + "; ".join(reasons))
    robot_approvers = _robot_approvers(spec, snap, requester, approvers)

    body_obj: dict[str, Any] = {
        "request_id": prepared.request_id,
        "action": spec.name,
        "parameters": prepared.parameters,
        "reason": prepared.reason,
        "requested_by": requester.identifier,
        "source": prepared.source,
        "authority": "request",
    }
    if prepared.ttl_seconds is not None:
        body_obj["ttl_seconds"] = prepared.ttl_seconds
    if robot_approvers:
        body_obj["approved_by"] = robot_approvers

    # 4. The platform audit log, before anything is signed or sent.
    audit = _ActionAudit(
        robot_id=robot.robot_id,
        request_id=prepared.request_id,
        operation="request_action",
        robot_action=wire_name(spec.name),
        request_digest=digest,
        request_submission_id=_submission_uuid(request_submission_id),
        approval_submission_ids=[_submission_uuid(s) for s in approval_submission_ids],
        requested_by_name=requester.identifier,
        approved_by_names=robot_approvers,
    )
    attempt_log = await audit.attempt()
    # A `busy` submission is resent unchanged (same request_id and body, a
    # fresh nonce): the robot judges it once or answers it as a duplicate (§7).
    # Every way out after the attempt closes it: a cancelled call, or an
    # answer that cannot be read, may still have reached the robot.
    try:
        answer = await _call_retrying(
            robot,
            "POST",
            _robot_target(robot.robot_id, "action-requests"),
            body_bytes(body_obj),
        )
        data = answer.json()
        outcome = _outcome(data, action=spec.name)
    except BaseException as exc:
        await audit.failed(exc)
        raise
    return {
        "request_id": prepared.request_id,
        "action": spec.name,
        "wire_name": wire_name(spec.name),
        "approval": "two_person" if spec.two_person else "single",
        "requested_by": requester.as_dict(),
        "approved_by": [a.as_dict() for a in approvers],
        "robot_approved_by": robot_approvers,
        "robot_safety_state": snap.get("safety_state"),
        "robot_executor": snap.get("executor"),
        **outcome,
        "answer_signature_verified": True,
        **_audit_fields(attempt_log, await audit.answered(outcome)),
        "answer": data,
    }


@registry.register(
    default_title="Get RoboDR action status",
    description=(
        "Read the stored state of a robot action request (signed answer). "
        "recorded_not_executed, refused, failed, applied and reverted are "
        "terminal: never poll them. Poll pending until it becomes verified, "
        "applied (request_safe_state, rollback_config), refused or failed, "
        "and a held verified action until it is re-armed (in_force true) or "
        "reverted. A verified robot_quarantine_node reports containment (full, "
        "partial, guid_only or unknown) and what it cut and left out; only full "
        "is contained."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
)
async def get_action_status(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    robot_ca_pem: Annotated[str, _ROBOT_CA_DOC],
    request_id: Annotated[str, Doc("The request_id of the action request.")],
    answer_public_key_hex: Annotated[str, _ANSWER_KEY_DOC],
    robot_spki_sha256: Annotated[str | None, _SPKI_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    _check_request_id(request_id)
    robot = _robot(
        base_url=base_url,
        robot_id=robot_id,
        robot_ca_pem=robot_ca_pem,
        robot_spki_sha256=robot_spki_sha256,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    answer = await _call_retrying(
        robot, "GET", _robot_target(robot.robot_id, "action-requests", request_id)
    )
    data = answer.json()
    return {
        "request_id": request_id,
        **_outcome(data),
        "answer_signature_verified": True,
        "answer": data,
    }


@registry.register(
    default_title="Prepare RoboDR action revert",
    description=(
        "Validate a revert and compute the request_digest its sign-offs must "
        "carry. Sends nothing."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
)
def prepare_revert_request(
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    request_id: Annotated[str, Doc("The request_id of the action request.")],
    reason: Annotated[str, Doc("Why, at most 500 characters.")] = "",
) -> dict[str, Any]:
    fields = {
        "robot_id": _check_robot_id(robot_id),
        "request_id": _check_request_id(request_id),
        "reason": _check_reason(reason),
    }
    digest = request_digest("revert", fields)
    return {
        **fields,
        "request_digest": digest,
        "required_approvals": (
            "1, or 2 when the stored request is robot_safe_pause, "
            "robot_request_safe_state or robot_rollback_config"
        ),
        "signoff_answers": {
            SIGNOFF_REQUEST_ID: request_id,
            SIGNOFF_DIGEST: digest,
            SIGNOFF_ROBOT_ID: fields["robot_id"],
        },
    }


@registry.register(
    default_title="Revert RoboDR action",
    description=(
        "Ask a robot to revert a signed-off action request. Needs the same "
        "platform sign-off as a request (two approvers to revert a two-person "
        "action such as robot_safe_pause; their names are sent as approved_by). "
        "Reverting a safe_pause releases the pause and never resumes a "
        "mission. request_safe_state, rollback_config "
        "and record_evidence are not reversible (refused, not_reversible); a "
        "request that never took effect answers not_applied; an executed one "
        "answers pending, then reverted. Recorded by the platform before it is "
        "sent; refused if the configured audit sink does not confirm it. "
        "audit_log says written (sink confirmed) or no_sink (no audit sink "
        "configured: platform log only)."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
    requires_approval=True,
    required_entitlements=["forms"],
)
async def revert_action(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    robot_ca_pem: Annotated[str, _ROBOT_CA_DOC],
    request_id: Annotated[str, Doc("The request_id of the action request.")],
    request_submission_id: Annotated[str, _REQUEST_SUBMISSION_DOC],
    approval_submission_ids: Annotated[list[str], _APPROVAL_SUBMISSIONS_DOC],
    answer_public_key_hex: Annotated[str, _ANSWER_KEY_DOC],
    reason: Annotated[str, Doc("Why, at most 500 characters.")] = "",
    robot_spki_sha256: Annotated[str | None, _SPKI_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    fields = {
        "robot_id": _check_robot_id(robot_id),
        "request_id": _check_request_id(request_id),
        "reason": _check_reason(reason),
    }
    robot = _robot(
        base_url=base_url,
        robot_id=robot_id,
        robot_ca_pem=robot_ca_pem,
        robot_spki_sha256=robot_spki_sha256,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    digest = request_digest("revert", fields)
    requester, approvers = await _collect_signoff(
        request_id=request_id,
        digest=digest,
        robot_id=robot.robot_id,
        action=None,
        request_submission_id=request_submission_id,
        approval_submission_ids=approval_submission_ids,
    )

    # Which action the revert undoes decides how many approvals it needs: ask
    # the robot (signed answer) instead of trusting an input.
    stored = await _call_retrying(
        robot, "GET", _robot_target(robot.robot_id, "action-requests", request_id)
    )
    state = stored.json().get("state")
    stored_action = state.get("action") if isinstance(state, dict) else None
    if not isinstance(stored_action, str) or stored_action not in CATALOG:
        raise ControlPlaneError(
            "the robot's stored request names no catalog action; nothing is reverted"
        )
    if isinstance(state, dict) and state.get("robot_id", robot_id) != robot_id:
        raise ControlPlaneError("the stored request is for another robot_id")
    spec = CATALOG[stored_action]
    _require_approvals(
        f"a revert of {wire_name(spec.name)}", 2 if spec.two_person else 1, approvers
    )

    snap = await _verified_snapshot(robot)
    reasons = _policy_reasons(spec, snap.get("morphology"))
    if reasons:
        raise ValueError("revert refused by the SOC policy: " + "; ".join(reasons))
    # The executor lifts a `safe_pause` it carried out only with two
    # approvers in the signed revert body (§6, §6a).
    robot_approvers = _robot_approvers(spec, snap, requester, approvers)

    revert_body: dict[str, Any] = {
        "reason": fields["reason"],
        "requested_by": requester.identifier,
    }
    if robot_approvers:
        revert_body["approved_by"] = robot_approvers
    body = body_bytes(revert_body)
    audit = _ActionAudit(
        robot_id=robot.robot_id,
        request_id=request_id,
        operation="revert_action",
        robot_action=wire_name(spec.name),
        request_digest=digest,
        request_submission_id=_submission_uuid(request_submission_id),
        approval_submission_ids=[_submission_uuid(s) for s in approval_submission_ids],
        requested_by_name=requester.identifier,
        approved_by_names=robot_approvers,
    )
    attempt_log = await audit.attempt()
    # Resent only when the robot did nothing (fenced, rate limited); after
    # `busy` the revert may be recorded: read get_action_status first.
    try:
        answer = await _call_retrying(
            robot,
            "POST",
            _robot_target(robot.robot_id, "action-requests", request_id, "revert"),
            body,
            busy_codes=(),
        )
        data = answer.json()
        outcome = _outcome(data, revert=True, action=spec.name)
    except BaseException as exc:
        await audit.failed(exc)
        raise
    return {
        "request_id": request_id,
        "action": spec.name,
        "approval": "two_person" if spec.two_person else "single",
        "requested_by": requester.as_dict(),
        "approved_by": [a.as_dict() for a in approvers],
        "robot_approved_by": robot_approvers,
        **outcome,
        "answer_signature_verified": True,
        **_audit_fields(attempt_log, await audit.answered(outcome)),
        "answer": data,
    }


# --------------------------------------------------------------------------- #
# Evidence (§11)
# --------------------------------------------------------------------------- #

_EXPORT_ID_DOC = Doc(
    "Export id and idempotency key, [A-Za-z0-9._:-]{1,128} (e.g. case-42:ev-1)."
)
_FINDING_ID_DOC = Doc(
    "finding selector: the finding's finding_id (1..256 bytes). Give it with "
    "evidence_links; exactly one selector per export."
)
_EVIDENCE_LINKS_DOC = Doc(
    "finding selector: 1..64 robodr-blackbox:// links of this robot (the "
    "finding's evidence_links)."
)
_CONTEXT_RECORDS_DOC = Doc(
    "finding selector: records exported on each side of the linked ones, "
    "0..1024 (robot default 16)."
)
_FROM_SEQ_DOC = Doc("seq_range selector: first black-box seq (with to_seq).")
_TO_SEQ_DOC = Doc("seq_range selector: last black-box seq, >= from_seq.")
_FROM_MS_DOC = Doc("time_range selector: start, Unix ms (with to_ms).")
_TO_MS_DOC = Doc("time_range selector: end, Unix ms; at most 7 days after from_ms.")
_EXPORT_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def _check_export_id(export_id: object) -> str:
    if not isinstance(export_id, str) or not _full(_EXPORT_ID_RE, export_id):
        raise ValueError("export_id must match [A-Za-z0-9._:-]{1,128}")
    return export_id


@dataclass
class _AccessAudit:
    """What the platform audit log records for one evidence read or delete."""

    robot_id: str
    operation: EvidenceOperation
    export_id: str | None = None

    async def attempt(self) -> str:
        """Record the access before the robot is contacted.

        Fails closed: an evidence access the platform does not record (the
        route refused, the audit sink did not confirm it) is refused, never
        done unaudited.

        Returns:
            The audit log result (see :func:`_audit_log`).
        """
        try:
            answer = await self._record()
        except Exception as exc:
            raise EvidenceError(
                f"the platform did not audit-log this evidence access "
                f"({self.operation}: {type(exc).__name__}: {exc}); nothing was "
                "sent to the robot. Check that the workflow's executor may "
                "record evidence access"
            ) from exc
        return _audit_log(answer)

    async def succeeded(self) -> str:
        """Record that the access completed; best effort."""
        return await self._after(phase="succeeded")

    async def failed(self, exc: BaseException) -> str:
        """Record that the access failed; best effort, also when cancelled."""
        return await _record_shielded(
            self._after(phase="failed", failure_reason=type(exc).__name__)
        )

    async def _after(self, **fields: Any) -> str:
        try:
            return _audit_log(await self._record(**fields))
        except Exception:
            return "failed"

    async def _record(self, **fields: Any) -> Any:
        return await get_context().robot_edr.record_evidence_access(
            robot_id=self.robot_id,
            operation=self.operation,
            export_id=self.export_id,
            **fields,
        )


def _access_fields(attempt_log: str, outcome_log: str) -> dict[str, Any]:
    """The audit results an evidence access reports."""
    return {
        "audit_logged": attempt_log == "written",
        "audit_log": attempt_log,
        "outcome_audit_log": outcome_log,
    }


async def _registered_blackbox_keys(
    robot_id: str, from_ms: int | None, to_ms: int | None
) -> list[str]:
    """The black-box keys the robot registered at fleet enrollment.

    Only those valid for the selected record times (the whole history when
    the selector names no times), newest first.
    """
    try:
        keys = await get_context().robot_edr.blackbox_public_keys(
            robot_id, from_ms=from_ms, to_ms=to_ms
        )
    except Exception as exc:  # fail closed: no keyring, no verification
        raise EvidenceError(
            "no black-box public keys given and none registered for the robot "
            f"({type(exc).__name__}); pass blackbox_public_keys"
        ) from exc
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        raise EvidenceError("the platform returned malformed black-box keys")
    return keys


@registry.register(
    default_title="List RoboDR evidence",
    description=(
        "Read a robot's black-box evidence inventory: chain identity, retained "
        "seqs and gaps, head, kept exports and export limits. Read-only, signed "
        "answer, audit-logged."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
)
async def list_evidence(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    robot_ca_pem: Annotated[str, _ROBOT_CA_DOC],
    answer_public_key_hex: Annotated[str, _ANSWER_KEY_DOC],
    robot_spki_sha256: Annotated[str | None, _SPKI_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    robot = _robot(
        base_url=base_url,
        robot_id=robot_id,
        robot_ca_pem=robot_ca_pem,
        robot_spki_sha256=robot_spki_sha256,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    access = _AccessAudit(robot.robot_id, "list")
    attempt_log = await access.attempt()
    try:
        answer = await _call_retrying(
            robot, "GET", _robot_target(robot.robot_id, "evidence")
        )
        data = answer.json()
    except BaseException as exc:
        await access.failed(exc)
        raise
    return {
        "answer_signature_verified": True,
        **_access_fields(attempt_log, await access.succeeded()),
        "data": data,
    }


@dataclass(frozen=True, slots=True)
class _VerifiedManifest:
    manifest: Manifest
    manifest_bytes: bytes
    manifest_signature: str
    status: int


def _verified_manifest(
    robot: _Robot,
    answer: SignedAnswer,
    export_id: str,
    selector: dict[str, Any],
) -> _VerifiedManifest:
    """§11.6 step 2: manifest signature, identity fields and the selector."""
    header = answer.raw.header("X-RoboDR-Manifest-Signature")
    verify_manifest_signature(
        answer.body, header, robot.answer_key, robot.answer_key_id
    )
    manifest = parse_manifest(answer.body, robot_id=robot.robot_id, export_id=export_id)
    if not selector_matches(manifest, selector, robot.robot_id):
        raise EvidenceError("the manifest's selector is not the one asked for")
    return _VerifiedManifest(manifest, answer.body, header or "", answer.status)


def _selector(
    robot_id: str,
    finding_id: str | None,
    evidence_links: list[str] | None,
    context_records: int | None,
    from_seq: int | None,
    to_seq: int | None,
    from_ms: int | None,
    to_ms: int | None,
) -> dict[str, Any]:
    return build_selector(
        robot_id=robot_id,
        finding_id=finding_id,
        evidence_links=evidence_links,
        context_records=context_records,
        from_seq=from_seq,
        to_seq=to_seq,
        from_ms=from_ms,
        to_ms=to_ms,
    )


@registry.register(
    default_title="Create RoboDR evidence export",
    description=(
        "Ask a robot to export black-box evidence for exactly one selector: a "
        "finding's evidence links (with context records), a seq range or a time "
        "range. Returns the export manifest after checking its manifest "
        "signature and selector. Read-only for the robot (the export is "
        "recorded in its black box), so no sign-off is needed; audit-logged. "
        "The same export_id with the same selector returns the same manifest."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
)
async def create_evidence_export(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    robot_ca_pem: Annotated[str, _ROBOT_CA_DOC],
    answer_public_key_hex: Annotated[str, _ANSWER_KEY_DOC],
    export_id: Annotated[str, _EXPORT_ID_DOC],
    requested_by: Annotated[
        str, Doc("Who asks, 1..100 characters without control characters.")
    ],
    reason: Annotated[str, Doc("Why, at most 500 characters.")] = "",
    finding_id: Annotated[str | None, _FINDING_ID_DOC] = None,
    evidence_links: Annotated[list[str] | None, _EVIDENCE_LINKS_DOC] = None,
    context_records: Annotated[int | None, _CONTEXT_RECORDS_DOC] = None,
    from_seq: Annotated[int | None, _FROM_SEQ_DOC] = None,
    to_seq: Annotated[int | None, _TO_SEQ_DOC] = None,
    from_ms: Annotated[int | None, _FROM_MS_DOC] = None,
    to_ms: Annotated[int | None, _TO_MS_DOC] = None,
    robot_spki_sha256: Annotated[str | None, _SPKI_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    robot = _robot(
        base_url=base_url,
        robot_id=robot_id,
        robot_ca_pem=robot_ca_pem,
        robot_spki_sha256=robot_spki_sha256,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    _check_export_id(export_id)
    if not _text_ok(requested_by, _MAX_IDENTITY_CHARS) or not requested_by:
        raise ValueError(
            "requested_by must be 1..100 characters without control characters"
        )
    _check_reason(reason)
    selector = _selector(
        robot.robot_id,
        finding_id,
        evidence_links,
        context_records,
        from_seq,
        to_seq,
        from_ms,
        to_ms,
    )
    access = _AccessAudit(robot.robot_id, "create_export", export_id)
    attempt_log = await access.attempt()
    body = body_bytes(
        {
            "export_id": export_id,
            "selector": selector,
            "requested_by": requested_by,
            "reason": reason,
        }
    )
    try:
        # The same export_id and selector answer the same export (200), so a
        # busy robot is asked again.
        answer = await _call_retrying(
            robot,
            "POST",
            _robot_target(robot.robot_id, "evidence", "exports"),
            body,
            ok=(200, 201),
            busy_codes=("busy", "evidence_busy"),
        )
        verified = _verified_manifest(robot, answer, export_id, selector)
    except BaseException as exc:
        await access.failed(exc)
        raise
    return {
        "export_id": export_id,
        "created": answer.status == 201,
        "answer_signature_verified": True,
        "manifest_signature_verified": True,
        "manifest_signature": verified.manifest_signature,
        "manifest_sha256": hashlib.sha256(verified.manifest_bytes).hexdigest(),
        **_access_fields(attempt_log, await access.succeeded()),
        "manifest": verified.manifest.raw,
    }


async def _fetch_chunk(robot: _Robot, export_id: str, index: int, size: int) -> bytes:
    """One chunk, retried on transport faults, `busy` and rate limits (§11.5).

    Chunks are immutable and independent, so a retry fetches only this one:
    the download resumes where it stopped. A chunk the robot refuses for good
    (unknown export or chunk, corrupt export) is not retried.
    """
    target = _robot_target(
        robot.robot_id, "evidence", "exports", export_id, "chunks", str(index)
    )
    delay = 1.0
    for attempt in range(1, CHUNK_ATTEMPTS + 1):
        try:
            answer = await _call(robot, "GET", target, max_body=size)
            return answer.body
        except RobotHTTPError as exc:
            if attempt == CHUNK_ATTEMPTS or not (
                exc.fenced or exc.retryable(("busy", "evidence_busy"))
            ):
                raise
            wait = (
                FENCE_RETRY_WAIT_S
                if exc.fenced
                else min(exc.retry_after or delay, MAX_RETRY_AFTER_S)
            )
        except (OSError, TimeoutError, ssl.SSLError):
            if attempt == CHUNK_ATTEMPTS:
                raise
            wait = delay
        await asyncio.sleep(wait)
        delay = min(delay * 2, MAX_RETRY_AFTER_S)
    raise ControlPlaneError("unreachable: chunk retries exhausted")


def _verification_report(
    verified: _VerifiedManifest, report: dict[str, Any]
) -> dict[str, Any]:
    manifest = verified.manifest
    manifest_key = parse_signature_header(verified.manifest_signature)
    return {
        "verified": True,
        "steps": [
            "answer_signatures",
            "manifest_signature",
            "chunk_hashes",
            "bundle",
            "manifest_consistency",
        ],
        "manifest_sha256": hashlib.sha256(verified.manifest_bytes).hexdigest(),
        "manifest_key_id": manifest_key[0] if manifest_key else None,
        "bundle_sha256": manifest.bundle_sha256,
        "bundle_bytes": manifest.bundle_bytes,
        "chunks": len(manifest.chunks),
        **report,
    }


@registry.register(
    default_title="Download RoboDR evidence export",
    description=(
        "Download an evidence export chunk by chunk (resuming after transient "
        "faults), verify it as robodr.control-plane §11.6 requires (answer "
        "signatures, manifest signature, chunk and bundle SHA-256, every "
        "black-box record's hash, signature and chain under the robot's "
        "black-box keyring, and the result against the manifest) and store the "
        "verified bundle for the case. Nothing that fails verification is "
        "stored. Read-only for the robot unless delete_after_download; "
        "audit-logged."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
    required_entitlements=["robot_edr"],
)
async def download_evidence_export(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    robot_ca_pem: Annotated[str, _ROBOT_CA_DOC],
    answer_public_key_hex: Annotated[str, _ANSWER_KEY_DOC],
    export_id: Annotated[str, _EXPORT_ID_DOC],
    case_id: Annotated[str, Doc("Case the verified evidence is stored for.")],
    blackbox_public_keys: Annotated[
        list[str] | None,
        Doc(
            "The robot's black-box public key files (robodr-blackbox keygen "
            ".pub JSON), every key the chain names across rotations. Public "
            "key files only. Omit to use the black-box keys the robot "
            "registered at fleet enrollment that are valid for the selected "
            "record times (newest first; more than 16 is an error)."
        ),
    ] = None,
    finding_id: Annotated[str | None, _FINDING_ID_DOC] = None,
    evidence_links: Annotated[list[str] | None, _EVIDENCE_LINKS_DOC] = None,
    context_records: Annotated[int | None, _CONTEXT_RECORDS_DOC] = None,
    from_seq: Annotated[int | None, _FROM_SEQ_DOC] = None,
    to_seq: Annotated[int | None, _TO_SEQ_DOC] = None,
    from_ms: Annotated[int | None, _FROM_MS_DOC] = None,
    to_ms: Annotated[int | None, _TO_MS_DOC] = None,
    delete_after_download: Annotated[
        bool,
        Doc("Delete the export on the robot once it is verified and stored."),
    ] = False,
    robot_spki_sha256: Annotated[str | None, _SPKI_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    robot = _robot(
        base_url=base_url,
        robot_id=robot_id,
        robot_ca_pem=robot_ca_pem,
        robot_spki_sha256=robot_spki_sha256,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    _check_export_id(export_id)
    if blackbox_public_keys is None:
        blackbox_public_keys = await _registered_blackbox_keys(
            robot.robot_id, from_ms, to_ms
        )
    keyring = parse_blackbox_keyring(blackbox_public_keys)
    selector = _selector(
        robot.robot_id,
        finding_id,
        evidence_links,
        context_records,
        from_seq,
        to_seq,
        from_ms,
        to_ms,
    )
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id is required")
    access = _AccessAudit(robot.robot_id, "download_export", export_id)
    attempt_log = await access.attempt()
    try:
        # Step 1-2: the manifest (signed answer, signed manifest, the selector).
        export_target = _robot_target(robot.robot_id, "evidence", "exports", export_id)
        verified = _verified_manifest(
            robot,
            await _call_retrying(robot, "GET", export_target),
            export_id,
            selector,
        )
        manifest = verified.manifest
        if manifest.bundle_bytes > MAX_STORED_BUNDLE_BYTES:
            raise EvidenceError(
                f"the export is {manifest.bundle_bytes} bytes; at most "
                f"{MAX_STORED_BUNDLE_BYTES} are downloaded and stored (export a "
                "smaller selection)"
            )

        # Step 3: every chunk (signed answer, length, SHA-256), then the bundle.
        chunks: dict[int, bytes] = {}
        for spec in manifest.chunks:
            data = await _fetch_chunk(robot, export_id, spec.index, spec.size)
            check_chunk(spec, data)
            chunks[spec.index] = data
        bundle = assemble_bundle(manifest, chunks)

        # Step 4-5: the records under the black-box keyring, against the manifest.
        report = verify_bundle(
            bundle,
            keyring,
            robot_id=robot.robot_id,
            signing_key_id=manifest.signing_key_id,
        )
        problems = report.problems or check_report_against_manifest(report, manifest)
        if problems:
            raise EvidenceError(
                "the evidence does not verify: "
                + "; ".join(problems[:5])
                + (
                    ""
                    if all(UNVERIFIABLE in p for p in problems)
                    else " (the robot's black box or the transfer reports a problem: "
                    "investigate before relying on this robot's evidence)"
                )
            )
        verification = _verification_report(verified, report.as_dict())

        stored = await get_context().robot_edr.store_evidence(
            case_id,
            robot_id=robot.robot_id,
            export_id=export_id,
            manifest_base64=base64.b64encode(verified.manifest_bytes).decode("ascii"),
            manifest_signature=verified.manifest_signature,
            bundle_base64=base64.b64encode(bundle).decode("ascii"),
            verification=verification,
        )
    except BaseException as exc:
        await access.failed(exc)
        raise
    outcome_log = await access.succeeded()

    deleted = False
    delete_audit_log: str | None = None
    if delete_after_download:
        deleted, delete_audit_log = await _delete_export(
            robot, export_id, export_target
        )
    return {
        "export_id": export_id,
        "verified": True,
        "verification": verification,
        "stored": stored,
        "deleted": deleted,
        "delete_audit_log": delete_audit_log,
        **_access_fields(attempt_log, outcome_log),
        "manifest": manifest.raw,
    }


async def _delete_export(
    robot: _Robot, export_id: str, export_target: str
) -> tuple[bool, str]:
    """Delete a stored export on the robot, recorded by the platform first.

    The evidence is already stored, so a delete the platform does not record
    is skipped and reported (``deleted: false``) instead of failing the
    download. A failed delete raises after it is recorded.

    Returns:
        Whether the export was deleted, and the delete's audit log result
        (``refused`` when the platform did not record it).
    """
    access = _AccessAudit(robot.robot_id, "delete_export", export_id)
    try:
        attempt_log = await access.attempt()
    except EvidenceError:
        return False, "refused"
    try:
        await _call_retrying(robot, "DELETE", export_target)
    except BaseException as exc:
        await access.failed(exc)
        raise
    await access.succeeded()
    return True, attempt_log
