"""RoboDR robot control plane v1 (`robodr-control-plane/v1`).

A SOC asks a robot's on-board agent (`robodr-agentd`) for one of seven catalog
actions. The robot judges each request against its current safety state and
may refuse it. In the current RoboDR release nothing is executed: an accepted
request answers `recorded_not_executed` with `executed: false`, which these
actions report as not applied.

Every request is signed with the SOC's Ed25519 key over

    robodr-control-plane/v1
    <METHOD>
    <request target exactly as sent>
    <robot id>
    <key id>
    <timestamp: Unix seconds>
    <nonce>
    <lower-case hex SHA-256 of the body bytes>

(lines joined by LF, no trailing newline), sent as `X-RoboDR-Key-Id`,
`X-RoboDR-Timestamp`, `X-RoboDR-Nonce` and `X-RoboDR-Signature`.

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
   submission carries `robodr_request_id` and `robodr_request_digest`.
3. `request_action` / `revert_action` take the submission ids, fetch each
   submission from the platform (`ctx.forms.get_submission`) and require:
   submitted by a platform user (`submitted_by.type == "user"`, never a
   service account; workflows, agents and the executor have no
   `form:submit` scope, so they cannot create one), the same form for all, the
   same request id and digest as the request being sent, the right decision,
   and at most 24 hours old. People are identified only by the platform user
   ids on those records; no action input names a person. An approver must
   differ from the requester and from every other approver: one approval, or
   two for `safe_pause`, `request_safe_state`, `rollback_config` and the
   revert of any of them (the robot's stored request says which action a
   revert undoes).
4. Any failure (no platform context, unreadable submission, mismatch) raises
   `SignoffError` before a request is signed, and nothing reaches the robot.

`requires_approval=True` additionally pauses an agent's tool call in the
inbox, but that gate is not relied on: a workflow step calling the action
directly, or an agent whose tool approval was turned off, still needs the
sign-off submissions above. The robot's answers, including the snapshot the
morphology check reads, must carry a valid answer signature for these two
actions (`answer_public_key_hex` is required).
"""

import hashlib
import ipaddress
import json
import math
import re
import secrets as pysecrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import quote, urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing_extensions import Doc

from autosecops_registry import RegistrySecret, registry, secrets
from autosecops_registry.context import get_context
from autosecops_registry.integrations.robodr import (
    DISPLAY_GROUP,
    DOC_URL,
    ed25519_verify_strict,
    parse_public_key_hex,
)

API_VERSION = "robodr-control-plane/v1"
REQUEST_TIMEOUT_S = 10.0
MAX_ANSWER_BYTES = 256 * 1024

robodr_control_plane_secret = RegistrySecret(
    name="robodr_control_plane",
    keys=["ROBODR_SOC_KEY_ID", "ROBODR_SOC_SECRET_HEX"],
)
"""SOC signing key: `key_id` and `secret_hex` (32-byte Ed25519 seed, 64 hex)
from the `robodr-blackbox keygen` secret key file whose `.pub` is installed on
the robot (`control_plane.soc_keys`)."""


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

# Sign-off form (see the module docstring).
SIGNOFF_REQUEST_ID = "robodr_request_id"
SIGNOFF_DIGEST = "robodr_request_digest"
SIGNOFF_DECISION = "robodr_decision"
MAX_SIGNOFF_AGE = timedelta(hours=24)
MAX_SIGNOFF_CLOCK_SKEW = timedelta(minutes=5)
MAX_APPROVAL_SUBMISSIONS = 4


class ControlPlaneError(RuntimeError):
    """The robot answered with an HTTP error or an unverifiable answer."""


class SignoffError(PermissionError):
    """The platform does not prove the sign-off this request needs."""


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
        if "to_version" in given and not _full(_NAME64_RE, given["to_version"]):
            raise ValueError("to_version must match [A-Za-z0-9._-]{1,64}")
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
    request_submission_id: object,
    approval_submission_ids: object,
) -> tuple[Person, list[Person]]:
    """Read the sign-off submissions from the platform and check them.

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


# --------------------------------------------------------------------------- #
# Signed transport
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
    return f"{API_VERSION} answer\n{request_signature_hex}\n{status}\n{digest}".encode()


def _signing_key() -> tuple[str, Ed25519PrivateKey]:
    key_id = secrets.get("ROBODR_SOC_KEY_ID")
    secret_hex = secrets.get("ROBODR_SOC_SECRET_HEX")
    if not key_id or not all("!" <= c <= "~" for c in key_id) or len(key_id) > 128:
        raise ValueError("ROBODR_SOC_KEY_ID must be 1..128 printable ASCII")
    seed = parse_public_key_hex(secret_hex or "")
    if seed is None:
        raise ValueError("ROBODR_SOC_SECRET_HEX must be a 64-hex-digit Ed25519 seed")
    return key_id, Ed25519PrivateKey.from_private_bytes(seed)


def _robot_target(robot_id: str, *rest: str) -> str:
    _check_robot_id(robot_id)
    parts = ["", "api", "v1", "robots", quote(robot_id, safe="")]
    parts += [quote(p, safe="") for p in rest]
    return "/".join(parts)


def _robot_url(base_url: object, target: str) -> httpx.URL:
    """The request URL: `base_url` (scheme and authority only) plus `target`.

    https only; plain http only to a loopback IP literal (a local TLS
    terminator). A path prefix is refused: the signature covers the target
    exactly as sent, and robodr-agentd serves `/api/v1/...` at the root.
    """
    if (
        not isinstance(base_url, str)
        or not base_url.isascii()
        or any(not ("!" <= c <= "~") for c in base_url)
        or "?" in base_url
        or "#" in base_url
    ):
        raise ValueError("base_url must be scheme://host[:port] in printable ASCII")
    try:
        parts = urlsplit(base_url)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"base_url is not a valid URL: {exc}") from exc
    host = parts.hostname
    if not host or parts.username is not None or parts.password is not None:
        raise ValueError("base_url must be scheme://host[:port] without credentials")
    if parts.path not in ("", "/"):
        raise ValueError(
            "base_url must not carry a path: the robot serves /api/v1 at the root "
            "and the signature covers the target exactly as sent"
        )
    if parts.scheme == "http":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ValueError(
                "base_url must be https; plain http is allowed only to a "
                "loopback IP literal"
            )
    elif parts.scheme != "https":
        raise ValueError("base_url must be https")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    # The signature covers the target exactly as sent: build the URL from the
    # raw (already percent-encoded) target and keep httpx from re-encoding it.
    return httpx.URL(f"{parts.scheme}://{netloc}").copy_with(
        raw_path=target.encode("ascii")
    )


def _parse_answer_signature(header: str) -> tuple[str, bytes] | None:
    fields = header.split(";")
    if len(fields) != 3 or fields[0] != "ed25519":
        return None
    if not fields[1].startswith("key_id=") or not fields[2].startswith("sig="):
        return None
    key_id = fields[1].removeprefix("key_id=")
    if not _full(_KEY_ID_RE, key_id):
        return None
    sig_hex = fields[2].removeprefix("sig=")
    if len(sig_hex) != 128 or any(c not in "0123456789abcdef" for c in sig_hex):
        return None
    return key_id, bytes.fromhex(sig_hex)


def _check_answer_key(
    answer_public_key_hex: object, answer_key_id: object, *, required: bool
) -> None:
    if answer_public_key_hex in (None, ""):
        if required:
            raise ValueError(
                "answer_public_key_hex is required: state-changing requests are "
                "sent only when the robot's answers (and the snapshot they are "
                "judged against) are signed by the robot's key"
            )
    elif not isinstance(answer_public_key_hex, str) or (
        parse_public_key_hex(answer_public_key_hex) is None
    ):
        raise ValueError("answer_public_key_hex must be 64 hex digits")
    if answer_key_id is not None and not _full(_KEY_ID_RE, answer_key_id):
        raise ValueError("answer_key_id must be 1..128 printable ASCII without ';'")


async def _read_capped(response: httpx.Response) -> bytes:
    """The body, refusing it as soon as it exceeds MAX_ANSWER_BYTES."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > MAX_ANSWER_BYTES:
            raise ControlPlaneError("the robot's answer exceeds 256 KiB")
        chunks.append(chunk)
    return b"".join(chunks)


async def _signed_request(
    *,
    base_url: str,
    robot_id: str,
    method: str,
    target: str,
    body: bytes,
    answer_public_key_hex: str | None,
    answer_key_id: str | None,
) -> dict[str, Any]:
    _check_answer_key(answer_public_key_hex, answer_key_id, required=False)
    url = _robot_url(base_url, target)
    key_id, private_key = _signing_key()
    timestamp = int(time.time())
    nonce = pysecrets.token_urlsafe(24)
    signature = private_key.sign(
        signing_message(method, target, robot_id, key_id, timestamp, nonce, body)
    )
    signature_hex = signature.hex()
    headers = {
        "X-RoboDR-Key-Id": key_id,
        "X-RoboDR-Timestamp": str(timestamp),
        "X-RoboDR-Nonce": nonce,
        "X-RoboDR-Signature": signature_hex,
        "Connection": "close",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    if method == "POST":
        headers["Content-Type"] = "application/json"
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_S, follow_redirects=False
    ) as client:
        async with client.stream(
            method, url, headers=headers, content=body if method == "POST" else None
        ) as response:
            answer = await _read_capped(response)
            status_code = response.status_code
            answer_header = response.headers.get("X-RoboDR-Answer-Signature")

    answer_verified: bool | None = None
    if answer_public_key_hex:
        public_key = parse_public_key_hex(answer_public_key_hex)
        if public_key is None:  # checked above; keeps the type checker honest
            raise ValueError("answer_public_key_hex must be 64 hex digits")
        parsed = _parse_answer_signature(answer_header) if answer_header else None
        if parsed is None:
            raise ControlPlaneError("the answer carries no valid answer signature")
        signed_key_id, answer_sig = parsed
        if answer_key_id is not None and signed_key_id != answer_key_id:
            raise ControlPlaneError("the answer is signed by an unexpected key id")
        message = answer_message(signature_hex, status_code, answer)
        if not ed25519_verify_strict(public_key, message, answer_sig):
            raise ControlPlaneError("the answer signature does not verify")
        answer_verified = True

    try:
        data = json.loads(answer) if answer else None
    except ValueError:
        data = None
    if status_code != 200:
        error = data.get("error") if isinstance(data, dict) else None
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        raise ControlPlaneError(
            f"robot answered HTTP {status_code}"
            f" ({_shown(code) if code else 'no error code'}): "
            f"{message if isinstance(message, str) else 'no message'}"
        )
    if not isinstance(data, dict):
        raise ControlPlaneError("the robot's answer is not a JSON object")
    return {
        "status_code": status_code,
        "answer_signature_verified": answer_verified,
        "data": data,
    }


def _outcome(data: dict[str, Any]) -> dict[str, Any]:
    """Report a request state as the contract requires (§5, §9)."""
    status = data.get("status")
    executed = data.get("executed") is True
    applied = status == "applied" and executed
    if status == "recorded_not_executed":
        report = (
            "Not applied: the robot accepted the request and recorded it as a "
            "plan in its black box; it executed nothing."
        )
    elif status == "refused":
        raw_refusal = data.get("refusal")
        refusal: dict[str, Any] = raw_refusal if isinstance(raw_refusal, dict) else {}
        report = (
            f"Refused by the robot ({refusal.get('code')}, safety state "
            f"{refusal.get('safety_state')}): {refusal.get('reason')}. Refusals "
            "are final; do not retry."
        )
    elif status == "failed":
        report = "Failed: the robot's black box did not take the request; nothing was decided."
    elif status == "not_applied":
        report = "Not applied: the request never took effect, so there was nothing to revert."
    elif applied:
        report = "Applied and executed by the robot."
    else:
        report = f"Not applied (status {status!r})."
    return {
        "status": status,
        "executed": executed,
        "applied": applied,
        "terminal": status
        in ("recorded_not_executed", "refused", "failed", "not_applied"),
        "refusal": data.get("refusal"),
        "report": report,
    }


async def _verified_snapshot(
    base_url: str,
    robot_id: str,
    answer_public_key_hex: str,
    answer_key_id: str | None,
) -> dict[str, Any]:
    snapshot = await _signed_request(
        base_url=base_url,
        robot_id=robot_id,
        method="GET",
        target=_robot_target(robot_id),
        body=b"",
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    snap = snapshot["data"]
    if snap.get("robot_id") != robot_id:
        raise ControlPlaneError("the snapshot is for another robot_id")
    return snap


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #

_BASE_URL_DOC = Doc(
    "Robot control-plane URL, https://host[:port] with no path, of the TLS "
    "terminator in front of robodr-agentd (plain http only to a loopback IP "
    "literal). It must forward the request target unchanged."
)
_ROBOT_ID_DOC = Doc("Robot id robodr-agentd is configured with.")
_ANSWER_KEY_DOC = Doc(
    "Robot finding public key (64 hex). When set, the answer must carry a "
    "valid X-RoboDR-Answer-Signature bound to this request."
)
_REQUIRED_ANSWER_KEY_DOC = Doc(
    "Robot finding public key (64 hex). Required: the snapshot and the answer "
    "must carry a valid X-RoboDR-Answer-Signature bound to each request."
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
        "Read a robot's control-plane snapshot: safety state, mode, morphology "
        "and the actions it may be asked for. Read-only."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
)
async def get_robot(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    answer_public_key_hex: Annotated[str | None, _ANSWER_KEY_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    return await _signed_request(
        base_url=base_url,
        robot_id=robot_id,
        method="GET",
        target=_robot_target(robot_id),
        body=b"",
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )


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
        str | None, Doc("rollback_config: target version, [A-Za-z0-9._-]{1,64}.")
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
        },
    }


@registry.register(
    default_title="Request RoboDR robot action",
    description=(
        "Send one signed-off catalog action request (robot_restrict_motion, "
        "robot_quarantine_node, robot_isolate_network, robot_record_evidence, "
        "robot_safe_pause, robot_request_safe_state, robot_rollback_config) to a "
        "robot's control plane. Refuses unless platform form submissions prove "
        "the requester and one approver (two for the two-person actions), all "
        "different platform users, signed off this exact request. The robot "
        "judges it against its safety state and may refuse it. The current "
        "RoboDR release records but never executes: recorded_not_executed is "
        "reported as not applied."
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
    answer_public_key_hex: Annotated[str, _REQUIRED_ANSWER_KEY_DOC],
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
        str | None, Doc("rollback_config: target version, [A-Za-z0-9._-]{1,64}.")
    ] = None,
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
    _check_answer_key(answer_public_key_hex, answer_key_id, required=True)
    _robot_url(base_url, "/")

    # 2. The platform sign-off for exactly this request.
    required = 2 if spec.two_person else 1
    requester, approvers = await _collect_signoff(
        request_id=prepared.request_id,
        digest=request_digest("action", prepared.digest_fields()),
        request_submission_id=request_submission_id,
        approval_submission_ids=approval_submission_ids,
    )
    _require_approvals(wire_name(spec.name), required, approvers)

    # 3. The policy against the robot's own signed snapshot.
    snap = await _verified_snapshot(
        base_url, robot_id, answer_public_key_hex, answer_key_id
    )
    reasons = _policy_reasons(spec, snap.get("morphology"), snap.get("actions"))
    if reasons:
        raise ValueError("request refused by the SOC policy: " + "; ".join(reasons))

    body_obj: dict[str, Any] = {
        "request_id": prepared.request_id,
        "action": spec.name,
        "parameters": prepared.parameters,
    }
    if prepared.ttl_seconds is not None:
        body_obj["ttl_seconds"] = prepared.ttl_seconds
    body_obj |= {
        "reason": prepared.reason,
        "requested_by": requester.identifier,
        "source": prepared.source,
        "authority": "request",
    }
    body = json.dumps(body_obj, separators=(",", ":"), ensure_ascii=True).encode()
    answer = await _signed_request(
        base_url=base_url,
        robot_id=robot_id,
        method="POST",
        target=_robot_target(robot_id, "action-requests"),
        body=body,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    return {
        "request_id": prepared.request_id,
        "action": spec.name,
        "wire_name": wire_name(spec.name),
        "approval": "two_person" if spec.two_person else "single",
        "requested_by": requester.as_dict(),
        "approved_by": [a.as_dict() for a in approvers],
        "robot_safety_state": snap.get("safety_state"),
        **_outcome(answer["data"]),
        "answer_signature_verified": answer["answer_signature_verified"],
        "answer": answer["data"],
    }


@registry.register(
    default_title="Get RoboDR action status",
    description=(
        "Read the stored state of a robot action request. recorded_not_executed, "
        "refused and failed are terminal: never poll them."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
)
async def get_action_status(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    request_id: Annotated[str, Doc("The request_id of the action request.")],
    answer_public_key_hex: Annotated[str | None, _ANSWER_KEY_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    _check_request_id(request_id)
    answer = await _signed_request(
        base_url=base_url,
        robot_id=robot_id,
        method="GET",
        target=_robot_target(robot_id, "action-requests", request_id),
        body=b"",
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    return {
        "request_id": request_id,
        **_outcome(answer["data"]),
        "answer_signature_verified": answer["answer_signature_verified"],
        "answer": answer["data"],
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
        "signoff_answers": {SIGNOFF_REQUEST_ID: request_id, SIGNOFF_DIGEST: digest},
    }


@registry.register(
    default_title="Revert RoboDR action",
    description=(
        "Ask a robot to revert a signed-off action request. Needs the same "
        "platform sign-off as a request (two approvers to revert a two-person "
        "action such as robot_safe_pause). request_safe_state and "
        "rollback_config are not reversible (refused, not_reversible); a request "
        "that never took effect answers not_applied."
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
    request_id: Annotated[str, Doc("The request_id of the action request.")],
    request_submission_id: Annotated[str, _REQUEST_SUBMISSION_DOC],
    approval_submission_ids: Annotated[list[str], _APPROVAL_SUBMISSIONS_DOC],
    answer_public_key_hex: Annotated[str, _REQUIRED_ANSWER_KEY_DOC],
    reason: Annotated[str, Doc("Why, at most 500 characters.")] = "",
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    fields = {
        "robot_id": _check_robot_id(robot_id),
        "request_id": _check_request_id(request_id),
        "reason": _check_reason(reason),
    }
    _check_answer_key(answer_public_key_hex, answer_key_id, required=True)
    _robot_url(base_url, "/")
    requester, approvers = await _collect_signoff(
        request_id=request_id,
        digest=request_digest("revert", fields),
        request_submission_id=request_submission_id,
        approval_submission_ids=approval_submission_ids,
    )

    # Which action the revert undoes decides how many approvals it needs: ask
    # the robot (signed answer) instead of trusting an input.
    stored = await _signed_request(
        base_url=base_url,
        robot_id=robot_id,
        method="GET",
        target=_robot_target(robot_id, "action-requests", request_id),
        body=b"",
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    state = stored["data"].get("state")
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

    snap = await _verified_snapshot(
        base_url, robot_id, answer_public_key_hex, answer_key_id
    )
    reasons = _policy_reasons(spec, snap.get("morphology"))
    if reasons:
        raise ValueError("revert refused by the SOC policy: " + "; ".join(reasons))

    body = json.dumps(
        {"reason": fields["reason"], "requested_by": requester.identifier},
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    answer = await _signed_request(
        base_url=base_url,
        robot_id=robot_id,
        method="POST",
        target=_robot_target(robot_id, "action-requests", request_id, "revert"),
        body=body,
        answer_public_key_hex=answer_public_key_hex,
        answer_key_id=answer_key_id,
    )
    return {
        "request_id": request_id,
        "action": spec.name,
        "approval": "two_person" if spec.two_person else "single",
        "requested_by": requester.as_dict(),
        "approved_by": [a.as_dict() for a in approvers],
        **_outcome(answer["data"]),
        "answer_signature_verified": answer["answer_signature_verified"],
        "answer": answer["data"],
    }
