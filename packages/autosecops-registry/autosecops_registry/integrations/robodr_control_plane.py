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

No robot action is autonomous. Actions that change robot state are registered
with `requires_approval=True`, and `request_action` / `revert_action` also
check the declared approvers: one person, or two different people (neither
the requester) for `safe_pause`, `request_safe_state` and `rollback_config`.
"""

import hashlib
import json
import math
import re
import secrets as pysecrets
import time
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing_extensions import Doc

from autosecops_registry import RegistrySecret, registry, secrets
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
MAX_REQUESTED_BY_CHARS = 100
HUMANOID_REFUSED = frozenset({"safe_pause", "request_safe_state", "rollback_config"})
QUADRUPED_REFUSED = frozenset({"rollback_config"})

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ROBOT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_NAME64_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SOURCE_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_GUID_RE = re.compile(r"^(?:[0-9a-f]{24}|[0-9a-f]{32})$")
_ROS_SEGMENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


class ControlPlaneError(RuntimeError):
    """The robot answered with an HTTP error or an unverifiable answer."""


def wire_name(action: str) -> str:
    return f"{WIRE_PREFIX}{action}"


def resolve_action(action: str) -> ActionSpec:
    """Catalog entry for a wire name (`robot_safe_pause`) or a plain name."""
    name = (
        action.removeprefix(WIRE_PREFIX) if action.startswith(WIRE_PREFIX) else action
    )
    if name not in CATALOG:
        allowed = ", ".join(wire_name(n) for n in CATALOG)
        raise ValueError(f"unknown action {action!r}; allowed: {allowed}")
    return CATALOG[name]


def _ros_name_ok(name: str) -> bool:
    body = name.removeprefix("/")
    segments = body.split("/")
    return (
        bool(body)
        and len(segments) <= 16
        and all(_ROS_SEGMENT_RE.match(seg) for seg in segments)
    )


def _text_ok(text: str, max_chars: int) -> bool:
    return len(text) <= max_chars and all(
        ch.isprintable() and ch not in "\x85  " for ch in text
    )


def _normalise_people(people: list[str] | None) -> list[str]:
    return [p.strip() for p in (people or []) if isinstance(p, str) and p.strip()]


def _check_action_policy(
    action: str,
    requested_by: str,
    approved_by: list[str] | None,
    morphology: str | None = None,
    advertised_actions: list[str] | None = None,
) -> dict[str, Any]:
    """The SOC-side gate. Returns `allowed` and every reason it is not."""
    reasons: list[str] = []
    try:
        spec = resolve_action(action)
    except ValueError as exc:
        return {
            "allowed": False,
            "action": action,
            "approval": None,
            "required_approvals": None,
            "reasons": [str(exc)],
        }
    requester = requested_by.strip().casefold()
    approvers = _normalise_people(approved_by)
    folded = [a.casefold() for a in approvers]
    required = 2 if spec.two_person else 1
    if not requester:
        reasons.append("requested_by is required")
    if requester and requester in folded:
        reasons.append("the requester cannot approve their own request")
    if len(set(folded)) != len(folded):
        reasons.append("each approver must be a different person")
    distinct = {a for a in folded if a != requester}
    if len(distinct) < required:
        reasons.append(
            f"{wire_name(spec.name)} needs {required} approval(s) from people other "
            f"than the requester; got {len(distinct)}"
        )
    shape = (morphology or "").strip().lower()
    if shape in ("", "unspecified", "humanoid") and spec.name in HUMANOID_REFUSED:
        # The robot refuses these with fall_hazard for a humanoid and for an
        # unspecified morphology; refuse before anything is sent.
        reasons.append(
            f"{wire_name(spec.name)} is never sent to a humanoid or a robot of "
            f"unknown morphology (morphology={shape or 'unknown'}): it may "
            "de-energise the joints and a balancing robot falls"
        )
    elif shape == "quadruped" and spec.name in QUADRUPED_REFUSED:
        reasons.append(
            "robot_rollback_config is never sent to a quadruped: a controller "
            "restart collapses a robot that balances actively"
        )
    if advertised_actions is not None and spec.name not in advertised_actions:
        reasons.append(f"the robot does not offer {spec.name} (snapshot `actions`)")
    return {
        "allowed": not reasons,
        "action": spec.name,
        "wire_name": wire_name(spec.name),
        "approval": "two_person" if spec.two_person else "single",
        "required_approvals": required,
        "approved_by": approvers,
        "reversible": spec.reversible,
        "reasons": reasons,
    }


@registry.register(
    default_title="Check RoboDR action policy",
    description=(
        "Check a robot action request against the SOC-side rules before it is "
        "sent: catalog action, approvals (single or two-person, never the "
        "requester), and morphology (no safe_pause, request_safe_state or "
        "rollback_config on a humanoid; no rollback_config on a quadruped)."
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
    requested_by: Annotated[str, Doc("Person who requests the action.")],
    approved_by: Annotated[
        list[str] | None,
        Doc("People who approved the request. Two-person actions need two."),
    ] = None,
    morphology: Annotated[
        str | None,
        Doc(
            "Robot morphology from the robot snapshot (humanoid, quadruped, "
            "wheeled_mobile, ...). Unknown is treated like humanoid."
        ),
    ] = None,
    advertised_actions: Annotated[
        list[str] | None,
        Doc("The robot snapshot's `actions` list (plain names)."),
    ] = None,
) -> dict[str, Any]:
    return _check_action_policy(
        action, requested_by, approved_by, morphology, advertised_actions
    )


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
    if "workspace_zone" in given and not _NAME64_RE.match(str(given["workspace_zone"])):
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
        if "participant_guid" in given and not _GUID_RE.match(
            given["participant_guid"]
        ):
            raise ValueError("participant_guid must be 24 or 32 lower-case hex")
        if "node" in given and not _ros_name_ok(given["node"]):
            raise ValueError("node must be a plain ROS 2 node name")
    if spec.name == "rollback_config":
        given.setdefault("config", "profile")
        if given["config"] not in ("profile", "program"):
            raise ValueError("config must be profile or program")
        if "to_version" in given and not _NAME64_RE.match(given["to_version"]):
            raise ValueError("to_version must match [A-Za-z0-9._-]{1,64}")
    return given


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
    if not _ROBOT_ID_RE.match(robot_id):
        raise ValueError("robot_id must match [A-Za-z0-9._-]{1,64}")
    parts = ["", "api", "v1", "robots", quote(robot_id, safe="")]
    parts += [quote(p, safe="") for p in rest]
    return "/".join(parts)


def _parse_answer_signature(header: str) -> tuple[str, bytes] | None:
    fields = header.split(";")
    if len(fields) != 3 or fields[0] != "ed25519":
        return None
    if not fields[1].startswith("key_id=") or not fields[2].startswith("sig="):
        return None
    sig_hex = fields[2].removeprefix("sig=")
    if len(sig_hex) != 128 or any(c not in "0123456789abcdef" for c in sig_hex):
        return None
    return fields[1].removeprefix("key_id="), bytes.fromhex(sig_hex)


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
    }
    if method == "POST":
        headers["Content-Type"] = "application/json"
    # The signature covers the target exactly as sent: build the URL from the
    # raw (already percent-encoded) target and keep httpx from re-encoding it.
    url = httpx.URL(base_url.rstrip("/")).copy_with(raw_path=target.encode("ascii"))
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S) as client:
        response = await client.request(
            method, url, headers=headers, content=body if method == "POST" else None
        )
    answer = response.content[: MAX_ANSWER_BYTES + 1]
    if len(answer) > MAX_ANSWER_BYTES:
        raise ControlPlaneError("the robot's answer exceeds 256 KiB")

    answer_verified: bool | None = None
    if answer_public_key_hex is not None:
        public_key = parse_public_key_hex(answer_public_key_hex)
        if public_key is None:
            raise ValueError("answer_public_key_hex must be 64 hex digits")
        raw = response.headers.get("X-RoboDR-Answer-Signature")
        parsed = _parse_answer_signature(raw) if raw else None
        if parsed is None:
            raise ControlPlaneError("the answer carries no valid answer signature")
        signed_key_id, answer_sig = parsed
        if answer_key_id is not None and signed_key_id != answer_key_id:
            raise ControlPlaneError("the answer is signed by an unexpected key id")
        message = answer_message(signature_hex, response.status_code, answer)
        if not ed25519_verify_strict(public_key, message, answer_sig):
            raise ControlPlaneError("the answer signature does not verify")
        answer_verified = True

    try:
        data = json.loads(answer) if answer else None
    except json.JSONDecodeError:
        data = None
    if response.status_code != 200:
        error = data.get("error") if isinstance(data, dict) else None
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        raise ControlPlaneError(
            f"robot answered HTTP {response.status_code}"
            f" ({code or 'no error code'}): {message or 'no message'}"
        )
    if not isinstance(data, dict):
        raise ControlPlaneError("the robot's answer is not a JSON object")
    return {
        "status_code": response.status_code,
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


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #

_BASE_URL_DOC = Doc(
    "Robot control-plane URL (scheme://host[:port]) of the TLS terminator in "
    "front of robodr-agentd. It must forward the request target unchanged."
)
_ROBOT_ID_DOC = Doc("Robot id robodr-agentd is configured with.")
_ANSWER_KEY_DOC = Doc(
    "Optional robot finding public key (64 hex). When set, the answer must carry "
    "a valid X-RoboDR-Answer-Signature bound to this request."
)
_ANSWER_KEY_ID_DOC = Doc("Optional expected key id of the answer signature.")


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


@registry.register(
    default_title="Request RoboDR robot action",
    description=(
        "Send one approved catalog action request (robot_restrict_motion, "
        "robot_quarantine_node, robot_isolate_network, robot_record_evidence, "
        "robot_safe_pause, robot_request_safe_state, robot_rollback_config) to a "
        "robot's control plane. The robot judges it against its safety state and "
        "may refuse it. The current RoboDR release records but never executes: "
        "recorded_not_executed is reported as not applied."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
    requires_approval=True,
)
async def request_action(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    action: Annotated[
        str,
        Doc("Catalog action by wire name (robot_<name>) or plain name."),
    ],
    requested_by: Annotated[str, Doc("Requester, 1..100 characters.")],
    approved_by: Annotated[
        list[str],
        Doc(
            "Approvers other than the requester: one, or two different people "
            "for robot_safe_pause, robot_request_safe_state, robot_rollback_config."
        ),
    ],
    reason: Annotated[
        str, Doc("Why the action is requested, at most 500 characters.")
    ] = "",
    source: Annotated[str, Doc("SOC label, [a-z0-9_-]{1,32}.")] = "autosecops",
    ttl_seconds: Annotated[
        int | None,
        Doc(
            "Lifetime in seconds, 1..86400. Required for restrict_motion and "
            "isolate_network; not allowed for the other actions."
        ),
    ] = None,
    request_id: Annotated[
        str | None,
        Doc(
            "Idempotency key, [A-Za-z0-9._:-]{1,128}. Reuse only to resubmit the "
            "identical request. Default: robot_<action>:<robot_id>:<random>."
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
    answer_public_key_hex: Annotated[str | None, _ANSWER_KEY_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    spec = resolve_action(action)
    if not _text_ok(requested_by, MAX_REQUESTED_BY_CHARS) or not requested_by.strip():
        raise ValueError(
            "requested_by must be 1..100 characters without control characters"
        )
    if not _text_ok(reason, MAX_REASON_CHARS):
        raise ValueError(
            "reason must be at most 500 characters without control characters"
        )
    if not _SOURCE_RE.match(source):
        raise ValueError("source must match [a-z0-9_-]{1,32}")
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
    if not _ID_RE.match(request_id):
        raise ValueError("request_id must match [A-Za-z0-9._:-]{1,128}")

    # Re-check the policy against the robot's own snapshot before sending.
    snapshot = await get_robot(base_url, robot_id, answer_public_key_hex, answer_key_id)
    snap = snapshot["data"]
    advertised = snap.get("actions")
    policy = _check_action_policy(
        spec.name,
        requested_by,
        approved_by,
        morphology=snap.get("morphology")
        if isinstance(snap.get("morphology"), str)
        else None,
        advertised_actions=advertised if isinstance(advertised, list) else None,
    )
    if not policy["allowed"]:
        raise ValueError(
            "request refused by the SOC policy: " + "; ".join(policy["reasons"])
        )

    body_obj: dict[str, Any] = {
        "request_id": request_id,
        "action": spec.name,
        "parameters": parameters,
    }
    if ttl_seconds is not None:
        body_obj["ttl_seconds"] = ttl_seconds
    body_obj |= {
        "reason": reason,
        "requested_by": requested_by,
        "source": source,
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
        "request_id": request_id,
        "action": spec.name,
        "wire_name": wire_name(spec.name),
        "approved_by": policy["approved_by"],
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
    if not _ID_RE.match(request_id):
        raise ValueError("request_id must match [A-Za-z0-9._:-]{1,128}")
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
    default_title="Revert RoboDR action",
    description=(
        "Ask a robot to revert an action request. request_safe_state and "
        "rollback_config are not reversible (refused, not_reversible); a request "
        "that never took effect answers not_applied."
    ),
    display_group=DISPLAY_GROUP,
    doc_url=DOC_URL,
    namespace="tools.robodr",
    secrets=[robodr_control_plane_secret],
    requires_approval=True,
)
async def revert_action(
    base_url: Annotated[str, _BASE_URL_DOC],
    robot_id: Annotated[str, _ROBOT_ID_DOC],
    request_id: Annotated[str, Doc("The request_id of the action request.")],
    requested_by: Annotated[str, Doc("Requester, 1..100 characters.")],
    approved_by: Annotated[
        list[str],
        Doc("At least one approver other than the requester."),
    ],
    reason: Annotated[str, Doc("Why, at most 500 characters.")] = "",
    answer_public_key_hex: Annotated[str | None, _ANSWER_KEY_DOC] = None,
    answer_key_id: Annotated[str | None, _ANSWER_KEY_ID_DOC] = None,
) -> dict[str, Any]:
    if not _ID_RE.match(request_id):
        raise ValueError("request_id must match [A-Za-z0-9._:-]{1,128}")
    if not _text_ok(requested_by, MAX_REQUESTED_BY_CHARS) or not requested_by.strip():
        raise ValueError(
            "requested_by must be 1..100 characters without control characters"
        )
    if not _text_ok(reason, MAX_REASON_CHARS):
        raise ValueError(
            "reason must be at most 500 characters without control characters"
        )
    requester = requested_by.strip().casefold()
    approvers = {a.casefold() for a in _normalise_people(approved_by)} - {requester}
    if not approvers:
        raise ValueError("a revert needs one approver other than the requester")
    body = json.dumps(
        {"reason": reason, "requested_by": requested_by},
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
        **_outcome(answer["data"]),
        "answer_signature_verified": answer["answer_signature_verified"],
        "answer": answer["data"],
    }
