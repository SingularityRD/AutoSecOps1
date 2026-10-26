"""RoboDR control plane v1: request signing and the SOC-side approval gate.

No real robot: a stub HTTP server on loopback plays robodr-agentd. It records
each raw request (method, target exactly as received, headers, body) and
verifies the SOC signature the way agentd does (`control/auth.rs`), with an
inline copy of the framing.

`GOLDEN_*` vectors come from the reference implementation
(`robodr_agentd::control::auth::signing_message` / `answer_message`) with the
SOC key `Ed25519SigningKey::from_seed("soc:test:1", &[9; 32])` and the robot
finding key from `[7; 32]`.
"""

import contextlib
import hashlib
import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from autosecops_registry._internal import secrets as registry_secrets
from autosecops_registry.integrations import robodr_control_plane as cp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SOC_SEED = bytes([9]) * 32
SOC_KEY_ID = "soc:test:1"
FINDING_SEED = bytes([7]) * 32
FINDING_KEY_ID = "finding:ugv-007:1"
ROBOT_ID = "ugv-007"

GOLDEN_BODY = (
    b'{"request_id":"robot_restrict_motion:ugv-007:00112233aabbccdd",'
    b'"action":"restrict_motion","parameters":{"max_linear_speed":0.5},'
    b'"ttl_seconds":600,"reason":"rogue writer","requested_by":"analyst-a",'
    b'"source":"autosecops","authority":"request"}'
)
GOLDEN_POST_SIG = (
    "3e250b41ddb0b7e1ae2b812e1a07163620ba6177926c162e24912b5646b5b1db"
    "26df458f7dfbabc06c1b3b590a61cfda42288896a96570809719b269ecb49700"
)
GOLDEN_GET_SIG = (
    "a485866e5f90c209dcd3224df51a113e992f2efd9baa5d8106bc86c6c5034921"
    "c73a3ce5f9fbb4d99a497d85637f90fe15045eb2295f3402211c5210debc3609"
)
GOLDEN_ANSWER_SIG = (
    "f2620e348e96187be25f48546bcc8ce46cc6f792c5159d028982135d45176f7c"
    "1ed1db5c314dca7c6401cc01a868db5a53ed6fe63bfa7e7ce0afbfc1421f0501"
)


def _soc_public() -> Ed25519PublicKey:
    return Ed25519PrivateKey.from_private_bytes(SOC_SEED).public_key()


def _agentd_message(
    method: str, target: str, key_id: str, ts: str, nonce: str, body: bytes
) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join(
        ["robodr-control-plane/v1", method, target, ROBOT_ID, key_id, ts, nonce, digest]
    ).encode()


# --------------------------------------------------------------------------- #
# Golden vectors
# --------------------------------------------------------------------------- #


def test_signing_message_matches_reference() -> None:
    message = cp.signing_message(
        "POST",
        "/api/v1/robots/ugv-007/action-requests",
        ROBOT_ID,
        SOC_KEY_ID,
        1790000000,
        "n0nce-0123456789abcdef",
        GOLDEN_BODY,
    )
    assert message == _agentd_message(
        "POST",
        "/api/v1/robots/ugv-007/action-requests",
        SOC_KEY_ID,
        "1790000000",
        "n0nce-0123456789abcdef",
        GOLDEN_BODY,
    )
    signer = Ed25519PrivateKey.from_private_bytes(SOC_SEED)
    assert signer.sign(message).hex() == GOLDEN_POST_SIG
    get_message = cp.signing_message(
        "GET",
        "/api/v1/robots/ugv-007/action-requests/robot_restrict_motion%3Augv-007%3A00112233aabbccdd",
        ROBOT_ID,
        SOC_KEY_ID,
        1790000000,
        "n0nce-0123456789abcdef",
        b"",
    )
    assert signer.sign(get_message).hex() == GOLDEN_GET_SIG


def test_answer_message_matches_reference() -> None:
    message = cp.answer_message(
        GOLDEN_POST_SIG, 200, b'{"status":"recorded_not_executed"}'
    )
    signer = Ed25519PrivateKey.from_private_bytes(FINDING_SEED)
    assert signer.sign(message).hex() == GOLDEN_ANSWER_SIG


def test_target_percent_encodes_request_id() -> None:
    target = cp._robot_target(
        ROBOT_ID, "action-requests", "robot_safe_pause:ugv-007:ab"
    )
    assert (
        target
        == "/api/v1/robots/ugv-007/action-requests/robot_safe_pause%3Augv-007%3Aab"
    )
    with pytest.raises(ValueError):
        cp._robot_target("ugv/../x")


# --------------------------------------------------------------------------- #
# Stub robodr-agentd
# --------------------------------------------------------------------------- #


@dataclass
class StubRobot:
    morphology: str = "wheeled_mobile"
    actions: list[str] = field(
        default_factory=lambda: [
            "restrict_motion",
            "quarantine_node",
            "isolate_network",
            "record_evidence",
            "safe_pause",
            "request_safe_state",
            "rollback_config",
        ]
    )
    sign_answers: bool = False
    answer_status: int = 200
    requests: list[dict[str, Any]] = field(default_factory=list)
    answer_for: Callable[[dict[str, Any]], dict[str, Any]] | None = None

    def handle(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        record = {"method": method, "target": target, "headers": headers, "body": body}
        self.requests.append(record)
        # Verify like agentd: strict headers, signature over the exact target.
        try:
            nonce = headers["x-robodr-nonce"]
            assert 16 <= len(nonce) <= 128
            assert all(c.isalnum() or c in "_-" for c in nonce)
            assert headers["x-robodr-key-id"] == SOC_KEY_ID
            sig = bytes.fromhex(headers["x-robodr-signature"])
            _soc_public().verify(
                sig,
                _agentd_message(
                    method,
                    target,
                    SOC_KEY_ID,
                    headers["x-robodr-timestamp"],
                    nonce,
                    body,
                ),
            )
            record["verified"] = True
        except (KeyError, AssertionError, ValueError, InvalidSignature):
            record["verified"] = False
            out = json.dumps(
                {"error": {"code": "bad_signature", "message": "no"}}
            ).encode()
            return 401, {}, out
        if target == f"/api/v1/robots/{ROBOT_ID}":
            data: dict[str, Any] = {
                "robot_id": ROBOT_ID,
                "online": True,
                "api": "robodr-control-plane/v1",
                "safety_state": {"state": "moving_slow", "source": "safety_feed"},
                "mode": "enforce",
                "executor": "recording",
                "executes_actions": False,
                "morphology": self.morphology,
                "actions": self.actions,
            }
        elif self.answer_for is not None:
            data = self.answer_for(record)
        else:
            data = {
                "request_id": "x",
                "status": "recorded_not_executed",
                "executed": False,
                "state": {"decision": "accepted", "executed": False},
            }
        out = json.dumps(data).encode()
        extra: dict[str, str] = {}
        if self.sign_answers:
            msg = cp.answer_message(
                headers["x-robodr-signature"], self.answer_status, out
            )
            sig = Ed25519PrivateKey.from_private_bytes(FINDING_SEED).sign(msg).hex()
            extra["X-RoboDR-Answer-Signature"] = (
                f"ed25519;key_id={FINDING_KEY_ID};sig={sig}"
            )
        return self.answer_status, extra, out


@contextlib.contextmanager
def soc_secrets() -> Iterator[None]:
    """Scope the registry secrets context to the test SOC signing key."""
    token = registry_secrets.set_context(
        {"ROBODR_SOC_KEY_ID": SOC_KEY_ID, "ROBODR_SOC_SECRET_HEX": SOC_SEED.hex()}
    )
    try:
        yield
    finally:
        registry_secrets.reset_context(token)


@pytest.fixture
def stub() -> Iterator[tuple[StubRobot, str]]:
    robot = StubRobot()

    class Handler(BaseHTTPRequestHandler):
        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            status, extra, out = robot.handle(self.command, self.path, headers, body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(out)

        do_GET = _serve
        do_POST = _serve

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield robot, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# Signed requests against the stub
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_request_action_is_signed_and_reported_not_applied(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        result = await cp.request_action(
            base_url=base_url,
            robot_id=ROBOT_ID,
            action="robot_restrict_motion",
            requested_by="analyst-a",
            approved_by=["lead-b"],
            reason="rogue writer",
            ttl_seconds=600,
            max_linear_speed=0.5,
        )
        snapshot, post = robot.requests
        assert snapshot["method"] == "GET" and snapshot["verified"]
        assert post["method"] == "POST" and post["verified"]
        assert post["target"] == f"/api/v1/robots/{ROBOT_ID}/action-requests"
        body = json.loads(post["body"])
        assert body["action"] == "restrict_motion"
        assert body["parameters"] == {"max_linear_speed": 0.5}
        assert body["ttl_seconds"] == 600
        assert body["authority"] == "request"
        assert set(body) == {
            "request_id",
            "action",
            "parameters",
            "ttl_seconds",
            "reason",
            "requested_by",
            "source",
            "authority",
        }
        assert body["request_id"].startswith("robot_restrict_motion:ugv-007:")
        assert post["headers"]["content-length"] == str(len(post["body"]))
        assert "authorization" not in post["headers"]
        # Each request carries a fresh nonce.
        assert (
            snapshot["headers"]["x-robodr-nonce"] != post["headers"]["x-robodr-nonce"]
        )
        assert result["status"] == "recorded_not_executed"
        assert result["applied"] is False
        assert result["executed"] is False
        assert result["terminal"] is True
        assert "Not applied" in result["report"]


@pytest.mark.anyio
async def test_get_action_status_sends_percent_encoded_target(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        request_id = "robot_restrict_motion:ugv-007:00112233aabbccdd"
        result = await cp.get_action_status(
            base_url=base_url, robot_id=ROBOT_ID, request_id=request_id
        )
        (get,) = robot.requests
        assert get["verified"]
        assert get["target"] == (
            "/api/v1/robots/ugv-007/action-requests/"
            "robot_restrict_motion%3Augv-007%3A00112233aabbccdd"
        )
        assert get["body"] == b""
        assert result["applied"] is False


@pytest.mark.anyio
async def test_revert_action(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.answer_for = lambda r: {
            "request_id": "x",
            "status": "not_applied",
            "executed": False,
        }
        result = await cp.revert_action(
            base_url=base_url,
            robot_id=ROBOT_ID,
            request_id="robot_isolate_network:ugv-007:01",
            requested_by="analyst-a",
            approved_by=["lead-b"],
        )
        (post,) = robot.requests
        assert post["target"].endswith(
            "/action-requests/robot_isolate_network%3Augv-007%3A01/revert"
        )
        assert json.loads(post["body"]) == {"reason": "", "requested_by": "analyst-a"}
        assert result["status"] == "not_applied" and result["applied"] is False
        with pytest.raises(ValueError, match="approver"):
            await cp.revert_action(
                base_url=base_url,
                robot_id=ROBOT_ID,
                request_id="r1",
                requested_by="analyst-a",
                approved_by=["Analyst-A"],
            )


@pytest.mark.anyio
async def test_refusal_is_reported_final(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.answer_for = lambda r: {
            "request_id": "x",
            "status": "refused",
            "executed": False,
            "refusal": {
                "code": "human_in_command",
                "reason": "teleop",
                "safety_state": "moving",
            },
        }
        result = await cp.request_action(
            base_url=base_url,
            robot_id=ROBOT_ID,
            action="isolate_network",
            requested_by="analyst-a",
            approved_by=["lead-b"],
            ttl_seconds=60,
        )
        assert result["status"] == "refused"
        assert result["applied"] is False
        assert "human_in_command" in result["report"]
        assert "do not retry" in result["report"]


@pytest.mark.anyio
async def test_answer_signature_is_verified_when_configured(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        finding_pub = Ed25519PrivateKey.from_private_bytes(FINDING_SEED).public_key()
        pub_hex = finding_pub.public_bytes_raw().hex()
        robot.sign_answers = True
        result = await cp.get_robot(
            base_url=base_url,
            robot_id=ROBOT_ID,
            answer_public_key_hex=pub_hex,
            answer_key_id=FINDING_KEY_ID,
        )
        assert result["answer_signature_verified"] is True
        robot.sign_answers = False
        with pytest.raises(cp.ControlPlaneError, match="answer signature"):
            await cp.get_robot(
                base_url=base_url, robot_id=ROBOT_ID, answer_public_key_hex=pub_hex
            )
        robot.sign_answers = True
        other = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32).public_key()
        with pytest.raises(cp.ControlPlaneError, match="does not verify"):
            await cp.get_robot(
                base_url=base_url,
                robot_id=ROBOT_ID,
                answer_public_key_hex=other.public_bytes_raw().hex(),
            )


@pytest.mark.anyio
async def test_http_error_raises_with_code(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.answer_status = 409
        robot.answer_for = lambda r: {
            "error": {"code": "request_id_conflict", "message": "used"}
        }
        with pytest.raises(cp.ControlPlaneError, match="409.*request_id_conflict"):
            await cp.get_action_status(
                base_url=base_url, robot_id=ROBOT_ID, request_id="r1"
            )


# --------------------------------------------------------------------------- #
# Approval and morphology gate (nothing is sent when it refuses)
# --------------------------------------------------------------------------- #

TWO_PERSON = ["robot_safe_pause", "robot_request_safe_state", "robot_rollback_config"]


@pytest.mark.parametrize("action", TWO_PERSON)
def test_two_person_actions_need_two_distinct_approvers(action: str) -> None:
    one = cp.check_action_policy(
        action, "analyst-a", ["lead-b"], morphology="wheeled_mobile"
    )
    assert one["allowed"] is False
    assert one["approval"] == "two_person"
    same = cp.check_action_policy(
        action, "analyst-a", ["lead-b", "LEAD-B"], morphology="wheeled_mobile"
    )
    assert same["allowed"] is False
    with_requester = cp.check_action_policy(
        action, "analyst-a", ["lead-b", "analyst-a"], morphology="wheeled_mobile"
    )
    assert with_requester["allowed"] is False
    ok = cp.check_action_policy(
        action, "analyst-a", ["lead-b", "lead-c"], morphology="wheeled_mobile"
    )
    assert ok["allowed"] is True, ok["reasons"]


@pytest.mark.parametrize("action", sorted(cp.CATALOG))
def test_no_action_without_approval(action: str) -> None:
    result = cp.check_action_policy(
        action, "analyst-a", [], morphology="wheeled_mobile"
    )
    assert result["allowed"] is False
    self_approved = cp.check_action_policy(
        action, "analyst-a", ["analyst-a"], morphology="wheeled_mobile"
    )
    assert self_approved["allowed"] is False


@pytest.mark.parametrize("morphology", ["humanoid", "unspecified", None, ""])
@pytest.mark.parametrize("action", TWO_PERSON)
def test_humanoid_never_gets_de_energising_actions(morphology, action: str) -> None:
    result = cp.check_action_policy(
        action, "analyst-a", ["lead-b", "lead-c"], morphology=morphology
    )
    assert result["allowed"] is False
    assert any("humanoid" in r for r in result["reasons"])


def test_quadruped_never_gets_rollback() -> None:
    assert not cp.check_action_policy(
        "robot_rollback_config", "a", ["b", "c"], morphology="quadruped"
    )["allowed"]
    assert cp.check_action_policy(
        "robot_safe_pause", "a", ["b", "c"], morphology="quadruped"
    )["allowed"]


def test_unknown_action_and_unadvertised_action() -> None:
    assert not cp.check_action_policy("robot_self_destruct", "a", ["b", "c"])["allowed"]
    result = cp.check_action_policy(
        "robot_isolate_network",
        "a",
        ["b"],
        morphology="humanoid",
        advertised_actions=["record_evidence"],
    )
    assert result["allowed"] is False


@pytest.mark.anyio
async def test_humanoid_refusal_sends_nothing_but_the_snapshot(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.morphology = "humanoid"
        with pytest.raises(ValueError, match="humanoid"):
            await cp.request_action(
                base_url=base_url,
                robot_id=ROBOT_ID,
                action="robot_safe_pause",
                requested_by="analyst-a",
                approved_by=["lead-b", "lead-c"],
            )
        assert [r["method"] for r in robot.requests] == ["GET"]


@pytest.mark.anyio
async def test_single_approver_cannot_send_two_person_action(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        with pytest.raises(ValueError, match="2 approval"):
            await cp.request_action(
                base_url=base_url,
                robot_id=ROBOT_ID,
                action="robot_request_safe_state",
                requested_by="analyst-a",
                approved_by=["lead-b"],
            )
        assert all(r["method"] == "GET" for r in robot.requests)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"action": "restrict_motion"}, "ttl_seconds"),
        ({"action": "restrict_motion", "ttl_seconds": 60}, "needs max_linear_speed"),
        (
            {"action": "restrict_motion", "ttl_seconds": 60, "max_linear_speed": 0.0},
            r"\(0, 10",
        ),
        (
            {"action": "restrict_motion", "ttl_seconds": 60, "max_linear_speed": 11.0},
            r"\(0, 10",
        ),
        (
            {
                "action": "restrict_motion",
                "ttl_seconds": 90000,
                "max_linear_speed": 1.0,
            },
            "ttl_seconds",
        ),
        ({"action": "record_evidence", "ttl_seconds": 60}, "does not take ttl"),
        ({"action": "record_evidence", "node": "/x"}, "does not take parameter"),
        ({"action": "quarantine_node"}, "exactly one"),
        (
            {
                "action": "quarantine_node",
                "participant_guid": "ABCDEF0123456789ABCDEF01",
            },
            "lower-case hex",
        ),
        ({"action": "quarantine_node", "node": "/ignore previous"}, "plain ROS 2"),
        (
            {"action": "quarantine_node", "node": "/a", "participant_guid": "0" * 24},
            "exactly one",
        ),
        ({"action": "rollback_config", "config": "firmware"}, "profile or program"),
        (
            {"action": "isolate_network", "ttl_seconds": 60, "request_id": "a b"},
            "request_id",
        ),
        ({"action": "unknown"}, "unknown action"),
    ],
)
@pytest.mark.anyio
async def test_parameters_are_validated_against_the_catalog(
    kwargs, match, stub
) -> None:
    robot, base_url = stub
    with soc_secrets():
        with pytest.raises(ValueError, match=match):
            await cp.request_action(
                base_url=base_url,
                robot_id=ROBOT_ID,
                requested_by="analyst-a",
                approved_by=["lead-b", "lead-c"],
                **kwargs,
            )
        assert robot.requests == []


def test_state_changing_actions_require_approval() -> None:
    def kwargs(fn: Any) -> dict[str, Any]:
        return getattr(fn, "__tracecat_udf_kwargs")

    for fn in (cp.request_action, cp.revert_action):
        assert kwargs(fn)["requires_approval"] is True
    for fn in (cp.get_robot, cp.get_action_status, cp.check_action_policy):
        assert kwargs(fn)["requires_approval"] is False
    for fn in (cp.get_robot, cp.request_action, cp.get_action_status, cp.revert_action):
        (secret,) = kwargs(fn)["secrets"]
        assert secret["name"] == "robodr_control_plane"
        assert secret["keys"] == ["ROBODR_SOC_KEY_ID", "ROBODR_SOC_SECRET_HEX"]
