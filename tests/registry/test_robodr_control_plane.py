"""RoboDR control plane v1: request signing and the SOC-side approval gate.

The approval gate reads platform records only: form submissions fetched
through the registry SDK (a fake `ctx.forms` here) carry the platform user
ids of the requester and the approvers. Nothing an action input says about
people is trusted.

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
import copy
import hashlib
import inspect
import json
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest
from autosecops_registry._internal import secrets as registry_secrets
from autosecops_registry.context import RegistryContext, clear_context, set_context
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

FINDING_PUBLIC_HEX = (
    Ed25519PrivateKey.from_private_bytes(FINDING_SEED).public_key().public_bytes_raw()
).hex()


@dataclass
class StubRobot:
    morphology: str | None = "wheeled_mobile"
    snapshot_robot_id: str = ROBOT_ID
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
    sign_answers: bool = True
    answer_key_id: str = FINDING_KEY_ID
    answer_status: int = 200
    stall_body: bool = False
    release: threading.Event = field(default_factory=threading.Event)
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
                "robot_id": self.snapshot_robot_id,
                "online": True,
                "api": "robodr-control-plane/v1",
                "safety_state": {"state": "moving_slow", "source": "safety_feed"},
                "mode": "enforce",
                "executor": "recording",
                "executes_actions": False,
                "actions": self.actions,
            }
            if self.morphology is not None:
                data["morphology"] = self.morphology
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
                f"ed25519;key_id={self.answer_key_id};sig={sig}"
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
            if robot.stall_body:
                # Announce a huge answer, send a little over the cap, then
                # stall: only a client that enforces the cap while reading
                # returns before the request timeout.
                self.send_response(200)
                self.send_header("Content-Length", str(100 * 1024 * 1024))
                self.end_headers()
                self.wfile.write(b"x" * (cp.MAX_ANSWER_BYTES + 4096))
                self.wfile.flush()
                robot.release.wait(30)
                return
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
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield robot, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        robot.release.set()
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# Platform sign-off: form submissions read through the registry SDK
# --------------------------------------------------------------------------- #

FORM_ID = "0b0c8f8e-0d0b-4d3a-9a57-3d0f2a3e6b11"
REQUESTER = "11111111-1111-4111-8111-111111111111"
LEAD_B = "22222222-2222-4222-8222-222222222222"
LEAD_C = "33333333-3333-4333-8333-333333333333"
EMAILS = {
    REQUESTER: "analyst.a@example.com",
    LEAD_B: "lead.b@example.com",
    LEAD_C: "lead.c@example.com",
}


@dataclass
class FakeForms:
    """Stands in for `ctx.forms`: the platform's own submission records."""

    submissions: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    fail: bool = False

    async def get_submission(self, submission_id: str) -> dict[str, Any]:
        self.calls.append(submission_id)
        if self.fail:
            raise RuntimeError("action gateway unavailable")
        if submission_id not in self.submissions:
            raise LookupError("Submission not found")
        return copy.deepcopy(self.submissions[submission_id])

    def add(
        self,
        user_id: str,
        decision: str,
        request_id: str,
        digest: str,
        *,
        actor_type: str = "user",
        email: str | None = None,
        age: timedelta = timedelta(minutes=5),
        form_id: str = FORM_ID,
    ) -> str:
        submission_id = str(uuid.uuid4())
        self.submissions[submission_id] = {
            "id": submission_id,
            "form_id": form_id,
            "answers": {
                "robodr_request_id": request_id,
                "robodr_request_digest": digest,
                "robodr_decision": decision,
            },
            "submitted_by": {
                "type": actor_type,
                "id": user_id,
                "email": email if email is not None else EMAILS.get(user_id),
            },
            "submitted_at": (datetime.now(UTC) - age).isoformat(),
            "wf_exec_id": "wf-x/exec-y",
        }
        return submission_id


@dataclass
class FakeClient:
    forms: FakeForms


@pytest.fixture
async def platform() -> AsyncIterator[FakeForms]:
    # Async, so the context is set in the event loop the test runs in.
    forms = FakeForms()
    set_context(
        RegistryContext(
            workspace_id="ws",
            workflow_id="wf",
            run_id="run",
            _client=cast(Any, FakeClient(forms)),
        )
    )
    try:
        yield forms
    finally:
        clear_context()


ACTION_PARAMS: dict[str, dict[str, Any]] = {
    "robot_restrict_motion": {"ttl_seconds": 600, "max_linear_speed": 0.5},
    "robot_quarantine_node": {"node": "/rogue"},
    "robot_isolate_network": {"ttl_seconds": 60},
    "robot_record_evidence": {},
    "robot_safe_pause": {},
    "robot_request_safe_state": {},
    "robot_rollback_config": {"config": "profile"},
}


def _signoffs(
    forms: FakeForms,
    prepared: dict[str, Any],
    approvers: tuple[str, ...],
    requester: str = REQUESTER,
) -> dict[str, Any]:
    request_id, digest = prepared["request_id"], prepared["request_digest"]
    return {
        "request_submission_id": forms.add(requester, "request", request_id, digest),
        "approval_submission_ids": [
            forms.add(user, "approve", request_id, digest) for user in approvers
        ],
    }


async def _send(
    base_url: str,
    forms: FakeForms,
    action: str = "robot_restrict_motion",
    approvers: tuple[str, ...] = (LEAD_B,),
    *,
    reason: str = "rogue writer",
    signoff: dict[str, Any] | None = None,
    request_id: str | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    params = ACTION_PARAMS[action]
    prepared = cp.prepare_action_request(
        robot_id=ROBOT_ID, action=action, reason=reason, request_id=request_id, **params
    )
    kwargs: dict[str, Any] = {
        "base_url": base_url,
        "robot_id": ROBOT_ID,
        "action": action,
        "request_id": prepared["request_id"],
        "reason": reason,
        "answer_public_key_hex": FINDING_PUBLIC_HEX,
        "answer_key_id": FINDING_KEY_ID,
    }
    kwargs |= signoff or _signoffs(forms, prepared, approvers)
    return await cp.request_action(**(kwargs | params | overrides))


# --------------------------------------------------------------------------- #
# Signed requests against the stub
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_request_action_is_signed_and_reported_not_applied(
    stub, platform
) -> None:
    robot, base_url = stub
    with soc_secrets():
        result = await _send(base_url, platform)
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
        # The requester is the platform user who submitted the request form.
        assert body["requested_by"] == EMAILS[REQUESTER]
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
        assert result["answer_signature_verified"] is True
        assert result["requested_by"] == {"user_id": REQUESTER, "id": EMAILS[REQUESTER]}
        assert result["approved_by"] == [{"user_id": LEAD_B, "id": EMAILS[LEAD_B]}]
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


def _stored(action: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def answer(record: dict[str, Any]) -> dict[str, Any]:
        if record["method"] == "GET":
            return {
                "request_id": "x",
                "status": "recorded_not_executed",
                "executed": False,
                "state": {"robot_id": ROBOT_ID, "action": action},
            }
        return {"request_id": "x", "status": "not_applied", "executed": False}

    return answer


async def _revert(
    base_url: str,
    forms: FakeForms,
    request_id: str,
    approvers: tuple[str, ...],
    requester: str = REQUESTER,
    **overrides: Any,
) -> dict[str, Any]:
    prepared = cp.prepare_revert_request(
        robot_id=ROBOT_ID, request_id=request_id, reason="false positive"
    )
    kwargs: dict[str, Any] = {
        "base_url": base_url,
        "robot_id": ROBOT_ID,
        "request_id": request_id,
        "reason": "false positive",
        "answer_public_key_hex": FINDING_PUBLIC_HEX,
        **_signoffs(forms, prepared, approvers, requester),
    }
    return await cp.revert_action(**(kwargs | overrides))


@pytest.mark.anyio
async def test_revert_action(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.answer_for = _stored("isolate_network")
        request_id = "robot_isolate_network:ugv-007:01"
        result = await _revert(base_url, platform, request_id, (LEAD_B,))
        status, snapshot, post = robot.requests
        assert status["method"] == "GET" and snapshot["method"] == "GET"
        assert post["target"].endswith(
            "/action-requests/robot_isolate_network%3Augv-007%3A01/revert"
        )
        assert json.loads(post["body"]) == {
            "reason": "false positive",
            "requested_by": EMAILS[REQUESTER],
        }
        assert result["status"] == "not_applied" and result["applied"] is False
        robot.requests.clear()
        with pytest.raises(cp.SignoffError, match="requester"):
            await _revert(base_url, platform, request_id, (REQUESTER,))
        assert all(r["method"] == "GET" for r in robot.requests)


@pytest.mark.anyio
async def test_refusal_is_reported_final(stub, platform) -> None:
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
        result = await _send(base_url, platform, "robot_isolate_network")
        assert result["status"] == "refused"
        assert result["applied"] is False
        assert "human_in_command" in result["report"]
        assert "do not retry" in result["report"]


@pytest.mark.anyio
async def test_answer_signature_is_verified_when_configured(stub) -> None:
    robot, base_url = stub
    with soc_secrets():
        result = await cp.get_robot(
            base_url=base_url,
            robot_id=ROBOT_ID,
            answer_public_key_hex=FINDING_PUBLIC_HEX,
            answer_key_id=FINDING_KEY_ID,
        )
        assert result["answer_signature_verified"] is True
        robot.sign_answers = False
        with pytest.raises(cp.ControlPlaneError, match="answer signature"):
            await cp.get_robot(
                base_url=base_url,
                robot_id=ROBOT_ID,
                answer_public_key_hex=FINDING_PUBLIC_HEX,
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
# H1: the platform sign-off gate (nothing is sent when it refuses)
# --------------------------------------------------------------------------- #

TWO_PERSON = ["robot_safe_pause", "robot_request_safe_state", "robot_rollback_config"]


def test_free_text_approvers_are_gone() -> None:
    """Approvals come from platform records only, never from action inputs."""
    for fn in (cp.request_action, cp.revert_action, cp.check_action_policy):
        params = inspect.signature(fn).parameters
        assert "approved_by" not in params
        assert "requested_by" not in params
    for fn in (cp.request_action, cp.revert_action):
        params = inspect.signature(fn).parameters
        assert "request_submission_id" in params
        assert "approval_submission_ids" in params


@pytest.mark.anyio
@pytest.mark.parametrize("action", sorted(ACTION_PARAMS))
async def test_direct_call_without_platform_signoff_sends_nothing(
    action: str, stub
) -> None:
    """A workflow step calling request_action with no platform context."""
    robot, base_url = stub
    clear_context()
    with soc_secrets():
        with pytest.raises(cp.SignoffError):
            await _send(
                base_url,
                FakeForms(),
                action,
                signoff={
                    "request_submission_id": str(uuid.uuid4()),
                    "approval_submission_ids": [str(uuid.uuid4()), str(uuid.uuid4())],
                },
            )
    assert robot.requests == []


@pytest.mark.anyio
async def test_unknown_or_unreadable_submissions_fail_closed(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        with pytest.raises(cp.SignoffError, match="not readable"):
            await _send(
                base_url,
                platform,
                signoff={
                    "request_submission_id": str(uuid.uuid4()),
                    "approval_submission_ids": [str(uuid.uuid4())],
                },
            )
        platform.fail = True
        with pytest.raises(cp.SignoffError, match="not readable"):
            await _send(base_url, platform)
        with pytest.raises(cp.SignoffError, match="UUID"):
            await _send(
                base_url,
                platform,
                signoff={
                    "request_submission_id": "bob",
                    "approval_submission_ids": ["alice"],
                },
            )
    assert robot.requests == []


@pytest.mark.anyio
async def test_no_action_without_an_approval(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        for action in sorted(ACTION_PARAMS):
            with pytest.raises(cp.SignoffError, match="needs"):
                await _send(base_url, platform, action, approvers=())
            # The requester approving their own request does not count.
            with pytest.raises(cp.SignoffError, match="requester"):
                await _send(base_url, platform, action, approvers=(REQUESTER,))
    assert robot.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize("action", TWO_PERSON)
async def test_two_person_actions_need_two_distinct_platform_users(
    action: str, stub, platform
) -> None:
    robot, base_url = stub
    with soc_secrets():
        with pytest.raises(cp.SignoffError, match="needs 2"):
            await _send(base_url, platform, action, approvers=(LEAD_B,))
        # Two submissions by the same account are one person.
        with pytest.raises(cp.SignoffError, match="different"):
            await _send(base_url, platform, action, approvers=(LEAD_B, LEAD_B))
        with pytest.raises(cp.SignoffError, match="requester"):
            await _send(base_url, platform, action, approvers=(LEAD_B, REQUESTER))
        assert robot.requests == []
        result = await _send(base_url, platform, action, approvers=(LEAD_B, LEAD_C))
        assert [a["user_id"] for a in result["approved_by"]] == [LEAD_B, LEAD_C]
        assert result["approval"] == "two_person"


@pytest.mark.anyio
async def test_homoglyph_identities_do_not_matter(stub, platform) -> None:
    """Identity is the platform user id; a lookalike email is just metadata."""
    _, base_url = stub
    with soc_secrets():
        prepared = cp.prepare_action_request(
            robot_id=ROBOT_ID, action="robot_safe_pause", reason="r"
        )
        rid, digest = prepared["request_id"], prepared["request_digest"]
        signoff = {
            "request_submission_id": platform.add(REQUESTER, "request", rid, digest),
            "approval_submission_ids": [
                platform.add(LEAD_B, "approve", rid, digest, email="bob@example.com"),
                # Same account, Cyrillic "о" in the email: still one person.
                platform.add(LEAD_B, "approve", rid, digest, email="bоb@x.com"),
            ],
        }
        with pytest.raises(cp.SignoffError, match="different"):
            await _send(
                base_url,
                platform,
                "robot_safe_pause",
                reason="r",
                signoff=signoff,
                request_id=rid,
            )
        # A different account with a non-ASCII email counts, and is reported
        # by its user id: identifiers are ASCII only.
        signoff["approval_submission_ids"][1] = platform.add(
            LEAD_C, "approve", rid, digest, email="bоb@x.com"
        )
        result = await _send(
            base_url,
            platform,
            "robot_safe_pause",
            reason="r",
            signoff=signoff,
            request_id=rid,
        )
        assert result["approved_by"][1] == {
            "user_id": LEAD_C,
            "id": f"user:{LEAD_C}",
        }
        assert all(a["id"].isascii() for a in result["approved_by"])


@pytest.mark.anyio
async def test_signoff_is_bound_to_this_exact_request(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        prepared = cp.prepare_action_request(
            robot_id=ROBOT_ID,
            action="robot_restrict_motion",
            reason="rogue writer",
            ttl_seconds=600,
            max_linear_speed=0.5,
        )
        signoff = _signoffs(platform, prepared, (LEAD_B,))
        # Same request id and sign-offs, different speed cap: refused.
        with pytest.raises(cp.SignoffError, match="digest"):
            await cp.request_action(
                base_url=base_url,
                robot_id=ROBOT_ID,
                action="robot_restrict_motion",
                request_id=prepared["request_id"],
                reason="rogue writer",
                ttl_seconds=600,
                max_linear_speed=5.0,
                answer_public_key_hex=FINDING_PUBLIC_HEX,
                **signoff,
            )
        # A sign-off for another request id: refused.
        other = cp.prepare_action_request(
            robot_id=ROBOT_ID,
            action="robot_restrict_motion",
            reason="rogue writer",
            ttl_seconds=600,
            max_linear_speed=0.5,
        )
        mixed = {
            "request_submission_id": signoff["request_submission_id"],
            "approval_submission_ids": _signoffs(platform, other, (LEAD_B,))[
                "approval_submission_ids"
            ],
        }
        with pytest.raises(cp.SignoffError, match="request_id"):
            await _send(
                base_url, platform, signoff=mixed, request_id=prepared["request_id"]
            )
        # An approval submitted as a "request" (and vice versa) does not count.
        swapped = {
            "request_submission_id": signoff["approval_submission_ids"][0],
            "approval_submission_ids": [signoff["request_submission_id"]],
        }
        with pytest.raises(cp.SignoffError, match="decision"):
            await _send(
                base_url, platform, signoff=swapped, request_id=prepared["request_id"]
            )
        # The same submission cannot be both the request and an approval.
        with pytest.raises(cp.SignoffError, match="more than once"):
            await _send(
                base_url,
                platform,
                signoff={
                    "request_submission_id": signoff["request_submission_id"],
                    "approval_submission_ids": [signoff["request_submission_id"]],
                },
                request_id=prepared["request_id"],
            )
    assert robot.requests == []


@pytest.mark.anyio
async def test_stale_service_account_and_cross_form_signoffs_are_refused(
    stub, platform
) -> None:
    robot, base_url = stub
    with soc_secrets():
        prepared = cp.prepare_action_request(
            robot_id=ROBOT_ID, action="robot_isolate_network", ttl_seconds=60
        )
        rid, digest = prepared["request_id"], prepared["request_digest"]
        requested = platform.add(REQUESTER, "request", rid, digest)

        async def send(approval: str) -> None:
            await _send(
                base_url,
                platform,
                "robot_isolate_network",
                reason="",
                signoff={
                    "request_submission_id": requested,
                    "approval_submission_ids": [approval],
                },
                request_id=rid,
            )

        stale = platform.add(LEAD_B, "approve", rid, digest, age=timedelta(days=2))
        with pytest.raises(cp.SignoffError, match="older"):
            await send(stale)
        service = platform.add(
            LEAD_B, "approve", rid, digest, actor_type="service_account"
        )
        with pytest.raises(cp.SignoffError, match="platform user"):
            await send(service)
        elsewhere = platform.add(
            LEAD_B, "approve", rid, digest, form_id=str(uuid.uuid4())
        )
        with pytest.raises(cp.SignoffError, match="same form"):
            await send(elsewhere)
    assert robot.requests == []


@pytest.mark.anyio
async def test_revert_of_safe_pause_needs_two_approvals(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.answer_for = _stored("safe_pause")
        request_id = "robot_safe_pause:ugv-007:01"
        with pytest.raises(cp.SignoffError, match="needs 2"):
            await _revert(base_url, platform, request_id, (LEAD_B,))
        assert all(r["method"] == "GET" for r in robot.requests)
        result = await _revert(base_url, platform, request_id, (LEAD_B, LEAD_C))
        assert result["status"] == "not_applied"
        assert robot.requests[-1]["method"] == "POST"


@pytest.mark.anyio
async def test_revert_signoff_is_bound_to_the_revert(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.answer_for = _stored("isolate_network")
        # Sign-offs for the original action request do not authorise a revert.
        prepared = cp.prepare_action_request(
            robot_id=ROBOT_ID, action="robot_isolate_network", ttl_seconds=60
        )
        signoff = _signoffs(platform, prepared, (LEAD_B,))
        with pytest.raises(cp.SignoffError, match="digest"):
            await cp.revert_action(
                base_url=base_url,
                robot_id=ROBOT_ID,
                request_id=prepared["request_id"],
                answer_public_key_hex=FINDING_PUBLIC_HEX,
                **signoff,
            )
        assert all(r["method"] == "GET" for r in robot.requests)


def test_state_changing_actions_require_approval() -> None:
    def kwargs(fn: Any) -> dict[str, Any]:
        return getattr(fn, "__tracecat_udf_kwargs")

    for fn in (cp.request_action, cp.revert_action):
        assert kwargs(fn)["requires_approval"] is True
        assert kwargs(fn)["required_entitlements"] == ["forms"]
    for fn in (
        cp.get_robot,
        cp.get_action_status,
        cp.check_action_policy,
        cp.prepare_action_request,
        cp.prepare_revert_request,
    ):
        assert kwargs(fn)["requires_approval"] is False
    for fn in (cp.get_robot, cp.request_action, cp.get_action_status, cp.revert_action):
        (secret,) = kwargs(fn)["secrets"]
        assert secret["name"] == "robodr_control_plane"
        assert secret["keys"] == ["ROBODR_SOC_KEY_ID", "ROBODR_SOC_SECRET_HEX"]


# --------------------------------------------------------------------------- #
# M1: morphology allow-list and authenticated snapshots
# --------------------------------------------------------------------------- #

DE_ENERGISE_OK = ["wheeled_mobile", "arm", "aerial", "other"]
DE_ENERGISE_REFUSED = [
    "humanoid",
    "unspecified",
    None,
    "",
    "quadruped",
    "Humanoid",
    "HUMANOID",
    " wheeled_mobile",
    "wheeled_mobile\n",
    "wheeled_quadruped",
    "biped",
    "legged",
]


@pytest.mark.parametrize("morphology", DE_ENERGISE_REFUSED)
@pytest.mark.parametrize("action", TWO_PERSON)
def test_de_energising_actions_fail_closed_on_any_other_morphology(
    morphology, action: str
) -> None:
    result = cp.check_action_policy(action, morphology=morphology)
    assert result["allowed"] is False
    assert any("morphology" in r for r in result["reasons"])


@pytest.mark.parametrize("morphology", DE_ENERGISE_OK)
@pytest.mark.parametrize("action", ["robot_safe_pause", "robot_request_safe_state"])
def test_de_energising_actions_allowed_on_listed_morphologies(
    morphology: str, action: str
) -> None:
    assert cp.check_action_policy(action, morphology=morphology)["allowed"] is True


def test_rollback_never_on_a_quadruped() -> None:
    result = cp.check_action_policy("robot_rollback_config", morphology="quadruped")
    assert result["allowed"] is False
    assert any("quadruped" in r for r in result["reasons"])
    assert cp.check_action_policy("robot_rollback_config", morphology="arm")["allowed"]


@pytest.mark.parametrize("morphology", [None, "humanoid", "unknown_shape"])
def test_non_de_energising_actions_ignore_morphology(morphology) -> None:
    for action in (
        "robot_restrict_motion",
        "robot_quarantine_node",
        "robot_isolate_network",
        "robot_record_evidence",
    ):
        assert cp.check_action_policy(action, morphology=morphology)["allowed"]


def test_unknown_action_and_unadvertised_action() -> None:
    assert not cp.check_action_policy("robot_self_destruct")["allowed"]
    result = cp.check_action_policy(
        "robot_isolate_network",
        morphology="humanoid",
        advertised_actions=["record_evidence"],
    )
    assert result["allowed"] is False


@pytest.mark.anyio
@pytest.mark.parametrize("morphology", ["humanoid", None, "unknown_shape"])
async def test_snapshot_refusal_sends_nothing_but_the_snapshot(
    morphology, stub, platform
) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.morphology = morphology
        with pytest.raises(ValueError, match="morphology"):
            await _send(base_url, platform, "robot_safe_pause", (LEAD_B, LEAD_C))
        assert [r["method"] for r in robot.requests] == ["GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("key", [None, ""])
async def test_state_changing_actions_require_a_robot_answer_key(
    key, stub, platform
) -> None:
    robot, base_url = stub
    with soc_secrets():
        with pytest.raises(ValueError, match="answer_public_key_hex"):
            await _send(base_url, platform, answer_public_key_hex=key)
        robot.answer_for = _stored("isolate_network")
        with pytest.raises(ValueError, match="answer_public_key_hex"):
            await _revert(
                base_url,
                platform,
                "robot_isolate_network:ugv-007:01",
                (LEAD_B,),
                answer_public_key_hex=key,
            )
    assert robot.requests == []


@pytest.mark.anyio
async def test_unsigned_snapshot_is_refused(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.sign_answers = False
        with pytest.raises(cp.ControlPlaneError, match="answer signature"):
            await _send(base_url, platform)
        assert [r["method"] for r in robot.requests] == ["GET"]


@pytest.mark.anyio
async def test_snapshot_of_another_robot_is_refused(stub, platform) -> None:
    robot, base_url = stub
    with soc_secrets():
        robot.snapshot_robot_id = "ugv-008"
        with pytest.raises(cp.ControlPlaneError, match="robot_id"):
            await _send(base_url, platform)
        assert [r["method"] for r in robot.requests] == ["GET"]


# --------------------------------------------------------------------------- #
# Input validation (L1, L3, L6)
# --------------------------------------------------------------------------- #


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
        (
            {"action": "restrict_motion", "ttl_seconds": True, "max_linear_speed": 1},
            "ttl_seconds",
        ),
        ({"action": "isolate_network", "ttl_seconds": 60.0}, "ttl_seconds"),
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
        (
            {"action": "quarantine_node", "participant_guid": "0" * 24 + "\n"},
            "lower-case hex",
        ),
        ({"action": "quarantine_node", "node": "/ignore previous"}, "plain ROS 2"),
        ({"action": "quarantine_node", "node": "/rogue\n"}, "plain ROS 2"),
        (
            {"action": "quarantine_node", "node": "/a", "participant_guid": "0" * 24},
            "exactly one",
        ),
        ({"action": "rollback_config", "config": "firmware"}, "profile or program"),
        ({"action": "rollback_config", "to_version": "v1\n"}, "to_version"),
        (
            {
                "action": "restrict_motion",
                "ttl_seconds": 60,
                "workspace_zone": "zone-a\n",
            },
            "workspace_zone",
        ),
        (
            {"action": "isolate_network", "ttl_seconds": 60, "request_id": "a b"},
            "request_id",
        ),
        (
            {"action": "isolate_network", "ttl_seconds": 60, "request_id": "r1\n"},
            "request_id",
        ),
        ({"action": "isolate_network", "ttl_seconds": 60, "source": "soc\n"}, "source"),
        (
            {"action": "isolate_network", "ttl_seconds": 60, "robot_id": "ugv-007\n"},
            "robot_id",
        ),
        (
            {"action": "isolate_network", "ttl_seconds": 60, "answer_key_id": "a;b"},
            "answer_key_id",
        ),
        ({"action": "unknown"}, "unknown action"),
    ],
)
@pytest.mark.anyio
async def test_parameters_are_validated_before_anything_is_sent(
    kwargs, match, stub, platform
) -> None:
    robot, base_url = stub
    arguments: dict[str, Any] = {
        "base_url": base_url,
        "robot_id": ROBOT_ID,
        "request_id": "r-1",
        "answer_public_key_hex": FINDING_PUBLIC_HEX,
        "request_submission_id": str(uuid.uuid4()),
        "approval_submission_ids": [str(uuid.uuid4()), str(uuid.uuid4())],
    }
    with soc_secrets():
        with pytest.raises(ValueError, match=match):
            await cp.request_action(**(arguments | kwargs))
    assert robot.requests == []
    assert platform.calls == []


@pytest.mark.parametrize(
    "base_url",
    [
        "http://robot.example:8443",
        "http://localhost:8443",
        "http://10.0.0.5:8443",
        "ftp://127.0.0.1",
        "https://robot.example/prefix",
        "https://robot.example/api/",
        "https://user:pw@robot.example",
        "https://robot.example?x=1",
        "https://robot.example#f",
        "https://",
        "robot.example",
        "https://robot.example\n",
    ],
)
@pytest.mark.anyio
async def test_base_url_is_https_without_a_path(base_url: str) -> None:
    with soc_secrets():
        with pytest.raises(ValueError, match="base_url"):
            await cp.get_robot(base_url=base_url, robot_id=ROBOT_ID)


@pytest.mark.parametrize(
    "base_url",
    [
        "https://robot.example",
        "https://robot.example/",
        "https://robot.example:8443",
        "http://127.0.0.1:8443",
        "http://127.10.0.1",
        "http://[::1]:8443",
    ],
)
def test_base_url_accepted_forms(base_url: str) -> None:
    url = cp._robot_url(base_url, "/api/v1/robots/ugv-007")
    assert url.raw_path == b"/api/v1/robots/ugv-007"


@pytest.mark.anyio
async def test_answer_cap_is_enforced_while_reading(stub) -> None:
    robot, base_url = stub
    robot.stall_body = True
    with soc_secrets():
        started = time.monotonic()
        with pytest.raises(cp.ControlPlaneError, match="256 KiB"):
            await cp.get_robot(base_url=base_url, robot_id=ROBOT_ID)
        assert time.monotonic() - started < cp.REQUEST_TIMEOUT_S / 2


@pytest.mark.anyio
async def test_answer_key_id_with_separator_is_not_a_valid_signature(stub) -> None:
    robot, base_url = stub
    robot.answer_key_id = "finding;sig=00"
    with soc_secrets():
        with pytest.raises(cp.ControlPlaneError, match="answer signature"):
            await cp.get_robot(
                base_url=base_url,
                robot_id=ROBOT_ID,
                answer_public_key_hex=FINDING_PUBLIC_HEX,
            )
