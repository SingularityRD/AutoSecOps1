"""The shared `robodr.control-plane` v2 contract vectors (§12).

`tests/data/robodr_control_plane_v2/` is a copy of RoboDR's
`docs/contracts/fixtures/control-plane-v2/` (RoboDR commit d48e8b0), generated
by `cargo run -p robodr-agentd --example control_plane_vectors` and checked
against the reference implementation by RoboDR's
`tests/control_plane_vectors.rs`. Copied byte for byte (the pre-commit text
fixers skip the directory), except:

* `keys/`: only the public halves. The SOC test key's secret is the fixed
  seed of 32 bytes 0x51 (RoboDR publishes the test secret files on purpose);
  the test derives it and checks it against `keys/soc.key.pub`, so no secret
  key file is committed here.
* `evidence/blackbox/` (the synthetic black box the export was cut from) is
  not needed: the export itself (`evidence/bundle.rbbx`) is verified.

The Python signer must reproduce every request byte for byte (signing
message, signature, the request head and body), and the verifiers must accept
every sample answer, manifest and bundle and refuse the negative vectors.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from autosecops_registry.integrations import robodr_control_plane as cp
from autosecops_registry.integrations import robodr_evidence as ev
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VECTORS = Path(__file__).parents[1] / "data" / "robodr_control_plane_v2"
MANIFEST: dict[str, Any] = json.loads((VECTORS / "manifest.json").read_text())
ROBOT_ID = MANIFEST["robot_id"]
HOST = "ugv-007.robots.example"
SOC_SEED = bytes([0x51]) * 32


def _key(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / "keys" / f"{name}.key.pub").read_text())


FINDING_KEY = _key("finding")
FINDING_PUBLIC = bytes.fromhex(FINDING_KEY["public_hex"])


def _case(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / "requests" / f"{name}.json").read_text())


def _http(name: str) -> bytes:
    return (VECTORS / "requests" / f"{name}.http").read_bytes()


def _body(name: str) -> bytes:
    return _http(name).split(b"\r\n\r\n", 1)[1]


CASES = [case["name"] for case in MANIFEST["cases"]]
AUTHENTICATED = [n for n in CASES if _case(n)["expect"]["authenticated"]]
REFUSED = [n for n in CASES if not _case(n)["expect"]["authenticated"]]
ANSWERED = [n for n in CASES if "answer" in _case(n)]


def _robot() -> Any:
    return cp._robot(
        base_url=f"https://{HOST}",
        robot_id=ROBOT_ID,
        robot_ca_pem="-----BEGIN CERTIFICATE-----\n(unused)\n",
        robot_spki_sha256=None,
        answer_public_key_hex=FINDING_KEY["public_hex"],
        answer_key_id=FINDING_KEY["key_id"],
    )


def test_the_soc_test_key_is_the_published_one() -> None:
    public = Ed25519PrivateKey.from_private_bytes(SOC_SEED).public_key()
    assert public.public_bytes_raw().hex() == _key("soc")["public_hex"]
    assert MANIFEST["api"] == cp.API_VERSION == ev.API_VERSION


@pytest.mark.parametrize("name", AUTHENTICATED)
def test_requests_are_reproduced_byte_for_byte(name: str) -> None:
    case = _case(name)
    body = _body(name)
    assert hashlib.sha256(body).hexdigest() == case["body_sha256"]
    message = cp.signing_message(
        case["method"],
        case["target"],
        ROBOT_ID,
        case["key_id"],
        case["timestamp"],
        case["nonce"],
        body,
    )
    assert message == case["signing_message"].encode()
    signer = Ed25519PrivateKey.from_private_bytes(SOC_SEED)
    signature = signer.sign(message).hex()
    assert signature == case["signature"]
    assert cp.request_bytes(
        method=case["method"],
        target=case["target"],
        host=HOST,
        key_id=case["key_id"],
        timestamp=case["timestamp"],
        nonce=case["nonce"],
        signature_hex=signature,
        body=body,
    ) == _http(name)


@pytest.mark.parametrize("name", REFUSED)
def test_negative_vectors_do_not_verify_as_v2_requests(name: str) -> None:
    case = _case(name)
    body = _body(name)
    message = cp.signing_message(
        case["method"],
        case["target"],
        ROBOT_ID,
        case["key_id"],
        case["timestamp"],
        case["nonce"],
        body,
    )
    public = Ed25519PrivateKey.from_private_bytes(SOC_SEED).public_key()
    signature = bytes.fromhex(case["signature"])
    assert not cp.ed25519_verify_strict(public.public_bytes_raw(), message, signature)
    # What the vector did sign is a valid signature over another message.
    signed = case["signing_message"].encode()
    assert signed != message
    assert cp.ed25519_verify_strict(public.public_bytes_raw(), signed, signature)


def test_targets_are_built_like_the_vectors() -> None:
    request_id = "robot_safe_pause:ugv-007:0001"
    assert cp._robot_target(ROBOT_ID) == _case("01-robot")["target"]
    assert (
        cp._robot_target(ROBOT_ID, "action-requests", request_id)
        == _case("03-get-request")["target"]
    )
    assert (
        cp._robot_target(ROBOT_ID, "action-requests", request_id, "revert")
        == _case("04-revert")["target"]
    )
    assert (
        cp._robot_target(ROBOT_ID, "evidence")
        == _case("05-evidence-inventory")["target"]
    )
    assert (
        cp._robot_target(ROBOT_ID, "evidence", "exports", "case-42:ev-1", "chunks", "1")
        == _case("09-evidence-chunk-1")["target"]
    )


def test_bodies_are_built_like_the_vectors() -> None:
    submit = cp.body_bytes(
        {
            "request_id": "robot_safe_pause:ugv-007:0001",
            "action": "safe_pause",
            "parameters": {},
            "reason": "rogue /cmd_vel writer",
            "requested_by": "analyst@soc",
            "source": "soc-a",
            "authority": "request",
        }
    )
    assert submit == _body("02-submit")
    revert = cp.body_bytes({"reason": "false positive", "requested_by": "analyst@soc"})
    assert revert == _body("04-revert")
    export = json.loads(_body("06-evidence-export"))
    selector = ev.build_selector(
        robot_id=ROBOT_ID,
        finding_id=export["selector"]["finding"]["finding_id"],
        evidence_links=export["selector"]["finding"]["evidence"],
        context_records=export["selector"]["finding"]["context_records"],
    )
    built = cp.body_bytes(
        {
            "export_id": "case-42:ev-1",
            "selector": selector,
            "requested_by": "analyst@soc",
            "reason": "case 42",
        }
    )
    assert built == _body("06-evidence-export")


def _answer(name: str) -> cp.RawAnswer:
    answer = _case(name)["answer"]
    body = (VECTORS / answer["body_file"]).read_bytes()
    assert hashlib.sha256(body).hexdigest() == answer["body_sha256"]
    headers = [
        ("Content-Type", answer["content_type"]),
        ("X-RoboDR-Answer-Signature", answer["x_robodr_answer_signature"]),
    ]
    if "x_robodr_manifest_signature" in answer:
        headers.append(
            ("X-RoboDR-Manifest-Signature", answer["x_robodr_manifest_signature"])
        )
    return cp.RawAnswer(answer["status"], tuple(headers), body)


@pytest.mark.parametrize("name", ANSWERED)
def test_sample_answers_verify(name: str) -> None:
    case = _case(name)
    raw = _answer(name)
    assert (
        cp.answer_message(case["signature"], raw.status, raw.body)
        == case["answer"]["answer_message"].encode()
    )
    assert cp.verify_answer(_robot(), case["signature"], raw)


@pytest.mark.parametrize("name", ANSWERED)
def test_answers_do_not_verify_for_another_request_status_or_body(name: str) -> None:
    case = _case(name)
    raw = _answer(name)
    other_request = "0" * 128
    assert not cp.verify_answer(_robot(), other_request, raw)
    assert not cp.verify_answer(
        _robot(), case["signature"], cp.RawAnswer(raw.status + 1, raw.headers, raw.body)
    )
    assert not cp.verify_answer(
        _robot(),
        case["signature"],
        cp.RawAnswer(raw.status, raw.headers, raw.body + b" "),
    )
    unsigned = tuple(h for h in raw.headers if h[0] != "X-RoboDR-Answer-Signature")
    assert not cp.verify_answer(
        _robot(), case["signature"], cp.RawAnswer(raw.status, unsigned, raw.body)
    )


def test_parse_answer_reads_the_wire_form() -> None:
    raw = _answer("01-robot")
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(raw.body)}\r\n".encode()
        + f"X-RoboDR-Answer-Signature: {raw.header('X-RoboDR-Answer-Signature')}\r\n".encode()
        + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
        + raw.body
    )
    parsed = cp.parse_answer(wire, max_body=cp.MAX_ANSWER_BYTES)
    assert parsed.status == 200
    assert parsed.body == raw.body
    assert cp.verify_answer(_robot(), _case("01-robot")["signature"], parsed)
    with pytest.raises(cp.ControlPlaneError, match="truncated"):
        cp.parse_answer(wire[:-1], max_body=cp.MAX_ANSWER_BYTES)
    with pytest.raises(cp.ControlPlaneError, match="exceeds"):
        cp.parse_answer(wire, max_body=len(raw.body) - 1)
    chunked = wire.replace(b"Connection: close", b"Transfer-Encoding: chunked")
    with pytest.raises(cp.ControlPlaneError, match="transfer encoding"):
        cp.parse_answer(chunked, max_body=cp.MAX_ANSWER_BYTES)
    twice = wire.replace(
        b"Cache-Control: no-store",
        b"X-RoboDR-Answer-Signature: ed25519;key_id=x;sig=" + b"0" * 128,
    )
    assert not cp.verify_answer(
        _robot(),
        _case("01-robot")["signature"],
        cp.parse_answer(twice, max_body=cp.MAX_ANSWER_BYTES),
    )


# --------------------------------------------------------------------------- #
# Evidence (§11)
# --------------------------------------------------------------------------- #

EXPORT_ID = "case-42:ev-1"
EXPECTED: dict[str, Any] = json.loads(
    (VECTORS / "evidence" / "expected.json").read_text()
)


def _manifest_bytes() -> bytes:
    return (VECTORS / "evidence" / "manifest.json").read_bytes()


def _keyring() -> dict[str, ev.KeyringEntry]:
    return ev.parse_blackbox_keyring(
        [(VECTORS / "keys" / "blackbox.key.pub").read_text()]
    )


def _selector() -> dict[str, Any]:
    return json.loads(_body("06-evidence-export"))["selector"]


def test_manifest_answers_are_the_manifest_bytes_and_signed() -> None:
    manifest = _manifest_bytes()
    signature = (VECTORS / "evidence" / "manifest.sig").read_text()
    assert (
        ev.manifest_message(manifest)
        == (VECTORS / "evidence" / "manifest.message").read_bytes()
    )
    for name in ("06-evidence-export", "07-evidence-manifest"):
        raw = _answer(name)
        assert raw.body == manifest
        assert raw.header("X-RoboDR-Manifest-Signature") == signature
    key_id = ev.verify_manifest_signature(
        manifest, signature, FINDING_PUBLIC, FINDING_KEY["key_id"]
    )
    assert key_id == FINDING_KEY["key_id"]
    with pytest.raises(ev.EvidenceError, match="does not verify"):
        ev.verify_manifest_signature(manifest + b" ", signature, FINDING_PUBLIC)
    with pytest.raises(ev.EvidenceError, match="unexpected key id"):
        ev.verify_manifest_signature(manifest, signature, FINDING_PUBLIC, "other:1")
    with pytest.raises(ev.EvidenceError, match="no valid"):
        ev.verify_manifest_signature(manifest, None, FINDING_PUBLIC)


def test_manifest_identity_and_selector_are_checked() -> None:
    manifest = ev.parse_manifest(
        _manifest_bytes(), robot_id=ROBOT_ID, export_id=EXPORT_ID
    )
    assert ev.selector_matches(manifest, _selector(), ROBOT_ID)
    other = json.loads(json.dumps(_selector()))
    other["finding"]["context_records"] = 4
    assert not ev.selector_matches(manifest, other, ROBOT_ID)
    # Links in another order (or repeated) are the same normalized selection.
    shuffled = json.loads(json.dumps(_selector()))
    links = shuffled["finding"]["evidence"]
    shuffled["finding"]["evidence"] = [links[1], links[0], links[1]]
    assert ev.selector_matches(manifest, shuffled, ROBOT_ID)
    assert not ev.selector_matches(
        manifest, {"seq_range": {"from_seq": 7, "to_seq": 15}}, ROBOT_ID
    )
    with pytest.raises(ev.EvidenceError, match="another robot_id"):
        ev.parse_manifest(_manifest_bytes(), robot_id="ugv-008", export_id=EXPORT_ID)
    with pytest.raises(ev.EvidenceError, match="another export_id"):
        ev.parse_manifest(
            _manifest_bytes(), robot_id=ROBOT_ID, export_id="case-42:ev-2"
        )


def test_chunks_reassemble_into_the_bundle() -> None:
    manifest = ev.parse_manifest(
        _manifest_bytes(), robot_id=ROBOT_ID, export_id=EXPORT_ID
    )
    assert manifest.chunk_bytes == MANIFEST["chunk_bytes"]
    chunks = {
        spec.index: (
            VECTORS / "evidence" / "chunks" / f"{spec.index:04d}.bin"
        ).read_bytes()
        for spec in manifest.chunks
    }
    assert chunks[0] == _answer("08-evidence-chunk-0").body
    assert chunks[1] == _answer("09-evidence-chunk-1").body
    bundle = ev.assemble_bundle(manifest, chunks)
    assert bundle == (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
    assert hashlib.sha256(bundle).hexdigest() == EXPECTED["bundle_sha256"]
    with pytest.raises(ev.EvidenceError, match="chunk 1"):
        ev.assemble_bundle(manifest, {**chunks, 1: chunks[1][:-1] + b"\x00"})
    with pytest.raises(ev.EvidenceError, match="missing"):
        ev.assemble_bundle(manifest, {0: chunks[0], 2: chunks[2]})


def test_bundle_verifies_like_the_reference() -> None:
    manifest = ev.parse_manifest(
        _manifest_bytes(), robot_id=ROBOT_ID, export_id=EXPORT_ID
    )
    bundle = (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
    report = ev.verify_bundle(
        bundle,
        _keyring(),
        robot_id=ROBOT_ID,
        signing_key_id=manifest.signing_key_id,
    )
    assert report.intact, report.problems
    assert EXPECTED["verdict"] == "intact"
    assert report.chain_id == EXPECTED["chain_id"]
    assert report.device_id == EXPECTED["device_id"]
    assert (report.first_seq, report.last_seq) == (
        EXPECTED["first_seq"],
        EXPECTED["last_seq"],
    )
    assert report.verified_records == EXPECTED["records"]
    assert report.last_hash == EXPECTED["last_sha256"]
    assert (report.anchor_seq, report.anchor_hash) == (
        EXPECTED["anchor"]["seq"],
        EXPECTED["anchor"]["sha256"],
    )
    assert report.signing_key_id == EXPECTED["signing_key"]["key_id"]
    for ref in EXPECTED["referenced"]:
        assert report.record_hashes[ref["seq"]] == ref["sha256"]
    assert ev.check_report_against_manifest(report, manifest) == []


def test_tampered_bundle_is_not_verified() -> None:
    tampered = (
        VECTORS / "evidence" / "tampered" / "bundle-flipped-byte.rbbx"
    ).read_bytes()
    report = ev.verify_bundle(
        tampered, _keyring(), robot_id=ROBOT_ID, signing_key_id="bb:ugv-007:1"
    )
    assert not report.intact
    assert EXPECTED["tampered/bundle-flipped-byte.rbbx"].startswith(
        "tamper (HashMismatch at seq 10"
    )
    assert report.problems == ["hash mismatch at seq 10"]


@pytest.mark.parametrize(
    ("robot_id", "signing_key_id", "problem"),
    [
        ("ugv-008", "bb:ugv-007:1", "another device"),
        (ROBOT_ID, "bb:ugv-007:2", "no ed25519 key"),
    ],
)
def test_bundle_under_the_wrong_device_or_key_is_not_verified(
    robot_id: str, signing_key_id: str, problem: str
) -> None:
    bundle = (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
    report = ev.verify_bundle(
        bundle, _keyring(), robot_id=robot_id, signing_key_id=signing_key_id
    )
    assert not report.intact
    assert problem in report.problems[0]


def test_bundle_under_another_key_does_not_verify() -> None:
    other = Ed25519PrivateKey.from_private_bytes(bytes([0x52]) * 32).public_key()
    keyring = ev.parse_blackbox_keyring(
        [
            json.dumps(
                {
                    "format": "robodr-blackbox-key/v2",
                    "kind": "public",
                    "algorithm": "ed25519",
                    "key_id": "bb:ugv-007:1",
                    "public_hex": other.public_bytes_raw().hex(),
                }
            )
        ]
    )
    bundle = (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
    report = ev.verify_bundle(
        bundle, keyring, robot_id=ROBOT_ID, signing_key_id="bb:ugv-007:1"
    )
    assert report.problems == ["bad signature at seq 7"]


def test_truncated_or_padded_bundles_are_not_verified() -> None:
    bundle = (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
    for broken in (bundle[:-1], bundle + b"\x00", b"RBBXBND2" + bundle[8:]):
        report = ev.verify_bundle(
            broken, _keyring(), robot_id=ROBOT_ID, signing_key_id="bb:ugv-007:1"
        )
        assert not report.intact


def test_keyring_refuses_secret_key_files() -> None:
    public = _key("blackbox")
    with pytest.raises(ev.EvidenceError, match="public key files"):
        ev.parse_blackbox_keyring([json.dumps({**public, "kind": "secret"})])
    with pytest.raises(ev.EvidenceError, match="public key files"):
        ev.parse_blackbox_keyring([json.dumps({**public, "secret_hex": "00" * 32})])
    with pytest.raises(ev.EvidenceError, match="same key id"):
        ev.parse_blackbox_keyring([json.dumps(public), json.dumps(public)])
    bound = ev.parse_blackbox_keyring([json.dumps({**public, "device_id": "ugv-008"})])
    bundle = (VECTORS / "evidence" / "bundle.rbbx").read_bytes()
    report = ev.verify_bundle(
        bundle, bound, robot_id=ROBOT_ID, signing_key_id="bb:ugv-007:1"
    )
    assert report.problems == ["key 'bb:ugv-007:1' is bound to another device"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"finding_id": "rf1-x", "evidence_links": ["x"], "from_seq": 1, "to_seq": 2},
        {"from_seq": 1, "to_seq": 2, "from_ms": 1, "to_ms": 2},
        {"from_seq": 3, "to_seq": 2},
        {"from_ms": 0, "to_ms": 7 * 24 * 3600 * 1000 + 1},
        {"finding_id": "rf1-x", "evidence_links": []},
        {
            "finding_id": "rf1-x",
            "evidence_links": ["robodr-blackbox://ugv-008/0/1?sha256=" + "0" * 64],
        },
        {"from_seq": 1, "to_seq": 2, "context_records": 3},
    ],
)
def test_exactly_one_valid_selector(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ev.EvidenceError):
        ev.build_selector(robot_id=ROBOT_ID, **kwargs)
