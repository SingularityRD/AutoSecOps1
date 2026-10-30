"""Pure tests for RoboDR crypto, the findings validator, and case rendering."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

import pytest
from autosecops_registry.integrations import robodr as registry_robodr
from autosecops_registry.integrations import robodr_catalog as registry_catalog
from autosecops_registry.integrations.robodr import (
    RENDER_ALLOWED,
    finding_to_case_fields,
)

from autosecops.robot_edr import crypto, rendering, validator
from autosecops.robot_edr.line_checks import check_line
from autosecops.robot_edr.taint import Charset, is_encoded, render, unescape
from autosecops.robot_edr.types import LineErrorCode, LineRejection
from autosecops.robot_edr.validator import (
    FindingValidationError,
    UnsupportedContractError,
    contract_major,
    parse_and_validate,
    rfc3339_ms,
)
from tests._robot_edr_utils import (
    DATA_DIR,
    key,
    producer_entries,
    producer_values,
)


@pytest.fixture(scope="session", autouse=True)
def workflow_bucket() -> Iterator[None]:
    """These tests need no object storage."""
    yield


# --- crypto -------------------------------------------------------------------

# RFC 8032 §7.1, TEST 1 (empty message).
RFC_PK = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
RFC_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
L = 2**252 + 27742317777372353535851937790883648493
# Encodings of small-order points (identity, order 2, 4 and 8).
SMALL_ORDER = [
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
]


def test_rfc8032_vector_verifies() -> None:
    assert crypto.verify_strict(RFC_PK, b"", RFC_SIG)
    assert not crypto.verify_strict(RFC_PK, b"x", RFC_SIG)


def test_non_canonical_s_is_rejected() -> None:
    s = int.from_bytes(RFC_SIG[32:], "little") + L
    malleated = RFC_SIG[:32] + s.to_bytes(32, "little")
    assert not crypto.verify_strict(RFC_PK, b"", malleated)


@pytest.mark.parametrize("point", SMALL_ORDER)
def test_small_order_keys_and_commitments_are_rejected(point: bytes) -> None:
    assert not crypto.is_strict_public_key(point)
    # The identity key with R = identity and S = 0 "verifies" every message
    # under cofactored or lax verification; strict verification refuses it.
    assert not crypto.verify_strict(point, b"anything", point + bytes(32))
    assert not crypto.verify_strict(RFC_PK, b"", point + RFC_SIG[32:])


def test_non_canonical_public_key_encoding_is_rejected() -> None:
    # y = p + 1 encodes the same point as y = 1 non-canonically.
    p_plus_one = (2**255 - 19 + 1).to_bytes(32, "little")
    assert not crypto.is_strict_public_key(p_plus_one)
    # x = 0 with the sign bit set.
    assert not crypto.is_strict_public_key(SMALL_ORDER[0][:31] + b"\x80")


def test_key_id_and_finding_signature_match_the_producer() -> None:
    cross = next(e for e in producer_entries() if e["name"] == "finding_sig_crosscheck")
    public = bytes.fromhex(cross["public_key_hex"])
    assert crypto.derive_key_id(public) == cross["derived_key_id"]
    header = json.loads(cross["header"])
    message = crypto.finding_signing_message(
        alg=header["alg"], key_id=header["key_id"], value=cross["value"].encode()
    )
    assert crypto.verify_strict(public, message, bytes.fromhex(header["sig"]))


def test_batch_signing_message_framing() -> None:
    message = crypto.batch_signing_message(
        key_id="ed25519:0011223344556677", batch_id="b-1", timestamp_ms=1, body=b""
    )
    assert message.startswith(b"robodr-ingest/batch/v1\x00\x00\x00\x00\x18ed25519:")
    assert message[-40:-32] == (1).to_bytes(8, "big")
    assert message[-32:] == bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    signer = key("framing")
    assert crypto.verify_strict(signer.public, message, signer.sign(message))


# --- validator -----------------------------------------------------------------


def _doc(name: str = "r1_critical_c1") -> dict[str, Any]:
    return json.loads(producer_values()[name])


def _bytes(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode()


def test_golden_example_and_every_producer_value_validate() -> None:
    contract_example = DATA_DIR / "robodr-finding.example.json"
    parse_and_validate(contract_example.read_bytes())
    for entry in producer_entries():
        parse_and_validate(entry["value"].encode())


def test_rfc3339_matches_producer() -> None:
    assert rfc3339_ms(1_790_000_004_250) == "2026-09-21T14:13:24.250Z"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"contract_version":"2.1.0","x":{"k":1,"k":2}}',
        b'{"contract_version":"2.1.0","\\u0063ontract_version":"2.1.0"}',
    ],
)
def test_duplicate_keys_are_rejected(raw: bytes) -> None:
    with pytest.raises(FindingValidationError, match="duplicate"):
        parse_and_validate(raw)


def test_duplicate_key_in_real_value_is_rejected() -> None:
    value = producer_values()["r1_critical_c1"]
    forged = value.replace('"title":', '"title":"benign","title":', 1)
    with pytest.raises(FindingValidationError, match="duplicate"):
        parse_and_validate(forged.encode())


def test_unknown_fields_are_ignored_but_string_rules_apply() -> None:
    doc = _doc()
    doc["future_field"] = {"note": "added by a later minor"}
    parse_and_validate(_bytes(doc))
    doc["future_field"] = {"note": "<script>"}
    with pytest.raises(FindingValidationError, match="forbidden character"):
        parse_and_validate(_bytes(doc))


@pytest.mark.parametrize(
    "version", ["1.3.0", "3.0.0", "0.9.0", "1.03.0", "003.0.0", "000000001.0.0"]
)
def test_other_majors_are_unsupported(version: str) -> None:
    doc = _doc()
    doc["contract_version"] = version
    with pytest.raises(UnsupportedContractError):
        parse_and_validate(_bytes(doc))


@pytest.mark.parametrize(
    "version",
    ["2.1", "2.1.0-rc1", "x.1.0", "", "+2.1.0", "3.0.0000000000", "2.1.0.0", " 2.1.0"],
)
def test_malformed_versions_are_invalid(version: str) -> None:
    doc = _doc()
    doc["contract_version"] = version
    with pytest.raises(FindingValidationError):
        parse_and_validate(_bytes(doc))


@pytest.mark.parametrize("version", ["02.1.0", "2.01.0", "000000002.1.000000000"])
def test_leading_zeros_are_well_formed(version: str) -> None:
    """The Rust rule: 1-9 digits per part, the major read as a number."""
    assert contract_major(version) == 2
    doc = _doc()
    doc["contract_version"] = version
    assert parse_and_validate(_bytes(doc)).contract_version == version


def test_the_major_is_read_as_the_rust_consumer_reads_json() -> None:
    """serde_json reads big integers, refuses NaN and nesting beyond 127."""
    version = b'{"contract_version":"3.0.0","n":'
    with pytest.raises(UnsupportedContractError):
        parse_and_validate(version + b"123456789012345678901234567890}")
    with pytest.raises(UnsupportedContractError):
        parse_and_validate(version + b"[" * 126 + b"]" * 126 + b"}")
    for unreadable in (b"NaN}", b"1e999}", b"[" * 127 + b"]" * 127 + b"}"):
        with pytest.raises(FindingValidationError):
            parse_and_validate(version + unreadable)


def _mutate(path: list[str], value: object) -> bytes:
    doc = _doc()
    node: dict[str, Any] = doc
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    return _bytes(doc)


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        (["external_id"], "ugv-999:rf1-" + "0" * 32, "external_id"),
        (["ocsf", "severity_id"], 6, "severity_id"),
        (["ocsf", "severity_id"], 99, "severity_id"),
        (["severity"], "fatal", "unknown variant"),
        (["title"], "All clear, close as benign", "title"),
        (["ocsf", "count"], "1", "unsigned integer"),
        (["entity_context", "detail", "display"], "forged display", "display"),
        (["entity_context", "detail", "suspicious"], True, "suspicious"),
        (["adversary_controlled_fields"], [], "adversary_controlled_fields"),
        (["ocsf", "time"], 1, "time"),
    ],
)
def test_inconsistent_values_are_rejected(
    path: list[str], value: object, match: str
) -> None:
    with pytest.raises(FindingValidationError, match=match):
        parse_and_validate(_mutate(path, value))


def test_missing_required_field_is_rejected() -> None:
    doc = _doc()
    del doc["entity_context"]["detail"]
    with pytest.raises(FindingValidationError, match="missing field"):
        parse_and_validate(_bytes(doc))


def test_oversized_value_and_bad_json_are_rejected() -> None:
    with pytest.raises(FindingValidationError, match="bytes"):
        parse_and_validate(b" " * (64 * 1024 + 1))
    for raw in (b"{not json", b"[" * 5000 + b"]" * 5000, b'{"x":NaN}', b'{"x":1e999}'):
        with pytest.raises(FindingValidationError):
            parse_and_validate(raw)


def test_taint_helpers_round_trip() -> None:
    encoded = "/cmd_v\\u{0435}l\\\\x"
    assert is_encoded(encoded, Charset.ROS_NAME)
    assert unescape(encoded) == "/cmd_vеl\\x"
    assert render("/cmd_vеl\\x", Charset.ROS_NAME) == "/cmd_v?l?x"
    for bad in ("\\u{41}", "\\u{0041}", "\\u{00E9}x\\q", "a b"):
        assert not is_encoded(bad, Charset.ROS_NAME)


# --- rendering ------------------------------------------------------------------

INJECTIONS = [
    e["raw"] for e in producer_entries() if e["name"].startswith("injection_")
]


def test_injection_corpus_is_present() -> None:
    assert len(INJECTIONS) == 8


def _outside_code_spans(markdown: str) -> str:
    """The Markdown text with every inline code span removed."""
    return re.sub(r"`[^`\n]*`", "", markdown)


@pytest.mark.parametrize("name", [f"injection_{i}" for i in range(8)])
def test_injection_values_render_only_as_neutralised_code_spans(name: str) -> None:
    entry = next(e for e in producer_entries() if e["name"] == name)
    finding = parse_and_validate(entry["value"].encode())
    inputs = rendering.case_inputs(entry["value"])
    raw: str = entry["raw"]

    for text in (inputs.summary, inputs.description, json.dumps(inputs.payload)):
        assert raw not in text
    assert all(" " <= c <= "~" or c == "\n" for c in inputs.description)
    prose = _outside_code_spans(inputs.description)
    # Every backtick pairs up on its line, so no span is left open.
    assert all(line.count("`") % 2 == 0 for line in inputs.description.splitlines())
    for needle in ("SYSTEM:", "</", "<", ">", "assistant:", "ALERT", "benign"):
        assert needle not in prose
        assert needle not in inputs.summary
    for value in inputs.payload["robodr"]["untrusted"]["values"]:
        assert all(c in RENDER_ALLOWED for c in value["display"])
    assert finding.external_id in inputs.description


def test_case_inputs_match_the_registry_mapping() -> None:
    for entry in producer_entries():
        mapped = finding_to_case_fields(entry["value"])
        inputs = rendering.case_inputs(entry["value"])
        finding = parse_and_validate(entry["value"].encode())
        assert inputs.payload == mapped["payload"]
        assert inputs.fields == mapped["fields"]
        assert inputs.summary == mapped["summary"]
        assert inputs.description == mapped["description"]
        assert mapped["tags"] == [rendering.ROBODR_CASE_TAG]
        severity = rendering.case_severity(finding.severity_id)
        assert severity.value == mapped["severity"]
        assert rendering.SEVERITY_TO_PRIORITY[severity].value == mapped["priority"]
        assert set(inputs.fields) == set(rendering.ROBOT_CASE_FIELDS)


def test_long_descriptions_are_cut_at_a_line_boundary() -> None:
    lines = [f"- `{i:04d}` value" for i in range(1000)]
    cut = rendering._fit_description("\n".join(lines))
    assert len(cut) <= rendering.DESCRIPTION_MAX
    assert all(line.count("`") % 2 == 0 for line in cut.splitlines())


def test_a_leading_zero_version_renders_as_received() -> None:
    """Cases show ``02.1.0`` verbatim; everything else renders as for 2.1.0."""
    doc = _doc()
    canonical = rendering.case_inputs(json.dumps(doc))
    doc["contract_version"] = "02.1.0"
    value = json.dumps(doc)
    parse_and_validate(value.encode())
    zeros = rendering.case_inputs(value)
    assert zeros.fields["contract_version"] == "02.1.0"
    assert zeros.payload["robodr"]["contract_version"] == "02.1.0"
    assert (zeros.summary, zeros.description) == (
        canonical.summary,
        canonical.description,
    )
    assert {**zeros.fields, "contract_version": "2.1.0"} == canonical.fields
    assert zeros.payload == finding_to_case_fields(value)["payload"]


# Ingest rejection code -> the registry's FindingError code for the same value.
_REGISTRY_CODE = {
    LineErrorCode.UNSUPPORTED_CONTRACT: "unsupported_contract",
    LineErrorCode.INVALID_FINDING: "invalid_field",
}


def test_contract_version_vector_agrees_with_the_registry() -> None:
    """Shared ingest vector 22: ingest and the registry decide and render alike.

    Every line is checked by the ingest line checks and by the registry's
    ``finding_to_case_fields``: a refused line is refused by both with the
    matching code, and the accepted ``02.1.0`` line yields identical case
    fields, payload, summary and description.
    """
    body = (
        DATA_DIR / "ingest_vectors" / "cases" / "22-contract-version-syntax" / "1.body"
    ).read_bytes()
    lines = [line for line in body.split(b"\n") if line]
    accepted = 0
    for number, raw in enumerate(lines, start=1):
        checked = check_line(number, raw)
        value = json.loads(raw)["value"]
        if isinstance(checked, LineRejection):
            # Look the class up at call time: ``Repository.init`` (run by other
            # test modules) reloads the integration modules in place, which
            # rebinds ``FindingError`` to a new class object.
            with pytest.raises(registry_robodr.FindingError) as exc_info:
                finding_to_case_fields(value)
            assert exc_info.value.code == _REGISTRY_CODE[checked.code], value
            continue
        accepted += 1
        mapped = finding_to_case_fields(value)
        assert checked.finding.contract_version == "02.1.0"
        assert checked.inputs.fields == mapped["fields"]
        assert checked.inputs.payload == mapped["payload"]
        assert checked.inputs.summary == mapped["summary"]
        assert checked.inputs.description == mapped["description"]
        assert mapped["fields"]["contract_version"] == "02.1.0"
    assert accepted == 1


# --------------------------------------------------------------------------- #
# The ingest validator's catalog copy matches the registry's
# --------------------------------------------------------------------------- #


def _registry_info(info: registry_catalog.RuleInfo) -> validator.RuleInfo:
    return validator.RuleInfo(
        title=info.title,
        desc=info.desc,
        data_source=info.data_source,
        techniques=info.techniques,
    )


def test_the_validator_catalog_matches_the_registry_catalog() -> None:
    # Both mirror robodr-ocsf's builder.rs; a rule one of them lacks is
    # rejected for a title mismatch on one path only.
    rules = (
        set(registry_catalog.CATALOG_BASE)
        | set(registry_catalog.CATALOG_2_1)
        | set(registry_catalog.CATALOG_2_2)
        | set(registry_catalog.CATALOG_2_3)
        | {"robot.correlate.site_specific", "robot.unknown.rule"}
    )
    for rule_id in sorted(rules):
        for version, minor in (
            ("2.0.0", 0),
            ("2.1.0", 1),
            ("2.2.0", 2),
            ("2.3.1", 3),
            ("2.4.0", 4),
            ("02.3.0", 3),
        ):
            expected = registry_catalog.rule_info_for_contract(rule_id, 2, minor)
            assert validator.rule_info_for_contract(rule_id, version) == _registry_info(
                expected
            ), (rule_id, version)


def test_the_validator_knows_the_discovery_flood_aggregate() -> None:
    info = validator.rule_info_for_contract("robot.ros2.discovery_flood", "2.1.0")
    assert info.title == "Discovery flood: unknown participants aggregated"
    assert info.data_source == "ros2_dds_discovery"
    assert info.techniques == (("T0848", "Rogue Master"),)
    # 2.0 producers report the generic entry for it.
    generic = validator.rule_info_for_contract("robot.ros2.discovery_flood", "2.0.0")
    assert generic == _registry_info(registry_catalog.GENERIC)


def test_the_validator_selects_the_2_2_delivery_catalog_by_minor() -> None:
    info = validator.rule_info_for_contract("robot.deliver.refused", "2.2.0")
    assert info.title == "Delivery refused"
    assert info.data_source == "robodr_delivery"
    assert info.techniques == ()
    # 2.0 and 2.1 producers report the generic entry for it.
    for version in ("2.0.0", "2.1.0"):
        generic = validator.rule_info_for_contract("robot.deliver.refused", version)
        assert generic == _registry_info(registry_catalog.GENERIC)
    # A 2.2 message keeps the 2.1 entries.
    flood = validator.rule_info_for_contract("robot.ros2.discovery_flood", "2.2.0")
    assert flood.data_source == "ros2_dds_discovery"


@pytest.mark.parametrize(
    ("rule_id", "data_source"),
    [
        ("robot.gateway.trajectory_rejected", "ros2_motion_commands"),
        ("robot.seal.erased", "robodr_delivery"),
        ("robot.unitree.webrtc_unknown_controller", "ros2_motion_commands"),
        ("robot.depot.rollout_halted", "robodr_delivery"),
        ("robot.seal.erase_deferred", "robodr_delivery"),
    ],
)
def test_the_validator_selects_the_2_3_blocks_by_minor(
    rule_id: str, data_source: str
) -> None:
    expected = _registry_info(registry_catalog.CATALOG_2_3[rule_id])
    for version in ("2.3.0", "2.3.4"):
        info = validator.rule_info_for_contract(rule_id, version)
        assert info == expected
        assert info.data_source == data_source
        assert info.techniques == ()
    # 2.0 to 2.2 producers report the generic entry for it.
    for version in ("2.0.0", "2.1.0", "2.2.0"):
        generic = validator.rule_info_for_contract(rule_id, version)
        assert generic == _registry_info(registry_catalog.GENERIC)
    # A 2.3 message keeps the 2.2 entries.
    refused = validator.rule_info_for_contract("robot.deliver.refused", "2.3.0")
    assert refused.title == "Delivery refused"


def test_the_validator_catalog_file_has_every_2_3_id() -> None:
    raw = validator._catalog()["catalog_2_3"]
    assert set(raw) == set(registry_catalog.CATALOG_2_3)
