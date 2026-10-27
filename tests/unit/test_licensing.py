"""Tests for signed license keys and single-tenant entitlement resolution."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import check_license_public_key
import license_tool
import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import ValidationError

from autosecops import config
from autosecops.admin.license.router import get_license
from autosecops.auth.types import PlatformRole
from autosecops.db.models import Tier
from autosecops.licensing import keys
from autosecops.licensing import service as license_service
from autosecops.licensing.evaluation import (
    LICENSE_CLOCK_SKEW,
    LICENSE_GRACE_PERIOD,
    evaluate_license,
    license_grants_multi_tenant,
)
from autosecops.licensing.token import (
    LicenseVerificationError,
    decode_license,
    encode_license,
)
from autosecops.licensing.types import (
    MAX_LICENSE_EXPIRY,
    LicenseClaims,
    LicenseErrorCode,
    LicenseGrant,
    LicenseStatus,
)
from autosecops.tiers import access as tier_access
from autosecops.tiers import defaults as tier_defaults
from autosecops.tiers import service as tier_service_module
from autosecops.tiers.access import is_org_entitled
from autosecops.tiers.enums import Entitlement
from autosecops.tiers.service import TierService

ISSUED_AT = datetime(2026, 1, 1, tzinfo=UTC)
EXPIRES_AT = datetime(2027, 1, 1, tzinfo=UTC)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _claims(entitlements: list[str] | None = None) -> LicenseClaims:
    return LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        entitlements=entitlements
        if entitlements is not None
        else ["git_sync", "rbac_addons"],
    )


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def embedded_key(
    monkeypatch: pytest.MonkeyPatch, private_key: Ed25519PrivateKey
) -> Iterator[Ed25519PrivateKey]:
    """Swap the embedded public key for a per-test key and reset caches."""
    pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    monkeypatch.setattr(keys, "LICENSE_PUBLIC_KEY_PEM", pem)
    monkeypatch.setattr(license_service, "_last_logged", None)
    license_service._decode_cached.cache_clear()
    license_service._embedded_public_key.cache_clear()
    yield private_key
    license_service._decode_cached.cache_clear()
    license_service._embedded_public_key.cache_clear()


@pytest.fixture
def single_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """Single-tenant mode with the production free baseline.

    The session conftest widens DEFAULT_ENTITLEMENTS for unrelated suites;
    these tests need the real baseline.
    """
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(),
    )


def _install(monkeypatch: pytest.MonkeyPatch, token: str | None) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__LICENSE_KEY", token)


# --- Token sign/verify -------------------------------------------------------


def test_encode_decode_round_trip(private_key: Ed25519PrivateKey) -> None:
    claims = _claims()
    token = encode_license(claims, private_key)

    assert token.count(".") == 1
    assert "=" not in token
    assert decode_license(token, private_key.public_key()) == claims


def test_decode_tolerates_surrounding_whitespace(
    private_key: Ed25519PrivateKey,
) -> None:
    token = encode_license(_claims(), private_key)

    assert decode_license(f"  {token}\n", private_key.public_key()) == _claims()


def test_tampered_payload_fails_signature(private_key: Ed25519PrivateKey) -> None:
    token = encode_license(_claims(["git_sync"]), private_key)
    _, signature = token.split(".")
    forged = _claims([e.value for e in Entitlement]).model_dump(mode="json")
    forged_token = f"{_b64(orjson.dumps(forged))}.{signature}"

    with pytest.raises(LicenseVerificationError) as exc_info:
        decode_license(forged_token, private_key.public_key())
    assert exc_info.value.code == LicenseErrorCode.BAD_SIGNATURE


def test_tampered_signature_fails(private_key: Ed25519PrivateKey) -> None:
    token = encode_license(_claims(), private_key)
    payload, signature = token.split(".")
    flipped = "A" if signature[0] != "A" else "B"

    with pytest.raises(LicenseVerificationError) as exc_info:
        decode_license(f"{payload}.{flipped}{signature[1:]}", private_key.public_key())
    assert exc_info.value.code == LicenseErrorCode.BAD_SIGNATURE


def test_token_signed_by_other_key_fails(private_key: Ed25519PrivateKey) -> None:
    token = encode_license(_claims(), Ed25519PrivateKey.generate())

    with pytest.raises(LicenseVerificationError) as exc_info:
        decode_license(token, private_key.public_key())
    assert exc_info.value.code == LicenseErrorCode.BAD_SIGNATURE


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("", id="empty"),
        pytest.param("not-a-license", id="no_separator"),
        pytest.param("a.b.c", id="too_many_parts"),
        pytest.param("!!!.###", id="non_base64"),
        pytest.param("ab+c.de/f", id="standard_base64_alphabet"),
        pytest.param(".", id="empty_parts"),
        pytest.param("a" * 20_000 + ".b", id="oversized"),
    ],
)
def test_garbled_token_is_malformed(private_key: Ed25519PrivateKey, token: str) -> None:
    with pytest.raises(LicenseVerificationError) as exc_info:
        decode_license(token, private_key.public_key())
    assert exc_info.value.code == LicenseErrorCode.MALFORMED


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"not json", id="not_json"),
        pytest.param(b'{"customer": "x"}', id="missing_fields"),
        pytest.param(
            orjson.dumps(
                {
                    "version": 1,
                    "license_id": "lic",
                    "customer": "x",
                    "issued_at": "2027-01-01T00:00:00Z",
                    "expires_at": "2026-01-01T00:00:00Z",
                }
            ),
            id="expires_before_issued",
        ),
        pytest.param(
            orjson.dumps(
                {
                    "version": 1,
                    "license_id": "lic",
                    "customer": "x",
                    "issued_at": "2026-01-01T00:00:00",
                    "expires_at": "2027-01-01T00:00:00",
                }
            ),
            id="naive_datetimes",
        ),
        pytest.param(
            orjson.dumps({**_claims().model_dump(mode="json"), "version": 2}),
            id="unknown_version",
        ),
    ],
)
def test_signed_but_invalid_claims(
    private_key: Ed25519PrivateKey, payload: bytes
) -> None:
    token = f"{_b64(payload)}.{_b64(private_key.sign(payload))}"

    with pytest.raises(LicenseVerificationError) as exc_info:
        decode_license(token, private_key.public_key())
    assert exc_info.value.code == LicenseErrorCode.INVALID_CLAIMS


def test_claims_reject_expiry_before_issue() -> None:
    with pytest.raises(ValidationError):
        LicenseClaims(
            license_id="lic",
            customer="x",
            issued_at=EXPIRES_AT,
            expires_at=ISSUED_AT,
        )


# --- Expiry and grace --------------------------------------------------------


@pytest.mark.parametrize(
    ("now", "status", "granted"),
    [
        pytest.param(ISSUED_AT, LicenseStatus.VALID, True, id="issued"),
        pytest.param(
            EXPIRES_AT - timedelta(seconds=1),
            LicenseStatus.VALID,
            True,
            id="last_second",
        ),
        pytest.param(EXPIRES_AT, LicenseStatus.GRACE, True, id="grace_starts"),
        pytest.param(
            EXPIRES_AT + LICENSE_GRACE_PERIOD - timedelta(seconds=1),
            LicenseStatus.GRACE,
            True,
            id="grace_last_second",
        ),
        pytest.param(
            EXPIRES_AT + LICENSE_GRACE_PERIOD,
            LicenseStatus.EXPIRED,
            False,
            id="grace_ends",
        ),
    ],
)
def test_evaluate_license_expiry_and_grace(
    private_key: Ed25519PrivateKey,
    now: datetime,
    status: LicenseStatus,
    granted: bool,
) -> None:
    token = encode_license(_claims(), private_key)

    state = evaluate_license(token, now=now, public_key=private_key.public_key())

    assert LICENSE_GRACE_PERIOD == timedelta(days=14)
    assert state.status == status
    assert state.claims == _claims()
    assert state.grace_ends_at == EXPIRES_AT + LICENSE_GRACE_PERIOD
    expected = {Entitlement.GIT_SYNC, Entitlement.RBAC_ADDONS} if granted else set()
    assert state.granted == expected


@pytest.mark.parametrize("token", [None, ""])
def test_evaluate_missing_license(
    private_key: Ed25519PrivateKey, token: str | None
) -> None:
    state = evaluate_license(token, now=ISSUED_AT, public_key=private_key.public_key())

    assert state.status == LicenseStatus.MISSING
    assert state.granted == frozenset()


def test_evaluate_invalid_license_never_raises(
    private_key: Ed25519PrivateKey,
) -> None:
    state = evaluate_license(
        "garbage", now=ISSUED_AT, public_key=private_key.public_key()
    )

    assert state.status == LicenseStatus.INVALID
    assert state.error == LicenseErrorCode.MALFORMED
    assert state.granted == frozenset()


def test_unknown_entitlements_are_ignored(private_key: Ed25519PrivateKey) -> None:
    token = encode_license(_claims(["forms", "future_feature"]), private_key)

    state = evaluate_license(token, now=ISSUED_AT, public_key=private_key.public_key())

    assert state.status == LicenseStatus.VALID
    assert state.granted == {Entitlement.FORMS}
    assert state.unknown_entitlements == ("future_feature",)


def test_get_license_state_reads_config_and_embedded_key(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _install(monkeypatch, encode_license(_claims(), embedded_key))

    valid = license_service.get_license_state(now=ISSUED_AT)
    grace = license_service.get_license_state(now=EXPIRES_AT + timedelta(days=1))
    expired = license_service.get_license_state(now=EXPIRES_AT + timedelta(days=15))

    assert valid.status == LicenseStatus.VALID
    assert grace.status == LicenseStatus.GRACE
    assert expired.status == LicenseStatus.EXPIRED


def test_embedded_dev_public_key_loads() -> None:
    """The committed key must stay a loadable Ed25519 public key."""
    license_service._embedded_public_key.cache_clear()
    assert license_service._embedded_public_key(keys.LICENSE_PUBLIC_KEY_PEM)


# --- Single-tenant entitlement resolution ------------------------------------


@pytest.mark.usefixtures("single_tenant")
def test_single_tenant_without_license_uses_free_baseline(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _install(monkeypatch, None)

    entitlements = tier_defaults.get_single_tenant_entitlements()

    assert entitlements == tier_defaults.BASELINE_ENTITLEMENTS
    enabled = {name for name, on in entitlements.model_dump().items() if on}
    assert enabled == {"custom_registry", "workspace_chat"}


@pytest.mark.usefixtures("single_tenant")
def test_single_tenant_valid_license_extends_baseline(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    claims = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=datetime.now(UTC) - timedelta(days=1),
        expires_at=datetime.now(UTC) + timedelta(days=30),
        entitlements=["git_sync", "forms"],
    )
    _install(monkeypatch, encode_license(claims, embedded_key))

    entitlements = tier_defaults.get_single_tenant_entitlements()

    enabled = {name for name, on in entitlements.model_dump().items() if on}
    assert enabled == {"custom_registry", "workspace_chat", "git_sync", "forms"}


@pytest.mark.usefixtures("single_tenant")
def test_single_tenant_license_in_grace_keeps_entitlements(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    claims = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=datetime.now(UTC) - timedelta(days=60),
        expires_at=datetime.now(UTC) - timedelta(days=3),
        entitlements=["case_addons"],
    )
    _install(monkeypatch, encode_license(claims, embedded_key))

    assert tier_defaults.get_single_tenant_entitlements().case_addons is True


@pytest.mark.usefixtures("single_tenant")
@pytest.mark.parametrize(
    "token_kind",
    ["expired_past_grace", "garbled", "wrong_key"],
)
def test_single_tenant_unusable_license_falls_back_to_baseline(
    monkeypatch: pytest.MonkeyPatch,
    embedded_key: Ed25519PrivateKey,
    token_kind: str,
) -> None:
    all_entitlements = [e.value for e in Entitlement]
    match token_kind:
        case "expired_past_grace":
            claims = LicenseClaims(
                license_id="lic_test",
                customer="Synthetic Customer",
                issued_at=datetime.now(UTC) - timedelta(days=90),
                expires_at=datetime.now(UTC) - timedelta(days=15),
                entitlements=all_entitlements,
            )
            token = encode_license(claims, embedded_key)
        case "garbled":
            token = "this is not a license"
        case _:
            token = encode_license(
                _claims(all_entitlements), Ed25519PrivateKey.generate()
            )
    _install(monkeypatch, token)

    assert (
        tier_defaults.get_single_tenant_entitlements()
        == tier_defaults.BASELINE_ENTITLEMENTS
    )


@pytest.mark.usefixtures("single_tenant")
def test_legacy_feature_flags_no_longer_grant_entitlements(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    legacy = "git-sync,agent-approvals,case-durations,rbac,agent-channels,forms"
    monkeypatch.setenv("AUTOSECOPS__FEATURE_FLAGS", legacy)
    _install(monkeypatch, None)

    entitlements = tier_defaults.get_single_tenant_entitlements()

    assert entitlements == tier_defaults.BASELINE_ENTITLEMENTS
    assert tier_defaults.legacy_flag_entitlements(legacy) == {
        Entitlement.GIT_SYNC,
        Entitlement.AGENT_ADDONS,
        Entitlement.CASE_ADDONS,
        Entitlement.RBAC_ADDONS,
        Entitlement.AGENT_CHANNELS,
        Entitlement.FORMS,
    }
    # The startup warning path must not raise.
    tier_defaults.warn_on_legacy_entitlement_flags()


def test_legacy_flag_parsing_normalizes_and_ignores_unknown() -> None:
    assert tier_defaults.legacy_flag_entitlements(
        " GIT_SYNC , unknown-flag , CASE_TRIGGERS "
    ) == {Entitlement.GIT_SYNC, Entitlement.CASE_ADDONS}
    assert tier_defaults.legacy_flag_entitlements(None) == set()


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_is_org_entitled_single_tenant_uses_license(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    claims = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=datetime.now(UTC) - timedelta(days=1),
        expires_at=datetime.now(UTC) + timedelta(days=30),
        entitlements=["watchtower"],
    )
    session = AsyncMock()
    org_id = uuid.uuid4()

    _install(monkeypatch, None)
    assert not await is_org_entitled(session, org_id, Entitlement.WATCHTOWER)

    _install(monkeypatch, encode_license(claims, embedded_key))
    assert await is_org_entitled(session, org_id, Entitlement.WATCHTOWER)
    session.execute.assert_not_awaited()


# --- Multi-tenant mode is unchanged ------------------------------------------


@pytest.mark.anyio
async def test_multi_tenant_ignores_license(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    _install(
        monkeypatch,
        encode_license(
            LicenseClaims(
                license_id="lic_test",
                customer="Synthetic Customer",
                issued_at=datetime.now(UTC) - timedelta(days=1),
                expires_at=datetime.now(UTC) + timedelta(days=30),
                entitlements=[e.value for e in Entitlement],
            ),
            embedded_key,
        ),
    )
    tier = Tier(display_name="Free", entitlements={"git_sync": False})
    resolve = AsyncMock(return_value=(None, tier))
    monkeypatch.setattr(tier_access, "get_org_tier_and_resolved_tier", resolve)
    monkeypatch.setattr(tier_service_module, "get_org_tier_and_resolved_tier", resolve)
    org_id = uuid.uuid4()

    assert not await is_org_entitled(AsyncMock(), org_id, Entitlement.GIT_SYNC)
    effective = await TierService(AsyncMock()).get_effective_entitlements(org_id)
    assert not any(effective.model_dump().values())


# --- Admin status endpoint ---------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("multi_tenant", [False, True])
async def test_admin_license_endpoint_reports_status(
    monkeypatch: pytest.MonkeyPatch,
    embedded_key: Ed25519PrivateKey,
    multi_tenant: bool,
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", multi_tenant)
    claims = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=datetime.now(UTC) - timedelta(days=60),
        expires_at=datetime.now(UTC) - timedelta(days=1),
        entitlements=["git_sync", "future_feature"],
    )
    _install(monkeypatch, encode_license(claims, embedded_key))
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")

    result = await get_license(role)

    assert result.status == LicenseStatus.GRACE
    assert result.enforced is (not multi_tenant)
    assert result.customer == "Synthetic Customer"
    assert result.expires_at == claims.expires_at
    assert result.entitlements == [Entitlement.GIT_SYNC]
    assert result.licensed_entitlements == ["git_sync", "future_feature"]


@pytest.mark.anyio
async def test_admin_license_endpoint_reports_missing(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _install(monkeypatch, None)
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")

    result = await get_license(role)

    assert result.status == LicenseStatus.MISSING
    assert result.customer is None
    assert result.entitlements == []
    # The free baseline is reported separately from licensed entitlements.
    assert result.included_entitlements == [
        Entitlement.CUSTOM_REGISTRY,
        Entitlement.WORKSPACE_CHAT,
    ]


# --- Issuer CLI ---------------------------------------------------------------


def test_license_tool_issue_and_inspect(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
    )
    expires = (datetime.now(UTC) + timedelta(days=365)).date().isoformat()

    exit_code = license_tool.main(
        [
            "issue",
            "--private-key",
            str(private_path),
            "--customer",
            "Synthetic Customer",
            "--expires",
            expires,
            "--entitlement",
            "git_sync",
        ]
    )
    token = capsys.readouterr().out.strip()

    assert exit_code == 0
    claims = decode_license(token, private_key.public_key())
    assert claims.entitlements == ["git_sync"]
    assert claims.expires_at.date().isoformat() == expires

    assert license_tool.main(["inspect", token, "--public-key", str(public_path)]) == 0
    assert '"status": "valid"' in capsys.readouterr().out
    assert (
        license_tool.main(["inspect", "garbage", "--public-key", str(public_path)]) == 1
    )


def test_license_tool_rejects_unknown_entitlement(tmp_path) -> None:
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )

    exit_code = license_tool.main(
        [
            "issue",
            "--private-key",
            str(private_path),
            "--customer",
            "Synthetic Customer",
            "--expires",
            "2030-01-01",
            "--entitlement",
            "not_real",
        ]
    )

    assert exit_code == 2


def test_license_tool_keygen_writes_private_key_owner_only(tmp_path) -> None:
    out_dir = tmp_path / "keys"

    assert license_tool.main(["keygen", "--out-dir", str(out_dir)]) == 0
    assert (out_dir / "license-private.pem").stat().st_mode & 0o777 == 0o600
    assert license_tool.main(["keygen", "--out-dir", str(out_dir)]) == 2


# --- Far-future expiry --------------------------------------------------------


def test_claims_reject_expiry_at_or_after_cap() -> None:
    with pytest.raises(ValidationError):
        LicenseClaims(
            license_id="lic",
            customer="x",
            issued_at=ISSUED_AT,
            expires_at=datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
        )
    with pytest.raises(ValidationError):
        LicenseClaims(
            license_id="lic",
            customer="x",
            issued_at=ISSUED_AT,
            expires_at=MAX_LICENSE_EXPIRY,
        )


def test_far_future_expiry_token_is_invalid_and_never_raises(
    private_key: Ed25519PrivateKey,
) -> None:
    """A signed "perpetual" license must not overflow the grace computation."""
    payload = orjson.dumps(
        {
            **_claims().model_dump(mode="json"),
            "expires_at": "9999-12-31T23:59:59Z",
        }
    )
    token = f"{_b64(payload)}.{_b64(private_key.sign(payload))}"

    state = evaluate_license(token, now=ISSUED_AT, public_key=private_key.public_key())

    assert state.status == LicenseStatus.INVALID
    assert state.error == LicenseErrorCode.INVALID_CLAIMS
    assert state.granted == frozenset()


def test_latest_allowed_expiry_evaluates(private_key: Ed25519PrivateKey) -> None:
    expires_at = MAX_LICENSE_EXPIRY - timedelta(seconds=1)
    claims = _claims().model_copy(update={"expires_at": expires_at})
    token = encode_license(claims, private_key)

    state = evaluate_license(token, now=ISSUED_AT, public_key=private_key.public_key())

    assert state.status == LicenseStatus.VALID
    assert state.grace_ends_at == expires_at + LICENSE_GRACE_PERIOD


def test_license_tool_rejects_far_future_expiry(tmp_path) -> None:
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )

    exit_code = license_tool.main(
        [
            "issue",
            "--private-key",
            str(private_path),
            "--customer",
            "Synthetic Customer",
            "--expires",
            "9999-12-31",
        ]
    )

    assert exit_code == 2


# --- Not-yet-valid licenses ---------------------------------------------------


@pytest.mark.parametrize(
    ("issued_in", "status"),
    [
        pytest.param(LICENSE_CLOCK_SKEW, LicenseStatus.VALID, id="within_skew"),
        pytest.param(
            LICENSE_CLOCK_SKEW + timedelta(seconds=1),
            LicenseStatus.INVALID,
            id="beyond_skew",
        ),
        pytest.param(timedelta(days=365), LicenseStatus.INVALID, id="next_year"),
    ],
)
def test_license_issued_in_the_future(
    private_key: Ed25519PrivateKey, issued_in: timedelta, status: LicenseStatus
) -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    claims = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=now + issued_in,
        expires_at=now + timedelta(days=400),
        entitlements=["git_sync"],
    )
    token = encode_license(claims, private_key)

    state = evaluate_license(token, now=now, public_key=private_key.public_key())

    assert state.status == status
    if status == LicenseStatus.INVALID:
        assert state.error == LicenseErrorCode.NOT_YET_VALID
        assert state.granted == frozenset()
    else:
        assert state.granted == {Entitlement.GIT_SYNC}


# --- Canonical base64url --------------------------------------------------------

_B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _flip_low_bit(segment: str) -> str:
    last = _B64URL_ALPHABET.index(segment[-1])
    return segment[:-1] + _B64URL_ALPHABET[last ^ 1]


def test_non_canonical_base64_is_malformed(private_key: Ed25519PrivateKey) -> None:
    """Unused trailing bits must be zero, so a token has one encoding."""
    token = encode_license(_claims(), private_key)
    payload_part, signature_part = token.split(".")
    # An Ed25519 signature is 64 bytes: 86 base64url chars with 4 unused bits.
    assert len(signature_part) % 4 != 0
    variant = f"{payload_part}.{_flip_low_bit(signature_part)}"
    # The variant decodes to the same bytes under a lenient decoder.
    padding = "=" * (-len(signature_part) % 4)
    assert base64.urlsafe_b64decode(
        _flip_low_bit(signature_part) + padding
    ) == base64.urlsafe_b64decode(signature_part + padding)

    with pytest.raises(LicenseVerificationError) as exc_info:
        decode_license(variant, private_key.public_key())
    assert exc_info.value.code == LicenseErrorCode.MALFORMED


# --- Multi-tenant mode requires a license grant ---------------------------------


def _multi_tenant_token(
    private_key: Ed25519PrivateKey,
    *,
    entitlements: list[str],
    expires_at: datetime | None = None,
) -> str:
    now = datetime.now(UTC)
    return encode_license(
        LicenseClaims(
            license_id="lic_test",
            customer="Synthetic Customer",
            issued_at=now - timedelta(days=60),
            expires_at=expires_at or now + timedelta(days=30),
            entitlements=entitlements,
        ),
        private_key,
    )


def test_multi_tenant_grant_is_known_but_not_an_org_entitlement(
    private_key: Ed25519PrivateKey,
) -> None:
    token = encode_license(_claims(["multi_tenant", "git_sync"]), private_key)

    state = evaluate_license(token, now=ISSUED_AT, public_key=private_key.public_key())

    assert state.grants == {LicenseGrant.MULTI_TENANT}
    assert state.granted == {Entitlement.GIT_SYNC}
    assert state.unknown_entitlements == ()


def test_license_grants_multi_tenant(embedded_key: Ed25519PrivateKey) -> None:
    now = datetime.now(UTC)

    assert not license_grants_multi_tenant(None)
    assert not license_grants_multi_tenant("garbage")
    assert not license_grants_multi_tenant(
        _multi_tenant_token(embedded_key, entitlements=["git_sync"])
    )
    assert license_grants_multi_tenant(
        _multi_tenant_token(embedded_key, entitlements=["multi_tenant"])
    )
    in_grace = _multi_tenant_token(
        embedded_key,
        entitlements=["multi_tenant"],
        expires_at=now - timedelta(days=1),
    )
    assert license_grants_multi_tenant(in_grace)
    past_grace = _multi_tenant_token(
        embedded_key,
        entitlements=["multi_tenant"],
        expires_at=now - timedelta(days=15),
    )
    assert not license_grants_multi_tenant(past_grace)


def test_multi_tenant_flag_without_license_stays_single_tenant() -> None:
    """Setting the env flag alone must not turn on multi-tenant mode."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key != "AUTOSECOPS__LICENSE_KEY"
    }
    env["AUTOSECOPS__EE_MULTI_TENANT"] = "true"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from autosecops import config;"
            "print(config.AUTOSECOPS__EE_MULTI_TENANT_REQUESTED,"
            " config.AUTOSECOPS__EE_MULTI_TENANT)",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.split() == ["True", "False"]


async def _entitlement_sources(
    monkeypatch: pytest.MonkeyPatch, token: str | None
) -> tuple[bool, AsyncMock]:
    """Resolve multi-tenant mode like config does and check git_sync."""
    _install(monkeypatch, token)
    monkeypatch.setattr(
        config, "AUTOSECOPS__EE_MULTI_TENANT", license_grants_multi_tenant(token)
    )
    # Tiers grant git_sync; a license without git_sync does not.
    tier = Tier(display_name="Paid", entitlements={"git_sync": True})
    resolve = AsyncMock(return_value=(None, tier))
    monkeypatch.setattr(tier_access, "get_org_tier_and_resolved_tier", resolve)
    entitled = await is_org_entitled(AsyncMock(), uuid.uuid4(), Entitlement.GIT_SYNC)
    return entitled, resolve


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_multi_tenant_flag_without_license_uses_license_mode(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    entitled, resolve = await _entitlement_sources(monkeypatch, None)

    assert config.AUTOSECOPS__EE_MULTI_TENANT is False
    assert entitled is False
    resolve.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_multi_tenant_flag_with_license_lacking_grant_uses_license_mode(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    token = _multi_tenant_token(embedded_key, entitlements=["forms"])

    entitled, resolve = await _entitlement_sources(monkeypatch, token)

    assert config.AUTOSECOPS__EE_MULTI_TENANT is False
    assert entitled is False
    resolve.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.usefixtures("single_tenant")
async def test_multi_tenant_flag_with_licensed_grant_uses_tier_mode(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    token = _multi_tenant_token(embedded_key, entitlements=["multi_tenant"])

    entitled, resolve = await _entitlement_sources(monkeypatch, token)

    assert config.AUTOSECOPS__EE_MULTI_TENANT is True
    assert entitled is True
    resolve.assert_awaited_once()


def test_startup_logs_error_when_multi_tenant_is_not_licensed(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT_REQUESTED", True)
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", False)
    _install(monkeypatch, None)
    mock_logger = MagicMock()
    monkeypatch.setattr(tier_defaults, "logger", mock_logger)

    tier_defaults.log_license_startup()

    messages = [call.args[0] for call in mock_logger.error.call_args_list]
    assert any("grants multi_tenant" in message for message in messages)


@pytest.mark.anyio
async def test_admin_license_endpoint_reports_grants(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    _install(
        monkeypatch,
        _multi_tenant_token(embedded_key, entitlements=["multi_tenant", "forms"]),
    )
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="autosecops-api")

    result = await get_license(role)

    assert result.entitlements == [Entitlement.FORMS]
    assert result.grants == [LicenseGrant.MULTI_TENANT]


def test_license_tool_all_entitlements_excludes_multi_tenant(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    base_args = [
        "issue",
        "--private-key",
        str(private_path),
        "--customer",
        "Synthetic Customer",
        "--expires",
        "2030-01-01",
        "--all-entitlements",
    ]

    assert license_tool.main(base_args) == 0
    token = capsys.readouterr().out.strip()
    assert (
        "multi_tenant"
        not in decode_license(token, private_key.public_key()).entitlements
    )

    assert license_tool.main([*base_args, "--entitlement", "multi_tenant"]) == 0
    token = capsys.readouterr().out.strip()
    assert (
        "multi_tenant" in decode_license(token, private_key.public_key()).entitlements
    )


# --- Development key guard ------------------------------------------------------

# A copy of the development key, so these tests keep passing after the
# production key replaces it in keys.py.
_DEV_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9SNn3/ISCoRcLmzTqRyi37LOYO/boUAld+8JlK0mjyo=
-----END PUBLIC KEY-----
"""


def _other_public_key_pem() -> bytes:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )


def test_development_key_fingerprint() -> None:
    assert keys.is_development_public_key(_DEV_PUBLIC_KEY_PEM)
    assert not keys.is_development_public_key(_other_public_key_pem())


def test_startup_logs_error_for_development_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(keys, "LICENSE_PUBLIC_KEY_PEM", _DEV_PUBLIC_KEY_PEM)
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    mock_logger = MagicMock()
    monkeypatch.setattr(tier_defaults, "logger", mock_logger)

    tier_defaults.log_license_startup()

    messages = [call.args[0] for call in mock_logger.error.call_args_list]
    assert any("DEVELOPMENT license public key" in message for message in messages)


def test_startup_does_not_log_development_key_error_for_other_keys(
    monkeypatch: pytest.MonkeyPatch, embedded_key: Ed25519PrivateKey
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__EE_MULTI_TENANT", True)
    mock_logger = MagicMock()
    monkeypatch.setattr(tier_defaults, "logger", mock_logger)

    tier_defaults.log_license_startup()

    mock_logger.error.assert_not_called()


def _keys_module_with(tmp_path: Path, pem: bytes) -> Path:
    """Copy keys.py with ``LICENSE_PUBLIC_KEY_PEM`` set to ``pem``."""
    source = check_license_public_key.KEYS_PATH.read_text()
    current = keys.LICENSE_PUBLIC_KEY_PEM.decode()
    assert current in source
    path = tmp_path / "keys.py"
    path.write_text(source.replace(current, pem.decode()))
    return path


def test_release_check_fails_on_development_key(tmp_path: Path) -> None:
    path = _keys_module_with(tmp_path, _DEV_PUBLIC_KEY_PEM)

    assert check_license_public_key.main([str(path)]) == 1


def test_release_check_passes_on_other_key(tmp_path: Path) -> None:
    path = _keys_module_with(tmp_path, _other_public_key_pem())

    assert check_license_public_key.main([str(path)]) == 0
