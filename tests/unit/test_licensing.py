"""Tests for signed license keys and single-tenant entitlement resolution."""

from __future__ import annotations

import base64
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

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

from tracecat import config
from tracecat.admin.license.router import get_license
from tracecat.auth.types import PlatformRole
from tracecat.db.models import Tier
from tracecat.licensing import keys
from tracecat.licensing import service as license_service
from tracecat.licensing.service import LICENSE_GRACE_PERIOD, evaluate_license
from tracecat.licensing.token import (
    LicenseVerificationError,
    decode_license,
    encode_license,
)
from tracecat.licensing.types import LicenseClaims, LicenseErrorCode, LicenseStatus
from tracecat.tiers import access as tier_access
from tracecat.tiers import defaults as tier_defaults
from tracecat.tiers import service as tier_service_module
from tracecat.tiers.access import is_org_entitled
from tracecat.tiers.enums import Entitlement
from tracecat.tiers.service import TierService

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
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", False)
    monkeypatch.setattr(
        tier_defaults,
        "DEFAULT_ENTITLEMENTS",
        tier_defaults.BASELINE_ENTITLEMENTS.model_copy(),
    )


def _install(monkeypatch: pytest.MonkeyPatch, token: str | None) -> None:
    monkeypatch.setattr(config, "TRACECAT__LICENSE_KEY", token)


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
    monkeypatch.setenv("TRACECAT__FEATURE_FLAGS", legacy)
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
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", True)
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
    monkeypatch.setattr(config, "TRACECAT__EE_MULTI_TENANT", multi_tenant)
    claims = LicenseClaims(
        license_id="lic_test",
        customer="Synthetic Customer",
        issued_at=datetime.now(UTC) - timedelta(days=60),
        expires_at=datetime.now(UTC) - timedelta(days=1),
        entitlements=["git_sync", "future_feature"],
    )
    _install(monkeypatch, encode_license(claims, embedded_key))
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="tracecat-api")

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
    role = PlatformRole(type="user", user_id=uuid.uuid4(), service_id="tracecat-api")

    result = await get_license(role)

    assert result.status == LicenseStatus.MISSING
    assert result.customer is None
    assert result.entitlements == []


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
