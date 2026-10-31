"""Regression tests for the RoboDR fleet API review (findings F1-F10).

Each test pins one finding: trust roots and revocation-list withdrawal (F1),
black-box key provenance and the evidence keyring (F2), approval-key
separation and offline signing (F3), SOC-wide key uniqueness (F4),
per-robot rotation ids (F5), 64-bit storage limits (F6), the Redis replay
cache (F7), pre-buffer authentication, 401 audit aggregation and the draft
cap (F8), and ring floors, test-key deny-list and refusal auditing (F10).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

from autosecops import config
from autosecops.audit.enums import AuditEventStatus
from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import (
    Organization,
    RobotFleetProfileDraft,
    RobotFleetSocKey,
    RobotKey,
)
from autosecops.exceptions import (
    AutoSecOpsAuthorizationError,
    AutoSecOpsValidationError,
)
from autosecops.redis.client import get_redis_client
from autosecops.robot_edr import fleet, fleet_replay, fleet_throttle
from autosecops.robot_edr import fleet_wire as wire
from autosecops.robot_edr.evidence import RobotEvidenceService
from autosecops.robot_edr.schemas import (
    FleetApprovalCreate,
    FleetApprovalSignature,
    FleetOfferUpdate,
    FleetRevocationCreate,
    FleetRevocationWithdraw,
    FleetRingUpdate,
    FleetSocKeyCreate,
    FleetTrustRootCreate,
    RobotKeyCreate,
)
from autosecops.robot_edr.service import RobotConflictError, RobotsService
from autosecops.robot_edr.types import (
    FleetApprovalStatus,
    FleetSocKeyCustody,
    FleetSocKeyKind,
    FleetSocKeyStatus,
    RobotKeyRole,
)
from tests.support.robot_fleet import (
    DISTRIBUTION,
    FLEET_SCOPES,
    VECTORS,
    SimRobot,
    Soc,
    add_robot,
    drop_soc,
    enroll,
    enrolled,
    issue,
    new_key,
    new_soc,
    revocation_list,
    robot_api,
    robot_edr_entitled,
    setup_keys,
    signed_get,
    signed_post,
    soc,
)

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]

__all__ = ["robot_api", "robot_edr_entitled", "soc"]

MAX_STORED_INT = 2**63 - 1


@pytest.fixture
async def other_soc(svc_organization: Organization) -> AsyncIterator[Soc]:
    created, user_ids = await new_soc(svc_organization)
    try:
        yield created
    finally:
        await drop_soc(created, user_ids)


async def _trust(soc: Soc, root: wire.SigningKey) -> None:
    async with get_async_session_bypass_rls_context_manager() as session:
        await soc.fleet(soc.alice, session).add_trust_root(
            FleetTrustRootCreate(public_key=wire.public_key_file(root.public_key))
        )


# --- F1: trust roots, verified lists only, two-person withdrawal ----------------


async def test_unverified_list_with_huge_serial_cannot_block_real_lists(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    _robot_uuid, sim = await enrolled(soc, robot_api)
    root, attacker = new_key(), new_key()
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        # No trust root configured: nothing can be published.
        with pytest.raises(AutoSecOpsValidationError, match="trust root"):
            await service.publish_revocation_list(
                FleetRevocationCreate(revocation_list=revocation_list(root))
            )
    await _trust(soc, root)
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        # A list signed by anything else never sets the serial floor.
        with pytest.raises(AutoSecOpsValidationError, match="trust root"):
            await service.publish_revocation_list(
                FleetRevocationCreate(
                    revocation_list=revocation_list(attacker, serial=MAX_STORED_INT)
                )
            )
        published = await service.publish_revocation_list(
            FleetRevocationCreate(revocation_list=revocation_list(root, serial=3))
        )
    assert published.serial == 3 and published.signature_checked
    path = "/robot-edr/v2/fleet/revocations/ugv-x1"
    served = await signed_get(robot_api, sim, path)
    assert served.status_code == 200
    assert json.loads(served.content)["serial"] == 3


async def test_trust_roots_need_robot_trust(soc: Soc) -> None:
    root = new_key()
    no_trust = soc.alice.model_copy(update={"scopes": FLEET_SCOPES - {"robot:trust"}})
    async with get_async_session_bypass_rls_context_manager() as session:
        with pytest.raises(AutoSecOpsAuthorizationError):
            await soc.fleet(no_trust, session).add_trust_root(
                FleetTrustRootCreate(public_key=root.public_key.hex())
            )
        # The contract vectors' test trust root is never trusted for real.
        with pytest.raises(AutoSecOpsValidationError, match="test key"):
            await soc.fleet(soc.alice, session).add_trust_root(
                FleetTrustRootCreate(
                    public_key=(VECTORS / "keys/trust-root.key.pub").read_text()
                )
            )


async def test_withdrawing_a_bad_list_takes_two_people(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    _robot_uuid, sim = await enrolled(soc, robot_api)
    root = new_key()
    await _trust(soc, root)
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        good = await service.publish_revocation_list(
            FleetRevocationCreate(revocation_list=revocation_list(root, serial=2))
        )
        bad = await service.publish_revocation_list(
            FleetRevocationCreate(revocation_list=revocation_list(root, serial=900))
        )
        requested = await service.request_revocation_withdrawal(
            bad.id, FleetRevocationWithdraw(reason="published by mistake")
        )
        assert requested.withdrawal_requested_by == soc.alice.user_id
        with pytest.raises(AutoSecOpsAuthorizationError, match="second person"):
            await service.confirm_revocation_withdrawal(bad.id)
        with pytest.raises(AutoSecOpsAuthorizationError):
            await soc.fleet(soc.service, session).confirm_revocation_withdrawal(bad.id)
    path = "/robot-edr/v2/fleet/revocations/ugv-x1"
    assert json.loads((await signed_get(robot_api, sim, path)).content)["serial"] == 900
    async with get_async_session_bypass_rls_context_manager() as session:
        withdrawn = await soc.fleet(soc.bob, session).confirm_revocation_withdrawal(
            bad.id
        )
        assert withdrawn.withdrawn_at is not None
        # The floor is the newest list still published.
        again = await soc.fleet(soc.alice, session).publish_revocation_list(
            FleetRevocationCreate(revocation_list=revocation_list(root, serial=5))
        )
    assert again.serial == 5 and good.serial == 2
    assert json.loads((await signed_get(robot_api, sim, path)).content)["serial"] == 5


# --- F2: black-box keys come from enrollment only ---------------------------------


async def test_blackbox_keys_cannot_be_added_manually(soc: Soc) -> None:
    await add_robot(soc, "ugv-201")
    for role in (soc.alice, soc.service):
        async with get_async_session_bypass_rls_context_manager() as session:
            with pytest.raises(AutoSecOpsValidationError, match="enrollment"):
                await RobotsService(session, role=role).create_key(
                    RobotKeyCreate(
                        role=RobotKeyRole.BLACKBOX,
                        robot_id="ugv-201",
                        public_key=new_key().public_key.hex(),
                    )
                )


async def test_evidence_keyring_is_newest_first_and_keeps_the_current_key(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid = await add_robot(soc, "ugv-101")
    await setup_keys(soc)
    sims = [await enroll(soc, robot_api, robot_uuid) for _ in range(18)]
    # A black-box key that did not come from enrollment is never offered.
    async with get_async_session_bypass_rls_context_manager() as session:
        session.add(
            RobotKey(
                workspace_id=soc.workspace.id,
                key_id=new_key().key_id,
                role=RobotKeyRole.BLACKBOX.value,
                robot_fk=robot_uuid,
                public_key=new_key().public_key,
            )
        )
        await session.commit()
    async with get_async_session_bypass_rls_context_manager() as session:
        evidence = RobotEvidenceService(session, role=soc.service)
        # 18 keys are valid for an open range: refused, never truncated.
        with pytest.raises(AutoSecOpsValidationError, match="16"):
            await evidence.blackbox_key_files("ugv-101")
        # From now on only the current key signs records.
        current = await evidence.blackbox_key_files(
            "ugv-101", from_ms=fleet.now_ms() + 3_600_000
        )
    assert [wire.parse_key_file(k).key_id for k in current] == [
        sims[-1].blackbox.key_id
    ]

    # Spread the enrollments over days: key i signed during day i.
    base = datetime(2026, 1, 1, tzinfo=UTC)
    async with get_async_session_bypass_rls_context_manager() as session:
        for day, sim in enumerate(sims):
            key = await session.scalar(
                select(RobotKey).where(RobotKey.key_id == sim.blackbox.key_id)
            )
            assert key is not None
            key.created_at = base + timedelta(days=day)
            if key.revoked_at is not None:
                key.revoked_at = base + timedelta(days=day + 1)
        await session.commit()

    def ms(days: float) -> int:
        return int((base + timedelta(days=days)).timestamp() * 1000)

    async with get_async_session_bypass_rls_context_manager() as session:
        evidence = RobotEvidenceService(session, role=soc.service)
        window = await evidence.blackbox_key_files(
            "ugv-101", from_ms=ms(10.5), to_ms=ms(12.5)
        )
        first_day = await evidence.blackbox_key_files("ugv-101", to_ms=ms(0.5))
    # Newest first, the current key always included.
    assert [wire.parse_key_file(k).key_id for k in window] == [
        sims[17].blackbox.key_id,
        sims[12].blackbox.key_id,
        sims[11].blackbox.key_id,
        sims[10].blackbox.key_id,
    ]
    # The first enrolled key also covers records from before its enrollment.
    assert [wire.parse_key_file(k).key_id for k in first_day] == [
        sims[17].blackbox.key_id,
        sims[0].blackbox.key_id,
    ]


# --- F3: approval key separation and offline signing ------------------------------


async def test_approval_key_secrets_cannot_be_imported(soc: Soc) -> None:
    secret = wire.SigningKey.from_seed(secrets.token_bytes(32))
    secret_file = json.dumps(
        {
            "format": "robodr-blackbox-key/v2",
            "kind": "secret",
            "algorithm": "ed25519",
            "key_id": secret.key_id,
            "public_hex": secret.public_key.hex(),
            "secret_hex": secret.seed.hex(),
        }
    )
    async with get_async_session_bypass_rls_context_manager() as session:
        with pytest.raises(AutoSecOpsValidationError, match="never imported"):
            await soc.fleet(soc.alice, session).create_approval_key(
                FleetSocKeyCreate(
                    kind=FleetSocKeyKind.APPROVAL,
                    custody=FleetSocKeyCustody.ONLINE,
                    secret_key_file=secret_file,
                )
            )


async def test_approval_key_activation_takes_a_second_platform_user(soc: Soc) -> None:
    async with get_async_session_bypass_rls_context_manager() as session:
        alice = soc.fleet(soc.alice, session)
        created = await alice.create_approval_key(
            FleetSocKeyCreate(
                kind=FleetSocKeyKind.APPROVAL, custody=FleetSocKeyCustody.ONLINE
            )
        )
        # Even the first approval key waits for a second person.
        assert created.status == FleetSocKeyStatus.PENDING.value
        with pytest.raises(AutoSecOpsAuthorizationError, match="second person"):
            await alice.activate_approval_key(created)
        with pytest.raises(AutoSecOpsAuthorizationError):
            await soc.fleet(soc.service, session).activate_approval_key(created)
        active = await soc.fleet(soc.bob, session).activate_approval_key(created)
    assert active.status == FleetSocKeyStatus.ACTIVE.value
    assert active.activated_by == soc.bob.user_id


def _locked_profile(robot_id: str, version: int | None = None) -> tuple[str, str]:
    offer = wire.parse_offer((DISTRIBUTION / "offers-ugv-001.body").read_bytes())
    text = offer.profile.decode()
    text = text.replace('"unit_id": "ugv-001"', f'"unit_id": "{robot_id}"')
    if version is not None:
        text = text.replace('"profile_version": 4', f'"profile_version": {version}')
    seal_line = re.match(r'\{\n  "seal": "sha256:[0-9a-f]{64}",\n', text)
    assert seal_line is not None
    rest = text[seal_line.end() :]
    seal = hashlib.sha256(("{\n" + rest).encode()).hexdigest()
    return f'{{\n  "seal": "sha256:{seal}",\n{rest}', offer.sig.decode()


async def test_offline_approval_key_signs_a_prepared_approval(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid = await add_robot(soc, "ugv-101")
    held = new_key()  # Held by an operator; its secret never reaches the SOC.
    async with get_async_session_bypass_rls_context_manager() as session:
        alice = soc.fleet(soc.alice, session)
        await alice.create_fleet_key(FleetSocKeyCreate(kind=FleetSocKeyKind.FLEET))
        offline = await alice.create_approval_key(
            FleetSocKeyCreate(
                kind=FleetSocKeyKind.APPROVAL,
                custody=FleetSocKeyCustody.OFFLINE,
                public_key_file=wire.public_key_file(held.public_key),
            )
        )
        assert offline.encrypted_seed is None
        await soc.fleet(soc.bob, session).activate_approval_key(offline)
    sim = await enroll(soc, robot_api, robot_uuid)
    profile, sig = _locked_profile("ugv-101")
    async with get_async_session_bypass_rls_context_manager() as session:
        alice = soc.fleet(soc.alice, session)
        offered = await alice.set_offer(
            robot_uuid, FleetOfferUpdate(profile=profile, signature=sig)
        )
        pending = await alice.request_approval(
            robot_uuid, FleetApprovalCreate(profile_digest=offered.digest)
        )
        prepared = await soc.fleet(soc.bob, session).approve(robot_uuid, pending.id)
    assert prepared.status is FleetApprovalStatus.PREPARED
    assert prepared.signer_key_id == held.key_id
    assert prepared.signing_payload is not None
    assert prepared.signing_message_hex is not None
    payload = wire.b64_decode(prepared.signing_payload)
    assert payload is not None
    message = bytes.fromhex(prepared.signing_message_hex)
    assert message == wire.sig_message(wire.T_APPROVAL, held.key_id, payload)

    path = f"/robot-edr/v2/fleet/profiles/approvals/{offered.digest[7:]}"
    assert (await signed_get(robot_api, sim, path)).status_code == 404
    async with get_async_session_bypass_rls_context_manager() as session:
        alice = soc.fleet(soc.alice, session)
        with pytest.raises(AutoSecOpsValidationError, match="does not verify"):
            await alice.submit_approval_signature(
                robot_uuid,
                pending.id,
                FleetApprovalSignature(signature=new_key().sign(message).hex()),
            )
        signed = await alice.submit_approval_signature(
            robot_uuid,
            pending.id,
            FleetApprovalSignature(signature=held.sign(message).hex()),
        )
    assert signed.status is FleetApprovalStatus.SIGNED
    served = await signed_get(robot_api, sim, path)
    assert served.status_code == 200
    opened = wire.parse_envelope(served.content, wire.T_APPROVAL)
    assert opened.signers == [held.key_id]
    assert opened.verify_by(held.key_id, held.public_key)
    assert opened.payload == payload


# --- F4: SOC-wide key uniqueness on every registration path -----------------------


async def test_manual_keys_are_unique_across_the_soc(
    soc: Soc, other_soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    _robot_uuid, sim = await enrolled(soc, robot_api)
    await add_robot(other_soc, "ugv-301")
    async with get_async_session_bypass_rls_context_manager() as session:
        fleet_key = next(
            k
            for k in await soc.fleet(soc.alice, session).list_soc_keys()
            if k.kind is FleetSocKeyKind.FLEET
        )
    fleet_public = wire.parse_key_file(fleet_key.public_key_file).public_key
    for public in (sim.finding.public_key, fleet_public):
        async with get_async_session_bypass_rls_context_manager() as session:
            with pytest.raises(RobotConflictError):
                await RobotsService(session, role=other_soc.alice).create_key(
                    RobotKeyCreate(
                        role=RobotKeyRole.FINDING,
                        robot_id="ugv-301",
                        public_key=public.hex(),
                    )
                )
    # A deleted key keeps its id: it is never registered again.
    reused = new_key()
    async with get_async_session_bypass_rls_context_manager() as session:
        robots = RobotsService(session, role=other_soc.alice)
        created = await robots.create_key(
            RobotKeyCreate(
                role=RobotKeyRole.FINDING,
                robot_id="ugv-301",
                public_key=reused.public_key.hex(),
            )
        )
        await robots.delete_key(created)
    async with get_async_session_bypass_rls_context_manager() as session:
        with pytest.raises(RobotConflictError):
            await soc.fleet(soc.alice, session).create_fleet_key(
                FleetSocKeyCreate(
                    kind=FleetSocKeyKind.FLEET,
                    secret_key_file=json.dumps(
                        {
                            "format": "robodr-blackbox-key/v2",
                            "kind": "secret",
                            "algorithm": "ed25519",
                            "key_id": reused.key_id,
                            "public_hex": reused.public_key.hex(),
                            "secret_hex": reused.seed.hex(),
                        }
                    ),
                )
            )


# --- F5: rotation ids are per robot ------------------------------------------------


async def test_a_cancel_by_one_robot_cannot_block_another_robots_rotation(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_a = await add_robot(soc, "ugv-101")
    robot_b = await add_robot(soc, "ugv-102")
    await setup_keys(soc)
    sim_a = await enroll(soc, robot_api, robot_a, "ugv-101")
    sim_b = await enroll(soc, robot_api, robot_b, "ugv-102")
    rotation_id = f"rfr1-{secrets.token_hex(16)}"
    cancel = await signed_post(
        robot_api,
        sim_a,
        "/robot-edr/v2/fleet/keys/cancel",
        sim_a.cancel_body(rotation_id, new_key().key_id, "sha256:" + "a" * 64),
    )
    assert cancel.status_code == 200, cancel.text
    rotate = await signed_post(
        robot_api,
        sim_b,
        "/robot-edr/v2/fleet/keys/rotate",
        sim_b.rotate_body(rotation_id, new_key()),
    )
    assert rotate.status_code == 200, rotate.text
    # Robot A's own late rotate request with that id is still refused.
    late = await signed_post(
        robot_api,
        sim_a,
        "/robot-edr/v2/fleet/keys/rotate",
        sim_a.rotate_body(rotation_id, new_key()),
    )
    assert late.status_code == 409 and late.json()["code"] == "rotation_cancelled"


# --- F6: 64-bit values the database cannot hold are client errors -----------------


async def test_values_above_int64_are_refused_not_500(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid, _sim = await enrolled(soc, robot_api)
    root = new_key()
    await _trust(soc, root)
    profile, sig = _locked_profile("ugv-101", version=MAX_STORED_INT + 1)
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        with pytest.raises(AutoSecOpsValidationError, match="2\\^63"):
            await service.publish_revocation_list(
                FleetRevocationCreate(
                    revocation_list=revocation_list(root, serial=2**64 - 1)
                )
            )
        with pytest.raises(AutoSecOpsValidationError, match="2\\^63"):
            await service.set_offer(
                robot_uuid, FleetOfferUpdate(profile=profile, signature=sig)
            )
        top = await service.publish_revocation_list(
            FleetRevocationCreate(
                revocation_list=revocation_list(root, serial=MAX_STORED_INT)
            )
        )
    assert top.serial == MAX_STORED_INT


# --- F7: the replay cache really uses Redis; a fallback is loud --------------------


async def test_replay_cache_writes_to_redis() -> None:
    signature = secrets.token_hex(64)
    key_id = "ed25519:00000000000000aa"
    fallbacks = fleet_replay.fallback_count()
    assert await fleet_replay.seen_before(key_id, signature) is False
    client = await (await get_redis_client())._get_client()
    ttl = await client.ttl(f"robot_edr:fleet_replay:{key_id}:{signature}")
    assert 0 < ttl <= fleet_replay.WINDOW_SECONDS
    assert fleet_replay.fallback_count() == fallbacks
    # Another process (replica) sees the entry: the local cache is not used.
    await fleet_replay.clear_local()
    assert await fleet_replay.seen_before(key_id, signature) is True


async def test_replay_cache_fallback_is_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _down() -> Any:
        raise ConnectionError("redis down")

    monkeypatch.setattr(fleet_replay, "get_redis_client", _down)
    before = fleet_replay.fallback_count()
    signature = secrets.token_hex(64)
    assert (
        await fleet_replay.seen_before("ed25519:00000000000000bb", signature) is False
    )
    assert await fleet_replay.seen_before("ed25519:00000000000000bb", signature) is True
    assert fleet_replay.fallback_count() == before + 2


# --- F8: no body is buffered for an unknown key; 401 audits are aggregated ---------


async def test_unknown_key_is_refused_before_the_body_is_read(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    stranger = new_key()
    path = "/robot-edr/v2/fleet/profiles/drafts"
    body = b"{" + b" " * (wire.MAX_DRAFT_BYTES + 16) + b"}"
    headers = {
        "X-RoboDR-Key-Id": stranger.key_id,
        "X-RoboDR-Timestamp": str(fleet.now_ms()),
        "X-RoboDR-Signature": "0" * 128,
        "Content-Type": "application/json",
    }
    response = await robot_api.post(path, content=body, headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == "unknown_key"


async def test_401_audit_events_are_aggregated(
    soc: Soc, robot_api: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[dict[str, Any]] = []

    async def _capture(**kwargs: Any) -> None:
        events.append(kwargs)

    monkeypatch.setattr(fleet, "_audit", _capture)
    # Count every refusal in one fresh minute: a real minute boundary mid-loop
    # restarts the counters, and earlier tests share the source address.
    minute_s = (30_000_000 + secrets.randbelow(1_000_000)) * 60.0
    monkeypatch.setattr(fleet_throttle, "time", SimpleNamespace(time=lambda: minute_s))
    stranger = new_key()
    for _ in range(40):
        response = await robot_api.get(
            "/robot-edr/v2/fleet/ring",
            headers={
                "X-RoboDR-Key-Id": stranger.key_id,
                "X-RoboDR-Timestamp": str(fleet.now_ms()),
                "X-RoboDR-Signature": "0" * 128,
            },
        )
        assert response.status_code == 401
    assert [e["data"]["failures_this_minute"] for e in events] == [1, 10]
    assert events[-1]["data"]["presented_key_id"] == stranger.key_id


async def test_drafts_per_robot_are_capped(
    soc: Soc, robot_api: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "AUTOSECOPS__ROBOT_EDR_FLEET_MAX_DRAFTS", 3)
    robot_uuid, sim = await enrolled(soc, robot_api)
    draft = json.loads((VECTORS / "cases/13-distribution/8.body").read_text())
    digests: list[str] = []
    path = "/robot-edr/v2/fleet/profiles/drafts"
    for n in range(5):
        draft["model"] = f"ugv-test-{n}"
        body = json.dumps(draft, indent=2).encode()
        response = await signed_post(robot_api, sim, path, body)
        assert response.status_code == 200, response.text
        digests.append(response.json()["digest"])
    async with get_async_session_bypass_rls_context_manager() as session:
        kept = (
            await session.scalars(
                select(RobotFleetProfileDraft.digest).where(
                    RobotFleetProfileDraft.robot_fk == robot_uuid
                )
            )
        ).all()
    assert sorted(kept) == sorted(digests[-3:])


# --- F10: ring floor, test-key deny-list, refusal auditing --------------------------


async def test_ring_min_version_never_drops(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid, _sim = await enrolled(soc, robot_api)
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        await service.set_ring(
            robot_uuid, FleetRingUpdate(ring=0, min_version="0.10.0")
        )
        for lower in ("0.9.9", "0.10.0~rc1", None):
            with pytest.raises(AutoSecOpsValidationError, match="min_version"):
                await service.set_ring(
                    robot_uuid, FleetRingUpdate(ring=1, min_version=lower)
                )
        same = await service.set_ring(
            robot_uuid, FleetRingUpdate(ring=1, min_version="0.10.0")
        )
        higher = await service.set_ring(
            robot_uuid, FleetRingUpdate(ring=2, min_version="0.10.0+1")
        )
    assert (same.serial, higher.serial) == (2, 3)


async def test_contract_test_keys_are_never_real_soc_keys(soc: Soc) -> None:
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        with pytest.raises(AutoSecOpsValidationError, match="test key"):
            await service.create_fleet_key(
                FleetSocKeyCreate(
                    kind=FleetSocKeyKind.FLEET,
                    secret_key_file=(VECTORS / "keys/soc.key").read_text(),
                )
            )
        with pytest.raises(AutoSecOpsValidationError, match="test key"):
            await service.create_approval_key(
                FleetSocKeyCreate(
                    kind=FleetSocKeyKind.APPROVAL,
                    custody=FleetSocKeyCustody.OFFLINE,
                    public_key_file=(VECTORS / "keys/soc-approval.key.pub").read_text(),
                )
            )
        count = await session.scalar(
            select(func.count())
            .select_from(RobotFleetSocKey)
            .where(RobotFleetSocKey.workspace_id == soc.workspace.id)
        )
    assert count == 0


async def test_enrollment_replays_and_refusals_are_audited(
    soc: Soc, robot_api: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[dict[str, Any]] = []

    async def _capture(**kwargs: Any) -> None:
        events.append(kwargs)

    robot_uuid = await add_robot(soc, "ugv-101")
    await setup_keys(soc)
    token = await issue(soc, robot_uuid)
    monkeypatch.setattr(fleet, "_audit", _capture)
    sim = SimRobot.new("ugv-101", "lab-9")
    body = sim.enroll_body(token)
    for _ in range(2):  # The answer, then the stored answer for a lost one.
        response = await robot_api.post(
            "/robot-edr/v2/fleet/enroll",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
    other = await robot_api.post(
        "/robot-edr/v2/fleet/enroll",
        content=sim.enroll_body(token),
        headers={"Content-Type": "application/json"},
    )
    assert other.status_code == 409
    operations = [(e["status"], e["data"].get("operation")) for e in events]
    assert (AuditEventStatus.SUCCESS, "enroll") in operations
    assert (AuditEventStatus.SUCCESS, "enroll_replay") in operations
    refused = [e for e in events if e["data"].get("refusal_code") == "token_used"]
    assert len(refused) == 1 and refused[0]["status"] is AuditEventStatus.FAILURE


async def test_soc_key_rows_without_a_seed_are_offline_only(soc: Soc) -> None:
    async with get_async_session_bypass_rls_context_manager() as session:
        with pytest.raises(AutoSecOpsValidationError, match="public_key_file"):
            await soc.fleet(soc.alice, session).create_approval_key(
                FleetSocKeyCreate(
                    kind=FleetSocKeyKind.APPROVAL, custody=FleetSocKeyCustody.OFFLINE
                )
            )
        with pytest.raises(AutoSecOpsValidationError, match="online"):
            await soc.fleet(soc.alice, session).create_fleet_key(
                FleetSocKeyCreate(
                    kind=FleetSocKeyKind.FLEET,
                    custody=FleetSocKeyCustody.OFFLINE,
                    public_key_file=wire.public_key_file(new_key().public_key),
                )
            )
