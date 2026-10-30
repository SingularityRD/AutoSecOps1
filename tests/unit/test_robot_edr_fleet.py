"""End-to-end tests of the `robodr.fleet` SOC side beyond the contract vectors.

The operator side runs through :class:`RobotFleetService` (SOC keys, tokens,
offers, two-person approvals, rings, revocation lists); a simulated robot
talks to the public fleet routes exactly as `robodr-enroll` does.
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from autosecops.db.engine import get_async_session_bypass_rls_context_manager
from autosecops.db.models import Robot, RobotKey
from autosecops.exceptions import (
    AutoSecOpsAuthorizationError,
    AutoSecOpsValidationError,
)
from autosecops.pagination import PageParams
from autosecops.robot_edr import fleet_wire as wire
from autosecops.robot_edr.evidence import RobotEvidenceService
from autosecops.robot_edr.schemas import (
    FleetApprovalCreate,
    FleetOfferUpdate,
    FleetRevocationCreate,
    FleetRingUpdate,
    FleetSocKeyCreate,
    FleetTokenCreate,
    FleetTrustRootCreate,
)
from autosecops.robot_edr.service import RobotConflictError
from autosecops.robot_edr.types import (
    FleetApprovalStatus,
    FleetSocKeyKind,
    FleetSocKeyStatus,
)
from tests.support.robot_fleet import (
    DISTRIBUTION,
    SimRobot,
    Soc,
    enrolled,
    issue,
    new_key,
    revocation_list,
    robot_api,
    robot_edr_entitled,
    setup_keys_and_robot,
    soc,
)

pytestmark = [pytest.mark.usefixtures("db"), pytest.mark.anyio]

__all__ = ["robot_api", "robot_edr_entitled", "soc"]

# --- tests ------------------------------------------------------------------------


async def test_issue_token_and_enroll_registers_three_roles(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid = await setup_keys_and_robot(soc)
    token = await issue(soc, robot_uuid)
    async with get_async_session_bypass_rls_context_manager() as session:
        keys = await soc.fleet(soc.alice, session).list_soc_keys()
    fleet_key = next(k for k in keys if k.kind is FleetSocKeyKind.FLEET)
    assert token.verify(
        bytes.fromhex(json.loads(fleet_key.public_key_file)["public_hex"])
    )
    assert token.payload.site == "lab-9"
    assert token.payload.expires_at_ms - token.payload.issued_at_ms == 24 * 3_600_000

    sim = SimRobot.new("ugv-101", "lab-9")
    body = sim.enroll_body(token)
    response = await robot_api.post(
        "/robot-edr/v2/fleet/enroll",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200, response.text
    answer = wire.parse_envelope(response.content, wire.T_ENROLL_ANSWER)
    assert answer.signers == [fleet_key.key_id]
    assert answer.verify_by(
        fleet_key.key_id,
        bytes.fromhex(json.loads(fleet_key.public_key_file)["public_hex"]),
    )
    payload = json.loads(answer.payload)
    assert [k["role"] for k in payload["keys"]] == ["uplink", "finding", "blackbox"]

    # A lost answer: the same bytes get the same answer; other bytes are refused.
    again = await robot_api.post(
        "/robot-edr/v2/fleet/enroll",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert again.content == response.content
    other = await robot_api.post(
        "/robot-edr/v2/fleet/enroll",
        content=sim.enroll_body(token),
        headers={"Content-Type": "application/json"},
    )
    assert other.status_code == 409 and other.json()["code"] == "token_used"

    async with get_async_session_bypass_rls_context_manager() as session:
        roles = (
            (
                await session.execute(
                    select(RobotKey.role, RobotKey.key_id).where(
                        RobotKey.robot_fk == robot_uuid
                    )
                )
            )
            .tuples()
            .all()
        )
        status = await soc.fleet(soc.alice, session).get_status(robot_uuid)
        evidence_keys = await RobotEvidenceService(
            session, role=soc.service
        ).blackbox_key_files("ugv-101")
    assert dict(roles) == {
        "uplink": sim.uplink.key_id,
        "finding": sim.finding.key_id,
        "blackbox": sim.blackbox.key_id,
    }
    assert status.enrolled and status.agentd_version == "0.2.0"
    assert status.tokens[0].status == "consumed"
    assert [wire.parse_key_file(k).key_id for k in evidence_keys] == [
        sim.blackbox.key_id
    ]

    # The black-box and finding keys authenticate no fleet request.
    for key in (sim.blackbox, sim.finding):
        denied = await robot_api.get(
            "/robot-edr/v2/fleet/ring",
            headers=sim.auth_headers("GET", "/robot-edr/v2/fleet/ring", key=key),
        )
        assert denied.status_code == 401 and denied.json()["code"] == "unknown_key"
    ring = await robot_api.get(
        "/robot-edr/v2/fleet/ring",
        headers=sim.auth_headers("GET", "/robot-edr/v2/fleet/ring"),
    )
    assert ring.status_code == 404 and ring.json()["code"] == "no_ring"


async def test_revoked_token_answers_bad_token(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid = await setup_keys_and_robot(soc)
    token = await issue(soc, robot_uuid)
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        status = await service.get_status(robot_uuid)
        revoked = await service.revoke_token(robot_uuid, status.tokens[0].id)
    assert revoked.status == "revoked"
    response = await robot_api.post(
        "/robot-edr/v2/fleet/enroll",
        content=SimRobot.new("ugv-101", "lab-9").enroll_body(token),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401 and response.json()["code"] == "bad_token"


async def test_token_validity_is_at_most_seven_days(soc: Soc) -> None:
    with pytest.raises(ValidationError):
        FleetTokenCreate(validity_hours=169)
    robot_uuid = await setup_keys_and_robot(soc)
    token = await issue(soc, robot_uuid, hours=168)
    assert (
        token.payload.expires_at_ms - token.payload.issued_at_ms == 7 * 24 * 3_600_000
    )


async def test_token_needs_a_fleet_key(soc: Soc) -> None:
    async with get_async_session_bypass_rls_context_manager() as session:
        robot = Robot(workspace_id=soc.workspace.id, robot_id="ugv-102")
        session.add(robot)
        await session.commit()
        with pytest.raises(AutoSecOpsValidationError, match="fleet key"):
            await soc.fleet(soc.alice, session).issue_token(
                robot.id, FleetTokenCreate()
            )


def _secret_file(key: wire.SigningKey) -> str:
    return json.dumps(
        {
            "format": "robodr-blackbox-key/v2",
            "kind": "secret",
            "algorithm": "ed25519",
            "key_id": key.key_id,
            "public_hex": key.public_key.hex(),
            "secret_hex": key.seed.hex(),
        }
    )


async def test_soc_key_rotation_keeps_one_active_key(soc: Soc) -> None:
    imported = new_key()
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        first = await service.create_fleet_key(
            FleetSocKeyCreate(kind=FleetSocKeyKind.FLEET)
        )
        second = await service.create_fleet_key(
            FleetSocKeyCreate(
                kind=FleetSocKeyKind.FLEET, secret_key_file=_secret_file(imported)
            )
        )
        assert (first.status, second.status) == ("active", "pending")
        assert second.key_id == imported.key_id
        first_id, second_id = first.key_id, second.key_id
        await service.activate_fleet_key(second)
        keys = {k.key_id: k.status for k in await service.list_soc_keys()}
        with pytest.raises(AutoSecOpsAuthorizationError):
            await service.activate_approval_key(second)
        # A key is registered once on the whole SOC.
        with pytest.raises(RobotConflictError):
            await service.create_fleet_key(
                FleetSocKeyCreate(
                    kind=FleetSocKeyKind.FLEET, secret_key_file=_secret_file(imported)
                )
            )
    assert keys == {
        first_id: FleetSocKeyStatus.RETIRED,
        second_id: FleetSocKeyStatus.ACTIVE,
    }


async def test_approval_needs_two_distinct_platform_users(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid, sim = await enrolled(soc, robot_api)
    offer = wire.parse_offer((DISTRIBUTION / "offers-ugv-001.body").read_bytes())
    profile = offer.profile.decode()
    async with get_async_session_bypass_rls_context_manager() as session:
        # The vector profile is locked for unit ugv-001, not this robot.
        with pytest.raises(AutoSecOpsValidationError, match="unit"):
            await soc.fleet(soc.alice, session).set_offer(
                robot_uuid,
                FleetOfferUpdate(profile=profile, signature=offer.sig.decode()),
            )
        robot = await session.scalar(select(Robot).where(Robot.id == robot_uuid))
        assert robot is not None
        robot.robot_id = "ugv-001"
        await session.commit()
    sim.robot_id = "ugv-001"
    async with get_async_session_bypass_rls_context_manager() as session:
        alice = soc.fleet(soc.alice, session)
        offered = await alice.set_offer(
            robot_uuid, FleetOfferUpdate(profile=profile, signature=offer.sig.decode())
        )
        assert (offered.digest, offered.profile_version, offered.platform) == (
            offer.digest,
            4,
            "ugv-x1",
        )
        with pytest.raises(AutoSecOpsValidationError, match="currently offered"):
            await alice.request_approval(
                robot_uuid, FleetApprovalCreate(profile_digest="sha256:" + "0" * 64)
            )
        with pytest.raises(AutoSecOpsAuthorizationError):
            await soc.fleet(soc.service, session).request_approval(
                robot_uuid, FleetApprovalCreate(profile_digest=offer.digest)
            )
        pending = await alice.request_approval(
            robot_uuid,
            FleetApprovalCreate(profile_digest=offer.digest, validity_hours=2),
        )
        assert pending.status is FleetApprovalStatus.PENDING
        with pytest.raises(AutoSecOpsAuthorizationError, match="second person"):
            await alice.approve(robot_uuid, pending.id)
    path = (
        f"/robot-edr/v2/fleet/profiles/approvals/{offer.digest.removeprefix('sha256:')}"
    )
    nothing = await robot_api.get(path, headers=sim.auth_headers("GET", path))
    assert nothing.status_code == 404 and nothing.json()["code"] == "no_approval"

    async with get_async_session_bypass_rls_context_manager() as session:
        signed = await soc.fleet(soc.bob, session).approve(robot_uuid, pending.id)
        with pytest.raises(AutoSecOpsValidationError, match="pending"):
            await soc.fleet(soc.bob, session).approve(robot_uuid, pending.id)
        keys = await soc.fleet(soc.alice, session).list_soc_keys()
    assert signed.status is FleetApprovalStatus.SIGNED
    approval_key = next(k for k in keys if k.kind is FleetSocKeyKind.APPROVAL)
    fleet_key = next(k for k in keys if k.kind is FleetSocKeyKind.FLEET)
    assert signed.signer_key_id == approval_key.key_id != fleet_key.key_id

    served = await robot_api.get(path, headers=sim.auth_headers("GET", path))
    assert served.status_code == 200
    opened = wire.parse_envelope(served.content, wire.T_APPROVAL)
    assert opened.signers == [approval_key.key_id]
    approval = wire.parse_approval(opened.payload)
    assert approval.robot_id == "ugv-001"
    assert approval.profile_digest == offer.digest
    assert approval.profile_version == 4 and approval.platform == "ugv-x1"
    assert approval.approved_by == (
        f"user:{soc.alice.user_id}",
        f"user:{soc.bob.user_id}",
    )
    assert approval.expires_at_ms - approval.issued_at_ms == 2 * 3_600_000

    current = await robot_api.get(
        "/robot-edr/v2/fleet/profiles/current",
        headers=sim.auth_headers("GET", "/robot-edr/v2/fleet/profiles/current"),
    )
    assert current.content == wire.offer_body(offer.profile, offer.sig, 4)

    async with get_async_session_bypass_rls_context_manager() as session:
        await soc.fleet(soc.alice, session).cancel_approval(robot_uuid, pending.id)
    gone = await robot_api.get(path, headers=sim.auth_headers("GET", path))
    assert gone.status_code == 404


async def test_ring_serial_rises_and_is_fleet_signed(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    robot_uuid, sim = await enrolled(soc, robot_api)
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        await service.set_ring(robot_uuid, FleetRingUpdate(ring=0))
        second = await service.set_ring(
            robot_uuid,
            FleetRingUpdate(
                ring=1,
                target_version="0.3.0",
                bundle_sha256="ab" * 32,
                min_version="0.2.0",
            ),
        )
        fleet_key = next(
            k for k in await service.list_soc_keys() if k.kind is FleetSocKeyKind.FLEET
        )
    assert second.serial == 2
    response = await robot_api.get(
        "/robot-edr/v2/fleet/ring",
        headers=sim.auth_headers("GET", "/robot-edr/v2/fleet/ring"),
    )
    opened = wire.parse_envelope(response.content, wire.T_RING)
    assert opened.signers == [fleet_key.key_id]
    ring = wire.parse_ring(opened.payload)
    assert (ring.serial, ring.ring, ring.min_version) == (2, 1, "0.2.0")
    assert ring.workspace == str(soc.workspace.id)


async def test_replayed_request_headers_are_refused(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    _robot_uuid, sim = await enrolled(soc, robot_api)
    headers = sim.auth_headers("GET", "/robot-edr/v2/fleet/ring")
    first = await robot_api.get("/robot-edr/v2/fleet/ring", headers=headers)
    replay = await robot_api.get("/robot-edr/v2/fleet/ring", headers=headers)
    assert first.json()["code"] == "no_ring"
    assert replay.status_code == 401 and replay.json()["code"] == "replayed_request"


async def test_revocation_lists_are_monotonic(
    soc: Soc, robot_api: httpx.AsyncClient
) -> None:
    _robot_uuid, sim = await enrolled(soc, robot_api)
    root, other_root = new_key(), new_key()
    body = revocation_list(root, serial=2)
    async with get_async_session_bypass_rls_context_manager() as session:
        service = soc.fleet(soc.alice, session)
        await service.add_trust_root(
            FleetTrustRootCreate(public_key=root.public_key.hex(), label="oem root")
        )
        with pytest.raises(AutoSecOpsValidationError, match="does not verify"):
            await service.publish_revocation_list(
                FleetRevocationCreate(revocation_list=revocation_list(other_root))
            )
        published = await service.publish_revocation_list(
            FleetRevocationCreate(revocation_list=body)
        )
        assert published.serial == 2 and published.signature_checked
        assert published.trust_root_key_id == root.key_id
        # The same list again is idempotent; a lower serial or another list
        # with the same serial is refused.
        again = await service.publish_revocation_list(
            FleetRevocationCreate(revocation_list=body)
        )
        assert again.id == published.id
        with pytest.raises(AutoSecOpsValidationError, match="lower"):
            await service.publish_revocation_list(
                FleetRevocationCreate(revocation_list=revocation_list(root, serial=1))
            )
        with pytest.raises(RobotConflictError):
            await service.publish_revocation_list(
                FleetRevocationCreate(
                    revocation_list=revocation_list(
                        root, serial=2, digests=["sha256:" + "1" * 64]
                    )
                )
            )
        page = await service.list_revocation_lists(PageParams(limit=10, cursor=None))
    assert [r.serial for r in page.items] == [2]
    path = "/robot-edr/v2/fleet/revocations/ugv-x1"
    served = await robot_api.get(path, headers=sim.auth_headers("GET", path))
    assert served.content == body.encode()
