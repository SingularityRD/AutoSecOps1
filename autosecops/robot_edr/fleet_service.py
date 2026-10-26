"""Workspace management of the `robodr.fleet` lifecycle (operator side).

SOC keys (§2.7), enrollment tokens (§3.1), the profile offer (§6.2), the
two-person approval of the observe -> enforce transition (§6.3), update-ring
information (§7) and revocation lists (§4.1). The robot-facing endpoints that
consume these live in :mod:`autosecops.robot_edr.fleet`.

An approval is signed by the workspace's approval key only after two
distinct platform users signed it off: the requester and one approver, both
holding ``robot:approve``. Nothing signs an approval automatically, and a
service account cannot request or approve one.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from autosecops.audit.logger import audit_log
from autosecops.authz.controls import require_scope
from autosecops.db.models import (
    Robot,
    RobotFleetApproval,
    RobotFleetProfileDraft,
    RobotFleetProfileOffer,
    RobotFleetRevocationList,
    RobotFleetRing,
    RobotFleetRotation,
    RobotFleetSocKey,
    RobotFleetToken,
)
from autosecops.exceptions import (
    TracecatAuthorizationError,
    TracecatNotFoundError,
    TracecatValidationError,
)
from autosecops.pagination import Page, PageParams, paginate
from autosecops.robot_edr import fleet_wire as wire
from autosecops.robot_edr.fleet import now_ms
from autosecops.robot_edr.fleet_keys import (
    active_signing_key,
    active_soc_key,
    encrypt_secret,
)
from autosecops.robot_edr.fleet_profiles import (
    ProfileFileError,
    check_locked_profile,
    parse_revocation_list,
)
from autosecops.robot_edr.schemas import (
    FleetApprovalCreate,
    FleetApprovalRead,
    FleetDraftContent,
    FleetDraftRead,
    FleetOfferRead,
    FleetOfferUpdate,
    FleetRevocationCreate,
    FleetRevocationRead,
    FleetRingRead,
    FleetRingUpdate,
    FleetRotationRead,
    FleetSocKeyCreate,
    FleetSocKeyRead,
    FleetTokenCreate,
    FleetTokenIssued,
    FleetTokenRead,
    RobotFleetStatus,
)
from autosecops.robot_edr.service import RobotConflictError
from autosecops.robot_edr.types import (
    FleetApprovalStatus,
    FleetRotationStatus,
    FleetSocKeyKind,
    FleetSocKeyStatus,
    RobotKeyRole,
)
from autosecops.service import BaseWorkspaceService
from autosecops.tiers.enums import Entitlement

_STATUS_LIMIT = 20
_HOUR_MS = 3_600_000


def _dt(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


type _TokenStatus = Literal["active", "consumed", "expired", "revoked"]


def _token_status(token: RobotFleetToken, at_ms: int) -> _TokenStatus:
    if token.consumed_at is not None:
        return "consumed"
    if token.revoked_at is not None:
        return "revoked"
    if at_ms > token.expires_at_ms:
        return "expired"
    return "active"


def token_read(token: RobotFleetToken, at_ms: int) -> FleetTokenRead:
    """Serialize a token row (never the token or its nonce)."""
    return FleetTokenRead(
        id=token.id,
        token_id=token.token_id,
        robot_id=token.robot_id,
        site=token.site,
        workspace=token.fleet_workspace,
        soc_key_id=token.soc_key_id,
        issued_at=_dt(token.issued_at_ms),
        expires_at=_dt(token.expires_at_ms),
        consumed_at=token.consumed_at,
        revoked_at=token.revoked_at,
        status=_token_status(token, at_ms),
    )


def soc_key_read(row: RobotFleetSocKey) -> FleetSocKeyRead:
    """Serialize a SOC key row (public material only)."""
    return FleetSocKeyRead(
        id=row.id,
        kind=FleetSocKeyKind(row.kind),
        key_id=row.key_id,
        fingerprint=wire.fingerprint(row.public_key),
        status=FleetSocKeyStatus(row.status),
        public_key_file=wire.public_key_file(row.public_key),
        created_at=row.created_at,
        activated_at=row.activated_at,
        retired_at=row.retired_at,
    )


def approval_read(row: RobotFleetApproval) -> FleetApprovalRead:
    """Serialize an approval row."""
    return FleetApprovalRead(
        id=row.id,
        approval_id=row.approval_id,
        profile_digest=row.profile_digest,
        profile_version=row.profile_version,
        platform=row.platform,
        status=FleetApprovalStatus(row.status),
        requested_by=row.requested_by,
        approved_by=row.approved_by,
        validity_hours=row.validity_ms // _HOUR_MS,
        issued_at=_dt(row.issued_at_ms) if row.issued_at_ms is not None else None,
        expires_at=_dt(row.expires_at_ms) if row.expires_at_ms is not None else None,
        signer_key_id=row.signer_key_id,
        created_at=row.created_at,
    )


def _ring_read(row: RobotFleetRing) -> FleetRingRead:
    return FleetRingRead(
        serial=row.serial,
        ring=row.ring,
        target_version=row.target_version,
        bundle_sha256=row.bundle_sha256,
        min_version=row.min_version,
        issued_at=_dt(row.issued_at_ms),
        expires_at=_dt(row.expires_at_ms),
    )


def _revocation_read(row: RobotFleetRevocationList) -> FleetRevocationRead:
    return FleetRevocationRead(
        id=row.id,
        platform=row.platform,
        serial=row.serial,
        list_digest=row.list_digest,
        signer_key_id=row.signer_key_id,
        signature_checked=row.signature_checked,
        created_at=row.created_at,
    )


def _parse_public_key(text: str) -> bytes:
    stripped = text.strip()
    if wire.is_lower_hex(stripped, 64):
        return bytes.fromhex(stripped)
    try:
        return wire.parse_key_file(stripped).public_key
    except wire.WireError as exc:
        raise TracecatValidationError(
            "trust_root_public_key must be a robodr-blackbox-key/v2 file or 64 hex"
        ) from exc


class RobotFleetService(BaseWorkspaceService):
    """Manage SOC keys, tokens, offers, approvals, rings and revocation lists."""

    service_name = "robot_edr_fleet"

    # --- SOC keys (§2.7) -----------------------------------------------------------

    @require_scope("robot:read")
    async def list_soc_keys(self) -> list[FleetSocKeyRead]:
        """The workspace's SOC keys (at most a few per kind)."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        rows = await self.session.scalars(
            select(RobotFleetSocKey)
            .where(RobotFleetSocKey.workspace_id == self.workspace_id)
            .order_by(RobotFleetSocKey.created_at.desc(), RobotFleetSocKey.id)
        )
        return [soc_key_read(row) for row in rows]

    @require_scope("robot:enroll")
    @audit_log(resource_type="robot_fleet", action="create")
    async def create_fleet_key(self, params: FleetSocKeyCreate) -> RobotFleetSocKey:
        """Generate or import the fleet key (tokens, answers, ring information)."""
        return await self._create_soc_key(FleetSocKeyKind.FLEET, params)

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="create")
    async def create_approval_key(self, params: FleetSocKeyCreate) -> RobotFleetSocKey:
        """Generate or import the approval key (profile approvals only)."""
        return await self._create_soc_key(FleetSocKeyKind.APPROVAL, params)

    async def _create_soc_key(
        self, kind: FleetSocKeyKind, params: FleetSocKeyCreate
    ) -> RobotFleetSocKey:
        """The first key of a kind becomes active; later ones wait (§2.7 rotation).

        Raises:
            TracecatValidationError: The imported file is not a secret key file.
            RobotConflictError: The key is already registered on this SOC.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        if params.secret_key_file is not None:
            try:
                key_file = wire.parse_key_file(params.secret_key_file)
            except wire.WireError as exc:
                raise TracecatValidationError(f"secret_key_file: {exc}") from exc
            if key_file.seed is None:
                raise TracecatValidationError("secret_key_file is a public key file")
            key = wire.SigningKey.from_seed(key_file.seed)
        else:
            key = wire.SigningKey.from_seed(secrets.token_bytes(32))
        current = await active_soc_key(self.session, self.workspace_id, kind)
        now = datetime.now(UTC)
        row = RobotFleetSocKey(
            workspace_id=self.workspace_id,
            kind=kind.value,
            key_id=key.key_id,
            public_key=key.public_key,
            encrypted_seed=encrypt_secret(key.seed),
            status=(
                FleetSocKeyStatus.PENDING.value
                if current is not None
                else FleetSocKeyStatus.ACTIVE.value
            ),
            activated_at=None if current is not None else now,
            created_by=self.role.user_id,
        )
        self.session.add(row)
        await self._commit_or_conflict("This key is already registered on this SOC")
        await self.session.refresh(row)
        return row

    async def get_soc_key(self, key_uuid: uuid.UUID) -> RobotFleetSocKey:
        """A SOC key of this workspace.

        Raises:
            TracecatNotFoundError: No such key here.
        """
        row = await self.session.scalar(
            select(RobotFleetSocKey).where(
                RobotFleetSocKey.workspace_id == self.workspace_id,
                RobotFleetSocKey.id == key_uuid,
            )
        )
        if row is None:
            raise TracecatNotFoundError("SOC key not found")
        return row

    @require_scope("robot:enroll")
    @audit_log(resource_type="robot_fleet", action="update")
    async def activate_fleet_key(self, row: RobotFleetSocKey) -> RobotFleetSocKey:
        """Switch fleet signing to a pending key (install it on every unit first)."""
        return await self._activate(row, FleetSocKeyKind.FLEET)

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="update")
    async def activate_approval_key(self, row: RobotFleetSocKey) -> RobotFleetSocKey:
        """Switch approval signing to a pending key."""
        return await self._activate(row, FleetSocKeyKind.APPROVAL)

    async def _activate(
        self, row: RobotFleetSocKey, kind: FleetSocKeyKind
    ) -> RobotFleetSocKey:
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        if row.kind != kind.value:
            raise TracecatValidationError(f"not a {kind.value} key")
        if row.status != FleetSocKeyStatus.PENDING.value:
            raise TracecatValidationError("only a pending key can be activated")
        now = datetime.now(UTC)
        if (
            current := await active_soc_key(self.session, self.workspace_id, kind)
        ) is not None:
            current.status = FleetSocKeyStatus.RETIRED.value
            current.retired_at = now
            await self.session.flush()
        row.status = FleetSocKeyStatus.ACTIVE.value
        row.activated_at = now
        await self.session.commit()
        await self.session.refresh(row)
        return row

    # --- robots ------------------------------------------------------------------

    async def _robot(self, robot_uuid: uuid.UUID) -> Robot:
        robot = await self.session.scalar(
            select(Robot).where(
                Robot.workspace_id == self.workspace_id, Robot.id == robot_uuid
            )
        )
        if robot is None:
            raise TracecatNotFoundError("Robot not found")
        return robot

    def _workspace_label(self, robot: Robot) -> str:
        return robot.fleet_workspace or str(self.workspace_id)

    @require_scope("robot:read")
    async def get_status(self, robot_uuid: uuid.UUID) -> RobotFleetStatus:
        """The robot's enrollment, tokens, rotations, profiles and ring."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        at_ms = now_ms()
        tokens = await self.session.scalars(
            select(RobotFleetToken)
            .where(
                RobotFleetToken.workspace_id == self.workspace_id,
                RobotFleetToken.robot_id == robot.robot_id,
            )
            .order_by(RobotFleetToken.issued_at_ms.desc())
            .limit(_STATUS_LIMIT)
        )
        rotations = await self.session.scalars(
            select(RobotFleetRotation)
            .where(RobotFleetRotation.robot_fk == robot.id)
            .order_by(RobotFleetRotation.created_at.desc())
            .limit(_STATUS_LIMIT)
        )
        drafts = (
            await self.session.execute(
                select(
                    RobotFleetProfileDraft.id,
                    RobotFleetProfileDraft.digest,
                    func.octet_length(RobotFleetProfileDraft.body),
                    RobotFleetProfileDraft.created_at,
                )
                .where(RobotFleetProfileDraft.robot_fk == robot.id)
                .order_by(RobotFleetProfileDraft.created_at.desc())
                .limit(_STATUS_LIMIT)
            )
        ).tuples()
        offer = await self.session.scalar(
            select(RobotFleetProfileOffer).where(
                RobotFleetProfileOffer.robot_fk == robot.id
            )
        )
        approvals = await self.session.scalars(
            select(RobotFleetApproval)
            .where(RobotFleetApproval.robot_fk == robot.id)
            .order_by(RobotFleetApproval.created_at.desc())
            .limit(_STATUS_LIMIT)
        )
        ring = await self.session.scalar(
            select(RobotFleetRing)
            .where(RobotFleetRing.robot_fk == robot.id)
            .order_by(RobotFleetRing.serial.desc())
            .limit(1)
        )
        return RobotFleetStatus(
            enrolled=robot.fleet_enrolled_at is not None,
            workspace=robot.fleet_workspace,
            enrolled_at=robot.fleet_enrolled_at,
            agentd_version=robot.fleet_agentd_version,
            profile_digest=robot.fleet_profile_digest,
            tokens=[token_read(t, at_ms) for t in tokens],
            rotations=[
                FleetRotationRead(
                    rotation_id=r.rotation_id,
                    role=RobotKeyRole(r.role),
                    old_key_id=r.old_key_id,
                    new_key_id=r.new_key_id,
                    status=FleetRotationStatus(r.status),
                    received=r.rotate_answer is not None,
                    created_at=r.created_at,
                    closed_at=r.closed_at,
                )
                for r in rotations
            ],
            drafts=[
                FleetDraftRead(id=d_id, digest=d, size=size, received_at=at)
                for d_id, d, size, at in drafts
            ],
            offer=(
                FleetOfferRead(
                    digest=offer.digest,
                    profile_version=offer.profile_version,
                    platform=offer.platform,
                    updated_at=offer.updated_at,
                )
                if offer is not None
                else None
            ),
            approvals=[approval_read(a) for a in approvals],
            ring=_ring_read(ring) if ring is not None else None,
        )

    @require_scope("robot:read")
    async def get_draft(
        self, robot_uuid: uuid.UUID, draft_uuid: uuid.UUID
    ) -> FleetDraftContent:
        """A published draft profile with its text (for review)."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        draft = await self.session.scalar(
            select(RobotFleetProfileDraft).where(
                RobotFleetProfileDraft.robot_fk == robot.id,
                RobotFleetProfileDraft.id == draft_uuid,
            )
        )
        if draft is None:
            raise TracecatNotFoundError("Draft not found")
        return FleetDraftContent(
            id=draft.id,
            digest=draft.digest,
            size=len(draft.body),
            received_at=draft.created_at,
            profile=draft.body.decode("utf-8", errors="replace"),
        )

    # --- tokens (§3.1) -------------------------------------------------------------

    @require_scope("robot:enroll")
    @audit_log(resource_type="robot_fleet", action="create")
    async def issue_token(
        self, robot_uuid: uuid.UUID, params: FleetTokenCreate
    ) -> FleetTokenIssued:
        """Issue a single-use enrollment token; the token is returned only here.

        Raises:
            TracecatValidationError: No active fleet key, or the robot's site is
                not a fleet label.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        if robot.site is not None and not wire.is_label(robot.site):
            raise TracecatValidationError(
                "The robot's site must match [A-Za-z0-9._-]{1,64} to enroll it"
            )
        fleet_key = await active_signing_key(
            self.session, self.workspace_id, FleetSocKeyKind.FLEET
        )
        if fleet_key is None:
            raise TracecatValidationError(
                "Generate a SOC fleet key before issuing enrollment tokens"
            )
        nonce = secrets.token_bytes(32)
        while not any(nonce):  # The contract refuses an all-zero nonce.
            nonce = secrets.token_bytes(32)
        issued_at = now_ms()
        payload = wire.TokenPayload(
            token_id=f"rdt-{secrets.token_hex(12)}",
            workspace=self._workspace_label(robot),
            robot_id=robot.robot_id,
            site=robot.site,
            soc_key_id=fleet_key.key_id,
            issued_at_ms=issued_at,
            expires_at_ms=issued_at + params.validity_hours * _HOUR_MS,
            nonce=nonce.hex(),
        )
        token_text = wire.issue_token(payload, fleet_key)
        row = self.store_token(payload, robot_fk=robot.id)
        await self.session.commit()
        await self.session.refresh(row)
        return FleetTokenIssued(
            **token_read(row, issued_at).model_dump(), token=token_text
        )

    def store_token(
        self, payload: wire.TokenPayload, *, robot_fk: uuid.UUID | None
    ) -> RobotFleetToken:
        """Stage the row for an issued token: payload fields and the encrypted nonce."""
        row = RobotFleetToken(
            workspace_id=self.workspace_id,
            token_id=payload.token_id,
            fleet_workspace=payload.workspace,
            robot_id=payload.robot_id,
            site=payload.site,
            soc_key_id=payload.soc_key_id,
            issued_at_ms=payload.issued_at_ms,
            expires_at_ms=payload.expires_at_ms,
            encrypted_nonce=encrypt_secret(bytes.fromhex(payload.nonce)),
            robot_fk=robot_fk,
            created_by=self.role.user_id,
        )
        self.session.add(row)
        return row

    @require_scope("robot:enroll")
    @audit_log(resource_type="robot_fleet", action="revoke")
    async def revoke_token(
        self, robot_uuid: uuid.UUID, token_uuid: uuid.UUID
    ) -> FleetTokenRead:
        """Revoke an unused token: enrolling with it answers ``401 bad_token``."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        token = await self.session.scalar(
            select(RobotFleetToken).where(
                RobotFleetToken.workspace_id == self.workspace_id,
                RobotFleetToken.robot_id == robot.robot_id,
                RobotFleetToken.id == token_uuid,
            )
        )
        if token is None:
            raise TracecatNotFoundError("Token not found")
        if token.consumed_at is None and token.revoked_at is None:
            token.revoked_at = datetime.now(UTC)
            await self.session.commit()
            await self.session.refresh(token)
        return token_read(token, now_ms())

    # --- profile offer (§6.2) ------------------------------------------------------

    @require_scope("robot:update")
    @audit_log(resource_type="robot_fleet", action="publish")
    async def set_offer(
        self, robot_uuid: uuid.UUID, params: FleetOfferUpdate
    ) -> FleetOfferRead:
        """Offer a locked, signed profile to the robot (it stages, never enforces).

        Raises:
            TracecatValidationError: Not a locked profile, or it names another unit.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        profile = params.profile.encode("utf-8")
        signature = params.signature.encode("utf-8")
        try:
            locked = check_locked_profile(profile)
        except ProfileFileError as exc:
            raise TracecatValidationError(f"profile: {exc}") from exc
        if locked.unit_id is not None and locked.unit_id != robot.robot_id:
            raise TracecatValidationError(
                f"The profile is locked for unit {locked.unit_id}, not this robot"
            )
        body = wire.offer_body(profile, signature, locked.profile_version)
        offer = await self.session.scalar(
            select(RobotFleetProfileOffer).where(
                RobotFleetProfileOffer.robot_fk == robot.id
            )
        )
        if offer is None:
            offer = RobotFleetProfileOffer(
                workspace_id=self.workspace_id, robot_fk=robot.id
            )
            self.session.add(offer)
        offer.profile_version = locked.profile_version
        offer.platform = locked.platform
        offer.digest = locked.digest
        offer.body = body
        offer.created_by = self.role.user_id
        await self.session.commit()
        await self.session.refresh(offer)
        return FleetOfferRead(
            digest=offer.digest,
            profile_version=offer.profile_version,
            platform=offer.platform,
            updated_at=offer.updated_at,
        )

    # --- approvals (§6.3) -----------------------------------------------------------

    def _platform_user(self) -> uuid.UUID:
        if self.role.type != "user" or self.role.user_id is None:
            raise TracecatAuthorizationError(
                "Profile approvals are signed off by platform users only"
            )
        return self.role.user_id

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="create")
    async def request_approval(
        self, robot_uuid: uuid.UUID, params: FleetApprovalCreate
    ) -> FleetApprovalRead:
        """Request the observe -> enforce approval of the offered profile.

        The request is bound to the robot and the offer's exact digest, version
        and platform; a second, distinct user must approve it before anything
        is signed.

        Raises:
            TracecatValidationError: The digest is not the offered profile's,
                or the robot is not enrolled.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        requester = self._platform_user()
        robot = await self._robot(robot_uuid)
        if robot.fleet_workspace is None:
            raise TracecatValidationError("The robot is not enrolled")
        offer = await self._offer_for(robot, params.profile_digest)
        row = RobotFleetApproval(
            workspace_id=self.workspace_id,
            approval_id=f"ap-{secrets.token_hex(12)}",
            robot_fk=robot.id,
            platform=offer.platform,
            profile_digest=offer.digest,
            profile_version=offer.profile_version,
            status=FleetApprovalStatus.PENDING.value,
            validity_ms=params.validity_hours * _HOUR_MS,
            requested_by=requester,
        )
        self.session.add(row)
        await self.session.commit()
        await self.session.refresh(row)
        return approval_read(row)

    async def _offer_for(
        self, robot: Robot, profile_digest: str
    ) -> RobotFleetProfileOffer:
        offer = await self.session.scalar(
            select(RobotFleetProfileOffer).where(
                RobotFleetProfileOffer.robot_fk == robot.id
            )
        )
        if offer is None or offer.digest != profile_digest:
            raise TracecatValidationError(
                "Only the profile currently offered to the robot can be approved"
            )
        return offer

    async def _approval(
        self, robot_uuid: uuid.UUID, approval_uuid: uuid.UUID
    ) -> tuple[Robot, RobotFleetApproval]:
        robot = await self._robot(robot_uuid)
        row = await self.session.scalar(
            select(RobotFleetApproval)
            .where(
                RobotFleetApproval.robot_fk == robot.id,
                RobotFleetApproval.id == approval_uuid,
            )
            .with_for_update()
        )
        if row is None:
            raise TracecatNotFoundError("Approval not found")
        return robot, row

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="approve")
    async def approve(
        self, robot_uuid: uuid.UUID, approval_uuid: uuid.UUID
    ) -> FleetApprovalRead:
        """Second sign-off: sign the approval with the approval key (single use).

        Raises:
            TracecatAuthorizationError: The approver is the requester or not a user.
            TracecatValidationError: Not pending, the offer changed, or no
                active approval key.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        approver = self._platform_user()
        robot, row = await self._approval(robot_uuid, approval_uuid)
        if row.status != FleetApprovalStatus.PENDING.value:
            raise TracecatValidationError("Only a pending approval can be approved")
        if row.requested_by == approver:
            raise TracecatAuthorizationError(
                "The requester cannot approve their own request: a second person must"
            )
        if robot.fleet_workspace is None:
            raise TracecatValidationError("The robot is not enrolled")
        offer = await self._offer_for(robot, row.profile_digest)
        if (offer.profile_version, offer.platform) != (
            row.profile_version,
            row.platform,
        ):
            raise TracecatValidationError("The offered profile changed; request again")
        approval_key = await active_signing_key(
            self.session, self.workspace_id, FleetSocKeyKind.APPROVAL
        )
        if approval_key is None:
            raise TracecatValidationError("Generate a SOC approval key first")
        issued_at = now_ms()
        approval = wire.Approval(
            approval_id=row.approval_id,
            workspace=robot.fleet_workspace,
            robot_id=robot.robot_id,
            platform=row.platform,
            profile_digest=row.profile_digest,
            profile_version=row.profile_version,
            approved_by=(f"user:{row.requested_by}", f"user:{approver}"),
            issued_at_ms=issued_at,
            expires_at_ms=issued_at + row.validity_ms,
        )
        approval.check()
        row.envelope = wire.sign_envelope(
            wire.T_APPROVAL, approval.to_bytes(), [approval_key]
        )
        row.status = FleetApprovalStatus.SIGNED.value
        row.approved_by = approver
        row.issued_at_ms = issued_at
        row.expires_at_ms = approval.expires_at_ms
        row.signer_key_id = approval_key.key_id
        await self.session.commit()
        await self.session.refresh(row)
        return approval_read(row)

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="cancel")
    async def cancel_approval(
        self, robot_uuid: uuid.UUID, approval_uuid: uuid.UUID
    ) -> FleetApprovalRead:
        """Withdraw a pending or signed approval (a signed one is no longer served)."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        self._platform_user()
        _, row = await self._approval(robot_uuid, approval_uuid)
        if row.status != FleetApprovalStatus.CANCELLED.value:
            row.status = FleetApprovalStatus.CANCELLED.value
            row.envelope = None
            await self.session.commit()
            await self.session.refresh(row)
        return approval_read(row)

    # --- ring (§7) ------------------------------------------------------------------

    @require_scope("robot:update")
    @audit_log(resource_type="robot_fleet", action="publish")
    async def set_ring(
        self, robot_uuid: uuid.UUID, params: FleetRingUpdate
    ) -> FleetRingRead:
        """Sign and publish the next ring document (serial + 1); information only."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        if robot.fleet_workspace is None:
            raise TracecatValidationError("The robot is not enrolled")
        fleet_key = await active_signing_key(
            self.session, self.workspace_id, FleetSocKeyKind.FLEET
        )
        if fleet_key is None:
            raise TracecatValidationError("Generate a SOC fleet key first")
        last = await self.session.scalar(
            select(func.max(RobotFleetRing.serial)).where(
                RobotFleetRing.robot_fk == robot.id
            )
        )
        issued_at = now_ms()
        info = wire.RingInfo(
            serial=(last or 0) + 1,
            workspace=robot.fleet_workspace,
            robot_id=robot.robot_id,
            ring=params.ring,
            target_version=params.target_version,
            bundle_sha256=params.bundle_sha256,
            min_version=params.min_version,
            issued_at_ms=issued_at,
            expires_at_ms=issued_at + params.validity_hours * _HOUR_MS,
        )
        info.check()
        row = RobotFleetRing(
            workspace_id=self.workspace_id,
            robot_fk=robot.id,
            serial=info.serial,
            ring=info.ring,
            target_version=info.target_version,
            bundle_sha256=info.bundle_sha256,
            min_version=info.min_version,
            issued_at_ms=info.issued_at_ms,
            expires_at_ms=info.expires_at_ms,
            envelope=wire.sign_envelope(wire.T_RING, info.to_bytes(), [fleet_key]),
            created_by=self.role.user_id,
        )
        self.session.add(row)
        await self._commit_or_conflict("A ring document was published concurrently")
        return _ring_read(row)

    # --- revocation lists (§4.1) ----------------------------------------------------

    @require_scope("robot:read")
    async def list_revocation_lists(
        self, page: PageParams
    ) -> Page[FleetRevocationRead]:
        """Published revocation lists, newest first."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        stmt = select(RobotFleetRevocationList).where(
            RobotFleetRevocationList.workspace_id == self.workspace_id
        )
        rows = await paginate(
            self.session,
            stmt,
            page=page,
            order_by=(
                RobotFleetRevocationList.created_at.desc(),
                RobotFleetRevocationList.id.desc(),
            ),
        )
        return Page(
            items=[_revocation_read(r) for r in rows.items],
            next_cursor=rows.next_cursor,
            prev_cursor=rows.prev_cursor,
        )

    @require_scope("robot:update")
    @audit_log(resource_type="robot_fleet", action="publish")
    async def publish_revocation_list(
        self, params: FleetRevocationCreate
    ) -> FleetRevocationRead:
        """Publish a root-signed list for its platform; the serial only rises.

        Raises:
            TracecatValidationError: Malformed, the signature does not verify
                under the given trust root, or a lower serial.
            RobotConflictError: The same serial with other content (equivocation).
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        body = params.revocation_list.encode("utf-8")
        try:
            parsed = parse_revocation_list(body)
        except ProfileFileError as exc:
            raise TracecatValidationError(f"revocation_list: {exc}") from exc
        checked = False
        if params.trust_root_public_key is not None:
            if not parsed.verify(_parse_public_key(params.trust_root_public_key)):
                raise TracecatValidationError(
                    "The list's signature does not verify under this trust root"
                )
            checked = True
        current = await self.session.scalar(
            select(RobotFleetRevocationList)
            .where(
                RobotFleetRevocationList.workspace_id == self.workspace_id,
                RobotFleetRevocationList.platform == parsed.platform,
            )
            .order_by(RobotFleetRevocationList.serial.desc())
            .limit(1)
        )
        if current is not None:
            if parsed.serial < current.serial:
                raise TracecatValidationError(
                    f"Serial {parsed.serial} is lower than the published {current.serial}"
                )
            if parsed.serial == current.serial:
                if parsed.list_digest != current.list_digest:
                    raise RobotConflictError(
                        "Another list with this serial is published (equivocation)"
                    )
                return _revocation_read(current)
        row = RobotFleetRevocationList(
            workspace_id=self.workspace_id,
            platform=parsed.platform,
            serial=parsed.serial,
            list_digest=parsed.list_digest,
            signer_key_id=parsed.signer_key_id,
            signature_checked=checked,
            body=body,
            created_by=self.role.user_id,
        )
        self.session.add(row)
        await self._commit_or_conflict(
            "A list with this serial was published concurrently"
        )
        await self.session.refresh(row)
        return _revocation_read(row)

    async def _commit_or_conflict(self, message: str) -> None:
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise RobotConflictError(message) from exc
