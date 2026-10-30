"""Workspace management of the `robodr.fleet` lifecycle (operator side).

SOC keys (§2.7), enrollment tokens (§3.1), the profile offer (§6.2), the
two-person approval of the observe -> enforce transition (§6.3), update-ring
information (§7) and revocation lists (§4.1). The robot-facing endpoints that
consume these live in :mod:`autosecops.robot_edr.fleet`.

An approval is signed by the workspace's approval key only after two
distinct platform users signed it off: the requester and one approver, both
holding ``robot:approve``. Nothing signs an approval automatically, and a
service account cannot request or approve one.

The approval key is held offline by default (contract §2.7): the SOC keeps
its public key only, prepares the exact approval payload once both people
signed it off, and accepts the detached signature of the operator holding
the key. An online approval key (generated on the server, lower assurance)
remains possible. Either way an approval key is never imported, and it
signs only after a second platform user activated it.

Revocation lists are published only when their signature verifies under one
of the workspace's trust roots (``robot:trust``); a published list can be
withdrawn by two platform users holding ``robot:trust``.
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
    RobotFleetTrustRoot,
)
from autosecops.exceptions import (
    AutoSecOpsAuthorizationError,
    AutoSecOpsNotFoundError,
    AutoSecOpsValidationError,
)
from autosecops.pagination import Page, PageParams, paginate
from autosecops.robot_edr import fleet_wire as wire
from autosecops.robot_edr.crypto import derive_key_id, is_strict_public_key
from autosecops.robot_edr.fleet import now_ms
from autosecops.robot_edr.fleet_keys import (
    active_signing_key,
    active_soc_key,
    encrypt_secret,
    signing_key,
)
from autosecops.robot_edr.fleet_profiles import (
    ProfileFileError,
    check_locked_profile,
    parse_revocation_list,
)
from autosecops.robot_edr.key_registry import (
    ClaimedKey,
    KeyConflictError,
    VectorKeyError,
    claim_keys,
    is_test_key,
)
from autosecops.robot_edr.schemas import (
    FleetApprovalCreate,
    FleetApprovalRead,
    FleetApprovalSignature,
    FleetDraftContent,
    FleetDraftRead,
    FleetOfferRead,
    FleetOfferUpdate,
    FleetRevocationCreate,
    FleetRevocationRead,
    FleetRevocationWithdraw,
    FleetRingRead,
    FleetRingUpdate,
    FleetRotationRead,
    FleetSocKeyCreate,
    FleetSocKeyRead,
    FleetTokenCreate,
    FleetTokenIssued,
    FleetTokenRead,
    FleetTrustRootCreate,
    FleetTrustRootRead,
    RobotFleetStatus,
)
from autosecops.robot_edr.service import RobotConflictError
from autosecops.robot_edr.types import (
    FleetApprovalStatus,
    FleetRotationStatus,
    FleetSocKeyCustody,
    FleetSocKeyKind,
    FleetSocKeyStatus,
    RobotKeyRole,
)
from autosecops.robot_edr.versions import compare_versions
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
        custody=FleetSocKeyCustody(row.custody),
        status=FleetSocKeyStatus(row.status),
        public_key_file=wire.public_key_file(row.public_key),
        created_by=row.created_by,
        activated_by=row.activated_by,
        created_at=row.created_at,
        activated_at=row.activated_at,
        retired_at=row.retired_at,
    )


def approval_read(row: RobotFleetApproval) -> FleetApprovalRead:
    """Serialize an approval row (with what to sign while it is prepared)."""
    prepared = (
        row.status == FleetApprovalStatus.PREPARED.value
        and row.payload is not None
        and row.signer_key_id is not None
    )
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
        signing_payload=(
            wire.b64_encode(row.payload) if prepared and row.payload else None
        ),
        signing_message_hex=(
            wire.sig_message(wire.T_APPROVAL, row.signer_key_id, row.payload).hex()
            if prepared and row.payload and row.signer_key_id
            else None
        ),
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
        trust_root_key_id=row.trust_root_key_id,
        withdrawal_reason=row.withdrawal_reason,
        withdrawal_requested_by=row.withdrawal_requested_by,
        withdrawal_requested_at=row.withdrawal_requested_at,
        withdrawn_by=row.withdrawn_by,
        withdrawn_at=row.withdrawn_at,
        created_at=row.created_at,
    )


def _trust_root_read(row: RobotFleetTrustRoot) -> FleetTrustRootRead:
    return FleetTrustRootRead(
        id=row.id,
        key_id=row.key_id,
        fingerprint=wire.fingerprint(row.public_key),
        label=row.label,
        created_by=row.created_by,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
    )


def _parse_public_key(text: str, field: str) -> bytes:
    """A strict Ed25519 public key from a key file or 64 hex digits."""
    stripped = text.strip()
    if wire.is_lower_hex(stripped, 64):
        public = bytes.fromhex(stripped)
    else:
        try:
            key_file = wire.parse_key_file(stripped)
        except wire.WireError as exc:
            raise AutoSecOpsValidationError(
                f"{field} must be a robodr-blackbox-key/v2 public key file or 64 hex"
            ) from exc
        if key_file.seed is not None:
            raise AutoSecOpsValidationError(
                f"{field} is a secret key file: give the public key file (.pub)"
            )
        public = key_file.public_key
    if not is_strict_public_key(public):
        raise AutoSecOpsValidationError(f"{field} is not a valid Ed25519 public key")
    return public


def _refuse_test_key(key_id: str, public_key: bytes) -> None:
    if is_test_key(key_id, public_key):
        raise AutoSecOpsValidationError(
            "This is a robodr.fleet contract test key; never use it for real"
        )


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
    @audit_log(resource_type="robot_fleet", action="create", fail_closed=True)
    async def create_fleet_key(self, params: FleetSocKeyCreate) -> RobotFleetSocKey:
        """Generate or import the fleet key (tokens, answers, ring information).

        The first fleet key becomes active; later ones wait (§2.7 rotation).
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        if params.custody is not FleetSocKeyCustody.ONLINE:
            raise AutoSecOpsValidationError(
                "The fleet key is online: the API signs answers with it"
            )
        if params.public_key_file is not None:
            raise AutoSecOpsValidationError(
                "public_key_file registers an offline approval key only"
            )
        if params.secret_key_file is not None:
            try:
                key_file = wire.parse_key_file(params.secret_key_file)
            except wire.WireError as exc:
                raise AutoSecOpsValidationError(f"secret_key_file: {exc}") from exc
            if key_file.seed is None:
                raise AutoSecOpsValidationError("secret_key_file is a public key file")
            key = wire.SigningKey.from_seed(key_file.seed)
        else:
            key = wire.SigningKey.from_seed(secrets.token_bytes(32))
        current = await active_soc_key(
            self.session, self.workspace_id, FleetSocKeyKind.FLEET
        )
        return await self._store_soc_key(
            FleetSocKeyKind.FLEET,
            FleetSocKeyCustody.ONLINE,
            key.public_key,
            key.seed,
            activate=current is None,
        )

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="create", fail_closed=True)
    async def create_approval_key(self, params: FleetSocKeyCreate) -> RobotFleetSocKey:
        """Register an offline approval key, or generate an online one.

        ``offline`` (recommended, contract §2.7): only the public key file is
        stored; approvals are signed by the operator who holds the secret.
        ``online``: the server generates and holds the key (lower assurance:
        whoever controls the server can sign approvals). An approval key's
        secret is never imported, and every approval key starts ``pending``
        until a second platform user activates it.

        Raises:
            AutoSecOpsAuthorizationError: Not a platform user.
            AutoSecOpsValidationError: A secret key file, a missing or invalid
                public key file, or a contract test key.
            RobotConflictError: The key is already registered on this SOC.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        self._platform_user()
        if params.secret_key_file is not None:
            raise AutoSecOpsValidationError(
                "An approval key's secret is never imported: register an offline "
                "key with its public_key_file, or generate an online key"
            )
        seed: bytes | None = None
        if params.custody is FleetSocKeyCustody.OFFLINE:
            if params.public_key_file is None:
                raise AutoSecOpsValidationError(
                    "An offline approval key is registered by its public_key_file"
                )
            public_key = _parse_public_key(params.public_key_file, "public_key_file")
        else:
            if params.public_key_file is not None:
                raise AutoSecOpsValidationError(
                    "public_key_file registers an offline approval key only"
                )
            key = wire.SigningKey.from_seed(secrets.token_bytes(32))
            public_key, seed = key.public_key, key.seed
        return await self._store_soc_key(
            FleetSocKeyKind.APPROVAL,
            params.custody,
            public_key,
            seed,
            activate=False,
        )

    async def _store_soc_key(
        self,
        kind: FleetSocKeyKind,
        custody: FleetSocKeyCustody,
        public_key: bytes,
        seed: bytes | None,
        *,
        activate: bool,
    ) -> RobotFleetSocKey:
        """Register a SOC key SOC-wide (key registry) and store it.

        Raises:
            AutoSecOpsValidationError: A contract test key.
            RobotConflictError: The key id or public key is already registered.
        """
        key_id = derive_key_id(public_key)
        _refuse_test_key(key_id, public_key)
        try:
            await claim_keys(self.session, [ClaimedKey(key_id, public_key)], "soc")
        except (KeyConflictError, VectorKeyError) as exc:
            await self.session.rollback()
            raise RobotConflictError(
                "This key is already registered on this SOC"
            ) from exc
        now = datetime.now(UTC)
        row = RobotFleetSocKey(
            workspace_id=self.workspace_id,
            kind=kind.value,
            key_id=key_id,
            public_key=public_key,
            encrypted_seed=encrypt_secret(seed) if seed is not None else None,
            custody=custody.value,
            status=(
                FleetSocKeyStatus.ACTIVE.value
                if activate
                else FleetSocKeyStatus.PENDING.value
            ),
            activated_at=now if activate else None,
            activated_by=self.role.user_id if activate else None,
            created_by=self.role.user_id,
        )
        self.session.add(row)
        await self._commit_or_conflict("This key is already registered on this SOC")
        await self.session.refresh(row)
        return row

    async def get_soc_key(self, key_uuid: uuid.UUID) -> RobotFleetSocKey:
        """A SOC key of this workspace.

        Raises:
            AutoSecOpsNotFoundError: No such key here.
        """
        row = await self.session.scalar(
            select(RobotFleetSocKey).where(
                RobotFleetSocKey.workspace_id == self.workspace_id,
                RobotFleetSocKey.id == key_uuid,
            )
        )
        if row is None:
            raise AutoSecOpsNotFoundError("SOC key not found")
        return row

    @require_scope("robot:enroll")
    @audit_log(resource_type="robot_fleet", action="update", fail_closed=True)
    async def activate_fleet_key(self, row: RobotFleetSocKey) -> RobotFleetSocKey:
        """Switch fleet signing to a pending key (install it on every unit first)."""
        return await self._activate(row, FleetSocKeyKind.FLEET)

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="update", fail_closed=True)
    async def activate_approval_key(self, row: RobotFleetSocKey) -> RobotFleetSocKey:
        """Switch approval signing to a pending key: a second person's step.

        Raises:
            AutoSecOpsAuthorizationError: Not a platform user, or the user who
                registered the key.
        """
        activator = self._platform_user()
        if row.created_by is None or row.created_by == activator:
            raise AutoSecOpsAuthorizationError(
                "The user who registered an approval key cannot activate it: "
                "a second person must"
            )
        return await self._activate(row, FleetSocKeyKind.APPROVAL)

    async def _activate(
        self, row: RobotFleetSocKey, kind: FleetSocKeyKind
    ) -> RobotFleetSocKey:
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        if row.kind != kind.value:
            raise AutoSecOpsValidationError(f"not a {kind.value} key")
        if row.status != FleetSocKeyStatus.PENDING.value:
            raise AutoSecOpsValidationError("only a pending key can be activated")
        now = datetime.now(UTC)
        if (
            current := await active_soc_key(self.session, self.workspace_id, kind)
        ) is not None:
            current.status = FleetSocKeyStatus.RETIRED.value
            current.retired_at = now
            await self.session.flush()
        row.status = FleetSocKeyStatus.ACTIVE.value
        row.activated_at = now
        row.activated_by = self.role.user_id
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
            raise AutoSecOpsNotFoundError("Robot not found")
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
            raise AutoSecOpsNotFoundError("Draft not found")
        return FleetDraftContent(
            id=draft.id,
            digest=draft.digest,
            size=len(draft.body),
            received_at=draft.created_at,
            profile=draft.body.decode("utf-8", errors="replace"),
        )

    # --- tokens (§3.1) -------------------------------------------------------------

    @require_scope("robot:enroll")
    @audit_log(resource_type="robot_fleet", action="create", fail_closed=True)
    async def issue_token(
        self, robot_uuid: uuid.UUID, params: FleetTokenCreate
    ) -> FleetTokenIssued:
        """Issue a single-use enrollment token; the token is returned only here.

        Raises:
            AutoSecOpsValidationError: No active fleet key, or the robot's site is
                not a fleet label.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        if robot.site is not None and not wire.is_label(robot.site):
            raise AutoSecOpsValidationError(
                "The robot's site must match [A-Za-z0-9._-]{1,64} to enroll it"
            )
        fleet_key = await active_signing_key(
            self.session, self.workspace_id, FleetSocKeyKind.FLEET
        )
        if fleet_key is None:
            raise AutoSecOpsValidationError(
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
    @audit_log(resource_type="robot_fleet", action="revoke", fail_closed=True)
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
            raise AutoSecOpsNotFoundError("Token not found")
        if token.consumed_at is None and token.revoked_at is None:
            token.revoked_at = datetime.now(UTC)
            await self.session.commit()
            await self.session.refresh(token)
        return token_read(token, now_ms())

    # --- profile offer (§6.2) ------------------------------------------------------

    @require_scope("robot:update")
    @audit_log(resource_type="robot_fleet", action="publish", fail_closed=True)
    async def set_offer(
        self, robot_uuid: uuid.UUID, params: FleetOfferUpdate
    ) -> FleetOfferRead:
        """Offer a locked, signed profile to the robot (it stages, never enforces).

        Raises:
            AutoSecOpsValidationError: Not a locked profile, or it names another unit.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        profile = params.profile.encode("utf-8")
        signature = params.signature.encode("utf-8")
        try:
            locked = check_locked_profile(profile)
        except ProfileFileError as exc:
            raise AutoSecOpsValidationError(f"profile: {exc}") from exc
        if locked.unit_id is not None and locked.unit_id != robot.robot_id:
            raise AutoSecOpsValidationError(
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
            raise AutoSecOpsAuthorizationError(
                "Profile approvals are signed off by platform users only"
            )
        return self.role.user_id

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="create", fail_closed=True)
    async def request_approval(
        self, robot_uuid: uuid.UUID, params: FleetApprovalCreate
    ) -> FleetApprovalRead:
        """Request the observe -> enforce approval of the offered profile.

        The request is bound to the robot and the offer's exact digest, version
        and platform; a second, distinct user must approve it before anything
        is signed.

        Raises:
            AutoSecOpsValidationError: The digest is not the offered profile's,
                or the robot is not enrolled.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        requester = self._platform_user()
        robot = await self._robot(robot_uuid)
        if robot.fleet_workspace is None:
            raise AutoSecOpsValidationError("The robot is not enrolled")
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
            raise AutoSecOpsValidationError(
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
            raise AutoSecOpsNotFoundError("Approval not found")
        return robot, row

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="approve", fail_closed=True)
    async def approve(
        self, robot_uuid: uuid.UUID, approval_uuid: uuid.UUID
    ) -> FleetApprovalRead:
        """Second sign-off: sign the approval with the approval key (single use).

        Raises:
            AutoSecOpsAuthorizationError: The approver is the requester or not a user.
            AutoSecOpsValidationError: Not pending, the offer changed, or no
                active approval key.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        approver = self._platform_user()
        robot, row = await self._approval(robot_uuid, approval_uuid)
        if row.status != FleetApprovalStatus.PENDING.value:
            raise AutoSecOpsValidationError("Only a pending approval can be approved")
        if row.requested_by == approver:
            raise AutoSecOpsAuthorizationError(
                "The requester cannot approve their own request: a second person must"
            )
        if robot.fleet_workspace is None:
            raise AutoSecOpsValidationError("The robot is not enrolled")
        offer = await self._offer_for(robot, row.profile_digest)
        if (offer.profile_version, offer.platform) != (
            row.profile_version,
            row.platform,
        ):
            raise AutoSecOpsValidationError(
                "The offered profile changed; request again"
            )
        approval_key = await active_soc_key(
            self.session, self.workspace_id, FleetSocKeyKind.APPROVAL
        )
        if approval_key is None:
            raise AutoSecOpsValidationError("Activate a SOC approval key first")
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
        payload = approval.to_bytes()
        row.payload = payload
        row.approved_by = approver
        row.issued_at_ms = issued_at
        row.expires_at_ms = approval.expires_at_ms
        row.signer_key_id = approval_key.key_id
        if (online := signing_key(approval_key)) is not None:
            row.envelope = wire.sign_envelope(wire.T_APPROVAL, payload, [online])
            row.status = FleetApprovalStatus.SIGNED.value
        else:  # Offline key: the holder signs the prepared payload.
            row.status = FleetApprovalStatus.PREPARED.value
        await self.session.commit()
        await self.session.refresh(row)
        return approval_read(row)

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="approve", fail_closed=True)
    async def submit_approval_signature(
        self,
        robot_uuid: uuid.UUID,
        approval_uuid: uuid.UUID,
        params: FleetApprovalSignature,
    ) -> FleetApprovalRead:
        """Attach the offline approval key's detached signature (§6.3, §2.3).

        Raises:
            AutoSecOpsAuthorizationError: Not a platform user.
            AutoSecOpsValidationError: Not prepared, expired, the approval key
                changed since, or the signature does not verify.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        self._platform_user()
        _, row = await self._approval(robot_uuid, approval_uuid)
        if (
            row.status != FleetApprovalStatus.PREPARED.value
            or row.payload is None
            or row.signer_key_id is None
        ):
            raise AutoSecOpsValidationError(
                "Only a prepared approval takes a signature"
            )
        if row.expires_at_ms is not None and now_ms() >= row.expires_at_ms:
            raise AutoSecOpsValidationError("The approval expired; request it again")
        approval_key = await active_soc_key(
            self.session, self.workspace_id, FleetSocKeyKind.APPROVAL
        )
        if approval_key is None or approval_key.key_id != row.signer_key_id:
            raise AutoSecOpsValidationError(
                "The approval key changed since the approval was prepared; "
                "cancel it and request again"
            )
        message = wire.sig_message(wire.T_APPROVAL, row.signer_key_id, row.payload)
        if not wire.verify_hex(approval_key.public_key, message, params.signature):
            raise AutoSecOpsValidationError(
                "The signature does not verify under the active approval key"
            )
        row.envelope = wire.assemble_envelope(
            wire.T_APPROVAL, row.payload, [(row.signer_key_id, params.signature)]
        )
        row.status = FleetApprovalStatus.SIGNED.value
        await self.session.commit()
        await self.session.refresh(row)
        return approval_read(row)

    @require_scope("robot:approve")
    @audit_log(resource_type="robot_fleet", action="cancel", fail_closed=True)
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
    @audit_log(resource_type="robot_fleet", action="publish", fail_closed=True)
    async def set_ring(
        self, robot_uuid: uuid.UUID, params: FleetRingUpdate
    ) -> FleetRingRead:
        """Sign and publish the next ring document (serial + 1); information only."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        robot = await self._robot(robot_uuid)
        if robot.fleet_workspace is None:
            raise AutoSecOpsValidationError("The robot is not enrolled")
        fleet_key = await active_signing_key(
            self.session, self.workspace_id, FleetSocKeyKind.FLEET
        )
        if fleet_key is None:
            raise AutoSecOpsValidationError("Generate a SOC fleet key first")
        last = await self.session.scalar(
            select(RobotFleetRing)
            .where(RobotFleetRing.robot_fk == robot.id)
            .order_by(RobotFleetRing.serial.desc())
            .limit(1)
        )
        if last is not None and last.min_version is not None:
            if params.min_version is None or (
                compare_versions(params.min_version, last.min_version) < 0
            ):
                raise AutoSecOpsValidationError(
                    f"min_version only rises: it is {last.min_version} (the "
                    "robot's security floor); give it or a higher release"
                )
        issued_at = now_ms()
        info = wire.RingInfo(
            serial=(last.serial if last is not None else 0) + 1,
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
    @audit_log(resource_type="robot_fleet", action="publish", fail_closed=True)
    async def publish_revocation_list(
        self, params: FleetRevocationCreate
    ) -> FleetRevocationRead:
        """Publish a list signed by a workspace trust root; the serial only rises.

        Only a list whose signature verifies under an active trust root of the
        workspace is stored, so only such lists are served and set the
        platform's serial floor (the newest list not withdrawn).

        Raises:
            AutoSecOpsValidationError: Malformed, no trust root configured, the
                signature verifies under none, a lower serial, or the serial
                of a withdrawn list.
            RobotConflictError: The same serial with other content (equivocation).
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        body = params.revocation_list.encode("utf-8")
        try:
            parsed = parse_revocation_list(body)
        except ProfileFileError as exc:
            raise AutoSecOpsValidationError(f"revocation_list: {exc}") from exc
        roots = (
            await self.session.scalars(
                select(RobotFleetTrustRoot).where(
                    RobotFleetTrustRoot.workspace_id == self.workspace_id,
                    RobotFleetTrustRoot.revoked_at.is_(None),
                )
            )
        ).all()
        if not roots:
            raise AutoSecOpsValidationError(
                "Add the trust root that signs revocation lists first (robot:trust)"
            )
        root = next((r for r in roots if parsed.verify(r.public_key)), None)
        if root is None:
            raise AutoSecOpsValidationError(
                "The list's signature does not verify under any trust root of "
                "this workspace"
            )
        same_serial = await self.session.scalar(
            select(RobotFleetRevocationList).where(
                RobotFleetRevocationList.workspace_id == self.workspace_id,
                RobotFleetRevocationList.platform == parsed.platform,
                RobotFleetRevocationList.serial == parsed.serial,
            )
        )
        if same_serial is not None:
            if same_serial.list_digest != parsed.list_digest:
                raise RobotConflictError(
                    "Another list with this serial is published (equivocation)"
                )
            if (
                same_serial.withdrawn_at is not None
                or not same_serial.signature_checked
            ):
                raise AutoSecOpsValidationError(
                    f"Serial {parsed.serial} belongs to a withdrawn or unverified "
                    "list; publish the list again under a higher serial"
                )
            return _revocation_read(same_serial)
        floor = await self.session.scalar(
            select(func.max(RobotFleetRevocationList.serial)).where(
                RobotFleetRevocationList.workspace_id == self.workspace_id,
                RobotFleetRevocationList.platform == parsed.platform,
                RobotFleetRevocationList.signature_checked.is_(True),
                RobotFleetRevocationList.withdrawn_at.is_(None),
            )
        )
        if floor is not None and parsed.serial < floor:
            raise AutoSecOpsValidationError(
                f"Serial {parsed.serial} is lower than the published {floor}"
            )
        row = RobotFleetRevocationList(
            workspace_id=self.workspace_id,
            platform=parsed.platform,
            serial=parsed.serial,
            list_digest=parsed.list_digest,
            signer_key_id=parsed.signer_key_id,
            signature_checked=True,
            trust_root_key_id=root.key_id,
            body=body,
            created_by=self.role.user_id,
        )
        self.session.add(row)
        await self._commit_or_conflict(
            "A list with this serial was published concurrently"
        )
        await self.session.refresh(row)
        return _revocation_read(row)

    async def _revocation_list(self, list_uuid: uuid.UUID) -> RobotFleetRevocationList:
        row = await self.session.scalar(
            select(RobotFleetRevocationList)
            .where(
                RobotFleetRevocationList.workspace_id == self.workspace_id,
                RobotFleetRevocationList.id == list_uuid,
            )
            .with_for_update()
        )
        if row is None:
            raise AutoSecOpsNotFoundError("Revocation list not found")
        return row

    @require_scope("robot:trust")
    @audit_log(resource_type="robot_fleet", action="withdraw", fail_closed=True)
    async def request_revocation_withdrawal(
        self, list_uuid: uuid.UUID, params: FleetRevocationWithdraw
    ) -> FleetRevocationRead:
        """First sign-off of withdrawing a list (a second user confirms).

        A withdrawn list is kept but no longer served, and no longer sets the
        serial floor. Robots that installed it keep refusing lower serials
        (contract §4.1): publish the replacement under a higher serial.

        Raises:
            AutoSecOpsAuthorizationError: Not a platform user.
            AutoSecOpsValidationError: Already withdrawn or requested.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        requester = self._platform_user()
        row = await self._revocation_list(list_uuid)
        if row.withdrawn_at is not None or row.withdrawal_requested_at is not None:
            raise AutoSecOpsValidationError(
                "The list is already withdrawn or its withdrawal is requested"
            )
        row.withdrawal_reason = params.reason
        row.withdrawal_requested_by = requester
        row.withdrawal_requested_at = datetime.now(UTC)
        await self.session.commit()
        await self.session.refresh(row)
        return _revocation_read(row)

    @require_scope("robot:trust")
    @audit_log(resource_type="robot_fleet", action="withdraw", fail_closed=True)
    async def confirm_revocation_withdrawal(
        self, list_uuid: uuid.UUID
    ) -> FleetRevocationRead:
        """Second sign-off: withdraw the list.

        Raises:
            AutoSecOpsAuthorizationError: Not a platform user, or the requester.
            AutoSecOpsValidationError: No pending withdrawal request.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        confirmer = self._platform_user()
        row = await self._revocation_list(list_uuid)
        if row.withdrawn_at is not None or row.withdrawal_requested_at is None:
            raise AutoSecOpsValidationError("No withdrawal of this list is pending")
        if row.withdrawal_requested_by == confirmer:
            raise AutoSecOpsAuthorizationError(
                "The requester cannot confirm their own withdrawal: a second "
                "person must"
            )
        row.withdrawn_by = confirmer
        row.withdrawn_at = datetime.now(UTC)
        await self.session.commit()
        await self.session.refresh(row)
        return _revocation_read(row)

    # --- trust roots (§4.1) ----------------------------------------------------------

    @require_scope("robot:read")
    async def list_trust_roots(self) -> list[FleetTrustRootRead]:
        """The workspace's trust roots, newest first."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        rows = await self.session.scalars(
            select(RobotFleetTrustRoot)
            .where(RobotFleetTrustRoot.workspace_id == self.workspace_id)
            .order_by(RobotFleetTrustRoot.created_at.desc(), RobotFleetTrustRoot.id)
        )
        return [_trust_root_read(row) for row in rows]

    @require_scope("robot:trust")
    @audit_log(resource_type="robot_fleet", action="create", fail_closed=True)
    async def add_trust_root(self, params: FleetTrustRootCreate) -> FleetTrustRootRead:
        """Trust a robodr-commission trust root for this workspace's lists.

        Raises:
            AutoSecOpsValidationError: Not a public key, or a contract test key.
            RobotConflictError: Already a trust root of this workspace.
        """
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        public_key = _parse_public_key(params.public_key, "public_key")
        key_id = derive_key_id(public_key)
        _refuse_test_key(key_id, public_key)
        row = RobotFleetTrustRoot(
            workspace_id=self.workspace_id,
            key_id=key_id,
            public_key=public_key,
            label=params.label,
            created_by=self.role.user_id,
        )
        self.session.add(row)
        await self._commit_or_conflict("This trust root is already configured")
        await self.session.refresh(row)
        return _trust_root_read(row)

    @require_scope("robot:trust")
    @audit_log(resource_type="robot_fleet", action="revoke", fail_closed=True)
    async def revoke_trust_root(self, root_uuid: uuid.UUID) -> FleetTrustRootRead:
        """Stop trusting a root for new lists (published lists stay)."""
        await self.require_entitlement(Entitlement.ROBOT_EDR)
        row = await self.session.scalar(
            select(RobotFleetTrustRoot).where(
                RobotFleetTrustRoot.workspace_id == self.workspace_id,
                RobotFleetTrustRoot.id == root_uuid,
            )
        )
        if row is None:
            raise AutoSecOpsNotFoundError("Trust root not found")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
            row.revoked_by = self.role.user_id
            await self.session.commit()
            await self.session.refresh(row)
        return _trust_root_read(row)

    async def _commit_or_conflict(self, message: str) -> None:
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise RobotConflictError(message) from exc
