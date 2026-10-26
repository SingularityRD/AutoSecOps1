"""Workspace API for the `robodr.fleet` lifecycle (SOC keys, tokens, approvals)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from autosecops import config
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.authz.controls import require_scope
from autosecops.db.dependencies import AsyncDBSession
from autosecops.exceptions import (
    TracecatAuthorizationError,
    TracecatNotFoundError,
    TracecatValidationError,
)
from autosecops.pagination import Page, PageParams, PaginationError
from autosecops.robot_edr.fleet_service import RobotFleetService, soc_key_read
from autosecops.robot_edr.schemas import (
    FleetApprovalCreate,
    FleetApprovalRead,
    FleetApprovalSignature,
    FleetDraftContent,
    FleetOfferRead,
    FleetOfferUpdate,
    FleetRevocationCreate,
    FleetRevocationRead,
    FleetRevocationWithdraw,
    FleetRingRead,
    FleetRingUpdate,
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
from autosecops.robot_edr.types import FleetSocKeyKind
from autosecops.tiers.entitlements import check_entitlement
from autosecops.tiers.enums import Entitlement


async def _require_entitlement(
    role: WorkspaceActorRouteRole, session: AsyncDBSession
) -> None:
    await check_entitlement(session, role, Entitlement.ROBOT_EDR)


router = APIRouter(
    prefix="/robot-edr",
    tags=["robot-edr"],
    dependencies=[Depends(_require_entitlement)],
)


def _http(exc: Exception) -> HTTPException:
    match exc:
        case RobotConflictError():
            return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
        case TracecatNotFoundError():
            return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
        case TracecatAuthorizationError():
            return HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
        case _:
            return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


_HANDLED = (
    RobotConflictError,
    TracecatNotFoundError,
    TracecatAuthorizationError,
    TracecatValidationError,
)


# --- SOC keys ---------------------------------------------------------------------


@router.get("/fleet/soc-keys")
@require_scope("robot:read")
async def list_fleet_soc_keys(
    *, role: WorkspaceActorRouteRole, session: AsyncDBSession
) -> list[FleetSocKeyRead]:
    """The workspace's SOC fleet and approval keys (public halves)."""
    return await RobotFleetService(session, role=role).list_soc_keys()


@router.post("/fleet/soc-keys", status_code=status.HTTP_201_CREATED)
@require_scope("robot:read")
async def create_fleet_soc_key(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: FleetSocKeyCreate,
) -> FleetSocKeyRead:
    """Create a SOC key.

    A fleet key (`robot:enroll`) is generated or imported. An approval key
    (`robot:approve`, platform users) is registered offline by its public key
    file (recommended) or generated online; it is never imported and waits
    for a second user's activation.
    """
    service = RobotFleetService(session, role=role)
    try:
        if params.kind is FleetSocKeyKind.FLEET:
            row = await service.create_fleet_key(params)
        else:
            row = await service.create_approval_key(params)
    except _HANDLED as exc:
        raise _http(exc) from exc
    return soc_key_read(row)


@router.post("/fleet/soc-keys/{key_id}/activate")
@require_scope("robot:read")
async def activate_fleet_soc_key(
    *, role: WorkspaceActorRouteRole, session: AsyncDBSession, key_id: uuid.UUID
) -> FleetSocKeyRead:
    """Sign with a pending key from now on; the previous one is retired.

    An approval key is activated by a platform user other than the one who
    registered it.
    """
    service = RobotFleetService(session, role=role)
    try:
        row = await service.get_soc_key(key_id)
        if row.kind == FleetSocKeyKind.FLEET.value:
            row = await service.activate_fleet_key(row)
        else:
            row = await service.activate_approval_key(row)
    except _HANDLED as exc:
        raise _http(exc) from exc
    return soc_key_read(row)


# --- revocation lists -------------------------------------------------------------


@router.get("/fleet/revocations")
@require_scope("robot:read")
async def list_fleet_revocation_lists(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    limit: int = Query(
        config.TRACECAT__LIMIT_DEFAULT,
        ge=config.TRACECAT__LIMIT_MIN,
        le=config.TRACECAT__LIMIT_CURSOR_MAX,
    ),
    cursor: str | None = Query(None, max_length=8192),
) -> Page[FleetRevocationRead]:
    """Published revocation lists, newest first."""
    service = RobotFleetService(session, role=role)
    try:
        return await service.list_revocation_lists(
            PageParams(limit=limit, cursor=cursor)
        )
    except PaginationError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc


@router.post("/fleet/revocations", status_code=status.HTTP_201_CREATED)
@require_scope("robot:update")
async def publish_fleet_revocation_list(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: FleetRevocationCreate,
) -> FleetRevocationRead:
    """Publish a root-signed revocation list for its platform."""
    try:
        return await RobotFleetService(session, role=role).publish_revocation_list(
            params
        )
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/fleet/revocations/{list_id}/withdrawal")
@require_scope("robot:trust")
async def request_fleet_revocation_withdrawal(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    list_id: uuid.UUID,
    params: FleetRevocationWithdraw,
) -> FleetRevocationRead:
    """First sign-off of withdrawing a revocation list."""
    try:
        return await RobotFleetService(
            session, role=role
        ).request_revocation_withdrawal(list_id, params)
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/fleet/revocations/{list_id}/withdrawal/confirm")
@require_scope("robot:trust")
async def confirm_fleet_revocation_withdrawal(
    *, role: WorkspaceActorRouteRole, session: AsyncDBSession, list_id: uuid.UUID
) -> FleetRevocationRead:
    """Second sign-off by another user: the list is no longer served."""
    try:
        return await RobotFleetService(
            session, role=role
        ).confirm_revocation_withdrawal(list_id)
    except _HANDLED as exc:
        raise _http(exc) from exc


# --- trust roots ------------------------------------------------------------------


@router.get("/fleet/trust-roots")
@require_scope("robot:read")
async def list_fleet_trust_roots(
    *, role: WorkspaceActorRouteRole, session: AsyncDBSession
) -> list[FleetTrustRootRead]:
    """The trust roots revocation lists must verify under."""
    return await RobotFleetService(session, role=role).list_trust_roots()


@router.post("/fleet/trust-roots", status_code=status.HTTP_201_CREATED)
@require_scope("robot:trust")
async def add_fleet_trust_root(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: FleetTrustRootCreate,
) -> FleetTrustRootRead:
    """Trust a robodr-commission trust root for revocation lists."""
    try:
        return await RobotFleetService(session, role=role).add_trust_root(params)
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/fleet/trust-roots/{root_id}/revoke")
@require_scope("robot:trust")
async def revoke_fleet_trust_root(
    *, role: WorkspaceActorRouteRole, session: AsyncDBSession, root_id: uuid.UUID
) -> FleetTrustRootRead:
    """Stop trusting a root for new revocation lists."""
    try:
        return await RobotFleetService(session, role=role).revoke_trust_root(root_id)
    except _HANDLED as exc:
        raise _http(exc) from exc


# --- per robot --------------------------------------------------------------------


@router.get("/robots/{robot_id}/fleet")
@require_scope("robot:read")
async def get_robot_fleet_status(
    *, role: WorkspaceActorRouteRole, session: AsyncDBSession, robot_id: uuid.UUID
) -> RobotFleetStatus:
    """The robot's enrollment, tokens, key rotations, profiles and ring."""
    try:
        return await RobotFleetService(session, role=role).get_status(robot_id)
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/robots/{robot_id}/fleet/tokens", status_code=status.HTTP_201_CREATED)
@require_scope("robot:enroll")
async def issue_robot_enrollment_token(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    params: FleetTokenCreate,
) -> FleetTokenIssued:
    """Issue a single-use enrollment token. The token is shown only in this response."""
    try:
        return await RobotFleetService(session, role=role).issue_token(robot_id, params)
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/robots/{robot_id}/fleet/tokens/{token_id}/revoke")
@require_scope("robot:enroll")
async def revoke_robot_enrollment_token(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    token_id: uuid.UUID,
) -> FleetTokenRead:
    """Revoke an unused enrollment token."""
    try:
        return await RobotFleetService(session, role=role).revoke_token(
            robot_id, token_id
        )
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.get("/robots/{robot_id}/fleet/drafts/{draft_id}")
@require_scope("robot:read")
async def get_robot_profile_draft(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    draft_id: uuid.UUID,
) -> FleetDraftContent:
    """A draft profile the robot published, with its text."""
    try:
        return await RobotFleetService(session, role=role).get_draft(robot_id, draft_id)
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.put("/robots/{robot_id}/fleet/profile")
@require_scope("robot:update")
async def set_robot_profile_offer(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    params: FleetOfferUpdate,
) -> FleetOfferRead:
    """Offer a locked, signed profile to the robot (staged, never enforced)."""
    try:
        return await RobotFleetService(session, role=role).set_offer(robot_id, params)
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/robots/{robot_id}/fleet/approvals", status_code=status.HTTP_201_CREATED)
@require_scope("robot:approve")
async def request_robot_profile_approval(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    params: FleetApprovalCreate,
) -> FleetApprovalRead:
    """First sign-off: request the observe -> enforce approval of the offered profile."""
    try:
        return await RobotFleetService(session, role=role).request_approval(
            robot_id, params
        )
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/robots/{robot_id}/fleet/approvals/{approval_id}/approve")
@require_scope("robot:approve")
async def approve_robot_profile(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    approval_id: uuid.UUID,
) -> FleetApprovalRead:
    """Second sign-off by another user.

    With an online approval key the approval is signed now; with an offline
    key it is `prepared`: sign `signing_message_hex` with the key and submit
    the signature.
    """
    try:
        return await RobotFleetService(session, role=role).approve(
            robot_id, approval_id
        )
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/robots/{robot_id}/fleet/approvals/{approval_id}/signature")
@require_scope("robot:approve")
async def submit_robot_profile_approval_signature(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    approval_id: uuid.UUID,
    params: FleetApprovalSignature,
) -> FleetApprovalRead:
    """Attach the offline approval key's signature to a prepared approval."""
    try:
        return await RobotFleetService(session, role=role).submit_approval_signature(
            robot_id, approval_id, params
        )
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.post("/robots/{robot_id}/fleet/approvals/{approval_id}/cancel")
@require_scope("robot:approve")
async def cancel_robot_profile_approval(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    approval_id: uuid.UUID,
) -> FleetApprovalRead:
    """Withdraw an approval; a signed one is no longer served."""
    try:
        return await RobotFleetService(session, role=role).cancel_approval(
            robot_id, approval_id
        )
    except _HANDLED as exc:
        raise _http(exc) from exc


@router.put("/robots/{robot_id}/fleet/ring")
@require_scope("robot:update")
async def set_robot_ring(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    robot_id: uuid.UUID,
    params: FleetRingUpdate,
) -> FleetRingRead:
    """Publish the robot's next update-ring document (information only)."""
    try:
        return await RobotFleetService(session, role=role).set_ring(robot_id, params)
    except _HANDLED as exc:
        raise _http(exc) from exc
