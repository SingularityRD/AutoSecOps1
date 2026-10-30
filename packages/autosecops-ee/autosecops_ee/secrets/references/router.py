"""Workspace secret reference API: secrets whose values live in an external store."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from temporalio.client import WorkflowFailureError

from autosecops import config
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.authz.controls import require_scope
from autosecops.db.dependencies import AsyncDBSession
from autosecops.db.errors import is_unique_violation
from autosecops.dsl.client import get_temporal_client
from autosecops.exceptions import AutoSecOpsAuthorizationError, AutoSecOpsNotFoundError
from autosecops.pagination import Page, PageParams, PaginationError
from autosecops.secrets.dependencies import AnySecretIDPath
from autosecops.secrets.schemas import (
    AwsSecretReferenceCreate,
    AwsSecretReferenceUpdate,
    SecretReferenceCheckRequest,
    SecretReferenceCheckResult,
    WorkspaceSecretStoreRead,
)
from autosecops.secrets.service import is_external_reference
from autosecops.tiers.entitlements import check_entitlement
from autosecops.tiers.enums import Entitlement
from autosecops_ee.secrets.references.service import SecretReferencesService
from autosecops_ee.secrets.references.workflows import SecretReferenceCheckWorkflow


async def _require_entitlement(
    role: WorkspaceActorRouteRole, session: AsyncDBSession
) -> None:
    await check_entitlement(session, role, Entitlement.EXTERNAL_SECRET_STORES)


router = APIRouter(
    prefix="/secrets",
    tags=["secrets"],
    dependencies=[Depends(_require_entitlement)],
)
stores_router = APIRouter(
    prefix="/secret-stores",
    tags=["secrets"],
    dependencies=[Depends(_require_entitlement)],
)


@stores_router.get("", response_model=Page[WorkspaceSecretStoreRead])
@require_scope("secret:read")
async def list_authorized_secret_stores(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    limit: int = Query(
        config.AUTOSECOPS__LIMIT_DEFAULT,
        ge=config.AUTOSECOPS__LIMIT_MIN,
        le=config.AUTOSECOPS__LIMIT_CURSOR_MAX,
    ),
    cursor: str | None = Query(None, max_length=8192),
) -> Page[WorkspaceSecretStoreRead]:
    """List external secret stores this workspace is authorized to reference."""
    service = SecretReferencesService(session, role=role)
    try:
        stores = await service.list_authorized_stores(
            PageParams(limit=limit, cursor=cursor)
        )
    except PaginationError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    return Page(
        items=[WorkspaceSecretStoreRead.from_database(store) for store in stores.items],
        next_cursor=stores.next_cursor,
        prev_cursor=stores.prev_cursor,
    )


@router.post("/aws", status_code=status.HTTP_201_CREATED)
@require_scope("secret:create")
async def create_aws_secret_reference(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    params: AwsSecretReferenceCreate,
) -> None:
    """Create a custom secret whose values live in AWS Secrets Manager."""
    service = SecretReferencesService(session, role=role)
    try:
        await service.create_aws_secret_reference(params)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        ) from e
    except AutoSecOpsAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except IntegrityError as e:
        if not is_unique_violation(e, "uq_secret_name_environment_workspace_id"):
            raise
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Secret already exists"
        ) from e


@router.post("/aws/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_scope("secret:update")
async def update_aws_secret_reference(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    secret_id: AnySecretIDPath,
    params: AwsSecretReferenceUpdate,
) -> None:
    """Update the reference or key mapping of an AWS-backed secret."""
    service = SecretReferencesService(session, role=role)
    try:
        secret = await service.get_secret(secret_id)
        await service.update_aws_secret_reference(secret, params)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        ) from e
    except AutoSecOpsAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except AutoSecOpsNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Secret does not exist"
        ) from e
    except IntegrityError as e:
        if not is_unique_violation(e, "uq_secret_name_environment_workspace_id"):
            raise
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Secret already exists"
        ) from e


@router.post("/aws/{secret_id}/check", response_model=SecretReferenceCheckResult)
@require_scope("secret:read")
async def check_aws_secret_reference(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    secret_id: AnySecretIDPath,
) -> SecretReferenceCheckResult:
    """Verify a saved AWS-backed reference resolves. Values are never returned."""
    service = SecretReferencesService(session, role=role)
    try:
        secret = await service.get_secret(secret_id)
        if not is_external_reference(secret):
            raise ValueError("Secret is not backed by AWS Secrets Manager.")
        # Only identifiers and actor context cross Temporal; values stay on the executor.
        await session.commit()
        client = await get_temporal_client()
        return await client.execute_workflow(
            SecretReferenceCheckWorkflow.run,
            SecretReferenceCheckRequest(role=role, secret_id=secret_id),
            id=f"secret-reference-check-{uuid4()}",
            task_queue=config.AUTOSECOPS__EXECUTOR_QUEUE,
            execution_timeout=timedelta(seconds=60),
        )
    except WorkflowFailureError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secret reference check could not complete. Try again.",
        ) from exc
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        ) from e
    except AutoSecOpsNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Secret does not exist"
        ) from e
