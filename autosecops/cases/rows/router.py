import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from starlette.status import (
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
)

from autosecops import config
from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.authz.controls import require_scope
from autosecops.cases.rows.exceptions import raise_case_row_link_integrity_error
from autosecops.cases.rows.schemas import (
    CaseLinkedTableRead,
    CaseTableRowBatchLink,
    CaseTableRowBatchLinkResponse,
    CaseTableRowBatchUnlink,
    CaseTableRowBatchUnlinkResponse,
    CaseTableRowInsertCreate,
    CaseTableRowLinkCreate,
    CaseTableRowRead,
)
from autosecops.cases.rows.service import CaseTableRowsService
from autosecops.cases.schemas import CaseReadMinimal
from autosecops.db.dependencies import AsyncDBSession
from autosecops.exceptions import AutoSecOpsNotFoundError
from autosecops.pagination import CursorPaginatedResponse, CursorPaginationParams

router = APIRouter(prefix="/cases", tags=["cases"])
linked_cases_router = APIRouter(prefix="/tables", tags=["cases"])


@router.get("/{case_id}/rows")
@require_scope("case:read")
async def list_case_rows(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    case_id: uuid.UUID,
    limit: int = Query(
        config.AUTOSECOPS__LIMIT_DEFAULT,
        ge=config.AUTOSECOPS__LIMIT_MIN,
        le=config.AUTOSECOPS__LIMIT_CURSOR_MAX,
    ),
    cursor: str | None = Query(default=None),
    reverse: bool = Query(default=False),
    table_id: uuid.UUID | None = Query(
        default=None,
        description="Restrict results to one linked table",
    ),
    order_by: str | None = Query(
        default=None, description="Row column name to order by. Requires table_id"
    ),
    sort: Literal["asc", "desc"] | None = Query(
        default=None, description="Sort direction (asc or desc). Requires table_id"
    ),
    search_term: str | None = Query(
        default=None,
        max_length=1000,
        description="Text to search for in text-searchable row columns. "
        "Requires table_id",
    ),
    search_column: str | None = Query(
        default=None,
        description="Restrict search_term to this column. Requires table_id",
    ),
) -> CursorPaginatedResponse[CaseTableRowRead]:
    """List linked rows.

    ``total_estimate`` is an exact count of the table's linked rows when
    ``table_id`` is set, null otherwise. It does not reflect ``search_term``.
    """
    service = CaseTableRowsService(session, role)
    try:
        await service.get_case_or_raise(case_id)
        return await service.list_rows(
            case_id=case_id,
            limit=limit,
            cursor=cursor,
            reverse=reverse,
            include_row_data=True,
            table_id=table_id,
            order_by=order_by,
            sort=sort,
            search_term=search_term,
            search_column=search_column,
        )
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/{case_id}/rows/tables")
@require_scope("case:read")
async def list_case_linked_tables(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    case_id: uuid.UUID,
) -> list[CaseLinkedTableRead]:
    """List the tables that have rows linked to a case, with their columns.

    Only ``case:read`` is required: the links, and the column definitions needed
    to render them, are case data.
    """
    service = CaseTableRowsService(session, role)
    try:
        await service.get_case_or_raise(case_id)
        return await service.list_linked_tables(case_id=case_id)
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/{case_id}/rows", status_code=HTTP_201_CREATED)
@require_scope("case:update")
async def link_case_row(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    case_id: uuid.UUID,
    params: CaseTableRowLinkCreate,
) -> CaseTableRowRead:
    service = CaseTableRowsService(session, role)
    try:
        case = await service.get_case_or_raise(case_id)
        link = await service.link_row(case=case, params=params)
        hydrated = await service._hydrate_links([link], include_row_data=True)
        return hydrated[0]
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except IntegrityError as exc:
        await raise_case_row_link_integrity_error(session, exc)


@router.post("/{case_id}/rows/insert", status_code=HTTP_201_CREATED)
@require_scope("case:update", "table:create")
async def insert_case_row(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    case_id: uuid.UUID,
    params: CaseTableRowInsertCreate,
) -> CaseTableRowRead:
    service = CaseTableRowsService(session, role)
    try:
        case = await service.get_case_or_raise(case_id)
        link = await service.insert_row_to_case(case=case, params=params)
        hydrated = await service._hydrate_links([link], include_row_data=True)
        return hydrated[0]
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{case_id}/rows/batch-link")
@require_scope("case:update")
async def batch_link_case_rows(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    case_id: uuid.UUID,
    params: CaseTableRowBatchLink,
) -> CaseTableRowBatchLinkResponse:
    """Link rows in bulk; conflict handling makes an integrity error unreachable."""
    service = CaseTableRowsService(session, role)
    try:
        case = await service.get_case_or_raise(case_id)
        return await service.link_rows(
            case=case,
            table_id=params.table_id,
            row_ids=params.row_ids,
        )
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{case_id}/rows/batch-unlink")
@require_scope("case:update")
async def batch_unlink_case_rows(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    case_id: uuid.UUID,
    params: CaseTableRowBatchUnlink,
) -> CaseTableRowBatchUnlinkResponse:
    """Unlink rows in bulk, returning zero for a fully no-op batch."""
    service = CaseTableRowsService(session, role)
    try:
        case = await service.get_case_or_raise(case_id)
        unlinked_count = await service.unlink_rows(
            case=case,
            table_id=params.table_id,
            row_ids=params.row_ids,
        )
        return CaseTableRowBatchUnlinkResponse(unlinked_count=unlinked_count)
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.delete("/{case_id}/rows/{table_id}/{row_id}", status_code=HTTP_204_NO_CONTENT)
@require_scope("case:update")
async def unlink_case_row(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    case_id: uuid.UUID,
    table_id: uuid.UUID,
    row_id: uuid.UUID,
) -> None:
    service = CaseTableRowsService(session, role)
    try:
        case = await service.get_case_or_raise(case_id)
        deleted = await service.unlink_row(case=case, table_id=table_id, row_id=row_id)
        if not deleted:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND, detail="Linked row not found"
            )
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@linked_cases_router.get("/{table_id}/rows/{row_id}/cases")
@require_scope("case:read")
async def list_linked_cases(
    *,
    role: WorkspaceActorRouteRole,
    session: AsyncDBSession,
    table_id: uuid.UUID,
    row_id: uuid.UUID,
    limit: int = Query(
        config.AUTOSECOPS__LIMIT_DEFAULT,
        ge=config.AUTOSECOPS__LIMIT_MIN,
        le=config.AUTOSECOPS__LIMIT_CURSOR_MAX,
    ),
    cursor: str | None = Query(default=None),
    reverse: bool = Query(default=False),
    order_by: Literal[
        "created_at",
        "updated_at",
        "priority",
        "severity",
        "status",
        "tasks",
        "assignee",
        "tags",
    ]
    | None = Query(None, description="Case column to order by. Default: created_at"),
    sort: Literal["asc", "desc"] | None = Query(
        None, description="Direction to sort (asc or desc)"
    ),
    exclude_case_id: uuid.UUID | None = Query(
        default=None, description="Leave this case out of the results"
    ),
) -> CursorPaginatedResponse[CaseReadMinimal]:
    """List the cases that link a table row."""
    service = CaseTableRowsService(session, role)
    try:
        return await service.list_linked_cases(
            table_id=table_id,
            row_id=row_id,
            params=CursorPaginationParams(limit=limit, cursor=cursor, reverse=reverse),
            exclude_case_id=exclude_case_id,
            order_by=order_by,
            sort=sort,
        )
    except AutoSecOpsNotFoundError as exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
