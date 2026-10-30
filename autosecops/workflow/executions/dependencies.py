import urllib.parse
from typing import Annotated

from fastapi import Depends, HTTPException, Query, status

from autosecops.auth.dependencies import WorkspaceActorRouteRole
from autosecops.auth.enums import SpecialUserID
from autosecops.identifiers import UserID
from autosecops.identifiers.workflow import WorkflowExecutionID


def unquote_dep(execution_id: str) -> WorkflowExecutionID:
    unquoted = urllib.parse.unquote(execution_id)
    if not unquoted.strip():
        # An empty ID (e.g. ".../workflow-executions//compact") reached
        # Temporal as a request without a workflow ID and answered 500.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow execution not found",
        )
    return unquoted


UnquotedExecutionID = Annotated[WorkflowExecutionID, Depends(unquote_dep)]
"""Dependency for an unquoted execution ID."""


def resolve_triggered_by_user_id(
    role: WorkspaceActorRouteRole,
    triggered_by_user_id: UserID | SpecialUserID | None = Query(
        default=None,
        alias="user_id",
    ),
) -> UserID | None:
    if role.type == "service_account" and triggered_by_user_id is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="user_id filter is not supported for service accounts",
        )
    if triggered_by_user_id == SpecialUserID.CURRENT:
        if role.user_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User ID is required to filter by user ID",
            )
        return role.user_id
    return triggered_by_user_id
