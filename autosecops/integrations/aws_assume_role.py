from __future__ import annotations

from uuid import UUID

from autosecops import config


def get_autosecops_aws_account_id() -> str:
    """Return the AWS account ID used by AutoSecOps workloads."""
    if account_id := config.AUTOSECOPS__AWS_ASSUME_ROLE_ACCOUNT_ID:
        return account_id
    raise ValueError("AUTOSECOPS__AWS_ASSUME_ROLE_ACCOUNT_ID is not configured")


def get_autosecops_aws_principal_arn() -> str:
    """Return the dedicated AWS principal ARN used for customer AssumeRole."""
    if principal_arn := config.AUTOSECOPS__AWS_ASSUME_ROLE_PRINCIPAL_ARN:
        return principal_arn
    raise ValueError("AUTOSECOPS__AWS_ASSUME_ROLE_PRINCIPAL_ARN is not configured")


def build_workspace_external_id(workspace_id: UUID | str) -> str:
    """Build a workspace-scoped External ID for AWS AssumeRole."""
    return str(workspace_id).replace("-", "")
