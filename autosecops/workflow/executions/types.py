from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from autosecops.dsl.types import ActionErrorInfo
from autosecops.identifiers import WorkflowExecutionID, WorkflowID
from autosecops.workflow.executions.enums import TriggerType


@dataclass(frozen=True)
class ErrorHandlerWorkflowInput:
    message: str
    handler_wf_id: WorkflowID
    orig_wf_id: WorkflowID
    orig_wf_exec_id: WorkflowExecutionID
    orig_wf_title: str
    trigger_type: TriggerType
    errors: list[ActionErrorInfo] | None = None
    orig_wf_exec_url: str | None = None


type StartOutcome = Literal["started", "not_started", "unknown"]
"""What settling a lost start found: the run started, it never will, or the
check's own answer was lost too."""
