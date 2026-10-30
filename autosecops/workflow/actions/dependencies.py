"""Dependencies for workflow action routes."""

from typing import Annotated

from fastapi import Depends
from fastapi.exceptions import RequestValidationError

from autosecops.identifiers.action import ActionUUID


def action_id_path_dependency(action_id: str) -> ActionUUID:
    """Convert any action ID format (UUID, short, legacy) to ActionUUID."""
    try:
        return ActionUUID.new(action_id)
    except ValueError as exc:
        raise RequestValidationError(
            [
                {
                    "type": "value_error",
                    "loc": ("path", "action_id"),
                    "msg": (
                        "Invalid action ID. Expected a UUID, a short ID "
                        "(act_<base62>), or a legacy ID (act-<hex>)."
                    ),
                    "input": action_id,
                }
            ]
        ) from exc


AnyActionIDPath = Annotated[ActionUUID, Depends(action_id_path_dependency)]
"""An action ID that can be a UUID, short ID (act_xxx), or legacy format (act-<hex>)."""
