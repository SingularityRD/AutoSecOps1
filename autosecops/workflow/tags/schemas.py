from pydantic import BaseModel

from autosecops.identifiers import TagID


class WorkflowTagCreate(BaseModel):
    tag_id: TagID
