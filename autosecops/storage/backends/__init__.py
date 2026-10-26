"""Storage backend implementations."""

from autosecops.storage.backends.inline import InlineObjectStorage
from autosecops.storage.backends.s3 import S3ObjectStorage

__all__ = [
    "InlineObjectStorage",
    "S3ObjectStorage",
]
