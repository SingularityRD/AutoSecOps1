"""Configuration for autosecops-registry package."""

import os
from typing import Any

from pydantic_core import to_jsonable_python as _to_jsonable_python


def to_jsonable_python(value: Any) -> Any:
    """Convert a value to a JSONable Python object.

    Drop nulls and use fallback for unknown values.
    """

    def fallback(x: Any) -> Any:
        """Fallback for unknown values."""
        return None

    return _to_jsonable_python(value, fallback=fallback, exclude_none=True)


# API list/search limits (mirror autosecops/config.py where relevant)
AUTOSECOPS__LIMIT_MIN = 1
AUTOSECOPS__LIMIT_DEFAULT = 20
AUTOSECOPS__LIMIT_CURSOR_MAX = 200
AUTOSECOPS__LIMIT_TABLE_DOWNLOAD_MAX = 1000

# File upload limits
AUTOSECOPS__MAX_FILE_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_FILE_SIZE_BYTES", 20 * 1024 * 1024)  # Default 20MB
)
AUTOSECOPS__MAX_UPLOAD_FILES_COUNT = int(
    os.environ.get("AUTOSECOPS__MAX_UPLOAD_FILES_COUNT", 5)
)
AUTOSECOPS__MAX_AGGREGATE_UPLOAD_SIZE_BYTES = int(
    os.environ.get("AUTOSECOPS__MAX_AGGREGATE_UPLOAD_SIZE_BYTES", 100 * 1024 * 1024)
)

# S3 concurrency limit
AUTOSECOPS__S3_CONCURRENCY_LIMIT = int(
    os.environ.get("AUTOSECOPS__S3_CONCURRENCY_LIMIT", 10)
)

# DuckDB extension directory. Set in the Docker images to the directory that
# preinstalled DuckDB extensions are copied into. Left unset in local/dev/test
# environments, where DuckDB falls back to its default autoinstall behaviour.
AUTOSECOPS__DUCKDB_EXTENSION_DIRECTORY = os.environ.get(
    "AUTOSECOPS__DUCKDB_EXTENSION_DIRECTORY"
)

# Database connection validation (used to prevent connecting to internal DB)
AUTOSECOPS__DB_URI = os.environ.get(
    "AUTOSECOPS__DB_URI",
    "postgresql+psycopg://postgres:postgres@postgres_db:5432/postgres",
)
AUTOSECOPS__DB_ENDPOINT = os.environ.get("AUTOSECOPS__DB_ENDPOINT")
AUTOSECOPS__DB_PORT = os.environ.get("AUTOSECOPS__DB_PORT")
AUTOSECOPS__AGENT_MAX_RETRIES = int(os.environ.get("AUTOSECOPS__AGENT_MAX_RETRIES", 20))

AUTOSECOPS__AGENT_MAX_TOOL_CALLS = int(
    os.environ.get("AUTOSECOPS__AGENT_MAX_TOOL_CALLS", 40)
)
"""The maximum number of tool calls that can be made per agent run."""

AUTOSECOPS__AGENT_MAX_REQUESTS = int(
    os.environ.get("AUTOSECOPS__AGENT_MAX_REQUESTS", 120)
)
"""The maximum number of requests that can be made per agent run."""
