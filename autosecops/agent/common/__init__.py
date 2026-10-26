"""Lightweight shared module for agent sandbox communication.

This module provides types and utilities for orchestrator-runtime communication
with minimal dependencies. It is designed to be imported by the sandbox entrypoint
without pulling in heavy autosecops modules.

Key design principles:
- No imports from autosecops.config (reads os.environ directly)
- Pure dataclasses instead of Pydantic models
- orjson for serialization (no pydantic_core)
"""

from autosecops.agent.common.adapter_base import BaseHarnessAdapter
from autosecops.agent.common.config import (
    JAILED_CONTROL_SOCKET_PATH,
    JAILED_LLM_SOCKET_PATH,
    TRACECAT__AGENT_SANDBOX_MEMORY_MB,
    TRACECAT__AGENT_SANDBOX_TIMEOUT,
    TRACECAT__EXECUTOR_BACKEND,
)
from autosecops.agent.common.exceptions import (
    AgentSandboxError,
    AgentSandboxExecutionError,
    AgentSandboxTimeoutError,
    AgentSandboxValidationError,
)
from autosecops.agent.common.protocol import (
    RuntimeEventEnvelope,
    RuntimeInitPayload,
)
from autosecops.agent.common.socket_io import (
    HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    MessageType,
    SocketStreamWriter,
    build_message,
    read_message,
)
from autosecops.agent.common.stream_types import (
    ArtifactEventContent,
    HarnessType,
    StreamEventType,
    ToolCallContent,
    UnifiedStreamEvent,
)
from autosecops.agent.common.types import (
    MCPServerConfig,
    MCPToolDefinition,
    SandboxAgentConfig,
)

__all__ = [
    # Adapter base
    "BaseHarnessAdapter",
    # Config
    "JAILED_CONTROL_SOCKET_PATH",
    "JAILED_LLM_SOCKET_PATH",
    "TRACECAT__AGENT_SANDBOX_MEMORY_MB",
    "TRACECAT__AGENT_SANDBOX_TIMEOUT",
    "TRACECAT__EXECUTOR_BACKEND",
    # Exceptions
    "AgentSandboxError",
    "AgentSandboxExecutionError",
    "AgentSandboxTimeoutError",
    "AgentSandboxValidationError",
    # Protocol
    "RuntimeEventEnvelope",
    "RuntimeInitPayload",
    # Socket I/O
    "HEADER_SIZE",
    "MAX_PAYLOAD_SIZE",
    "MessageType",
    "SocketStreamWriter",
    "build_message",
    "read_message",
    # Stream types
    "ArtifactEventContent",
    "HarnessType",
    "StreamEventType",
    "ToolCallContent",
    "UnifiedStreamEvent",
    # Types
    "MCPServerConfig",
    "MCPToolDefinition",
    "SandboxAgentConfig",
]
