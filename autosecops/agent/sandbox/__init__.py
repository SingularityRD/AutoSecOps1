"""Sandboxed agent runtime utilities.

This package provides NSJail spawning utilities and config for running
agent runtimes in isolated sandboxes.

Import directly from submodules:
- autosecops.agent.sandbox.config: AgentSandboxConfig, AgentResourceLimits
- autosecops.agent.sandbox.nsjail: spawn_jailed_runtime, etc.
- autosecops.agent.sandbox.shim_entrypoint: CLI entrypoint for sandboxed Claude shim
- autosecops.agent.sandbox.llm_bridge: HTTP bridge for LLM socket

Note: This __init__.py is intentionally minimal to allow the sandbox
entrypoint to import without pulling in heavy dependencies like
autosecops.config (which is not mounted in the sandbox).
"""
