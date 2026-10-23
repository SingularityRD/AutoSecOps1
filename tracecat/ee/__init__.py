"""Enterprise Edition shim module.

This module contains shims and imports for AutoSecOps Enterprise Edition features.
All actual EE functionality is implemented in the `tracecat-ee` package, which is
part of AutoSecOps and covered by the same SingularityRD license as the rest of
the codebase.
When EE features are not installed, appropriate ImportError exceptions are raised
to guide users to install the required extras.
"""
