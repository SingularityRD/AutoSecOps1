"""Least-privilege environments for subprocesses of platform services.

Platform containers carry credentials in their environment: the database URI,
encryption, service and signing keys, Temporal and cloud credentials. A child
process inherits all of them unless it is given its own environment, and on
Linux any process running as the same user can read a dumpable child's
``/proc/<pid>/environ``. Subprocesses that run tools (git, uv, tar, mount) or
customer code therefore start from these allowlists instead of ``os.environ``.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping

BASE_ENV_NAMES = frozenset(
    {
        # Process plumbing.
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LANGUAGE",
        "TZ",
        "TMPDIR",
        "TEMP",
        "TMP",
        # Python import roots. Custom registries installed for local-repository
        # mode live in the user site that PYTHONUSERBASE/PYTHONPATH point at.
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "PYTHONUNBUFFERED",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "VIRTUAL_ENV",
        # TLS trust stores for outbound requests.
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        # Operator egress proxy.
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
)
"""Non-secret variables every restricted subprocess may inherit."""

BASE_ENV_PREFIXES = ("LC_",)
"""Name prefixes every restricted subprocess may inherit (locale categories)."""

TOOL_ENV_PREFIXES = ("GIT_", "SSH_", "UV_")
"""Tool configuration that git, ssh and uv subprocesses also inherit."""


def select_env(
    environ: Mapping[str, str],
    *,
    names: Iterable[str] = BASE_ENV_NAMES,
    prefixes: tuple[str, ...] = BASE_ENV_PREFIXES,
) -> dict[str, str]:
    """Return the variables of ``environ`` that are allowlisted.

    Args:
        environ: Environment to select from.
        names: Exact variable names to keep.
        prefixes: Variable name prefixes to keep.

    Returns:
        A new mapping holding only the allowlisted variables.
    """
    allowed = frozenset(names)
    return {
        name: value
        for name, value in environ.items()
        if name in allowed or name.startswith(prefixes)
    }


def tool_subprocess_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the environment for a git, ssh, uv, tar or mount subprocess.

    The tool keeps process plumbing, proxies, CA bundles and its own ``GIT_*``,
    ``SSH_*`` and ``UV_*`` settings, but none of the platform credentials.

    Args:
        extra: Variables the caller sets for this invocation, such as an SSH
            agent socket or ``GIT_DIR``. They override inherited values.

    Returns:
        The subprocess environment.
    """
    env = select_env(
        os.environ,
        prefixes=BASE_ENV_PREFIXES + TOOL_ENV_PREFIXES,
    )
    if extra:
        env.update(extra)
    return env
