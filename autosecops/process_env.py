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
import re
import shutil
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

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

PROXY_ENV_NAMES = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
)
"""Proxy URLs, which are passed on without any ``user:password@`` part."""

_CREDENTIAL_SEGMENT = re.compile(
    r"(KEY|KEYS|KEYRING|SECRET|SECRETS|PASSWORD|PASSWD|PASS|PWD|TOKEN|TOKENS|"
    r"CREDENTIAL|CREDENTIALS|CREDS|USERNAME|AUTH|DSN|COOKIE|SESSION)"
)
"""Name segments that mark a variable as a credential."""

DEFAULT_TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
"""Fallback executable search path when no inherited entry is trusted."""


def is_credential_name(name: str) -> bool:
    """Return whether a variable name has a credential-like segment.

    Args:
        name: Environment variable name, such as ``UV_INDEX_CORP_PASSWORD``.

    Returns:
        True when any ``_``-separated segment names a credential.
    """
    return any(
        _CREDENTIAL_SEGMENT.fullmatch(segment)
        for segment in name.upper().split("_")
        if segment
    )


def strip_url_credentials(url: str) -> str:
    """Remove any ``user:password@`` part from a URL.

    Args:
        url: A proxy URL.

    Returns:
        The URL without user information. Values that do not parse as URLs
        with a host are returned unchanged.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit(parts._replace(netloc=host))


def _is_trusted_directory(path: Path) -> bool:
    """Return whether this user cannot replace files in ``path`` or its parents."""
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return not any(
        os.access(directory, os.W_OK) for directory in (resolved, *resolved.parents)
    )


def trusted_path(path: str | None = None) -> str:
    """Return the executable search path without directories this user can write.

    A directory the current user can write (such as ``~/.local/bin``) lets any
    code running as that user plant a fake ``git``, ``uv`` or ``setpriv``. Root
    can write everywhere, so the path is returned unchanged for root.

    Args:
        path: Search path to filter. Defaults to this process's ``PATH``.

    Returns:
        The trusted entries in their original order, or else the trusted
        entries of a system default, which may be empty.
    """
    raw = path if path is not None else os.environ.get("PATH", "")
    if os.geteuid() == 0:
        return raw or DEFAULT_TRUSTED_PATH
    return _trusted_entries(raw) or _trusted_entries(DEFAULT_TRUSTED_PATH)


def _trusted_entries(path: str) -> str:
    """Keep the absolute search-path entries this user cannot write."""
    return os.pathsep.join(
        entry
        for entry in path.split(os.pathsep)
        if entry and os.path.isabs(entry) and _is_trusted_directory(Path(entry))
    )


def which_trusted(name: str) -> str | None:
    """Resolve an executable on ``trusted_path()`` only.

    Args:
        name: Executable name, such as ``setpriv``.

    Returns:
        The absolute path, or None when no trusted directory holds it.
    """
    return shutil.which(name, path=trusted_path())


def select_env(
    environ: Mapping[str, str],
    *,
    names: Iterable[str] = BASE_ENV_NAMES,
    prefixes: tuple[str, ...] = BASE_ENV_PREFIXES,
) -> dict[str, str]:
    """Return the variables of ``environ`` that are allowlisted.

    ``PATH`` is reduced to ``trusted_path()`` and proxy URLs lose their
    credentials.

    Args:
        environ: Environment to select from.
        names: Exact variable names to keep.
        prefixes: Variable name prefixes to keep.

    Returns:
        A new mapping holding only the allowlisted variables.
    """
    allowed = frozenset(names)
    env = {
        name: value
        for name, value in environ.items()
        if name in allowed or name.startswith(prefixes)
    }
    if "PATH" in env:
        # An empty PATH would make exec search the working directory.
        env["PATH"] = trusted_path(env["PATH"]) or os.devnull
    for name in PROXY_ENV_NAMES & env.keys():
        env[name] = strip_url_credentials(env[name])
    return env


def tool_subprocess_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the environment for a git, ssh, uv, tar or mount subprocess.

    The tool keeps process plumbing, proxies, CA bundles and its own ``GIT_*``,
    ``SSH_*`` and ``UV_*`` settings, but none of the platform credentials and
    no credential-like ``UV_*`` names, because uv runs repository build
    backends. Per-user git and uv configuration is ignored: any code running
    as this user can write it.

    Args:
        extra: Variables the caller sets for this invocation, such as an SSH
            agent socket or ``GIT_DIR``. They override inherited values.

    Returns:
        The subprocess environment.
    """
    env = {
        name: value
        for name, value in select_env(
            os.environ,
            prefixes=BASE_ENV_PREFIXES + TOOL_ENV_PREFIXES,
        ).items()
        if not (name.startswith("UV_") and is_credential_name(name))
    }
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["UV_NO_CONFIG"] = "1"
    # uv and git's HTTP transport read ~/.netrc, which this user can write.
    env["NETRC"] = os.devnull
    if extra:
        env.update(extra)
    return env


def uv_subprocess_env(
    cache_dir: Path, extra: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return the environment for one uv invocation with a private cache.

    The shared uv cache is writable by every process running as this user, so
    one repository's build could poison another's. Each install gets its own
    cache directory instead.

    Args:
        cache_dir: A fresh directory the caller owns and removes afterwards.
        extra: Variables to set for this invocation.

    Returns:
        The subprocess environment.
    """
    env = tool_subprocess_env(extra)
    env["UV_CACHE_DIR"] = str(cache_dir)
    return env
