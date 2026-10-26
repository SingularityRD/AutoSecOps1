#!/usr/bin/env python3
"""Fail when the embedded license public key is still the development key.

Release workflows run this before building or publishing release artifacts:

    python3 scripts/check_license_public_key.py

It loads ``autosecops/licensing/keys.py`` by path with only the standard
library, so it runs without installing project dependencies.

Exit codes:
    0  the embedded key is not the development key
    1  the embedded key is the development key
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

KEYS_PATH = Path(__file__).resolve().parent.parent / "autosecops/licensing/keys.py"


def load_keys_module(path: Path) -> ModuleType:
    """Load the keys module from ``path`` without importing the package."""
    spec = importlib.util.spec_from_file_location("_license_keys", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    """Check the keys module at ``argv[0]`` (default: the repo's keys.py)."""
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else KEYS_PATH
    keys = load_keys_module(path)
    if keys.is_development_public_key(keys.LICENSE_PUBLIC_KEY_PEM):
        print(
            f"::error file={path}::LICENSE_PUBLIC_KEY_PEM is the development"
            " license key. Replace it with the production public key before"
            " releasing; see the gh-release skill.",
            file=sys.stderr,
        )
        return 1
    print(
        "License public key fingerprint (SHA-256):"
        f" {keys.public_key_fingerprint(keys.LICENSE_PUBLIC_KEY_PEM)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
