"""Choose the version of the release draft that Release Drafter maintains on main.

    gh api --paginate repos/OWNER/REPO/releases \\
      --jq '.[] | select(.draft | not) | select(.prerelease | not) | .tag_name' \\
      | python scripts/release_draft_version.py

Prints the bare version (for example `1.3.0`) that the draft on `main` should
carry: the larger of

- `autosecops.__version__` on this checkout, and
- the next minor version after the newest published stable release.

Release Drafter's own resolver starts from the most recently *created*
release and from `0.0.0` when there is none, so it drafted `0.1.0` while the
product was already `1.0.0`, and a hotfix published on an older train would
make it draft a version that already exists. Computing the version here keeps
the draft at or ahead of the real product version and never behind a
published release. The person cutting the release still chooses the final
version (see the gh-release skill); a breaking change can raise it to the
next major then.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERSION_FILE = REPO / "autosecops" / "__init__.py"
STABLE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
PUBLIC_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)

Version = tuple[int, int, int]


def parse_stable(tag: str) -> Version | None:
    """`(major, minor, patch)` of a bare stable version, else None."""
    match = STABLE.match(tag.strip())
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def current_version(path: Path = VERSION_FILE) -> str:
    """`__version__` of this checkout."""
    match = re.search(r'^__version__ = "([^"]+)"$', path.read_text(), re.MULTILINE)
    if match is None or not PUBLIC_VERSION.match(match.group(1)):
        raise ValueError(f"No valid __version__ in {path}")
    return match.group(1)


def draft_version(current: str, released: Iterable[str]) -> str:
    """The version the main-branch draft should carry."""
    match = PUBLIC_VERSION.match(current)
    if match is None:
        raise ValueError(f"Invalid current version: {current!r}")
    # A prerelease `__version__` (1.3.0-rc.1) is heading for its stable core.
    floor: Version = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    stable = [v for tag in released if (v := parse_stable(tag)) is not None]
    if stable:
        major, minor, _ = max(stable)
        floor = max(floor, (major, minor + 1, 0))
    return ".".join(str(part) for part in floor)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print(__doc__, file=sys.stderr)
        return 2
    print(draft_version(current_version(), sys.stdin.read().split()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
