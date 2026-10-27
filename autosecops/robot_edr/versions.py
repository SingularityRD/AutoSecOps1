"""Ordering of RoboDR release versions (`robodr.fleet` §7 ``min_version``).

The robot compares releases as dpkg does (its installed release is dpkg's
record of the package), so the SOC orders ``min_version`` the same way:
Debian version comparison of ``upstream[-revision]`` (the contract's version
syntax ``[0-9][0-9A-Za-z.+~-]{0,63}`` has no epoch).
"""

from __future__ import annotations


def _order(char: str) -> int:
    """dpkg's character weight: ``~`` sorts before everything, even the end."""
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    """dpkg ``verrevcmp`` of one upstream or revision part."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (
            j < len(b) and not b[j].isdigit()
        ):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare_versions(a: str, b: str) -> int:
    """Negative, zero or positive as release ``a`` sorts before, with or after ``b``."""
    a_upstream, _, a_revision = a.rpartition("-") if "-" in a else (a, "", "")
    b_upstream, _, b_revision = b.rpartition("-") if "-" in b else (b, "", "")
    return _compare_part(a_upstream, b_upstream) or _compare_part(
        a_revision, b_revision
    )
