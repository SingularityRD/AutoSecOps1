"""Air-gap guards for the bundled MCP catalog.

The catalog must render without contacting third-party hosts: provider icons
ship inside the UI bundle and catalog rows carry no remote icon URLs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import orjson

REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_CATALOG = REPO_ROOT / "autosecops/integrations/catalog/mcp_catalog.json"
CATALOG_ICONS = REPO_ROOT / "frontend/src/components/mcp-catalog-icons.tsx"


def _servers() -> list[dict[str, Any]]:
    return orjson.loads(PUBLIC_CATALOG.read_bytes())["servers"]


def _embedded_icon_keys() -> set[str]:
    return set(
        re.findall(
            r"^  ([a-z0-9_]+): createEmbeddedCatalogIcon\(",
            CATALOG_ICONS.read_text(),
            flags=re.MULTILINE,
        )
    )


def _icon_candidates(slug: str) -> list[str]:
    """Mirror the slug lookup in `getMcpProviderIconId` (frontend icons.tsx)."""
    underscored = slug.lower().replace("-", "_")
    candidates = [underscored]
    if match := re.match(r"^(.*?)(?:_?mcp)$", underscored):
        base = match.group(1)
        candidates += [f"{base}_mcp", f"{base.replace('_', '')}_mcp"]
    else:
        candidates += [f"{underscored}_mcp", f"{underscored.replace('_', '')}_mcp"]
    return candidates


def test_public_catalog_rows_carry_no_remote_icon_urls() -> None:
    remote = [
        server["slug"]
        for server in _servers()
        if re.match(r"(?i)^(https?:)?//", str(server.get("icon") or ""))
    ]
    assert not remote, f"Catalog rows must not reference remote icons: {remote}"


def test_public_catalog_has_no_third_party_icon_hosts() -> None:
    raw = PUBLIC_CATALOG.read_text()
    for host in (
        "google.com/s2/favicons",
        "simpleicons.org",
        "raw.githubusercontent.com",
        "upload.wikimedia.org",
        "res.cdn.office.net",
    ):
        assert host not in raw


def test_every_catalog_row_has_a_bundled_icon() -> None:
    keys = _embedded_icon_keys()
    assert keys, "No embedded catalog icons found"
    missing = [
        server["slug"]
        for server in _servers()
        if not any(candidate in keys for candidate in _icon_candidates(server["slug"]))
    ]
    assert not missing, f"Add a bundled icon to mcp-catalog-icons.tsx for: {missing}"


def test_bundled_icons_are_inline_data_uris() -> None:
    source = CATALOG_ICONS.read_text()
    hrefs = re.findall(r'createEmbeddedCatalogIcon\(\s*"([^"]+)"', source)
    assert hrefs
    assert all(href.startswith("data:image/") for href in hrefs)
