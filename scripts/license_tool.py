#!/usr/bin/env python3
"""Issue and inspect AutoSecOps license keys (SingularityRD staff only).

Run from the repository root:

    uv run python scripts/license_tool.py keygen --out-dir ~/offline/license-keys
    uv run python scripts/license_tool.py issue \\
        --private-key ~/offline/license-keys/license-private.pem \\
        --customer "Example Corp" --expires 2027-12-31 \\
        --entitlement git_sync --entitlement rbac_addons
    uv run python scripts/license_tool.py inspect "<token>"

Keep the private key offline. The public key that verifies licenses is embedded
in ``autosecops/licensing/keys.py``; a key printed by ``keygen`` must replace it
before a release for licenses signed with that keygen's private key to verify.

Exit codes:
    0  success (``inspect``: the license is valid or in its grace period)
    1  ``inspect``: the license is invalid or expired past its grace period
    2  the invocation is broken (bad arguments or key files)
"""

from __future__ import annotations

import argparse
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime, time
from pathlib import Path

import orjson
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import ValidationError

from autosecops.licensing import keys
from autosecops.licensing.service import evaluate_license
from autosecops.licensing.token import (
    encode_license,
    load_private_key,
    load_public_key,
)
from autosecops.licensing.types import LicenseClaims, LicenseStatus
from autosecops.tiers.enums import Entitlement

_PRIVATE_KEY_NAME = "license-private.pem"
_PUBLIC_KEY_NAME = "license-public.pem"


def _parse_datetime(value: str) -> datetime:
    """Parse ``YYYY-MM-DD`` (end of that day, UTC) or an ISO 8601 timestamp."""
    try:
        day = date.fromisoformat(value)
    except ValueError:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return datetime.combine(day, time(23, 59, 59), tzinfo=UTC)


def _cmd_keygen(args: argparse.Namespace) -> int:
    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path = out_dir / _PRIVATE_KEY_NAME
    public_path = out_dir / _PUBLIC_KEY_NAME
    if private_path.exists() and not args.force:
        print(f"Refusing to overwrite {private_path}; pass --force", file=sys.stderr)
        return 2

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    private_path.touch(mode=0o600, exist_ok=True)
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    print(f"Wrote {private_path} (keep offline) and {public_path}", file=sys.stderr)
    print("Paste this into autosecops/licensing/keys.py LICENSE_PUBLIC_KEY_PEM:")
    print(public_pem.decode("ascii"), end="")
    return 0


def _cmd_issue(args: argparse.Namespace) -> int:
    known = {e.value for e in Entitlement}
    entitlements: list[str] = sorted(set(args.entitlement or []))
    if args.all_entitlements:
        entitlements = sorted(known)
    if unknown := [e for e in entitlements if e not in known]:
        print(
            f"Unknown entitlement(s): {', '.join(unknown)}."
            f" Known: {', '.join(sorted(known))}",
            file=sys.stderr,
        )
        return 2

    try:
        private_key = load_private_key(Path(args.private_key).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        print(f"Cannot load private key: {exc}", file=sys.stderr)
        return 2

    issued_at = (
        _parse_datetime(args.issued_at)
        if args.issued_at
        else datetime.now(UTC).replace(microsecond=0)
    )
    try:
        claims = LicenseClaims(
            license_id=args.license_id or f"lic_{uuid.uuid4().hex}",
            customer=args.customer,
            issued_at=issued_at,
            expires_at=_parse_datetime(args.expires),
            entitlements=entitlements,
        )
    except (ValidationError, ValueError) as exc:
        print(f"Invalid license claims: {exc}", file=sys.stderr)
        return 2
    print(encode_license(claims, private_key))
    print(
        orjson.dumps(
            claims.model_dump(mode="json"), option=orjson.OPT_INDENT_2
        ).decode(),
        file=sys.stderr,
    )
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    token: str = sys.stdin.read() if args.token == "-" else args.token
    pem = (
        Path(args.public_key).read_bytes()
        if args.public_key
        else keys.LICENSE_PUBLIC_KEY_PEM
    )
    try:
        public_key = load_public_key(pem)
    except ValueError as exc:
        print(f"Cannot load public key: {exc}", file=sys.stderr)
        return 2

    state = evaluate_license(
        token.strip(), now=datetime.now(UTC), public_key=public_key
    )
    # JSON report for humans and shell pipelines; a model would add nothing here.
    report = {
        "status": state.status.value,
        "error": state.error.value if state.error else None,
        "grace_ends_at": state.grace_ends_at.isoformat()
        if state.grace_ends_at
        else None,
        "claims": state.claims.model_dump(mode="json") if state.claims else None,
        "unknown_entitlements": list(state.unknown_entitlements),
    }
    print(orjson.dumps(report, option=orjson.OPT_INDENT_2).decode())
    healthy = state.status in (LicenseStatus.VALID, LicenseStatus.GRACE)
    return 0 if healthy else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate an Ed25519 signing keypair")
    keygen.add_argument("--out-dir", type=Path, required=True)
    keygen.add_argument("--force", action="store_true")
    keygen.set_defaults(func=_cmd_keygen)

    issue = sub.add_parser("issue", help="Sign a license and print the token")
    issue.add_argument("--private-key", required=True, help="PEM Ed25519 key path")
    issue.add_argument("--customer", required=True)
    issue.add_argument(
        "--expires",
        required=True,
        help="YYYY-MM-DD (end of day UTC) or ISO 8601 timestamp",
    )
    issue.add_argument("--issued-at", help="Defaults to now (UTC)")
    issue.add_argument("--license-id", help="Defaults to a random lic_<hex> id")
    issue.add_argument(
        "--entitlement",
        action="append",
        help="Entitlement key to grant; repeat for several",
    )
    issue.add_argument(
        "--all-entitlements",
        action="store_true",
        help="Grant every entitlement this release knows",
    )
    issue.set_defaults(func=_cmd_issue)

    inspect = sub.add_parser("inspect", help="Verify a token and print its claims")
    inspect.add_argument("token", help="License token, or - to read stdin")
    inspect.add_argument(
        "--public-key",
        help="PEM public key path; defaults to the key embedded in this checkout",
    )
    inspect.set_defaults(func=_cmd_inspect)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the license tool."""
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
