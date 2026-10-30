#!/usr/bin/env python3
"""Issue and inspect AutoSecOps license keys (SingularityRD staff only).

Run from the repository root:

    uv run python scripts/license_tool.py keygen --out-dir ~/offline/license-keys
    uv run python scripts/license_tool.py issue \\
        --private-key ~/offline/license-keys/license-private.pem \\
        --customer "Example Corp" --expires 2027-12-31 \\
        --entitlement git_sync --entitlement rbac_addons
    uv run python scripts/license_tool.py issue \\
        --private-key ~/offline/license-keys/license-private.pem \\
        --customer "Example Corp" --plan business --add tunnels \\
        --max-users 50 --max-workspaces 5 \\
        --deployment-id dep_0123456789abcdef0123456789abcdef \\
        --ledger ~/offline/license-ledger.csv
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
import csv
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime, time, timedelta
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
from autosecops.licensing.evaluation import LICENSE_CLOCK_SKEW, evaluate_license
from autosecops.licensing.plans import (
    ISSUABLE_PLANS,
    plan_duration,
    plan_entitlements,
)
from autosecops.licensing.token import (
    encode_license,
    load_private_key,
    load_public_key,
)
from autosecops.licensing.types import (
    LicenseClaims,
    LicenseGrant,
    LicenseLimitName,
    LicenseLimits,
    LicensePlan,
    LicenseStatus,
)
from autosecops.tiers.enums import Entitlement

_PRIVATE_KEY_NAME = "license-private.pem"
_PUBLIC_KEY_NAME = "license-public.pem"

LEDGER_FIELDS = (
    "license_id",
    "customer",
    "plan",
    "issued_at",
    "expires_at",
    "deployment_id",
    "limits",
    "entitlements",
)
"""Ledger CSV columns. The token and key material are never written."""


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


def _requested_entitlements(args: argparse.Namespace) -> set[str]:
    """Combine the plan preset, explicit entitlements, and overrides."""
    requested: set[str] = set(args.entitlement or [])
    if args.plan:
        requested |= {e.value for e in plan_entitlements(LicensePlan(args.plan))}
    if args.all_entitlements:
        # Deployment grants such as multi_tenant must be named explicitly.
        requested |= {e.value for e in Entitlement}
    requested |= set(args.add or [])
    requested -= set(args.remove or [])
    return requested


def _requested_limits(args: argparse.Namespace) -> LicenseLimits | None:
    """Build limits from the ``--max-*`` flags; ``None`` when none is set."""
    values: dict[str, int] = {}
    for name in LicenseLimitName:
        # argparse stores each --max-* flag under the limit's name.
        value: int | None = vars(args)[name.value]
        if value is not None:
            values[name.value] = value
    if not values:
        return None
    return LicenseLimits.model_validate(values)


def _expiry(args: argparse.Namespace, issued_at: datetime) -> datetime:
    """``--expires`` wins; otherwise ``--days`` or the plan's default period."""
    if args.expires:
        return _parse_datetime(args.expires)
    plan = LicensePlan(args.plan) if args.plan else None
    duration = timedelta(days=args.days) if args.days else plan_duration(plan)
    return issued_at + duration


def append_ledger_row(path: Path, claims: LicenseClaims) -> None:
    """Append one row describing ``claims`` to the CSV ledger at ``path``.

    Writes a header first when the file is new or empty. Only claim metadata
    is recorded: never the signed token or any key material.
    """
    write_header = not path.exists() or path.stat().st_size == 0
    limits = claims.limits.model_dump(exclude_none=True) if claims.limits else {}
    row = {
        "license_id": claims.license_id,
        "customer": claims.customer,
        "plan": claims.plan.value if claims.plan else "",
        "issued_at": claims.issued_at.isoformat(),
        "expires_at": claims.expires_at.isoformat(),
        "deployment_id": claims.deployment_id or "",
        "limits": orjson.dumps(limits, option=orjson.OPT_SORT_KEYS).decode(),
        "entitlements": " ".join(claims.entitlements),
    }
    with path.open("a", newline="", encoding="utf-8") as ledger:
        writer = csv.DictWriter(ledger, fieldnames=LEDGER_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def _cmd_issue(args: argparse.Namespace) -> int:
    entitlement_keys = {e.value for e in Entitlement}
    known = entitlement_keys | {g.value for g in LicenseGrant}
    named = [*(args.entitlement or []), *(args.add or []), *(args.remove or [])]
    if unknown := sorted({e for e in named if e not in known}):
        print(
            f"Unknown entitlement(s): {', '.join(unknown)}."
            f" Known: {', '.join(sorted(known))}",
            file=sys.stderr,
        )
        return 2
    entitlements: list[str] = sorted(_requested_entitlements(args))

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
            expires_at=_expiry(args, issued_at),
            entitlements=entitlements,
            limits=_requested_limits(args),
            deployment_id=args.deployment_id,
            plan=LicensePlan(args.plan) if args.plan else None,
        )
    except (ValidationError, ValueError, OverflowError) as exc:
        print(f"Invalid license claims: {exc}", file=sys.stderr)
        return 2
    if issued_at - datetime.now(UTC) > LICENSE_CLOCK_SKEW:
        print(
            "Warning: issued_at is in the future; the license stays invalid until then",
            file=sys.stderr,
        )
    token = encode_license(claims, private_key)
    if args.ledger:
        try:
            append_ledger_row(Path(args.ledger).expanduser(), claims)
        except OSError as exc:
            print(f"Cannot write ledger: {exc}", file=sys.stderr)
            return 2
    print(token)
    print(
        orjson.dumps(
            claims.model_dump(mode="json", exclude_none=True),
            option=orjson.OPT_INDENT_2,
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

    # Without --deployment-id the binding is reported but not checked.
    state = evaluate_license(
        token.strip(),
        now=datetime.now(UTC),
        public_key=public_key,
        deployment_id=args.deployment_id,
        check_deployment=args.deployment_id is not None,
    )
    claims = state.claims
    # JSON report for humans and shell pipelines; a model would add nothing here.
    report = {
        "status": state.status.value,
        "error": state.error.value if state.error else None,
        "grace_ends_at": state.grace_ends_at.isoformat()
        if state.grace_ends_at
        else None,
        "plan": claims.plan.value if claims and claims.plan else None,
        "deployment_id": claims.deployment_id if claims else None,
        "limits": claims.limits.model_dump(mode="json", exclude_none=True)
        if claims and claims.limits
        else {},
        "claims": claims.model_dump(mode="json") if claims else None,
        "grants": sorted(g.value for g in state.grants),
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
        "--plan",
        choices=[p.value for p in ISSUABLE_PLANS],
        help="Plan preset that expands to its entitlement set"
        " (see autosecops/licensing/plans.py)",
    )
    validity = issue.add_mutually_exclusive_group()
    validity.add_argument(
        "--expires",
        help="YYYY-MM-DD (end of day UTC) or ISO 8601 timestamp",
    )
    validity.add_argument(
        "--days",
        type=int,
        help="Validity in days from issued_at. Defaults to 60 for pilot and"
        " 365 otherwise",
    )
    issue.add_argument("--issued-at", help="Defaults to now (UTC)")
    issue.add_argument("--license-id", help="Defaults to a random lic_<hex> id")
    issue.add_argument(
        "--entitlement",
        action="append",
        help="Entitlement key (or deployment grant such as multi_tenant) to"
        " grant; repeat for several",
    )
    issue.add_argument(
        "--all-entitlements",
        action="store_true",
        help="Grant every organization entitlement this release knows;"
        " multi_tenant still needs --entitlement multi_tenant",
    )
    issue.add_argument(
        "--add",
        action="append",
        help="Entitlement or deployment grant to add to the plan; repeatable",
    )
    issue.add_argument(
        "--remove",
        action="append",
        help="Entitlement or deployment grant to drop from the plan; repeatable",
    )
    for name in LicenseLimitName:
        issue.add_argument(
            f"--{name.value.replace('_', '-')}",
            dest=name.value,
            type=int,
            help=f"Set the {name.value} limit (positive integer)",
        )
    issue.add_argument(
        "--deployment-id",
        help="Bind the license to the installation with this deployment ID",
    )
    issue.add_argument(
        "--ledger",
        help="Append a CSV row describing the license (never the token) to"
        " this file. Keep it outside the repository",
    )
    issue.set_defaults(func=_cmd_issue)

    inspect = sub.add_parser("inspect", help="Verify a token and print its claims")
    inspect.add_argument("token", help="License token, or - to read stdin")
    inspect.add_argument(
        "--public-key",
        help="PEM public key path; defaults to the key embedded in this checkout",
    )
    inspect.add_argument(
        "--deployment-id",
        help="Also check the license's binding against this deployment ID",
    )
    inspect.set_defaults(func=_cmd_inspect)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the license tool."""
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
