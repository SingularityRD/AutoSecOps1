#!/usr/bin/env python3
"""Check Alembic topology without running env.py or connecting to a database."""

import argparse
import re
import shutil
import sys
import tempfile
import warnings
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.script.revision import RevisionError
from alembic.util import CommandError

# This merge reconciles the heads that predate the linear-history policy.
# Its ancestors can contain branches, merges and cross-branch dependencies.
LINEAR_HISTORY_BASE = "2f14222e0d12"

# The 1.1.0-alpha.2.1 release commit re-parented 9680c861644a onto
# bc3124ad3437 on its release branch only. Main kept both as siblings of
# a7c3e9f1b2d4, so databases upgraded with alpha.2.1 failed later upgrades with
# column "email_claimed_at" already exists. These one-time rewrites make main
# match the shipped graph. They become inert once the rewrite is on every base
# and may then be deleted.
AUDITED_REWRITES: Mapping[str, tuple[tuple[bytes, bytes], ...]] = {
    # #3736 (d9107f689ccf) and #3662 (e379e38b8495) both revised d45011587673
    # and merged without a rebase. Sub-cases runs after skill library installs.
    "d9107f689ccf": (
        (b"Revises: d45011587673\n", b"Revises: e379e38b8495\n"),
        (
            b'down_revision: str | None = "d45011587673"\n',
            b'down_revision: str | None = "e379e38b8495"\n',
        ),
    ),
    "9680c861644a": (
        (b"Revises: a7c3e9f1b2d4\n", b"Revises: bc3124ad3437\n"),
        (
            b'down_revision = "a7c3e9f1b2d4"\n',
            b'down_revision = "bc3124ad3437"\n',
        ),
    ),
    "b4e8f2a6c1d9": (
        (
            b"Revises: 9680c861644a, bc3124ad3437\n",
            b"Revises: 9680c861644a\n",
        ),
        (
            b'down_revision: tuple[str, str] | None = ("9680c861644a", "bc3124ad3437")\n',
            b'down_revision: str | None = "9680c861644a"\n',
        ),
    ),
    "8c0e18190001": (
        (
            b"Revises: 391f391da70b, bc3124ad3437\n",
            b"Revises: 391f391da70b\n",
        ),
        (
            b'down_revision = ("391f391da70b", "bc3124ad3437")\n',
            b'down_revision = "391f391da70b"\n',
        ),
    ),
}


# The AutoSecOps rename (phase 1) moved the Python packages `tracecat`,
# `tracecat_registry` and `tracecat_ee` to `autosecops`, `autosecops_registry`
# and `autosecops_ee`. Existing migrations import those packages, and one reads
# a data file through the package directory, so they had to change in lockstep.
# This sanctioned rewrite permits exactly that token substitution and nothing
# else: an existing migration may differ from its base only if it equals the
# base with every module-path token below rewritten. The rename is all or
# nothing per file; any other byte change still fails. It leaves SQL object
# names (such as `tracecat_case_safe_vector_v1`), environment variable names,
# URLs and marker strings such as `tracecat:` byte-identical. `tracecat_registry`
# is also the built-in registry origin, which a migration compares against, so
# the origin literal moves with the package. Once every base carries the rename,
# rewriting a base is a no-op and this rule is inert; it may then be deleted.
MODULE_RENAME_REWRITES: tuple[tuple[re.Pattern[bytes], bytes], ...] = (
    # Dotted module paths: `from tracecat.db import x`, `tracecat.db.models`.
    (re.compile(rb"(?<![\w.\-/@])tracecat(?=\.[A-Za-z_])"), b"autosecops"),
    # Bare package imports: `import tracecat`, `from tracecat import x`.
    (
        re.compile(rb"^(\s*(?:from|import)\s+)tracecat(?=[ \t,\n])", re.MULTILINE),
        rb"\1autosecops",
    ),
    # Package directory path segments: `tracecat/agent/...`.
    (re.compile(rb"(?<![\w.\-/@:])tracecat(?=/)"), b"autosecops"),
    # Quoted path segments: `Path(...) / "tracecat" / "agent"`.
    (re.compile(rb'(?<=/ )"tracecat"(?= /)'), b'"autosecops"'),
    # Sibling packages: `tracecat_registry`, `tracecat_ee` as whole tokens.
    (
        re.compile(rb"(?<![\w.\-])tracecat_(registry|ee)(?![\w\-])"),
        rb"autosecops_\1",
    ),
)


def rename_module_paths(content: bytes) -> bytes:
    """Apply the sanctioned AutoSecOps module-path rename to migration bytes."""
    for pattern, replacement in MODULE_RENAME_REWRITES:
        content = pattern.sub(replacement, content)
    return content


def _matches_base(current: bytes, expected: bytes) -> bool:
    """Whether current is the expected bytes, as-is or with the module rename."""
    return current == expected or current == rename_module_paths(expected)


@contextmanager
def importable_base(base_dir: str) -> Iterator[ScriptDirectory]:
    """Load a base Alembic directory whose revisions may import pre-rename packages.

    Alembic executes each revision module to read its metadata, and base revisions
    written before the rename import `tracecat`, which no longer exists. Load them
    from a temporary copy with `rename_module_paths` applied. Revision metadata is
    unaffected by the rename; byte comparisons still use the original base files
    through `base_source_dir`.
    """
    with tempfile.TemporaryDirectory(prefix="alembic-base-") as tmp:
        copy = Path(tmp) / "alembic"
        shutil.copytree(base_dir, copy)
        for path in copy.rglob("*.py"):
            path.write_bytes(rename_module_paths(path.read_bytes()))
        yield ScriptDirectory(str(copy))


def check_migrations(
    scripts: ScriptDirectory,
    *,
    linear_since: str = LINEAR_HISTORY_BASE,
    base: ScriptDirectory | None = None,
    base_source_dir: Path | None = None,
    audited_rewrites: Mapping[str, tuple[tuple[bytes, bytes], ...]] = AUDITED_REWRITES,
) -> str:
    """Return the sole head, rejecting invalid graphs and new non-linear history.

    When `base` was loaded from a rewritten copy (see `importable_base`),
    `base_source_dir` is the original base directory whose bytes are compared.
    """
    # Alembic warns rather than fails for some invalid metadata (e.g. duplicate
    # revision IDs). Those must fail CI too.
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        heads = scripts.get_heads()
        if len(heads) != 1:
            raise ValueError(
                f"Expected exactly one Alembic head; found {len(heads)}: {heads}. "
                "Rebase unmerged migrations onto the latest head."
            )
        bases = scripts.get_bases()
        if len(bases) != 1:
            raise ValueError(f"Expected exactly one Alembic base; found {bases}.")

        revisions = list(scripts.walk_revisions())
        if base is not None:
            candidate = {revision.revision: revision for revision in revisions}
            for previous in base.walk_revisions():
                current = candidate.get(previous.revision)
                if current is None:
                    raise ValueError(
                        f"Existing revision {previous.revision} was removed or renamed."
                    )
                # Use declared metadata: Alembic's branch_labels attribute also
                # includes labels inherited from other revisions in the graph.
                audited_rewrite = audited_rewrites.get(previous.revision)
                fields = (
                    ("depends_on", "branch_labels")
                    if audited_rewrite is not None
                    else ("down_revision", "depends_on", "branch_labels")
                )
                for field in fields:
                    if getattr(current.module, field, None) != getattr(
                        previous.module, field, None
                    ):
                        raise ValueError(
                            f"Existing revision {previous.revision} changed {field}. "
                            "New migrations must extend the previous head without "
                            "rewriting existing revision metadata."
                        )
                current_bytes = Path(current.path).read_bytes()
                base_path = Path(previous.path)
                if base_source_dir is not None and base is not None:
                    base_path = base_source_dir / base_path.relative_to(base.dir)
                base_bytes = base_path.read_bytes()
                if audited_rewrite is not None:
                    expected_bytes = base_bytes
                    for old_line, new_line in audited_rewrite:
                        old_count = expected_bytes.count(old_line)
                        if old_count == 1:
                            expected_bytes = expected_bytes.replace(
                                old_line, new_line, 1
                            )
                        elif old_count == 0 and expected_bytes.count(new_line) == 1:
                            continue
                        else:
                            raise ValueError(
                                f"The audited rewrite for {previous.revision} no "
                                "longer matches the base file."
                            )
                    if not _matches_base(current_bytes, expected_bytes):
                        raise ValueError(
                            f"Existing revision {previous.revision} changed file "
                            "contents beyond its audited rewrite."
                        )
                elif not _matches_base(current_bytes, base_bytes):
                    raise ValueError(
                        f"Existing revision {previous.revision} changed file contents. "
                        "Existing migration files are immutable, including formatting; "
                        "put new operations in a new revision."
                    )
        historical = {
            revision.revision for revision in scripts.walk_revisions(head=linear_since)
        }
        for revision in revisions:
            if revision.revision in historical:
                continue
            if not isinstance(revision.down_revision, str):
                raise ValueError(
                    f"Revision {revision.revision} must have exactly one parent; "
                    f"found {revision.down_revision!r}. New merge revisions are "
                    f"not allowed after {linear_since}."
                )
            if revision.dependencies:
                raise ValueError(
                    f"Revision {revision.revision} uses depends_on; "
                    "new migrations must form a single down_revision chain."
                )
        return heads[0]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-dir",
        help="Base checkout's Alembic directory; also reject changes to existing revisions.",
    )
    args = parser.parse_args(argv)
    try:
        scripts = ScriptDirectory.from_config(Config("alembic.ini"))
        if args.base_dir is None:
            head = check_migrations(scripts)
        else:
            # Fail fast on a missing base, as ScriptDirectory would.
            ScriptDirectory(args.base_dir)
            with importable_base(args.base_dir) as base:
                head = check_migrations(
                    scripts, base=base, base_source_dir=Path(args.base_dir)
                )
    except (
        ValueError,
        KeyError,
        OSError,
        CommandError,
        RevisionError,
        UserWarning,
    ) as exc:
        print(f"Alembic migration history check failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Alembic migration history OK: one head ({head}), linear after {LINEAR_HISTORY_BASE}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
