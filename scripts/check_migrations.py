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
        # Rebrand: the operator-facing pgvector hints pointed at the upstream
        # docs site. Only the hint URLs change; the SQL is otherwise identical.
        (
            b"                HINT = 'For pgvector installation and permissions, "
            b"see https://docs.tracecat.com/self-hosting/pgvector';\n",
            b"                HINT = 'For pgvector installation and permissions, "
            b"see https://docs.singularityrd.com/self-hosting/pgvector';\n",
        ),
        (
            b"                    USING HINT = 'For pgvector version and schema "
            b"requirements, see https://docs.tracecat.com/self-hosting/pgvector';\n",
            b"                    USING HINT = 'For pgvector version and schema "
            b"requirements, see https://docs.singularityrd.com/self-hosting/pgvector';\n",
        ),
        (
            (
                b"extension if needed; its role needs permission to do so. Downgrade removes only\n"
            ),
            (
                b"extension if needed; its role needs permission to do so. An existing extension\n"
                b"stays in its schema, which must be on the search_path. A new one goes in public,\n"
                b"or in ibm_extension on IBM Cloud Databases for PostgreSQL, which only allows\n"
                b"extensions in that read-only, provider-managed schema. Downgrade removes only\n"
            ),
        ),
        (
            (
                b"        DO $$ BEGIN\n"
                b"            CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;\n"
            ),
            (
                b"        DO $$ BEGIN\n"
                b"            IF EXISTS (SELECT FROM pg_extension WHERE extname = 'vector') THEN\n"
                b"                NULL;\n"
                b"            ELSIF to_regnamespace('ibm_extension') IS NOT NULL THEN\n"
                b"                -- IBM's documented form; IBM places it in ibm_extension.\n"
                b"                CREATE EXTENSION IF NOT EXISTS vector;\n"
                b"            ELSE\n"
                b"                CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;\n"
                b"            END IF;\n"
            ),
        ),
        (
            (
                b"                WHERE e.extname = 'vector' AND n.nspname = 'public'\n"
                b"                  AND string_to_array(e.extversion, '.')::int[] >= ARRAY[0,8,0]\n"
                b"            ) THEN\n"
                b"                RAISE EXCEPTION 'Tracecat requires pgvector >= 0.8.0 in the public schema'\n"
            ),
            (
                b"                WHERE e.extname = 'vector' AND n.nspname = ANY(current_schemas(false))\n"
                b"                  AND string_to_array(e.extversion, '.')::int[] >= ARRAY[0,8,0]\n"
                b"            ) THEN\n"
                b"                RAISE EXCEPTION 'AutoSecOps requires pgvector >= 0.8.0 in a schema on the search_path'\n"
            ),
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
    # IBM Cloud Databases for PostgreSQL only allows extensions in its
    # read-only ibm_extension schema. These rewrites install pg_trgm there when
    # that schema exists (the 9680c861644a pairs above do the same for
    # pgvector), keep an existing extension in its schema, and look up
    # pg_trgm's schema instead of assuming public.
    "3e54217aadda": (
        (
            (
                b"preinstalled by an administrator. Downgrade retains this shared dependency.\n"
            ),
            (
                b"preinstalled by an administrator. An existing extension stays in its schema. A\n"
                b"new one goes in public, or in ibm_extension on IBM Cloud Databases for\n"
                b"PostgreSQL, which only allows extensions in that read-only, provider-managed\n"
                b"schema. Downgrade retains this shared dependency.\n"
            ),
        ),
        (
            (
                b"            CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;\n"
                b"        EXCEPTION WHEN insufficient_privilege THEN\n"
                b"            RAISE EXCEPTION 'Cannot install pg_trgm with the current role'\n"
                b"                USING ERRCODE = 'insufficient_privilege', DETAIL = SQLERRM,\n"
                b"                      HINT = 'Ask an authorized administrator to preinstall pg_trgm in public, then rerun migrations. On RDS, also check rds.allowed_extensions. The migration does not grant privileges.';\n"
            ),
            (
                b"            IF EXISTS (SELECT FROM pg_catalog.pg_extension WHERE extname = 'pg_trgm') THEN\n"
                b"                NULL;\n"
                b"            ELSIF pg_catalog.to_regnamespace('ibm_extension') IS NOT NULL THEN\n"
                b"                -- IBM's documented form; IBM places it in ibm_extension.\n"
                b"                CREATE EXTENSION IF NOT EXISTS pg_trgm;\n"
                b"            ELSE\n"
                b"                CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;\n"
                b"            END IF;\n"
                b"        EXCEPTION WHEN insufficient_privilege THEN\n"
                b"            RAISE EXCEPTION 'Cannot install pg_trgm with the current role'\n"
                b"                USING ERRCODE = 'insufficient_privilege', DETAIL = SQLERRM,\n"
                b"                      HINT = 'Ask an authorized administrator to preinstall pg_trgm in public (ibm_extension on IBM Cloud), then rerun migrations. On RDS, also check rds.allowed_extensions. The migration does not grant privileges.';\n"
            ),
        ),
        (
            (
                b"            IF extension_schema <> 'public' THEN\n"
                b"                RAISE EXCEPTION 'pg_trgm must be installed in the public schema'\n"
                b"                    USING ERRCODE = 'object_not_in_prerequisite_state',\n"
                b"                          HINT = 'Ask the database administrator to review the existing extension schema. This migration does not relocate, upgrade or drop extensions.';\n"
                b"            END IF;\n"
                b"            IF NOT pg_catalog.has_schema_privilege('public', 'USAGE') THEN\n"
                b"                RAISE EXCEPTION 'The current role needs USAGE on the public schema'\n"
                b"                    USING ERRCODE = 'insufficient_privilege',\n"
                b"                          HINT = 'Ask the database administrator to grant USAGE on schema public to the application and migration roles.';\n"
            ),
            (
                b"            IF NOT pg_catalog.has_schema_privilege(extension_schema, 'USAGE') THEN\n"
                b"                RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege',\n"
                b"                    MESSAGE = 'The current role needs USAGE on the ' || extension_schema || ' schema',\n"
                b"                    HINT = 'Ask the database administrator to grant USAGE on schema ' || quote_ident(extension_schema) || ' to the application and migration roles.';\n"
            ),
        ),
        (
            (
                b"                  AND n.nspname = 'public' AND c.opcintype = 'text'::regtype\n"
                b"            ) THEN\n"
                b"                RAISE EXCEPTION 'pg_trgm must provide public.gin_trgm_ops for text'\n"
                b"                    USING ERRCODE = 'object_not_in_prerequisite_state',\n"
                b"                          HINT = 'Ask the database administrator to repair the extension-owned GIN operator class. A same-named unrelated operator class is not supported.';\n"
                b"            END IF;\n"
                b"\n"
                b"            similarity_oid := pg_catalog.to_regprocedure('public.similarity(text,text)');\n"
                b"            IF similarity_oid IS NULL OR NOT EXISTS (\n"
                b"                SELECT FROM pg_catalog.pg_depend\n"
                b"                WHERE classid = 'pg_proc'::regclass AND objid = similarity_oid\n"
                b"                  AND deptype = 'e' AND refclassid = 'pg_extension'::regclass\n"
                b"                  AND refobjid = extension_oid\n"
                b"            ) THEN\n"
                b"                RAISE EXCEPTION 'pg_trgm must provide public.similarity(text,text)'\n"
                b"                    USING ERRCODE = 'object_not_in_prerequisite_state',\n"
                b"                          HINT = 'Ask the database administrator to repair the extension-owned similarity function. A same-named unrelated function is not supported.';\n"
                b"            END IF;\n"
                b"            IF NOT pg_catalog.has_function_privilege(similarity_oid, 'EXECUTE') THEN\n"
                b"                RAISE EXCEPTION 'The current role needs EXECUTE on public.similarity(text,text)'\n"
                b"                    USING ERRCODE = 'insufficient_privilege',\n"
                b"                          HINT = 'Ask the database administrator to grant EXECUTE on the pg_trgm functions used by search to the application and migration roles.';\n"
                b"            END IF;\n"
                b"        END\n"
                b"        $$;\n"
                b'    """)\n'
                b"\n"
                b'    op.execute("""\n'
                b"        SELECT public.similarity('synthetic search'::text, 'synthetic search'::text);\n"
            ),
            (
                b"                  AND n.nspname = extension_schema AND c.opcintype = 'text'::regtype\n"
                b"            ) THEN\n"
                b"                RAISE EXCEPTION USING ERRCODE = 'object_not_in_prerequisite_state',\n"
                b"                    MESSAGE = 'pg_trgm must provide ' || extension_schema || '.gin_trgm_ops for text',\n"
                b"                    HINT = 'Ask the database administrator to repair the extension-owned GIN operator class. A same-named unrelated operator class is not supported.';\n"
                b"            END IF;\n"
                b"\n"
                b"            similarity_oid := pg_catalog.to_regprocedure(\n"
                b"                quote_ident(extension_schema) || '.similarity(text,text)'\n"
                b"            );\n"
                b"            IF similarity_oid IS NULL OR NOT EXISTS (\n"
                b"                SELECT FROM pg_catalog.pg_depend\n"
                b"                WHERE classid = 'pg_proc'::regclass AND objid = similarity_oid\n"
                b"                  AND deptype = 'e' AND refclassid = 'pg_extension'::regclass\n"
                b"                  AND refobjid = extension_oid\n"
                b"            ) THEN\n"
                b"                RAISE EXCEPTION USING ERRCODE = 'object_not_in_prerequisite_state',\n"
                b"                    MESSAGE = 'pg_trgm must provide ' || extension_schema || '.similarity(text,text)',\n"
                b"                    HINT = 'Ask the database administrator to repair the extension-owned similarity function. A same-named unrelated function is not supported.';\n"
                b"            END IF;\n"
                b"            IF NOT pg_catalog.has_function_privilege(similarity_oid, 'EXECUTE') THEN\n"
                b"                RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege',\n"
                b"                    MESSAGE = 'The current role needs EXECUTE on ' || extension_schema || '.similarity(text,text)',\n"
                b"                    HINT = 'Ask the database administrator to grant EXECUTE on the pg_trgm functions used by search to the application and migration roles.';\n"
                b"            END IF;\n"
                b"\n"
                b"            EXECUTE 'SELECT ' || quote_ident(extension_schema) || '.similarity($1, $2)'\n"
                b"                USING 'synthetic search'::text, 'synthetic search'::text;\n"
                b"        END\n"
                b"        $$;\n"
            ),
        ),
    ),
    "e2018a1b2c3d": (
        (
            (
                b"The preceding shared migration enables pg_trgm in public when permitted;\n"
            ),
            (
                b"The preceding shared migration enables pg_trgm in public (ibm_extension on IBM\n"
                b"Cloud) when permitted, and keeps an existing extension in its schema;\n"
            ),
        ),
        (
            (
                b"            f\"lower(CASE WHEN octet_length(coalesce({field}::text, '')) <= {_DOCUMENT_BYTES} THEN coalesce({field}::text, '') ELSE '' END) public.gin_trgm_ops\",\n"
            ),
            (
                b"            f\"lower(CASE WHEN octet_length(coalesce({field}::text, '')) <= {_DOCUMENT_BYTES} THEN coalesce({field}::text, '') ELSE '' END) {{trgm_schema}}.gin_trgm_ops\",\n"
            ),
        ),
        (
            (b"            AND o.opcname = :opclass AND n.nspname = :opclass_schema\n"),
            (
                b"            AND o.opcname = :opclass AND n.nspname = CASE WHEN :is_fts\n"
                b"                THEN 'pg_catalog' ELSE (SELECT en.nspname FROM pg_extension e\n"
                b"                    JOIN pg_namespace en ON en.oid = e.extnamespace\n"
                b"                    WHERE e.extname = 'pg_trgm') END\n"
            ),
        ),
        (
            (
                b'                "opclass": "tsvector_ops" if is_fts else "gin_trgm_ops",\n'
                b'                "opclass_schema": "pg_catalog" if is_fts else "public",\n'
            ),
            (
                b'                "opclass": "tsvector_ops" if is_fts else "gin_trgm_ops",\n'
            ),
        ),
        (
            (
                b"            IF NOT EXISTS (\n"
                b"                SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace\n"
                b"                WHERE e.extname = 'pg_trgm' AND n.nspname = 'public'\n"
                b"            ) THEN\n"
                b"                RAISE EXCEPTION 'Case text search requires pg_trgm in the public schema'\n"
                b"                    USING HINT = 'Run the shared scripts/postgres/pg-trgm.sql check as the migration role and ask an operator to provision pg_trgm in public before retrying.';\n"
                b"            END IF;\n"
                b"        END\n"
                b"        $$\n"
                b'        """\n'
            ),
            (
                b"            IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN\n"
                b"                RAISE EXCEPTION 'Case text search requires pg_trgm to be enabled'\n"
                b"                    USING HINT = 'Run the shared scripts/postgres/pg-trgm.sql check as the migration role and ask an operator to provision pg_trgm in public (ibm_extension on IBM Cloud) before retrying.';\n"
                b"            END IF;\n"
                b"        END\n"
                b"        $$\n"
                b'        """\n'
                b"    )\n"
                b"    # pg_trgm is in public, or ibm_extension on IBM Cloud; regnamespace quotes it.\n"
                b"    trgm_schema = op.get_bind().scalar(\n"
                b"        sa.text(\n"
                b"            \"SELECT extnamespace::regnamespace::text FROM pg_extension WHERE extname = 'pg_trgm'\"\n"
                b"        )\n"
            ),
        ),
        (
            (
                b'                f\'CREATE INDEX CONCURRENTLY IF NOT EXISTS "{name}" ON public."case" USING gin ({expression})\'\n'
            ),
            (
                b'                f\'CREATE INDEX CONCURRENTLY IF NOT EXISTS "{name}" ON public."case" USING gin ({expression.format(trgm_schema=trgm_schema)})\'\n'
            ),
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
