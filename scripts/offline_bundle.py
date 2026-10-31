"""Build the AutoSecOps offline (air-gapped) installation bundle.

    uv run python scripts/offline_bundle.py --version 1.2.3
    uv run python scripts/offline_bundle.py --version 1.2.3 --dry-run
    just offline-bundle 1.2.3

Run it from a checkout of the release tag: the Compose files, Helm chart, and
image list come from this checkout, and the script refuses a version that
differs from `autosecops.__version__` unless `--allow-version-mismatch` is set.

The bundle is `autosecops-offline-<version>.tar.zst` (or `.tar.gz` without
`zstd`) and holds:

- every image the Compose stack and the Helm chart run, pulled for one
  platform, pinned to the digest resolved at build time, and written with
  `docker save` to `images/`;
- `images.txt`, a tab-separated manifest of every image;
- the Compose install files in `install/` and the packaged chart in `charts/`;
- `load-images.sh`, the customer-side helper that verifies, loads, and pushes
  the images (`scripts/offline_bundle_load.sh`);
- `THIRD_PARTY_NOTICES/`, `README.md`, and `SHA256SUMS`.

Image pulls use the Docker credentials already configured on this machine
(`docker login ghcr.io` for private images); the script never reads or prints
them. When `OFFLINE_BUNDLE_COSIGN_KEY` or `OFFLINE_BUNDLE_MINISIGN_KEY` names a
signing key, the script signs `SHA256SUMS` and the archive checksum with it.
`--require-signature` refuses to build without one; release builds use it.

Next to the archive the script writes `<archive>.sha256`, a copy of the
bundle's `SHA256SUMS` as `autosecops-offline-<version>.SHA256SUMS`, and their
signatures. These small files identify the bundle without carrying any image,
so they can be published where the bundle itself cannot.

`--dry-run` resolves the image list and stages every file except the image
archives, without calling Docker or writing the archive.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO / "docker-compose.yml"
CHART_DIR = REPO / "deployments" / "helm" / "autosecops"
CHART_VALUES = CHART_DIR / "values.yaml"
LOAD_SCRIPT = REPO / "scripts" / "offline_bundle_load.sh"
VERSION_FILE = REPO / "autosecops" / "__init__.py"

# The files the API image ships in /opt/autosecops/install (see Dockerfile).
INSTALL_FILES = (
    "docker-compose.yml",
    "docker-compose.sandbox.yml",
    "Caddyfile",
    ".env.example",
    "env.sh",
    "env-migration.sh",
    "backup_compose.sh",
    "restore_compose.sh",
    "support_bundle.sh",
)
# Install files whose source is not at the repository root.
INSTALL_SOURCES = {
    "backup_compose.sh": REPO / "scripts" / "backup_compose.sh",
    "restore_compose.sh": REPO / "scripts" / "restore_compose.sh",
    "support_bundle.sh": REPO / "scripts" / "support_bundle.sh",
}
NOTICE_FILES = {
    "autosecops.md": REPO / "THIRD_PARTY_NOTICES.md",
    "autosecops-ui.md": REPO / "frontend" / "THIRD_PARTY_NOTICES.md",
}

# Images the Helm chart runs, by values path. The chart's images default to the
# chart appVersion, which equals the release version.
HELM_IMAGE_VALUES = (
    ("image", "repository"),
    ("uiImage", "repository"),
    ("tunnels", "gateway", "image", "repository"),
)

FIRST_PARTY_PREFIX = "ghcr.io/singularityrd/"


@dataclass(frozen=True, slots=True)
class UpstreamLicense:
    """License of a third-party image the bundle redistributes."""

    license: str
    source: str


# Every third-party image in the bundle needs an entry: the bundler stops on an
# image without one, so a new Compose service cannot ship without its notice.
THIRD_PARTY_LICENSES: dict[str, UpstreamLicense] = {
    "caddy": UpstreamLicense("Apache-2.0", "https://github.com/caddyserver/caddy"),
    "postgres": UpstreamLicense(
        "PostgreSQL License", "https://www.postgresql.org/about/licence/"
    ),
    "temporalio/auto-setup": UpstreamLicense(
        "MIT", "https://github.com/temporalio/temporal"
    ),
    "temporalio/ui": UpstreamLicense("MIT", "https://github.com/temporalio/ui"),
    # Chainguard builds MinIO from its own fork (upstream minio/minio is no
    # longer maintained), so the corresponding source for the shipped binary is
    # the fork plus the Wolfi package recipe, not upstream.
    "cgr.dev/chainguard/minio": UpstreamLicense(
        "AGPL-3.0-or-later",
        "https://github.com/chainguard-forks/minio, built by "
        "https://github.com/wolfi-dev/os/blob/main/minio.yaml",
    ),
    # Valkey, not Redis: Redis 7.4 and later are RSALv2/SSPLv1, which the bundle
    # must not redistribute. Without a `redis` entry the bundler refuses one.
    "valkey/valkey": UpstreamLicense(
        "BSD-3-Clause", "https://github.com/valkey-io/valkey"
    ),
}


def upstream_license(ref: ImageRef) -> UpstreamLicense | None:
    """License entry for a third-party image, also when it comes from a mirror."""
    if entry := THIRD_PARTY_LICENSES.get(ref.name):
        return entry
    for name, entry in THIRD_PARTY_LICENSES.items():
        if ImageRef.parse(name).path == ref.path:
            return entry
    return None


_VAR_PATTERN = re.compile(
    r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:(?P<op>:?-)(?P<default>[^}]*))?\}"
)
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")


class BundleError(RuntimeError):
    """A bundle input is invalid or a build step failed."""


@dataclass(frozen=True, slots=True)
class ImageRef:
    """A parsed image reference: `name[:tag][@digest]`."""

    name: str
    tag: str | None
    digest: str | None

    @classmethod
    def parse(cls, ref: str) -> ImageRef:
        """Split a reference into name, tag, and digest."""
        rest, _, digest = ref.partition("@")
        last_slash = rest.rfind("/")
        colon = rest.rfind(":")
        tag: str | None = None
        if colon > last_slash:
            rest, tag = rest[:colon], rest[colon + 1 :]
        if not rest or (digest and not _DIGEST_PATTERN.match(digest)):
            raise BundleError(f"Invalid image reference: {ref}")
        return cls(name=rest, tag=tag or None, digest=digest or None)

    def __str__(self) -> str:
        ref = self.name
        if self.tag:
            ref += f":{self.tag}"
        if self.digest:
            ref += f"@{self.digest}"
        return ref

    @property
    def path(self) -> str:
        """Repository path without the registry host (`temporalio/ui`)."""
        first, sep, rest = self.name.partition("/")
        if sep and ("." in first or ":" in first or first == "localhost"):
            return rest
        return self.name

    @property
    def is_first_party(self) -> bool:
        """Whether SingularityRD publishes this image."""
        return self.name.startswith(FIRST_PARTY_PREFIX)


@dataclass(frozen=True, slots=True)
class BundleImage:
    """One image in the bundle and the settings that select it."""

    source: ImageRef
    # Compose variable that selects the image, and whether it holds the full
    # reference (`full`) or only the repository (`repository`).
    compose_var: str | None = None
    compose_kind: str | None = None
    helm_value: str | None = None
    digest: str | None = None

    @property
    def bundle_ref(self) -> str:
        """Tagged reference the image carries after `docker load`.

        A digest-pinned reference loses its digest on `docker load` with the
        classic image store, so the bundle tags it with a name that includes
        the digest instead.
        """
        if self.source.digest is None:
            return f"{self.source.name}:{self.source.tag or 'latest'}"
        short = self.source.digest.removeprefix("sha256:")[:12]
        return f"{self.source.name}:{self.source.tag or 'pinned'}-{short}"

    @property
    def archive(self) -> str:
        """Archive path of the image inside the bundle."""
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", self.source.path)
        return f"images/{slug}.tar"


def resolve_compose_value(value: str, env: Mapping[str, str]) -> str:
    """Interpolate `${VAR}`, `${VAR:-default}`, and `${VAR-default}` like Compose."""

    def substitute(match: re.Match[str]) -> str:
        name = match.group("name")
        op = match.group("op")
        current = env.get(name)
        if op == ":-" and not current:
            return match.group("default")
        if op == "-" and current is None:
            return match.group("default")
        if current is None:
            raise BundleError(f"Image variable {name} has no default")
        return current

    return _VAR_PATTERN.sub(substitute, value)


def _compose_setting(raw: str) -> tuple[str | None, str | None]:
    """Return the Compose variable that selects an image and its kind."""
    whole = _VAR_PATTERN.fullmatch(raw)
    if whole:
        return whole.group("name"), "full"
    repository = re.fullmatch(rf"({_VAR_PATTERN.pattern}):\$\{{[^}}]+\}}", raw)
    if repository:
        return repository.group("name"), "repository"
    return None, None


def compose_images(
    compose_file: Path, env: Mapping[str, str]
) -> dict[str, BundleImage]:
    """Images the Compose stack runs, keyed by resolved reference."""
    services = yaml.safe_load(compose_file.read_text())["services"]
    images: dict[str, BundleImage] = {}
    for name, service in services.items():
        raw = service.get("image")
        if raw is None:
            raise BundleError(f"Compose service {name} has no image")
        compose_var, compose_kind = _compose_setting(raw)
        ref = ImageRef.parse(resolve_compose_value(raw, env))
        images[str(ref)] = BundleImage(
            source=ref, compose_var=compose_var, compose_kind=compose_kind
        )
    return images


def helm_images(values_file: Path, version: str) -> dict[str, str]:
    """Image repositories the Helm chart runs, keyed by tagged reference."""
    values = yaml.safe_load(values_file.read_text())
    images: dict[str, str] = {}
    for path in HELM_IMAGE_VALUES:
        node = values
        for key in path:
            node = node[key]
        if not isinstance(node, str) or not node:
            raise BundleError(f"Helm value {'.'.join(path)} is not set")
        images[f"{node}:{version}"] = ".".join(path)
    return images


def bundle_images(
    version: str,
    *,
    compose_file: Path = COMPOSE_FILE,
    values_file: Path = CHART_VALUES,
    env: Mapping[str, str] | None = None,
) -> list[BundleImage]:
    """Every image the bundle must carry, sorted by reference.

    Compose image variables resolve to their defaults; set them in `env` to
    bundle a different image. `AUTOSECOPS__IMAGE_TAG` is always `version`.
    """
    compose_env = {
        key: value
        for key, value in (env or {}).items()
        if key != "AUTOSECOPS__IMAGE_TAG"
    }
    compose_env["AUTOSECOPS__IMAGE_TAG"] = version
    images = compose_images(compose_file, compose_env)
    for ref, helm_value in helm_images(values_file, version).items():
        existing = images.get(ref)
        if existing is None:
            images[ref] = BundleImage(source=ImageRef.parse(ref), helm_value=helm_value)
        else:
            images[ref] = replace(existing, helm_value=helm_value)

    for image in images.values():
        if not image.source.is_first_party and upstream_license(image.source) is None:
            raise BundleError(
                f"No license entry for third-party image {image.source.name}. "
                "Add it to THIRD_PARTY_LICENSES in scripts/offline_bundle.py."
            )
    archives = [image.archive for image in images.values()]
    if len(archives) != len(set(archives)):
        raise BundleError(f"Image archive names collide: {sorted(archives)}")
    return sorted(images.values(), key=lambda image: str(image.source))


def manifest_lines(images: Iterable[BundleImage]) -> list[str]:
    """Render `images.txt`: one tab-separated row per image, `-` for empty."""
    lines = [
        "# AutoSecOps offline bundle image manifest. Tab-separated; '-' means empty.",
        "# name\ttag\tdigest\tbundle_ref\tarchive\tcompose_var\tcompose_kind\thelm_value",
    ]
    for image in images:
        fields = (
            image.source.name,
            image.source.tag,
            image.digest or image.source.digest,
            image.bundle_ref,
            image.archive,
            image.compose_var,
            image.compose_kind,
            image.helm_value,
        )
        lines.append("\t".join(field or "-" for field in fields))
    return lines


def _run(cmd: Sequence[str], *, capture: bool = False) -> str:
    """Run a command, echoing it; raise on failure."""
    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(
        cmd, check=False, text=True, stdout=subprocess.PIPE if capture else None
    )
    if result.returncode != 0:
        raise BundleError(f"Command failed ({result.returncode}): {cmd[0]} {cmd[1]}")
    return result.stdout if capture else ""


def _repo_digest(ref: str, name: str) -> str:
    """Registry digest Docker recorded for `name` when it pulled `ref`."""
    output = _run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{range .RepoDigests}}{{println .}}{{end}}",
            ref,
        ],
        capture=True,
    )
    candidates = {name}
    if "/" not in name:
        candidates.add(f"docker.io/library/{name}")
    elif "." not in name.split("/", 1)[0]:
        candidates.add(f"docker.io/{name}")
    for line in output.splitlines():
        repo, _, digest = line.strip().partition("@")
        if repo in candidates and _DIGEST_PATTERN.match(digest):
            return digest
    raise BundleError(f"Docker recorded no registry digest for {ref}")


def save_image(image: BundleImage, platform: str, staging: Path) -> BundleImage:
    """Pull one image for `platform`, pin it by digest, and `docker save` it."""
    source = str(image.source)
    pulled = _run(["docker", "pull", "--platform", platform, source], capture=True)
    reported = re.search(r"^Digest: (sha256:[0-9a-f]{64})$", pulled, re.MULTILINE)
    digest = (
        image.source.digest
        or (reported.group(1) if reported else None)
        or _repo_digest(source, image.source.name)
    )
    pinned = f"{image.source.name}@{digest}"
    pinned_image = replace(image, digest=digest)
    _run(["docker", "tag", pinned, pinned_image.bundle_ref])
    archive = staging / pinned_image.archive
    archive.parent.mkdir(parents=True, exist_ok=True)
    _run(["docker", "save", "--output", str(archive), pinned_image.bundle_ref])
    return pinned_image


def package_chart(destination: Path, version: str) -> Path:
    """Package the Helm chart with `helm package`, or tar it without helm."""
    destination.mkdir(parents=True, exist_ok=True)
    package = destination / f"autosecops-{version}.tgz"
    if shutil.which("helm"):
        _run(["helm", "package", str(CHART_DIR), "--destination", str(destination)])
    else:
        # helm installs a gzipped tar of the chart directory just like its own
        # package format; skip the files .helmignore lists.
        with tarfile.open(package, "w:gz") as tar:
            for path in sorted(CHART_DIR.rglob("*")):
                if path.is_file() and not _helm_ignored(path):
                    tar.add(path, arcname=f"autosecops/{path.relative_to(CHART_DIR)}")
    if not package.is_file():
        raise BundleError(f"Chart package not found: {package}")
    return package


def _helm_ignored(path: Path) -> bool:
    name = path.name
    return name in {".DS_Store", ".helmignore"} or name.endswith(
        (".swp", ".bak", ".tmp", ".orig", "~")
    )


def third_party_images_notice(images: Iterable[BundleImage]) -> str:
    """List the third-party images and their upstream licenses."""
    lines = [
        "# Third-party container images",
        "",
        "The AutoSecOps offline bundle redistributes these upstream images",
        "unmodified. Each image carries its own license files; the licenses",
        "below are those of the main program in each image.",
        "",
        "| Image | Digest | License | Source |",
        "| --- | --- | --- | --- |",
    ]
    for image in images:
        if image.source.is_first_party:
            continue
        upstream = upstream_license(image.source)
        if upstream is None:
            raise BundleError(f"No license entry for {image.source.name}")
        digest = image.digest or image.source.digest or "resolved at build time"
        lines.append(
            f"| `{image.bundle_ref}` | `{digest}` | {upstream.license} | {upstream.source} |"
        )
    lines += [
        "",
        "`autosecops.md` covers the AutoSecOps API and tunnel gateway images,",
        "`autosecops-ui.md` the UI image. The AutoSecOps PostgreSQL image adds",
        "pgvector (PostgreSQL License) to the official postgres image.",
        "",
    ]
    return "\n".join(lines)


def readme(version: str, images: Sequence[BundleImage], archive_name: str) -> str:
    """Bundle README with the load and install steps."""
    image_lines = "\n".join(f"- `{image.bundle_ref}`" for image in images)
    return f"""# AutoSecOps {version} offline bundle

This bundle installs AutoSecOps {version} without internet access. The full
guide is the "Air-gapped installation" page of the AutoSecOps self-hosting
docs (`/self-hosting/air-gapped`).

## Contents

- `images/`: the container images, saved with `docker save`.
- `images.txt`: name, tag, digest, and settings of every image.
- `install/`: Docker Compose files, `Caddyfile`, `.env.example`, `env.sh`,
  `env-migration.sh`, `backup_compose.sh`, `restore_compose.sh`, and
  `support_bundle.sh`.
- `charts/autosecops-{version}.tgz`: the Helm chart.
- `load-images.sh`: verifies, loads, and pushes the images.
- `THIRD_PARTY_NOTICES/`: third-party licenses.
- `SHA256SUMS` (and `SHA256SUMS.sig` or `SHA256SUMS.minisig` when signed).

## 1. Verify

```bash
# Authenticate the checksum file with SingularityRD's public key, obtained
# outside the bundle, then check the archive against it before extracting.
cosign verify-blob --key /path/to/cosign.pub --insecure-ignore-tlog=true \\
  --signature {archive_name}.sha256.sig {archive_name}.sha256
sha256sum -c {archive_name}.sha256
tar -xf {archive_name}                 # zstd archives need tar with zstd support
cd autosecops-offline-{version}
./load-images.sh verify                # checks SHA256SUMS
./load-images.sh verify --cosign-key /path/to/cosign.pub   # key from SingularityRD
```

## 2a. Docker Compose on this host

```bash
./load-images.sh load
mkdir -p /opt/autosecops && cp -r install/. /opt/autosecops/ && cd /opt/autosecops
./env.sh
# append the overrides `load-images.sh load` printed to .env, then:
docker compose up -d
```

## 2b. Internal registry (Harbor, Nexus, Artifactory) and Kubernetes

```bash
docker login registry.example.internal
./load-images.sh push registry.example.internal/autosecops
```

The command prints the Docker Compose `.env` overrides and the Helm values
that point AutoSecOps at your registry. Install the chart with them:

```bash
helm install autosecops charts/autosecops-{version}.tgz -f values.yaml -f registry-values.yaml
```

## Images

{image_lines}
"""


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(root: Path) -> Path:
    """Write `SHA256SUMS` for every file under `root`, in `sha256sum` format."""
    sums = root / "SHA256SUMS"
    lines = [
        f"{sha256_file(path)}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path != sums
    ]
    sums.write_text("\n".join(lines) + "\n")
    return sums


def sign_file(path: Path) -> Path | None:
    """Sign `path` with the key named in the environment, if any.

    `OFFLINE_BUNDLE_COSIGN_KEY` takes a cosign key reference (a file path or a
    KMS URI; cosign reads `COSIGN_PASSWORD` itself). `OFFLINE_BUNDLE_MINISIGN_KEY`
    takes a minisign secret key file; its password, if any, comes from
    `MINISIGN_PASSWORD` on stdin. Key material never reaches the bundle or logs.
    """
    if cosign_key := os.environ.get("OFFLINE_BUNDLE_COSIGN_KEY"):
        signature = path.with_name(f"{path.name}.sig")
        # cosign 3 defaults to the Sigstore bundle format, ignores
        # `--output-signature`, and uploads to the public Rekor log. Ask for a
        # detached signature and no log entry explicitly: the bundle is
        # verified offline against SingularityRD's public key, and a public
        # log entry would announce every private build.
        _run(
            [
                "cosign",
                "sign-blob",
                "--yes",
                "--key",
                cosign_key,
                "--new-bundle-format=false",
                "--use-signing-config=false",
                "--tlog-upload=false",
                "--output-signature",
                str(signature),
                str(path),
            ]
        )
        _require_signature_file(signature, "cosign")
        return signature
    if minisign_key := os.environ.get("OFFLINE_BUNDLE_MINISIGN_KEY"):
        signature = path.with_name(f"{path.name}.minisig")
        cmd = [
            "minisign",
            "-S",
            "-s",
            minisign_key,
            "-m",
            str(path),
            "-x",
            str(signature),
        ]
        print(f"+ {' '.join(cmd)}", file=sys.stderr)
        password = os.environ.get("MINISIGN_PASSWORD")
        result = subprocess.run(
            cmd,
            check=False,
            text=True,
            input=f"{password}\n" if password is not None else None,
        )
        if result.returncode != 0:
            raise BundleError("minisign failed to sign the bundle")
        _require_signature_file(signature, "minisign")
        return signature
    return None


def signing_configured() -> bool:
    """Whether the environment names a signing key."""
    return bool(
        os.environ.get("OFFLINE_BUNDLE_COSIGN_KEY")
        or os.environ.get("OFFLINE_BUNDLE_MINISIGN_KEY")
    )


def _require_signature_file(signature: Path, tool: str) -> None:
    """Fail loudly when a signer exits 0 without writing its signature."""
    if not signature.is_file() or signature.stat().st_size == 0:
        raise BundleError(f"{tool} reported success but wrote no {signature.name}")


def export_checksums(
    sums: Path, signature: Path | None, output_dir: Path, version: str
) -> list[Path]:
    """Copy `SHA256SUMS` and its signature next to the archive."""
    exported: list[Path] = []
    target = output_dir / f"autosecops-offline-{version}.SHA256SUMS"
    shutil.copyfile(sums, target)
    exported.append(target)
    if signature is not None:
        suffix = signature.name.removeprefix(sums.name)
        signed = output_dir / f"{target.name}{suffix}"
        shutil.copyfile(signature, signed)
        exported.append(signed)
    return exported


def copy_public_key(staging: Path) -> None:
    """Ship the verification public key named in the environment, if any."""
    for env_name, target in (
        ("OFFLINE_BUNDLE_COSIGN_PUBLIC_KEY", "cosign.pub"),
        ("OFFLINE_BUNDLE_MINISIGN_PUBLIC_KEY", "minisign.pub"),
    ):
        if source := os.environ.get(env_name):
            shutil.copyfile(source, staging / target)


def archive_suffix() -> str:
    """`.tar.zst` when zstd is installed, otherwise `.tar.gz`."""
    return ".tar.zst" if shutil.which("zstd") else ".tar.gz"


def create_archive(staging: Path, output_dir: Path, version: str) -> Path:
    """Compress the staging directory with zstd, or gzip without zstd."""
    suffix = archive_suffix()
    archive = output_dir / f"autosecops-offline-{version}{suffix}"
    if suffix == ".tar.zst":
        compressor = "zstd -T0 -10"
    else:
        print("zstd not found; writing a .tar.gz instead", file=sys.stderr)
        compressor = "gzip -6"
    _run(
        [
            "tar",
            "--use-compress-program",
            compressor,
            "-C",
            str(staging.parent),
            "-cf",
            str(archive),
            staging.name,
        ]
    )
    return archive


def current_version() -> str:
    """`autosecops.__version__` of this checkout."""
    match = re.search(
        r'^__version__ = "([^"]+)"$', VERSION_FILE.read_text(), re.MULTILINE
    )
    if match is None:
        raise BundleError(f"No __version__ in {VERSION_FILE}")
    return match.group(1)


def stage_files(staging: Path, version: str, images: Sequence[BundleImage]) -> None:
    """Copy every non-image file into the bundle directory."""
    install = staging / "install"
    install.mkdir(parents=True, exist_ok=True)
    for name in INSTALL_FILES:
        shutil.copy2(INSTALL_SOURCES.get(name, REPO / name), install / name)
    package_chart(staging / "charts", version)
    shutil.copy2(LOAD_SCRIPT, staging / "load-images.sh")
    (staging / "load-images.sh").chmod(0o755)
    notices = staging / "THIRD_PARTY_NOTICES"
    notices.mkdir(exist_ok=True)
    for name, source in NOTICE_FILES.items():
        shutil.copy2(source, notices / name)
    shutil.copy2(REPO / "LICENSE", notices / "AUTOSECOPS-LICENSE")
    (notices / "IMAGES.md").write_text(third_party_images_notice(images))
    (staging / "images.txt").write_text("\n".join(manifest_lines(images)) + "\n")
    archive_name = f"autosecops-offline-{version}{archive_suffix()}"
    (staging / "README.md").write_text(readme(version, images, archive_name))
    copy_public_key(staging)


def build(args: argparse.Namespace) -> int:
    """Build (or dry-run) the bundle."""
    version: str = args.version
    if not _VERSION_PATTERN.match(version):
        raise BundleError(f"Invalid version: {version}")
    if version != (checkout := current_version()) and not args.allow_version_mismatch:
        raise BundleError(
            f"This checkout is {checkout}, not {version}. Check out the {version} "
            "release tag, or pass --allow-version-mismatch."
        )

    if args.require_signature and not args.dry_run and not signing_configured():
        raise BundleError(
            "--require-signature is set but neither OFFLINE_BUNDLE_COSIGN_KEY nor "
            "OFFLINE_BUNDLE_MINISIGN_KEY names a signing key"
        )

    images = bundle_images(version, env=os.environ)
    if args.image:
        wanted = set(args.image)
        images = [
            image
            for image in images
            if image.source.name in wanted or image.source.path in wanted
        ]
        if (
            missing := wanted
            - {i.source.name for i in images}
            - {i.source.path for i in images}
        ):
            raise BundleError(f"Unknown --image: {', '.join(sorted(missing))}")

    print(f"AutoSecOps {version} offline bundle: {len(images)} images", file=sys.stderr)
    for line in manifest_lines(images)[2:]:
        print(f"  {line.split(chr(9))[0]}:{line.split(chr(9))[1]}", file=sys.stderr)

    output_dir: Path = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="autosecops-offline-", dir=output_dir))
    staging = work / f"autosecops-offline-{version}"
    staging.mkdir()
    try:
        if not args.dry_run:
            images = [save_image(image, args.platform, staging) for image in images]
        stage_files(staging, version, images)
        sums = write_checksums(staging)
        if args.dry_run:
            print((staging / "images.txt").read_text(), end="")
            print(f"Dry run: staged {staging}", file=sys.stderr)
            return 0
        sums_signature = sign_file(sums)
        if args.require_signature and sums_signature is None:
            raise BundleError("the bundle was not signed")
        archive = create_archive(staging, output_dir, version)
        checksum = archive.with_name(f"{archive.name}.sha256")
        checksum.write_text(f"{sha256_file(archive)}  {archive.name}\n")
        sign_file(checksum)
        export_checksums(sums, sums_signature, output_dir, version)
        print(
            f"Wrote {archive} ({archive.stat().st_size / 1e9:.2f} GB)", file=sys.stderr
        )
        print(archive)
        return 0
    finally:
        if not args.keep_staging:
            shutil.rmtree(work, ignore_errors=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="Release version, e.g. 1.2.3")
    parser.add_argument(
        "--output-dir", type=Path, default=REPO / "dist", help="Default: dist/"
    )
    parser.add_argument(
        "--platform", default="linux/amd64", help="Image platform. Default: linux/amd64"
    )
    parser.add_argument(
        "--image",
        action="append",
        default=[],
        help="Bundle only this image name (repeatable), e.g. valkey/valkey",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Stage files and print the image list without Docker or an archive",
    )
    parser.add_argument(
        "--keep-staging", action="store_true", help="Keep the staging directory"
    )
    parser.add_argument(
        "--require-signature",
        action="store_true",
        help="Fail unless OFFLINE_BUNDLE_COSIGN_KEY or OFFLINE_BUNDLE_MINISIGN_KEY is set",
    )
    parser.add_argument(
        "--allow-version-mismatch",
        action="store_true",
        help="Allow a version that differs from this checkout",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point."""
    try:
        return build(parse_args(argv))
    except BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
