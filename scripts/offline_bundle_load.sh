#!/usr/bin/env bash
# Customer-side helper for the AutoSecOps offline bundle. The bundler
# (scripts/offline_bundle.py) ships this file as load-images.sh at the bundle
# root; run it from there.
#
#   ./load-images.sh verify [--cosign-key FILE | --minisign-key FILE]
#   ./load-images.sh load
#   ./load-images.sh push REGISTRY[/PREFIX] [--dry-run]
#
# verify  Checks every file against SHA256SUMS and, with a public key, the
#         signature on SHA256SUMS.
# load    Loads every image into the local Docker engine and prints the .env
#         overrides Docker Compose needs.
# push    Loads every image, retags it under REGISTRY[/PREFIX] keeping its
#         repository path (ghcr.io/singularityrd/autosecops becomes
#         REGISTRY/PREFIX/singularityrd/autosecops), pushes it, and prints the
#         Docker Compose .env overrides and Helm values for that registry.
#         Log in first with `docker login REGISTRY`; this script never reads
#         or prints registry credentials.
set -euo pipefail

BUNDLE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MANIFEST="$BUNDLE_DIR/images.txt"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '%s\n' "$*" >&2
}

usage() {
    sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

require() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

# Prints the manifest rows: name tag digest bundle_ref archive compose_var
# compose_kind helm_value, tab-separated, '-' for empty.
manifest_rows() {
    [[ -f "$MANIFEST" ]] || die "images.txt not found next to this script"
    grep -v '^#' "$MANIFEST" | grep -v '^[[:space:]]*$'
}

cmd_verify() {
    local cosign_key='' minisign_key=''
    while (($#)); do
        case "$1" in
        --cosign-key)
            [[ $# -ge 2 ]] || die "--cosign-key needs a file"
            cosign_key=$2
            shift 2
            ;;
        --minisign-key)
            [[ $# -ge 2 ]] || die "--minisign-key needs a file"
            minisign_key=$2
            shift 2
            ;;
        *) die "unknown verify option: $1" ;;
        esac
    done
    require sha256sum
    (cd "$BUNDLE_DIR" && sha256sum --quiet --strict -c SHA256SUMS) ||
        die "checksum verification failed"
    log "SHA256SUMS: every file matches"
    if [[ -n "$cosign_key" ]]; then
        require cosign
        [[ -f "$BUNDLE_DIR/SHA256SUMS.sig" ]] || die "SHA256SUMS.sig not found"
        cosign verify-blob --key "$cosign_key" \
            --signature "$BUNDLE_DIR/SHA256SUMS.sig" "$BUNDLE_DIR/SHA256SUMS" ||
            die "cosign signature verification failed"
        log "SHA256SUMS.sig: valid cosign signature"
    elif [[ -n "$minisign_key" ]]; then
        require minisign
        [[ -f "$BUNDLE_DIR/SHA256SUMS.minisig" ]] || die "SHA256SUMS.minisig not found"
        minisign -V -p "$minisign_key" -m "$BUNDLE_DIR/SHA256SUMS" \
            -x "$BUNDLE_DIR/SHA256SUMS.minisig" ||
            die "minisign signature verification failed"
        log "SHA256SUMS.minisig: valid minisign signature"
    else
        log "No public key given; signature not checked"
    fi
}

load_images() {
    local name tag digest bundle_ref archive _rest
    while IFS=$'\t' read -r name tag digest bundle_ref archive _rest; do
        [[ -f "$BUNDLE_DIR/$archive" ]] || die "missing image archive: $archive"
        log "Loading $bundle_ref"
        docker load --quiet --input "$BUNDLE_DIR/$archive" >/dev/null
        docker image inspect "$bundle_ref" >/dev/null 2>&1 ||
            die "$archive did not provide $bundle_ref"
    done < <(manifest_rows)
}

# The Compose value for an image: the full reference for `full` variables, the
# repository for `repository` variables (the tag comes from another variable).
compose_value() {
    local kind=$1 repository=$2 reference=$3
    if [[ "$kind" == repository ]]; then
        printf '%s' "$repository"
    else
        printf '%s' "$reference"
    fi
}

cmd_load() {
    (($# == 0)) || die "load takes no arguments"
    require docker
    load_images
    local name tag digest bundle_ref archive compose_var compose_kind _helm
    local overrides=()
    while IFS=$'\t' read -r name tag digest bundle_ref archive compose_var compose_kind _helm; do
        [[ "$compose_var" != - ]] || continue
        # Compose already resolves tagged images to the loaded ones; only
        # digest-pinned defaults need the loaded tag instead.
        if [[ "$bundle_ref" != "$name:$tag" ]]; then
            overrides+=("$compose_var=$(compose_value "$compose_kind" "$name" "$bundle_ref")")
        fi
    done < <(manifest_rows)
    log ""
    if ((${#overrides[@]} == 0)); then
        log "Images loaded. Docker Compose needs no .env overrides."
        return
    fi
    log "Images loaded. Add these lines to the .env next to docker-compose.yml:"
    printf '%s\n' "${overrides[@]}"
}

cmd_push() {
    local target='' dry_run=false
    while (($#)); do
        case "$1" in
        --dry-run)
            dry_run=true
            shift
            ;;
        -*) die "unknown push option: $1" ;;
        *)
            [[ -z "$target" ]] || die "push takes one REGISTRY[/PREFIX]"
            target=${1%/}
            shift
            ;;
        esac
    done
    [[ -n "$target" ]] || die "push needs REGISTRY[/PREFIX], e.g. registry.example.internal/autosecops"
    [[ "$target" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?(/[a-z0-9._/-]+)?$ ]] ||
        die "invalid registry target: $target"

    if ! $dry_run; then
        require docker
        load_images
    fi

    local name tag digest bundle_ref archive compose_var compose_kind helm_value
    local path repository reference pushed_digest
    local compose_lines=() helm_lines=()
    while IFS=$'\t' read -r name tag digest bundle_ref archive compose_var compose_kind helm_value; do
        # Drop the source registry host, keep the repository path.
        path=$name
        if [[ "$name" == */* ]]; then
            local first=${name%%/*}
            if [[ "$first" == *.* || "$first" == *:* || "$first" == localhost ]]; then
                path=${name#*/}
            fi
        fi
        repository="$target/$path"
        reference="$repository:${bundle_ref##*:}"
        pushed_digest=''
        if $dry_run; then
            log "Would push $bundle_ref -> $reference"
        else
            log "Pushing $reference"
            docker tag "$bundle_ref" "$reference"
            # The digest the registry stored, from push's final status line.
            # RepoDigests is not used: the containerd image store reports the
            # source index digest there, not the pushed manifest.
            pushed_digest=$(docker push "$reference" |
                sed -n 's/.*digest: \(sha256:[0-9a-f]\{64\}\).*/\1/p' | tail -n 1)
        fi
        if [[ "$compose_var" != - ]]; then
            if [[ "$compose_kind" == full && -n "$pushed_digest" ]]; then
                compose_lines+=("$compose_var=$reference@$pushed_digest")
            else
                compose_lines+=("$compose_var=$(compose_value "$compose_kind" "$repository" "$reference")")
            fi
        fi
        case "$helm_value" in
        image.repository) helm_lines+=("image:" "  repository: $repository") ;;
        uiImage.repository) helm_lines+=("uiImage:" "  repository: $repository") ;;
        tunnels.gateway.image.repository)
            helm_lines+=("tunnels:" "  gateway:" "    image:" "      repository: $repository")
            ;;
        -) ;;
        *) die "unknown Helm value in images.txt: $helm_value" ;;
        esac
    done < <(manifest_rows)

    printf '# Docker Compose: add to the .env next to docker-compose.yml\n'
    printf '%s\n' "${compose_lines[@]}"
    printf '\n# Helm: save as registry-values.yaml and pass it with -f\n'
    printf '%s\n' "${helm_lines[@]}"
    printf '# If the registry needs credentials, create a docker-registry Secret and add:\n'
    printf '# imagePullSecrets: [{name: <secret-name>}]\n'
    printf '# tunnels.gateway.imagePullSecrets: [{name: <secret-name>}]   # in the tunnels namespace\n'
}

main() {
    (($#)) || usage 1
    local command=$1
    shift
    case "$command" in
    verify) cmd_verify "$@" ;;
    load) cmd_load "$@" ;;
    push) cmd_push "$@" ;;
    -h | --help | help) usage 0 ;;
    *)
        log "unknown command: $command"
        usage 1
        ;;
    esac
}

main "$@"
