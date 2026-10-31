#!/usr/bin/env bash
# Collect a support bundle for an AutoSecOps deployment.
#
# Docker Compose: run from the directory that holds docker-compose.yml and .env.
# Kubernetes:     run anywhere with kubectl access, with --kubernetes.
#
# The bundle is one .tar.gz with:
#   summary.txt     collection time, host, tool and AutoSecOps versions
#   settings.txt    every .env key with values only for non-secret settings
#                   (Compose; secrets show as <set> or <empty>)
#   services.txt    service or pod status
#   images.txt      image reference and resolved digest of every container
#   probe.json      AutoSecOps version, alembic revision, and license
#                   entitlement status, read inside the API container
#   logs/*.log      recent logs of every service, with secrets redacted
#
# The probe never reads the license key or any credential, .env values are
# allowlisted, and every collected line passes through the redactor below,
# which replaces known secret patterns. Pattern matching cannot catch every
# secret, so review the bundle before you send it; your own log messages may
# also hold data your policy treats as sensitive.

set -euo pipefail

SCRIPT_NAME=$(basename "$0")
BUNDLE_FORMAT=1

OUTPUT_ROOT=${AUTOSECOPS_SUPPORT_DIR:-.}
SINCE=24h
TAIL=5000
MODE=compose
NAMESPACE=autosecops
RELEASE=autosecops
API_DEPLOYMENT=''
API_SERVICE=${AUTOSECOPS_SUPPORT_API_SERVICE:-api}

# .env keys whose values are safe to include. Everything else is reported only
# as <set> or <empty>.
SAFE_KEYS_RE='^(AUTOSECOPS__IMAGE_TAG|AUTOSECOPS__IMAGE_REPOSITORY|AUTOSECOPS__UI_IMAGE_REPOSITORY|AUTOSECOPS__[A-Z_]*_IMAGE|TEMPORAL__VERSION|TEMPORAL__UI_VERSION|TEMPORAL__IMAGE_REPOSITORY|TEMPORAL__UI_IMAGE_REPOSITORY|TEMPORAL__POSTGRES_IMAGE|TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED|AUTOSECOPS__EXECUTOR_BACKEND|AUTOSECOPS__RLS_MODE|AUTOSECOPS__EE_MULTI_TENANT|AUTOSECOPS__AUTH_TYPES|AUTOSECOPS__AUTH_ALLOWED_DOMAINS_ENABLED|AUTOSECOPS__APP_ENV|LOG_LEVEL|NODE_ENV|COMPOSE_PROJECT_NAME)$'

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Collect versions, image digests, service status, the alembic revision,
license entitlement status, and recent redacted logs into one archive.

Options:
  -o, --output DIR       Directory for the archive (default: ., or
                         \$AUTOSECOPS_SUPPORT_DIR)
      --since DURATION   Collect logs this far back (default: $SINCE)
      --tail LINES       At most this many log lines per service (default: $TAIL)
      --kubernetes       Collect from a Helm deployment with kubectl
  -n, --namespace NS     Kubernetes namespace (default: $NAMESPACE)
      --release NAME     Helm release name (default: $RELEASE)
      --api-deployment NAME
                         API Deployment name (default: <release>-api)
      --redact           Only redact stdin to stdout, e.g. logs you collected
                         yourself from AWS Fargate
  -h, --help             Show this help

Docker Compose environment overrides:
  AUTOSECOPS_SUPPORT_API_SERVICE   $API_SERVICE
  COMPOSE_FILE, COMPOSE_PROJECT_NAME  Passed through to docker compose
EOF
}

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() {
  log "ERROR: $*"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o | --output)
      [[ $# -ge 2 ]] || die "$1 needs a directory"
      OUTPUT_ROOT=$2
      shift 2
      ;;
    --since)
      [[ $# -ge 2 ]] || die "--since needs a duration such as 24h"
      SINCE=$2
      shift 2
      ;;
    --tail)
      [[ $# -ge 2 ]] || die "--tail needs a number"
      TAIL=$2
      shift 2
      ;;
    --kubernetes) MODE=kubernetes && shift ;;
    --redact) MODE=redact && shift ;;
    -n | --namespace)
      [[ $# -ge 2 ]] || die "$1 needs a namespace"
      NAMESPACE=$2
      shift 2
      ;;
    --release)
      [[ $# -ge 2 ]] || die "--release needs a name"
      RELEASE=$2
      shift 2
      ;;
    --api-deployment)
      [[ $# -ge 2 ]] || die "--api-deployment needs a name"
      API_DEPLOYMENT=$2
      shift 2
      ;;
    -h | --help) usage && exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[[ "$SINCE" =~ ^[0-9]+[smh]$ ]] || die "--since must look like 30m or 24h"
[[ "$TAIL" =~ ^[1-9][0-9]*$ ]] || die "--tail must be a positive number"
[[ -n "$API_DEPLOYMENT" ]] || API_DEPLOYMENT="${RELEASE}-api"

# Case-insensitive sed matching (the I flag) is a GNU extension.
printf 'A\n' | sed -E 's/a/b/I' >/dev/null 2>&1 && [[ "$(printf 'A\n' | sed -E 's/a/b/I')" == b ]] ||
  die "GNU sed is required for redaction (on macOS: brew install gnu-sed and put gsed first in PATH as sed)"

# Redaction rules for GNU sed -E, applied to every line in order: whole tokens
# first, then key/value pairs, then secrets inside SQL and URLs. They match
# known secret shapes only, so the bundle must still be reviewed before it is
# sent. The key/value rules share one pattern for secret-looking key names.
REDACT_SED=$(
  cat <<'SED'
s/-----BEGIN [A-Z ]*PRIVATE KEY-----.*-----END [A-Z ]*PRIVATE KEY-----/[REDACTED PRIVATE KEY]/g
/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/c [REDACTED PRIVATE KEY]
s/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/[REDACTED_JWT]/g
s/(bearer|basic|token)[[:space:]]+[A-Za-z0-9._~+\/=-]{8,}/\1 [REDACTED]/Ig
s/(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}/[REDACTED_AWS_KEY_ID]/g
s/(gh[pousr]_|github_pat_|glpat-|xox[abposr]-|xapp-|sk-|[sr]k_live_|[sr]k_test_)[A-Za-z0-9_-]{10,}/[REDACTED_TOKEN]/g
# Secret key in escaped JSON, {\"password\": \"value\"}: the value ends at the
# next backslash or quote.
s/([A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|encryption[_-]?key|service[_-]?key|signing[_-]?key|license[_-]?key|keyring|authorization|cookie|credential|session[_-]?id)s?[A-Za-z0-9_.-]*\\+["']?[[:space:]]*[:=][[:space:]]*\\+["'])[^"'\\]*/\1[REDACTED]/Ig
# Secret key with a double-quoted value, up to the closing quote even across
# spaces.
s/([A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|encryption[_-]?key|service[_-]?key|signing[_-]?key|license[_-]?key|keyring|authorization|cookie|credential|session[_-]?id)s?[A-Za-z0-9_.-]*"?[[:space:]]*[:=][[:space:]]*")([^"\\]|\\.)*/\1[REDACTED]/Ig
# Secret key with a single-quoted value, such as a Python repr.
s/([A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|encryption[_-]?key|service[_-]?key|signing[_-]?key|license[_-]?key|keyring|authorization|cookie|credential|session[_-]?id)s?[A-Za-z0-9_.-]*'?[[:space:]]*[:=][[:space:]]*')([^'\\]|\\.)*/\1[REDACTED]/Ig
# Secret key with an unquoted value, up to whitespace or a separator.
s/([A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|encryption[_-]?key|service[_-]?key|signing[_-]?key|license[_-]?key|keyring|authorization|cookie|credential|session[_-]?id)s?[A-Za-z0-9_.-]*["']?[[:space:]]*[:=][[:space:]]*["']?)[^"'[:space:],;&}]+/\1[REDACTED]/Ig
# SQL literals that PostgreSQL logs on error: CREATE/ALTER ROLE ... PASSWORD
# 'value', where '' escapes a quote.
s/(PASSWORD[[:space:]]+E?')([^']|'')*'/\1[REDACTED]'/Ig
# Webhook URL secrets: /webhooks/<workflow_id>/<secret>, also under /api.
s#(/webhooks/[^/[:space:]"'?&]+/)[^/[:space:]"'?&]+#\1[REDACTED]#g
# Capability URLs whose path is the credential.
s#(hooks\.slack\.com/(services|workflows|triggers)/)[^[:space:]"'<>]+#\1[REDACTED]#Ig
s#(\.webhook\.office\.com/)[^[:space:]"'<>]+#\1[REDACTED]#Ig
# Signed URL query parameters (S3 and GCS presigned URLs, Azure SAS).
s/([?&](X-Amz-Signature|X-Amz-Credential|X-Goog-Signature|X-Goog-Credential|sig|signature)=)[^&[:space:]"'<>]+/\1[REDACTED]/Ig
# Credentials inside URLs: scheme://user:password@host.
s#([a-z][a-z0-9+.-]*://[^:/@[:space:]]+:)[^@[:space:]]+@#\1[REDACTED]@#Ig
SED
)

# Redact secrets from stdin.
redact() {
  sed -E "$REDACT_SED"
}

if [[ "$MODE" == redact ]]; then
  redact
  exit 0
fi

# The probe runs inside the API container with Python and the AutoSecOps
# package. It prints JSON and never reads AUTOSECOPS__LICENSE_KEY itself or any
# credential value; the license service verifies the key and returns claims.
PROBE=$(
  cat <<'PY'
import asyncio
import json
from datetime import UTC, datetime


async def main() -> None:
    import autosecops

    out: dict[str, object] = {"autosecops_version": autosecops.__version__}
    try:
        from sqlalchemy import text

        from autosecops.db.engine import (
            get_async_session_bypass_rls_context_manager,
        )

        async with get_async_session_bypass_rls_context_manager() as session:
            result = await session.execute(
                text("select version_num from alembic_version")
            )
            out["alembic_revisions"] = sorted(result.scalars().all())
    except Exception as exc:  # report, do not fail the bundle
        out["alembic_error"] = type(exc).__name__
    try:
        from autosecops.licensing.service import (
            ensure_license_deployment_loaded,
            get_license_state,
            license_days_remaining,
        )

        try:
            await ensure_license_deployment_loaded()
        except Exception as exc:
            out["license_deployment_error"] = type(exc).__name__
        state = get_license_state(log=False)
        claims = state.claims
        out["license"] = {
            "status": str(state.status),
            "error": str(state.error) if state.error else None,
            "license_id": claims.license_id if claims else None,
            "plan": str(claims.plan) if claims and claims.plan else None,
            "expires_at": claims.expires_at.isoformat() if claims else None,
            "grace_ends_at": (
                state.grace_ends_at.isoformat() if state.grace_ends_at else None
            ),
            "days_remaining": license_days_remaining(state, datetime.now(UTC)),
            "entitlements": sorted(str(e) for e in state.granted),
            "bound_to_deployment": bool(claims and claims.deployment_id),
        }
    except Exception as exc:
        out["license_error"] = type(exc).__name__
    print(json.dumps(out, indent=2, default=str))


asyncio.run(main())
PY
)

umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="autosecops-support-$stamp"
mkdir -p "$OUTPUT_ROOT"
work=$(mktemp -d "${TMPDIR:-/tmp}/autosecops-support.XXXXXX")
trap 'rm -rf "$work"' EXIT
dest="$work/$name"
mkdir -p "$dest/logs"

# Run a collector; record a failure in the file instead of aborting, so one
# unreachable service never costs the rest of the bundle.
collect() {
  local file=$1
  shift
  local rc=0 errors="$dest/$file"
  # Keep JSON parseable: its stderr (service log lines) goes to a sibling file.
  [[ "$file" == *.json ]] && errors="$dest/$file.stderr.log"
  if [[ "$errors" == "$dest/$file" ]]; then
    "$@" >"$dest/$file" 2>&1 || rc=$?
  else
    "$@" >"$dest/$file" 2>"$errors" || rc=$?
  fi
  if ((rc != 0)); then
    printf '\n[collection failed: exit %s]\n' "$rc" >>"$errors"
    log "WARNING: could not collect $file (exit $rc)"
  fi
  local out
  for out in "$dest/$file" "$errors"; do
    [[ -f "$out" ]] || continue
    redact <"$out" >"$out.tmp" && mv "$out.tmp" "$out"
  done
}

summary_common() {
  echo "bundle_format=$BUNDLE_FORMAT"
  echo "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "mode=$MODE"
  echo "host_kernel=$(uname -srm)"
  echo "log_since=$SINCE"
  echo "log_tail=$TAIL"
}

if [[ "$MODE" == compose ]]; then
  command -v docker >/dev/null || die "docker is not installed"
  docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
  [[ -f docker-compose.yml || -n "${COMPOSE_FILE:-}" ]] ||
    die "run from the directory that holds docker-compose.yml"
  log "Collecting from Docker Compose"

  compose_summary() {
    summary_common
    echo "docker=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
    echo "docker_compose=$(docker compose version --short 2>/dev/null || echo unknown)"
  }
  collect summary.txt compose_summary

  env_settings() {
    [[ -f .env ]] || {
      echo "no .env in $(pwd)"
      return 0
    }
    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)= ]] || continue
      key=${BASH_REMATCH[1]}
      value=${line#*=}
      if [[ "$key" =~ $SAFE_KEYS_RE ]]; then
        printf '%s=%s\n' "$key" "$value"
      elif [[ -n "$value" ]]; then
        printf '%s=<set>\n' "$key"
      else
        printf '%s=<empty>\n' "$key"
      fi
    done <.env
  }
  # settings.txt holds only allowlisted values and <set>/<empty> markers, so it
  # skips the redactor, which would turn every marker into [REDACTED].
  env_settings >"$dest/settings.txt"
  collect services.txt docker compose ps -a

  compose_images() {
    local cid
    for cid in $(docker compose ps -aq); do
      docker inspect --format '{{.Name}} {{.Config.Image}} {{.Image}}' "$cid"
      docker image inspect --format '  repo_digests={{join .RepoDigests ","}}' \
        "$(docker inspect --format '{{.Image}}' "$cid")" 2>/dev/null || true
    done
  }
  collect images.txt compose_images
  collect probe.json docker compose exec -T "$API_SERVICE" python - <<<"$PROBE"

  for service in $(docker compose ps -a --services); do
    [[ "$service" =~ ^[A-Za-z0-9_.-]+$ ]] || continue
    collect "logs/$service.log" docker compose logs --no-color --timestamps \
      --since "$SINCE" --tail "$TAIL" "$service"
  done
else
  command -v kubectl >/dev/null || die "kubectl is not installed"
  [[ "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || die "invalid namespace: $NAMESPACE"
  log "Collecting from Kubernetes namespace $NAMESPACE"
  selector="app.kubernetes.io/instance=$RELEASE"

  k8s_summary() {
    summary_common
    echo "namespace=$NAMESPACE"
    echo "release=$RELEASE"
    kubectl version 2>/dev/null | sed 's/^/kubectl: /' || echo "kubectl: unknown"
    if command -v helm >/dev/null; then
      helm list -n "$NAMESPACE" --filter "^${RELEASE}\$" 2>/dev/null | sed 's/^/helm: /'
    fi
  }
  collect summary.txt k8s_summary
  collect services.txt kubectl get pods,deployments,jobs -n "$NAMESPACE" -l "$selector" -o wide
  collect events.txt kubectl get events -n "$NAMESPACE" --sort-by=.lastTimestamp
  collect images.txt kubectl get pods -n "$NAMESPACE" -l "$selector" -o \
    jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .status.containerStatuses[*]}{"  "}{.name}{" "}{.image}{" "}{.imageID}{"\n"}{end}{end}'
  collect probe.json kubectl exec -i -n "$NAMESPACE" "deploy/$API_DEPLOYMENT" -c api -- python - <<<"$PROBE"

  for pod in $(kubectl get pods -n "$NAMESPACE" -l "$selector" -o name); do
    pod=${pod#pod/}
    [[ "$pod" =~ ^[a-z0-9.-]+$ ]] || continue
    collect "logs/$pod.log" kubectl logs -n "$NAMESPACE" "$pod" --all-containers \
      --prefix --timestamps --since "$SINCE" --tail "$TAIL"
  done
fi

archive="$OUTPUT_ROOT/$name.tar.gz"
tar -C "$work" -czf "$archive" "$name"
chmod 600 "$archive"
log "Wrote $archive"
log "Review it, then send it to info@singularityrd.com or your SingularityRD contact."
echo "$archive"
