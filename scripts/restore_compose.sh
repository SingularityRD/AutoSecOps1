#!/usr/bin/env bash
# Restore a backup made by scripts/backup_compose.sh into a Docker Compose
# deployment of AutoSecOps.
#
# Run from the directory that holds docker-compose.yml and .env. The script:
#   1. verifies SHA256SUMS
#   2. refuses to continue when .env holds a different
#      AUTOSECOPS__DB_ENCRYPTION_KEY than the backup (compared by hash)
#   3. stops every running service except Postgres, MinIO and Redis
#   4. drops and recreates the core and Temporal databases from the dumps
#   5. mirrors the MinIO buckets back
#   6. leaves the application stopped so you can check it and start it with
#      `docker compose up -d`, which also runs any newer migrations
#
# The restore REPLACES the current databases. It never prints secret values.

set -euo pipefail

SCRIPT_NAME=$(basename "$0")

CORE_DB_SERVICE=${AUTOSECOPS_BACKUP_CORE_DB_SERVICE:-postgres_db}
CORE_DB_NAME=${AUTOSECOPS_BACKUP_CORE_DB_NAME:-postgres}
TEMPORAL_DB_SERVICE=${AUTOSECOPS_BACKUP_TEMPORAL_DB_SERVICE:-temporal_postgres_db}
MINIO_SERVICE=${AUTOSECOPS_BACKUP_MINIO_SERVICE:-minio}
KEEP_RUNNING=${AUTOSECOPS_BACKUP_KEEP_RUNNING:-redis}

ASSUME_YES=0
SKIP_TEMPORAL=0
SKIP_MINIO=0
ALLOW_KEY_MISMATCH=0
BACKUP=

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options] BACKUP_DIR

Restore an AutoSecOps backup into the Docker Compose deployment in the
current directory. Existing data in the core and Temporal databases is replaced.

Options:
  -y, --yes          Do not ask for confirmation
      --skip-temporal
                     Do not restore the Temporal databases
      --skip-minio   Do not restore MinIO buckets
      --allow-key-mismatch
                     Continue although .env and the backup hold different
                     AUTOSECOPS__DB_ENCRYPTION_KEY values. Stored credentials
                     will not decrypt.
  -h, --help         Show this help

Environment overrides match scripts/backup_compose.sh:
  AUTOSECOPS_BACKUP_CORE_DB_SERVICE      $CORE_DB_SERVICE
  AUTOSECOPS_BACKUP_CORE_DB_NAME         $CORE_DB_NAME
  AUTOSECOPS_BACKUP_TEMPORAL_DB_SERVICE  $TEMPORAL_DB_SERVICE
  AUTOSECOPS_BACKUP_MINIO_SERVICE        $MINIO_SERVICE
  AUTOSECOPS_BACKUP_KEEP_RUNNING         "$KEEP_RUNNING" (besides the services above)
  COMPOSE_FILE, COMPOSE_PROJECT_NAME     Passed through to docker compose
EOF
}

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() {
  log "ERROR: $*"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y | --yes) ASSUME_YES=1 && shift ;;
    --skip-temporal) SKIP_TEMPORAL=1 && shift ;;
    --skip-minio) SKIP_MINIO=1 && shift ;;
    --allow-key-mismatch) ALLOW_KEY_MISMATCH=1 && shift ;;
    -h | --help) usage && exit 0 ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *)
      [[ -z "$BACKUP" ]] || die "only one BACKUP_DIR is allowed"
      BACKUP=$1
      shift
      ;;
  esac
done

[[ -n "$BACKUP" ]] || {
  usage
  exit 2
}
[[ -d "$BACKUP" ]] || die "backup directory not found: $BACKUP"
BACKUP=$(cd "$BACKUP" && pwd)
[[ -f "$BACKUP/core.dump" ]] || die "$BACKUP/core.dump is missing"

command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"

running_services() { docker compose ps --status running --services 2>/dev/null; }
is_running() {
  local running
  running=$(running_services)
  grep -qx "$1" <<<"$running"
}

pg_exec() {
  local service=$1
  shift
  docker compose exec -T "$service" sh -c 'PGUSER="$POSTGRES_USER" exec "$@"' sh "$@"
}

container_env() {
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$1" | sed -n "s/^$2=//p" | head -n 1
}

urlencode() {
  local s=$1 out="" c i
  for ((i = 0; i < ${#s}; i++)); do
    c=${s:i:1}
    case "$c" in
      [a-zA-Z0-9.~_-]) out+=$c ;;
      *) out+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  printf '%s' "$out"
}

env_value_hash() {
  # env_value_hash <file> <VAR>: SHA-256 of the variable's value, or empty.
  local line
  line=$(grep -E "^$2=" "$1" 2>/dev/null | tail -n 1) || true
  [[ -n "$line" ]] || return 0
  printf '%s' "${line#*=}" | sha256sum | cut -d' ' -f1
}

log "Verifying checksums in $BACKUP"
if [[ -f "$BACKUP/SHA256SUMS" ]]; then
  (cd "$BACKUP" && sha256sum --quiet -c SHA256SUMS) || die "checksum verification failed"
else
  log "WARNING: no SHA256SUMS; skipping checksum verification"
fi

if [[ -f "$BACKUP/config/.env" ]]; then
  [[ -f .env ]] || die "no .env in $(pwd). Copy $BACKUP/config/.env here first (it holds the encryption key)."
  for var in AUTOSECOPS__DB_ENCRYPTION_KEY AUTOSECOPS__SERVICE_KEY AUTOSECOPS__SIGNING_SECRET USER_AUTH_SECRET; do
    if [[ "$(env_value_hash .env "$var")" != "$(env_value_hash "$BACKUP/config/.env" "$var")" ]]; then
      if [[ "$var" == AUTOSECOPS__DB_ENCRYPTION_KEY && $ALLOW_KEY_MISMATCH -eq 0 ]]; then
        die "$var in .env differs from the backup. Restore the backup's .env, or pass --allow-key-mismatch."
      fi
      log "WARNING: $var in .env differs from the backup"
    fi
  done
else
  log "WARNING: the backup has no .env. The current AUTOSECOPS__DB_ENCRYPTION_KEY must be the one the backup was taken with."
fi

if [[ -f "$BACKUP/MANIFEST" ]]; then
  log "Backup manifest:"
  sed -n '/^images:/q;p' "$BACKUP/MANIFEST" | sed 's/^/  /' >&2
fi

if [[ $ASSUME_YES -eq 0 ]]; then
  [[ -t 0 ]] || die "refusing to restore without a terminal; pass --yes"
  project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$(docker compose ps -q "$CORE_DB_SERVICE")" 2>/dev/null || echo "?")
  printf 'This replaces the databases of Compose project "%s". Type the project name to continue: ' "$project" >&2
  read -r answer
  [[ "$answer" == "$project" ]] || die "aborted"
fi

# Stop everything that can write, keep the stateful services up.
keep=" $CORE_DB_SERVICE $TEMPORAL_DB_SERVICE $MINIO_SERVICE $KEEP_RUNNING "
to_stop=()
for svc in $(running_services); do
  [[ "$keep" == *" $svc "* ]] || to_stop+=("$svc")
done
if [[ ${#to_stop[@]} -gt 0 ]]; then
  log "Stopping: ${to_stop[*]}"
  docker compose stop "${to_stop[@]}" >/dev/null
fi

start_s=$(date +%s)

restore_db() {
  # restore_db <service> <database> <dump file>
  local service=$1 db=$2 dump=$3
  is_running "$service" || die "service '$service' is not running; start it with: docker compose up -d $service"
  log "Recreating database '$db' on '$service'"
  pg_exec "$service" psql -XAtq -v ON_ERROR_STOP=1 -d template1 \
    -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" \
    -c "CREATE DATABASE \"$db\" TEMPLATE template0"
  log "Restoring '$db' from $(basename "$dump")"
  pg_exec "$service" pg_restore --no-owner --exit-on-error --single-transaction -d "$db" <"$dump"
}

restore_db "$CORE_DB_SERVICE" "$CORE_DB_NAME" "$BACKUP/core.dump"

if [[ $SKIP_TEMPORAL -eq 0 ]]; then
  shopt -s nullglob
  for dump in "$BACKUP"/temporal-*.dump; do
    db=$(basename "$dump" .dump)
    restore_db "$TEMPORAL_DB_SERVICE" "${db#temporal-}" "$dump"
  done
  shopt -u nullglob
fi

if [[ $SKIP_MINIO -eq 0 && -d "$BACKUP/minio" ]]; then
  minio_cid=$(docker compose ps -q "$MINIO_SERVICE" 2>/dev/null || true)
  if [[ -z "$minio_cid" ]] || ! is_running "$MINIO_SERVICE"; then
    die "service '$MINIO_SERVICE' is not running; start it with: docker compose up -d $MINIO_SERVICE"
  fi
  minio_image=$(docker inspect --format '{{.Config.Image}}' "$minio_cid")
  minio_user=$(container_env "$minio_cid" MINIO_ROOT_USER)
  minio_pass=$(container_env "$minio_cid" MINIO_ROOT_PASSWORD)
  [[ -n "$minio_user" && -n "$minio_pass" ]] || die "could not read MinIO credentials from the '$MINIO_SERVICE' container"
  MC_HOST_dst="http://$(urlencode "$minio_user"):$(urlencode "$minio_pass")@127.0.0.1:9000"
  export MC_HOST_dst
  log "Restoring MinIO buckets with mc"
  docker run --rm --network "container:$minio_cid" \
    --user "$(id -u):$(id -g)" -e HOME=/tmp -e MC_CONFIG_DIR=/tmp/.mc -e MC_HOST_dst \
    -v "$BACKUP/minio:/backup:ro" --entrypoint mc "$minio_image" \
    --quiet --no-color mirror --overwrite --preserve /backup dst >/dev/null
  unset MC_HOST_dst minio_user minio_pass
fi

elapsed=$(($(date +%s) - start_s))
rev=$(pg_exec "$CORE_DB_SERVICE" psql -XAtq -d "$CORE_DB_NAME" -c "select string_agg(version_num, ',') from alembic_version" 2>/dev/null || echo unknown)
log "Restore complete in ${elapsed}s. Core database alembic revision: $rev"
log "Next: docker compose up -d   (runs migrations if the image is newer than the backup)"
