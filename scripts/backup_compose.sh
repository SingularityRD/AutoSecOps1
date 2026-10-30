#!/usr/bin/env bash
# Back up a Docker Compose deployment of AutoSecOps.
#
# Run from the directory that holds docker-compose.yml and .env. The script
# writes one timestamped directory with:
#   core.dump                      pg_dump -Fc of the AutoSecOps database
#   temporal-<db>.dump             pg_dump -Fc of each Temporal database
#   minio/<bucket>/...             mc mirror of every MinIO bucket
#   config/                        .env, Compose files and Caddyfile
#   MANIFEST                       versions, alembic revision, sizes
#   SHA256SUMS                     checksums of every file above
#
# By default the script stops the services that write to these stores, takes
# the backup, and starts the same services again, so the databases and object
# storage agree with each other. Use --online to skip that (see the docs for
# what is and is not consistent online).
#
# The backup contains secrets (.env and encrypted credentials). The script
# creates it with mode 0700/0600 and never prints secret values.

set -euo pipefail

SCRIPT_NAME=$(basename "$0")

OUTPUT_ROOT=${AUTOSECOPS_BACKUP_DIR:-./backups}
CORE_DB_SERVICE=${AUTOSECOPS_BACKUP_CORE_DB_SERVICE:-postgres_db}
CORE_DB_NAME=${AUTOSECOPS_BACKUP_CORE_DB_NAME:-postgres}
TEMPORAL_DB_SERVICE=${AUTOSECOPS_BACKUP_TEMPORAL_DB_SERVICE:-temporal_postgres_db}
TEMPORAL_DB_NAMES=${AUTOSECOPS_BACKUP_TEMPORAL_DB_NAMES:-temporal temporal_visibility}
MINIO_SERVICE=${AUTOSECOPS_BACKUP_MINIO_SERVICE:-minio}
QUIESCE_SERVICES=${AUTOSECOPS_BACKUP_QUIESCE_SERVICES:-api worker executor agent-worker agent-executor litellm mcp temporal_ui temporal}

ONLINE=0
SKIP_TEMPORAL=0
SKIP_MINIO=0
COPY_ENV=1

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Back up the AutoSecOps Docker Compose deployment in the current directory.

Options:
  -o, --output DIR   Parent directory for the backup (default: ./backups,
                     or \$AUTOSECOPS_BACKUP_DIR)
      --online       Do not stop application services during the backup
      --skip-temporal
                     Do not dump the Temporal databases
      --skip-minio   Do not mirror MinIO buckets
      --no-env       Do not copy .env into the backup. Store it elsewhere:
                     without AUTOSECOPS__DB_ENCRYPTION_KEY the stored
                     credentials in the database backup cannot be decrypted
  -h, --help         Show this help

Environment overrides (defaults match docker-compose.yml):
  AUTOSECOPS_BACKUP_CORE_DB_SERVICE      $CORE_DB_SERVICE
  AUTOSECOPS_BACKUP_CORE_DB_NAME         $CORE_DB_NAME
  AUTOSECOPS_BACKUP_TEMPORAL_DB_SERVICE  $TEMPORAL_DB_SERVICE
  AUTOSECOPS_BACKUP_TEMPORAL_DB_NAMES    "$TEMPORAL_DB_NAMES"
  AUTOSECOPS_BACKUP_MINIO_SERVICE        $MINIO_SERVICE
  AUTOSECOPS_BACKUP_QUIESCE_SERVICES     "$QUIESCE_SERVICES"
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
    -o | --output)
      [[ $# -ge 2 ]] || die "$1 needs a directory"
      OUTPUT_ROOT=$2
      shift 2
      ;;
    --online) ONLINE=1 && shift ;;
    --skip-temporal) SKIP_TEMPORAL=1 && shift ;;
    --skip-minio) SKIP_MINIO=1 && shift ;;
    --no-env) COPY_ENV=0 && shift ;;
    -h | --help) usage && exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"

running_services() { docker compose ps --status running --services 2>/dev/null; }
is_running() {
  local running
  running=$(running_services)
  grep -qx "$1" <<<"$running"
}

# Run a command inside a Postgres service as its superuser over the local
# socket, so no password crosses the command line.
pg_exec() {
  local service=$1
  shift
  docker compose exec -T "$service" sh -c 'PGUSER="$POSTGRES_USER" exec "$@"' sh "$@"
}

container_env() {
  # container_env <container-id> <VAR>: print one variable from the container's
  # configuration. Callers capture it; it is never echoed.
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

is_running "$CORE_DB_SERVICE" || die "service '$CORE_DB_SERVICE' is not running; start it with: docker compose up -d $CORE_DB_SERVICE"

TS=$(date -u +%Y%m%dT%H%M%SZ)
umask 077
mkdir -p "$OUTPUT_ROOT"
DEST=$(cd "$OUTPUT_ROOT" && pwd)/autosecops-backup-$TS
mkdir "$DEST"
log "Writing backup to $DEST"

# Rough free-space check: the dumps are usually much smaller than the live
# database, so require at least the live size of the core database.
core_bytes=$(pg_exec "$CORE_DB_SERVICE" psql -XAtq -d "$CORE_DB_NAME" -c "select pg_database_size(current_database())")
free_kb=$(df -Pk "$DEST" | awk 'NR==2 {print $4}')
if ((free_kb * 1024 < core_bytes)); then
  die "only $((free_kb / 1024)) MiB free at $DEST; core database is $((core_bytes / 1048576)) MiB"
fi

STOPPED=()
restart_stopped() {
  if [[ ${#STOPPED[@]} -gt 0 ]]; then
    log "Starting services again: ${STOPPED[*]}"
    docker compose start "${STOPPED[@]}" >/dev/null || log "WARNING: could not restart ${STOPPED[*]}; run: docker compose up -d"
  fi
}
trap restart_stopped EXIT

if [[ $ONLINE -eq 0 ]]; then
  running=$(running_services)
  for svc in $QUIESCE_SERVICES; do
    if grep -qx "$svc" <<<"$running"; then
      STOPPED+=("$svc")
    fi
  done
  if [[ ${#STOPPED[@]} -gt 0 ]]; then
    log "Stopping writers for a consistent backup: ${STOPPED[*]}"
    docker compose stop "${STOPPED[@]}" >/dev/null
  fi
else
  log "Online backup: application services keep running"
fi

start_s=$(date +%s)

alembic_rev=$(pg_exec "$CORE_DB_SERVICE" psql -XAtq -d "$CORE_DB_NAME" -c "select string_agg(version_num, ',') from alembic_version" 2>/dev/null || echo unknown)
log "Dumping core database '$CORE_DB_NAME' (alembic revision $alembic_rev)"
pg_exec "$CORE_DB_SERVICE" pg_dump -Fc -d "$CORE_DB_NAME" >"$DEST/core.dump"

temporal_dumped=()
if [[ $SKIP_TEMPORAL -eq 0 ]]; then
  if is_running "$TEMPORAL_DB_SERVICE"; then
    existing=$(pg_exec "$TEMPORAL_DB_SERVICE" psql -XAtq -d postgres -c "select datname from pg_database")
    for db in $TEMPORAL_DB_NAMES; do
      if grep -qx "$db" <<<"$existing"; then
        log "Dumping Temporal database '$db'"
        pg_exec "$TEMPORAL_DB_SERVICE" pg_dump -Fc -d "$db" >"$DEST/temporal-$db.dump"
        temporal_dumped+=("$db")
      else
        log "Temporal database '$db' not found; skipping"
      fi
    done
  else
    log "WARNING: '$TEMPORAL_DB_SERVICE' is not running; Temporal history is not in this backup"
  fi
fi

minio_status=skipped
if [[ $SKIP_MINIO -eq 0 ]]; then
  minio_cid=$(docker compose ps -q "$MINIO_SERVICE" 2>/dev/null || true)
  if [[ -n "$minio_cid" ]] && is_running "$MINIO_SERVICE"; then
    minio_image=$(docker inspect --format '{{.Config.Image}}' "$minio_cid")
    minio_user=$(container_env "$minio_cid" MINIO_ROOT_USER)
    minio_pass=$(container_env "$minio_cid" MINIO_ROOT_PASSWORD)
    [[ -n "$minio_user" && -n "$minio_pass" ]] || die "could not read MinIO credentials from the '$MINIO_SERVICE' container"
    MC_HOST_src="http://$(urlencode "$minio_user"):$(urlencode "$minio_pass")@127.0.0.1:9000"
    export MC_HOST_src
    mkdir -p "$DEST/minio"
    log "Mirroring MinIO buckets with mc (image $minio_image)"
    # mc runs from the MinIO image itself, inside the MinIO container's network
    # namespace, so no extra image or published port is needed.
    docker run --rm --network "container:$minio_cid" \
      --user "$(id -u):$(id -g)" -e HOME=/tmp -e MC_CONFIG_DIR=/tmp/.mc -e MC_HOST_src \
      -v "$DEST/minio:/backup" --entrypoint mc "$minio_image" \
      --quiet --no-color mirror --preserve src /backup >/dev/null
    unset MC_HOST_src minio_user minio_pass
    minio_status="mirrored $(find "$DEST/minio" -type f | wc -l | tr -d ' ') objects"
    log "MinIO: $minio_status"
  else
    log "WARNING: '$MINIO_SERVICE' is not running; object storage is not in this backup"
  fi
fi

mkdir -p "$DEST/config"
for f in docker-compose.yml docker-compose.sandbox.yml docker-compose.override.yml Caddyfile; do
  [[ -f "$f" ]] && cp -p "$f" "$DEST/config/"
done
if [[ $COPY_ENV -eq 1 ]]; then
  if [[ -f .env ]]; then
    cp -p .env "$DEST/config/.env"
    chmod 600 "$DEST/config/.env"
  else
    log "WARNING: no .env in $(pwd); back up AUTOSECOPS__DB_ENCRYPTION_KEY and the other secrets separately"
  fi
else
  log "Skipped .env: store AUTOSECOPS__DB_ENCRYPTION_KEY, AUTOSECOPS__SERVICE_KEY, AUTOSECOPS__SIGNING_SECRET and USER_AUTH_SECRET separately"
fi

elapsed=$(($(date +%s) - start_s))

{
  echo "created_utc=$TS"
  echo "compose_project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$(docker compose ps -q "$CORE_DB_SERVICE")")"
  echo "mode=$([[ $ONLINE -eq 1 ]] && echo online || echo quiesced)"
  echo "core_db=$CORE_DB_SERVICE/$CORE_DB_NAME"
  echo "alembic_revision=$alembic_rev"
  echo "temporal_dbs=${temporal_dumped[*]:-}"
  echo "minio=$minio_status"
  echo "env_included=$([[ $COPY_ENV -eq 1 && -f .env ]] && echo yes || echo no)"
  echo "duration_seconds=$elapsed"
  echo "images:"
  docker compose ps -a --format '{{.Service}} {{.Image}}' 2>/dev/null | sort | sed 's/^/  /'
} >"$DEST/MANIFEST"

sums=$(cd "$DEST" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
printf '%s\n' "$sums" >"$DEST/SHA256SUMS"

restart_stopped
STOPPED=()

log "Backup complete in ${elapsed}s: $DEST ($(du -sh "$DEST" | cut -f1))"
log "Copy it off this host. It contains secrets: keep it encrypted and access-controlled."
printf '%s\n' "$DEST"
