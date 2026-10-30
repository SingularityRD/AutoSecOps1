#!/usr/bin/env bash
# AutoSecOps local evaluation lab helper.
#
# Run from any directory on Linux, macOS, or inside WSL2 on Windows (Docker
# Desktop with WSL integration enabled). Needs bash, docker, curl, and openssl.
#
#   lab.sh env                     Create .env.lab with generated local-only secrets
#   lab.sh wazuh-init              Download Wazuh's single-node config and make certs
#   lab.sh up [--gpu] PROFILE...   Start profiles: misp opensearch wazuh fleet mailpit ollama
#   lab.sh ps                      Show lab containers
#   lab.sh seed [TARGET...]        Load sample data: misp opensearch wazuh (default: all running)
#   lab.sh secrets                 Print the AutoSecOps secrets and variables to create
#   lab.sh llm-check [URL] [MODEL] Check that AutoSecOps can reach Ollama and the model calls tools
#   lab.sh allowlist [URL]         Print the AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS entry for an LLM URL
#   lab.sh down                    Stop and remove lab containers; keep their data volumes
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$LAB_DIR/.env.lab"
ENV_EXAMPLE="$LAB_DIR/.env.lab.example"
COMPOSE_FILE="$LAB_DIR/docker-compose.lab.yml"
GPU_FILE="$LAB_DIR/docker-compose.lab.gpu.yml"
WAZUH_VERSION="4.14.9"
WAZUH_DIR="$LAB_DIR/wazuh"
ALL_PROFILES=(misp opensearch wazuh fleet mailpit ollama)

die() {
    echo "lab.sh: $*" >&2
    exit 1
}

load_env() {
    [[ -f "$ENV_FILE" ]] || die "missing $ENV_FILE. Run: lab.sh env"
    if grep -q '=change-me-' "$ENV_FILE"; then
        die "$ENV_FILE still has change-me- placeholders. Delete it and run: lab.sh env"
    fi
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
}

compose() {
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

core_network() {
    echo "${AUTOSECOPS_CORE_NETWORK:-autosecops_core}"
}

# Container of a main-stack service, found by its Compose labels.
stack_container() {
    local service="$1" project
    project="$(core_network)"
    project="${project%_core}"
    docker ps -q \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.service=$service" | head -n 1
}

random_hex() {
    openssl rand -hex "$1"
}

# Upper case, lower case, digits, and a symbol: meets the OpenSearch, MISP,
# and Wazuh API password policies.
random_password() {
    printf 'Lab-%s-9x' "$(random_hex 12)"
}

cmd_env() {
    if [[ -f "$ENV_FILE" ]]; then
        echo "$ENV_FILE already exists; leaving it unchanged."
        return
    fi
    command -v openssl >/dev/null || die "openssl is required"
    local tmp key value
    tmp="$(mktemp)"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^([A-Z0-9_]+)=change-me- ]]; then
            key="${BASH_REMATCH[1]}"
            case "$key" in
                LAB_MISP_ADMIN_KEY) value="$(random_hex 20)" ;;
                LAB_MISP_ENCRYPTION_KEY) value="$(random_hex 16)" ;;
                *_PASSWORD) value="$(random_password)" ;;
                *) value="$(random_hex 16)" ;;
            esac
            line="$key=$value"
        fi
        printf '%s\n' "$line" >>"$tmp"
    done <"$ENV_EXAMPLE"
    mv "$tmp" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "Wrote $ENV_FILE with generated local-only secrets."
}

cmd_wazuh_init() {
    load_env
    local config="$WAZUH_DIR/config"
    if [[ ! -f "$config/certs.yml" ]]; then
        local tmp
        tmp="$(mktemp -d)"
        echo "Downloading wazuh-docker v$WAZUH_VERSION single-node config..."
        curl -fsSL -o "$tmp/wazuh-docker.tar.gz" \
            "https://github.com/wazuh/wazuh-docker/archive/refs/tags/v$WAZUH_VERSION.tar.gz"
        tar -xzf "$tmp/wazuh-docker.tar.gz" -C "$tmp" \
            "wazuh-docker-$WAZUH_VERSION/single-node/config"
        mkdir -p "$WAZUH_DIR"
        mv "$tmp/wazuh-docker-$WAZUH_VERSION/single-node/config" "$config"
        rm -rf "$tmp"
    fi
    if [[ -f "$config/wazuh_indexer_ssl_certs/root-ca.pem" ]]; then
        echo "Wazuh certificates already exist in $config/wazuh_indexer_ssl_certs."
        return
    fi
    echo "Generating Wazuh certificates..."
    compose --profile wazuh-init run --rm wazuh-certs
}

cmd_up() {
    load_env
    local files=(-f "$COMPOSE_FILE") profiles=() arg
    for arg in "$@"; do
        case "$arg" in
            --gpu) files+=(-f "$GPU_FILE") ;;
            misp | opensearch | wazuh | fleet | mailpit | ollama) profiles+=(--profile "$arg") ;;
            *) die "unknown profile: $arg (choose from: ${ALL_PROFILES[*]})" ;;
        esac
    done
    [[ ${#profiles[@]} -gt 0 ]] || die "name at least one profile: ${ALL_PROFILES[*]}"
    docker network inspect "$(core_network)" >/dev/null 2>&1 ||
        die "network $(core_network) not found. Start AutoSecOps first, or set AUTOSECOPS_CORE_NETWORK in $ENV_FILE"
    if [[ " $* " == *" wazuh "* && ! -f "$WAZUH_DIR/config/wazuh_indexer_ssl_certs/root-ca.pem" ]]; then
        die "run lab.sh wazuh-init before starting the wazuh profile"
    fi
    docker compose --env-file "$ENV_FILE" "${files[@]}" "${profiles[@]}" up -d
}

cmd_ps() {
    load_env
    compose --profile '*' ps
}

cmd_down() {
    load_env
    # No -v: lab data volumes survive. Remove them with
    # `docker compose -p autosecops-lab down -v` only if you want the data gone.
    compose --profile '*' down
}

running() {
    [[ -n "$(compose --profile '*' ps -q --status running "$1" 2>/dev/null)" ]]
}

# Poll a URL until it answers with one of the expected HTTP codes.
wait_for() {
    local name="$1" url="$2" codes="$3" tries="${4:-60}"
    shift 4 || true
    local code
    for ((i = 1; i <= tries; i++)); do
        code="$(curl -sk -o /dev/null -w '%{http_code}' "$@" "$url" || true)"
        if [[ "$code" =~ ^($codes)$ ]]; then
            return 0
        fi
        sleep 5
    done
    die "$name did not become ready at $url (last HTTP status $code)"
}

seed_misp() {
    local base="https://localhost:${LAB_MISP_PORT:-8443}"
    local auth=(-H "Authorization: $LAB_MISP_ADMIN_KEY" -H "Accept: application/json" -H "Content-Type: application/json")
    echo "MISP: waiting for $base (first start takes several minutes)..."
    wait_for MISP "$base/servers/getVersion" 200 120 "${auth[@]}"
    if curl -sk "${auth[@]}" -X POST "$base/attributes/restSearch" \
        -d '{"value":"203.0.113.10","limit":1}' | grep -q '"value":"203.0.113.10"'; then
        echo "MISP: sample event already present."
        return
    fi
    curl -fsSk "${auth[@]}" -X POST "$base/events/add" -o /dev/null -d @- <<'JSON'
{
  "Event": {
    "info": "AutoSecOps lab: sample commodity malware IOCs",
    "distribution": 0,
    "threat_level_id": 2,
    "analysis": 1,
    "Tag": [{"name": "tlp:clear"}],
    "Attribute": [
      {"type": "ip-dst", "category": "Network activity", "value": "203.0.113.10", "to_ids": true, "comment": "Synthetic C2 address (TEST-NET-3)"},
      {"type": "ip-src", "category": "Network activity", "value": "198.51.100.23", "to_ids": true, "comment": "Synthetic SSH brute-force source (TEST-NET-2)"},
      {"type": "domain", "category": "Network activity", "value": "c2.lab-malware.example", "to_ids": true, "comment": "Synthetic C2 domain"},
      {"type": "url", "category": "Network activity", "value": "http://c2.lab-malware.example/payload.exe", "to_ids": true, "comment": "Synthetic payload URL"},
      {"type": "md5", "category": "Payload delivery", "value": "44d88612fea8a8f36de82e1278abb02f", "to_ids": true, "comment": "EICAR test file"},
      {"type": "sha256", "category": "Payload delivery", "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "to_ids": true, "comment": "EICAR test file"}
    ]
  }
}
JSON
    echo "MISP: created sample event with 6 attributes."
}

seed_opensearch() {
    local base="https://localhost:${LAB_OPENSEARCH_PORT:-9201}"
    local auth=(-u "admin:$LAB_OPENSEARCH_ADMIN_PASSWORD" -H "Content-Type: application/json")
    echo "OpenSearch: waiting for $base..."
    wait_for OpenSearch "$base/_cluster/health" 200 60 -u "admin:$LAB_OPENSEARCH_ADMIN_PASSWORD"
    curl -sk "${auth[@]}" -X PUT "$base/lab-alerts" -o /dev/null -d @- <<'JSON'
{
  "settings": {"number_of_replicas": 0},
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "alert.id": {"type": "keyword"},
      "rule.name": {"type": "keyword"},
      "event.severity": {"type": "keyword"},
      "host.name": {"type": "keyword"},
      "user.name": {"type": "keyword"},
      "source.ip": {"type": "ip"},
      "destination.ip": {"type": "ip"},
      "destination.domain": {"type": "keyword"},
      "url.full": {"type": "keyword"},
      "file.hash.md5": {"type": "keyword"},
      "file.hash.sha256": {"type": "keyword"},
      "message": {"type": "text"}
    }
  }
}
JSON
    local now one_hour_ago
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    one_hour_ago="$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)"
    curl -fsSk "${auth[@]}" -H "Content-Type: application/x-ndjson" -X POST \
        "$base/_bulk?refresh=true" -o /dev/null --data-binary @- <<NDJSON
{"index":{"_index":"lab-alerts","_id":"lab-alert-0001"}}
{"@timestamp":"$one_hour_ago","alert.id":"lab-alert-0001","rule.name":"SSH brute force","event.severity":"high","host.name":"lab-endpoint-01","user.name":"root","source.ip":"198.51.100.23","message":"42 failed SSH logins for root from 198.51.100.23 in 5 minutes"}
{"index":{"_index":"lab-alerts","_id":"lab-alert-0002"}}
{"@timestamp":"$one_hour_ago","alert.id":"lab-alert-0002","rule.name":"Malware file detected","event.severity":"critical","host.name":"lab-workstation-07","user.name":"jdoe","file.hash.md5":"44d88612fea8a8f36de82e1278abb02f","file.hash.sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","message":"Endpoint agent quarantined eicar.com in the Downloads folder"}
{"index":{"_index":"lab-alerts","_id":"lab-alert-0003"}}
{"@timestamp":"$now","alert.id":"lab-alert-0003","rule.name":"Outbound connection to suspicious domain","event.severity":"medium","host.name":"lab-workstation-07","user.name":"jdoe","destination.ip":"203.0.113.10","destination.domain":"c2.lab-malware.example","url.full":"http://c2.lab-malware.example/payload.exe","message":"Proxy allowed GET http://c2.lab-malware.example/payload.exe"}
{"index":{"_index":"lab-alerts","_id":"lab-alert-0004"}}
{"@timestamp":"$now","alert.id":"lab-alert-0004","rule.name":"New local administrator","event.severity":"low","host.name":"lab-server-02","user.name":"svc-backup","message":"User svc-backup added to the local Administrators group"}
NDJSON
    echo "OpenSearch: indexed 4 sample alerts into lab-alerts."
}

seed_wazuh() {
    local base="https://localhost:${LAB_WAZUH_API_PORT:-55000}" token
    echo "Wazuh: waiting for the manager API at $base..."
    wait_for Wazuh "$base/security/user/authenticate" 200 90 \
        -u "wazuh-wui:$LAB_WAZUH_API_PASSWORD" -X POST
    token="$(curl -fsSk -u "wazuh-wui:$LAB_WAZUH_API_PASSWORD" -X POST \
        "$base/security/user/authenticate?raw=true")"
    for ((i = 1; i <= 24; i++)); do
        if curl -fsSk -H "Authorization: Bearer $token" "$base/agents?name=lab-endpoint-01" |
            grep -q '"name": *"lab-endpoint-01"'; then
            echo "Wazuh: agent lab-endpoint-01 is enrolled."
            break
        fi
        [[ $i -eq 24 ]] && echo "Wazuh: agent lab-endpoint-01 has not enrolled yet; check: lab.sh ps"
        sleep 5
    done
    # Synthetic sshd failures from a TEST-NET address. The manager decodes them
    # like agent logs, so the SSH rules (5710, 5712 brute force) fire.
    local ts events=() line
    ts="$(date -u '+%b %e %H:%M:%S')"
    for ((i = 1; i <= 10; i++)); do
        line="$ts lab-endpoint-01 sshd[41$i]: Failed password for invalid user admin from 198.51.100.23 port 5$((1000 + i)) ssh2"
        events+=("\"$line\"")
    done
    curl -fsSk -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
        -X POST "$base/events" -o /dev/null \
        -d "{\"events\":[$(IFS=,; echo "${events[*]}")]}"
    echo "Wazuh: sent 10 failed SSH logins from 198.51.100.23 (alerts appear in wazuh-alerts-* within a minute)."
}

cmd_seed() {
    load_env
    local targets=("$@")
    if [[ ${#targets[@]} -eq 0 ]]; then
        running misp && targets+=(misp)
        running lab-opensearch && targets+=(opensearch)
        running wazuh.manager && targets+=(wazuh)
        [[ ${#targets[@]} -gt 0 ]] || die "no seedable profile is running (misp, opensearch, wazuh)"
    fi
    local target
    for target in "${targets[@]}"; do
        case "$target" in
            misp) seed_misp ;;
            opensearch) seed_opensearch ;;
            wazuh) seed_wazuh ;;
            *) die "unknown seed target: $target" ;;
        esac
    done
}

cmd_secrets() {
    load_env
    cat <<EOF
Create these in your AutoSecOps workspace: secrets on the Credentials page,
variables on the Variables page. Values come from $ENV_FILE.

Secrets
  misp           MISP_API_KEY=$LAB_MISP_ADMIN_KEY
  opensearch     OPENSEARCH_USERNAME=admin  OPENSEARCH_PASSWORD=$LAB_OPENSEARCH_ADMIN_PASSWORD
  wazuh_wui      WAZUH_WUI_USERNAME=wazuh-wui  WAZUH_WUI_PASSWORD=$LAB_WAZUH_API_PASSWORD
  wazuh_indexer  WAZUH_INDEXER_USERNAME=admin  WAZUH_INDEXER_PASSWORD=${LAB_WAZUH_INDEXER_PASSWORD:-SecretPassword}
  smtp           SMTP_HOST=lab-mailpit  SMTP_PORT=1025  SMTP_USER=lab  SMTP_PASS=lab
  fleetdm        FLEETDM_API_TOKEN=<API-only user token from the Fleet UI>

Variables (name: key=value)
  misp:          base_url=https://misp:8443
  opensearch:    base_url=https://lab-opensearch:9200
  wazuh:         base_url=https://wazuh.manager:55000
  wazuh_indexer: base_url=https://wazuh.indexer:9200
  fleetdm:       base_url=http://lab-fleet:8080

Lab services use self-signed certificates: set verify_ssl to false.

Web UIs on this computer
  MISP                   https://localhost:${LAB_MISP_PORT:-8443}  (${LAB_MISP_ADMIN_EMAIL:-admin@lab.local} / $LAB_MISP_ADMIN_PASSWORD)
  OpenSearch Dashboards  http://localhost:${LAB_OPENSEARCH_DASHBOARDS_PORT:-5602}  (admin / $LAB_OPENSEARCH_ADMIN_PASSWORD)
  Wazuh dashboard        https://localhost:${LAB_WAZUH_DASHBOARD_PORT:-5443}  (admin / ${LAB_WAZUH_INDEXER_PASSWORD:-SecretPassword})
  Fleet                  http://localhost:${LAB_FLEET_PORT:-8412}
  Mailpit                http://localhost:${LAB_MAILPIT_UI_PORT:-8025}
EOF
}

# Python run inside the AutoSecOps litellm container, so the check uses the
# same network path and DNS as agent requests.
LLM_CHECK_PY='
import json, socket, sys, urllib.parse, urllib.request
base, model, mode = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
host = urllib.parse.urlsplit(base).hostname
addr = socket.gethostbyname(host)
if mode == "allowlist":
    print(f"{addr}/32")
    sys.exit(0)
root = base[:-3] if base.endswith("/v1") else base
print(f"{host} resolves to {addr} inside AutoSecOps.")
tags = json.load(urllib.request.urlopen(root + "/api/tags", timeout=15))
names = [m["name"] for m in tags.get("models", [])]
print("Models on this Ollama:", ", ".join(names) or "(none)")
if model not in names and f"{model}:latest" not in names:
    sys.exit(f"Model {model} is not pulled. Run: ollama pull {model}")
show = json.load(urllib.request.urlopen(urllib.request.Request(
    root + "/api/show", data=json.dumps({"model": model}).encode(),
    headers={"Content-Type": "application/json"}), timeout=60))
caps = show.get("capabilities", [])
print("Capabilities:", ", ".join(caps) or "(not reported)")
if caps and "tools" not in caps:
    sys.exit(f"{model} does not support tool calling. Pick a model with the tools capability.")
body = {
    "model": model, "stream": False,
    "messages": [{"role": "user", "content": "What is the EPSS score of CVE-2021-44228? Use the tool."}],
    "tools": [{"type": "function", "function": {
        "name": "lookup_cve_scores",
        "description": "Look up FIRST EPSS scores for a CVE identifier.",
        "parameters": {"type": "object", "properties": {"cve": {"type": "string"}}, "required": ["cve"]}}}],
}
if "thinking" in caps:
    body["think"] = False
print(f"Asking {model} to call a tool (CPU-only models can take a few minutes)...")
reply = json.load(urllib.request.urlopen(urllib.request.Request(
    root + "/api/chat", data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json"}), timeout=600))
calls = reply.get("message", {}).get("tool_calls") or []
if not calls:
    sys.exit("FAIL: the model answered without calling the tool: " + reply.get("message", {}).get("content", "")[:300])
print("PASS: tool call", json.dumps(calls[0].get("function", {})))
'

llm_python() {
    local container
    container="$(stack_container litellm)"
    [[ -n "$container" ]] || die "AutoSecOps litellm container not found. Is the stack running?"
    docker exec "$container" python -c "$LLM_CHECK_PY" "$@"
}

cmd_llm_check() {
    [[ -f "$ENV_FILE" ]] && load_env
    llm_python "${1:-http://host.docker.internal:11434/v1}" "${2:-qwen3:8b}" check
}

cmd_allowlist() {
    [[ -f "$ENV_FILE" ]] && load_env
    llm_python "${1:-http://host.docker.internal:11434/v1}" unused allowlist
}

main() {
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        env) cmd_env ;;
        wazuh-init) cmd_wazuh_init ;;
        up) cmd_up "$@" ;;
        ps) cmd_ps ;;
        seed) cmd_seed "$@" ;;
        secrets) cmd_secrets ;;
        llm-check) cmd_llm_check "$@" ;;
        allowlist) cmd_allowlist "$@" ;;
        down) cmd_down ;;
        *) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; [[ -z "$cmd" ]] || exit 1 ;;
    esac
}

main "$@"
