#!/bin/bash

# Define color codes
if command -v tput >/dev/null && [ -t 1 ]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    NC=$(tput sgr0) # No Color
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
fi

dotenv_replace() {
    local env_var_name=$1
    local new_value=$2
    local file_path=$3
    local sed_option=""

    # Check if running on macOS and adjust sed_option accordingly
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed_option="-i ''"
    else
        sed_option="-i"
    fi

    # Use eval to correctly handle the dynamic insertion of the sed option
    delimiter="#"
    eval sed $sed_option "s$delimiter^${env_var_name}=.*$delimiter${env_var_name}=${new_value}$delimiter" $file_path
}

# Placeholder values shipped in .env.example. A .env that still contains one of
# these must never be deployed. `your-*` values are placeholders from older
# releases of .env.example.
PLACEHOLDER_PATTERN='^[A-Za-z_][A-Za-z0-9_]*=["'"'"']?(change-me-|your-autosecops-|your-tracecat-|your-auth-secret)'

# Well-known credentials that older releases and developer setups use. They are
# acceptable for local development only.
WEAK_DEFAULTS=(
    "AUTOSECOPS__POSTGRES_PASSWORD=postgres"
    "TEMPORAL__POSTGRES_PASSWORD=temporal"
    "MINIO_ROOT_PASSWORD=password"
    "MINIO_ROOT_PASSWORD=minioadmin"
)

dotenv_get() {
    local env_var_name=$1
    local file_path=$2
    grep -E "^${env_var_name}=" "$file_path" | tail -n 1 | cut -d '=' -f 2- | sed -E 's/^["'"'"'](.*)["'"'"']$/\1/'
}

# Print the password embedded in a redis:// or rediss:// URL, percent-decoded,
# or nothing when the URL carries none.
redis_url_password() {
    local password
    password=$(sed -nE 's#^rediss?://[^:/@]*:([^@]+)@.*$#\1#p' <<< "$1")
    if [ -n "$password" ]; then
        printf '%b' "$(sed 's/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g' <<< "$password")"
    fi
}

# Bring an existing env file up to date with settings that later releases
# require. Idempotent; backs the file up before the first change.
#   REDIS_PASSWORD: the bundled Redis requires a password. Reuse the password
#   from REDIS_URL when it has one (installs that followed the earlier Redis
#   hardening steps), otherwise generate one.
upgrade_env_file() {
    local file_path=$1
    if [ ! -f "$file_path" ]; then
        echo -e "${RED}No env file found at ${file_path}. Run ./env.sh to create one.${NC}"
        return 1
    fi

    local redis_password
    redis_password=$(dotenv_get "REDIS_PASSWORD" "$file_path")
    if [ -n "$redis_password" ] && [[ "$redis_password" != change-me-* ]]; then
        echo -e "${GREEN}${file_path} is up to date.${NC}"
        return 0
    fi

    local backup
    backup="${file_path}.backup_$(date "+%Y%m%d_%H%M%S")"
    cp -p "$file_path" "$backup"
    echo -e "${YELLOW}Backed up ${file_path} to ${backup}.${NC}"

    local source="generated"
    local value
    redis_password=$(redis_url_password "$(dotenv_get "REDIS_URL" "$file_path")")
    if [[ "$redis_password" == *"'"* ]]; then
        echo -e "${YELLOW}The REDIS_URL password contains a single quote, which .env cannot hold literally. Generating a new password; remove the credentials from REDIS_URL.${NC}"
        redis_password=""
    fi
    if [ -n "$redis_password" ]; then
        source="taken from REDIS_URL"
    else
        redis_password=$(openssl rand -hex 24)
    fi
    value=$redis_password
    # Single quotes keep Docker Compose from interpolating `$` and the like.
    if [[ ! "$value" =~ ^[A-Za-z0-9._-]+$ ]]; then
        value="'${value}'"
    fi
    if grep -qE "^REDIS_PASSWORD=" "$file_path"; then
        local tmp_file
        tmp_file=$(mktemp)
        # awk, not sed: a password taken from REDIS_URL may hold sed metacharacters.
        REDIS_PASSWORD_VALUE="$value" awk '
            /^REDIS_PASSWORD=/ { print "REDIS_PASSWORD=" ENVIRON["REDIS_PASSWORD_VALUE"]; next }
            { print }
        ' "$file_path" > "$tmp_file"
        cat "$tmp_file" > "$file_path"
        rm -f "$tmp_file"
    else
        printf '\n# Password the bundled Redis (Valkey) requires. Added by ./env.sh --upgrade.\nREDIS_PASSWORD=%s\n' "$value" >> "$file_path"
    fi
    echo -e "${GREEN}Set REDIS_PASSWORD (${source}). Recreate the stack with docker compose up -d.${NC}"
}

# Validate an env file. Exits non-zero when placeholders remain; warns about
# weak development credentials when the file is configured for production.
check_env_file() {
    local file_path=$1
    local status=0

    if [ ! -f "$file_path" ]; then
        echo -e "${RED}No env file found at ${file_path}. Run ./env.sh to create one.${NC}"
        return 1
    fi

    local placeholders
    placeholders=$(grep -nE "$PLACEHOLDER_PATTERN" "$file_path" | cut -d '=' -f 1)
    if [ -n "$placeholders" ]; then
        echo -e "${RED}${file_path} still contains placeholder secrets. Refusing to continue.${NC}"
        echo -e "${RED}Generate real values with ./env.sh (or set them manually) for:${NC}"
        echo "$placeholders" | awk -F ':' '{ print "  line " $1 ": " $2 }'
        status=1
    fi

    if [ -z "$(dotenv_get "REDIS_PASSWORD" "$file_path")" ]; then
        echo -e "${RED}${file_path} has no REDIS_PASSWORD. The bundled Redis requires one: run ./env.sh --upgrade${NC}"
        status=1
    fi

    local app_env
    app_env=$(dotenv_get "AUTOSECOPS__APP_ENV" "$file_path")
    if [ "$app_env" = "production" ]; then
        local weak
        for weak in "${WEAK_DEFAULTS[@]}"; do
            if grep -qxE "${weak}" "$file_path"; then
                echo -e "${YELLOW}Warning: ${weak%%=*} uses a well-known development value in production mode.${NC}"
                echo -e "${YELLOW}Rotate it: https://docs.singularityrd.com/self-hosting/security#infrastructure-credentials${NC}"
            fi
        done
        if [ "$(dotenv_get "TEMPORAL__UI_VERSION" "$file_path")" = "latest" ]; then
            echo -e "${YELLOW}Warning: TEMPORAL__UI_VERSION=latest is not pinned. Set it to a specific Temporal UI release.${NC}"
        fi
        if [ -z "$(dotenv_get "AUTOSECOPS__AUTH_ALLOWED_DOMAINS" "$file_path")" ]; then
            echo -e "${YELLOW}Note: AUTOSECOPS__AUTH_ALLOWED_DOMAINS is blank, so any email domain can sign up. Set it to your organization's domains.${NC}"
        fi
    fi

    if [ "$status" -eq 0 ]; then
        echo -e "${GREEN}${file_path} has no placeholder secrets.${NC}"
    fi
    return $status
}

if [ "${1:-}" = "--check" ]; then
    check_env_file "${2:-.env}"
    exit $?
fi

if [ "${1:-}" = "--upgrade" ]; then
    if ! openssl version &> /dev/null; then
        echo -e "${RED}Could not run openssl. Please check if openssl is correctly installed.${NC}"
        exit 1
    fi
    upgrade_env_file "${2:-.env}" || exit $?
    check_env_file "${2:-.env}"
    exit $?
fi

if [ -n "${1:-}" ]; then
    echo -e "${RED}Unknown argument: $1${NC}"
    echo "Usage: ./env.sh            Create .env from .env.example"
    echo "       ./env.sh --check [file]  Refuse an env file that still has placeholder secrets"
    echo "       ./env.sh --upgrade [file]  Add settings a newer release requires (backs the file up first)"
    exit 2
fi

echo -e "${YELLOW}Creating .env...${NC}"

# If .env exists, ask user if they want to overwrite it
if [ -f .env ]; then
    read -p "A .env file already exists. Do you want to overwrite it? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Keeping the existing .env. Checking it for placeholder secrets...${NC}"
        check_env_file ".env"
        exit $?
    fi
fi

# Create .env file

if [ ! -e ".env.example" ] ; then
  echo "${RED}No .env.example file found in current directory: $(pwd). Copy .env.example from /opt/autosecops/install in the AutoSecOps image (see the Docker Compose self-hosting docs) and rerun the env.sh script."
  exit 1
fi
env_file=".env"

if ! openssl --help &> /dev/null
then
  echo  -e "${RED}Could not run openssl. Please check if openssl is correctly installed."
  exit 1
fi

echo -e "${YELLOW}Generating new service key and signing secret...${NC}"

service_key=$(openssl rand -hex 32)
signing_secret=$(openssl rand -hex 32)
user_auth_secret=$(openssl rand -hex 32)

echo -e "${YELLOW}Generating a Fernet encryption key for the database...${NC}"

# Use a cross-platform base64 command (works on both Linux and macOS)
db_fernet_key=$(openssl rand 32 | base64 | tr -d '\n' | tr '+/' '-_')

echo -e "${YELLOW}Creating new .env from .env.example...${NC}"
cp .env.example .env

# Replace existing values of AUTOSECOPS__SERVICE_KEY and AUTOSECOPS__SIGNING_SECRET
dotenv_replace "AUTOSECOPS__SERVICE_KEY" "$service_key" "$env_file"
dotenv_replace "AUTOSECOPS__SIGNING_SECRET" "$signing_secret" "$env_file"
dotenv_replace "AUTOSECOPS__DB_ENCRYPTION_KEY" "$db_fernet_key" "$env_file"
dotenv_replace "USER_AUTH_SECRET" "$user_auth_secret" "$env_file"

# Prompt user for environment mode
while true; do
    read -p "Use production mode? (y/n, default: y): " prod_mode
    prod_mode=${prod_mode:-y}
    case $prod_mode in
        [Yy]* )
            env_mode="production"
            break
            ;;
        [Nn]* )
            env_mode="development"
            break
            ;;
        * ) echo -e "${RED}Please answer y or n.${NC}";;
    esac
done

# Infrastructure credentials for the bundled PostgreSQL, Temporal PostgreSQL,
# and MinIO containers. Production mode always generates strong values.
# Development mode keeps the well-known DEV-ONLY values that local tooling and
# tests expect (postgres/postgres, temporal/temporal, minio/password).
# AUTOSECOPS_DEV_CREDENTIALS=true forces the DEV-ONLY values in either mode,
# for CI jobs that need production mode against throwaway local services.
use_dev_credentials="false"
if [ "$env_mode" = "development" ] || [ "${AUTOSECOPS_DEV_CREDENTIALS:-false}" = "true" ]; then
    use_dev_credentials="true"
fi
if [ "$use_dev_credentials" = "true" ]; then
    echo -e "${YELLOW}Using DEV-ONLY infrastructure credentials. Do not expose this deployment.${NC}"
    postgres_password="postgres"
    temporal_postgres_password="temporal"
    minio_root_password="password"
else
    echo -e "${YELLOW}Generating PostgreSQL, Temporal PostgreSQL, and MinIO passwords...${NC}"
    postgres_password=$(openssl rand -hex 24)
    temporal_postgres_password=$(openssl rand -hex 24)
    minio_root_password=$(openssl rand -hex 24)
fi
dotenv_replace "AUTOSECOPS__POSTGRES_PASSWORD" "$postgres_password" "$env_file"
dotenv_replace "TEMPORAL__POSTGRES_PASSWORD" "$temporal_postgres_password" "$env_file"
dotenv_replace "MINIO_ROOT_PASSWORD" "$minio_root_password" "$env_file"

# The services connect as a non-owner role so tenant row-level security
# applies; migrations create it with this password. Always random: no local
# tooling logs in as it.
echo -e "${YELLOW}Generating the database runtime role password...${NC}"
db_runtime_password=$(openssl rand -hex 24)
dotenv_replace "AUTOSECOPS__DB_RUNTIME_PASSWORD" "$db_runtime_password" "$env_file"

# The bundled Redis requires a password in every mode. Always random: host
# tooling and tests read it from .env.
echo -e "${YELLOW}Generating the Redis password...${NC}"
redis_password=$(openssl rand -hex 24)
dotenv_replace "REDIS_PASSWORD" "$redis_password" "$env_file"

# Prompt for the public address. Keep a typed http:// or https:// scheme.
# Without one, production mode uses https:// for any host but a loopback
# address, so session cookies are marked Secure; development mode uses http://.
is_loopback_host() {
    case "$1" in
        localhost | *.localhost | 127.* | "[::1]") return 0 ;;
        *) return 1 ;;
    esac
}

while true; do
    read -p "Set \`PUBLIC_APP_URL\` environment variable to (default: localhost): " new_ip
    # Trim whitespace and any trailing slash.
    new_ip=$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s#/+$##' <<< "$new_ip")
    scheme=""
    if [[ "$new_ip" =~ ^([A-Za-z][A-Za-z0-9+.-]*)://(.*)$ ]]; then
        scheme=$(tr '[:upper:]' '[:lower:]' <<< "${BASH_REMATCH[1]}")
        new_ip="${BASH_REMATCH[2]}"
        if [ "$scheme" != "http" ] && [ "$scheme" != "https" ]; then
            echo -e "${RED}Use an http:// or https:// address, or type the host without a scheme.${NC}"
            continue
        fi
    fi
    new_ip=${new_ip:-localhost}

    if [ "$new_ip" != "0.0.0.0" ]; then
        break
    fi
    echo -e "${RED}Cannot use 0.0.0.0 as address.\nSee https://docs.singularityrd.com/self-hosting/docker-compose#faq ${NC}"
done

# Extract hostname and port from the input
# Handle formats like: localhost, localhost:8080, 127.0.0.1:8080
if [[ "$new_ip" =~ ^([^:]+)(:([0-9]+))?$ ]]; then
    hostname="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[3]}"
else
    # Fallback if regex doesn't match
    hostname="$new_ip"
    port=""
fi

if [ -z "$scheme" ]; then
    if [ "$env_mode" = "production" ] && ! is_loopback_host "$hostname"; then
        scheme="https"
    else
        scheme="http"
    fi
fi

base_url="${scheme}://${hostname}${port:+:${port}}"
# Caddy serves plain HTTP on PUBLIC_APP_PORT. With https://, the port in the
# URL belongs to the TLS endpoint in front of Caddy, so leave PUBLIC_APP_PORT.
app_port=""
if [ "$scheme" = "http" ] && [ -n "$port" ]; then
    app_port="$port"
fi
if [ "$scheme" = "https" ]; then
    echo -e "${YELLOW}Using ${base_url}. Terminate TLS in Caddy or a load balancer: https://docs.singularityrd.com/self-hosting/tls${NC}"
    echo -e "${YELLOW}To serve plain HTTP instead, rerun ./env.sh and type http://${hostname}${port:+:${port}}.${NC}"
fi

public_app_url="$base_url"
public_api_url="${base_url}/api"


# Prompt user for PostgreSQL SSL mode
while true; do
    read -p "Require PostgreSQL SSL mode? (y/n, default: n): " postgres_ssl
    postgres_ssl=${postgres_ssl:-n}
    case $postgres_ssl in
        [Yy]* )
            ssl_mode="require"
            break
            ;;
        [Nn]* )
            ssl_mode="disable"
            break
            ;;
        * ) echo -e "${RED}Please answer y or n.${NC}";;
    esac
done

# Prompt user for superadmin email
echo -e "${YELLOW}Setting up first user (superadmin)...${NC}"
while true; do
    read -p "Enter email address for the first user (superadmin): " superadmin_email
    if [[ -z "$superadmin_email" ]]; then
        echo -e "${RED}Email address cannot be empty. Please enter a valid email address.${NC}"
        continue
    fi
    # Basic email validation
    if [[ "$superadmin_email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        echo -e "${RED}Please enter a valid email address.${NC}"
    fi
done

# Update environment variables
dotenv_replace "AUTOSECOPS__APP_ENV" "$env_mode" "$env_file"
dotenv_replace "NODE_ENV" "$env_mode" "$env_file"
dotenv_replace "NEXT_PUBLIC_APP_ENV" "$env_mode" "$env_file"
dotenv_replace "PUBLIC_API_URL" "$public_api_url" "$env_file"
dotenv_replace "PUBLIC_APP_URL" "$public_app_url" "$env_file"
# Update PUBLIC_APP_PORT if port was specified
if [ -n "$app_port" ]; then
    dotenv_replace "PUBLIC_APP_PORT" "$app_port" "$env_file"
fi
dotenv_replace "AUTOSECOPS__DB_SSLMODE" "$ssl_mode" "$env_file"
dotenv_replace "AUTOSECOPS__AUTH_SUPERADMIN_EMAIL" "$superadmin_email" "$env_file"

# Allow the public app URL, plus the local frontend dev server in development.
new_origins="${public_app_url}"
if [ "$env_mode" = "development" ]; then
    new_origins="http://localhost:3000,${public_app_url}"
fi
# Remove duplicate entries and leading/trailing commas
new_origins=$(echo "$new_origins" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/^,//;s/,$//')
dotenv_replace "AUTOSECOPS__ALLOW_ORIGINS" "$new_origins" "$env_file"

if ! check_env_file "$env_file"; then
    echo -e "${RED}Environment file is incomplete. Fix the values above before starting AutoSecOps.${NC}"
    exit 1
fi

echo -e "${GREEN}Environment file created successfully.${NC}"
echo -e "${GREEN}First user (superadmin) email set to: ${superadmin_email}${NC}"
