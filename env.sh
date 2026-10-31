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

# Replace a whole `NAME=value` line without passing the value through sed or
# eval, so values with quotes, braces, or `#` (such as a JSON keyring) stay
# intact. Keeps the file's permissions.
dotenv_replace_literal() {
    local env_var_name=$1
    local new_value=$2
    local file_path=$3
    local tmp_file
    tmp_file=$(mktemp "${file_path}.XXXXXX")
    ENV_NAME="$env_var_name" ENV_VALUE="$new_value" awk '
        BEGIN { name = ENVIRON["ENV_NAME"]; value = ENVIRON["ENV_VALUE"] }
        index($0, name "=") == 1 { print name "=" value; next }
        { print }
    ' "$file_path" > "$tmp_file" && cat "$tmp_file" > "$file_path"
    rm -f "$tmp_file"
}

# Print a Temporal payload encryption keyring with one random 256-bit root
# secret. Single-quoted so Docker Compose reads the JSON literally.
generate_temporal_payload_keyring() {
    local key_id=$1
    local root_secret
    root_secret=$(openssl rand -hex 32)
    printf "'{\"current_key_id\":\"%s\",\"keys\":{\"%s\":\"%s\"}}'" \
        "$key_id" "$key_id" "$root_secret"
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
        if [ "$(dotenv_get "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED" "$file_path")" != "true" ]; then
            echo -e "${YELLOW}Warning: TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED is not true, so workflow inputs and results are stored in plaintext in the Temporal database.${NC}"
            echo -e "${YELLOW}Enable it: https://docs.singularityrd.com/self-hosting/security#temporal-payload-encryption${NC}"
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

if [ -n "${1:-}" ]; then
    echo -e "${RED}Unknown argument: $1${NC}"
    echo "Usage: ./env.sh            Create .env from .env.example"
    echo "       ./env.sh --check [file]  Refuse an env file that still has placeholder secrets"
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

echo -e "${YELLOW}Generating a Temporal payload encryption keyring...${NC}"
temporal_payload_keyring=$(generate_temporal_payload_keyring "v1")

echo -e "${YELLOW}Creating new .env from .env.example...${NC}"
cp .env.example .env

# Replace existing values of AUTOSECOPS__SERVICE_KEY and AUTOSECOPS__SIGNING_SECRET
dotenv_replace "AUTOSECOPS__SERVICE_KEY" "$service_key" "$env_file"
dotenv_replace "AUTOSECOPS__SIGNING_SECRET" "$signing_secret" "$env_file"
dotenv_replace "AUTOSECOPS__DB_ENCRYPTION_KEY" "$db_fernet_key" "$env_file"
dotenv_replace "USER_AUTH_SECRET" "$user_auth_secret" "$env_file"
dotenv_replace_literal "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING" "$temporal_payload_keyring" "$env_file"
dotenv_replace "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED" "true" "$env_file"

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
