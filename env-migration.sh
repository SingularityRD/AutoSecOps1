#!/bin/bash

# SUMMARY
# -------
# This script migrates your existing .env file to match a new .env.template structure.
# Here's what it does:
#
# 1. Creates a timestamped backup of your current .env file.
# 2. Reads your existing .env file and the new .env.template.
# 3. Creates a new .env file based on the .env.template structure.
# 4. Preserves values from your old .env for keys that exist in the new template.
# 5. Adds new keys from the template (with empty values) if they didn't exist in your old .env.
# 6. Ignores keys from your old .env that don't exist in the new template.
#
# Note: This script will overwrite your current .env file, but a backup is always created first.
# You will be asked for confirmation before any changes are made.

# Function to read and parse .env file
parse_env() {
    local file=$1
    grep -v '^#' "$file" | grep '=' | sed 's/[[:space:]]*=[[:space:]]*/=/' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//'
}

# Get current datetime
DATETIME=$(date "+%Y%m%d_%H%M%S")

# Paths to the files
OLD_ENV=".env"
NEW_TEMPLATE=".env.example"
OUTPUT_ENV=".env"
BACKUP_ENV=".env.backup_${DATETIME}"

# Check if .env file exists
if [ ! -f "$OLD_ENV" ]; then
    echo "Error: $OLD_ENV file not found."
    exit 1
fi

# Check if .env.template file exists
if [ ! -f "$NEW_TEMPLATE" ]; then
    echo "Error: $NEW_TEMPLATE file not found."
    exit 1
fi

# Prompt for backup
read -p "Do you want to create a backup of the current .env file? (y/n): " backup_choice
if [[ $backup_choice =~ ^[Yy]$ ]]; then
    cp "$OLD_ENV" "$BACKUP_ENV"
    echo "Backup created at $BACKUP_ENV"
fi

# Warning about overriding
echo "Warning: This script will override the current .env file."
read -p "Do you want to continue? (y/n): " continue_choice
if [[ ! $continue_choice =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    exit 0
fi

# Temporary file for processing
TEMP_FILE=$(mktemp)

# Process the new template and create the output
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ $line =~ ^[[:space:]]*$ || $line =~ ^# ]]; then
        # Empty line or comment, copy as is
        echo "$line" >> "$TEMP_FILE"
    elif [[ $line =~ ^[[:space:]]*([^=]+)[[:space:]]*= ]]; then
        # Extract key
        key=${BASH_REMATCH[1]}
        # Look for the key in the old .env file
        old_value=$(grep "^${key}=" "$OLD_ENV" | sed "s/^${key}=//")
        if [[ -n "$old_value" ]]; then
            # Key exists in old .env, use its value
            echo "${key}=${old_value}" >> "$TEMP_FILE"
        else
            # Key doesn't exist in old .env, copy line as is
            echo "$line" >> "$TEMP_FILE"
        fi
    else
        # Any other line, copy as is
        echo "$line" >> "$TEMP_FILE"
    fi
done < "$NEW_TEMPLATE"

# Set KEY=VALUE in a file, replacing an existing line or appending one. awk,
# not sed: a value taken from REDIS_URL may hold sed metacharacters.
set_env_value() {
    local key=$1 value=$2 file=$3
    if grep -q "^${key}=" "$file"; then
        ENV_KEY="$key" ENV_VALUE="$value" awk '
            index($0, ENVIRON["ENV_KEY"] "=") == 1 { print ENVIRON["ENV_KEY"] "=" ENVIRON["ENV_VALUE"]; next }
            { print }
        ' "$file" > "${file}.set"
        mv "${file}.set" "$file"
    else
        printf '\n%s=%s\n' "$key" "$value" >> "$file"
    fi
}

# Print a random secret. Callers must check the status: a failure inside $(...)
# cannot stop this script by itself.
generate_secret() {
    local secret
    if secret=$(openssl rand -hex 24 2>/dev/null) && [[ -n "$secret" ]]; then
        printf '%s' "$secret"
    else
        echo "Error: could not run openssl to generate $1. Install openssl and rerun this script." >&2
        rm -f "$TEMP_FILE"
        exit 1
    fi
}

# Keep settings that .env.example does not list:
# - TEMPORAL__POSTGRES_IMAGE: installs whose temporal-db volume still holds
#   PostgreSQL 13 data pin postgres:13 until they upgrade the database; dropping
#   the pin here would stop temporal_postgres_db on the next start.
# - REDIS_CLIENT_PASSWORD: what the services send to an external Redis instead
#   of REDIS_PASSWORD (see below).
for key in TEMPORAL__POSTGRES_IMAGE REDIS_CLIENT_PASSWORD; do
    if ! grep -q "^${key}=" "$TEMP_FILE"; then
        pinned=$(grep "^${key}=" "$OLD_ENV" | tail -n 1)
        if [[ -n "$pinned" ]]; then
            printf '\n%s\n' "$pinned" >> "$TEMP_FILE"
            echo "Kept ${key}"
        fi
    fi
done

# The database runtime role password. A key missing from the old .env arrives
# here as the template placeholder, which `./env.sh --check` refuses: generate
# it, as env.sh does for new installs. The migrations service creates the role,
# or resets its password, on the next start. An old .env that set it to an
# empty value on purpose keeps it empty (the services then run as the owner
# role without row-level security).
runtime_password=$(grep "^AUTOSECOPS__DB_RUNTIME_PASSWORD=" "$TEMP_FILE" | tail -n 1 | sed "s/^AUTOSECOPS__DB_RUNTIME_PASSWORD=//; s/^[\"']//")
if [[ "$runtime_password" == change-me-* ]]; then
    if grep -qE "^AUTOSECOPS__DB_RUNTIME_PASSWORD=[\"']{0,2}[[:space:]]*$" "$OLD_ENV"; then
        set_env_value AUTOSECOPS__DB_RUNTIME_PASSWORD "" "$TEMP_FILE"
        echo "Kept AUTOSECOPS__DB_RUNTIME_PASSWORD empty, as in the old .env. Row-level security stays inactive."
    else
        runtime_password=$(generate_secret AUTOSECOPS__DB_RUNTIME_PASSWORD) || exit 1
        set_env_value AUTOSECOPS__DB_RUNTIME_PASSWORD "$runtime_password" "$TEMP_FILE"
        echo "Generated AUTOSECOPS__DB_RUNTIME_PASSWORD for the database runtime role"
    fi
fi

# The bundled Redis requires REDIS_PASSWORD. Never carry the template
# placeholder into .env: reuse the password from the old REDIS_URL when it has
# one (installs that followed the earlier Redis hardening steps keep working),
# otherwise generate one. `./env.sh --upgrade` applies the same rules.
redis_password=$(grep "^REDIS_PASSWORD=" "$TEMP_FILE" | tail -n 1 | sed "s/^REDIS_PASSWORD=//")
if [[ -z "$redis_password" || "$redis_password" == change-me-* ]]; then
    old_url=$(grep "^REDIS_URL=" "$OLD_ENV" | tail -n 1 | sed "s/^REDIS_URL=//; s/^[\"']//; s/[\"']$//")
    old_host=$(grep "^REDIS_HOST=" "$OLD_ENV" | tail -n 1 | sed "s/^REDIS_HOST=//; s/^[\"']//; s/[\"']$//")
    redis_password=$(sed -nE 's#^rediss?://[^:/@]*:([^@]+)@.*$#\1#p' <<< "$old_url")
    if [[ -n "$redis_password" ]]; then
        redis_password=$(printf '%b' "$(sed 's/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g' <<< "$redis_password")")
    fi
    if [[ "$redis_password" == *"'"* ]]; then
        echo "The REDIS_URL password contains a single quote, which .env cannot hold literally. Generating a new REDIS_PASSWORD; remove the credentials from REDIS_URL."
        redis_password=""
    fi
    url_has_password=false
    if [[ -n "$redis_password" ]]; then
        url_has_password=true
        echo "Set REDIS_PASSWORD from the password in REDIS_URL"
    else
        redis_password=$(generate_secret REDIS_PASSWORD) || exit 1
        echo "Generated REDIS_PASSWORD for the bundled Redis"
    fi
    if [[ ! "$redis_password" =~ ^[A-Za-z0-9._-]+$ ]]; then
        # Single quotes keep Docker Compose from interpolating `$` and the like.
        redis_password="'${redis_password}'"
    fi
    set_env_value REDIS_PASSWORD "$redis_password" "$TEMP_FILE"

    # The services send REDIS_PASSWORD when REDIS_URL carries no credentials.
    # An external Redis without AUTH rejects that, so keep those clients
    # unauthenticated, as before the upgrade, and say so.
    url_host=$(sed "s/\${REDIS_HOST}/${old_host:-redis}/g; s/\$REDIS_HOST/${old_host:-redis}/g" <<< "$old_url" | sed -nE 's#^rediss?://([^@/]*@)?\[?([^]:/?]+).*$#\2#p')
    if [[ "$url_has_password" == false && -n "$url_host" && "$url_host" != "redis" ]] \
        && ! grep -q "^REDIS_CLIENT_PASSWORD=" "$TEMP_FILE"; then
        set_env_value REDIS_CLIENT_PASSWORD "" "$TEMP_FILE"
        echo ""
        echo "WARNING: REDIS_URL points to an external Redis (${url_host}) without a password."
        echo "  Set REDIS_CLIENT_PASSWORD= (empty) so the services keep connecting without"
        echo "  AUTH, as before. Enable AUTH on that Redis and put its password in REDIS_URL,"
        echo "  then remove REDIS_CLIENT_PASSWORD from .env:"
        echo "  https://docs.singularityrd.com/self-hosting/updating#redis-password"
        echo ""
    fi
fi

# Move the temporary file to the final output
mv "$TEMP_FILE" "$OUTPUT_ENV"

echo "Migration completed. New .env file created"
