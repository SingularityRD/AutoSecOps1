# AutoSecOps Admin CLI

CLI tool for AutoSecOps platform operators to manage infrastructure and control plane operations.

## Installation

`autosecops-admin` is not published to PyPI. Install it from an AutoSecOps
checkout, never with `pip install autosecops-admin`: that name on PyPI is not
ours.

```bash
# API commands only
uv tool install ./packages/autosecops-admin

# With bootstrap operations (create-superuser with direct DB access), which
# need the full AutoSecOps package: run the CLI inside the workspace
uv sync --extra admin
uv run autosecops --help
```

## Configuration

The CLI uses environment variables for configuration:

| Variable | Description | Required |
|----------|-------------|----------|
| `AUTOSECOPS__API_URL` | AutoSecOps API URL (default: `http://localhost:8000`) | No |
| `AUTOSECOPS__SERVICE_KEY` | Service key for API authentication | Yes (for API commands) |
| `AUTOSECOPS__DB_URI` | Database URI for direct DB operations | Yes (for bootstrap/migrate) |

## Commands

### Admin Commands

```bash
# List all users
autosecops admin list-users

# Get user details
autosecops admin get-user <user-id>

# Promote a user to superuser (via API)
autosecops admin promote-user --email user@example.com

# Demote a user from superuser (via API)
autosecops admin demote-user --email user@example.com

# Create a superuser (direct DB - for bootstrap)
autosecops admin create-superuser --email admin@example.com

# Create a new user and promote to superuser
autosecops admin create-superuser --email admin@example.com --create
```

### Organization Commands

```bash
# List all organizations
autosecops orgs list

# Create a new organization
autosecops orgs create --name "My Org" --slug "my-org"

# Get organization details
autosecops orgs get <org-id>
```

### Registry Commands

```bash
# Sync all registry repositories
autosecops registry sync

# Sync a specific repository
autosecops registry sync --repository-id <repo-id>

# Get registry status
autosecops registry status

# List registry versions
autosecops registry versions
```

### Migration Commands

```bash
# Upgrade database to latest
autosecops migrate upgrade head

# Upgrade to specific revision
autosecops migrate upgrade <revision>

# Downgrade database
autosecops migrate downgrade -1

# Show current migration status
autosecops migrate status

# Show migration history
autosecops migrate history
```

## Output Formats

All commands support JSON output with the `--json` or `-j` flag:

```bash
autosecops admin list-users --json
autosecops orgs list -j
```

## Development

```bash
# Install in development mode
uv pip install -e packages/autosecops-admin

# Run the CLI
autosecops --help
```
