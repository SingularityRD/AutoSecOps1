# Required secrets in AWS Secrets Manager (all services):
# 1. AUTOSECOPS__DB_ENCRYPTION_KEY
# 2. AUTOSECOPS__SERVICE_KEY
# 3. AUTOSECOPS__SIGNING_SECRET
#
# Required secrets (API and MCP):
# 4. USER_AUTH_SECRET  — used by the API service (password reset, email
#    verification, OAuth state signing) and the MCP service (internal OIDC
#    client-secret derivation). Required for ALL auth types.
#    Do NOT add to required_autosecops_base_secrets; it must stay out of
#    executor and worker services to limit blast radius.
#
# Optional secrets:
# 1. OAUTH_CLIENT_ID (legacy OIDC alias)
# 2. OAUTH_CLIENT_SECRET (legacy OIDC alias)

### Required secrets
data "aws_secretsmanager_secret" "autosecops_db_encryption_key" {
  arn = var.autosecops_db_encryption_key_arn
}

data "aws_secretsmanager_secret" "autosecops_service_key" {
  arn = var.autosecops_service_key_arn
}

data "aws_secretsmanager_secret" "autosecops_signing_secret" {
  arn = var.autosecops_signing_secret_arn
}

data "aws_secretsmanager_secret" "user_auth_secret" {
  arn = var.user_auth_secret_arn
}

### Optional secrets

# AutoSecOps authentication

data "aws_secretsmanager_secret" "oauth_client_id" {
  count = var.oauth_client_id_arn != null ? 1 : 0
  arn   = var.oauth_client_id_arn
}

data "aws_secretsmanager_secret" "oauth_client_secret" {
  count = var.oauth_client_secret_arn != null ? 1 : 0
  arn   = var.oauth_client_secret_arn
}

data "aws_secretsmanager_secret" "oidc_client_id" {
  count = var.oidc_client_id_arn != null ? 1 : 0
  arn   = var.oidc_client_id_arn
}

data "aws_secretsmanager_secret" "oidc_client_secret" {
  count = var.oidc_client_secret_arn != null ? 1 : 0
  arn   = var.oidc_client_secret_arn
}

data "aws_secretsmanager_secret" "saml_idp_metadata_url" {
  count = var.saml_idp_metadata_url_arn != null ? 1 : 0
  arn   = var.saml_idp_metadata_url_arn
}

data "aws_secretsmanager_secret" "smtp_password" {
  count = var.smtp_password_arn != null ? 1 : 0
  arn   = var.smtp_password_arn
}

# Temporal UI authentication

data "aws_secretsmanager_secret" "temporal_auth_client_id" {
  count = var.temporal_auth_client_id_arn != null ? 1 : 0
  arn   = var.temporal_auth_client_id_arn
}

data "aws_secretsmanager_secret" "temporal_auth_client_secret" {
  count = var.temporal_auth_client_secret_arn != null ? 1 : 0
  arn   = var.temporal_auth_client_secret_arn
}

data "aws_secretsmanager_secret" "autosecops_db_encryption_previous_keys" {
  count = var.autosecops_db_encryption_previous_keys_arn != null ? 1 : 0
  arn   = var.autosecops_db_encryption_previous_keys_arn
}

data "aws_secretsmanager_secret" "temporal_api_key" {
  count = var.temporal_api_key_arn != null ? 1 : 0
  arn   = var.temporal_api_key_arn
}

### Retrieve secret values

# AutoSecOps secrets

data "aws_secretsmanager_secret_version" "autosecops_db_encryption_key" {
  secret_id = data.aws_secretsmanager_secret.autosecops_db_encryption_key.id
}

data "aws_secretsmanager_secret_version" "autosecops_service_key" {
  secret_id = data.aws_secretsmanager_secret.autosecops_service_key.id
}

data "aws_secretsmanager_secret_version" "autosecops_signing_secret" {
  secret_id = data.aws_secretsmanager_secret.autosecops_signing_secret.id
}

data "aws_secretsmanager_secret_version" "oauth_client_id" {
  count     = var.oauth_client_id_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.oauth_client_id[0].id
}

data "aws_secretsmanager_secret_version" "oauth_client_secret" {
  count     = var.oauth_client_secret_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.oauth_client_secret[0].id
}

data "aws_secretsmanager_secret_version" "oidc_client_id" {
  count     = var.oidc_client_id_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.oidc_client_id[0].id
}

data "aws_secretsmanager_secret_version" "oidc_client_secret" {
  count     = var.oidc_client_secret_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.oidc_client_secret[0].id
}

data "aws_secretsmanager_secret_version" "user_auth_secret" {
  secret_id = data.aws_secretsmanager_secret.user_auth_secret.id
}

data "aws_secretsmanager_secret_version" "saml_idp_metadata_url" {
  count     = var.saml_idp_metadata_url_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.saml_idp_metadata_url[0].id
}


# Temporal UI secrets

data "aws_secretsmanager_secret_version" "temporal_auth_client_id" {
  count     = var.temporal_auth_client_id_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.temporal_auth_client_id[0].id
}

data "aws_secretsmanager_secret_version" "temporal_auth_client_secret" {
  count     = var.temporal_auth_client_secret_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.temporal_auth_client_secret[0].id
}

data "aws_secretsmanager_secret_version" "autosecops_db_encryption_previous_keys" {
  count     = var.autosecops_db_encryption_previous_keys_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.autosecops_db_encryption_previous_keys[0].id
}

data "aws_secretsmanager_secret_version" "temporal_api_key" {
  count     = var.temporal_api_key_arn != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.temporal_api_key[0].id
}

### Database secrets

data "aws_secretsmanager_secret" "autosecops_db_password" {
  arn        = aws_db_instance.core_database.master_user_secret[0].secret_arn
  depends_on = [aws_db_instance.core_database]
}

data "aws_secretsmanager_secret" "temporal_db_password" {
  count      = var.disable_temporal_autosetup ? 0 : 1
  arn        = aws_db_instance.temporal_database[0].master_user_secret[0].secret_arn
  depends_on = [aws_db_instance.temporal_database]
}

data "aws_secretsmanager_secret_version" "autosecops_db_password" {
  secret_id = data.aws_secretsmanager_secret.autosecops_db_password.id
}

data "aws_secretsmanager_secret_version" "temporal_db_password" {
  count     = var.disable_temporal_autosetup ? 0 : 1
  secret_id = data.aws_secretsmanager_secret.temporal_db_password[0].id
}

# Password of the non-owner runtime role the services connect as, so tenant
# row-level security applies to them. The migrations container (as the RDS
# master user) creates the role with this password and re-applies its grants.
resource "random_password" "db_runtime_password" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "db_runtime_password" {
  name_prefix = "${var.name_prefix}-db-runtime-password-"
  description = "AutoSecOps database runtime role password"
}

resource "aws_secretsmanager_secret_version" "db_runtime_password" {
  secret_id     = aws_secretsmanager_secret.db_runtime_password.id
  secret_string = random_password.db_runtime_password.result
}

# Temporal payload encryption keyring. Unless the operator supplies their own
# secret, Terraform generates one keyring per stack. It is created whether or
# not encryption is enabled, so turning encryption off later keeps the key
# that decrypts existing history. `ignore_changes` lets operators rotate the
# keyring in Secrets Manager (add a key, move current_key_id) without the next
# apply reverting it; the random root secret is generated once and kept in
# state, so applies never rotate it silently.
locals {
  temporal_payload_encryption_generate_keyring = var.temporal_payload_encryption_keyring_arn == null
}

resource "random_password" "temporal_payload_encryption_root_secret" {
  count   = local.temporal_payload_encryption_generate_keyring ? 1 : 0
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "temporal_payload_encryption_keyring" {
  count       = local.temporal_payload_encryption_generate_keyring ? 1 : 0
  name_prefix = "${var.name_prefix}-temporal-payload-keyring-"
  description = "AutoSecOps Temporal payload encryption keyring. Losing it makes encrypted workflow history unreadable."
}

resource "aws_secretsmanager_secret_version" "temporal_payload_encryption_keyring" {
  count     = local.temporal_payload_encryption_generate_keyring ? 1 : 0
  secret_id = aws_secretsmanager_secret.temporal_payload_encryption_keyring[0].id
  secret_string = jsonencode({
    current_key_id = "v1"
    keys = {
      v1 = random_password.temporal_payload_encryption_root_secret[0].result
    }
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

locals {
  # Services read the keyring from Secrets Manager at runtime (and refresh it
  # on the cache TTL), so a rotation needs no redeploy.
  temporal_payload_encryption_keyring_arn = (
    local.temporal_payload_encryption_generate_keyring
    ? aws_secretsmanager_secret.temporal_payload_encryption_keyring[0].arn
    : var.temporal_payload_encryption_keyring_arn
  )
}

# Sentry DSN is stored in a Terraform-managed secret and injected via ECS
# `secrets`, never as a plain environment variable: var.sentry_dsn is
# sensitive, so putting it in the env lists marks every affected
# container_definitions as (sensitive value) in plans. Every gate on the DSN
# goes through this non-sensitive flag; a plain `var.sentry_dsn != null`
# conditional would re-poison the secrets list.
locals {
  sentry_dsn_enabled = nonsensitive(var.sentry_dsn != null)
}

# Store the Sentry DSN in Secrets Manager so ECS tasks can inject it.
resource "aws_secretsmanager_secret" "sentry_dsn" {
  count       = local.sentry_dsn_enabled ? 1 : 0
  name_prefix = "${var.name_prefix}-sentry-dsn-"
  description = "AutoSecOps Sentry DSN"
}

resource "aws_secretsmanager_secret_version" "sentry_dsn" {
  count         = local.sentry_dsn_enabled ? 1 : 0
  secret_id     = aws_secretsmanager_secret.sentry_dsn[0].id
  secret_string = var.sentry_dsn
}

# The license key and the outbound proxy URL (which can embed credentials) are
# sensitive, so they live in Terraform-managed secrets and reach containers via
# ECS `secrets`, not the plaintext task-definition environment. Same pattern as
# the Sentry DSN above.
locals {
  license_key_enabled        = nonsensitive(var.license_key != null && var.license_key != "")
  outbound_proxy_url_enabled = nonsensitive(var.outbound_proxy_url != null && var.outbound_proxy_url != "")
}

resource "aws_secretsmanager_secret" "license_key" {
  count       = local.license_key_enabled ? 1 : 0
  name_prefix = "${var.name_prefix}-license-key-"
  description = "AutoSecOps license key"
}

resource "aws_secretsmanager_secret_version" "license_key" {
  count         = local.license_key_enabled ? 1 : 0
  secret_id     = aws_secretsmanager_secret.license_key[0].id
  secret_string = var.license_key
}

resource "aws_secretsmanager_secret" "outbound_proxy_url" {
  count       = local.outbound_proxy_url_enabled ? 1 : 0
  name_prefix = "${var.name_prefix}-outbound-proxy-url-"
  description = "AutoSecOps outbound HTTP(S) proxy URL"
}

resource "aws_secretsmanager_secret_version" "outbound_proxy_url" {
  count         = local.outbound_proxy_url_enabled ? 1 : 0
  secret_id     = aws_secretsmanager_secret.outbound_proxy_url[0].id
  secret_string = var.outbound_proxy_url
}

locals {
  # Pin the secret versions so a changed value creates new task-definition
  # revisions that roll the services.
  license_key_secret = local.license_key_enabled ? [
    {
      name      = "AUTOSECOPS__LICENSE_KEY"
      valueFrom = "${aws_secretsmanager_secret_version.license_key[0].arn}:::${aws_secretsmanager_secret_version.license_key[0].version_id}"
    }
  ] : []

  outbound_proxy_url_secret = local.outbound_proxy_url_enabled ? [
    {
      name      = "AUTOSECOPS__OUTBOUND_PROXY_URL"
      valueFrom = "${aws_secretsmanager_secret_version.outbound_proxy_url[0].arn}:::${aws_secretsmanager_secret_version.outbound_proxy_url[0].version_id}"
    }
  ] : []

  # Settings every AutoSecOps backend service reads.
  autosecops_common_secrets = concat(
    local.license_key_secret,
    local.outbound_proxy_url_secret,
  )
}

locals {
  required_autosecops_base_secrets = [
    {
      name      = "AUTOSECOPS__SERVICE_KEY"
      valueFrom = data.aws_secretsmanager_secret_version.autosecops_service_key.arn
    },
    {
      name      = "AUTOSECOPS__SIGNING_SECRET"
      valueFrom = data.aws_secretsmanager_secret_version.autosecops_signing_secret.arn
    },
    {
      name      = "AUTOSECOPS__DB_ENCRYPTION_KEY"
      valueFrom = data.aws_secretsmanager_secret_version.autosecops_db_encryption_key.arn
    },
    {
      name      = "REDIS_URL"
      valueFrom = aws_secretsmanager_secret_version.redis_url.arn
    },
    local.db_runtime_password_secret,
  ]

  # Every service that receives AUTOSECOPS__DB_ENCRYPTION_KEY also needs the
  # retired keys during a rotation.
  db_encryption_previous_keys_secret = var.autosecops_db_encryption_previous_keys_arn != null ? [
    {
      name      = "AUTOSECOPS__DB_ENCRYPTION_PREVIOUS_KEYS"
      valueFrom = data.aws_secretsmanager_secret_version.autosecops_db_encryption_previous_keys[0].arn
    }
  ] : []

  db_runtime_password_secret = {
    name      = "AUTOSECOPS__DB_RUNTIME_PASSWORD"
    valueFrom = aws_secretsmanager_secret_version.db_runtime_password.arn
  }

  # The migrations container provisions the runtime role with this password.
  migrations_secrets = [local.db_runtime_password_secret]

  temporal_api_key_secret = var.temporal_api_key_arn != null ? [
    {
      name      = "TEMPORAL__API_KEY"
      valueFrom = data.aws_secretsmanager_secret_version.temporal_api_key[0].arn
    }
  ] : []

  # Pin the secret version so a DSN change updates container_definitions,
  # creating new task-definition revisions that roll the services.
  sentry_dsn_secret = local.sentry_dsn_enabled ? [
    {
      name      = "SENTRY_DSN"
      valueFrom = "${aws_secretsmanager_secret_version.sentry_dsn[0].arn}:::${aws_secretsmanager_secret_version.sentry_dsn[0].version_id}"
    }
  ] : []

  autosecops_base_secrets = concat(
    local.required_autosecops_base_secrets,
    local.db_encryption_previous_keys_secret,
    local.autosecops_common_secrets,
  )

  autosecops_temporal_secrets = concat(
    local.autosecops_base_secrets,
    local.temporal_api_key_secret,
  )

  oauth_client_id_secret = var.oauth_client_id_arn != null ? [
    {
      name      = "OAUTH_CLIENT_ID"
      valueFrom = data.aws_secretsmanager_secret_version.oauth_client_id[0].arn
    }
  ] : []

  oauth_client_secret_secret = var.oauth_client_secret_arn != null ? [
    {
      name      = "OAUTH_CLIENT_SECRET"
      valueFrom = data.aws_secretsmanager_secret_version.oauth_client_secret[0].arn
    }
  ] : []

  oidc_client_id_secret = var.oidc_client_id_arn != null ? [
    {
      name      = "OIDC_CLIENT_ID"
      valueFrom = data.aws_secretsmanager_secret_version.oidc_client_id[0].arn
    }
  ] : []

  oidc_client_secret_secret = var.oidc_client_secret_arn != null ? [
    {
      name      = "OIDC_CLIENT_SECRET"
      valueFrom = data.aws_secretsmanager_secret_version.oidc_client_secret[0].arn
    }
  ] : []

  # USER_AUTH_SECRET is needed by the API service (password reset, email
  # verification, OAuth state signing) and the MCP service (internal OIDC
  # client-secret derivation). Required for ALL auth types.
  # It must NOT be in required_autosecops_base_secrets to avoid leaking to
  # executor and worker services.
  user_auth_secret_secret = [
    {
      name      = "USER_AUTH_SECRET"
      valueFrom = data.aws_secretsmanager_secret_version.user_auth_secret.arn
    }
  ]

  saml_idp_metadata_url_secret = var.saml_idp_metadata_url_arn != null ? [
    {
      name      = "SAML_IDP_METADATA_URL"
      valueFrom = data.aws_secretsmanager_secret_version.saml_idp_metadata_url[0].arn
    }
  ] : []

  # Secret ARN only; reading the version would copy the password into state.
  smtp_password_secret = var.smtp_password_arn != null ? [
    {
      name      = "AUTOSECOPS__SMTP_PASSWORD"
      valueFrom = data.aws_secretsmanager_secret.smtp_password[0].arn
    }
  ] : []

  temporal_auth_client_id_secret = var.temporal_auth_client_id_arn != null ? [
    {
      name      = "TEMPORAL_AUTH_CLIENT_ID"
      valueFrom = data.aws_secretsmanager_secret_version.temporal_auth_client_id[0].arn
    }
  ] : []

  temporal_auth_client_secret_secret = var.temporal_auth_client_secret_arn != null ? [
    {
      name      = "TEMPORAL_AUTH_CLIENT_SECRET"
      valueFrom = data.aws_secretsmanager_secret_version.temporal_auth_client_secret[0].arn
    }
  ] : []

  autosecops_api_secrets = concat(
    local.autosecops_temporal_secrets,
    local.sentry_dsn_secret,
    local.oauth_client_id_secret,
    local.oauth_client_secret_secret,
    local.oidc_client_id_secret,
    local.oidc_client_secret_secret,
    local.user_auth_secret_secret,
    local.saml_idp_metadata_url_secret,
    local.smtp_password_secret
  )

  autosecops_ui_secrets = [
    {
      name      = "AUTOSECOPS__SERVICE_KEY"
      valueFrom = data.aws_secretsmanager_secret_version.autosecops_service_key.arn
    }
  ]

  temporal_secrets = var.disable_temporal_autosetup ? [] : [
    {
      name      = "POSTGRES_PWD"
      valueFrom = "${data.aws_secretsmanager_secret_version.temporal_db_password[0].arn}:password::"
    }
  ]

  temporal_ui_secrets = concat(
    local.temporal_auth_client_id_secret,
    local.temporal_auth_client_secret_secret,
  )

  worker_secrets       = concat(local.autosecops_temporal_secrets, local.sentry_dsn_secret)
  agent_worker_secrets = concat(local.autosecops_temporal_secrets, local.sentry_dsn_secret)
  executor_secrets     = concat(local.autosecops_temporal_secrets, local.sentry_dsn_secret)

  litellm_secrets = local.autosecops_base_secrets

  mcp_secrets = concat(
    local.autosecops_temporal_secrets,
    local.user_auth_secret_secret,
  )
}
