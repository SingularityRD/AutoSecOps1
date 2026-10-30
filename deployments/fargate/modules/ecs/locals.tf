# AutoSecOps and Temporal environment variables
locals {

  # AutoSecOps version
  autosecops_image_tag            = var.autosecops_image_tag
  autosecops_migrations_image     = coalesce(var.autosecops_migrations_image, var.autosecops_image)
  autosecops_migrations_image_tag = coalesce(var.autosecops_migrations_image_tag, local.autosecops_image_tag)

  # Pull credentials for a private registry such as GHCR, merged into every
  # container definition that runs an AutoSecOps image.
  autosecops_repository_credentials = var.autosecops_registry_credentials_arn != null ? {
    repositoryCredentials = {
      credentialsParameter = var.autosecops_registry_credentials_arn
    }
  } : {}

  # WAF regex pattern set names. Default to "${name_prefix}-..." so each stack
  # gets uniquely-named pattern sets within a shared AWS account; explicit
  # variable values override (e.g. legacy stacks that already own bare names).
  waf_attachments_endpoint_pattern_name = coalesce(var.waf_attachments_endpoint_pattern_name, "${var.name_prefix}-attachments-endpoint-pattern")
  waf_mcp_oauth_endpoints_pattern_name  = coalesce(var.waf_mcp_oauth_endpoints_pattern_name, "${var.name_prefix}-mcp-oauth-endpoints-pattern")
  waf_mcp_public_endpoint_pattern_name  = coalesce(var.waf_mcp_public_endpoint_pattern_name, "${var.name_prefix}-mcp-public-endpoint-pattern")

  # AutoSecOps common URLs
  public_app_url   = "https://${var.domain_name}"
  public_api_url   = "https://${var.domain_name}/api"
  internal_api_url = "http://api-service:8000" # Service connect DNS name

  temporal_cluster_url   = var.temporal_cluster_url
  temporal_cluster_queue = var.temporal_cluster_queue
  temporal_namespace     = var.temporal_namespace
  allow_origins          = "https://${var.domain_name},http://ui-service:3000"
  internal_litellm_url   = "http://litellm-service:4000"

  autosecops_litellm_env = {
    AUTOSECOPS__LITELLM_BASE_URL = local.internal_litellm_url
  }

  # AutoSecOps Postgres env vars
  autosecops_db_configs = {
    AUTOSECOPS__DB_USER              = "postgres"
    AUTOSECOPS__DB_PORT              = "5432"
    AUTOSECOPS__DB_NAME              = "postgres" # Hardcoded in RDS resource configs
    AUTOSECOPS__DB_PASS__ARN         = data.aws_secretsmanager_secret_version.autosecops_db_password.arn
    AUTOSECOPS__DB_MAX_OVERFLOW      = var.db_max_overflow
    AUTOSECOPS__DB_POOL_SIZE         = var.db_pool_size
    AUTOSECOPS__DB_POOL_TIMEOUT      = var.db_pool_timeout
    AUTOSECOPS__DB_POOL_RECYCLE      = var.db_pool_recycle
    AUTOSECOPS__DB_AUTH_MAX_OVERFLOW = var.db_auth_max_overflow
    AUTOSECOPS__DB_AUTH_POOL_SIZE    = var.db_auth_pool_size
  }

  autosecops_db_configs_executor = {
    AUTOSECOPS__DB_MAX_OVERFLOW = var.db_max_overflow_executor
    AUTOSECOPS__DB_POOL_SIZE    = var.db_pool_size_executor
  }

  autosecops_common_env = {
    AUTOSECOPS__BACKGROUND_QUEUE                        = var.background_queue
    LOG_LEVEL                                           = var.log_level
    TEMPORAL__CLUSTER_NAMESPACE                         = local.temporal_namespace
    TEMPORAL__CLUSTER_URL                               = local.temporal_cluster_url
    AUTOSECOPS__APP_ENV                                 = var.autosecops_app_env
    AUTOSECOPS__LOG_FORMAT                              = var.log_format
    AUTOSECOPS__AWS_ASSUME_ROLE_ACCOUNT_ID              = data.aws_caller_identity.current.account_id
    AUTOSECOPS__AWS_ASSUME_ROLE_PRINCIPAL_ARN           = aws_iam_role.executor_task.arn
    AUTOSECOPS__FEATURE_FLAGS                           = var.feature_flags
    AUTOSECOPS__EE_MULTI_TENANT                         = var.ee_multi_tenant
    AUTOSECOPS__CONTEXT_COMPRESSION_ENABLED             = var.context_compression_enabled
    AUTOSECOPS__CONTEXT_COMPRESSION_THRESHOLD_KB        = var.context_compression_threshold_kb
    AUTOSECOPS__RESULT_EXTERNALIZATION_ENABLED          = var.result_externalization_enabled
    AUTOSECOPS__COLLECTION_MANIFESTS_ENABLED            = var.collection_manifests_enabled
    AUTOSECOPS__RESULT_EXTERNALIZATION_THRESHOLD_BYTES  = var.result_externalization_threshold_bytes
    AUTOSECOPS__UNSAFE_DISABLE_SECRET_ERROR_WITHHOLDING = var.unsafe_disable_secret_error_withholding
    AUTOSECOPS__DB_SSLMODE                              = "require"
    # Agent timeout ceiling: every process that parses workflow DSL or
    # enforces the clamp must agree, so it rides the common env.
    AUTOSECOPS__AGENT_SANDBOX_TIMEOUT = var.agent_sandbox_timeout
    # Shared outbound policy for MCP and custom LLM requests.
    AUTOSECOPS__OUTBOUND_ALLOWED_PRIVATE_CIDRS = var.outbound_allowed_private_cidrs
    # AUTOSECOPS__OUTBOUND_PROXY_URL can hold credentials, so it is an ECS
    # secret (secrets.tf), like AUTOSECOPS__LICENSE_KEY.
    AUTOSECOPS__OUTBOUND_NO_PROXY = var.outbound_no_proxy
    # Audit client-IP attribution: both api and mcp resolve X-Forwarded-For,
    # so it rides the common env. Empty uses the built-in private-range default.
    AUTOSECOPS__AUDIT_TRUSTED_PROXY_CIDRS = var.audit_trusted_proxy_cidrs
  }

  autosecops_temporal_payload_encryption_env = {
    TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED           = var.temporal_payload_encryption_enabled
    TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING_ARN       = var.temporal_payload_encryption_keyring_arn
    TEMPORAL__PAYLOAD_ENCRYPTION_CACHE_TTL_SECONDS = var.temporal_payload_encryption_cache_ttl_seconds
    TEMPORAL__PAYLOAD_ENCRYPTION_CACHE_MAX_ITEMS   = var.temporal_payload_encryption_cache_max_items
  }

  # Presigned S3 origins the browser fetches directly (skills upload PUT,
  # inline attachment image fetch). Appended to the UI CSP connect-src.
  # botocore emits the legacy global host for us-east-1 unless
  # AWS_S3_US_EAST_1_REGIONAL_ENDPOINT=regional is set.
  presigned_browser_origins = distinct(flatten([
    for bucket in [aws_s3_bucket.skills.bucket, aws_s3_bucket.attachments.bucket] : compact([
      "https://${bucket}.s3.${var.aws_region}.amazonaws.com",
      var.aws_region == "us-east-1" ? "https://${bucket}.s3.amazonaws.com" : "",
    ])
  ]))

  autosecops_blob_storage_env = {
    AUTOSECOPS__BLOB_STORAGE_BUCKET_ATTACHMENTS = aws_s3_bucket.attachments.bucket
    AUTOSECOPS__BLOB_STORAGE_BUCKET_REGISTRY    = aws_s3_bucket.registry.bucket
    AUTOSECOPS__BLOB_STORAGE_BUCKET_SKILLS      = aws_s3_bucket.skills.bucket
    AUTOSECOPS__BLOB_STORAGE_BUCKET_WORKFLOW    = aws_s3_bucket.workflow.bucket
    AUTOSECOPS__BLOB_STORAGE_BUCKET_AGENT       = aws_s3_bucket.agent.bucket
  }

  api_env = [
    for k, v in merge(
      local.autosecops_common_env,
      local.autosecops_litellm_env,
      local.autosecops_temporal_payload_encryption_env,
      local.autosecops_blob_storage_env,
      local.autosecops_db_configs,
      {
        AUTOSECOPS__ALLOW_ORIGINS                    = local.allow_origins
        AUTOSECOPS__API_ROOT_PATH                    = "/api"
        AUTOSECOPS__API_URL                          = local.internal_api_url
        AUTOSECOPS__PUBLIC_API_URL                   = local.public_api_url
        AUTOSECOPS__PUBLIC_APP_URL                   = local.public_app_url
        AUTOSECOPS__AUTH_TYPES                       = var.auth_types
        AUTOSECOPS__AUTH_ALLOWED_DOMAINS             = var.auth_allowed_domains
        AUTOSECOPS__AUTH_MIN_PASSWORD_LENGTH         = var.auth_min_password_length
        AUTOSECOPS__AUTH_SUPERADMIN_EMAIL            = var.auth_superadmin_email
        AUTOSECOPS__SMTP_HOST                        = var.smtp_host
        AUTOSECOPS__SMTP_PORT                        = tostring(var.smtp_port)
        AUTOSECOPS__SMTP_USER                        = var.smtp_user
        AUTOSECOPS__EMAIL_FROM                       = var.email_from
        AUTOSECOPS__DB_ENDPOINT                      = local.core_db_hostname
        AUTOSECOPS__SERVICE_NAME                     = "api"
        OIDC_ISSUER                                  = var.oidc_issuer
        OIDC_SCOPES                                  = var.oidc_scopes
        TEMPORAL__CLUSTER_QUEUE                      = local.temporal_cluster_queue
        SAML_ALLOW_UNSOLICITED                       = var.saml_allow_unsolicited
        AUTOSECOPS__WORKFLOW_ARTIFACT_RETENTION_DAYS = var.workflow_artifact_retention_days

        # Break-glass recovery for a platform admin IP allowlist lockout.
        AUTOSECOPS__PLATFORM_ADMIN_IP_ALLOWLIST_BYPASS = var.platform_admin_ip_allowlist_bypass
        AUTOSECOPS__PLATFORM_ADMIN_MFA_BYPASS          = var.platform_admin_mfa_bypass
      }
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  worker_env = [
    for k, v in merge(
      local.autosecops_common_env,
      local.autosecops_temporal_payload_encryption_env,
      local.autosecops_blob_storage_env,
      local.autosecops_db_configs,
      {
        AUTOSECOPS__API_ROOT_PATH           = "/api"
        AUTOSECOPS__API_URL                 = local.internal_api_url
        AUTOSECOPS__DB_ENDPOINT             = local.core_db_hostname
        AUTOSECOPS__SERVICE_NAME            = "worker"
        AUTOSECOPS__PUBLIC_API_URL          = local.public_api_url
        AUTOSECOPS__PUBLIC_APP_URL          = local.public_app_url
        AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT = var.executor_client_timeout
        TEMPORAL__CLUSTER_QUEUE             = local.temporal_cluster_queue
        # Worker concurrency tuning (see autosecops/dsl/worker.py)
        TEMPORAL__THREADPOOL_MAX_WORKERS        = var.worker_threadpool_max_workers
        TEMPORAL__MAX_CONCURRENT_ACTIVITIES     = var.worker_max_concurrent_activities
        TEMPORAL__MAX_CONCURRENT_WORKFLOW_TASKS = var.worker_max_concurrent_workflow_tasks
      }
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  background_worker_env = concat(
    [for item in local.worker_env : item if item.name != "AUTOSECOPS__SERVICE_NAME"],
    [
      { name = "AUTOSECOPS__SERVICE_NAME", value = "background-worker" },
      { name = "AUTOSECOPS__BACKGROUND_MAX_CONCURRENT_ACTIVITIES", value = tostring(var.background_worker_max_concurrent_activities) }
    ]
  )

  agent_worker_env = [
    for k, v in merge(
      local.autosecops_common_env,
      local.autosecops_temporal_payload_encryption_env,
      local.autosecops_blob_storage_env,
      local.autosecops_db_configs,
      {
        AUTOSECOPS__API_ROOT_PATH                   = "/api"
        AUTOSECOPS__API_URL                         = local.internal_api_url
        AUTOSECOPS__PUBLIC_API_URL                  = local.public_api_url
        AUTOSECOPS__DB_ENDPOINT                     = local.core_db_hostname
        AUTOSECOPS__SERVICE_NAME                    = "agent-worker"
        AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT         = var.executor_client_timeout
        AUTOSECOPS__AGENT_QUEUE                     = var.agent_queue
        AUTOSECOPS__AGENT_EXECUTOR_QUEUE            = var.agent_executor_queue
        AUTOSECOPS__EXECUTOR_QUEUE                  = var.executor_queue
        AUTOSECOPS__AGENT_MAX_CONCURRENT_ACTIVITIES = var.agent_worker_max_concurrent_activities
        TEMPORAL__CLUSTER_QUEUE                     = local.temporal_cluster_queue
      }
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  executor_env = [
    for k, v in merge(
      local.autosecops_common_env,
      local.autosecops_temporal_payload_encryption_env,
      local.autosecops_blob_storage_env,
      local.autosecops_db_configs,
      local.autosecops_db_configs_executor,
      {
        AUTOSECOPS__API_URL                             = local.internal_api_url
        AUTOSECOPS__DB_ENDPOINT                         = local.core_db_hostname
        AUTOSECOPS__SERVICE_NAME                        = "executor"
        AUTOSECOPS__EXECUTOR_BACKEND                    = "direct"
        AUTOSECOPS__EXECUTOR_QUEUE                      = var.executor_queue
        AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_ENTRIES = var.executor_registry_cache_max_entries
        AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_BYTES   = var.executor_registry_cache_max_bytes
        # Executor concurrency tuning (see autosecops/executor/worker.py and autosecops/executor/service.py)
        AUTOSECOPS__EXECUTOR_MAX_CONCURRENT_ACTIVITIES = var.executor_max_concurrent_activities
        AUTOSECOPS__EXECUTOR_THREADPOOL_MAX_WORKERS    = var.executor_threadpool_max_workers
        AUTOSECOPS__EXECUTOR_FOR_EACH_MAX_CONCURRENCY  = var.executor_for_each_max_concurrency
        AUTOSECOPS__UNSAFE_DISABLE_SM_MASKING          = "false"
        AUTOSECOPS__SANDBOX_NSJAIL_PATH                = "/usr/local/bin/nsjail"
        AUTOSECOPS__SANDBOX_ROOTFS_PATH                = "/var/lib/autosecops/sandbox-rootfs"
        AUTOSECOPS__SANDBOX_CACHE_DIR                  = "/var/lib/autosecops/sandbox-cache"
        AUTOSECOPS__SANDBOX_PYPI_INDEX_URL             = var.sandbox_pypi_index_url
        AUTOSECOPS__SANDBOX_PYPI_EXTRA_INDEX_URLS      = var.sandbox_pypi_extra_index_urls
      }
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  agent_executor_env = [
    for k, v in merge(
      local.autosecops_common_env,
      local.autosecops_litellm_env,
      local.autosecops_temporal_payload_encryption_env,
      local.autosecops_blob_storage_env,
      local.autosecops_db_configs,
      local.autosecops_db_configs_executor,
      {
        AUTOSECOPS__API_URL                                  = local.internal_api_url
        AUTOSECOPS__DB_ENDPOINT                              = local.core_db_hostname
        AUTOSECOPS__SERVICE_NAME                             = "agent-executor"
        AUTOSECOPS__EXECUTOR_BACKEND                         = "direct"
        AUTOSECOPS__AGENT_QUEUE                              = var.agent_queue
        AUTOSECOPS__AGENT_EXECUTOR_QUEUE                     = var.agent_executor_queue
        AUTOSECOPS__EXECUTOR_QUEUE                           = var.executor_queue
        AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_ENTRIES      = var.executor_registry_cache_max_entries
        AUTOSECOPS__EXECUTOR_REGISTRY_CACHE_MAX_BYTES        = var.executor_registry_cache_max_bytes
        AUTOSECOPS__AGENT_EXECUTOR_MAX_CONCURRENT_ACTIVITIES = var.agent_executor_max_concurrent_activities
        AUTOSECOPS__EXECUTOR_CLIENT_TIMEOUT                  = var.executor_client_timeout
        AUTOSECOPS__LLM_PROXY_READ_TIMEOUT                   = var.llm_proxy_read_timeout
        AUTOSECOPS__LLM_GATEWAY_CREDENTIAL_CACHE_TTL_SECONDS = var.llm_gateway_credential_cache_ttl_seconds
        AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_INTERVAL_SECONDS = var.llm_gateway_healthcheck_interval_seconds
        AUTOSECOPS__LLM_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS  = var.llm_gateway_healthcheck_timeout_seconds
        AUTOSECOPS__LLM_GATEWAY_CONNECT_TIMEOUT_SECONDS      = var.llm_gateway_healthcheck_connect_timeout_seconds
        AUTOSECOPS__LLM_GATEWAY_READ_TIMEOUT_SECONDS         = var.llm_gateway_healthcheck_read_timeout_seconds
        AUTOSECOPS__LLM_GATEWAY_WRITE_TIMEOUT_SECONDS        = var.llm_gateway_healthcheck_write_timeout_seconds
        AUTOSECOPS__LLM_GATEWAY_POOL_TIMEOUT_SECONDS         = var.llm_gateway_healthcheck_pool_timeout_seconds
        AUTOSECOPS__LLM_GATEWAY_FAILURE_THRESHOLD            = var.llm_gateway_healthcheck_failure_threshold
        AUTOSECOPS__LLM_GATEWAY_STATUS_LOG_INTERVAL_SECONDS  = var.llm_gateway_status_log_interval_seconds
        AUTOSECOPS__LITELLM_BASE_URL                         = "http://litellm-service:4000"
        AUTOSECOPS__UNSAFE_DISABLE_SM_MASKING                = "false"
        AUTOSECOPS__SANDBOX_NSJAIL_PATH                      = "/usr/local/bin/nsjail"
        AUTOSECOPS__SANDBOX_ROOTFS_PATH                      = "/var/lib/autosecops/sandbox-rootfs"
        AUTOSECOPS__SANDBOX_CACHE_DIR                        = "/var/lib/autosecops/sandbox-cache"
      }
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  # LiteLLM shutdown mirrors the k8s chart (grace = preStop + drain + 30 s), but
  # Fargate caps a container's stopTimeout at 120 s and has no preStop hook, so
  # the drain is 90 s here instead of k8s's 30 min.
  litellm_stop_timeout_seconds  = 120
  litellm_drain_timeout_seconds = local.litellm_stop_timeout_seconds - 30

  litellm_env = [
    for k, v in merge(
      local.autosecops_common_env,
      local.autosecops_litellm_env,
      local.autosecops_db_configs,
      {
        AUTOSECOPS__DB_ENDPOINT         = local.core_db_hostname
        AUTOSECOPS__SERVICE_NAME        = "litellm"
        AUTOSECOPS__LITELLM_PORT        = "4000"
        AUTOSECOPS__LITELLM_NUM_WORKERS = var.litellm_num_workers
        # Drain budget D: gateway drain logs flag requests still open after it.
        GRACEFUL_SHUTDOWN_TIMEOUT = local.litellm_drain_timeout_seconds
      }
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  mcp_env = [
    for k, v in merge(
      local.autosecops_common_env,
      local.autosecops_temporal_payload_encryption_env,
      local.autosecops_blob_storage_env,
      local.autosecops_db_configs,
      {
        AUTOSECOPS__DB_ENDPOINT                     = local.core_db_hostname
        AUTOSECOPS__SERVICE_NAME                    = "mcp"
        AUTOSECOPS__API_URL                         = local.internal_api_url
        AUTOSECOPS__PUBLIC_APP_URL                  = local.public_app_url
        AUTOSECOPS__PUBLIC_API_URL                  = local.public_api_url
        AUTOSECOPS_MCP__HOST                        = "0.0.0.0"
        AUTOSECOPS_MCP__PORT                        = "8099"
        AUTOSECOPS_MCP__RATE_LIMIT_RPS              = var.mcp_rate_limit_rps
        AUTOSECOPS_MCP__RATE_LIMIT_BURST            = var.mcp_rate_limit_burst
        AUTOSECOPS_MCP__TOOL_TIMEOUT_SECONDS        = var.mcp_tool_timeout_seconds
        AUTOSECOPS_MCP__MAX_INPUT_SIZE_BYTES        = var.mcp_max_input_size_bytes
        AUTOSECOPS_MCP__STARTUP_MAX_ATTEMPTS        = var.mcp_startup_max_attempts
        AUTOSECOPS_MCP__STARTUP_RETRY_DELAY_SECONDS = var.mcp_startup_retry_delay_seconds
        TEMPORAL__CLUSTER_QUEUE                     = local.temporal_cluster_queue
      }
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  migrations_env = [
    for k, v in merge(
      {
        LOG_LEVEL                 = var.log_level
        AUTOSECOPS__APP_ENV       = var.autosecops_app_env
        AUTOSECOPS__DB_SSLMODE    = "require"
        AUTOSECOPS__DB_ENDPOINT   = local.core_db_hostname
        AUTOSECOPS__FEATURE_FLAGS = var.feature_flags
        AUTOSECOPS__LOG_FORMAT    = var.log_format
        AUTOSECOPS__SERVICE_NAME  = "migrations"
      },
      local.autosecops_db_configs
    ) :
    { name = k, value = tostring(v) } if v != null
  ]

  ui_env = [
    for k, v in {
      NEXT_PUBLIC_API_URL                 = local.public_api_url
      NEXT_PUBLIC_APP_ENV                 = var.autosecops_app_env
      NEXT_PUBLIC_APP_URL                 = local.public_app_url
      NEXT_SERVER_API_URL                 = local.internal_api_url
      NODE_ENV                            = "production"
      AUTOSECOPS__CSP_CONNECT_SRC_ORIGINS = join(" ", local.presigned_browser_origins)
    } :
    { name = k, value = tostring(v) } if v != null
  ]

  temporal_env = [
    # RDS for PostgreSQL 15+ defaults rds.force_ssl=1, so both Temporal server
    # config generation and temporal-sql-tool bootstrap must opt into TLS.
    for k, v in {
      DB                                = "postgres12"
      DBNAME                            = "temporal"
      DB_PORT                           = "5432"
      POSTGRES_USER                     = "postgres"
      VISIBILITY_DBNAME                 = "temporal_visibility"
      LOG_LEVEL                         = var.temporal_log_level
      TEMPORAL_BROADCAST_ADDRESS        = "0.0.0.0"
      BIND_ON_IP                        = "0.0.0.0"
      NUM_HISTORY_SHARDS                = var.temporal_num_history_shards
      DEFAULT_NAMESPACE_RETENTION       = var.temporal_default_namespace_retention
      SQL_TLS                           = var.temporal_db_tls_enabled
      SQL_TLS_ENABLED                   = var.temporal_db_tls_enabled
      SQL_TLS_DISABLE_HOST_VERIFICATION = !var.temporal_db_tls_enable_host_verification
      SQL_HOST_VERIFICATION             = var.temporal_db_tls_enable_host_verification
      SQL_HOST_NAME                     = local.temp_db_hostname
      SQL_TLS_SERVER_NAME               = local.temp_db_hostname
    } :
    { name = k, value = tostring(v) } if v != null
  ]
}
