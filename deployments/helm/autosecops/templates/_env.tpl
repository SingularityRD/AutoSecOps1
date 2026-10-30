{{/*
Environment variable blocks. Non-sensitive settings shared by every backend
service live in the `<fullname>-env` ConfigMap (configmap.yaml); this file
holds the Secret references and per-service settings.
*/}}

{{/* One env entry from a Secret key. Expects dict name, secret, key, optional. */}}
{{- define "autosecops.env.fromSecret" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: {{ .key }}
      {{- if .optional }}
      optional: true
      {{- end }}
{{- end }}

{{/* Database credentials. Expects root context. */}}
{{- define "autosecops.env.postgresCredentials" -}}
{{- $pg := include "autosecops.postgresSecretName" . -}}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__DB_USER" "secret" $pg "key" .Values.externalPostgres.auth.usernameKey) }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__DB_PASS" "secret" $pg "key" .Values.externalPostgres.auth.passwordKey) }}
{{- end }}

{{/*
Secrets for a backend component, scoped like the Fargate task definitions:
USER_AUTH_SECRET only reaches api and mcp, SSO and SMTP secrets only reach the
api. Expects dict root, component.
*/}}
{{- define "autosecops.env.backendSecrets" -}}
{{- $root := .root -}}
{{- $core := include "autosecops.coreSecretName" $root -}}
{{- $c := .component -}}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__DB_ENCRYPTION_KEY" "secret" $core "key" "dbEncryptionKey") }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__SERVICE_KEY" "secret" $core "key" "serviceKey") }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__SIGNING_SECRET" "secret" $core "key" "signingSecret") }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__LICENSE_KEY" "secret" $core "key" "licenseKey" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__DB_ENCRYPTION_PREVIOUS_KEYS" "secret" $core "key" "dbEncryptionPreviousKeys" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__OUTBOUND_PROXY_URL" "secret" $core "key" "outboundProxyUrl" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "SENTRY_DSN" "secret" $core "key" "sentryDsn" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "OTEL_EXPORTER_OTLP_HEADERS" "secret" $core "key" "otelExporterOtlpHeaders" "optional" true) }}
{{ include "autosecops.env.postgresCredentials" $root }}
{{ include "autosecops.env.fromSecret" (dict "name" "REDIS_URL" "secret" (include "autosecops.redisSecretName" $root) "key" $root.Values.externalRedis.auth.urlKey) }}
{{- if ne $c "litellm" }}
{{ include "autosecops.env.fromSecret" (dict "name" "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING" "secret" $core "key" "temporalPayloadEncryptionKeyring" "optional" true) }}
{{- if include "autosecops.temporalAuthEnabled" $root }}
{{ include "autosecops.env.fromSecret" (dict "name" "TEMPORAL__API_KEY" "secret" (include "autosecops.temporalSecretName" $root) "key" $root.Values.externalTemporal.auth.apiKeyKey) }}
{{- end }}
{{- if include "autosecops.s3CredentialsEnabled" $root }}
{{- $s3 := include "autosecops.s3SecretName" $root }}
{{- /* With a custom endpoint the app reads MINIO_ROOT_*, which keeps static
storage keys out of the default AWS credential chain used by integrations. */}}
{{- $idVar := ternary "MINIO_ROOT_USER" "AWS_ACCESS_KEY_ID" (not (empty $root.Values.externalS3.endpoint)) }}
{{- $secretVar := ternary "MINIO_ROOT_PASSWORD" "AWS_SECRET_ACCESS_KEY" (not (empty $root.Values.externalS3.endpoint)) }}
{{ include "autosecops.env.fromSecret" (dict "name" $idVar "secret" $s3 "key" $root.Values.externalS3.auth.accessKeyIdKey) }}
{{ include "autosecops.env.fromSecret" (dict "name" $secretVar "secret" $s3 "key" $root.Values.externalS3.auth.secretAccessKeyKey) }}
{{- end }}
{{- end }}
{{- if has $c (list "api" "mcp") }}
{{ include "autosecops.env.fromSecret" (dict "name" "USER_AUTH_SECRET" "secret" $core "key" "userAuthSecret") }}
{{- end }}
{{- if eq $c "api" }}
{{ include "autosecops.env.fromSecret" (dict "name" "OIDC_CLIENT_ID" "secret" $core "key" "oidcClientId" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "OIDC_CLIENT_SECRET" "secret" $core "key" "oidcClientSecret" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "OAUTH_CLIENT_ID" "secret" $core "key" "oauthClientId" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "OAUTH_CLIENT_SECRET" "secret" $core "key" "oauthClientSecret" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "SAML_IDP_METADATA_URL" "secret" $core "key" "samlIdpMetadataUrl" "optional" true) }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__SMTP_PASSWORD" "secret" $core "key" "smtpPassword" "optional" true) }}
{{- if include "autosecops.pangolinEnabled" $root }}
{{ include "autosecops.env.fromSecret" (dict "name" "AUTOSECOPS__PANGOLIN_API_KEY" "secret" (include "autosecops.pangolinSecretName" $root) "key" $root.Values.autosecops.pangolin.apiKeyKey) }}
{{- end }}
{{- end }}
{{- end }}

{{/* Plain env entry with the value rendered as a quoted string. */}}
{{- define "autosecops.env.value" -}}
- name: {{ .name }}
  value: {{ .value | toString | quote }}
{{- end }}

{{/* Global then component extraEnv. Expects dict root, values. */}}
{{- define "autosecops.env.extra" -}}
{{- with .root.Values.autosecops.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- with .values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/* Temporal SDK metrics port for worker processes. Expects root. */}}
{{- define "autosecops.env.metrics" -}}
{{- if .Values.autosecops.temporal.metrics.enabled }}
- name: TEMPORAL__METRICS_PORT
  value: {{ .Values.autosecops.temporal.metrics.port | toString | quote }}
{{- end }}
{{- end }}

{{- define "autosecops.metricsPodAnnotations" -}}
{{- if .Values.autosecops.temporal.metrics.enabled -}}
prometheus.io/scrape: "true"
prometheus.io/port: {{ .Values.autosecops.temporal.metrics.port | toString | quote }}
prometheus.io/path: /metrics
{{- end -}}
{{- end }}

{{- define "autosecops.metricsPort" -}}
{{- if .Values.autosecops.temporal.metrics.enabled }}
- name: metrics
  containerPort: {{ .Values.autosecops.temporal.metrics.port }}
  protocol: TCP
{{- end }}
{{- end }}

{{/* Sandbox paths baked into the backend image. */}}
{{- define "autosecops.env.sandboxPaths" -}}
- name: AUTOSECOPS__SANDBOX_NSJAIL_PATH
  value: /usr/local/bin/nsjail
- name: AUTOSECOPS__SANDBOX_ROOTFS_PATH
  value: /var/lib/autosecops/sandbox-rootfs
- name: AUTOSECOPS__SANDBOX_CACHE_DIR
  value: /var/lib/autosecops/sandbox-cache
- name: AUTOSECOPS__UNSAFE_DISABLE_SM_MASKING
  value: "false"
{{- end }}
