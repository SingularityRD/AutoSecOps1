{{/* Chart name. */}}
{{- define "autosecops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified release name. */}}
{{- define "autosecops.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "autosecops.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels. Pass the root context. */}}
{{- define "autosecops.labels" -}}
helm.sh/chart: {{ include "autosecops.chart" . }}
app.kubernetes.io/name: {{ include "autosecops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: autosecops
{{- end }}

{{/* Selector labels for a component. Pass (dict "root" $ "component" "api"). */}}
{{- define "autosecops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "autosecops.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/* Resource name for a component. Pass (dict "root" $ "component" "api"). */}}
{{- define "autosecops.componentFullname" -}}
{{- printf "%s-%s" (include "autosecops.fullname" .root | trunc 45 | trimSuffix "-") .component }}
{{- end }}

{{- define "autosecops.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "autosecops.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "autosecops.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{- define "autosecops.uiImage" -}}
{{- printf "%s:%s" .Values.uiImage.repository (default .Chart.AppVersion .Values.uiImage.tag) }}
{{- end }}

{{- define "autosecops.publicAppUrl" -}}
{{- .Values.urls.publicApp | trimSuffix "/" }}
{{- end }}

{{- define "autosecops.publicApiUrl" -}}
{{- default (printf "%s/api" (include "autosecops.publicAppUrl" .)) .Values.urls.publicApi | trimSuffix "/" }}
{{- end }}

{{- define "autosecops.internalApiUrl" -}}
{{- printf "http://%s:8000" (include "autosecops.componentFullname" (dict "root" . "component" "api")) }}
{{- end }}

{{- define "autosecops.litellmUrl" -}}
{{- printf "http://%s:4000" (include "autosecops.componentFullname" (dict "root" . "component" "litellm")) }}
{{- end }}

{{/* Connection targets, switched to the bundled services in dev mode. */}}
{{- define "autosecops.dbHost" -}}
{{- if .Values.devDependencies.enabled }}
{{- include "autosecops.componentFullname" (dict "root" . "component" "postgres") }}
{{- else }}
{{- .Values.externalPostgres.host }}
{{- end }}
{{- end }}

{{- define "autosecops.dbSslMode" -}}
{{- if .Values.devDependencies.enabled }}disable{{ else }}{{ .Values.externalPostgres.sslMode }}{{ end }}
{{- end }}

{{- define "autosecops.redisUrl" -}}
{{- if .Values.devDependencies.enabled }}
{{- printf "redis://%s:6379" (include "autosecops.componentFullname" (dict "root" . "component" "redis")) }}
{{- else }}
{{- .Values.externalRedis.url }}
{{- end }}
{{- end }}

{{- define "autosecops.blobEndpoint" -}}
{{- if .Values.devDependencies.enabled }}
{{- printf "http://%s:9000" (include "autosecops.componentFullname" (dict "root" . "component" "minio")) }}
{{- else }}
{{- .Values.externalS3.endpoint }}
{{- end }}
{{- end }}

{{- define "autosecops.blobProxyUpstream" -}}
{{- if .Values.externalS3.caddyProxyUpstream }}
{{- .Values.externalS3.caddyProxyUpstream }}
{{- else if .Values.devDependencies.enabled }}
{{- include "autosecops.blobEndpoint" . }}
{{- end }}
{{- end }}

{{- define "autosecops.presignedUrlEndpoint" -}}
{{- if .Values.externalS3.presignedUrlEndpoint }}
{{- .Values.externalS3.presignedUrlEndpoint }}
{{- else if and .Values.caddy.enabled (include "autosecops.blobProxyUpstream" .) }}
{{- printf "%s/s3" (include "autosecops.publicAppUrl" .) }}
{{- else }}
{{- include "autosecops.blobEndpoint" . }}
{{- end }}
{{- end }}

{{- define "autosecops.temporalUrl" -}}
{{- if .Values.devDependencies.enabled }}
{{- printf "%s:7233" (include "autosecops.componentFullname" (dict "root" . "component" "temporal")) }}
{{- else }}
{{- .Values.externalTemporal.clusterUrl }}
{{- end }}
{{- end }}

{{/*
Static facts about each backend component: resource suffix, container
command, listening port, and which platform secrets and services it needs.
Mirrors the service definitions in the root docker-compose.yml.
*/}}
{{- define "autosecops.backendComponents" -}}
api:
  component: api
  command: []
  port: 8000
  secrets: [dbEncryptionKey, serviceKey, signingSecret, userAuthSecret]
  services: true
worker:
  component: worker
  command: ["python", "-m", "autosecops.dsl.worker"]
  port: 0
  secrets: [dbEncryptionKey, serviceKey, signingSecret]
  services: true
executor:
  component: executor
  command: ["python", "-m", "autosecops.executor.worker"]
  sandboxEntrypoint: ["python", "-m", "autosecops.sandbox.bootstrap"]
  port: 0
  secrets: [dbEncryptionKey, serviceKey, signingSecret]
  services: true
agentWorker:
  component: agent-worker
  command: ["python", "-m", "autosecops.agent.worker"]
  port: 0
  secrets: [dbEncryptionKey, serviceKey, signingSecret]
  services: true
agentExecutor:
  component: agent-executor
  command: ["python", "-m", "autosecops.agent.executor_worker"]
  sandboxEntrypoint: ["python", "-m", "autosecops.agent.sandbox.cgroup"]
  port: 0
  secrets: [dbEncryptionKey, serviceKey, signingSecret]
  services: true
mcp:
  component: mcp
  command: ["python", "-m", "autosecops.mcp"]
  port: 8099
  secrets: [dbEncryptionKey, serviceKey, signingSecret, userAuthSecret]
  services: true
litellm:
  component: litellm
  command: ["python", "-m", "autosecops.agent.litellm"]
  port: 4000
  secrets: [dbEncryptionKey, serviceKey]
  services: false
{{- end }}

{{/* Render a key/value map as EnvVar entries. */}}
{{- define "autosecops.envMap" -}}
{{- range $name, $value := . }}
- name: {{ $name }}
  value: {{ $value | toString | quote }}
{{- end }}
{{- end }}

{{- define "autosecops.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: {{ .key }}
{{- end }}

{{/* Database connection env. Pass the root context. */}}
{{- define "autosecops.dbEnv" -}}
{{- $pg := .Values.externalPostgres }}
- name: TRACECAT__DB_ENDPOINT
  value: {{ include "autosecops.dbHost" . | quote }}
- name: TRACECAT__DB_PORT
  value: {{ $pg.port | toString | quote }}
- name: TRACECAT__DB_NAME
  value: {{ $pg.database | quote }}
- name: TRACECAT__DB_SSLMODE
  value: {{ include "autosecops.dbSslMode" . | quote }}
{{- if $pg.auth.usernameKey }}
{{ include "autosecops.secretEnv" (dict "name" "TRACECAT__DB_USER" "secret" $pg.auth.existingSecret "key" $pg.auth.usernameKey) }}
{{- else }}
- name: TRACECAT__DB_USER
  value: {{ $pg.auth.username | quote }}
{{- end }}
{{ include "autosecops.secretEnv" (dict "name" "TRACECAT__DB_PASS" "secret" $pg.auth.existingSecret "key" $pg.auth.passwordKey) }}
{{- end }}

{{/*
Environment for a backend component.
Pass (dict "root" $ "key" "api" "meta" <backendComponents entry>).
*/}}
{{- define "autosecops.backendEnv" -}}
{{- $root := .root }}
{{- $v := $root.Values }}
{{- $meta := .meta }}
{{- $values := index $v .key }}
- name: TRACECAT__SERVICE_NAME
  value: {{ $meta.component | quote }}
- name: TRACECAT__APP_ENV
  value: {{ $v.autosecops.appEnv | quote }}
- name: LOG_LEVEL
  value: {{ $v.autosecops.logLevel | quote }}
- name: TRACECAT__LOG_FORMAT
  value: {{ $v.autosecops.logFormat | quote }}
- name: TRACECAT__API_URL
  value: {{ include "autosecops.internalApiUrl" $root | quote }}
- name: TRACECAT__API_ROOT_PATH
  value: "/api"
- name: TRACECAT__PUBLIC_APP_URL
  value: {{ include "autosecops.publicAppUrl" $root | quote }}
- name: TRACECAT__PUBLIC_API_URL
  value: {{ include "autosecops.publicApiUrl" $root | quote }}
- name: TRACECAT__ALLOW_ORIGINS
  value: {{ default (include "autosecops.publicAppUrl" $root) $v.autosecops.allowOrigins | quote }}
- name: TRACECAT__AUTH_TYPES
  value: {{ $v.autosecops.auth.types | quote }}
- name: TRACECAT__AUTH_ALLOWED_DOMAINS
  value: {{ $v.autosecops.auth.allowedDomains | quote }}
- name: TRACECAT__AUTH_SUPERADMIN_EMAIL
  value: {{ $v.autosecops.auth.superadminEmail | quote }}
- name: TRACECAT__AUTH_MIN_PASSWORD_LENGTH
  value: {{ $v.autosecops.auth.minPasswordLength | toString | quote }}
- name: TRACECAT__FEATURE_FLAGS
  value: {{ $v.autosecops.featureFlags | quote }}
- name: TRACECAT__EE_MULTI_TENANT
  value: {{ $v.autosecops.eeMultiTenant | toString | quote }}
- name: TRACECAT__LITELLM_BASE_URL
  value: {{ include "autosecops.litellmUrl" $root | quote }}
- name: TRACECAT__OUTBOUND_ALLOWED_PRIVATE_CIDRS
  value: {{ $v.autosecops.outboundAllowedPrivateCidrs | quote }}
{{- if eq .key "litellm" }}
- name: TRACECAT__LITELLM_PORT
  value: "4000"
{{- end }}
{{- if or (eq .key "executor") (eq .key "agentExecutor") }}
- name: TRACECAT__EXECUTOR_BACKEND
  value: {{ $values.backend | quote }}
{{- end }}
{{ include "autosecops.dbEnv" $root }}
{{- range $meta.secrets }}
{{- $envName := get (dict "dbEncryptionKey" "TRACECAT__DB_ENCRYPTION_KEY" "serviceKey" "TRACECAT__SERVICE_KEY" "signingSecret" "TRACECAT__SIGNING_SECRET" "userAuthSecret" "USER_AUTH_SECRET") . }}
{{ include "autosecops.secretEnv" (dict "name" $envName "secret" $v.secrets.existingSecret "key" (index $v.secrets.keys .)) }}
{{- end }}
{{- if $meta.services }}
{{- if $v.secrets.keys.licenseKey }}
{{ include "autosecops.secretEnv" (dict "name" "TRACECAT__LICENSE_KEY" "secret" $v.secrets.existingSecret "key" $v.secrets.keys.licenseKey) }}
{{- end }}
{{- if and $v.externalRedis.auth.existingSecret (not $v.devDependencies.enabled) }}
{{ include "autosecops.secretEnv" (dict "name" "REDIS_URL" "secret" $v.externalRedis.auth.existingSecret "key" $v.externalRedis.auth.urlKey) }}
{{- else }}
- name: REDIS_URL
  value: {{ include "autosecops.redisUrl" $root | quote }}
{{- end }}
- name: TEMPORAL__CLUSTER_URL
  value: {{ include "autosecops.temporalUrl" $root | quote }}
- name: TEMPORAL__CLUSTER_NAMESPACE
  value: {{ $v.externalTemporal.namespace | quote }}
- name: TEMPORAL__CLUSTER_QUEUE
  value: {{ $v.externalTemporal.queue | quote }}
{{- if $v.externalTemporal.auth.existingSecret }}
{{ include "autosecops.secretEnv" (dict "name" "TEMPORAL__API_KEY" "secret" $v.externalTemporal.auth.existingSecret "key" $v.externalTemporal.auth.apiKeyKey) }}
{{- end }}
- name: TRACECAT__BLOB_STORAGE_ENDPOINT
  value: {{ include "autosecops.blobEndpoint" $root | quote }}
- name: TRACECAT__BLOB_STORAGE_SSL_VERIFY
  value: {{ $v.externalS3.sslVerify | toString | quote }}
- name: TRACECAT__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT
  value: {{ include "autosecops.presignedUrlEndpoint" $root | quote }}
- name: TRACECAT__BLOB_STORAGE_BUCKET_WORKFLOW
  value: {{ $v.externalS3.buckets.workflow | quote }}
- name: TRACECAT__BLOB_STORAGE_BUCKET_ATTACHMENTS
  value: {{ $v.externalS3.buckets.attachments | quote }}
- name: TRACECAT__BLOB_STORAGE_BUCKET_REGISTRY
  value: {{ $v.externalS3.buckets.registry | quote }}
- name: TRACECAT__BLOB_STORAGE_BUCKET_AGENT
  value: {{ $v.externalS3.buckets.agent | quote }}
{{- if $v.externalS3.region }}
- name: AWS_REGION
  value: {{ $v.externalS3.region | quote }}
- name: AWS_DEFAULT_REGION
  value: {{ $v.externalS3.region | quote }}
{{- end }}
{{- if $v.externalS3.auth.existingSecret }}
{{ include "autosecops.secretEnv" (dict "name" "AWS_ACCESS_KEY_ID" "secret" $v.externalS3.auth.existingSecret "key" $v.externalS3.auth.accessKeyIdKey) }}
{{ include "autosecops.secretEnv" (dict "name" "AWS_SECRET_ACCESS_KEY" "secret" $v.externalS3.auth.existingSecret "key" $v.externalS3.auth.secretAccessKeyKey) }}
{{- end }}
{{- end }}
{{- include "autosecops.envMap" $v.autosecops.env }}
{{- with $v.autosecops.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- include "autosecops.envMap" $values.env }}
{{- with $values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/* Writable scratch mounts for the backend image under a read-only root. */}}
{{- define "autosecops.backendScratchVolumes" -}}
- name: tmp
  emptyDir: {}
- name: cache-tmp
  emptyDir: {}
- name: cache-uv
  emptyDir: {}
- name: cache-s3
  emptyDir: {}
- name: run
  emptyDir: {}
- name: sandbox-cache
  emptyDir: {}
{{- end }}

{{- define "autosecops.backendScratchMounts" -}}
- name: tmp
  mountPath: /tmp
- name: cache-tmp
  mountPath: /home/apiuser/.cache/tmp
- name: cache-uv
  mountPath: /home/apiuser/.cache/uv
- name: cache-s3
  mountPath: /home/apiuser/.cache/s3
- name: run
  mountPath: /var/run/tracecat
- name: sandbox-cache
  mountPath: /var/lib/tracecat/sandbox-cache
{{- end }}

{{/* Shared pod scheduling fields. Pass the root context. */}}
{{- define "autosecops.podScheduling" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.priorityClassName }}
priorityClassName: {{ . }}
{{- end }}
{{- end }}

{{/* Fail fast on missing required values. */}}
{{- define "autosecops.validate" -}}
{{- $v := .Values }}
{{- if not $v.urls.publicApp }}
{{- fail "urls.publicApp is required (for example https://autosecops.example.com)" }}
{{- end }}
{{- if not $v.secrets.existingSecret }}
{{- fail "secrets.existingSecret is required: create a Secret with dbEncryptionKey, serviceKey, signingSecret, and userAuthSecret" }}
{{- end }}
{{- if not $v.externalPostgres.auth.existingSecret }}
{{- fail "externalPostgres.auth.existingSecret is required (also used by devDependencies)" }}
{{- end }}
{{- if and (not $v.externalPostgres.auth.usernameKey) (not $v.externalPostgres.auth.username) }}
{{- fail "set externalPostgres.auth.usernameKey or externalPostgres.auth.username" }}
{{- end }}
{{- if not $v.devDependencies.enabled }}
{{- if not $v.externalPostgres.host }}
{{- fail "externalPostgres.host is required unless devDependencies.enabled=true" }}
{{- end }}
{{- if and (not $v.externalRedis.url) (not $v.externalRedis.auth.existingSecret) }}
{{- fail "set externalRedis.url or externalRedis.auth.existingSecret unless devDependencies.enabled=true" }}
{{- end }}
{{- if not $v.externalTemporal.clusterUrl }}
{{- fail "externalTemporal.clusterUrl is required unless devDependencies.enabled=true" }}
{{- end }}
{{- else }}
{{- if not $v.externalS3.auth.existingSecret }}
{{- fail "devDependencies.enabled=true needs externalS3.auth.existingSecret for the bundled MinIO credentials" }}
{{- end }}
{{- if not $v.externalPostgres.auth.usernameKey }}
{{- fail "devDependencies.enabled=true needs externalPostgres.auth.usernameKey for the bundled PostgreSQL user" }}
{{- end }}
{{- end }}
{{- if and $v.ingress.enabled (not $v.caddy.enabled) }}
{{- fail "ingress.enabled requires caddy.enabled: the Ingress routes through Caddy, which strips the /api prefix" }}
{{- end }}
{{- range $key := list "executor" "agentExecutor" }}
{{- $backend := (index $v $key).backend }}
{{- if not (has $backend (list "direct" "nsjail")) }}
{{- fail (printf "%s.backend must be direct or nsjail" $key) }}
{{- end }}
{{- end }}
{{- end }}
