{{/*
Naming, labels, images, and shared lookups for the AutoSecOps chart.
*/}}

{{- define "autosecops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

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

{{/*
Resource name for a component: <fullname>-<component>. Names are DNS labels
(at most 63 characters). When the full name is too long, shorten the fullname
part and add a hash of it, so the component suffix survives and names stay
unique per release.
*/}}
{{- define "autosecops.componentName" -}}
{{- $fullname := include "autosecops.fullname" .root -}}
{{- $name := printf "%s-%s" $fullname .component -}}
{{- if gt (len $name) 63 -}}
{{- $keep := int (sub 63 (add (len .component) 10)) -}}
{{- $name = printf "%s-%s-%s" ($fullname | trunc $keep | trimSuffix "-") ($fullname | sha256sum | trunc 8) .component -}}
{{- end -}}
{{- $name -}}
{{- end }}

{{/* Migrations Job name. Without Helm hooks, each revision gets its own Job. */}}
{{- define "autosecops.migrationsJobName" -}}
{{- if .Values.migrations.useHelmHooks -}}
{{- include "autosecops.componentName" (dict "root" . "component" "migrations") -}}
{{- else -}}
{{- include "autosecops.componentName" (dict "root" . "component" (printf "migrations-%d" .Release.Revision)) -}}
{{- end -}}
{{- end }}

{{- define "autosecops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "autosecops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "autosecops.labels" -}}
helm.sh/chart: {{ include "autosecops.chart" . }}
{{ include "autosecops.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: autosecops
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/* Selector labels for a component. Expects dict root, component. */}}
{{- define "autosecops.componentSelectorLabels" -}}
{{ include "autosecops.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "autosecops.componentLabels" -}}
{{ include "autosecops.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/* Image reference. Expects dict image (repository/tag/digest), root. */}}
{{- define "autosecops.imageRef" -}}
{{- if .image.digest -}}
{{- printf "%s@%s" .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository (.image.tag | default .root.Chart.AppVersion | toString) -}}
{{- end -}}
{{- end }}

{{- define "autosecops.image" -}}
{{- include "autosecops.imageRef" (dict "image" .Values.image "root" .) -}}
{{- end }}

{{- define "autosecops.uiImage" -}}
{{- include "autosecops.imageRef" (dict "image" .Values.uiImage "root" .) -}}
{{- end }}

{{- define "autosecops.migrationsImage" -}}
{{- $repo := .Values.migrations.image.repository | default .Values.image.repository -}}
{{- if and (not .Values.migrations.image.repository) (not .Values.migrations.image.tag) .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (.Values.migrations.image.tag | default .Values.image.tag | default .Chart.AppVersion | toString) -}}
{{- end -}}
{{- end }}

{{- define "autosecops.tunnelGatewayImage" -}}
{{- printf "%s:%s" .Values.tunnels.gateway.image.repository (.Values.tunnels.gateway.image.tag | default .Chart.AppVersion | toString) -}}
{{- end }}

{{/* Service account name. Expects dict root, component, values. */}}
{{- define "autosecops.serviceAccountName" -}}
{{- $sa := default dict .values.serviceAccount -}}
{{- if $sa.create -}}
{{- $sa.name | default (include "autosecops.componentName" .) -}}
{{- else if $sa.name -}}
{{- $sa.name -}}
{{- else if .root.Values.serviceAccount.create -}}
{{- .root.Values.serviceAccount.name | default (include "autosecops.fullname" .root) -}}
{{- else -}}
{{- .root.Values.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end }}

{{/* ---------- URLs ---------- */}}

{{- define "autosecops.publicAppUrl" -}}
{{- required "urls.publicApp is required, e.g. https://autosecops.example.com" .Values.urls.publicApp | trimSuffix "/" -}}
{{- end }}

{{- define "autosecops.publicApiUrl" -}}
{{- .Values.urls.publicApi | default (printf "%s/api" (include "autosecops.publicAppUrl" .)) | trimSuffix "/" -}}
{{- end }}

{{- define "autosecops.internalApiUrl" -}}
{{- printf "http://%s:%v" (include "autosecops.componentName" (dict "root" . "component" "api")) .Values.api.service.port -}}
{{- end }}

{{- define "autosecops.internalApiFqdnUrl" -}}
{{- printf "http://%s.%s.svc.cluster.local:%v" (include "autosecops.componentName" (dict "root" . "component" "api")) .Release.Namespace .Values.api.service.port -}}
{{- end }}

{{- define "autosecops.internalLitellmUrl" -}}
{{- printf "http://%s:%v" (include "autosecops.componentName" (dict "root" . "component" "litellm")) .Values.litellm.service.port -}}
{{- end }}

{{- define "autosecops.presignedUrlEndpoint" -}}
{{- .Values.externalS3.presignedUrlEndpoint | default .Values.externalS3.endpoint -}}
{{- end }}

{{/* ---------- Secret names ---------- */}}

{{- define "autosecops.coreSecretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-secrets" (include "autosecops.fullname" .)) -}}
{{- end }}

{{- define "autosecops.postgresSecretName" -}}
{{- .Values.externalPostgres.auth.existingSecret | default (printf "%s-postgres-credentials" (include "autosecops.fullname" .)) -}}
{{- end }}

{{- define "autosecops.redisSecretName" -}}
{{- .Values.externalRedis.auth.existingSecret | default (printf "%s-redis-credentials" (include "autosecops.fullname" .)) -}}
{{- end }}

{{- define "autosecops.s3SecretName" -}}
{{- .Values.externalS3.auth.existingSecret | default (printf "%s-s3-credentials" (include "autosecops.fullname" .)) -}}
{{- end }}

{{- define "autosecops.temporalSecretName" -}}
{{- .Values.externalTemporal.auth.existingSecret | default (printf "%s-temporal-credentials" (include "autosecops.fullname" .)) -}}
{{- end }}

{{- define "autosecops.pangolinSecretName" -}}
{{- .Values.autosecops.pangolin.existingSecret | default (printf "%s-pangolin-credentials" (include "autosecops.fullname" .)) -}}
{{- end }}

{{/* "true" when S3 static credentials are configured. */}}
{{- define "autosecops.s3CredentialsEnabled" -}}
{{- if or .Values.externalS3.auth.existingSecret .Values.externalS3.auth.accessKeyId -}}true{{- end -}}
{{- end }}

{{- define "autosecops.temporalAuthEnabled" -}}
{{- if or .Values.externalTemporal.auth.existingSecret .Values.externalTemporal.auth.apiKey -}}true{{- end -}}
{{- end }}

{{- define "autosecops.pangolinEnabled" -}}
{{- if or .Values.autosecops.pangolin.existingSecret .Values.autosecops.pangolin.apiKey -}}true{{- end -}}
{{- end }}

{{/* ---------- Sandbox ---------- */}}

{{/* Execution backend for a sandboxed component. Expects dict root, values. */}}
{{- define "autosecops.executorBackend" -}}
{{- if .values.backend -}}
{{- .values.backend -}}
{{- else if .root.Values.autosecops.sandbox.disableNsjail -}}
direct
{{- else -}}
nsjail
{{- end -}}
{{- end }}

{{/* Agent executor drain timeout. */}}
{{- define "autosecops.agentGracefulShutdownTimeout" -}}
{{- $min := add (int .Values.autosecops.agentSandboxTimeout) 60 -}}
{{- if .Values.agentExecutor.gracefulShutdownTimeout -}}
{{- if lt (int .Values.agentExecutor.gracefulShutdownTimeout) (int $min) -}}
{{- fail (printf "agentExecutor.gracefulShutdownTimeout (%v) must be at least autosecops.agentSandboxTimeout + 60 (%v)" .Values.agentExecutor.gracefulShutdownTimeout $min) -}}
{{- end -}}
{{- int .Values.agentExecutor.gracefulShutdownTimeout -}}
{{- else -}}
{{- $min -}}
{{- end -}}
{{- end }}

{{/* ---------- Checksums ---------- */}}

{{/* Hash of rendered config and chart-managed secrets, so pods roll on change. */}}
{{- define "autosecops.configChecksum" -}}
{{- $parts := list (include (print .Template.BasePath "/configmap.yaml") .) (include (print .Template.BasePath "/secrets.yaml") .) -}}
{{- join "\n" $parts | sha256sum -}}
{{- end }}
