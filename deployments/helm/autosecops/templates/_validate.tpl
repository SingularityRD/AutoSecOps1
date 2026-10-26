{{/*
Fail early, with a message that names the value to set, when a required value
is missing or settings conflict. Rendered from configmap.yaml.
*/}}
{{- define "autosecops.validate" -}}
{{- $_ := include "autosecops.publicAppUrl" . -}}
{{- $_ = required "externalPostgres.host is required: the PostgreSQL server AutoSecOps connects to" .Values.externalPostgres.host -}}
{{- $_ = required "externalTemporal.clusterUrl is required, e.g. temporal-frontend.temporal:7233" .Values.externalTemporal.clusterUrl -}}
{{- if not .Values.secrets.existingSecret -}}
{{- $_ = required "secrets.dbEncryptionKey is required unless secrets.existingSecret is set (generate: openssl rand 32 | base64 | tr -d '\\n' | tr '+/' '-_')" .Values.secrets.dbEncryptionKey -}}
{{- $_ = required "secrets.serviceKey is required unless secrets.existingSecret is set (generate: openssl rand -hex 32)" .Values.secrets.serviceKey -}}
{{- $_ = required "secrets.signingSecret is required unless secrets.existingSecret is set (generate: openssl rand -hex 32)" .Values.secrets.signingSecret -}}
{{- $_ = required "secrets.userAuthSecret is required unless secrets.existingSecret is set (generate: openssl rand -hex 32)" .Values.secrets.userAuthSecret -}}
{{- end -}}
{{- if not .Values.externalPostgres.auth.existingSecret -}}
{{- $_ = required "externalPostgres.auth.username is required unless externalPostgres.auth.existingSecret is set" .Values.externalPostgres.auth.username -}}
{{- $_ = required "externalPostgres.auth.password is required unless externalPostgres.auth.existingSecret is set" .Values.externalPostgres.auth.password -}}
{{- end -}}
{{- if not .Values.externalRedis.auth.existingSecret -}}
{{- $_ = required "externalRedis.auth.url is required unless externalRedis.auth.existingSecret is set, e.g. rediss://:password@redis:6379" .Values.externalRedis.auth.url -}}
{{- end -}}
{{- if and (not .Values.externalS3.auth.existingSecret) (or .Values.externalS3.auth.accessKeyId .Values.externalS3.auth.secretAccessKey) -}}
{{- $_ = required "externalS3.auth.secretAccessKey is required when externalS3.auth.accessKeyId is set" .Values.externalS3.auth.secretAccessKey -}}
{{- $_ = required "externalS3.auth.accessKeyId is required when externalS3.auth.secretAccessKey is set" .Values.externalS3.auth.accessKeyId -}}
{{- end -}}
{{- range $name := list "executor" "agentExecutor" -}}
{{- $b := (index $.Values $name).backend -}}
{{- if and $b (not (has $b (list "nsjail" "direct"))) -}}
{{- fail (printf "%s.backend must be nsjail, direct, or empty (got %q)" $name $b) -}}
{{- end -}}
{{- end -}}
{{- if .Values.agentExecutor.enabled -}}
{{- $_ = include "autosecops.agentGracefulShutdownTimeout" . -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "ingress.host is required when ingress.enabled is true" -}}
{{- end -}}
{{- if .Values.tunnels.enabled -}}
{{- if not .Values.tunnels.gateway.blockedCidrs -}}
{{- fail "tunnels.gateway.blockedCidrs is required when tunnels.enabled is true: list every pod, service, and node CIDR in the cluster" -}}
{{- end -}}
{{- $_ = required "autosecops.pangolin.orgId is required when tunnels.enabled is true" .Values.autosecops.pangolin.orgId -}}
{{- if not (include "autosecops.pangolinEnabled" .) -}}
{{- fail "set autosecops.pangolin.existingSecret or autosecops.pangolin.apiKey when tunnels.enabled is true" -}}
{{- end -}}
{{- if not .Values.api.enabled -}}
{{- fail "tunnels.enabled requires api.enabled: the API creates the tunnel gateways" -}}
{{- end -}}
{{- end -}}
{{- end }}
