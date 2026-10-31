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
{{- include "autosecops.validatePayloadEncryption" . -}}
{{- if not .Values.externalPostgres.auth.existingSecret -}}
{{- $_ = required "externalPostgres.auth.username is required unless externalPostgres.auth.existingSecret is set" .Values.externalPostgres.auth.username -}}
{{- $_ = required "externalPostgres.auth.password is required unless externalPostgres.auth.existingSecret is set" .Values.externalPostgres.auth.password -}}
{{- end -}}
{{- if not .Values.externalRedis.auth.existingSecret -}}
{{- $_ = required "externalRedis.auth.url is required unless externalRedis.auth.existingSecret is set, e.g. rediss://:password@redis:6379" .Values.externalRedis.auth.url -}}
{{- if and (not .Values.externalRedis.auth.allowUnauthenticated) (not (regexMatch "^rediss?://[^@/]*:[^@/]+@" .Values.externalRedis.auth.url)) -}}
{{- fail "externalRedis.auth.url has no password, e.g. rediss://:password@redis:6379. Enable Redis authentication, or set externalRedis.auth.allowUnauthenticated=true to accept it" -}}
{{- end -}}
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
{{- if eq .Values.tunnels.namespace .Release.Namespace -}}
{{- fail "tunnels.namespace must differ from the release namespace: the API gets write access to Secrets and Deployments in the tunnels namespace" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Temporal payload encryption is on by default. The chart never generates the
keyring: a random value would change on every render (and `lookup` does not
work under `helm template` or GitOps tools), silently rotating the key and
making encrypted history unreadable. So require an explicit keyring source.

With secrets.existingSecret the chart cannot see the Secret's keys from values
alone. When the cluster is reachable (helm install/upgrade), `lookup` checks
that the Secret holds the keyring and fails the render, before the pre-upgrade
migration hook runs, rather than leaving every new pod in
CreateContainerConfigError against a migrated database. `lookup` returns
nothing under `helm template` and GitOps renders, which then skip the check.
*/}}
{{- define "autosecops.validatePayloadEncryption" -}}
{{- $pe := .Values.autosecops.temporal.payloadEncryption -}}
{{- $s := .Values.secrets -}}
{{- if $pe.enabled -}}
{{- if not (or $pe.keyringArn $s.existingSecret $s.temporalPayloadEncryptionKeyring) -}}
{{- fail "Temporal payload encryption is enabled (the default) but no keyring is configured. New release: set secrets.temporalPayloadEncryptionKeyring (generate: printf '{\"current_key_id\":\"v1\",\"keys\":{\"v1\":\"%s\"}}' \"$(openssl rand -hex 32)\"), add the temporalPayloadEncryptionKeyring key to secrets.existingSecret, or set autosecops.temporal.payloadEncryption.keyringArn. Existing release: upgrade once with the keyring and autosecops.temporal.payloadEncryption.enabled=false so every pod has the keyring, then upgrade again with enabled=true; pods without the keyring fail activities whose input another pod encrypted. See https://docs.singularityrd.com/self-hosting/updating#temporal-payload-encryption" -}}
{{- end -}}
{{- if and $s.existingSecret (not $pe.keyringArn) -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $s.existingSecret -}}
{{- if and $existing (not (hasKey ($existing.data | default dict) "temporalPayloadEncryptionKeyring")) -}}
{{- fail (printf "Temporal payload encryption is enabled (the default) but Secret %s/%s has no temporalPayloadEncryptionKeyring key. Add the key, or set autosecops.temporal.payloadEncryption.keyringArn. Existing release: upgrade once with the key added and autosecops.temporal.payloadEncryption.enabled=false, then upgrade again with enabled=true. See https://docs.singularityrd.com/self-hosting/updating#temporal-payload-encryption" .Release.Namespace $s.existingSecret) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with $s.temporalPayloadEncryptionKeyring -}}
{{- if not $s.existingSecret -}}
{{- $keyring := . | toString | fromJson -}}
{{- $keys := $keyring.keys | default dict -}}
{{- if or $keyring.Error (not $keyring.current_key_id) (not (kindIs "map" $keys)) (not (hasKey $keys (toString $keyring.current_key_id))) -}}
{{- fail "secrets.temporalPayloadEncryptionKeyring must be JSON like {\"current_key_id\": \"v1\", \"keys\": {\"v1\": \"<random secret>\"}} with current_key_id present in keys" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}
