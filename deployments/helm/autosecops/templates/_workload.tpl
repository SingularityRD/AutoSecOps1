{{/*
Shared Deployment, Service, HorizontalPodAutoscaler, and PodDisruptionBudget
templates. Each component file passes a dict with:
  root        chart root context
  component   component name (api, worker, ...)
  values      the component's values
  image       image reference
  pullPolicy  image pull policy
  container   YAML for the container fields after name/image (command, env, ports, probes, ...)
  backend     true for containers that read the shared backend config (ConfigMap, Postgres CA)
  sandboxed   true for privileged nsjail pods (root, privileged, unconfined)
  workerHealth true for Temporal workers: mounts an in-memory emptyDir at
              /var/run/autosecops for the health marker files, so they stay
              writable with containerSecurityContext.readOnlyRootFilesystem
  automountToken, terminationGracePeriodSeconds, strategy, extraPodAnnotations: optional
*/}}

{{- define "autosecops.deployment" -}}
{{- $root := .root -}}
{{- $v := .values -}}
{{- $ctx := dict "root" $root "component" .component "values" $v -}}
{{- $grace := .terminationGracePeriodSeconds | default $v.terminationGracePeriodSeconds -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "autosecops.componentName" $ctx }}
  labels:
    {{- include "autosecops.componentLabels" $ctx | nindent 4 }}
spec:
  {{- if not $v.autoscaling.enabled }}
  replicas: {{ $v.replicaCount }}
  {{- end }}
  revisionHistoryLimit: 5
  {{- with .strategy }}
  strategy:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "autosecops.componentSelectorLabels" $ctx | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "autosecops.componentSelectorLabels" $ctx | nindent 8 }}
        {{- with $v.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      annotations:
        checksum/config: {{ include "autosecops.configChecksum" $root }}
        {{- with .extraPodAnnotations }}
        {{- . | nindent 8 }}
        {{- end }}
        {{- with $v.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      serviceAccountName: {{ include "autosecops.serviceAccountName" $ctx }}
      automountServiceAccountToken: {{ .automountToken | default false }}
      enableServiceLinks: false
      {{- with $root.Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- if .sandboxed }}
      securityContext:
        # nsjail needs root to delegate cgroups; the bootstrap entrypoint drops
        # to uid 1001 before it starts the worker.
        runAsNonRoot: false
        runAsUser: 0
        runAsGroup: 0
        fsGroup: 1001
        seccompProfile:
          type: Unconfined
      {{- else }}
      securityContext:
        {{- toYaml $root.Values.podSecurityContext | nindent 8 }}
      {{- end }}
      {{- if not (kindIs "invalid" $grace) }}
      terminationGracePeriodSeconds: {{ $grace }}
      {{- end }}
      {{- with $v.priorityClassName }}
      priorityClassName: {{ . }}
      {{- end }}
      {{- with ($v.nodeSelector | default $root.Values.nodeSelector) }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with ($v.tolerations | default $root.Values.tolerations) }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with ($v.affinity | default $root.Values.affinity) }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $v.topologySpreadConstraints }}
      topologySpreadConstraints:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: {{ .component }}
          image: {{ .image }}
          imagePullPolicy: {{ .pullPolicy }}
          {{- if .sandboxed }}
          securityContext:
            # Required by nsjail: namespaces, cgroup delegation, /dev/net/tun,
            # and loop devices for SquashFS registry mounts.
            privileged: true
            allowPrivilegeEscalation: true
            runAsNonRoot: false
            runAsUser: 0
            capabilities:
              add: ["SYS_ADMIN"]
            # Privileged containers also run without the runtime's default
            # AppArmor profile, which blocks the cgroup remount.
            seccompProfile:
              type: Unconfined
          {{- else }}
          securityContext:
            {{- toYaml $root.Values.containerSecurityContext | nindent 12 }}
          {{- end }}
          {{- .container | nindent 10 }}
          {{- with $v.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- $pgCa := and .backend $root.Values.externalPostgres.tls.caCert }}
          {{- if or $pgCa .workerHealth $v.extraVolumeMounts }}
          volumeMounts:
            {{- if .workerHealth }}
            - name: worker-health
              mountPath: /var/run/autosecops
            {{- end }}
            {{- if $pgCa }}
            - name: postgres-ca
              mountPath: /etc/autosecops/postgres-ca
              readOnly: true
            {{- end }}
            {{- with $v.extraVolumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          {{- end }}
      {{- if or $pgCa .workerHealth $v.extraVolumes }}
      volumes:
        {{- if .workerHealth }}
        - name: worker-health
          emptyDir:
            medium: Memory
            sizeLimit: 16Mi
        {{- end }}
        {{- if $pgCa }}
        - name: postgres-ca
          configMap:
            name: {{ include "autosecops.fullname" $root }}-postgres-ca
        {{- end }}
        {{- with $v.extraVolumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- end }}
{{- end }}

{{/* ClusterIP Service on the container's `http` port. Expects dict root, component, values. */}}
{{- define "autosecops.service" -}}
{{- $ctx := dict "root" .root "component" .component -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "autosecops.componentName" $ctx }}
  labels:
    {{- include "autosecops.componentLabels" $ctx | nindent 4 }}
  {{- with .values.service.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  type: {{ .values.service.type }}
  selector:
    {{- include "autosecops.componentSelectorLabels" $ctx | nindent 4 }}
  ports:
    - name: http
      port: {{ .values.service.port }}
      targetPort: http
      protocol: TCP
{{- end }}

{{/* Optional HPA. Expects dict root, component, values. */}}
{{- define "autosecops.hpa" -}}
{{- $a := .values.autoscaling -}}
{{- if and .values.enabled $a.enabled }}
{{- $ctx := dict "root" .root "component" .component }}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "autosecops.componentName" $ctx }}
  labels:
    {{- include "autosecops.componentLabels" $ctx | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "autosecops.componentName" $ctx }}
  minReplicas: {{ $a.minReplicas }}
  maxReplicas: {{ $a.maxReplicas }}
  {{- if not (or $a.targetCPUUtilizationPercentage $a.targetMemoryUtilizationPercentage) }}
  {{- fail (printf "%s.autoscaling needs targetCPUUtilizationPercentage or targetMemoryUtilizationPercentage" .component) }}
  {{- end }}
  metrics:
    {{- with $a.targetCPUUtilizationPercentage }}
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ . }}
    {{- end }}
    {{- with $a.targetMemoryUtilizationPercentage }}
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: {{ . }}
    {{- end }}
  {{- with $a.behavior }}
  behavior:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
{{- end }}

{{/* Optional PDB. Expects dict root, component, values. */}}
{{- define "autosecops.pdb" -}}
{{- $p := .values.podDisruptionBudget -}}
{{- if and .values.enabled $p.enabled }}
{{- $ctx := dict "root" .root "component" .component }}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "autosecops.componentName" $ctx }}
  labels:
    {{- include "autosecops.componentLabels" $ctx | nindent 4 }}
spec:
  {{- if not (kindIs "invalid" $p.maxUnavailable) }}
  maxUnavailable: {{ $p.maxUnavailable }}
  {{- else }}
  minAvailable: {{ $p.minAvailable | default 1 }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "autosecops.componentSelectorLabels" $ctx | nindent 6 }}
{{- end }}
{{- end }}

{{/* Dedicated per-component ServiceAccount. Expects dict root, component, values. */}}
{{- define "autosecops.componentServiceAccount" -}}
{{- $sa := default dict .values.serviceAccount -}}
{{- if and .values.enabled $sa.create }}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "autosecops.serviceAccountName" . }}
  labels:
    {{- include "autosecops.componentLabels" . | nindent 4 }}
  {{- with $sa.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
automountServiceAccountToken: false
{{- end }}
{{- end }}

{{/* Everything a component renders besides its Deployment and Service. */}}
{{- define "autosecops.componentExtras" -}}
{{ include "autosecops.hpa" . }}
{{ include "autosecops.pdb" . }}
{{ include "autosecops.componentServiceAccount" . }}
{{- end }}

{{/* Probes from component values. Expects the component values. */}}
{{- define "autosecops.probes" -}}
{{- with .startupProbe }}
startupProbe:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .readinessProbe }}
readinessProbe:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .livenessProbe }}
livenessProbe:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Probes for a Temporal worker. A probe set in the component values replaces the
matching `workerProbes` default instead of merging into it, so an operator's
tcpSocket or httpGet probe never renders next to the default exec handler.
Expects dict root, values.
*/}}
{{- define "autosecops.workerProbes" -}}
{{- $defaults := .root.Values.workerProbes | default dict -}}
{{- range $kind := list "startupProbe" "readinessProbe" "livenessProbe" }}
{{- with (get $.values $kind) | default (get $defaults $kind) }}
{{ $kind }}:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- end }}

{{/* envFrom block for backend containers. Expects root. */}}
{{- define "autosecops.backendEnvFrom" -}}
envFrom:
  - configMapRef:
      name: {{ include "autosecops.fullname" . }}-env
{{- end }}
