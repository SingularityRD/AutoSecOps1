# AutoSecOps Helm chart

Deploys AutoSecOps on Kubernetes 1.27+: `api`, `worker`, `executor`,
`agent-worker`, `agent-executor`, `litellm`, `mcp`, and `ui`, plus a
migrations Job, an optional Ingress, and optional tunnel gateway wiring.

The chart is written from the Docker Compose (`docker-compose.yml`) and AWS
Fargate (`deployments/fargate/`) deployments in this repository. Review all
three targets together when you change one.

The chart does not bundle stateful services. Bring your own:

| Service | Requirement |
| :------ | :---------- |
| PostgreSQL | 15 or newer, with the `vector` (pgvector) extension available |
| Redis | 7 or newer, or a Redis-compatible server such as Valkey |
| Object storage | AWS S3 or an S3-compatible store (MinIO, Ceph, R2) |
| Temporal | Self-hosted Temporal server or Temporal Cloud |

Full documentation: `docs/self-hosting/kubernetes.mdx`
(published at `/self-hosting/kubernetes` on the docs site).

## Install

Each AutoSecOps release publishes the chart to GHCR with the release version as
the chart version:

```bash
helm install autosecops oci://ghcr.io/singularityrd/charts/autosecops \
  --version <version> \
  --namespace autosecops --create-namespace \
  -f my-values.yaml \
  --wait --timeout 15m
```

The chart and images are private GHCR packages. SingularityRD grants each
customer's GitHub account Read access. Log in with a personal access token
(classic) that has only `read:packages`, then reference a `docker-registry`
Secret in `imagePullSecrets` (and in `tunnels.gateway.imagePullSecrets` in
`tunnels.namespace` when tunnels are enabled):

```bash
echo "<read-packages-token>" | helm registry login ghcr.io --username <github-username> --password-stdin
kubectl -n autosecops create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<github-username> \
  --docker-password="<read-packages-token>"
```

To install from a checkout of this repository instead, check out the release
tag and replace the OCI reference with `deployments/helm/autosecops` (drop
`--version`).

Minimal values (see `ci/minimal-values.yaml`):

```yaml
urls:
  publicApp: https://autosecops.example.com
secrets:
  existingSecret: autosecops-secrets          # dbEncryptionKey, serviceKey, signingSecret, userAuthSecret, temporalPayloadEncryptionKeyring
externalPostgres:
  host: postgres.example.internal
  auth:
    existingSecret: autosecops-postgres-credentials   # username, password, runtime-password
externalRedis:
  auth:
    existingSecret: autosecops-redis-credentials      # url
externalTemporal:
  clusterUrl: temporal-frontend.temporal:7233
```

Required values fail `helm template` and `helm install` with a message naming
the value to set. `values.schema.json` rejects unknown keys, so typos and
leftover keys from other charts fail early.

## Values

`values.yaml` documents every key. The main groups:

| Key | Purpose |
| :-- | :------ |
| `image`, `uiImage` | Backend and UI images. Tags default to the chart `appVersion`. |
| `urls` | Public app and API URLs, CORS origins. |
| `autosecops.*` | Application settings: auth, SMTP, agent timeout, outbound policy, Temporal metrics and payload encryption, AWS role assumption, sandbox, OpenTelemetry, Pangolin. |
| `secrets` | Core secrets, from an existing Secret or created by the chart. |
| `externalPostgres`, `externalRedis`, `externalS3`, `externalTemporal` | Connection settings and credentials for the external services. |
| `serviceAccount`, `<component>.serviceAccount` | Shared and per-component service accounts, with annotations for IRSA. |
| `<component>.*` | Replicas, resources, probes, HPA, PDB, scheduling, extra env and volumes. |
| `migrations` | `alembic upgrade head` Job, run as a `pre-install,pre-upgrade` hook by default. |
| `ingress` | One Ingress with the Caddyfile routing: `/api` to api, MCP routes to mcp, `/` to ui. |
| `tunnels` | RBAC, namespace, NetworkPolicy, and admission policy for managed tunnel gateways. |

## Secrets

Every credential supports either a chart-created Secret (values) or an
`existingSecret` reference:

| Values | Secret created by the chart | Keys |
| :----- | :-------------------------- | :--- |
| `secrets.*` | `<fullname>-secrets` | `dbEncryptionKey`, `serviceKey`, `signingSecret`, `userAuthSecret`, optional `licenseKey`, `oidcClientId`, `oidcClientSecret`, `oauthClientId`, `oauthClientSecret`, `samlIdpMetadataUrl`, `smtpPassword`, `sentryDsn`, `outboundProxyUrl`, `otelExporterOtlpHeaders`; `temporalPayloadEncryptionKeyring` is required while payload encryption is on without `keyringArn` |
| `externalPostgres.auth` | `<fullname>-postgres-credentials` | `username`, `password`, optional `runtime-password` |
| `externalRedis.auth` | `<fullname>-redis-credentials` | `url` |
| `externalS3.auth` | `<fullname>-s3-credentials` | `accessKeyId`, `secretAccessKey` |
| `externalTemporal.auth` | `<fullname>-temporal-credentials` | `apiKey` |
| `autosecops.pangolin` | `<fullname>-pangolin-credentials` | `apiKey` |

Temporal payload encryption is on by default, so the core Secret also needs
`temporalPayloadEncryptionKeyring` unless you set
`autosecops.temporal.payloadEncryption.keyringArn`. Generate it once and keep
it with the other core secrets:

```bash
printf '{"current_key_id":"v1","keys":{"v1":"%s"}}' "$(openssl rand -hex 32)"
```

The chart never generates or rotates the keyring, because a value generated
at render time would change on every `helm upgrade` or GitOps sync and make
encrypted workflow history unreadable.

Releases installed before encryption was the default turn it on in two
upgrades. First upgrade with the keyring in place and
`autosecops.temporal.payloadEncryption.enabled=false`, so every pod restarts
with the keyring (with `secrets.existingSecret`, pods do not restart on a
Secret change: run `kubectl rollout restart deployment -l
app.kubernetes.io/instance=<release>` and wait for it to finish); then
upgrade again with `enabled=true`. Turning it on in a
single upgrade lets an upgraded pod encrypt a payload that a pod still on the
old configuration cannot decode, and an activity that runs with one attempt
fails its workflow. Until you add a keyring, the upgrade fails to render with
chart-created secrets. With `secrets.existingSecret`, `helm upgrade` checks
the live Secret with `lookup` and fails before the migration hook when the key
is missing; `helm template` and GitOps renders cannot see the Secret, so add
the key before you sync or new pods wait in `CreateContainerConfigError`.
Existing plaintext history stays readable after you enable encryption.

With the release name `autosecops`, `<fullname>` is `autosecops`. Each service
receives only the secrets its Fargate task definition receives:
`USER_AUTH_SECRET` reaches `api` and `mcp`, SSO and SMTP secrets reach `api`,
and `ui` receives only the service key.

## Database roles and tenant isolation

The migrations Job connects with `externalPostgres.auth.username`, which must
own the schema. After `alembic upgrade head` it creates
`externalPostgres.auth.runtimeUsername` (default `autosecops_app`) as a
`NOSUPERUSER NOBYPASSRLS` login role, sets its password from
`runtimePassword`, and grants it DML. Every other service connects as that
role, so the tenant row-level security policies apply and
`autosecops.rlsMode: enforce` isolates tenants. The owner role needs
`CREATEROLE`; otherwise create the role yourself and grant it to the owner.

Without a runtime password the services connect as the owner, which
PostgreSQL exempts from row-level security, and log a warning.

When migrations run as hooks, chart-created Secrets are hooks too, so they
exist before the migrations Job. Helm keeps hook resources on
`helm uninstall`; delete them by hand when you discard an installation.

## Sandboxing

`executor` and `agent-executor` default to the `nsjail` backend. In that mode
their pods start as root through the cgroup bootstrap entrypoint, run
privileged with `SYS_ADMIN` and an `Unconfined` seccomp profile, and drop to
uid 1001 before the worker starts. Nodes must use cgroup v2.

Set `autosecops.sandbox.disableNsjail: true` to run both with the `direct`
backend as unprivileged pods, or set `executor.backend` /
`agentExecutor.backend` per service.

Kubernetes has no per-pod process limit like Compose's `pids_limit: 4096`.
Set the kubelet `podPidsLimit` on executor nodes instead.

## Development

```bash
helm lint --strict deployments/helm/autosecops -f deployments/helm/autosecops/ci/minimal-values.yaml
helm template autosecops deployments/helm/autosecops -f deployments/helm/autosecops/ci/full-values.yaml \
  | kubeconform -strict -summary -kubernetes-version 1.30.0
uv run pytest --noconftest tests/unit/test_helm_chart.py
```

CI runs the same checks in `.github/workflows/lint-helm.yml` on pull requests
that touch `deployments/helm/**`. `version` and `appVersion` in `Chart.yaml`
both equal the release version; `scripts/update-version.sh` bumps them with each
release, and `.github/workflows/publish-helm-chart.yml` lints, packages, and
pushes the chart when the GitHub release is published. It fails when the tag
differs from either field and never overwrites a published chart version.
