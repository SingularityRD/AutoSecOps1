# Deployment notes

Rules for work under `deployments/` and the root `docker-compose*.yml` files.

## Review across targets

- Infrastructure changes must be reviewed across every relevant target:
  `docker-compose*.yml`, `deployments/fargate/`, and the Helm chart in
  `deployments/helm/autosecops/`. A new service, env var, secret, port, health
  check, or sandbox privilege usually needs a matching change in all three.
- Check the matching `deployments/helm/autosecops/values.yaml` (and
  `values.schema.json`), `variables.tf`, and `main.tf` files before closing out
  infra work.
- A change that could ship by redeploying the same image is `infra` scope, not
  `engine`.

## Helm chart

- The chart in `deployments/helm/autosecops/` is first-party and written from
  the Compose and Fargate deployments. Do not copy third-party chart code into
  it, and keep it free of chart dependencies: PostgreSQL, Redis, object
  storage, and Temporal stay external.
- Every env var the chart sets must use the names `autosecops/config.py`
  reads; booleans and numbers are rendered as quoted strings.
  `tests/unit/test_helm_chart.py` checks the names.
- Add new values to `values.schema.json` too. The schema rejects unknown keys.
- `version` and `appVersion` in `Chart.yaml` both equal the release version.
  Do not bump them by hand: `scripts/update-version.sh` bumps both, and
  `.github/workflows/publish-helm-chart.yml` publishes the chart to
  `oci://ghcr.io/singularityrd/charts/autosecops` when the release is
  published. Chart changes ship with the next release.
- Verify with `helm lint --strict` and `helm template | kubeconform -strict`
  against `ci/*-values.yaml`; `.github/workflows/lint-helm.yml` runs the same
  checks.

## Fargate and ECS Service Connect

- ECS Service Connect clients should explicitly depend on the ECS services that
  publish the Service Connect aliases they resolve. This avoids startup and
  rollout races where a client task starts before the provider alias is
  registered or stable. Follow the existing UI-to-API ordering pattern; for
  example, an agent-executor service that calls the managed LiteLLM alias should
  depend on the LiteLLM ECS service unless that would create a dependency cycle.
- When a cycle appears, prefer breaking the unnecessary provider dependency
  rather than leaving the Service Connect client unordered.
