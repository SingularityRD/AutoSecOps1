# Security Policy

## Supported versions

We always recommend using the latest version of AutoSecOps to ensure you get all security updates.
If possible, do not expose AutoSecOps's UI and API to the public internet.
If you need to receive webhooks from 3rd party sources, scope ingress on the `/api/webhooks` endpoint to the allowed IP addresses.

We also highly recommend using our `Kubernetes` deployment for production over `Docker Compose` or `AWS Fargate`.

For more hardening guidelines, check out the [self-hosting security guide](https://github.com/SingularityRD/AutoSecOps1/blob/main/docs/self-hosting/security.mdx).

## Security Features

The following security features are available in AutoSecOps:
- SAML SSO
- Audit logs
- Workspaces to isolate resources
- `nsjail` sandbox or `pid` runtime for isolated code and agent execution

> [!WARNING]
> The `direct` executor backend does not provide the supported `nsjail` boundary for ordinary workflow actions.
> Use `TRACECAT__EXECUTOR_BACKEND=nsjail` for supported action isolation.
> The legacy `ephemeral` value remains a compatibility alias for `nsjail`.
> See the [self-hosting security guide](https://github.com/SingularityRD/AutoSecOps1/blob/main/docs/self-hosting/security.mdx#nsjail-sandbox-recommended-for-production) for deployment requirements.

## Reporting Vulnerabilities

> [!NOTE]
> `nsjail` is the recommended executor runtime for production deployments. We do not accept reports related to "breakout" in the `pid` runtime using the `UnsafePidExecutor`.
> `nsjail` is enabled by default for Helm chart / Kubernetes deployments only and must be explicitly enabled in other deployment options.

If you are a security researcher and have discovered a vulnerability, please follow the steps below:

1. Open a new private [security advisory](https://github.com/SingularityRD/AutoSecOps1/security/advisories/new) on the `SingularityRD/AutoSecOps1` GitHub repository. Do not open a public issue for security problems.
2. The SingularityRD security team will get back to you as soon as possible.
3. We will review the vulnerability and determine if it is a valid security issue.
4. If it is a valid security issue, we will work with you to reproduce and fix it.

All reports are reviewed within 24 hours. Timeline for the fix is dependent on the severity of the vulnerability. As part of responsible disclosure, please report any security problems to us before disclosing it publicly.
