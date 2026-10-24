# Security Policy

## Supported versions

We always recommend using the latest version of AutoSecOps to ensure you get all security updates.
If possible, do not expose AutoSecOps's UI and API to the public internet.
If you need to receive webhooks from 3rd party sources, scope ingress on the `/api/webhooks` endpoint to the allowed IP addresses.

We also highly recommend using our `Kubernetes` deployment for production over `Docker Compose` or `AWS Fargate`.

For more hardening guidelines, check out the [self-hosting security guide](https://docs.singularityrd.com/self-hosting/security).

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
> See the [self-hosting security guide](https://docs.singularityrd.com/self-hosting/security#nsjail-sandbox-recommended-for-production) for deployment requirements.

## Reporting Vulnerabilities

> [!NOTE]
> `nsjail` is the recommended executor runtime for production deployments. We do not accept reports related to "breakout" in the `pid` runtime using the `UnsafePidExecutor`.
> `nsjail` is enabled by default for Helm chart / Kubernetes deployments only and must be explicitly enabled in other deployment options.

Report security vulnerabilities privately by email to [security@singularityrd.com](mailto:security@singularityrd.com).
Do not open a public issue, discussion, or pull request for a security problem.

Include as much of the following as you can:

- The affected AutoSecOps version and deployment option (Docker Compose, AWS Fargate, or Kubernetes).
- The affected component, endpoint, or feature.
- A description of the vulnerability and its impact.
- Step-by-step instructions or a proof of concept to reproduce it.
- Any relevant logs, screenshots, or configuration, with secrets and customer data removed.
- Whether and how you would like to be credited.

What to expect:

1. We will acknowledge your report.
2. The SingularityRD security team will review the report and determine whether it is a valid security issue.
3. If it is valid, we will work with you to reproduce and fix it, and keep you informed of progress.
4. The timeline for a fix depends on the severity of the vulnerability.

As part of responsible disclosure, please give us a reasonable opportunity to fix the issue before you disclose it publicly.

## Contact

- Security vulnerabilities: [security@singularityrd.com](mailto:security@singularityrd.com)
- Product support: [support@singularityrd.com](mailto:support@singularityrd.com)
- Documentation: [docs.singularityrd.com](https://docs.singularityrd.com)
