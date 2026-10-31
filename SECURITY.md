# Security Policy

## Supported versions

SingularityRD supports the latest two minor release trains of AutoSecOps. A release train is one minor version and its patches, for example `1.4.0`, `1.4.1`, `1.4.2`.

| Version | Supported |
| --- | --- |
| Newest minor release train | Yes: security and bug fixes |
| Previous minor release train | Yes: security fixes and critical bug fixes |
| Older trains | No |
| Prereleases (`-alpha.N`, `-rc.N`) and `nightly-*` builds | No: evaluation only |

Each minor version is supported for 12 months after its `.0` release, or until the second newer minor version ships, whichever comes first. Supported trains receive fixes as patch releases, which never contain database migrations. The full policy, end-of-life rules, and supported deployment targets are in the [support policy](https://docs.singularityrd.com/self-hosting/support-policy).

Before production use, apply the [production hardening checklist](https://docs.singularityrd.com/self-hosting/production-hardening). Do not expose AutoSecOps's UI and API to the public internet. If you need to receive webhooks from third-party sources, expose only the `/api/webhooks` endpoint and limit it to the senders' IP addresses. Kubernetes is the recommended production target; see the [self-hosting security guide](https://docs.singularityrd.com/self-hosting/security) for more.

## Response timelines

Measured from the moment SingularityRD confirms a reported vulnerability, a patched release is available on every supported train within:

| Severity | Patched release |
| --- | --- |
| Critical | 7 days |
| High | 30 days |
| Medium and low | The next scheduled release |

An actively exploited vulnerability is fixed as soon as a fix is ready. A customer support agreement takes precedence where it states different terms.

## Security advisories

SingularityRD announces every fixed vulnerability through:

- A GitHub security advisory on the AutoSecOps repository, with the affected and fixed versions, severity, and CVE when one is assigned.
- An email advisory from [info@singularityrd.com](mailto:info@singularityrd.com) to the technical and security contacts on file for each deployment, sent with the patched release, plus an early warning with a mitigation for critical issues when one exists.
- The Security section of the release notes and the [changelog](https://docs.singularityrd.com/self-hosting/changelog).

## Security Features

The following security features are available in AutoSecOps:
- SAML SSO
- Audit logs
- Workspaces to isolate resources
- `nsjail` sandbox or `pid` runtime for isolated code and agent execution

> [!WARNING]
> The `direct` executor backend does not provide the supported `nsjail` boundary for ordinary workflow actions.
> Use `AUTOSECOPS__EXECUTOR_BACKEND=nsjail` for supported action isolation.
> The legacy `ephemeral` value remains a compatibility alias for `nsjail`.
> See the [self-hosting security guide](https://docs.singularityrd.com/self-hosting/security#nsjail-sandbox-recommended-for-production) for deployment requirements.

## Accepted image scan findings

The image scan workflow (`.github/workflows/image-scan.yml`) fails on any HIGH or CRITICAL vulnerability with a published fix in the API or UI image.
A finding is ignored only when no release we can ship contains the fix yet.
Each ignore lives in `.trivyignore.yaml`, is scoped to the affected advisory and file paths, and expires so the scan fails again for re-review.

| Advisory | Package and location | Why the risk is accepted | Review by |
| --- | --- | --- | --- |
| CVE-2026-109869 | `undici` 6.29.0 bundled in npm 11.21.1, API image only (`/usr/local/lib/node_modules/npm` and the sandbox rootfs copy) | Fixed in `undici` 6.29.1, which no npm release bundles yet. Within npm, only `node-gyp` header downloads use it, and the impact is a crash of that npm process when it talks to a malicious server. The API process never loads npm's `undici`. | 2026-12-31 |
| CVE-2026-109383 | `undici` 6.29.0 bundled in npm 11.21.1, API image only (same paths as above) | Fixed in `undici` 6.29.1, which no npm release bundles yet. Certificate validation can be bypassed when TLS options are dropped. Within npm, only `node-gyp` Node.js header downloads use `undici`, so an attacker who can intercept that download could tamper with headers for a native addon build; the image has no C/C++ toolchain for such builds. npm registry fetches do not use `undici`, and the API process never loads npm's `undici`. | 2026-12-31 |
| CVE-2026-87018 | `undici` 6.29.0 bundled in npm 11.21.1, API image only (same paths as above) | Fixed in `undici` 6.29.1, which no npm release bundles yet. Within npm, only `node-gyp` header downloads use it, and the impact is a crash of that npm process when it talks to a malicious server. The API process never loads npm's `undici`. | 2026-12-31 |

## Reporting Vulnerabilities

> [!NOTE]
> `nsjail` is the recommended executor runtime for production deployments. We do not accept reports related to "breakout" in the `pid` runtime using the `UnsafePidExecutor`.
> `nsjail` is enabled by default for Helm chart / Kubernetes deployments only and must be explicitly enabled in other deployment options.

Report security vulnerabilities privately by email to [info@singularityrd.com](mailto:info@singularityrd.com?subject=Security), and put "Security" in the subject line.
Do not open a public issue, discussion, or pull request for a security problem.

Include as much of the following as you can:

- The affected AutoSecOps version and deployment option (Docker Compose, AWS Fargate, or Kubernetes).
- The affected component, endpoint, or feature.
- A description of the vulnerability and its impact.
- Step-by-step instructions or a proof of concept to reproduce it.
- Any relevant logs, screenshots, or configuration, with secrets and customer data removed.
- Whether and how you would like to be credited.

You can also report through a [private GitHub security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on the AutoSecOps repository, if you have access to it.

What to expect:

1. We acknowledge your report.
2. The SingularityRD security team confirms whether it is a valid security issue and rates its severity.
3. If it is valid, we work with you to reproduce and fix it, keep you informed of progress, and ship the fix within the [response timelines](#response-timelines).
4. We publish an advisory when the fix is available, and credit you if you wish.

As part of responsible disclosure, please give us a reasonable opportunity to fix the issue before you disclose it publicly.

## Contact

- Security vulnerabilities: [info@singularityrd.com](mailto:info@singularityrd.com?subject=Security), with "Security" in the subject
- Product support: [info@singularityrd.com](mailto:info@singularityrd.com)
- Documentation: [docs.singularityrd.com](https://docs.singularityrd.com)
