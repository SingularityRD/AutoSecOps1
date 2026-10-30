---
name: customer-registry-access
description: Internal SingularityRD runbook for granting, auditing, and revoking a customer's pull access to the private AutoSecOps GHCR images and Helm chart. Use when onboarding or offboarding a customer, or when a customer reports denied or unauthorized pulls.
argument-hint: "grant|revoke|audit <github-username>"
---

# customer-registry-access

Internal procedure for SingularityRD staff. Do not copy it into `docs/`; the
public docs only tell customers how to log in once access exists.

The AutoSecOps images and Helm chart stay private on GHCR. Every customer gets
Read access through one GitHub account, so access is revocable per customer.
Never make a package public, never grant a customer Write or Admin, and never
share one account or token across customers.

Never write a real customer name, GitHub username, or token into the
repository, a PR, an issue, or a commit message. Keep the customer-to-account
mapping in SingularityRD's internal customer records.

## Packages

| Package | Needed by |
| :------ | :-------- |
| `autosecops` | Every deployment path, including extracting install files |
| `autosecops-ui` | Every deployment path |
| `autosecops-postgres` | Docker Compose with the bundled PostgreSQL (`AUTOSECOPS__PGVECTOR_IMAGE` unset) |
| `autosecops-tunnel-gateway` | Kubernetes with `tunnels.enabled` |
| `charts/autosecops` | Kubernetes (Helm OCI chart) |

When in doubt, grant all five. Fargate needs only `autosecops` and
`autosecops-ui`.

## Prerequisites

- You have Admin on each package (an organization owner has it).
- Each package manages access directly. The image build adds the
  `org.opencontainers.image.source` label, so GitHub links each image package
  to the repository and makes it inherit repository access by default. While a
  package inherits access, granting Read on the package means granting Read on
  the repository. Under Package settings, clear `Inherit access from
  repository` once per package, then confirm the
  `SingularityRD/AutoSecOps1` repository still has Write under `Manage Actions
  access`, so `build-push-images.yml`, `build-postgres-image.yml`, and
  `publish-helm-chart.yml` can keep pushing with `GITHUB_TOKEN`.

## Grant access

1. Ask the customer for the GitHub account that will pull. Recommend a
   dedicated machine user for the deployment instead of a person's account.
   The account must have two-factor authentication enabled if the organization
   requires it.
2. For each package in the table: open the organization's Packages tab, select
   the package, open Package settings, and under `Manage access` choose
   `Invite teams or people`. Enter `<github-username>` and set the role to
   `Read`.
   - If GitHub only offers organization members, add the account to the
     organization with no team memberships and confirm the organization's base
     repository permission is `No permission`, so it reads only the packages
     you grant.
3. Record the account, the packages granted, and the date in the customer's
   internal record.
4. Tell the customer to create a personal access token (classic) with only
   `read:packages` and follow the Registry access section of their deployment
   guide (`/self-hosting/docker-compose`, `/self-hosting/aws-fargate`, or
   `/self-hosting/kubernetes`). GitHub Packages does not accept fine-grained
   tokens.
5. Ask the customer to confirm a pull works:

   ```bash
   echo "<read-packages-token>" | docker login ghcr.io -u <github-username> --password-stdin
   docker pull ghcr.io/singularityrd/autosecops:<version>
   ```

## Revoke access

1. For each package granted, open Package settings, find `<github-username>`
   under `Manage access`, and remove it.
2. If you added the account to the organization in step 2 of the grant, remove
   it from the organization.
3. Record the revocation date in the customer's internal record.

Revocation blocks new pulls with every existing token for that account.
Images already cached on the customer's hosts, nodes, or mirrors keep running;
revocation does not stop a running deployment.

## Audit

Periodically, and at every contract change, list each package's `Manage
access` entries and compare them with active customers. Remove any account
without an active customer record. Confirm every package is still private.

## Troubleshooting denied pulls

- `denied`: the account lacks Read on that package. Check the package list
  against the deployment path, especially `autosecops-postgres` and
  `autosecops-tunnel-gateway`.
- `unauthorized`: the token is wrong, expired, revoked, or lacks
  `read:packages`. The customer creates a new token and logs in again.
- Kubernetes `ImagePullBackOff` on tunnel gateways: the `ghcr-pull` Secret is
  missing from `tunnels.namespace` or from `tunnels.gateway.imagePullSecrets`.
- Fargate `CannotPullContainerError`: the Secrets Manager secret is not
  `{"username","password"}` JSON, or `autosecops_registry_credentials_arn` is
  unset.
