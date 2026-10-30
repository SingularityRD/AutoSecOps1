"use client"

import { AlertTriangleIcon } from "lucide-react"
import {
  adminLicenseGetLicense,
  type Entitlement,
  type LicenseLimits,
  type LicensePlan,
  type LicenseRead,
  type LicenseStatus,
} from "@/client"
import { CopyButton } from "@/components/copy-button"
import { CenteredSpinner } from "@/components/loading/spinner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { useQuery } from "@/lib/query"

const LICENSE_CONTACT = "sales@singularityrd.com"

const STATUS_LABELS: Record<LicenseStatus, string> = {
  missing: "No license",
  valid: "Valid",
  grace: "Expired, in grace period",
  expired: "Expired",
  invalid: "Invalid",
}

const PLAN_LABELS: Record<LicensePlan, string> = {
  community: "Community",
  team: "Team",
  business: "Business",
  enterprise: "Enterprise",
  mssp: "MSSP",
  pilot: "Pilot",
}

type LimitRow = {
  label: string
  limit: number | null | undefined
  usage?: number
}

function formatDate(value: string | null | undefined): string {
  if (!value) {
    return "-"
  }
  return new Date(value).toLocaleString()
}

function statusVariant(
  status: LicenseStatus
): "secondary" | "destructive" | "outline" {
  switch (status) {
    case "valid":
      return "secondary"
    case "grace":
    case "expired":
    case "invalid":
      return "destructive"
    default:
      return "outline"
  }
}

function formatDaysRemaining(days: number | null | undefined): string {
  if (days === null || days === undefined) {
    return "-"
  }
  if (days < 0) {
    return `Expired ${Math.abs(days)} days ago`
  }
  return `${days} days`
}

function invalidReason(license: LicenseRead): string {
  if (license.error === "deployment_mismatch") {
    return "The configured license key is bound to a different deployment ID."
  }
  return `The configured license key is invalid (${license.error ?? "unknown error"}).`
}

function LicenseAlert({ license }: { license: LicenseRead }) {
  if (!license.enforced) {
    return (
      <Alert>
        <AlertTitle>Multi-tenant mode</AlertTitle>
        <AlertDescription>
          The license grants multi-tenant mode. Entitlements come from tiers.
        </AlertDescription>
      </Alert>
    )
  }
  switch (license.status) {
    case "grace":
      return (
        <Alert variant="warning">
          <AlertTriangleIcon className="size-4" />
          <AlertTitle>License expired</AlertTitle>
          <AlertDescription>
            Paid features stay on until {formatDate(license.grace_ends_at)}.
            Contact {LICENSE_CONTACT} to renew.
          </AlertDescription>
        </Alert>
      )
    case "expired":
    case "invalid":
      return (
        <Alert variant="destructive">
          <AlertTriangleIcon className="size-4" />
          <AlertTitle>Paid features are off</AlertTitle>
          <AlertDescription>
            {license.status === "invalid"
              ? invalidReason(license)
              : "The license and its grace period have expired."}{" "}
            Contact {LICENSE_CONTACT} for a new key.
          </AlertDescription>
        </Alert>
      )
    case "valid":
      if (license.notice !== "expiring") {
        return null
      }
      return (
        <Alert variant="warning">
          <AlertTriangleIcon className="size-4" />
          <AlertTitle>License expires soon</AlertTitle>
          <AlertDescription>
            The license expires on {formatDate(license.expires_at)}. Contact{" "}
            {LICENSE_CONTACT} to renew.
          </AlertDescription>
        </Alert>
      )
    case "missing":
      return (
        <Alert>
          <AlertTitle>No license key installed</AlertTitle>
          <AlertDescription>
            Set AUTOSECOPS__LICENSE_KEY to unlock paid features. Contact{" "}
            {LICENSE_CONTACT} to buy a license.
          </AlertDescription>
        </Alert>
      )
    default:
      return null
  }
}

function EntitlementBadges({
  entitlements,
}: {
  entitlements: readonly string[]
}) {
  return (
    <dd className="flex flex-wrap gap-1.5">
      {entitlements.length === 0 && (
        <span className="text-muted-foreground">None</span>
      )}
      {entitlements.map((entitlement) => (
        <Badge key={entitlement} variant="outline">
          {entitlement}
        </Badge>
      ))}
    </dd>
  )
}

function formatLimit(limit: number | null | undefined): string {
  if (limit === null || limit === undefined) {
    return "Unlimited"
  }
  return limit.toString()
}

function limitRows(license: LicenseRead): LimitRow[] {
  const limits: LicenseLimits = license.limits ?? {}
  return [
    {
      label: "Users",
      limit: limits.max_users,
      usage: license.usage.users,
    },
    {
      label: "Workspaces",
      limit: limits.max_workspaces,
      usage: license.usage.workspaces,
    },
    {
      label: "Organizations",
      limit: limits.max_organizations,
      usage: license.usage.organizations,
    },
    {
      label: "Concurrent workflows",
      limit: limits.max_concurrent_workflows,
    },
    { label: "Concurrent actions", limit: limits.max_concurrent_actions },
    {
      label: "Actions per workflow run",
      limit: limits.max_action_executions_per_workflow,
    },
  ]
}

function LimitsTable({ license }: { license: LicenseRead }) {
  return (
    <div className="space-y-3">
      <h3 className="text-base font-medium">Limits and usage</h3>
      <dl className="grid grid-cols-[200px_1fr] gap-y-3 text-sm">
        {limitRows(license).map((row) => {
          const atLimit =
            row.usage !== undefined &&
            row.limit !== null &&
            row.limit !== undefined &&
            row.usage >= row.limit
          return (
            <div key={row.label} className="contents">
              <dt className="text-muted-foreground">{row.label}</dt>
              <dd className="flex items-center gap-2">
                {row.usage !== undefined ? (
                  <span>
                    {row.usage} of {formatLimit(row.limit)}
                  </span>
                ) : (
                  <span>{formatLimit(row.limit)}</span>
                )}
                {atLimit && <Badge variant="outline">Limit reached</Badge>}
              </dd>
            </div>
          )
        })}
      </dl>
    </div>
  )
}

function DeploymentId({ license }: { license: LicenseRead }) {
  return (
    <div className="space-y-3">
      <h3 className="text-base font-medium">Deployment ID</h3>
      <p className="text-sm text-muted-foreground">
        Send this ID to {LICENSE_CONTACT} to receive a license bound to this
        installation.
      </p>
      <div className="flex items-center gap-2">
        <code className="rounded-md border px-2 py-1 font-mono text-sm">
          {license.deployment_id}
        </code>
        <CopyButton
          value={license.deployment_id}
          toastMessage="Copied deployment ID"
          tooltipMessage="Copy deployment ID"
        />
      </div>
      {license.license_deployment_id && (
        <p className="text-sm text-muted-foreground">
          The license is bound to {license.license_deployment_id}.
        </p>
      )}
    </div>
  )
}

/**
 * Read-only view of the platform license reported by `GET /admin/license`.
 */
export function PlatformLicenseStatus() {
  const {
    data: license,
    isLoading,
    error,
  } = useQuery<LicenseRead>({
    queryKey: ["admin", "license"],
    queryFn: adminLicenseGetLicense,
  })

  if (isLoading) {
    return <CenteredSpinner />
  }
  if (error || !license) {
    return (
      <div className="text-center text-muted-foreground">
        Failed to load license status
      </div>
    )
  }

  const rows: Array<[string, string]> = [
    ["Customer", license.customer ?? "-"],
    ["Plan", license.plan ? PLAN_LABELS[license.plan] : "-"],
    ["License ID", license.license_id ?? "-"],
    ["Issued", formatDate(license.issued_at)],
    ["Expires", formatDate(license.expires_at)],
    ["Days remaining", formatDaysRemaining(license.days_remaining)],
    ["Grace period ends", formatDate(license.grace_ends_at)],
  ]
  // Free baseline entitlements apply without a license, so list them apart
  // from the paid ones even when the license key also names them.
  const includedEntitlements = license.included_entitlements ?? []
  const includedSet = new Set<Entitlement>(includedEntitlements)
  // Deployment grants such as multi_tenant are listed with paid entitlements.
  const paidEntitlements: string[] = [
    ...(license.entitlements ?? []).filter(
      (entitlement) => !includedSet.has(entitlement)
    ),
    ...(license.grants ?? []),
  ]

  return (
    <div className="space-y-8">
      <LicenseAlert license={license} />
      <dl className="grid grid-cols-[160px_1fr] gap-y-3 text-sm">
        <dt className="text-muted-foreground">Status</dt>
        <dd>
          <Badge variant={statusVariant(license.status)}>
            {STATUS_LABELS[license.status]}
          </Badge>
        </dd>
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
        <dt className="text-muted-foreground">Licensed entitlements</dt>
        <EntitlementBadges entitlements={paidEntitlements} />
        {license.enforced && (
          <>
            <dt className="text-muted-foreground">Included without license</dt>
            <EntitlementBadges entitlements={includedEntitlements} />
          </>
        )}
      </dl>
      <LimitsTable license={license} />
      <DeploymentId license={license} />
    </div>
  )
}
