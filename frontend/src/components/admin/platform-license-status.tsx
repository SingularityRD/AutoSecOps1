"use client"

import { AlertTriangleIcon } from "lucide-react"
import {
  adminLicenseGetLicense,
  type Entitlement,
  type LicenseRead,
  type LicenseStatus,
} from "@/client"
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

function LicenseAlert({ license }: { license: LicenseRead }) {
  if (!license.enforced) {
    return (
      <Alert>
        <AlertTitle>Multi-tenant mode</AlertTitle>
        <AlertDescription>
          Entitlements come from tiers. The license key is ignored.
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
              ? `The configured license key is invalid (${license.error ?? "unknown error"}).`
              : "The license and its grace period have expired."}{" "}
            Contact {LICENSE_CONTACT} for a new key.
          </AlertDescription>
        </Alert>
      )
    case "missing":
      return (
        <Alert>
          <AlertTitle>No license key installed</AlertTitle>
          <AlertDescription>
            Set TRACECAT__LICENSE_KEY to unlock paid features. Contact{" "}
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
  entitlements: readonly Entitlement[]
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
    ["License ID", license.license_id ?? "-"],
    ["Issued", formatDate(license.issued_at)],
    ["Expires", formatDate(license.expires_at)],
  ]
  // Free baseline entitlements apply without a license, so list them apart
  // from the paid ones even when the license key also names them.
  const includedEntitlements = license.included_entitlements ?? []
  const includedSet = new Set<Entitlement>(includedEntitlements)
  const paidEntitlements = (license.entitlements ?? []).filter(
    (entitlement) => !includedSet.has(entitlement)
  )

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
    </div>
  )
}
