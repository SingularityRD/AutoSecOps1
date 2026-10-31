"use client"

import { AlertTriangleIcon } from "lucide-react"
import { AdminTiersTable } from "@/components/admin/admin-tiers-table"
import { CreateTierDialog } from "@/components/admin/create-tier-dialog"
import { CenteredSpinner } from "@/components/loading/spinner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { useAdminTiers } from "@/hooks/use-admin"

export default function AdminTiersPage() {
  const { isLoading, error } = useAdminTiers(true)

  if (isLoading) {
    return <CenteredSpinner />
  }

  if (error) {
    return (
      <div className="text-center text-muted-foreground">
        Failed to load tiers
      </div>
    )
  }

  return (
    <div className="size-full overflow-auto">
      <div className="container flex h-full max-w-[1000px] flex-col space-y-12">
        <div className="flex w-full">
          <div className="items-start space-y-3 text-left">
            <h2 className="text-2xl font-semibold tracking-tight">Tiers</h2>
            <p className="text-base text-muted-foreground">
              Manage plans and resource limits.
            </p>
          </div>
          <div className="ml-auto flex items-center space-x-2">
            <CreateTierDialog />
          </div>
        </div>
        <Alert variant="warning">
          <AlertTriangleIcon className="size-4" />
          <AlertTitle>MSSP license required</AlertTitle>
          <AlertDescription>
            Tiers apply in multi-tenant mode, which needs an MSSP license that
            grants multi_tenant. Single-tenant deployments take entitlements
            from the license key instead.
          </AlertDescription>
        </Alert>
        <AdminTiersTable />
      </div>
    </div>
  )
}
